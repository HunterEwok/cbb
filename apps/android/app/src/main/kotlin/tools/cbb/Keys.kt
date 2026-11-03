// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import tools.cbb.kit.Attestation
import tools.cbb.kit.CertificateSigner
import tools.cbb.kit.PeriodKeys
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The phone's keys in the Android Keystore, which never lets them out: in
 * StrongBox where the phone has it, else in the TEE.
 *
 * - The member key signs the TLS handshakes with the computers; it needs no
 *   unlock, so the phone syncs in the background.
 * - The root key (the group CA's, on the phone that made the group) and the
 *   admin key (a phone the root made an admin) sign certificates and
 *   records. They sign only for [AUTH_SECONDS] after the user passed the
 *   fingerprint, the face or the screen lock, as Face ID guards them on the
 *   iPhone.
 *
 * - The keys for the servers of each period (docs/protocol.md, section
 *   18), the server key and on the root the period key, sign in the
 *   background like the member key ([PhoneKeys]).
 *
 * Each key is made with an attestation challenge ([Attestation.challenge]),
 * so its certificate chain from the Keystore can prove later where it lives
 * ([evidence]).
 */
object Keys {
    const val MEMBER = "cbb.member"
    const val ROOT = "cbb.ca"
    const val ADMIN = "cbb.admin"

    /**
     * How long one authentication lets the root and admin keys sign: one
     * action's signatures, and the renewals right after, and little more, so
     * that a phone left unlocked does not sign for long without asking. The
     * Keystore keeps the window a key was made with: keys made by earlier
     * versions keep theirs, and the app still asks within this one.
     */
    const val AUTH_SECONDS = 30

    private const val PROVIDER = "AndroidKeyStore"

    /** The phone has no screen lock, which the root and admin keys need. */
    class NoScreenLock : Exception("set a screen lock first: the group's keys need it")

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** The signer of the key under alias, or null when there is none. */
    fun load(alias: String): KeystoreSigner? {
        val entry = store().getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return null
        return KeystoreSigner(entry.privateKey, entry.certificate.publicKey.encoded)
    }

    /** The signer of the key under alias, made now when there is none. */
    fun loadOrCreate(context: Context, alias: String, groupTag: String = ""): KeystoreSigner =
        load(alias) ?: create(context, alias, groupTag)

    /**
     * What proves where the key under alias lives: the Keystore's chain
     * for it, leaf first, and the salt and group tag of its challenge. A
     * key on a phone whose Keystore could not attest it has none.
     */
    class Evidence(val chain: List<ByteArray>, val salt: ByteArray, val groupTag: String)

    fun evidence(context: Context, alias: String): Evidence? {
        val chain = store().getCertificateChain(alias)?.map { it.encoded } ?: return null
        // A key made without a challenge has only its self-signed certificate.
        if (chain.size < 2) return null
        val p = prefs(context)
        val salt = p.getString("salt.$alias", null)?.let { Base64.getDecoder().decode(it) } ?: return null
        return Evidence(chain, salt, p.getString("tag.$alias", "")!!)
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences("keys", Context.MODE_PRIVATE)

    /**
     * Makes a P-256 key under alias, replacing one that was there. The root
     * and admin keys need the user's authentication; a debug build on a
     * device without a screen lock, such as a fresh emulator, makes them
     * without, so the app can be tried there.
     *
     * groupTag is the group the key is made in, when there is one already
     * (an admin key made for the group the phone is joining, a root key
     * that takes a group over). The root and admin keys' challenges also
     * bind the member key, which is made first when there is none.
     */
    fun create(context: Context, alias: String, groupTag: String = ""): KeystoreSigner {
        val auth = alias != MEMBER
        if (auth && !context.getSystemService(KeyguardManager::class.java).isDeviceSecure && !isDebuggable(context)) throw NoScreenLock()
        val secure = auth && context.getSystemService(KeyguardManager::class.java).isDeviceSecure
        val member = if (alias == MEMBER) ByteArray(0) else loadOrCreate(context, MEMBER).publicKeyDER
        remove(alias)
        val salt = Attestation.newSalt()
        val challenge = Attestation.challenge(groupTag, member, salt)
        prefs(context).edit()
            .putString("salt.$alias", Base64.getEncoder().encodeToString(salt))
            .putString("tag.$alias", groupTag)
            .commit()
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBox) {
            try {
                return generate(alias, secure, strongBox = true, challenge)
            } catch (e: StrongBoxUnavailableException) {
                // Some StrongBox chips lack P-256 or are busy: the TEE then.
            }
        }
        return try {
            generate(alias, secure, strongBox = false, challenge)
        } catch (e: ProviderException) {
            // A Keystore that cannot attest now (no attestation key
            // provisioned yet, as after a factory reset offline) still
            // makes the key, which then has no evidence.
            generate(alias, secure, strongBox = false, challenge = null)
        }
    }

    private fun generate(alias: String, auth: Boolean, strongBox: Boolean, challenge: ByteArray?): KeystoreSigner {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // Conscrypt signs the TLS handshake over a digest it computed, which needs NONE.
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .setIsStrongBoxBacked(strongBox)
            .apply { if (challenge != null) setAttestationChallenge(challenge) }
            .apply { if (auth) authenticate(this) }
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        kpg.initialize(spec)
        val kp = kpg.generateKeyPair()
        return KeystoreSigner(kp.private, kp.public.encoded)
    }

    @Suppress("DEPRECATION")
    private fun authenticate(b: KeyGenParameterSpec.Builder) {
        b.setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setUserAuthenticationParameters(
                AUTH_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            b.setUserAuthenticationValidityDurationSeconds(AUTH_SECONDS)
        }
    }

    fun remove(alias: String) {
        val s = store()
        if (s.containsAlias(alias)) s.deleteEntry(alias)
    }

    /** The prefix of the keys for the servers, one per kind and period. */
    private const val PERIOD = "cbb.period."

    /** The keys for the servers of each period, in the TEE, without the user's authentication, since they sign in the background. */
    object PhoneKeys : PeriodKeys {
        private fun alias(kind: String, tag: String) = "$PERIOD$kind.$tag"

        override fun get(kind: String, tag: String): CertificateSigner =
            load(alias(kind, tag)) ?: generate(alias(kind, tag), auth = false, strongBox = false, challenge = null)

        override fun has(kind: String, tag: String): Boolean = store().containsAlias(alias(kind, tag))

        override fun keep(tag: String) {
            val s = store()
            for (a in s.aliases().toList()) if (a.startsWith(PERIOD) && !a.endsWith(".$tag")) s.deleteEntry(a)
        }

        /** Drops every key for the servers, as when the phone leaves the group. */
        fun clear() = keep("")
    }

    private fun isDebuggable(context: Context): Boolean =
        context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
}

/** A Keystore key as a CertificateSigner, and as the private key of the phone's TLS identity. */
class KeystoreSigner(val privateKey: PrivateKey, override val publicKeyDER: ByteArray) : CertificateSigner {
    override fun signature(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    /** An ECDSA signature, ASN.1 DER, of a SHA-256 digest: the member key signs the hub's TLS to its forwarder so (cbbtun's Signer). */
    fun signDigest(digest: ByteArray): ByteArray =
        Signature.getInstance("NONEwithECDSA").run {
            initSign(privateKey)
            update(digest)
            sign()
        }
}
