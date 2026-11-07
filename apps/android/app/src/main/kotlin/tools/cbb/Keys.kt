// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import tools.cbb.kit.Attestation
import tools.cbb.kit.CertificateSigner
import tools.cbb.kit.PeriodKeys
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The phone's keys in the Android Keystore, which never lets them out: in
 * StrongBox where the phone has it, else in the TEE.
 *
 * - The member key signs the TLS handshakes with the computers; it needs no
 *   unlock, so the phone syncs in the background.
 * - The root key (the group CA's, on the phone that made the group) and the
 *   admin key (a phone the root made an admin) sign certificates and
 *   records. Each of their signatures needs the fingerprint, the face or
 *   the screen lock first, which the Keystore checks for that one
 *   signature ([Authenticator]): a phone just unlocked, or code in the
 *   app's process, signs nothing without the user.
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

    private const val PROVIDER = "AndroidKeyStore"

    /** The phone has no screen lock, which the root and admin keys need. */
    class NoScreenLock : Exception("set a screen lock first: the group's keys need it")

    /** Android 10 has no fingerprint or face enrolled, which its root and admin keys need. */
    class NoBiometric : Exception("add a fingerprint or face first: on Android 10 the group's keys need one")

    /**
     * The root or admin key was made by an earlier version of the app, for
     * a time after any authentication rather than for each signature; the
     * Keystore keeps what a key was made with, so the phone sets the group
     * up again.
     */
    class OldKey : Exception("this group key was made by an earlier version of the app")

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
     * The signer of the root or admin key under alias, made now when there
     * is none, whose every signature asks the user through authorize. A key
     * made without authentication (a debug build on a phone without a
     * screen lock) signs without asking. Throws OldKey for a key that an
     * earlier version made.
     */
    fun loadOrCreateAuthorized(context: Context, alias: String, groupTag: String = "", authorize: (Signature) -> Signature): KeystoreSigner {
        val k = loadOrCreate(context, alias, groupTag)
        val info = info(k)
        if (!info.isUserAuthenticationRequired) return k
        if (isOld(info)) throw OldKey()
        return KeystoreSigner(k.privateKey, k.publicKeyDER, authorize)
    }

    /** The signer of the key under alias, or null when there is none or an earlier version made it (OldKey). */
    fun loadCurrent(alias: String): KeystoreSigner? = load(alias)?.takeUnless { isOld(info(it)) }

    private fun info(k: KeystoreSigner): KeyInfo =
        KeyFactory.getInstance(k.privateKey.algorithm, PROVIDER).getKeySpec(k.privateKey, KeyInfo::class.java)

    /** A key for a time after any authentication; one for each signature has 0 (Android 11 on) or -1 (Android 10). */
    private fun isOld(info: KeyInfo): Boolean =
        info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds > 0

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
        if (secure && Build.VERSION.SDK_INT < Build.VERSION_CODES.R && !hasBiometric(context)) throw NoBiometric()
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

    /**
     * Makes the key sign once per authentication, through the prompt's
     * CryptoObject. A fingerprint or face added later keeps the key: whoever
     * adds one passed the screen lock, which the key takes anyway, and a
     * group's root key lost that way would lose the group.
     */
    @Suppress("DEPRECATION")
    private fun authenticate(b: KeyGenParameterSpec.Builder) {
        b.setUserAuthenticationRequired(true)
        b.setInvalidatedByBiometricEnrollment(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else {
            // Android 10: each signature after a fingerprint or face, the
            // only authentication it binds to one operation.
            b.setUserAuthenticationValidityDurationSeconds(-1)
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

    @Suppress("DEPRECATION")
    private fun hasBiometric(context: Context): Boolean =
        context.getSystemService(BiometricManager::class.java).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS

    private fun isDebuggable(context: Context): Boolean =
        context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
}

/**
 * A Keystore key as a CertificateSigner, and as the private key of the
 * phone's TLS identity. With authorize, each signature first goes to the
 * user (Keys.loadOrCreateAuthorized), who gives back the Signature that may
 * sign.
 */
class KeystoreSigner(
    val privateKey: PrivateKey,
    override val publicKeyDER: ByteArray,
    private val authorize: ((Signature) -> Signature)? = null,
) : CertificateSigner {
    override fun signature(data: ByteArray): ByteArray {
        val s = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
        return (authorize?.invoke(s) ?: s).run {
            update(data)
            sign()
        }
    }

    /**
     * A signer for one signature that asks the user now rather than when
     * it signs: for a signature made where waiting for the user would hold
     * others up.
     */
    fun once(): CertificateSigner {
        val ready = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }.let { authorize?.invoke(it) ?: it }
        val used = AtomicBoolean(false)
        return object : CertificateSigner {
            override val publicKeyDER = this@KeystoreSigner.publicKeyDER

            override fun signature(data: ByteArray): ByteArray {
                check(used.compareAndSet(false, true)) { "a signer for one signature signed twice" }
                ready.update(data)
                return ready.sign()
            }
        }
    }

    /**
     * An ECDSA signature, ASN.1 DER, of a SHA-256 digest: what the Rust
     * core's signing callback asks for, as the member key signs the node's
     * TLS and the root or admin key the certificates and records the core
     * issues. With authorize, the user allows each signature first.
     */
    fun signDigest(digest: ByteArray): ByteArray {
        val s = Signature.getInstance("NONEwithECDSA").apply { initSign(privateKey) }
        return (authorize?.invoke(s) ?: s).run {
            update(digest)
            sign()
        }
    }
}
