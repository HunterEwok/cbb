// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.wear

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import tools.cbb.WatchState
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The watch's admin key (docs/protocol.md, section 10, "Watches"): a P-256 key
 * in the watch's Keystore, in StrongBox where the watch has one and else in
 * the TEE, usable only while the watch is unlocked, which the root phone
 * certifies as an admin CA with the role watch. The admin CA it gave sits in
 * the preferences.
 */
object WatchKey {
    class NotProtected : Exception("the watch has no secure lock screen")

    private const val PREFS = "watch-key"
    private const val PENDING = "pending"
    private const val ADMIN = "admin"
    private const val ADMISSION = "admission"

    /** Whether the watch has a secure lock screen, which its key needs. */
    fun protected(context: Context): Boolean = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    /**
     * Makes a new key for the root to certify, under a new device ID, and
     * returns what the phone needs. An earlier pending key goes; a certified
     * one stays until the new one is certified.
     */
    fun request(context: Context, name: String): WatchState.KeyRequest {
        if (!protected(context)) throw NotProtected()
        val device = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.getString(PENDING, null)?.let { keyStore().deleteEntry(alias(it)) }
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val pair = try {
            generate(device, strongBox)
        } catch (e: StrongBoxUnavailableException) {
            generate(device, false)
        }
        prefs.edit().putString(PENDING, device).apply()
        return WatchState.KeyRequest(device, name, pair)
    }

    private fun generate(device: String, strongBox: Boolean): ByteArray {
        val spec = KeyGenParameterSpec.Builder(alias(device), KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        g.initialize(spec)
        return g.generateKeyPair().public.encoded
    }

    /** Takes the root's answer to the pending request: the pending key becomes the admin key; an answer for another request is refused. */
    fun admit(context: Context, a: WatchState.Admission): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (a.device != prefs.getString(PENDING, null) || !keyStore().containsAlias(alias(a.device))) return false
        prefs.getString(ADMIN, null)?.takeIf { it != a.device }?.let { keyStore().deleteEntry(alias(it)) }
        prefs.edit()
            .putString(ADMIN, a.device)
            .remove(PENDING)
            .putString(ADMISSION, Base64.getEncoder().encodeToString(a.encode()))
            .apply()
        return true
    }

    /** What the root certified, when it did. */
    fun admission(context: Context): WatchState.Admission? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ADMISSION, null)
            ?.let { WatchState.Admission.decode(Base64.getDecoder().decode(it)) }

    /** Forgets the admin key, the pending one and the admission, as when the phone left the group the root certified the key in. */
    fun forget(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val ks = keyStore()
        for (d in listOfNotNull(prefs.getString(ADMIN, null), prefs.getString(PENDING, null))) {
            if (ks.containsAlias(alias(d))) ks.deleteEntry(alias(d))
        }
        prefs.edit().remove(ADMIN).remove(PENDING).remove(ADMISSION).apply()
    }

    /** The certified key, for signing; null without one. */
    fun adminKey(context: Context): PrivateKey? {
        val device = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ADMIN, null) ?: return null
        return keyStore().getKey(alias(device), null) as? PrivateKey
    }

    private fun alias(device: String) = "cbb-watch-$device"

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
}
