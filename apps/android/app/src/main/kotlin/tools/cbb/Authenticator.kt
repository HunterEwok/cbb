// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Asks for the fingerprint, the face or the screen lock before the root or
 * admin key signs (Keys), and remembers for a little less than the keys'
 * window that it did, so one action asks once.
 */
class Authenticator {
    /** The user cancelled, or authentication failed for good. */
    class Cancelled(message: String) : Exception(message)

    private var passedAt = 0L

    /** Whether the keys still sign without asking. */
    val isFresh: Boolean
        get() = passedAt != 0L && android.os.SystemClock.elapsedRealtime() - passedAt < (Keys.AUTH_SECONDS - 5) * 1000L

    /**
     * Asks unless the last authentication is fresh. A device without a
     * screen lock has keys without authentication (a debug build only), so
     * it passes at once.
     */
    suspend fun authenticate(context: Context, title: String, subtitle: String? = null) {
        if (isFresh || !context.getSystemService(KeyguardManager::class.java).isDeviceSecure) return
        prompt(context, title, subtitle)
        passedAt = android.os.SystemClock.elapsedRealtime()
    }

    /** Forgets the last authentication, as when the screen locks. */
    fun forget() {
        passedAt = 0L
    }

    @Suppress("DEPRECATION")
    private suspend fun prompt(context: Context, title: String, subtitle: String?) = suspendCancellableCoroutine { c ->
        val b = BiometricPrompt.Builder(context).setTitle(title)
        if (subtitle != null) b.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            b.setDeviceCredentialAllowed(true)
        }
        val cancel = CancellationSignal()
        c.invokeOnCancellation { cancel.cancel() }
        b.build().authenticate(
            cancel,
            context.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (c.isActive) c.resume(Unit)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (c.isActive) c.resumeWithException(Cancelled(errString.toString()))
                }
            },
        )
    }
}
