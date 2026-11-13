// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Looper
import java.security.Signature
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException

/**
 * Asks for the fingerprint, the face or the screen lock before the root or
 * admin key signs (Keys): once for Keys.KEEP_SECONDS for a key made so, or
 * before each signature for a key of an earlier version, which the Keystore
 * lets sign only through the Signature that the prompt carried as its
 * CryptoObject. Either way only the system's own authentication lets the
 * key sign.
 */
class Authenticator {
    /** The user cancelled, or authentication failed for good. */
    class Cancelled(message: String) : Exception(message)

    /**
     * Shows the prompt for signature, an initialized Signature of a key that
     * needs the user for each signature, and returns the Signature the prompt
     * authorized, good for one signature; with signature null, the prompt
     * lets a timed key sign for its time, and returns null. It waits for the
     * user, so it runs off the main thread, as the kit signs.
     */
    fun authorize(context: Context, title: String, subtitle: String?, signature: Signature?): Signature? {
        check(Looper.myLooper() != Looper.getMainLooper()) { "a signature that needs the user is made off the main thread" }
        val cancel = CancellationSignal()
        val done = CompletableFuture<Signature?>()
        context.mainExecutor.execute {
            try {
                prompt(context, title, subtitle, signature, cancel, done)
            } catch (e: Exception) {
                done.completeExceptionally(e)
            }
        }
        try {
            return done.get()
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        } catch (e: InterruptedException) {
            cancel.cancel()
            Thread.currentThread().interrupt()
            throw Cancelled("interrupted")
        }
    }

    @Suppress("DEPRECATION")
    private fun prompt(
        context: Context,
        title: String,
        subtitle: String?,
        signature: Signature?,
        cancel: CancellationSignal,
        done: CompletableFuture<Signature?>,
    ) {
        val b = BiometricPrompt.Builder(context).setTitle(title)
        if (subtitle != null) b.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else if (signature == null) {
            // Android 10: a timed key takes the screen lock too.
            b.setDeviceCredentialAllowed(true)
        } else {
            // Android 10 takes no screen lock with a CryptoObject: its keys
            // are made for a fingerprint or face alone (Keys).
            b.setNegativeButton(context.getString(android.R.string.cancel), context.mainExecutor) { _, _ -> done.completeExceptionally(Cancelled("cancelled")) }
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (signature == null) {
                    done.complete(null)
                    return
                }
                val authorized = result.cryptoObject?.signature
                if (authorized == null) {
                    done.completeExceptionally(Cancelled("the prompt returned no signature"))
                } else {
                    done.complete(authorized)
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                done.completeExceptionally(Cancelled(errString.toString()))
            }
        }
        val prompt = b.build()
        if (signature == null) {
            prompt.authenticate(cancel, context.mainExecutor, callback)
        } else {
            prompt.authenticate(BiometricPrompt.CryptoObject(signature), cancel, context.mainExecutor, callback)
        }
    }
}
