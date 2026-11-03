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
 * Asks for the fingerprint, the face or the screen lock before each
 * signature of the root or admin key (Keys). The Keystore lets such a key
 * sign once per authentication, and only through the Signature that the
 * prompt carried as its CryptoObject, so a prompt shown or answered by
 * anything but the system's own authentication signs nothing.
 */
class Authenticator {
    /** The user cancelled, or authentication failed for good. */
    class Cancelled(message: String) : Exception(message)

    /**
     * Shows the prompt for signature, an initialized Signature of a key that
     * needs the user, and returns the Signature the prompt authorized, good
     * for one signature. It waits for the user, so it runs off the main
     * thread, as the kit signs.
     */
    fun authorize(context: Context, title: String, subtitle: String?, signature: Signature): Signature {
        check(Looper.myLooper() != Looper.getMainLooper()) { "a signature that needs the user is made off the main thread" }
        val cancel = CancellationSignal()
        val done = CompletableFuture<Signature>()
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
        signature: Signature,
        cancel: CancellationSignal,
        done: CompletableFuture<Signature>,
    ) {
        val b = BiometricPrompt.Builder(context).setTitle(title)
        if (subtitle != null) b.setSubtitle(subtitle)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            // Android 10 takes no screen lock with a CryptoObject: its keys
            // are made for a fingerprint or face alone (Keys).
            b.setNegativeButton(context.getString(android.R.string.cancel), context.mainExecutor) { _, _ -> done.completeExceptionally(Cancelled("cancelled")) }
        }
        b.build().authenticate(
            BiometricPrompt.CryptoObject(signature),
            cancel,
            context.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
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
            },
        )
    }
}
