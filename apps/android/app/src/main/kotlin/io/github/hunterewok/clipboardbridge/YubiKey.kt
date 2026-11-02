// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import io.github.hunterewok.clipboardbridge.kit.SmartCard
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException

/**
 * A YubiKey held to the phone, over NFC: [withCard] turns on the reader
 * while the screen asks the user to hold the YubiKey to the back of the
 * phone, and runs the kit's PIV commands on it once it is there (the kit's
 * Piv). The card's own NFC tap is the touch its key asks for.
 */
internal object YubiKeyNfc {
    class Unavailable(val off: Boolean) : Exception(if (off) "NFC is off" else "this phone has no NFC")

    /** No YubiKey came to the phone within [WAIT_MS]. */
    class NoCard : Exception("no YubiKey was held to the phone")

    /** How long the phone waits for the YubiKey, and how long one command may take. */
    const val WAIT_MS = 60_000L
    private const val COMMAND_TIMEOUT_MS = 10_000

    fun available(context: Context): Boolean = NfcAdapter.getDefaultAdapter(context)?.isEnabled == true

    /**
     * Waits for a YubiKey on activity's reader and runs block on it, on the
     * reader's thread, while the card stays connected; the reader is off
     * again when it returns.
     */
    suspend fun <T> withCard(activity: Activity, block: (SmartCard) -> T): T {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: throw Unavailable(off = false)
        if (!adapter.isEnabled) throw Unavailable(off = true)
        val done = CompletableDeferred<T>()
        val callback = NfcAdapter.ReaderCallback { tag: Tag ->
            if (done.isCompleted) return@ReaderCallback
            val iso = IsoDep.get(tag) ?: return@ReaderCallback
            try {
                iso.connect()
                iso.timeout = COMMAND_TIMEOUT_MS
                done.complete(block(SmartCard { apdu -> iso.transceive(apdu) }))
            } catch (e: IOException) {
                // The card left too soon: the next tap tries again.
                Log.w(TAG, "the YubiKey left before the commands ended", e)
            } catch (e: Exception) {
                done.completeExceptionally(e)
            } finally {
                runCatching { iso.close() }
            }
        }
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
        activity.runOnUiThread { adapter.enableReaderMode(activity, callback, flags, null) }
        try {
            return (withTimeoutOrNull(WAIT_MS) { Result.success(done.await()) } ?: throw NoCard()).getOrThrow()
        } finally {
            activity.runOnUiThread { runCatching { adapter.disableReaderMode(activity) } }
        }
    }

    private const val TAG = "YubiKeyNfc"
}

/**
 * Asks for the YubiKey's PIN before the phone waits for the card: title and
 * body say what follows. The PIN stays in memory only until the card took it.
 */
@Composable
internal fun YubiKeyPinDialog(title: String, body: String, dismiss: () -> Unit, go: (String) -> Unit) {
    val palette = LocalPalette.current
    var pin by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                Text(body)
                OutlinedTextField(
                    value = pin,
                    onValueChange = { v -> pin = v.take(8) },
                    singleLine = true,
                    label = { Text(stringResource(R.string.yubikey_pin)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, autoCorrectEnabled = false),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                dismiss()
                go(pin)
            }, enabled = pin.length in 6..8) { Text(stringResource(R.string.yubikey_go), color = palette.accent) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

/** While the phone waits for the YubiKey: what to do with it, and a way to stop waiting. */
@Composable
internal fun YubiKeyPrompt(model: AppModel, cancel: () -> Unit) {
    val prompt = model.cardPrompt ?: return
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = {},
        icon = { CircularProgressIndicator(color = palette.accent) },
        text = { Text(stringResource(prompt), textAlign = TextAlign.Center) },
        confirmButton = {},
        dismissButton = { TextButton(onClick = cancel) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        textContentColor = palette.text,
    )
}
