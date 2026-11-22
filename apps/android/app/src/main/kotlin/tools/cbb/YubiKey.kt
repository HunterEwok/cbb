// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.core.content.ContextCompat
import tools.cbb.kit.CardLink
import tools.cbb.kit.CcidBulk
import tools.cbb.kit.SmartCard
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A YubiKey for the core's PIV steps (the kit's RecoveryCard), held to the
 * phone over NFC or plugged into its USB-C port: [withCard] takes one that
 * is plugged in already, or else turns on the NFC reader while the screen
 * asks for the YubiKey and takes whichever comes first, a tap or a plug.
 * Over NFC the tap is the touch its key asks for; on USB the person touches
 * the YubiKey when it blinks.
 */
internal object YubiKeys {
    /** The phone reaches a YubiKey neither over NFC nor over USB. */
    class Unavailable : Exception("this phone has neither NFC nor USB host")

    /** No YubiKey came to the phone within [WAIT_MS]. */
    class NoCard : Exception("no YubiKey was held to the phone or plugged in")

    /** How long the phone waits for the YubiKey. */
    const val WAIT_MS = 60_000L
    private const val POLL_MS = 300L

    /** Whether the phone can reach a YubiKey at all: NFC on, or a USB port that hosts devices. */
    fun available(context: Context): Boolean = YubiKeyNfc.available(context) || YubiKeyUsb.hosts(context)

    /**
     * Waits for a YubiKey and runs block on it, off the main thread, while
     * it stays connected; plugged is called when it is one on USB, so the
     * screen can ask for the touch.
     */
    suspend fun <T> withCard(activity: Activity, plugged: () -> Unit, block: (CardLink) -> T): T {
        YubiKeyUsb.find(activity)?.let { d ->
            plugged()
            return YubiKeyUsb.withCard(activity, d, block)
        }
        val nfc = YubiKeyNfc.available(activity)
        val usb = YubiKeyUsb.hosts(activity)
        if (!nfc && !usb) {
            NfcAdapter.getDefaultAdapter(activity)?.let { throw YubiKeyNfc.Unavailable(off = true) }
            throw Unavailable()
        }
        return coroutineScope {
            // The first of a tap and a plug takes the step; the other stops.
            val taken = AtomicBoolean(false)
            val tapped = CompletableDeferred<Result<T>>()
            val found = CompletableDeferred<UsbDevice>()
            val watch = if (usb) {
                launch {
                    while (true) {
                        delay(POLL_MS)
                        val d = YubiKeyUsb.find(activity) ?: continue
                        if (taken.compareAndSet(false, true)) found.complete(d)
                        return@launch
                    }
                }
            } else {
                null
            }
            val reader = if (nfc) YubiKeyNfc.start(activity, taken) { link -> runCatching { block(link) } }.also { r ->
                launch { tapped.complete(r.await()) }
            } else {
                null
            }
            try {
                val got = withTimeoutOrNull(WAIT_MS) {
                    kotlinx.coroutines.selects.select<Any?> {
                        tapped.onAwait { it }
                        found.onAwait { it }
                    }
                } ?: throw NoCard()
                reader?.stop()
                watch?.cancel()
                @Suppress("UNCHECKED_CAST")
                when (got) {
                    is UsbDevice -> {
                        plugged()
                        YubiKeyUsb.withCard(activity, got, block)
                    }
                    else -> (got as Result<T>).getOrThrow()
                }
            } finally {
                reader?.stop()
                watch?.cancel()
            }
        }
    }
}

/** A YubiKey held to the phone, over NFC (IsoDep). */
internal object YubiKeyNfc {
    class Unavailable(val off: Boolean) : Exception(if (off) "NFC is off" else "this phone has no NFC")

    /** How long one command may take. */
    private const val COMMAND_TIMEOUT_MS = 10_000

    fun available(context: Context): Boolean = NfcAdapter.getDefaultAdapter(context)?.isEnabled == true

    /** The reader while it is on: [await] gives what block did with the first card, [stop] turns the reader off. */
    class Reader<T>(private val activity: Activity, private val adapter: NfcAdapter, val done: CompletableDeferred<T>) {
        suspend fun await(): T = done.await()

        fun stop() {
            activity.runOnUiThread { runCatching { adapter.disableReaderMode(activity) } }
        }
    }

    /**
     * Turns on activity's reader and runs block on the first YubiKey held to
     * it, on the reader's thread, while the card stays connected; taken is
     * shared with the USB watch so that only one of them runs a step.
     */
    fun <T> start(activity: Activity, taken: AtomicBoolean, block: (CardLink) -> T): Reader<T> {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: throw Unavailable(off = false)
        if (!adapter.isEnabled) throw Unavailable(off = true)
        val done = CompletableDeferred<T>()
        val mine = AtomicBoolean(false)
        val callback = NfcAdapter.ReaderCallback { tag: Tag ->
            if (done.isCompleted) return@ReaderCallback
            val iso = IsoDep.get(tag) ?: return@ReaderCallback
            // A plug that came first keeps the step; a second tap after a
            // card that left too soon tries again.
            if (!mine.get()) {
                if (!taken.compareAndSet(false, true)) return@ReaderCallback
                mine.set(true)
            }
            try {
                iso.connect()
                iso.timeout = COMMAND_TIMEOUT_MS
                done.complete(block(CardLink.Apdu(SmartCard { apdu -> iso.transceive(apdu) })))
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
        return Reader(activity, adapter, done)
    }

    private const val TAG = "YubiKeyNfc"
}

/**
 * A YubiKey plugged into the phone's USB-C port: the app finds its CCID
 * interface (class 0x0B), asks the person to allow it, claims it and moves
 * the bytes of its bulk endpoints; the core frames each APDU (the transport
 * ccid_bulk, member/src/piv/ccid.rs).
 */
internal object YubiKeyUsb {
    /** The person did not allow the app to use the YubiKey on USB. */
    class Denied : Exception("the YubiKey on USB was not allowed")

    private const val ACTION = "tools.cbb.USB_PERMISSION"
    private const val READ_MS = 1_000
    private const val WRITE_MS = 5_000
    private const val ASK_MS = 60_000L

    fun hosts(context: Context): Boolean = context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)

    /** The first plugged-in device with a smart card interface, if any. */
    fun find(context: Context): UsbDevice? {
        if (!hosts(context)) return null
        val usb = context.getSystemService(Context.USB_SERVICE) as? UsbManager ?: return null
        return usb.deviceList.values.firstOrNull { d -> ccid(d) != null }
    }

    private fun ccid(d: UsbDevice): UsbInterface? =
        (0 until d.interfaceCount).map { d.getInterface(it) }.firstOrNull { it.interfaceClass == UsbConstants.USB_CLASS_CSCID }

    private suspend fun allow(context: Context, usb: UsbManager, d: UsbDevice) {
        if (usb.hasPermission(d)) return
        val answer = CompletableDeferred<Boolean>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                if (i.action == ACTION) answer.complete(i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false))
            }
        }
        ContextCompat.registerReceiver(context, receiver, IntentFilter(ACTION), ContextCompat.RECEIVER_NOT_EXPORTED)
        try {
            val intent = Intent(ACTION).setPackage(context.packageName)
            // Mutable, so that the system can add whether it was allowed.
            val pending = PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            usb.requestPermission(d, pending)
            val ok = withTimeoutOrNull(ASK_MS) { answer.await() } ?: false
            if (!ok) throw Denied()
        } finally {
            runCatching { context.unregisterReceiver(receiver) }
        }
    }

    suspend fun <T> withCard(context: Context, d: UsbDevice, block: (CardLink) -> T): T {
        val usb = context.getSystemService(Context.USB_SERVICE) as? UsbManager ?: throw YubiKeys.Unavailable()
        allow(context, usb, d)
        val face = ccid(d) ?: throw IOException("the USB device has no smart card interface")
        var input: UsbEndpoint? = null
        var output: UsbEndpoint? = null
        for (i in 0 until face.endpointCount) {
            val e = face.getEndpoint(i)
            if (e.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
            if (e.direction == UsbConstants.USB_DIR_IN) input = e else output = e
        }
        val bulkIn = input ?: throw IOException("the YubiKey's smart card interface has no bulk-in endpoint")
        val bulkOut = output ?: throw IOException("the YubiKey's smart card interface has no bulk-out endpoint")
        return withContext(Dispatchers.IO) {
            val conn: UsbDeviceConnection = usb.openDevice(d) ?: throw IOException("the YubiKey on USB did not open")
            try {
                if (!conn.claimInterface(face, true)) throw IOException("the YubiKey's smart card interface is busy")
                block(CardLink.Ccid(Bulk(usb, d, conn, bulkIn, bulkOut)))
            } finally {
                runCatching { conn.releaseInterface(face) }
                conn.close()
            }
        }
    }

    private class Bulk(
        val usb: UsbManager,
        val device: UsbDevice,
        val conn: UsbDeviceConnection,
        val input: UsbEndpoint,
        val output: UsbEndpoint,
    ) : CcidBulk {
        override fun write(data: ByteArray) {
            val n = conn.bulkTransfer(output, data, data.size, WRITE_MS)
            if (n != data.size) throw IOException("the YubiKey on USB took $n of ${data.size} bytes")
        }

        override fun read(max: Int): ByteArray {
            val buf = ByteArray(max)
            val n = conn.bulkTransfer(input, buf, max, READ_MS)
            if (n >= 0) return buf.copyOf(n)
            // -1 is a timeout or a device that left: only the second ends the step.
            if (usb.deviceList.values.none { it.deviceName == device.deviceName }) throw IOException("the YubiKey left the USB port")
            return ByteArray(0)
        }
    }
}

/**
 * Asks for the YubiKey's PIN before the phone waits for the card: title and
 * body say what follows; goLabel names the button that goes on, and other,
 * when given, a second way to go on. The PIN stays in memory only until the
 * card took it.
 */
@Composable
internal fun YubiKeyPinDialog(
    title: String,
    body: String,
    dismiss: () -> Unit,
    goLabel: String = stringResource(R.string.yubikey_go),
    other: Pair<String, (String) -> Unit>? = null,
    go: (String) -> Unit,
) {
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
                    // Six to eight characters, not only digits.
                    onValueChange = { v -> pin = v.take(8) },
                    singleLine = true,
                    label = { Text(stringResource(R.string.yubikey_pin)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                )
            }
        },
        confirmButton = {
            val ok = pin.toByteArray().size in 6..8
            Column(horizontalAlignment = Alignment.End) {
                TextButton(onClick = {
                    dismiss()
                    go(pin)
                }, enabled = ok) { Text(goLabel, color = palette.accent) }
                other?.let { (label, act) ->
                    TextButton(onClick = {
                        dismiss()
                        act(pin)
                    }, enabled = ok) { Text(label, color = palette.accent) }
                }
            }
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
