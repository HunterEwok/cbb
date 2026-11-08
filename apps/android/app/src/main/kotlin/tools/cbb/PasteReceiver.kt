// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import tools.cbb.kit.Commands
import tools.cbb.kit.Member
import tools.cbb.kit.RemotePaste
import java.io.File
import java.io.IOException

/**
 * This phone as a remote paste target (docs/design.md, "Remote paste"):
 * a paste command an admin signed puts its text into the focused text
 * field of another app, through the accessibility service, once this
 * phone's user turned remote paste on. It keeps the switches, the limits
 * per sender and the log of the last pastes (never their text), and shows
 * a notification with the sender. When the user sends pastes to the
 * Bluetooth keyboard instead, the keyboard types them on its host.
 */
class PasteReceiver(private val context: Context, dir: File, private val keyboard: BluetoothKeyboard) {
    private val settingsFile = File(dir, "paste-receive")
    private val logFile = File(dir, "pastes.json")
    private val limiter = RemotePaste.Limiter()

    var settings: RemotePaste.Settings
        get() = runCatching { RemotePaste.Settings.decode(settingsFile.readBytes()) }.getOrDefault(RemotePaste.Settings())
        set(s) = save(settingsFile, s.encode())

    /** The last pastes, oldest first. */
    val log: List<RemotePaste.Entry>
        get() = runCatching { RemotePaste.decodeLog(logFile.readBytes()) }.getOrDefault(emptyList())

    /**
     * Carries out a paste command that Commands.verify took, from sender
     * (RecordSet.commandSender), verified when the records show that the
     * device by names signed; name is that device's, when known.
     */
    fun paste(body: Commands.Body, sender: String, verified: Boolean, name: String?, image: () -> Pair<File, String>): Member.CommandResult {
        val set = settings
        val nowMS = System.currentTimeMillis()
        val res = when {
            !set.on -> refused(body, "remote paste is off on this device; its user turns it on in the app's settings")
            body.enter && !set.enter -> refused(body, "this device takes pastes without Enter only; its user allows Enter in the app's settings")
            !limiter.allow(sender, nowMS) -> refused(body, "too many pastes: at most one a second and 30 a minute from one device")
            body.kind == "media" -> injectImage(body, image)
            else -> inject(body, RemotePaste.clean(body.text ?: ""))
        }
        val who = if (verified) body.by else "${body.by} (unverified)"
        if (res.status == "done") {
            Log.i(TAG, "$who pasted ${body.text?.length ?: 0} characters here")
            notifyPasted(name ?: body.by)
        } else {
            Log.w(TAG, "a paste from $who: ${res.status}: ${res.reason}")
        }
        if (body.kind != "secret") {
            val e = RemotePaste.Entry(
                nowMS, body.by, name, (body.text ?: "").toByteArray().size, body.mode ?: "paste",
                body.enter, res.status, res.reason, !verified,
            )
            try {
                save(logFile, RemotePaste.encodeLog(RemotePaste.appended(log, e)))
            } catch (e: IOException) {
                Log.e(TAG, "keeping the paste log", e)
            }
        }
        return res
    }

    /** Turns remote paste off, as a paste-off command from any admin does. */
    fun turnOff(): Member.CommandResult? = try {
        settings = RemotePaste.Settings()
        null
    } catch (e: IOException) {
        Log.e(TAG, "turning remote paste off", e)
        Member.CommandResult("", "failed", e.message)
    }

    /** Deletes the log of pastes, which names the group's devices, as when the phone leaves its group. */
    fun forgetLog() {
        logFile.delete()
    }

    private fun inject(body: Commands.Body, text: String): Member.CommandResult {
        if (text.isEmpty()) return refused(body, "the text has nothing that may be pasted: only control characters")
        val k = keyboard.settings
        if (k.on && k.pastes) return typeOnHost(body, text)
        val target = CopyWatcher.running ?: return refused(
            body,
            if (CopyWatcher.isOn(context)) {
                // On in the settings but not bound: the system stopped it, as Android TV 14 does with some services.
                "CBB's accessibility service is on in the settings but the system stopped it; its user turns it off and on again"
            } else {
                "this device pastes through CBB's accessibility service, which is off; its user turns it on in the app's settings"
            },
        )
        return when (val r = target.inject(text, body.mode ?: "paste", body.enter, body.kind == "secret")) {
            null -> Member.CommandResult(body.id, "done")
            else -> Member.CommandResult(body.id, if (r.refused) "refused" else "failed", r.reason)
        }
    }

    /** Why a paste of images or files did not go in. */
    class NotPasted(message: String, val refused: Boolean = true) : Exception(message)

    /**
     * Pastes the image of the group's copy that body names into the focused
     * text field: image fetches it, the accessibility service puts it on the
     * clipboard and pastes it. The Bluetooth keyboard types only text.
     */
    private fun injectImage(body: Commands.Body, image: () -> Pair<File, String>): Member.CommandResult {
        val k = keyboard.settings
        if (k.on && k.pastes) return refused(body, "this device sends its pastes to the Bluetooth keyboard, which types only text")
        val target = CopyWatcher.running ?: return refused(body, "this device pastes through CBB's accessibility service, which is off; its user turns it on in the app's settings")
        val (file, alt) = try {
            image()
        } catch (e: NotPasted) {
            return Member.CommandResult(body.id, if (e.refused) "refused" else "failed", e.message)
        }
        return when (val r = target.injectImage(file, alt, body.enter)) {
            null -> Member.CommandResult(body.id, "done")
            else -> Member.CommandResult(body.id, if (r.refused) "refused" else "failed", r.reason)
        }
    }

    /**
     * Types the text on the Bluetooth keyboard's host. Keys go straight in
     * there, so a line break presses Enter: a text with one is refused
     * unless the user allowed Enter, as for a typed paste on a computer.
     */
    private fun typeOnHost(body: Commands.Body, text: String): Member.CommandResult {
        if ('\n' in text && !settings.enter) {
            return refused(body, "the text has a line break, which the Bluetooth keyboard types as Enter; this device's user allows Enter in the app's settings")
        }
        val f = keyboard.type(if (body.enter) text + "\n" else text) ?: return Member.CommandResult(body.id, "done")
        return Member.CommandResult(body.id, if (f.refused) "refused" else "failed", f.reason)
    }

    private fun refused(body: Commands.Body, reason: String) = Member.CommandResult(body.id, "refused", reason)

    private fun notifyPasted(name: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.channel_pastes), NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.cbb_name))
            .setContentText(context.getString(R.string.pasted_from, name))
            .setAutoCancel(true)
            .setTimeoutAfter(60_000)
            .build()
        runCatching { nm.notify(NOTIFICATION, n) }.onFailure { Log.e(TAG, "notification not posted", it) }
    }

    private fun save(f: File, data: ByteArray) {
        f.parentFile?.mkdirs()
        val tmp = File(f.parentFile, f.name + ".tmp")
        tmp.writeBytes(data)
        if (!tmp.renameTo(f)) throw IOException("cannot save ${f.name}")
    }

    companion object {
        private const val TAG = "cbb"
        private const val CHANNEL = "pastes"
        private const val NOTIFICATION = 0x70617374
    }
}
