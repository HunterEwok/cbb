// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The one button without the app's screens, for a moment and transparent:
 * from the Quick Settings tile, the notification, the "cbb send" launcher
 * entry (for Quick Tap or a back-tap app), Share and the selection menu.
 * Once it has the input focus it reads the clipboard, which only an app
 * with the focus may, sends or fetches by the Home button's rule (or sends
 * the shared or selected text), says what it did in a toast and closes.
 * It is not exported: the tile, the notification and the widget open it
 * from this app. Another app reaches only OutsideSendActivity.
 */
open class SendActivity : Activity() {
    /** Whether another app opened it (OutsideSendActivity). */
    protected open val outside = false

    private val scope = MainScope()
    private var started = false

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(Settings.localized(base))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val model = (application as CBBApp).model
        if (!model.group.hasGroup) {
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || started || isFinishing) return
        started = true
        if (!outside) {
            // A copy CopyWatcher sends by itself stays on the phone when it is marked sensitive.
            if (intent.getBooleanExtra(AUTO, false) && Clipboard.sensitive(this)) {
                finish()
                return
            }
            send(null)
            return
        }
        val model = (application as CBBApp).model
        val text = sharedText(intent)
        val app = launchedBy()
        val streams = if (text == null) sharedStreams(intent) else emptyList()
        if (streams.isNotEmpty()) {
            if (app != null && app in model.settings.allowedApps) sendStreams(streams) else askStreams(streams, app)
            return
        }
        when {
            app != null && app in model.settings.allowedApps -> send(text)
            // The launcher entry, from the home screen or Quick Tap.
            text == null && app != null && app in system() -> send(null)
            else -> ask(text, app)
        }
    }

    /**
     * Asks whether to send the text that another app handed over, or, with
     * none, whether to sync: syncing may put the computers' latest text on
     * the clipboard, where the app that opened this one could read it.
     */
    private fun ask(text: String?, app: String?) {
        val model = (application as CBBApp).model
        var answered = false
        val name = app?.let { label(it) } ?: getString(R.string.share_unknown_app)
        val b = AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
        if (text != null) {
            b.setTitle(R.string.share_confirm_title).setMessage(getString(R.string.share_confirm_body, name, text.length))
        } else {
            b.setTitle(R.string.outside_sync_title).setMessage(getString(R.string.outside_sync_body, name))
        }
        b.setPositiveButton(R.string.share_allow) { _, _ ->
            answered = true
            send(text)
        }
        // "Always" holds for this app only, and only when Android names it.
        if (app != null) {
            b.setNeutralButton(R.string.share_always) { _, _ ->
                answered = true
                model.settings.allowedApps = model.settings.allowedApps + app
                send(text)
            }
        }
        b.setNegativeButton(android.R.string.cancel, null)
            .setOnDismissListener { if (!answered) finish() }
            .show()
    }

    /** Asks whether to send the images or files another app handed over. */
    private fun askStreams(streams: List<Uri>, app: String?) {
        val model = (application as CBBApp).model
        var answered = false
        val name = app?.let { label(it) } ?: getString(R.string.share_unknown_app)
        val b = AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle(R.string.share_files_title)
            .setMessage(getString(R.string.share_files_body, name, streams.size))
            .setPositiveButton(R.string.share_allow) { _, _ ->
                answered = true
                sendStreams(streams)
            }
        if (app != null) {
            b.setNeutralButton(R.string.share_always) { _, _ ->
                answered = true
                model.settings.allowedApps = model.settings.allowedApps + app
                sendStreams(streams)
            }
        }
        b.setNegativeButton(android.R.string.cancel, null)
            .setOnDismissListener { if (!answered) finish() }
            .show()
    }

    private fun sendStreams(streams: List<Uri>) {
        val model = (application as CBBApp).model
        scope.launch {
            val note = model.sendShared(streams)
            Toast.makeText(this@SendActivity, getString(note.text), Toast.LENGTH_LONG).show()
            finish()
        }
    }

    /**
     * The package of the app that opened this activity, as Android recorded
     * it; null when the intent names a referrer itself, which any app may
     * put there.
     */
    private fun launchedBy(): String? {
        if (intent.hasExtra(Intent.EXTRA_REFERRER) || intent.hasExtra(Intent.EXTRA_REFERRER_NAME)) return null
        val r = referrer ?: return null
        return r.host?.takeIf { r.scheme == "android-app" && it.isNotEmpty() && it != packageName }
    }

    /** The home screens and the system, which open the launcher entry. */
    private fun system(): Set<String> {
        val home = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        val homes = packageManager.queryIntentActivities(home, PackageManager.MATCH_DEFAULT_ONLY).map { it.activityInfo.packageName }
        return homes.toSet() + setOf("android", "com.android.systemui")
    }

    private fun label(pkg: String): String =
        runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)

    private fun send(text: String?) {
        val model = (application as CBBApp).model
        scope.launch {
            val note = model.syncFromOutside(text)
            Toast.makeText(this@SendActivity, getString(note.text), Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        /** Whether CopyWatcher opened it for a copy it sends by itself. */
        private const val AUTO = "tools.cbb.extra.AUTO"

        /** The button; auto when CopyWatcher sends a copy by itself, which skips a sensitive one. */
        fun intent(context: Context, auto: Boolean = false): Intent =
            Intent(context, SendActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
                .putExtra(AUTO, auto)

        /** The images or files of Share, by their content URIs. */
        @Suppress("DEPRECATION") // the typed getters are API 33+
        fun sharedStreams(intent: Intent?): List<Uri> = when (intent?.action) {
            Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM))
            Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM).orEmpty()
            else -> emptyList()
        }

        /** The text of Share or of the selection menu; null to use the clipboard. */
        fun sharedText(intent: Intent?): String? = when (intent?.action) {
            Intent.ACTION_SEND -> intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }?.takeIf { it.isNotEmpty() }
    }
}

/**
 * The exported entries: Share, the selection menu and the "cbb send"
 * launcher entry (for Quick Tap or a back-tap app). Any app can open it, so
 * it asks first, unless the user allowed that app always, or the home
 * screen or the system opened the launcher entry.
 */
class OutsideSendActivity : SendActivity() {
    override val outside = true
}
