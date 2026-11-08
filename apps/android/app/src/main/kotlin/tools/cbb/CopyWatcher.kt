// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.Resources
import android.graphics.PixelFormat
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import android.view.accessibility.AccessibilityNodeInfo
import tools.cbb.kit.Member
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * "Send my copies by themselves" (docs/apps.md, "Android: the clipboard
 * without taps"): an accessibility service that notices a copy, a click on
 * a "Copy" action or the system's clipboard overlay of Android 13 and
 * later, and then takes the input focus for a moment with a 1-pixel
 * overlay, reads the clipboard and sends it. If the overlay does not get
 * the focus, SendActivity does the same. It reads nothing on the screen
 * beyond what tells it that a copy happened.
 *
 * It is also the phone's remote paste target (docs/design.md, "Remote
 * paste"; PasteReceiver): it puts a text into the focused text field of
 * another app, through the clipboard and ACTION_PASTE, or ACTION_SET_TEXT
 * where the field takes no paste and for typing, and presses Enter with
 * ACTION_IME_ENTER.
 */
class CopyWatcher : AccessibilityService() {
    private val main = Handler(Looper.getMainLooper())
    private val scope = MainScope()
    private var overlay: View? = null
    private var lastCopy = 0L
    private val tv: Boolean by lazy { Tv.isTv(this) }

    /** Until when a copy is the service's own paste, not the user's. */
    private var pastingUntil = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        running = this
    }

    /** The labels of a copy action: the platform's in the system's language, and English. */
    private val copyLabels: Set<String> by lazy {
        setOfNotNull(runCatching { Resources.getSystem().getString(android.R.string.copy) }.getOrNull(), "Copy", "Copy text", "Copy link")
            .map { it.lowercase() }.toSet()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val copied = when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_CLICKED -> isCopy(event)
            AccessibilityEvent.TYPE_WINDOWS_CHANGED -> clipboardOverlayShown()
            else -> false
        }
        if (copied) {
            Clipboard.changed()
            copied()
        }
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        if (running === this) running = null
        removeOverlay()
        scope.cancel()
        super.onDestroy()
    }

    private fun isCopy(e: AccessibilityEvent): Boolean {
        val words = (e.text.map { it.toString() } + listOfNotNull(e.contentDescription?.toString())).map { it.trim().lowercase() }
        return words.any { it in copyLabels }
    }

    /** Whether the system's clipboard overlay, which Android 13 and later show after each copy, is on screen. */
    private fun clipboardOverlayShown(): Boolean = runCatching {
        windows.any { w -> w.title?.toString()?.contains("clipboard", ignoreCase = true) == true }
    }.getOrDefault(false)

    /**
     * A copy happened: once per second at most, take the focus and send, in
     * a sync mode that sends this phone's copies. Not on a TV, where the
     * service is only the paste target.
     */
    private fun copied() {
        if (tv) return
        if (!Member.sends((application as CBBApp).model.group.syncMode)) return
        val now = SystemClock.elapsedRealtime()
        if (now < pastingUntil || now - lastCopy < 1_000) return
        lastCopy = now
        // The app that copied sets the clipboard right after the click.
        main.postDelayed({ focusAndSend() }, 150)
    }

    private fun focusAndSend() {
        if (overlay != null) return
        val wm = getSystemService(WindowManager::class.java)
        val view = object : View(this) {
            override fun onWindowFocusChanged(hasWindowFocus: Boolean) {
                super.onWindowFocusChanged(hasWindowFocus)
                if (hasWindowFocus) {
                    val text = Clipboard.readForAutoSend(context)
                    removeOverlay()
                    if (text != null) send(text)
                }
            }
        }
        val params = WindowManager.LayoutParams(
            1,
            1,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT,
        ).apply { gravity = Gravity.TOP or Gravity.START }
        if (runCatching { wm.addView(view, params) }.isFailure) {
            startActivity(SendActivity.intent(this, auto = true))
            return
        }
        overlay = view
        main.postDelayed({
            if (overlay === view) {
                // No focus: the transparent activity gets it instead.
                removeOverlay()
                startActivity(SendActivity.intent(this, auto = true))
            }
        }, 700)
    }

    private fun removeOverlay() {
        val v = overlay ?: return
        overlay = null
        runCatching { getSystemService(WindowManager::class.java).removeView(v) }
    }

    private fun send(text: String) {
        val model = (application as CBBApp).model
        scope.launch { runCatching { withContext(Dispatchers.IO) { model.group.send(text) } } }
    }

    /** Why a paste did not go in: refused, or failed. */
    data class InjectFailure(val reason: String, val refused: Boolean = true)

    /** Puts text into the focused text field, on the main thread; null when it did. */
    fun inject(text: String, method: String, enter: Boolean, secret: Boolean): InjectFailure? {
        if (method != "paste" && method != "type") return InjectFailure("this phone pastes or types, not $method")
        val done = CompletableFuture<InjectFailure?>()
        main.post {
            done.complete(
                try {
                    injectNow(text, method, enter, secret)
                } catch (e: RuntimeException) {
                    Log.e(TAG, "a paste failed", e)
                    InjectFailure("the paste failed: $e", refused = false)
                },
            )
        }
        return try {
            done.get(5, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            InjectFailure("the accessibility service did not answer", refused = false)
        }
    }

    /**
     * Puts a received image into the focused text field, on the main thread:
     * on the clipboard through the app's FileProvider, then ACTION_PASTE. The
     * clipboard keeps it, as the group's copy it is. Null when it went in.
     */
    fun injectImage(file: File, alt: String, enter: Boolean): InjectFailure? {
        val done = CompletableFuture<InjectFailure?>()
        main.post {
            done.complete(
                try {
                    injectImageNow(file, alt, enter)
                } catch (e: RuntimeException) {
                    Log.e(TAG, "a paste of an image failed", e)
                    InjectFailure("the paste failed: $e", refused = false)
                },
            )
        }
        return try {
            done.get(5, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            InjectFailure("the accessibility service did not answer", refused = false)
        }
    }

    private fun injectImageNow(file: File, alt: String, enter: Boolean): InjectFailure? {
        if (getSystemService(KeyguardManager::class.java).isKeyguardLocked) return InjectFailure("the phone is locked")
        if (enter && Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return InjectFailure("this phone presses Enter from Android 11 on; send the image without Enter")
        val node = findFocus(AccessibilityNodeInfo.FOCUS_INPUT)?.takeIf { it.isEditable }
            ?: return InjectFailure("no text field has the focus on this phone")
        pastingUntil = SystemClock.elapsedRealtime() + 2_000
        Clipboard.writeImage(this, file, alt)
        if (!node.performAction(AccessibilityNodeInfo.ACTION_PASTE)) return InjectFailure("the text field took no paste", refused = false)
        if (enter && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            !node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
        ) {
            return InjectFailure("the image is in, but the text field took no Enter", refused = false)
        }
        return null
    }

    private fun injectNow(text: String, method: String, enter: Boolean, secret: Boolean): InjectFailure? {
        if (getSystemService(KeyguardManager::class.java).isKeyguardLocked) return InjectFailure("the phone is locked")
        if (enter && Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return InjectFailure("this phone presses Enter from Android 11 on; send the text without Enter")
        val node = findFocus(AccessibilityNodeInfo.FOCUS_INPUT)?.takeIf { it.isEditable }
            ?: return InjectFailure(if (tv) "no text field has the focus on this TV: open a search or text field with the remote first" else "no text field has the focus on this phone")
        val ok = if (method == "paste") paste(node, text, secret) else insert(node, text)
        if (!ok) return InjectFailure("the text field took no text", refused = false)
        // Enter before Android 11 returned above; the check is repeated here for lint, which
        // since the Android Gradle plugin 9.5 does not follow that return.
        if (enter && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            !node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
        ) {
            return InjectFailure("the text is in, but the text field took no Enter", refused = false)
        }
        return null
    }

    /** Pastes through the clipboard, which gets its item back after half a second unless the user copied meanwhile; a field that takes no paste gets the text set. */
    private fun paste(node: AccessibilityNodeInfo, text: String, secret: Boolean): Boolean {
        val cm = getSystemService(ClipboardManager::class.java)
        val prev = runCatching { cm.primaryClip }.getOrNull()
        val clip = ClipData.newPlainText("cbb", text)
        if (secret) clip.description.extras = PersistableBundle().apply { putBoolean(Clipboard.SENSITIVE, true) }
        pastingUntil = SystemClock.elapsedRealtime() + 2_000
        cm.setPrimaryClip(clip)
        val ok = node.performAction(AccessibilityNodeInfo.ACTION_PASTE) || insert(node, text)
        main.postDelayed({
            val now = runCatching { cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString() }.getOrNull()
            if (now == text) {
                pastingUntil = SystemClock.elapsedRealtime() + 2_000
                if (prev != null) cm.setPrimaryClip(prev) else cm.clearPrimaryClip()
            }
        }, RESTORE_AFTER_MS)
        return ok
    }

    /** Puts text in place of the field's selection, the cursor after it. */
    private fun insert(node: AccessibilityNodeInfo, text: String): Boolean {
        val old = if (node.isShowingHintText) "" else node.text?.toString() ?: ""
        var start = node.textSelectionStart.takeIf { it in 0..old.length } ?: old.length
        var end = node.textSelectionEnd.takeIf { it in 0..old.length } ?: start
        if (start > end) start = end.also { end = start }
        val args = Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, old.substring(0, start) + text + old.substring(end)) }
        if (!node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)) return false
        val at = start + text.length
        node.performAction(
            AccessibilityNodeInfo.ACTION_SET_SELECTION,
            Bundle().apply {
                putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_START_INT, at)
                putInt(AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_END_INT, at)
            },
        )
        return true
    }

    companion object {
        private const val TAG = "cbb"

        /** How long the app with the focus has to read a pasted text before the clipboard gets its item back. */
        private const val RESTORE_AFTER_MS = 500L

        /** The service while it runs: the phone's remote paste target. */
        @Volatile
        var running: CopyWatcher? = null
            private set

        /** Whether the user turned the service on. */
        fun isOn(context: Context): Boolean =
            context.getSystemService(AccessibilityManager::class.java)
                .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .any { it.resolveInfo.serviceInfo.packageName == context.packageName && it.resolveInfo.serviceInfo.name == CopyWatcher::class.java.name }
    }
}
