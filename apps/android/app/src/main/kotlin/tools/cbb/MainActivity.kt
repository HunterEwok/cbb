// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/** The app: one model for every screen, and later for the service and the tile. */
class CBBApp : Application() {
    val model: AppModel by lazy { AppModel(this) }

    override fun onCreate() {
        super.onCreate()
        // Push while the app is closed: the platform's token, when on.
        runCatching { PushSetup.start(this) }.onFailure { PushSetup.failed(this, it) }
    }
}

class MainActivity : ComponentActivity() {
    private val model get() = (application as CBBApp).model

    /** The chosen language, before anything reads a string. */
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(Settings.localized(base))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // adb shell am start -n tools.cbb/tools.cbb.MainActivity --ez ShowErrorDetails true
        // Any app can start this activity with extras, so a release build
        // takes the switch in Settings only.
        if (model.settings.takesErrorDetailsExtra && intent.hasExtra(Settings.ERROR_DETAILS)) {
            model.settings.showsErrorDetails = intent.getBooleanExtra(Settings.ERROR_DETAILS, false)
        }
        enableEdgeToEdge()
        setContent { Root(model) }
    }

    override fun onStart() {
        super.onStart()
        // The phone is the group's hub while the app is open (D-64).
        model.group.setForeground(true)
        // Turning the screen makes the activity again; that is no opening (D-128).
        if (!model.turning) model.sentOnOpen = false
        model.turning = false
        model.apkUpdate.runIfDue()
    }

    override fun onStop() {
        model.turning = isChangingConfigurations
        model.group.setForeground(false)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        // The prompt before the group's keys sign needs an activity in front.
        model.group.activity = this
    }

    /**
     * Android lets an app read the clipboard only while one of its windows
     * has the focus: once each time the app comes to the front. A system
     * overlay that took the focus (the notification shade, a prompt) gives
     * it back without an opening (D-128).
     */
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || model.sentOnOpen) return
        model.sentOnOpen = true
        lifecycleScope.launch { model.opened() }
    }

    override fun onPause() {
        if (model.group.activity === this) model.group.activity = null
        super.onPause()
    }
}
