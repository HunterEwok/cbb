// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.wear

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.lifecycleScope

/**
 * The Wear OS app: the group's devices as the phone sees them, the latest
 * events and the switch for sync away from home (docs/apps.md, Wear OS),
 * the twin of the Apple Watch app. It works only through the paired phone.
 */
class MainActivity : ComponentActivity() {
    private lateinit var model: WearModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        model = WearModel(applicationContext, lifecycleScope)
        setContent { WearHome(model) }
    }

    override fun onResume() {
        super.onResume()
        model.start()
    }

    override fun onPause() {
        model.stop()
        super.onPause()
    }
}
