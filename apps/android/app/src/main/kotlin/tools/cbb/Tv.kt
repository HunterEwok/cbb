// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.UiModeManager
import android.content.Context
import android.content.res.Configuration

/**
 * The app on a TV (Android TV, Google TV, Fire OS; docs/apps.md, "Android
 * TV"): the same APK, which there joins a phone's group by the QR code it
 * shows, as a member without an admin key, takes pastes and receives
 * copies. The camera, its own copies and the watch are a phone's.
 */
object Tv {
    fun isTv(context: Context): Boolean =
        context.getSystemService(UiModeManager::class.java)?.currentModeType == Configuration.UI_MODE_TYPE_TELEVISION
}
