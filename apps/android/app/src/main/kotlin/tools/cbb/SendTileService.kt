// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** The Quick Settings tile "Send clipboard": one tap sends what the phone copied, through SendActivity. */
class SendTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        qsTile?.apply {
            state = Tile.STATE_INACTIVE
            updateTile()
        }
    }

    // The Intent form, only below Android 14, where the PendingIntent one does not exist.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    override fun onClick() {
        super.onClick()
        val intent = SendActivity.intent(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 2, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
