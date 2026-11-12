// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The Quick Settings tile, the house (docs/apps.md): a tap turns sync on
 * this phone on or off, as Home's house does; a long press opens the app,
 * which takes the tile's preferences intent. On, the clipboard is filled;
 * off, it is grey and struck through. Without a group a tap opens the app.
 */
class SyncTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val model get() = (application as CBBApp).model

    override fun onStartListening() {
        super.onStartListening()
        show()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()
        if (!model.group.hasGroup) return open()
        // Quick Settings also open on a locked phone: there the phone is
        // unlocked first, as the iPhone's control asks for Face ID.
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }

    private fun toggle() {
        val on = model.group.syncMode == "own"
        scope.launch {
            model.turnSync(on)
            show()
        }
    }

    private fun show() {
        val tile = qsTile ?: return
        val group = model.group
        val on = group.hasGroup && group.syncMode != "own"
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.icon = Icon.createWithResource(this, if (on) R.drawable.ic_notification else R.drawable.ic_tile_sync_off)
        tile.contentDescription = getString(if (on) R.string.tile_sync_on else R.string.tile_sync_off)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(if (!group.hasGroup) R.string.tile_no_group else if (on) R.string.tile_on else R.string.tile_off)
        }
        tile.updateTile()
    }

    // The Intent form, only below Android 14, where the PendingIntent one does not exist.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun open() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 3, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    companion object {
        /** Asks the system to draw the tile again: sync changed in the app or by an admin's command. */
        fun changed(context: Context) {
            runCatching { requestListeningState(context, ComponentName(context, SyncTileService::class.java)) }
        }
    }
}
