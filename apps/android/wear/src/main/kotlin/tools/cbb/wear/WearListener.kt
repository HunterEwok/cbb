// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.wear

import android.provider.Settings
import android.util.Log
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import tools.cbb.WatchState

/**
 * The root phone's messages that certify the watch's admin key
 * (WatchKey): Play services start it when the phone asks, and it answers
 * the node that asked. The phone's answers to an emergency action go to
 * the WearModel that waits for them.
 */
class WearListener : WearableListenerService() {
    override fun onMessageReceived(event: MessageEvent) {
        val answer = when (event.path) {
            WatchState.CERTIFY_PATH -> WatchState.KEY_PATH to request().encode()
            WatchState.ADMITTED_PATH -> {
                val a = WatchState.Admission.decode(event.data)
                val kept = a != null && WatchKey.admit(this, a)
                WatchState.ADMITTED_PATH to (if (kept) a.device else "").toByteArray()
            }
            WatchState.BODY_PATH, WatchState.DONE_PATH -> return WearModel.answered(event.data)
            else -> return
        }
        Wearable.getMessageClient(this).sendMessage(event.sourceNodeId, answer.first, answer.second)
            .addOnFailureListener { Log.e(TAG, "no answer sent to the phone", it) }
    }

    private fun request(): WatchState.KeyRequest = try {
        val name = Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME) ?: "Wear OS"
        WatchKey.request(this, name)
    } catch (e: WatchKey.NotProtected) {
        WatchState.KeyRequest(refused = WatchState.NOT_PROTECTED)
    } catch (e: Exception) {
        Log.e(TAG, "no admin key made", e)
        WatchState.KeyRequest(refused = e.toString())
    }

    companion object {
        private const val TAG = "cbb"
    }
}
