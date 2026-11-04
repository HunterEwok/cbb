// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.wear

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import com.google.android.gms.wearable.DataClient
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.Wearable
import tools.cbb.WatchState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.security.Signature

/**
 * The group as the phone last told it, and the away switch, which asks the
 * phone; Compose state, changed on the main thread.
 */
class WearModel(private val context: Context, private val scope: CoroutineScope) : DataClient.OnDataChangedListener {
    /** A note under the switch, with the error underneath when details are on. */
    data class Note(@StringRes val text: Int, val detail: String? = null)

    var state by mutableStateOf(WatchState())
        private set

    /** Whether the phone is connected now; the state may be old without it. */
    var reachable by mutableStateOf(true)
        private set
    var switching by mutableStateOf(false)
        private set
    var note by mutableStateOf<Note?>(null)
        private set

    /** Whether the root phone certified this watch's admin key (WatchKey). */
    var admin by mutableStateOf(false)
        private set

    /** Whether an emergency action is on its way, and what the last one said. */
    var acting by mutableStateOf(false)
        private set
    var actionNote by mutableStateOf<Note?>(null)
        private set
    var actionDone by mutableStateOf(false)
        private set

    private val data = Wearable.getDataClient(context)

    fun start() {
        admin = WatchKey.admission(context) != null
        data.addListener(this)
        scope.launch {
            try {
                val items = data.dataItems.await()
                try {
                    items.firstOrNull { it.uri.path == WatchState.STATE_PATH }?.let { take(it.data) }
                } finally {
                    items.release()
                }
                reachable = Wearable.getNodeClient(context).connectedNodes.await().isNotEmpty()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "no state from the phone", e)
            }
        }
    }

    fun stop() {
        data.removeListener(this)
    }

    override fun onDataChanged(events: DataEventBuffer) {
        for (e in events) {
            if (e.type == DataEvent.TYPE_CHANGED && e.dataItem.uri.path == WatchState.STATE_PATH) take(e.dataItem.data)
        }
    }

    private fun take(bytes: ByteArray?) {
        WatchState.decode(bytes)?.let {
            state = it
            forgetIfLeft(it)
        }
        reachable = true
    }

    /** Forgets the admin key once the phone is in no group or in another one than the root certified the key in: the phone left its group (D-83). */
    private fun forgetIfLeft(s: WatchState) {
        val a = WatchKey.admission(context) ?: return
        if (s.hasGroup && (s.group == null || s.group == a.group)) return
        WatchKey.forget(context)
        admin = false
        Log.i(TAG, "the phone left the group: the watch's admin key is deleted")
    }

    /** Turns the phone's sync away from home on or off, as its Settings do. */
    fun setAway(on: Boolean) {
        if (switching) return
        switching = true
        note = null
        val before = state
        scope.launch {
            try {
                val nodes = Wearable.getNodeClient(context).connectedNodes.await()
                reachable = nodes.isNotEmpty()
                if (nodes.isEmpty()) {
                    note = Note(R.string.no_phone)
                    return@launch
                }
                val messages = Wearable.getMessageClient(context)
                nodes.forEach { messages.sendMessage(it.id, WatchState.AWAY_PATH, byteArrayOf(if (on) 1 else 0)).await() }
                // The phone answers with its new state; the same state when it could not switch.
                withTimeoutOrNull(ANSWER_MS) { snapshotFlow { state }.first { it != before } }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "away not switched", e)
                note = Note(R.string.no_answer, if (showsDetails) e.toString() else null)
            } finally {
                switching = false
            }
        }
    }

    /** The phone's body says something else than the watch asked. */
    class Mismatch : Exception("the phone's body is not what the watch asked")

    /** The phone did not do it, and says why. */
    class Refused(val why: String) : Exception(why)

    /**
     * Runs an emergency action (docs/protocol.md, section 10, "Watches"): the
     * phone builds the body, the watch checks that it says what was asked,
     * signs it with its admin key, which works only while the watch is
     * unlocked, and the phone brings the result into the group.
     */
    fun run(action: String, device: String, name: String? = null) {
        val a = WatchKey.admission(context) ?: return
        if (acting) return
        acting = true
        actionNote = null
        actionDone = false
        scope.launch {
            try {
                val node = Wearable.getNodeClient(context).connectedNodes.await().firstOrNull()
                reachable = node != null
                if (node == null) {
                    actionNote = Note(R.string.no_phone)
                    return@launch
                }
                val ask = WatchState.Ask(action, device, name, a.device)
                val reply = ask(node.id, WatchState.ASK_PATH, ask.encode())
                val body = reply.body ?: throw Refused(reply.refused ?: "")
                check(body, ask, a)
                val key = WatchKey.adminKey(context) ?: throw IllegalStateException("no admin key")
                val sig = Signature.getInstance("SHA256withECDSA").run {
                    initSign(key)
                    update(body)
                    sign()
                }
                val done = ask(node.id, WatchState.SIGNED_PATH, WatchState.Signed(body, sig, a.adminCA).encode())
                if (!done.done) throw Refused(done.refused ?: "")
                actionDone = true
                actionNote = Note(R.string.done)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Refused) {
                actionNote = if (e.why.isEmpty()) Note(R.string.not_done) else Note(R.string.not_done_because, e.why)
            } catch (e: Exception) {
                Log.e(TAG, "emergency action failed", e)
                actionNote = Note(R.string.not_signed, if (showsDetails) e.toString() else null)
            } finally {
                acting = false
            }
        }
    }

    /** Sends a message to the phone and waits for its answer, which WearListener hands over. */
    private suspend fun ask(node: String, path: String, bytes: ByteArray): WatchState.Answer {
        val d = CompletableDeferred<WatchState.Answer>()
        answer = d
        try {
            Wearable.getMessageClient(context).sendMessage(node, path, bytes).await()
            return withTimeoutOrNull(ACTION_MS) { d.await() } ?: throw Refused("")
        } finally {
            if (answer === d) answer = null
        }
    }

    /** As the phone's setting says, and always in a debug build. */
    private val showsDetails: Boolean
        get() = state.details || (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    companion object {
        private const val TAG = "cbb"
        private const val ANSWER_MS = 10_000L

        /** The phone may wait for a member's answer to a command (25 s) before it says done. */
        private const val ACTION_MS = 30_000L

        /** The answer the running action waits for. */
        @Volatile
        private var answer: CompletableDeferred<WatchState.Answer>? = null

        /** The phone's answer on BODY_PATH or DONE_PATH, from WearListener. */
        fun answered(data: ByteArray?) {
            WatchState.Answer.decode(data)?.let { answer?.complete(it) }
        }

        /**
         * Whether body, which the phone built, says what the watch asked:
         * the type, the group, the watch as its signer and, for a command,
         * its device and quick action. The keys a freeze or a removal names
         * are the phone's to pick; the watch cannot check them.
         */
        fun check(body: ByteArray, ask: WatchState.Ask, a: WatchState.Admission) {
            val o = runCatching { JSONObject(String(body)) }.getOrNull() ?: throw Mismatch()
            val type = if (ask.action == "remove") "revoke" else ask.action
            if (o.optString("type") != type || o.optString("group") != a.group || o.optString("by") != a.device) throw Mismatch()
            if (type != "freeze" && type != "revoke") {
                if (o.optString("to") != ask.device) throw Mismatch()
                if (type == "action" && o.optString("action") != ask.name) throw Mismatch()
            }
        }
    }
}
