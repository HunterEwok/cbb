// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.util.Log
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.PutDataRequest
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withTimeout

/**
 * The phone's side of the Wear OS app (../wear): it hands the watch the
 * group as the app sees it, in a data item of the Wearable Data Layer, and
 * turns sync away from home on or off when the watch asks (docs/apps.md,
 * Wear OS); on the root phone it asks the watch for its admin key and hands
 * it the admin CA (docs/protocol.md, section 10, "Watches"). Without Google
 * Play services there is no watch to tell. This is the full build's; the
 * F-Droid build's (src/fdroid) has no watch.
 */
object WatchLink {
    private const val TAG = "clipboardbridge"

    /** Whether this build can reach a watch at all: Settings offers one only then. */
    const val available = true
    private var last: WatchState? = null
    private var failed = false

    /** Sends the state when it changed; on the main thread. */
    fun update(context: Context, model: AppModel) {
        if (Tv.isTv(context)) return // a TV has no watch
        val state = state(model)
        if (state == last) return
        last = state
        val request = PutDataRequest.create(WatchState.STATE_PATH).setData(state.encode()).setUrgent()
        Wearable.getDataClient(context.applicationContext).putDataItem(request)
            .addOnSuccessListener { failed = false }
            .addOnFailureListener { e ->
                last = null
                // Once: a phone without Play services fails every time.
                if (!failed) Log.i(TAG, "watch not updated", e)
                failed = true
            }
    }

    /** No watch connected, or it did not answer in time. */
    class NotReachable : Exception("no watch answered")

    /** The watch has no secure lock screen. */
    class NotProtected : Exception("the watch has no secure lock screen")

    private var keyAnswer: CompletableDeferred<WatchState.KeyRequest>? = null
    private var admittedAnswer: CompletableDeferred<String>? = null

    /** Asks the connected watch to make a new admin key. */
    suspend fun keyRequest(context: Context): WatchState.KeyRequest {
        val answer = CompletableDeferred<WatchState.KeyRequest>().also { keyAnswer = it }
        send(context, WatchState.CERTIFY_PATH, ByteArray(0))
        val r = try {
            withTimeout(ANSWER_MS) { answer.await() }
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            throw NotReachable()
        }
        when (r.refused) {
            null -> return r
            WatchState.NOT_PROTECTED -> throw NotProtected()
            else -> throw IllegalStateException(r.refused)
        }
    }

    /** Hands the watch the admin CA the root issued for its key. */
    suspend fun admit(context: Context, a: WatchState.Admission) {
        val answer = CompletableDeferred<String>().also { admittedAnswer = it }
        send(context, WatchState.ADMITTED_PATH, a.encode())
        val kept = try {
            withTimeout(ANSWER_MS) { answer.await() }
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            throw NotReachable()
        }
        if (kept != a.device) throw IllegalStateException("the watch did not keep its admin CA")
    }

    private suspend fun send(context: Context, path: String, data: ByteArray) {
        val nodes = Wearable.getNodeClient(context.applicationContext).connectedNodes.await()
        if (nodes.isEmpty()) throw NotReachable()
        val messages = Wearable.getMessageClient(context.applicationContext)
        nodes.forEach { messages.sendMessage(it.id, path, data).await() }
    }

    /** The watch's answers, from WatchListener. */
    internal fun answered(path: String, data: ByteArray) {
        when (path) {
            WatchState.KEY_PATH -> WatchState.KeyRequest.decode(data)?.let { keyAnswer?.complete(it) }
            WatchState.ADMITTED_PATH -> admittedAnswer?.complete(String(data))
        }
    }

    private const val ANSWER_MS = 15_000L

    fun state(model: AppModel) = WatchState(
        hasGroup = model.phase == AppModel.Phase.HOME,
        // The phone itself first, as the phone's own list has it; then in the
        // user's order, a collection's devices one after another.
        devices = model.devices.filter { it.isSelf }.map { WatchState.Device(it.id, it.name, it.kind.form, true, phone = true) } +
            model.arranged.flatMap { item ->
            when (item) {
                is AppModel.Arranged.Device -> listOf(item.device to null)
                is AppModel.Arranged.Collection -> item.devices.map { it to item.collection.name }
            }
        }.map { (d, c) -> WatchState.Device(d.id, d.name, d.kind.form, d.online, model.group.watchActions(d.id), d.actions, c) },
        away = model.away?.let { a ->
            if (!a.on) {
                WatchState.Away.OFF
            } else {
                when (a.status) {
                    AwayFromHome.Status.AT_HOME -> WatchState.Away.AT_HOME
                    AwayFromHome.Status.CONNECTING -> WatchState.Away.CONNECTING
                    AwayFromHome.Status.CONNECTED -> WatchState.Away.CONNECTED
                    AwayFromHome.Status.OFF, AwayFromHome.Status.WAITING_FOR_HUB -> WatchState.Away.WAITING
                }
            }
        },
        events = model.notifier.recent,
        // The wallpaper's colours are the phone's own; the watch takes the default.
        color = model.color.takeIf { c -> Tokens.colors.any { it.name == c } } ?: Tokens.colors.first().name,
        details = model.settings.showsErrorDetails,
    )
}

/** The watch's away switch, the same as the one in Settings; Play services start it when the watch asks. */
class WatchListener : WearableListenerService() {
    /**
     * The watch's emergency actions (docs/protocol.md, section 10, "Watches"):
     * the body it asks for, or what it signed brought into the group; the
     * answer goes back to the watch that asked.
     */
    private fun emergency(event: MessageEvent) {
        val model = (application as ClipboardBridgeApp).model
        val (path, answer) = runBlocking(Dispatchers.Main) {
            try {
                if (event.path == WatchState.ASK_PATH) {
                    val ask = WatchState.Ask.decode(event.data) ?: throw IllegalArgumentException("not an ask")
                    WatchState.BODY_PATH to WatchState.Answer(body = model.group.watchBody(ask))
                } else {
                    val signed = WatchState.Signed.decode(event.data) ?: throw IllegalArgumentException("not a signed action")
                    model.group.deliverFromWatch(signed)
                    model.refresh()
                    WatchState.DONE_PATH to WatchState.Answer(done = true)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val note = model.describe(e)
                val back = if (event.path == WatchState.ASK_PATH) WatchState.BODY_PATH else WatchState.DONE_PATH
                back to WatchState.Answer(refused = getString(note.text) + (note.detail?.let { "\n\n" + it } ?: ""))
            }
        }
        Wearable.getMessageClient(this).sendMessage(event.sourceNodeId, path, answer.encode())
            .addOnFailureListener { Log.e("clipboardbridge", "no answer sent to the watch", it) }
    }

    override fun onMessageReceived(event: MessageEvent) {
        if (event.path == WatchState.KEY_PATH || event.path == WatchState.ADMITTED_PATH) return WatchLink.answered(event.path, event.data)
        if (event.path == WatchState.ASK_PATH || event.path == WatchState.SIGNED_PATH) return emergency(event)
        if (event.path != WatchState.AWAY_PATH) return
        val on = event.data.firstOrNull() == 1.toByte()
        val model = (application as ClipboardBridgeApp).model
        // On a thread of Play services': the model changes on the main thread.
        runBlocking(Dispatchers.Main) {
            model.refresh()
            model.setAway(on)
        }
    }
}
