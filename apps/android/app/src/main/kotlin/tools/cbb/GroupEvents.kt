// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.annotation.StringRes
import org.json.JSONObject

/**
 * An event of the group the app notifies of (docs/apps.md, Notifications);
 * a paired watch shows the notification too. The twin of the iPhone app's.
 */
data class GroupEvent(val what: What, val name: String = "") {
    val kind: Kind get() = what.kind

    /** The settings, one for each kind of event, all on by default. */
    enum class Kind(val key: String, @StringRes val title: Int) {
        DEVICES("notify.devices", R.string.notify_devices),
        ADMINS("notify.admins", R.string.notify_admins),
        FROZEN("notify.frozen", R.string.notify_frozen),
        TAKEOVER("notify.takeover", R.string.notify_takeover),
        HUB("notify.hub", R.string.notify_hub),
    }

    enum class What(val kind: Kind, @StringRes val text: Int) {
        ADDED(Kind.DEVICES, R.string.event_added),
        REMOVED(Kind.DEVICES, R.string.event_removed),
        MADE_ADMIN(Kind.ADMINS, R.string.event_made_admin),
        FROZEN(Kind.FROZEN, R.string.event_frozen),
        UNFROZEN(Kind.FROZEN, R.string.event_unfrozen),
        TAKEN_OVER(Kind.TAKEOVER, R.string.event_taken_over),
        HUB_UNREACHABLE(Kind.HUB, R.string.away_error),
    }

    /** What the app knew of a device when it last looked. */
    data class Seen(val name: String, val admin: Boolean = false, val frozen: Boolean = false, val root: Boolean = false)

    companion object {
        fun seen(devices: List<LiveGroup.Device>): Map<String, Seen> =
            devices.filter { !it.isSelf }.associate { it.id to Seen(it.name, it.admin, it.frozen, it.isRoot) }

        /** The events between what the app saw before and what it sees now, in a fixed order: by name, removals after the rest. */
        fun between(old: Map<String, Seen>, new: Map<String, Seen>): List<GroupEvent> {
            val events = mutableListOf<GroupEvent>()
            for ((id, now) in new.entries.sortedBy { it.value.name }) {
                val was = old[id]
                if (was == null) {
                    events += GroupEvent(What.ADDED, now.name)
                    continue
                }
                if (now.root && !was.root) {
                    events += GroupEvent(What.TAKEN_OVER, now.name)
                } else if (now.admin && !was.admin) {
                    events += GroupEvent(What.MADE_ADMIN, now.name)
                }
                if (now.frozen != was.frozen) events += GroupEvent(if (now.frozen) What.FROZEN else What.UNFROZEN, now.name)
            }
            for ((id, was) in old.entries.sortedBy { it.value.name }) if (id !in new) events += GroupEvent(What.REMOVED, was.name)
            return events
        }

        fun encode(seen: Map<String, Seen>): String = JSONObject().apply {
            for ((id, s) in seen) put(id, JSONObject().put("name", s.name).put("admin", s.admin).put("frozen", s.frozen).put("root", s.root))
        }.toString()

        fun decode(text: String?): Map<String, Seen>? = text?.let {
            runCatching {
                val o = JSONObject(it)
                o.keys().asSequence().associateWith { id ->
                    val s = o.getJSONObject(id)
                    Seen(s.getString("name"), s.optBoolean("admin"), s.optBoolean("frozen"), s.optBoolean("root"))
                }
            }.getOrNull()
        }
    }
}

/**
 * Notifies of the group's events: compares the devices with what it saw
 * last time, whenever records arrive (the service keeps the connections in
 * the background) and at each refresh, and watches the tunnel while away
 * from home.
 */
class Notifier(private val context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private var failingSince: Long? = null
    private var hubNotified = false

    fun on(kind: GroupEvent.Kind): Boolean = prefs.getBoolean(kind.key, true)

    fun set(kind: GroupEvent.Kind, on: Boolean) = prefs.edit().putBoolean(kind.key, on).apply()

    /** Notifies of what changed since the last look; the first look only remembers. */
    @Synchronized
    fun observe(devices: List<LiveGroup.Device>) {
        if (devices.isEmpty()) return
        val now = GroupEvent.seen(devices)
        val old = GroupEvent.decode(prefs.getString(SEEN, null))
        if (old == now) return
        prefs.edit().putString(SEEN, GroupEvent.encode(now)).apply()
        if (old != null) GroupEvent.between(old, now).forEach(::post)
    }

    /** Forgets the group's devices and events, once the phone left its group: the next group's devices are not news of this one. */
    @Synchronized
    fun forget() {
        prefs.edit().remove(SEEN).apply()
        recent = emptyList()
        failingSince = null
        hubNotified = false
    }

    /** Notifies once when the hub has not answered through the tunnel for a while, and again only after it answered. */
    @Synchronized
    fun away(trying: Boolean, nowMS: Long = System.currentTimeMillis()) {
        if (!trying) {
            failingSince = null
            hubNotified = false
            return
        }
        val since = failingSince ?: nowMS.also { failingSince = it }
        if (!hubNotified && nowMS - since >= HUB_GRACE_MS) {
            hubNotified = true
            post(GroupEvent(GroupEvent.What.HUB_UNREACHABLE))
        }
    }

    /** The latest events, newest first, for the watch. */
    @Volatile
    var recent: List<String> = emptyList()
        private set

    /** Called after each event, for the watch. */
    var onEvent: (() -> Unit)? = null

    private fun post(e: GroupEvent) {
        val text = if (e.name.isEmpty()) context.getString(e.what.text) else context.getString(e.what.text, e.name)
        recent = (listOf(text) + recent).take(5)
        onEvent?.invoke()
        if (!on(e.kind)) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.channel_events), NotificationManager.IMPORTANCE_DEFAULT))
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val n = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.cbb_name))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setGroup(e.kind.key)
            .build()
        runCatching { nm.notify(next++, n) }.onFailure { Log.e(TAG, "notification not posted", it) }
    }

    companion object {
        private const val TAG = "cbb"
        private const val CHANNEL = "events"
        private const val SEEN = "events.seen"
        const val HUB_GRACE_MS = 120_000L

        /** Ids above the service's own notification. */
        private var next = 100
    }
}
