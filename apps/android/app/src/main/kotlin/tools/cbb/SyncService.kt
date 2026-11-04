// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder

/**
 * Keeps the app running while there is a group, so that its connections to
 * the computers stay and what they copy lands on the phone's clipboard by
 * itself (docs/apps.md, "Android: the clipboard without taps"). Android
 * requires the ongoing notification; its Send button sends what the phone
 * copied.
 */
class SyncService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val model = (application as CBBApp).model
        if (!model.group.hasGroup) {
            stopSelf()
            return START_NOT_STICKY
        }
        val n = notification(this)
        startForeground(NOTIFICATION, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        return START_STICKY
    }

    companion object {
        private const val CHANNEL = "sync"
        private const val NOTIFICATION = 1

        /** Starts the service when there is a group; from the app in front, or at boot. */
        fun start(context: Context) {
            if (!(context.applicationContext as CBBApp).model.group.hasGroup) return
            runCatching { context.startForegroundService(Intent(context, SyncService::class.java)) }
        }

        /** Stops the service, once the phone left its group. */
        fun stop(context: Context) {
            context.stopService(Intent(context, SyncService::class.java))
        }

        private fun notification(context: Context): Notification {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, context.getString(R.string.channel_sync), NotificationManager.IMPORTANCE_LOW).apply {
                    setShowBadge(false)
                },
            )
            val open = PendingIntent.getActivity(
                context,
                0,
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE,
            )
            val send = PendingIntent.getActivity(context, 1, SendActivity.intent(context), PendingIntent.FLAG_IMMUTABLE)
            return Notification.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(context.getString(R.string.notification_title))
                .setContentText(context.getString(R.string.notification_text))
                .setContentIntent(open)
                .setOngoing(true)
                .addAction(Notification.Action.Builder(null, context.getString(R.string.send), send).build())
                .build()
        }
    }
}

/** Starts the service after the phone starts, when there is a group. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) SyncService.start(context)
    }
}
