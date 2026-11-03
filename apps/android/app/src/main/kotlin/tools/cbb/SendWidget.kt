// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.widget.RemoteViews

/** The home-screen widget "Send clipboard": one tap sends what the phone copied, through SendActivity, as the tile does. */
class SendWidget : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        val tap = PendingIntent.getActivity(context, 3, SendActivity.intent(context), PendingIntent.FLAG_IMMUTABLE)
        val views = RemoteViews(context.packageName, R.layout.widget_send).apply { setOnClickPendingIntent(R.id.widget_send, tap) }
        manager.updateAppWidget(ids, views)
    }
}
