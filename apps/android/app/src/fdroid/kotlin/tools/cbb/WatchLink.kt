// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context

/**
 * The F-Droid build's WatchLink: no Wear OS watch, which only Google Play
 * services reach (the full build's WatchLink, in src/full, and docs/apps.md,
 * "F-Droid"). Settings offers no watch, and the rest of the app works as on
 * a phone without Play services.
 */
object WatchLink {
    /** Whether this build can reach a watch at all: Settings offers one only then. */
    const val available = false

    /** No watch to tell. */
    fun update(context: Context, model: AppModel) {}

    /** No watch connected, or it did not answer in time. */
    class NotReachable : Exception("no watch answered")

    /** The watch has no secure lock screen. */
    class NotProtected : Exception("the watch has no secure lock screen")

    suspend fun keyRequest(context: Context): WatchState.KeyRequest = throw NotReachable()

    suspend fun admit(context: Context, a: WatchState.Admission): Unit = throw NotReachable()
}
