// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch

/** The choices Settings offers, in milliseconds, within the copies record's bounds (D-129); the group's own value joins them when it is another. */
private val COPY_CHOICES = listOf(60_000L, 300_000L, 900_000L, 1_800_000L, 3_600_000L)
private val SECRET_CHOICES = listOf(5_000L, 15_000L, 30_000L, 60_000L)

/**
 * Settings' copy lifetime and secret lifetime, on an admin phone (docs/design.md, "Sync
 * model", D-129): how long a copy and a secret live, settings of the whole
 * group. A copy's lifetime ends the last received line and the push hint;
 * a secret also leaves the clipboard when its time is up.
 */
@Composable
internal fun LifetimeSection(model: AppModel, ms: Pair<Long, Long>) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    fun set(copy: Long?, secret: Long?) {
        if (busy) return
        busy = true
        scope.launch {
            model.setTtl(copy, secret)
            busy = false
        }
    }
    Section(stringResource(R.string.ttl_copies)) {
        for (value in (COPY_CHOICES + ms.first).distinct().sorted()) {
            Choice(lifetimeLabel(value), selected = value == ms.first) { if (value != ms.first) set(value, null) }
        }
    }
    Section(stringResource(R.string.ttl_secrets)) {
        for (value in (SECRET_CHOICES + ms.second).distinct().sorted()) {
            Choice(lifetimeLabel(value), selected = value == ms.second) { if (value != ms.second) set(null, value) }
        }
        model.ttlNote?.let { NoteText(it) }
        Tip(R.string.ttl_body, Modifier.padding(Tokens.spacingMedium))
    }
}

@Composable
private fun lifetimeLabel(ms: Long): String {
    val s = ms / 1000
    return if (s >= 60 && s % 60 == 0L) stringResource(R.string.ttl_minutes, s / 60) else stringResource(R.string.ttl_seconds, s)
}
