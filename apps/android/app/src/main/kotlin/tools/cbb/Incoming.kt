// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch

/** The choices Settings offers, in milliseconds; the group's own value joins them when it is another. */
private val INCOMING_CHOICES = listOf(15_000L, 30_000L, 60_000L, 120_000L, 300_000L, 600_000L)

/**
 * Settings' copies from other devices, on an admin phone (docs/design.md,
 * "The one button"): how long a copy from another device stays live after
 * it is copied, a setting of the whole group.
 */
@Composable
internal fun IncomingSection(model: AppModel, ms: Long) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    Section(stringResource(R.string.incoming_title)) {
        for (value in (INCOMING_CHOICES + ms).distinct().sorted()) {
            Choice(incomingLabel(value), selected = value == ms) {
                if (!busy && value != ms) {
                    busy = true
                    scope.launch {
                        model.setIncoming(value)
                        busy = false
                    }
                }
            }
        }
        model.incomingNote?.let { NoteText(it) }
        Tip(R.string.incoming_body, Modifier.padding(Tokens.spacingMedium))
    }
}

@Composable
private fun incomingLabel(ms: Long): String {
    val s = ms / 1000
    return if (s >= 60 && s % 60 == 0L) stringResource(R.string.incoming_minutes, s / 60) else stringResource(R.string.incoming_seconds, s)
}
