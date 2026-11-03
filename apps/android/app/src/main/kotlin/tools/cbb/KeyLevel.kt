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
import tools.cbb.kit.Records as KitRecords
import kotlinx.coroutines.launch

/**
 * Settings' admin keys, on the root phone (docs/guide/keys.md, "The three
 * levels"): which devices may be the group's admins and hubs.
 */
@Composable
internal fun KeyLevelSection(model: AppModel, level: String) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    Section(stringResource(R.string.key_level_title)) {
        for ((value, title) in listOf(
            KitRecords.PROVEN to R.string.key_level_proven,
            KitRecords.HARDWARE to R.string.key_level_hardware,
            KitRecords.LEVEL_FILES to R.string.key_level_files,
        )) {
            Choice(stringResource(title), selected = value == level) {
                if (!busy && value != level) {
                    busy = true
                    scope.launch {
                        model.setKeyLevel(value)
                        busy = false
                    }
                }
            }
        }
        model.keyLevelNote?.let { NoteText(it) }
        Text(
            stringResource(R.string.key_level_body),
            Modifier.padding(Tokens.spacingMedium),
            style = MaterialTheme.typography.bodyMedium,
            color = palette.textDim,
        )
    }
}
