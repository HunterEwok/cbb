// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch

/**
 * Leaving the group (D-83, docs/design.md, "Leaving the group"): the
 * button and its question, in Settings and on the card of a removed phone;
 * why it did not leave shows under it.
 */
@Composable
internal fun LeaveButton(model: AppModel) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var asking by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf<AppModel.Note?>(null) }
    QuietButton(stringResource(R.string.leave_group), enabled = !model.busy, onClick = { asking = true }, modifier = Modifier.fillMaxWidth())
    failed?.let { NoteText(it) }
    if (asking) {
        AlertDialog(
            onDismissRequest = { asking = false },
            title = { Text(stringResource(R.string.leave_question)) },
            text = { Text(stringResource(R.string.leave_text)) },
            confirmButton = {
                TextButton(onClick = {
                    asking = false
                    scope.launch { failed = if (model.leave()) null else model.message }
                }) { Text(stringResource(R.string.leave_group), color = palette.danger) }
            },
            dismissButton = { TextButton(onClick = { asking = false }) { Text(stringResource(R.string.back)) } },
            containerColor = palette.surface,
            titleContentColor = palette.text,
            textContentColor = palette.textDim,
        )
    }
}

/** Settings' section with the button, and what leaving does. */
@Composable
internal fun LeaveSection(model: AppModel) {
    Section(stringResource(R.string.leave_group)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Text(
                stringResource(if (model.isRoot) R.string.leave_footer_root else R.string.leave_footer),
                style = MaterialTheme.typography.bodyMedium,
                color = LocalPalette.current.textDim,
            )
            LeaveButton(model)
        }
    }
}

/** On Home, when the group removed this phone: it syncs with nobody, so the card offers to leave and join again. */
@Composable
internal fun RemovedCard(model: AppModel) {
    if (!model.removed) return
    val palette = LocalPalette.current
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Text(stringResource(R.string.removed_self_title), style = MaterialTheme.typography.titleMedium, color = palette.danger)
        Text(stringResource(R.string.removed_self_text), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        LeaveButton(model)
    }
}
