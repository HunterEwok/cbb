// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

/**
 * The bug report's question in release mode (docs/core-api.md, "Bug
 * reports"): "Oops, something broke", Allow and Cancel, "Always allow"
 * after the user allowed twice, and a small "Technical details" link that
 * shows the report as it would go.
 */
@Composable
internal fun BugDialog(model: AppModel) {
    val offer = model.bug ?: return
    val palette = LocalPalette.current
    var always by remember(offer) { mutableStateOf(false) }
    var details by remember(offer) { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { model.cancelBug() },
        title = { Text(stringResource(R.string.bug_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                Text(stringResource(R.string.bug_text))
                if (offer.fixedIn.isNotEmpty()) Text(stringResource(R.string.bug_fixed_in, offer.fixedIn), color = palette.text)
                if (offer.offerAlways) {
                    Row(Modifier.clickable { always = !always }, verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = always, onCheckedChange = { always = it })
                        Text(stringResource(R.string.bug_always))
                    }
                }
                Text(
                    stringResource(R.string.bug_details),
                    style = MaterialTheme.typography.labelSmall,
                    color = palette.accent,
                    modifier = Modifier.clickable { details = !details },
                )
                if (details) {
                    SelectionContainer {
                        Text(
                            offer.text,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.heightIn(max = 240.dp).verticalScroll(rememberScrollState()),
                        )
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { model.allowBug(always) }) { Text(stringResource(R.string.bug_allow)) } },
        dismissButton = { TextButton(onClick = { model.cancelBug() }) { Text(stringResource(R.string.bug_cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}
