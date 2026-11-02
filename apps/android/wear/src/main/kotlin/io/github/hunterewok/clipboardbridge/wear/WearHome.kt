// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.wear

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.wear.compose.foundation.lazy.ScalingLazyColumn
import androidx.wear.compose.foundation.lazy.rememberScalingLazyListState
import androidx.wear.compose.material3.AlertDialog
import androidx.wear.compose.material3.AlertDialogDefaults
import androidx.wear.compose.material3.AppScaffold
import androidx.wear.compose.material3.Button
import androidx.wear.compose.material3.ColorScheme
import androidx.wear.compose.material3.ListHeader
import androidx.wear.compose.material3.MaterialTheme
import androidx.wear.compose.material3.ScreenScaffold
import androidx.wear.compose.material3.SwitchButton
import androidx.wear.compose.material3.Text
import io.github.hunterewok.clipboardbridge.FormGlyph
import io.github.hunterewok.clipboardbridge.Palette
import io.github.hunterewok.clipboardbridge.WatchState
import io.github.hunterewok.clipboardbridge.paletteNamed

/**
 * The main page: how many devices are online, the away switch, the devices
 * and the latest events; on a watch that is an admin, a device opens its
 * emergency actions.
 */
@Composable
fun WearHome(model: WearModel) {
    // A watch is dark.
    val palette = paletteNamed(model.state.color).dark
    var open by remember { mutableStateOf<String?>(null) }
    MaterialTheme(colorScheme = scheme(palette)) {
        AppScaffold {
            val device = open?.let { id -> model.state.devices.firstOrNull { it.id == id } }
            if (device != null) {
                BackHandler { open = null }
                DevicePage(model, device, palette)
                return@AppScaffold
            }
            val list = rememberScalingLazyListState()
            ScreenScaffold(scrollState = list) { padding ->
                ScalingLazyColumn(
                    state = list,
                    contentPadding = padding,
                    modifier = Modifier.fillMaxSize().background(palette.background),
                ) {
                    item { ListHeader { Text("CBB", color = palette.accent) } }
                    val s = model.state
                    if (!s.hasGroup) {
                        item { Text(stringResource(R.string.no_group), color = palette.textDim, textAlign = TextAlign.Center) }
                        return@ScalingLazyColumn
                    }
                    item {
                        Text(
                            stringResource(R.string.online_count, s.devices.count { it.online }, s.devices.size),
                            style = MaterialTheme.typography.titleMedium,
                            color = palette.text,
                        )
                    }
                    s.away?.let { away ->
                        item {
                            SwitchButton(
                                checked = away != WatchState.Away.OFF,
                                onCheckedChange = { model.setAway(it) },
                                enabled = !model.switching,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text(stringResource(R.string.away)) },
                                secondaryLabel = { Text(stringResource(awayLine(away))) },
                            )
                        }
                    }
                    model.note?.let { n ->
                        item {
                            Text(
                                stringResource(n.text) + (n.detail?.let { "\n\n" + it } ?: ""),
                                color = palette.danger,
                                style = MaterialTheme.typography.bodySmall,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                    // The devices in no collection, then each of the phone's collections.
                    for ((name, ds) in s.sections) {
                        if (name != null && ds.isEmpty()) continue
                        item { ListHeader { Text(name ?: stringResource(R.string.devices), color = palette.textDim) } }
                        items(ds.size) { i ->
                            val d = ds[i]
                            DeviceRow(d, palette, if (model.admin && d.can.isNotEmpty()) ({ open = d.id }) else null)
                        }
                    }
                    if (s.events.isNotEmpty()) {
                        item { ListHeader { Text(stringResource(R.string.latest), color = palette.textDim) } }
                        items(s.events.size) { i ->
                            Text(s.events[i], color = palette.text, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth())
                        }
                    }
                    if (model.admin) {
                        item { Text(stringResource(R.string.watch_admin), color = palette.textDim, style = MaterialTheme.typography.bodySmall) }
                    }
                    if (!model.reachable) {
                        item { Text(stringResource(R.string.stale), color = palette.textDim, style = MaterialTheme.typography.bodySmall) }
                    }
                }
            }
        }
    }
}

@Composable
private fun DeviceRow(d: WatchState.Device, palette: Palette, onClick: (() -> Unit)?) {
    val state = stringResource(if (d.online) R.string.online else R.string.offline)
    Row(
        Modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier).padding(horizontal = 8.dp, vertical = 6.dp).semantics(mergeDescendants = true) { stateDescription = state },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FormGlyph(d.form, if (d.online) palette.accent else palette.textDim, 20.dp)
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(d.name, color = palette.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (d.phone) Text(stringResource(R.string.watch_phone), color = palette.textDim, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.width(8.dp))
        Box(Modifier.size(8.dp).clip(CircleShape).background(if (d.online) palette.accent else palette.textDim.copy(alpha = 0.4f)))
    }
}

/**
 * The emergency actions this watch has for one device (docs/protocol.md,
 * section 10, "Watches"): each asks for a tap on what it signs, then the watch
 * signs it with its own key.
 */
@Composable
private fun DevicePage(model: WearModel, d: WatchState.Device, palette: Palette) {
    var asking by remember { mutableStateOf<Pair<String, String?>?>(null) }
    val list = rememberScalingLazyListState()
    ScreenScaffold(scrollState = list) { padding ->
        ScalingLazyColumn(
            state = list,
            contentPadding = padding,
            modifier = Modifier.fillMaxSize().background(palette.background),
        ) {
            item { ListHeader { Text(d.name, color = palette.text, maxLines = 1, overflow = TextOverflow.Ellipsis) } }
            val buttons = d.can.flatMap { a -> if (a == "action") d.actions.map { a to it } else listOf(a to null) }
            items(buttons.size) { i ->
                val (a, name) = buttons[i]
                Button(
                    onClick = { asking = a to name },
                    enabled = !model.acting,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(name ?: stringResource(actionTitle(a))) },
                )
            }
            model.actionNote?.let { n ->
                item {
                    Text(
                        stringResource(n.text) + (n.detail?.let { "\n\n" + it } ?: ""),
                        color = if (model.actionDone) palette.accent else palette.danger,
                        style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
    val q = asking
    AlertDialog(
        visible = q != null,
        onDismissRequest = { asking = null },
        title = { Text(q?.let { question(it.first, it.second, d.name) } ?: "", textAlign = TextAlign.Center) },
        confirmButton = {
            AlertDialogDefaults.ConfirmButton(onClick = {
                asking = null
                q?.let { model.run(it.first, d.id, it.second) }
            })
        },
        dismissButton = { AlertDialogDefaults.DismissButton(onClick = { asking = null }) },
    )
}

private fun actionTitle(action: String): Int = when (action) {
    "freeze" -> R.string.act_freeze
    "remove" -> R.string.act_remove
    "paste-off" -> R.string.act_paste_off
    "actions-off" -> R.string.act_actions_off
    else -> R.string.act_away_off
}

@Composable
private fun question(action: String, name: String?, device: String): String = when (action) {
    "freeze" -> stringResource(R.string.ask_freeze, device)
    "remove" -> stringResource(R.string.ask_remove, device)
    "paste-off" -> stringResource(R.string.ask_paste_off, device)
    "actions-off" -> stringResource(R.string.ask_actions_off, device)
    "away-off" -> stringResource(R.string.ask_away_off, device)
    else -> stringResource(R.string.ask_action, name ?: "", device)
}

private fun awayLine(away: WatchState.Away): Int = when (away) {
    WatchState.Away.OFF -> R.string.away_off
    WatchState.Away.AT_HOME -> R.string.away_at_home
    WatchState.Away.CONNECTING -> R.string.away_connecting
    WatchState.Away.CONNECTED -> R.string.away_connected
    WatchState.Away.WAITING -> R.string.away_waiting
}

/** The phone's colour on the watch's dark theme. */
private fun scheme(p: Palette) = ColorScheme(
    primary = p.accent,
    onPrimary = p.onAccent,
    background = p.background,
    onBackground = p.text,
    surfaceContainerLow = p.surface,
    surfaceContainer = p.surface,
    surfaceContainerHigh = p.surface,
    onSurface = p.text,
    onSurfaceVariant = p.textDim,
    error = p.danger,
)
