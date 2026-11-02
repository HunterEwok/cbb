// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * One device: a summary of what it is and where it stands, then what an
 * admin phone may do with it (docs/apps.md, Devices). A page of its own on
 * a phone; on a big screen a pane beside the devices, which close hides.
 */
@Composable
internal fun DeviceDetail(model: AppModel, id: String, close: (() -> Unit)? = null, back: () -> Unit) {
    val d = model.devices.firstOrNull { it.id == id }
    // Removed here or by another admin: back to the devices.
    LaunchedEffect(d == null) { if (d == null) back() }
    if (d == null) return
    val content: @Composable ColumnScope.() -> Unit = {
        Header(d, close)
        Summary(d)
        Actions(model, d)
        model.message?.let { NoteText(it, dim = true) }
    }
    if (close == null) {
        Page(d.name, back, content)
    } else {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
            verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
            content = content,
        )
    }
}

@Composable
private fun Header(d: LiveGroup.Device, close: (() -> Unit)?) {
    val palette = LocalPalette.current
    Row(verticalAlignment = Alignment.Top) {
        DeviceIcon(d, 64.dp)
        Column(Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium).semantics(mergeDescendants = true) {}) {
            Text(d.name, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, maxLines = 2)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OnlineDot(d.online)
                Text(
                    stringResource(if (d.online) R.string.online else R.string.offline),
                    color = if (d.online) palette.accent else palette.textDim,
                    modifier = Modifier.padding(start = 6.dp),
                )
            }
        }
        if (close != null) IconText("✕", stringResource(R.string.close), onClick = close)
    }
}

/** A row of the summary: what it is, and its value. */
private data class Line(val label: String, val value: String, val mono: Boolean = false, val dim: Boolean = false)

/** What the group knows of it, a row each. */
@Composable
private fun Summary(d: LiveGroup.Device) {
    val palette = LocalPalette.current
    val lines = buildList {
        add(Line(stringResource(R.string.type), stringResource(d.kind.title)))
        d.systemWithVersion?.let { add(Line(stringResource(R.string.operating_system), it)) }
        d.device?.version?.let { add(Line(stringResource(R.string.cbb_name), it, mono = true)) }
        val mac = d.device?.mac
        if (mac != null) {
            add(Line(stringResource(R.string.mac_address), mac, mono = true))
        } else if (d.kind == DeviceKind.PHONE || d.kind == DeviceKind.TABLET) {
            add(Line(stringResource(R.string.mac_address), stringResource(R.string.hidden_by_system), dim = true))
        }
        add(Line(stringResource(R.string.role), stringResource(roleTitle(d.role, d.rootless))))
        d.standing?.let { add(Line(stringResource(R.string.in_the_group), stringResource(it))) }
        d.mode?.let { m -> modeTitle(m)?.let { add(Line(stringResource(R.string.sync_mode), stringResource(it))) } }
    }
    Column(Modifier.fillMaxWidth().card()) {
        lines.forEachIndexed { i, line ->
            if (i > 0) HorizontalDivider(color = palette.line)
            Row(
                Modifier.fillMaxWidth().heightIn(min = 44.dp).padding(horizontal = Tokens.spacingMedium).semantics(mergeDescendants = true) {},
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(line.label, color = palette.textDim, modifier = Modifier.padding(end = Tokens.spacingMedium))
                Text(
                    line.value,
                    fontFamily = if (line.mono) FontFamily.Monospace else null,
                    color = if (line.dim) palette.textDim else Color.Unspecified,
                    textAlign = TextAlign.End,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

/** A rootless install is never an admin or a hub (D-79), so its role says so. */
private fun roleTitle(role: String, rootless: Boolean) = when (role) {
    "phone" -> R.string.role_phone
    "lite" -> if (rootless) R.string.role_lite_rootless else R.string.role_lite
    "shortcut" -> R.string.role_shortcut
    "watch" -> R.string.kind_watch
    else -> if (rootless) R.string.role_full_rootless else R.string.role_full
}

/** The sync modes, in the order the apps show them (docs/design.md, Sync modes). */
private val modes = listOf("own", "shared", "receive", "send")

private fun modeTitle(mode: String) = when (mode) {
    "own" -> R.string.mode_own
    "shared" -> R.string.mode_shared
    "receive" -> R.string.mode_receive
    "send" -> R.string.mode_send
    else -> null
}

private fun modeNote(mode: String) = when (mode) {
    "own" -> R.string.mode_own_note
    "shared" -> R.string.mode_shared_note
    "receive" -> R.string.mode_receive_note
    else -> R.string.mode_send_note
}

/** The actions an admin phone has for it; a phone that is no admin has only its own sync mode. */
@Composable
private fun Actions(model: AppModel, d: LiveGroup.Device) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var removing by remember { mutableStateOf(false) }
    var promoting by remember { mutableStateOf(false) }
    var thawing by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf(false) }
    var choosingMode by remember { mutableStateOf(false) }
    var pasting by remember { mutableStateOf(false) }
    var acting by remember { mutableStateOf(false) }
    if (choosingMode) ModeChoice(d, dismiss = { choosingMode = false }) { mode -> scope.launch { model.setMode(d.id, mode) } }
    // Every phone sets its own sync mode; an admin sets any other device's.
    if (!model.isAdmin) {
        if (d.isSelf) {
            Column(Modifier.fillMaxWidth().card()) { Action("⇄", stringResource(R.string.sync_mode)) { choosingMode = true } }
        } else {
            Text(stringResource(R.string.not_admin_note), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
        }
        return
    }
    Column(Modifier.fillMaxWidth().card()) {
        Action("✎", stringResource(R.string.rename)) { renaming = true }
        if (d.frozen) {
            HorizontalDivider(color = palette.line)
            Action("❄", stringResource(R.string.unfreeze)) { thawing = true }
        }
        if (d.canMakeAdmin) {
            HorizontalDivider(color = palette.line)
            Action("★", stringResource(R.string.make_admin)) { promoting = true }
        }
        // A phone or lite member from before 0.5 has no mode and refuses.
        if (d.isSelf || d.online) {
            HorizontalDivider(color = palette.line)
            Action("⇄", stringResource(R.string.sync_mode)) { choosingMode = true }
        }
        // Computers, lite members and Android phones take pastes; iPhones cannot.
        if (!d.isSelf && (d.role == "full" || d.role == "lite" || (d.role == "phone" && d.os == "android"))) {
            HorizontalDivider(color = palette.line)
            Action("⌨", stringResource(R.string.paste_on_it)) { pasting = true }
        }
        // Computers run quick actions; the lite member reboots and restarts.
        if (!d.isSelf && d.online && (d.role == "full" || d.role == "lite")) {
            HorizontalDivider(color = palette.line)
            Action("⚡", stringResource(R.string.quick_actions)) { acting = true }
        }
        if (!d.isSelf) {
            HorizontalDivider(color = palette.line)
            Action("✕", stringResource(R.string.remove), danger = true) { removing = true }
        }
    }
    if (removing) {
        Confirm(
            title = stringResource(R.string.remove_title, d.name),
            body = stringResource(if (d.isRoot) R.string.remove_root_body else R.string.remove_body),
            action = stringResource(R.string.remove),
            dismiss = { removing = false },
        ) { scope.launch { model.remove(d.id) } }
    }
    if (promoting) {
        Confirm(
            title = stringResource(R.string.make_admin_title, d.name),
            body = stringResource(if (d.keysInFile) R.string.make_admin_body else R.string.make_admin_hardware_body),
            action = stringResource(R.string.make_admin),
            dismiss = { promoting = false },
        ) { scope.launch { model.makeAdmin(d.id) } }
    }
    if (pasting) PasteOn(model, d, dismiss = { pasting = false })
    if (acting) QuickActions(model, d, dismiss = { acting = false })
    if (renaming) Rename(d, dismiss = { renaming = false }) { name -> scope.launch { model.rename(d.id, name) } }
    if (thawing) {
        Confirm(
            title = stringResource(R.string.unfreeze_title, d.name),
            body = stringResource(R.string.unfreeze_body),
            action = stringResource(R.string.unfreeze),
            dismiss = { thawing = false },
        ) { scope.launch { model.unfreeze(d.id) } }
    }
}

/**
 * Remote paste (docs/design.md, "Remote paste"): a text to put where a
 * computer's focus is, pasted or typed, with Enter after it if asked. The
 * computer takes it only when its user turned remote paste on there.
 */
@Composable
private fun PasteOn(model: AppModel, d: LiveGroup.Device, dismiss: () -> Unit) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var text by rememberSaveable { mutableStateOf("") }
    var typing by rememberSaveable { mutableStateOf(false) }
    var enter by rememberSaveable { mutableStateOf(false) }
    var secret by rememberSaveable { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.message = null }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.paste_on_title, d.name)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                Text(stringResource(R.string.paste_on_body, d.name))
                OutlinedTextField(
                    value = text, onValueChange = { text = it }, minLines = 3, maxLines = 10,
                    label = { Text(stringResource(R.string.paste_text)) },
                    supportingText = { Text(stringResource(R.string.paste_empty_clipboard)) },
                )
                // Why the device did not take it, right under the text.
                model.message?.takeIf { !sending }?.let { NoteText(it) }
                Switch(stringResource(R.string.paste_type), typing) { typing = it }
                Switch(stringResource(R.string.paste_enter), enter) { enter = it }
                Switch(stringResource(R.string.paste_secret), secret) { secret = it }
                Text(stringResource(R.string.paste_note), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            TextButton(enabled = !sending, onClick = {
                // An empty field sends what the phone's clipboard holds.
                val out = text.ifEmpty { clipText(context).orEmpty() }
                if (out.isEmpty()) {
                    model.message = AppModel.Note(R.string.paste_clipboard_empty, error = true)
                    return@TextButton
                }
                sending = true
                scope.launch {
                    val done = model.paste(d.id, out, if (typing) "type" else "paste", enter, secret)
                    sending = false
                    if (done) dismiss()
                }
            }) { Text(stringResource(R.string.paste), color = palette.accent) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

/** The title of a quick action: the presets in words, the user's own by name. */
@Composable
private fun actionTitle(name: String): String = when (name) {
    "lock" -> stringResource(R.string.action_lock)
    "sleep" -> stringResource(R.string.action_sleep)
    "reboot" -> stringResource(R.string.action_reboot)
    "shutdown" -> stringResource(R.string.action_shutdown)
    "cancel-shutdown" -> stringResource(R.string.action_cancel)
    "restart" -> stringResource(R.string.action_restart)
    else -> name
}

/**
 * The quick actions a computer's hello says are on (docs/protocol.md,
 * section 15): one tap runs one, reboot and shut down ask again. The
 * computer defines each; its user turns them on there, and any admin turns
 * them all off from here.
 */
@Composable
private fun QuickActions(model: AppModel, d: LiveGroup.Device, dismiss: () -> Unit) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var sending by remember { mutableStateOf(false) }
    var confirming by remember { mutableStateOf<String?>(null) }
    var off by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.message = null }
    fun run(name: String) {
        sending = true
        scope.launch {
            val done = model.runAction(d.id, name)
            sending = false
            if (done) dismiss()
        }
    }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.quick_actions_title, d.name)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (d.actions.isEmpty()) Text(stringResource(R.string.quick_actions_none, d.name))
                for (a in d.actions) {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp).focusRing().clickable(enabled = !sending, role = Role.Button) {
                            if (a == "reboot" || a == "shutdown") confirming = a else run(a)
                        },
                        verticalAlignment = Alignment.CenterVertically,
                    ) { Text(actionTitle(a), color = palette.text) }
                }
                Text(stringResource(R.string.quick_actions_note), style = MaterialTheme.typography.bodySmall)
                model.message?.takeIf { !sending }?.let { NoteText(it, dim = true) }
            }
        },
        confirmButton = {
            TextButton(enabled = !sending, onClick = { off = true }) { Text(stringResource(R.string.actions_off), color = palette.danger) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
    confirming?.let { a ->
        Confirm(
            title = stringResource(R.string.action_confirm_title, actionTitle(a), d.name),
            body = stringResource(R.string.action_confirm_body),
            action = actionTitle(a),
            dismiss = { confirming = null },
        ) { run(a) }
    }
    if (off) {
        Confirm(
            title = stringResource(R.string.actions_off_title, d.name),
            body = stringResource(R.string.actions_off_body),
            action = stringResource(R.string.actions_off),
            dismiss = { off = false },
        ) {
            sending = true
            scope.launch {
                val done = model.actionsOff(d.id)
                sending = false
                if (done) dismiss()
            }
        }
    }
}

/** What the clipboard holds as text; the app may read it while it is in front. */
private fun clipText(context: Context): String? =
    context.getSystemService(ClipboardManager::class.java)?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()

@Composable
private fun Switch(title: String, on: Boolean, change: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).focusRing().toggleable(value = on, role = Role.Switch, onValueChange = change),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, modifier = Modifier.weight(1f))
        androidx.compose.material3.Switch(checked = on, onCheckedChange = null)
    }
}

/** The sync modes to pick from, the device's own marked. */
@Composable
private fun ModeChoice(d: LiveGroup.Device, dismiss: () -> Unit, choose: (String) -> Unit) {
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.sync_mode)) },
        text = {
            Column {
                for (m in modes) {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp).focusRing().clickable(role = Role.Button) {
                            dismiss()
                            choose(m)
                        },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(if (m == d.mode) "✓" else "", color = palette.accent, modifier = Modifier.width(24.dp))
                        Column(Modifier.padding(start = Tokens.spacingMedium, top = Tokens.spacingSmall, bottom = Tokens.spacingSmall)) {
                            Text(stringResource(modeTitle(m)!!), color = palette.text)
                            Text(stringResource(modeNote(m)), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

@Composable
private fun Action(symbol: String, title: String, danger: Boolean = false, perform: () -> Unit) {
    val palette = LocalPalette.current
    val color = if (danger) palette.danger else palette.accent
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).focusRing().clickable(role = Role.Button, onClick = perform).padding(horizontal = Tokens.spacingMedium),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(symbol, color = color, modifier = Modifier.width(24.dp))
        Text(title, color = color, modifier = Modifier.padding(start = Tokens.spacingMedium))
    }
}
