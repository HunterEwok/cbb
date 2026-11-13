// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.ui.draw.clip
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
import tools.cbb.kit.Records as KitRecords
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
        Header(model, d, close)
        SyncCard(model, d)
        IconRow(model, d)
        model.message?.let { NoteText(it, dim = true) }
        More(d)
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

/**
 * The card's head (docs/apps.md, Devices): the icon, the name, the online
 * dot and the badges (root, admin, hub), one line "system · CBB version",
 * and on an admin phone ⋯ with what changes the device in the group.
 */
@Composable
private fun Header(model: AppModel, d: LiveGroup.Device, close: (() -> Unit)?) {
    val palette = LocalPalette.current
    Row(verticalAlignment = Alignment.Top) {
        DeviceIcon(d, 64.dp)
        Column(
            Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium).semantics(mergeDescendants = true) {},
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(d.name, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, maxLines = 2)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OnlineDot(d.online)
                Text(
                    stringResource(
                        when {
                            d.throughHub -> R.string.online_through_hub
                            d.online -> R.string.online
                            else -> R.string.offline
                        },
                    ),
                    color = if (d.online) palette.accent else palette.textDim,
                )
                for (b in badges(d)) Badge(stringResource(b))
            }
            val line = listOfNotNull(d.systemWithVersion, d.device?.version?.let { "CBB $it" }).joinToString(" · ")
            if (line.isNotEmpty()) Text(line, style = MaterialTheme.typography.bodySmall, color = palette.textDim)
        }
        if (model.isAdmin) DeviceMenu(model, d)
        if (close != null) IconText("✕", stringResource(R.string.close), onClick = close)
    }
}

/** The badges after the online dot. */
private fun badges(d: LiveGroup.Device): List<Int> = buildList {
    if (d.isRoot) add(R.string.root) else if (d.admin) add(R.string.admin)
    if (d.hub != null) add(R.string.badge_hub)
    if (d.frozen) add(R.string.frozen)
}

@Composable
private fun Badge(text: String) {
    val palette = LocalPalette.current
    Text(
        text,
        style = MaterialTheme.typography.labelSmall,
        color = palette.accent,
        modifier = Modifier.border(1.dp, palette.accent, RoundedCornerShape(50)).padding(horizontal = 6.dp, vertical = 1.dp),
    )
}

/** ⋯: rename, unfreeze, make it an admin, make it the hub, remove; each asks first where it should. */
@Composable
private fun DeviceMenu(model: AppModel, d: LiveGroup.Device) {
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf(false) }
    var promoting by remember { mutableStateOf(false) }
    var thawing by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf(false) }
    var hubbing by remember { mutableStateOf(false) }
    Box {
        IconText("⋯", stringResource(R.string.more)) { open = true }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            fun item(title: Int, danger: Boolean = false, act: () -> Unit) = @Composable {
                DropdownMenuItem(
                    text = { Text(stringResource(title), color = if (danger) LocalPalette.current.danger else Color.Unspecified) },
                    onClick = {
                        open = false
                        act()
                    },
                )
            }
            item(R.string.rename) { renaming = true }()
            if (d.frozen) item(R.string.unfreeze) { thawing = true }()
            if (d.canMakeAdmin) item(R.string.make_admin) { promoting = true }()
            // An admin member that may be a hub, or one the root makes an admin first; this phone is the hub under Settings.
            // A member that is no admin can be a hub that only passes the copies on.
            // The hub is chosen by itself: making one is in the advanced settings.
            if (model.settings.advanced && !d.isSelf && d.online && !d.throughHub && d.can("hub") && !d.frozen && !d.rootless && (d.mayHub || d.canMakeAdmin || !d.admin)) {
                item(R.string.make_hub) { hubbing = true }()
            }
            if (!d.isSelf) item(R.string.remove, danger = true) { removing = true }()
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
            body = if (d.role == "phone") {
                stringResource(R.string.make_admin_phone_body)
            } else if (d.keysInFile && model.keyLevel != KitRecords.LEVEL_FILES) {
                stringResource(R.string.make_admin_body) + " " + stringResource(R.string.make_admin_files_body)
            } else {
                stringResource(if (d.keysInFile) R.string.make_admin_body else R.string.make_admin_hardware_body)
            },
            action = stringResource(R.string.make_admin),
            dismiss = { promoting = false },
        ) { scope.launch { model.makeAdmin(d.id) } }
    }
    if (hubbing) HubChoice(d, dismiss = { hubbing = false }) { forwardOnly -> scope.launch { model.makeHub(d.id, forwardOnly) } }
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
 * The house for this device: this phone's own sync, or on an admin phone
 * another device's, turned with a command while it is online.
 */
@Composable
private fun SyncCard(model: AppModel, d: LiveGroup.Device) {
    val scope = rememberCoroutineScope()
    val on = if (d.isSelf) model.syncOff == null else d.mode != "own"
    if (!d.isSelf && (!model.isAdmin || d.mode == null)) return
    val enabled = d.isSelf || d.online
    Row(
        Modifier.fillMaxWidth().card().toggleable(value = on, enabled = enabled, role = Role.Switch) { v ->
            scope.launch { if (d.isSelf) model.turnSync(v) else model.setSync(d.id, v) }
        }.padding(Tokens.spacingMedium),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
    ) {
        SwitchGlyph("house", if (on) LocalPalette.current.accent else LocalPalette.current.textDim, 24.dp)
        Text(stringResource(R.string.sync), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
        androidx.compose.material3.Switch(checked = on, onCheckedChange = null, enabled = enabled)
    }
}

/** The icons: paste on it, mute or unmute it, its quick actions; each only where it applies. */
@Composable
private fun IconRow(model: AppModel, d: LiveGroup.Device) {
    if (!model.isAdmin) return
    val scope = rememberCoroutineScope()
    var pasting by remember { mutableStateOf(false) }
    var acting by remember { mutableStateOf(false) }
    var muting by remember { mutableStateOf(false) }
    Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
        // Members and Android and Aurora phones take pastes; iPhones cannot.
        if (!d.isSelf && (d.role == "member" || (d.role == "phone" && d.os in setOf("android", "aurora", "sailfish")))) {
            IconLabel("⌨", stringResource(R.string.paste_on_it)) { pasting = true }
        }
        // An admin mutes any device for the whole group, or ends its mute (docs/design.md, "Muting a device").
        if (d.muted != null) {
            IconLabel("🔊", stringResource(R.string.unmute)) { scope.launch { model.setMuted(d.id, false) } }
        } else {
            IconLabel("🔇", stringResource(R.string.mute)) { muting = true }
        }
        // Members run quick actions.
        if (!d.isSelf && d.online && d.role == "member") {
            IconLabel("⚡", stringResource(R.string.quick_actions)) { acting = true }
        }
    }
    if (muting) MuteChoice(dismiss = { muting = false }) { ms -> scope.launch { model.setMuted(d.id, true, ms) } }
    if (pasting) PasteOn(model, d, dismiss = { pasting = false })
    if (acting) QuickActions(model, d, dismiss = { acting = false })
}

/** An icon with its name under it, as one button. */
@Composable
private fun IconLabel(symbol: String, title: String, onClick: () -> Unit) {
    val palette = LocalPalette.current
    Column(
        Modifier.width(80.dp).clip(RoundedCornerShape(LocalStyle.current.radiusCard)).focusRing().clickable(role = Role.Button, onClick = onClick)
            .padding(vertical = Tokens.spacingSmall).semantics(mergeDescendants = true) {},
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Box(Modifier.size(44.dp).clip(CircleShape).background(palette.surface), contentAlignment = Alignment.Center) {
            Text(symbol, style = MaterialTheme.typography.titleMedium, color = palette.accent)
        }
        Text(title, style = MaterialTheme.typography.labelSmall, color = palette.text, textAlign = TextAlign.Center, maxLines = 2)
    }
}

/** More: the rest of what the group knows of it, the MAC address and the ID among it. */
@Composable
private fun More(d: LiveGroup.Device) {
    var open by rememberSaveable { mutableStateOf(false) }
    val palette = LocalPalette.current
    Text(
        (if (open) "▾ " else "▸ ") + stringResource(R.string.more),
        color = palette.accent,
        modifier = Modifier.fillMaxWidth().heightIn(min = 44.dp).focusRing().toggleable(value = open, role = Role.Button) { open = it }
            .padding(vertical = Tokens.spacingSmall),
    )
    if (open) Summary(d)
}

/** A row of the summary: what it is, and its value. */
private data class Line(val label: String, val value: String, val mono: Boolean = false, val dim: Boolean = false)

/** What the group knows of it, a row each. */
@Composable
private fun Summary(d: LiveGroup.Device) {
    val palette = LocalPalette.current
    val lines = buildList {
        add(Line(stringResource(R.string.type), stringResource(d.kind.title)))
        val mac = d.device?.mac
        if (mac != null) {
            add(Line(stringResource(R.string.mac_address), mac, mono = true))
        } else if (d.kind == DeviceKind.PHONE || d.kind == DeviceKind.TABLET) {
            add(Line(stringResource(R.string.mac_address), stringResource(R.string.hidden_by_system), dim = true))
        }
        add(Line(stringResource(R.string.role), stringResource(roleTitle(d.role, d.rootless))))
        if (d.forwardOnly) add(Line(stringResource(R.string.copies), stringResource(R.string.copies_forward_only)))
        d.muted?.let { m ->
            add(Line(stringResource(R.string.copies), m.until?.let { stringResource(R.string.muted_until, shortTime(it, date = true)) } ?: stringResource(R.string.muted_until_unmuted)))
        }
        d.hub?.let { add(Line(stringResource(R.string.away_title), stringResource(if (it == LiveGroup.HubMark.IN_USE) R.string.group_hub_in_use else R.string.group_hub))) }
        add(Line(stringResource(R.string.device_id), d.id, mono = true))
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
    "watch" -> R.string.kind_watch
    else -> if (rootless) R.string.role_member_rootless else R.string.role_member
}

/**
 * The kind of hub a computer becomes: one that reads the copies is an admin,
 * whose keys the group's key level checks; one that only passes them on is
 * no admin and needs no such keys.
 */
@Composable
private fun HubChoice(d: LiveGroup.Device, dismiss: () -> Unit, choose: (forwardOnly: Boolean) -> Unit) {
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.make_hub_title, d.name)) },
        text = { Text(stringResource(R.string.make_hub_body) + " " + stringResource(R.string.make_hub_kinds_body)) },
        confirmButton = {
            Column(horizontalAlignment = Alignment.End) {
                if (d.admin || d.canMakeAdmin) {
                    TextButton(onClick = {
                        dismiss()
                        choose(false)
                    }) { Text(stringResource(R.string.make_hub_reads), color = palette.accent) }
                }
                if (!d.admin && !d.isRoot) {
                    TextButton(onClick = {
                        dismiss()
                        choose(true)
                    }) { Text(stringResource(R.string.make_hub_forward_only), color = palette.accent) }
                }
                TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) }
            }
        },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
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
    // An image or files the user picks go as a copy that the computer pastes.
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        sending = true
        scope.launch {
            val done = model.pasteShared(d.id, uris, enter)
            sending = false
            if (done) dismiss()
        }
    }
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
                TextButton(enabled = !sending, onClick = { pick.launch(arrayOf("*/*")) }) {
                    Text(stringResource(R.string.paste_pick), color = palette.accent)
                }
                Text(stringResource(R.string.paste_pick_note), style = MaterialTheme.typography.bodySmall)
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
    "keyboard-layout" -> stringResource(R.string.action_keyboard_layout)
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

/** How long an admin mutes a device: its copies then reach no device of the group, and it still takes theirs. */
@Composable
private fun MuteChoice(dismiss: () -> Unit, choose: (Long) -> Unit) {
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.mute)) },
        text = {
            Column {
                Text(stringResource(R.string.mute_note), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
                for (t in PauseTime.entries) {
                    Text(
                        stringResource(if (t == PauseTime.EVER) R.string.mute_ever else t.title),
                        color = palette.text,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).focusRing().clickable(role = Role.Button) {
                            dismiss()
                            choose(t.ms)
                        }.padding(vertical = Tokens.spacingMedium),
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}
