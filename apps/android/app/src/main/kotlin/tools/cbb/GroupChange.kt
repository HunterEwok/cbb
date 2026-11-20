// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import tools.cbb.kit.ChangePreview
import tools.cbb.kit.Notice
import tools.cbb.kit.RecoveryInput

/**
 * The member's notices about the group, on Home (docs/apps.md, "Notices"):
 * each in a sentence, with a button that hides it when it may be hidden.
 */
@Composable
internal fun NoticesCard(model: AppModel) {
    val names = model.devices.associate { it.id to it.name }
    val shown = model.notices.mapNotNull { n -> noticeText(n, names)?.let { n to it } }
    if (shown.isEmpty()) return
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        for ((n, text) in shown) {
            Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                Text(text, style = MaterialTheme.typography.bodyMedium, color = palette.text, modifier = Modifier.weight(1f))
                if (n.dismissable) IconText("✕", stringResource(R.string.notice_hide), small = true) { scope.launch { model.dismiss(n) } }
            }
        }
    }
}

/** The notice in a sentence; null for a kind this app does not show. */
@Composable
private fun noticeText(n: Notice, names: Map<String, String>): String? {
    val device = n.args["device"]?.let { names[it] ?: it } ?: ""
    return when (n.kind) {
        "change_arriving" -> stringResource(R.string.notice_change_arriving)
        "admins_silent" -> {
            val days = n.args["days_left"]?.toIntOrNull() ?: 0
            if (days > 0) stringResource(R.string.notice_admins_silent, device, days) else stringResource(R.string.notice_admins_silent_now, device)
        }
        "removals_waiting" -> stringResource(R.string.notice_removals_waiting)
        "root_room_waiting" -> stringResource(R.string.notice_root_room_waiting, (n.args["percent"] ?: "") + "%")
        "ack_owed" -> stringResource(R.string.notice_ack_owed)
        "frozen_holding" -> stringResource(R.string.notice_frozen_holding, device)
        "checkpoint_stuck" -> stringResource(R.string.notice_checkpoint_stuck)
        "returned_after_removal" -> stringResource(R.string.notice_returned_after_removal, device)
        "recovery_not_saved" -> stringResource(R.string.notice_recovery_not_saved)
        else -> null
    }
}

/**
 * The group's root changed, on every device, until the person has seen it
 * (docs/apps.md, "Changing the main device"): who is the main device now,
 * and "This wasn't me", which explains what to do.
 */
@Composable
internal fun RootChangedCard(model: AppModel) {
    val c = model.rootChanged ?: return
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var notMe by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Text(stringResource(R.string.root_changed_title), style = MaterialTheme.typography.titleMedium, color = palette.text)
        Text(stringResource(R.string.root_changed_body, c.to, c.from), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            QuietButton(stringResource(R.string.root_changed_ok), onClick = { model.rootChangeSeen() })
            QuietButton(stringResource(R.string.root_changed_not_me), onClick = { notMe = true })
        }
    }
    if (notMe) {
        Confirm(
            stringResource(R.string.root_changed_not_me_title),
            stringResource(R.string.root_changed_not_me_body),
            stringResource(R.string.leave_group),
            dismiss = { notMe = false },
            confirm = {
                notMe = false
                scope.launch {
                    model.leave()
                    model.rootChangeSeen()
                }
            },
        )
    }
}

/**
 * In Settings on a phone that is not the main device: moving the group's
 * main device to it with the recovery key.
 */
@Composable
internal fun ChangeRootSection(model: AppModel) {
    var open by remember { mutableStateOf(false) }
    Section(stringResource(R.string.change_root)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            QuietButton(stringResource(R.string.change_root), onClick = { open = true })
            Tip(R.string.change_root_tip)
        }
    }
    if (open) ChangeRootDialog(model) { open = false }
}

/**
 * Moving the group's main device to this phone with the recovery key
 * (docs/apps.md, "Changing the main device"): the key from the sheet's QR
 * code or its typed text, then the list of who stays, which the core
 * writes and the person only unticks, then the fingerprint or the screen
 * lock. Each unticked device is removed in the same act; the old main
 * device starts unticked. The window keeps out of screenshots while the
 * key is on it.
 */
@Composable
private fun ChangeRootDialog(model: AppModel, close: () -> Unit) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var recovery by remember { mutableStateOf<RecoveryInput?>(null) }
    var preview by remember { mutableStateOf<ChangePreview?>(null) }
    var leaveOut by remember { mutableStateOf(emptySet<String>()) }
    var overWaiting by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.message = null }

    fun start(r: RecoveryInput) {
        if (recovery != null || busy) return
        busy = true
        scope.launch {
            val old = model.devices.filter { it.isRoot }.map { it.id }
            model.changePreview(r, old)?.let {
                recovery = r
                leaveOut = old.toSet()
                preview = it
            }
            busy = false
        }
    }

    fun toggle(device: String, stays: Boolean) {
        val r = recovery ?: return
        leaveOut = if (stays) leaveOut - device else leaveOut + device
        val out = leaveOut.toList()
        scope.launch { model.changePreview(r, out)?.let { preview = it } }
    }

    Dialog(
        onDismissRequest = close,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        BackHandler { close() }
        Column(
            Modifier.fillMaxSize().background(palette.background).safeDrawingPadding().verticalScroll(rememberScrollState())
                .padding(Tokens.spacingLarge),
            verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
        ) {
            Text(stringResource(R.string.change_root), style = MaterialTheme.typography.titleLarge, color = palette.text)
            val p = preview
            if (p == null) {
                RecoveryKeyInput(model, enabled = !busy, read = ::start)
            } else {
                Text(stringResource(R.string.change_root_who_stays), fontWeight = FontWeight.SemiBold, color = palette.text)
                for (row in p.rows) {
                    if (row.outcome == "removed_earlier") {
                        Column(Modifier.fillMaxWidth().padding(vertical = Tokens.spacingSmall)) {
                            Text(row.name, color = palette.text)
                            Text(stringResource(R.string.change_root_removed_earlier), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
                        }
                    } else {
                        val stays = row.device !in leaveOut
                        Row(
                            Modifier.fillMaxWidth().clickable(role = Role.Switch, enabled = !busy) { toggle(row.device, !stays) }
                                .padding(vertical = Tokens.spacingSmall),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(row.name, color = palette.text)
                                Text(stringResource(outcome(row)), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
                            }
                            Switch(checked = stays, onCheckedChange = null)
                        }
                    }
                }
                Text(
                    stringResource(R.string.change_root_online, model.devices.count { it.online }, model.devices.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = palette.textDim,
                )
                if (p.waiting) {
                    Text(stringResource(R.string.change_root_waiting_body), style = MaterialTheme.typography.bodySmall, color = palette.danger)
                    Row(
                        Modifier.fillMaxWidth().clickable(role = Role.Switch) { overWaiting = !overWaiting },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(stringResource(R.string.change_root_over_waiting), modifier = Modifier.weight(1f), color = palette.text)
                        Switch(checked = overWaiting, onCheckedChange = null)
                    }
                }
                AccentButton(
                    stringResource(R.string.change_root_confirm),
                    enabled = !busy && (!p.waiting || overWaiting),
                    onClick = {
                        val r = recovery ?: return@AccentButton
                        busy = true
                        scope.launch {
                            val done = model.changeRoot(r, leaveOut.toList(), overWaiting)
                            busy = false
                            if (done) close()
                        }
                    },
                )
                Text(stringResource(R.string.change_root_cannot_undo), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
            }
            model.message?.let { NoteText(it) }
            QuietButton(stringResource(R.string.cancel), onClick = close)
        }
    }
}

/** The recovery key: the camera for the sheet's QR code, or its text typed. */
@Composable
private fun RecoveryKeyInput(model: AppModel, enabled: Boolean, read: (RecoveryInput) -> Unit) {
    val context = LocalContext.current
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    var allowed by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed = it }
    var cameraError by remember { mutableStateOf<Exception?>(null) }
    LaunchedEffect(Unit) { if (hasCamera && !allowed) launcher.launch(Manifest.permission.CAMERA) }
    if (hasCamera && allowed && cameraError == null) {
        QrScanner(
            onCode = { text -> if (enabled) read(RecoveryInput.Qr(text)) },
            modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(LocalStyle.current.radiusCard)),
            onError = { cameraError = it },
        )
    } else if (cameraError != null) {
        NoteText(model.describe(cameraError!!, R.string.camera_failed, log = false))
    }
    var typed by remember { mutableStateOf("") }
    OutlinedTextField(
        value = typed,
        onValueChange = { typed = it },
        label = { Text(stringResource(R.string.change_root_key_text)) },
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
        minLines = 4,
        modifier = Modifier.fillMaxWidth(),
    )
    AccentButton(stringResource(R.string.change_root_next), enabled = enabled && typed.isNotBlank(), onClick = { read(RecoveryInput.Text(typed)) })
    Text(stringResource(R.string.change_root_key_hint), style = MaterialTheme.typography.bodySmall, color = LocalPalette.current.textDim)
}

/** What the change does to a device, in words. */
private fun outcome(row: ChangePreview.Row): Int = when (row.outcome) {
    "out" -> R.string.change_root_out
    "admin_kept" -> R.string.change_root_admin_kept
    "admin_lost" -> R.string.change_root_admin_lost
    "frozen" -> R.string.change_root_frozen
    else -> if (row.frozen) R.string.change_root_frozen else R.string.change_root_stays
}
