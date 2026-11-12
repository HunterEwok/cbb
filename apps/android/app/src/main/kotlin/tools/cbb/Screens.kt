// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.annotation.StringRes
import android.content.Context
import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import tools.cbb.kit.RemotePaste
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** The terms of the project's forwarder and relay, in the reader's language. */
private const val PROJECT_TERMS = "https://cbb.tools/?p=terms.html"

/** Picks the screen, and asks once for the local network, which finding the computers needs on Android 17. */
@Composable
fun Root(model: AppModel) {
    AppTheme(model.theme, model.appearance) {
        AppBackground {
            LocalNetworkPermission(model)
            BugDialog(model)
            Box(Modifier.safeDrawingPadding()) {
                when (model.phase) {
                    AppModel.Phase.START -> StartScreen(model)
                    AppModel.Phase.JOINING -> JoinScreen(model)
                    AppModel.Phase.HOME -> HomeScreen(model)
                }
            }
        }
    }
}

/** The permission for devices on the local network: Android 17 asks for it before mDNS and the connections to the computers work. */
@Composable
private fun LocalNetworkPermission(model: AppModel) {
    if (Build.VERSION.SDK_INT < 37) return
    val context = LocalContext.current
    val permission = "android.permission.ACCESS_LOCAL_NETWORK"
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) model.group.reconnect()
    }
    LaunchedEffect(Unit) {
        if (ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) launcher.launch(permission)
    }
}

// Start

/**
 * No group yet (docs/apps.md, Start): settings and the language at the
 * top, the logo, "Create a group", "Join a group", "Join with an
 * invitation" and a small link to restore with the recovery key.
 */
@Composable
private fun StartScreen(model: AppModel) {
    val palette = LocalPalette.current
    var adding by rememberSaveable { mutableStateOf(false) }
    var restoring by rememberSaveable { mutableStateOf(false) }
    var settings by rememberSaveable { mutableStateOf(false) }
    var invited by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.prepare() }
    model.pendingInvite?.let { p ->
        InvitationAnswerScreen(model, p)
        return
    }
    if (invited) {
        InvitationScreen(model) { invited = false }
        return
    }
    if (adding || restoring) {
        AddDeviceScreen(model, restore = restoring) {
            adding = false
            restoring = false
        }
        return
    }
    if (settings) {
        SettingsScreen(model) { settings = false }
        return
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            StartLanguageMenu(model)
            Spacer(Modifier.weight(1f))
            IconText("⚙", stringResource(R.string.settings)) { settings = true }
        }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineLarge,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            color = palette.accent,
        )
        Text(stringResource(R.string.full_name), fontFamily = FontFamily.Monospace, color = palette.accent)
        Text(stringResource(R.string.tagline), textAlign = TextAlign.Center, color = palette.textDim)
        if (model.isTv) {
            // A TV has no camera to scan a code: it shows its own, for the phone.
            Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
            AccentButton(stringResource(R.string.join_tv), onClick = { model.startJoining() }, modifier = Modifier.widthIn(max = 480.dp))
            Text(stringResource(R.string.join_tv_hint), textAlign = TextAlign.Center, color = palette.textDim)
            model.message?.let { NoteText(it) }
            return@Column
        }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        AccentButton(stringResource(R.string.create_group), onClick = { adding = true }, modifier = Modifier.widthIn(max = 480.dp))
        QuietButton(stringResource(R.string.join_group), onClick = { model.startJoining() })
        QuietButton(stringResource(R.string.invitation_join), onClick = { invited = true })
        TextButton(onClick = { restoring = true }) {
            Text(stringResource(R.string.restore_link), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
        }
        model.message?.let { NoteText(it) }
    }
}

/** The language menu across from the gear: the system's language or one of the translations. */
@Composable
private fun StartLanguageMenu(model: AppModel) {
    val activity = LocalActivity.current
    var open by remember { mutableStateOf(false) }
    Box {
        IconText("🌐", stringResource(R.string.language)) { open = true }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (l in listOf(LanguageChoice.SYSTEM) + LanguageChoice.translations) {
                DropdownMenuItem(text = { Text(l.ownName ?: stringResource(R.string.language_system)) }, onClick = {
                    open = false
                    model.settings.language = l
                    activity?.recreate()
                })
            }
        }
    }
}

// Joining

/** Joining another phone's group: this phone's QR code, which the other phone scans in Add a device. */
@Composable
private fun JoinScreen(model: AppModel) {
    if (model.joiningInvite != null) {
        JoinByInviteScreen(model)
        return
    }
    val palette = LocalPalette.current
    LaunchedEffect(Unit) { model.join() }
    BackHandler { model.cancelJoin() }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
    ) {
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.join_title),
            style = MaterialTheme.typography.headlineMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            color = palette.accent,
        )
        val code = model.joinCode
        if (code != null) {
            val label = stringResource(R.string.join_qr_label)
            QrCode(
                code.qrText,
                Modifier.widthIn(max = 280.dp).fillMaxWidth().aspectRatio(1f)
                    .clip(RoundedCornerShape(LocalStyle.current.radiusCard)).background(Color.White).padding(Tokens.spacingMedium)
                    .semantics { contentDescription = label },
            )
            Text(
                code.grouped,
                style = MaterialTheme.typography.headlineLarge,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.semantics { contentDescription = code.code.toList().joinToString(" ") },
            )
            val hint = if (model.isTv) R.string.join_hint_tv else R.string.join_hint
            Text(stringResource(hint), textAlign = TextAlign.Center, color = palette.textDim)
        } else if (model.message == null) {
            CircularProgressIndicator(color = palette.accent)
        }
        model.message?.let { NoteText(it) }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        QuietButton(stringResource(R.string.cancel), onClick = { model.cancelJoin() })
    }
}

/**
 * Joining by an accepted invitation: the fingerprint this phone shows, which
 * the inviting admin compares before admitting it.
 */
@Composable
private fun JoinByInviteScreen(model: AppModel) {
    val palette = LocalPalette.current
    LaunchedEffect(Unit) { model.joinByInvite() }
    BackHandler { model.cancelJoin() }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
    ) {
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.invitation_join),
            style = MaterialTheme.typography.headlineMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            color = palette.accent,
            textAlign = TextAlign.Center,
        )
        val fp = model.inviteFingerprint
        if (fp != null) {
            Text(fp, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
            Text(stringResource(R.string.invitation_fingerprint_hint), textAlign = TextAlign.Center, color = palette.textDim)
        }
        if (model.message == null) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                CircularProgressIndicator(Modifier.size(20.dp), color = palette.accent, strokeWidth = 2.dp)
                Text(stringResource(R.string.invitation_connecting))
            }
        }
        model.message?.let { NoteText(it) }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        QuietButton(stringResource(R.string.cancel), onClick = { model.cancelJoin() })
    }
}

/**
 * Join with an invitation (docs/apps.md, Start): the camera for the
 * invitation's QR code, the usual way; its file, or its text pasted, when
 * the QR code came another way. What it reads goes to the screen that
 * accepts or declines it.
 */
@Composable
private fun InvitationScreen(model: AppModel, close: () -> Unit) {
    val context = LocalContext.current
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    var allowed by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var asked by rememberSaveable { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        allowed = it
        asked = true
    }
    var cameraError by remember { mutableStateOf<Exception?>(null) }
    LaunchedEffect(Unit) {
        model.message = null
        if (hasCamera && !allowed && !asked) launcher.launch(Manifest.permission.CAMERA)
    }
    val read = { text: String -> if (model.readInvitation(text)) close() }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        // An invitation's file is one short line; a big file is none.
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.use { readUpTo(it, INVITE_FILE_MAX + 1) }
        }.getOrNull()
        if (text == null || text.size > INVITE_FILE_MAX) {
            model.message = AppModel.Note(R.string.invitation_not_one, error = true)
        } else {
            read(String(text, Charsets.UTF_8))
        }
    }
    BackHandler { close() }
    Page(stringResource(R.string.invitation_join), close) {
        if (hasCamera && allowed && cameraError == null) {
            QrScanner(
                onCode = { text -> read(text) },
                modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(LocalStyle.current.radiusCard)),
                onError = { cameraError = it },
            )
            Text(stringResource(R.string.invitation_scan_hint), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        } else if (cameraError != null) {
            NoteText(model.describe(cameraError!!, R.string.camera_failed, log = false))
        }
        var typed by rememberSaveable { mutableStateOf("") }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text(stringResource(R.string.invitation_text)) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        AccentButton(stringResource(R.string.invitation_read), enabled = typed.isNotBlank(), onClick = { read(typed) })
        QuietButton(stringResource(R.string.invitation_open_file), onClick = { picker.launch(arrayOf("*/*")) })
        model.message?.let { NoteText(it) }
    }
}

/** The longest file read as an invitation: its one line is far shorter. */
private const val INVITE_FILE_MAX = 4096

/** Up to max bytes of a stream. */
private fun readUpTo(input: java.io.InputStream, max: Int): ByteArray {
    val buf = ByteArray(max)
    var n = 0
    while (n < max) {
        val r = input.read(buf, n, max - n)
        if (r < 0) break
        n += r
    }
    return buf.copyOf(n)
}

/** An invitation that waits for the user: the group it joins, its hub and when it expires, with Join and Decline. Declining sends nothing. */
@Composable
private fun InvitationAnswerScreen(model: AppModel, invite: AppModel.PendingInvite) {
    val palette = LocalPalette.current
    BackHandler { model.declineInvitation() }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge),
    ) {
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.invitation_title),
            style = MaterialTheme.typography.headlineMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            color = palette.accent,
            textAlign = TextAlign.Center,
        )
        val until = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT)
            .format(Instant.ofEpochSecond(invite.invitation.expires).atZone(ZoneId.systemDefault()))
        Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Text(stringResource(R.string.invitation_group, invite.invitation.group), fontFamily = FontFamily.Monospace)
            Text(stringResource(R.string.invitation_hub, invite.invitation.hub.take(12)), fontFamily = FontFamily.Monospace)
            Text(stringResource(R.string.invitation_until, until))
        }
        Text(stringResource(R.string.invitation_answer_hint), textAlign = TextAlign.Center, color = palette.textDim)
        AccentButton(stringResource(R.string.invitation_accept), onClick = model::acceptInvitation, modifier = Modifier.widthIn(max = 480.dp))
        QuietButton(stringResource(R.string.invitation_decline), onClick = model::declineInvitation)
    }
}

/** A QR code drawn module by module, black on the white behind it. */
@Composable
internal fun QrCode(text: String, modifier: Modifier) {
    val matrix = remember(text) {
        QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 0))
    }
    Canvas(modifier) {
        val n = matrix.width
        val cell = minOf(size.width, size.height) / n
        for (y in 0 until n) for (x in 0 until n) {
            if (matrix[x, y]) drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}

// Dialogs (Home.kt and DeviceDetail.kt have the pages)

/** Asks for a device's new name, starting from its name. */
@Composable
internal fun Rename(d: LiveGroup.Device, dismiss: () -> Unit, rename: (String) -> Unit) {
    val palette = LocalPalette.current
    var name by rememberSaveable { mutableStateOf(d.name) }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.rename_title, d.name)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                Text(stringResource(R.string.rename_body))
                OutlinedTextField(value = name, onValueChange = { name = it }, singleLine = true, label = { Text(stringResource(R.string.name)) })
            }
        },
        confirmButton = {
            TextButton(enabled = name.isNotBlank(), onClick = {
                dismiss()
                rename(name)
            }) { Text(stringResource(R.string.rename), color = palette.accent) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

@Composable
internal fun Confirm(title: String, body: String, action: String, dismiss: () -> Unit, confirm: () -> Unit) {
    val palette = LocalPalette.current
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            TextButton(onClick = {
                dismiss()
                confirm()
            }) { Text(action, color = palette.danger) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

// Adding

/**
 * The camera with a frame; the text of the QR code by hand when there is no
 * camera or it is not allowed. With restore, it scans the recovery sheet's
 * QR code instead, on a phone without a group.
 */
@Composable
internal fun AddDeviceScreen(model: AppModel, restore: Boolean = false, close: () -> Unit) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    var allowed by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var asked by rememberSaveable { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        allowed = it
        asked = true
    }
    LaunchedEffect(Unit) {
        model.message = null
        if (hasCamera && !allowed && !asked) launcher.launch(Manifest.permission.CAMERA)
    }
    // The device being admitted: one at a time; leaving the page cancels it.
    var adding by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    // Why the camera did not start, if it did not.
    var cameraError by remember { mutableStateOf<Exception?>(null) }
    val add = { text: String ->
        if (adding == null) {
            adding = scope.launch {
                try {
                    if (if (restore) model.restore(text.trim()) else model.scanned(text)) close()
                } finally {
                    adding = null
                }
            }
        }
    }
    BackHandler { close() }
    // The recovery key typed or pasted stays out of screenshots and the
    // recent apps' preview.
    if (restore) SecureWindow()
    Page(stringResource(if (restore) R.string.restore_title else R.string.add_device), close) {
        if (hasCamera && allowed && cameraError == null) {
            QrScanner(
                onCode = { text -> scope.launch { if (!model.busy) add(text) } },
                modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(LocalStyle.current.radiusCard)),
                onError = { cameraError = it },
            )
            Text(stringResource(if (restore) R.string.restore_hint else R.string.scan_hint), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        } else if (cameraError != null) {
            // The camera did not start: the text of the QR code still works.
            NoteText(model.describe(cameraError!!, R.string.camera_failed, log = false))
        } else {
            Text(
                stringResource(if (hasCamera) R.string.camera_denied else R.string.paste_hint),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        var typed by rememberSaveable { mutableStateOf("") }
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            label = { Text(stringResource(R.string.qr_text)) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth(),
        )
        AccentButton(stringResource(if (restore) R.string.restore_go else R.string.add), enabled = typed.isNotBlank() && !model.busy, onClick = { add(typed) })
        if (restore) {
            var askingPin by remember { mutableStateOf(false) }
            QuietButton(stringResource(R.string.yubikey_restore), onClick = { askingPin = true }, enabled = !model.busy)
            if (askingPin) {
                YubiKeyPinDialog(
                    stringResource(R.string.yubikey_restore_title),
                    stringResource(R.string.yubikey_restore_body),
                    dismiss = { askingPin = false },
                ) { pin ->
                    if (adding == null) {
                        adding = scope.launch {
                            try {
                                if (model.restoreWithCard(pin)) close()
                            } finally {
                                adding = null
                            }
                        }
                    }
                }
            }
            YubiKeyPrompt(model) { adding?.cancel() }
        }
        if (model.busy) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                CircularProgressIndicator(Modifier.size(20.dp), color = palette.accent, strokeWidth = 2.dp)
                Text(if (model.retries > 0) stringResource(R.string.not_ready_yet, model.retries) else stringResource(R.string.connecting))
            }
        } else {
            model.message?.let { NoteText(it) }
        }
    }
}

// Settings

/**
 * Settings (docs/apps.md, Settings): the basic ones first (the look,
 * notifications, sending copies by themselves, the watch, the recovery key
 * on the root), then the switch for the advanced ones (away from home, the
 * group's rules for admins), leaving the group and about. No long text
 * under an item: a tip says it once, until it is closed.
 */
@Composable
internal fun SettingsScreen(model: AppModel, back: () -> Unit) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val home = model.phase == AppModel.Phase.HOME
    var advanced by remember { mutableStateOf(model.settings.advanced) }
    BackHandler { back() }
    Page(stringResource(R.string.settings), back) {
        Section(stringResource(R.string.appearance)) { Appearance(model) }
        if (home) Notifications(model.notifier)
        // A TV sends no copies of its own: the service there is only the paste target.
        if (home && !model.isTv) AutoSend()
        if (WatchLink.available && home && model.devices.any { it.isSelf && it.isRoot }) WatchSection(model)
        if (home && model.isRoot) RecoverySection(model)
        if (home) {
            Row(
                Modifier.fillMaxWidth().card().focusRing().clickable(role = Role.Switch) {
                    advanced = !advanced
                    model.settings.advanced = advanced
                }.padding(Tokens.spacingMedium),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.advanced_settings), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = advanced, onCheckedChange = null)
            }
        }
        if (home && advanced) {
            WhySection(model, model.settings.showsErrorDetails)
            model.hub?.let { HubSection(model, it) }
            model.blindRelay?.let { BlindRelaySection(model, it) }
            if (!model.isTv) ShareAsk(model)
            RemotePasteSection(model.group.pastes, model.isTv)
            model.incomingMS?.let { IncomingSection(model, it) }
            model.keyLevel?.let { KeyLevelSection(model, it) }
            // The lab: what works but is no promise of 1.0 (docs/apps.md,
            // "The lab"). A TV has nothing near it to type into.
            if (!model.isTv) {
                Text(
                    stringResource(R.string.lab),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.semantics { heading() }.testTag("lab"),
                )
                KeyboardSection(model.group.keyboard, model.settings.showsErrorDetails)
            }
        }
        if (home) LeaveSection(model)
        UpdateSection(model)
        Section(stringResource(R.string.about)) {
            val version = remember { runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "" }
            // Seven taps on the version show the error details switch, as
            // the build number shows the developer options.
            var taps by remember { mutableIntStateOf(0) }
            var shown by remember { mutableStateOf(model.settings.errorDetailsSwitch) }
            var details by remember { mutableStateOf(model.settings.showsErrorDetails) }
            Row(
                Modifier.fillMaxWidth().focusRing().clickable {
                    taps++
                    if (taps >= 7 && !shown) {
                        shown = true
                        model.settings.errorDetailsSwitch = true
                    }
                }.padding(Tokens.spacingMedium),
            ) {
                Text(stringResource(R.string.version), modifier = Modifier.weight(1f))
                Text(version, fontFamily = FontFamily.Monospace, color = palette.textDim)
            }
            if (shown) {
                HorizontalDivider(color = palette.grid)
                Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                    Row(
                        Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) {
                            details = !details
                            model.settings.showsErrorDetails = details
                        },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(stringResource(R.string.error_details_switch), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                        Switch(checked = details, onCheckedChange = null)
                    }
                    Tip(R.string.error_details_body)
                }
            }
            HorizontalDivider(color = palette.grid)
            Text(
                stringResource(R.string.source),
                color = palette.accent,
                modifier = Modifier.fillMaxWidth().focusRing().clickable(role = Role.Button) {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/HunterEwok/cbb")))
                }.padding(Tokens.spacingMedium),
            )
        }
    }
}

/**
 * The app's own update when it came from a release (ApkUpdate): what the
 * last check found, the button for the next step, and the switch for
 * automatic updates. A copy from a store, or a build without release
 * keys, shows nothing.
 */
@Composable
private fun UpdateSection(model: AppModel) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val state = model.apkState
    if (state is ApkUpdate.State.Store || state is ApkUpdate.State.NoKeys) return
    var auto by remember { mutableStateOf(model.apkUpdate.automatic) }
    Section(stringResource(R.string.update)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            val line = when (state) {
                is ApkUpdate.State.Checking -> stringResource(R.string.update_checking)
                is ApkUpdate.State.UpToDate -> stringResource(R.string.update_up_to_date, state.version)
                is ApkUpdate.State.Available -> stringResource(R.string.update_available, state.version)
                is ApkUpdate.State.Installing -> stringResource(R.string.update_installing, state.version)
                is ApkUpdate.State.TooOld -> stringResource(R.string.update_too_old, state.version, state.minFrom)
                is ApkUpdate.State.Failed -> stringResource(R.string.update_failed)
                else -> null
            }
            line?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = if (state is ApkUpdate.State.Failed) palette.danger else palette.text) }
            if (state is ApkUpdate.State.Failed && model.settings.showsErrorDetails) {
                Text(state.error.toString(), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = palette.textDim)
            }
            when (state) {
                is ApkUpdate.State.Available -> TextButton(onClick = { model.apkUpdate.install() }) { Text(stringResource(R.string.update_install, state.version)) }
                is ApkUpdate.State.TooOld -> TextButton(onClick = {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/HunterEwok/cbb/releases")))
                }) { Text(stringResource(R.string.update_releases)) }
                is ApkUpdate.State.Checking, is ApkUpdate.State.Installing -> {}
                else -> TextButton(onClick = { model.apkUpdate.start(install = false) }) { Text(stringResource(R.string.update_check)) }
            }
            HorizontalDivider(color = palette.grid)
            Row(
                Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) {
                    auto = !auto
                    model.apkUpdate.automatic = auto
                },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.update_auto), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = auto, onCheckedChange = null)
            }
            Tip(R.string.update_auto_body)
        }
    }
}

/** The apps that send without asking ("Always for this app"), and the way to ask every app again. */
@Composable
private fun ShareAsk(model: AppModel) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    var allowed by remember { mutableStateOf(model.settings.allowedApps) }
    Section(stringResource(R.string.send_share)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Text(stringResource(R.string.share_ask_switch), fontWeight = FontWeight.SemiBold)
            val names = allowed.map { pkg ->
                runCatching { context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
            }.sorted()
            Text(if (names.isEmpty()) stringResource(R.string.share_allowed_none) else names.joinToString(", "), style = MaterialTheme.typography.bodyMedium)
            Tip(R.string.share_ask_body)
            if (allowed.isNotEmpty()) {
                TextButton(onClick = {
                    model.settings.allowedApps = emptySet()
                    allowed = emptySet()
                }) { Text(stringResource(R.string.share_forget)) }
            }
        }
    }
}

/** The setup of CopyWatcher: what it is for, whether it is on, and the way to the system's settings. */
@Composable
private fun AutoSend() {
    val palette = LocalPalette.current
    val context = LocalContext.current
    var on by remember { mutableStateOf(CopyWatcher.isOn(context)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { on = CopyWatcher.isOn(context) }
    Section(stringResource(R.string.accessibility_label)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Text(
                stringResource(if (on) R.string.auto_send_on else R.string.auto_send_off),
                color = if (on) palette.accent else palette.textDim,
                fontWeight = FontWeight.SemiBold,
            )
            Tip(R.string.auto_send_body)
            if (!on) {
                TextButton(onClick = {
                    context.startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }) { Text(stringResource(R.string.open_accessibility), color = palette.accent) }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    Text(stringResource(R.string.restricted_hint), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
                    TextButton(onClick = {
                        context.startActivity(
                            Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }) { Text(stringResource(R.string.app_info), color = palette.accent) }
                }
            }
        }
    }
}

/**
 * Remote paste on this phone (docs/design.md, "Remote paste"): the switch
 * that lets the group's admins paste into the focused text field, the one
 * for Enter, and the accessibility service it needs.
 */
@Composable
private fun RemotePasteSection(pastes: PasteReceiver, tv: Boolean) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    var set by remember { mutableStateOf(pastes.settings) }
    var service by remember { mutableStateOf(CopyWatcher.isOn(context)) }
    // On in the settings, but not running: the system stopped it, as Android TV 14 does.
    var stopped by remember { mutableStateOf(service && CopyWatcher.running == null) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        set = pastes.settings
        service = CopyWatcher.isOn(context)
        stopped = service && CopyWatcher.running == null
    }
    fun change(new: RemotePaste.Settings) {
        runCatching { pastes.settings = new }.onFailure { Log.e("cbb", "saving the remote paste switches", it) }
        set = pastes.settings
    }
    Section(stringResource(R.string.remote_paste)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Row(Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) { change(RemotePaste.Settings(on = !set.on)) }, verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.remote_paste_switch), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = set.on, onCheckedChange = null)
            }
            if (set.on) {
                Row(Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) { change(set.copy(enter = !set.enter)) }, verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.remote_paste_enter), modifier = Modifier.weight(1f))
                    Switch(checked = set.enter, onCheckedChange = null)
                }
            }
            Tip(R.string.remote_paste_body)
            if (set.on && (!service || stopped)) {
                val why = when {
                    stopped -> R.string.remote_paste_service_stopped
                    tv -> R.string.remote_paste_needs_service_tv
                    else -> R.string.remote_paste_needs_service
                }
                Text(stringResource(why), style = MaterialTheme.typography.bodyMedium, color = palette.danger)
                TextButton(onClick = {
                    context.startActivity(Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }) { Text(stringResource(R.string.open_accessibility), color = palette.accent) }
            }
        }
    }
}

/** The root phone makes its Wear OS watch an admin, for the emergency actions (docs/protocol.md, section 10, "Watches"). */
@Composable
private fun WatchSection(model: AppModel) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val watches = model.devices.filter { it.role == "watch" }
    Section(stringResource(R.string.watch_title)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            watches.forEach { Text(it.name, fontWeight = FontWeight.SemiBold) }
            if (watches.isEmpty()) {
                Button(onClick = {
                    busy = true
                    scope.launch {
                        model.addWatch()
                        busy = false
                    }
                }, enabled = !busy) { Text(stringResource(R.string.watch_make_admin)) }
            }
            model.watchNote?.let { NoteText(it) }
            Text(
                stringResource(if (watches.isEmpty()) R.string.watch_body else R.string.watch_replace),
                style = MaterialTheme.typography.bodyMedium,
                color = palette.textDim,
            )
        }
    }
}

/**
 * The blind relay (docs/design.md, "Blind relay"): where the phone stands
 * there, its address and key, and what it learns, which the user reads and
 * accepts before the phone meets the group there.
 */
@Composable
private fun BlindRelaySection(model: AppModel, relay: AppModel.BlindRelay) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var asking by remember { mutableStateOf(false) }
    var address by rememberSaveable(relay.relay) { mutableStateOf(relay.relay?.endpoint ?: "") }
    var pin by rememberSaveable(relay.relay) { mutableStateOf(relay.relay?.pin ?: "") }
    fun save() {
        busy = true
        scope.launch {
            model.setRelay(address, pin)
            busy = false
        }
    }
    Section(stringResource(R.string.relay_title)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            val status = when (relay.status) {
                RelayOnPhone.Status.OFF -> stringResource(R.string.relay_off)
                RelayOnPhone.Status.PAUSED -> stringResource(R.string.relay_paused)
                RelayOnPhone.Status.CONNECTING -> stringResource(R.string.relay_connecting)
                RelayOnPhone.Status.CONNECTED ->
                    if (relay.online == 0) stringResource(R.string.relay_alone) else stringResource(R.string.relay_with, relay.online)
                RelayOnPhone.Status.FAILED -> stringResource(R.string.relay_failed)
            }
            Text(status, color = if (relay.status == RelayOnPhone.Status.CONNECTED) palette.accent else palette.textDim)
            // The relay's error underneath, when details are on.
            relay.error?.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = palette.textDim) }
            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                singleLine = true,
                label = { Text(stringResource(R.string.relay_address)) },
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it },
                singleLine = true,
                label = { Text(stringResource(R.string.relay_key)) },
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            val empty = address.isBlank() && pin.isBlank()
            val changed = address != (relay.relay?.endpoint ?: "") || pin != (relay.relay?.pin ?: "")
            AccentButton(
                stringResource(if (empty) R.string.relay_leave else R.string.relay_meet),
                enabled = changed && !busy,
                onClick = { if (empty) save() else asking = true },
            )
            model.relayNote?.let { NoteText(it) }
            Tip(R.string.relay_body)
        }
    }
    if (asking) {
        Confirm(stringResource(R.string.relay_ask_title), stringResource(R.string.relay_ask_body), stringResource(R.string.relay_meet),
            dismiss = { asking = false }, confirm = ::save)
    }
}

/**
 * The phone as the group's hub: the switch, where it stands, the
 * forwarder, the home networks and, on Android, the background.
 */
@Composable
private fun HubSection(model: AppModel, hub: AppModel.Hub) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    fun act(f: suspend () -> Unit) {
        busy = true
        scope.launch {
            f()
            busy = false
        }
    }
    Section(stringResource(R.string.hub_title)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Row(
                Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch, enabled = !busy) { act { model.setHub(!hub.on) } },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.hub_switch), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = hub.on, onCheckedChange = null, enabled = !busy)
            }
            val status = when (hub.status) {
                HubOnPhone.Status.OFF -> R.string.hub_off
                HubOnPhone.Status.PAUSED -> R.string.hub_paused
                HubOnPhone.Status.HOME_ONLY -> R.string.hub_home_only
                HubOnPhone.Status.REGISTERING -> R.string.hub_registering
                HubOnPhone.Status.REGISTERED -> R.string.hub_registered
                HubOnPhone.Status.FAILED -> R.string.hub_failed
            }
            Text(stringResource(status), color = if (hub.status == HubOnPhone.Status.REGISTERED) palette.accent else palette.textDim)
            // The registration's error underneath, when details are on.
            hub.error?.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = palette.textDim) }
            if (hub.entriesStale) {
                Text("⚠ " + stringResource(R.string.hub_entries_stale), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
            }
            if (hub.on) {
                Text(
                    stringResource(if (hub.home) R.string.hub_on_home else R.string.hub_not_home),
                    style = MaterialTheme.typography.bodyMedium,
                    color = palette.textDim,
                )
                if (!hub.home) QuietButton(stringResource(R.string.hub_add_home), onClick = { if (!busy) act { model.addHomeNetwork() } })
                // The fields show the user's own forwarder; the project's leaves them empty.
                val own = hub.forwarder?.takeUnless { it.isProject }
                var address by rememberSaveable(hub.forwarder) { mutableStateOf(own?.endpoint ?: "") }
                var pin by rememberSaveable(hub.forwarder) { mutableStateOf(own?.pin ?: "") }
                Text(stringResource(R.string.hub_forwarder), fontWeight = FontWeight.SemiBold)
                Text(
                    stringResource(if (hub.forwarder?.isProject == true) R.string.hub_forwarder_project else R.string.hub_forwarder_back),
                    style = MaterialTheme.typography.bodySmall,
                    color = palette.textDim,
                )
                if (hub.forwarder?.isProject == true) {
                    val context = LocalContext.current
                    Text(
                        stringResource(R.string.project_terms),
                        style = MaterialTheme.typography.bodySmall,
                        color = palette.accent,
                        modifier = Modifier.focusRing().clickable(role = Role.Button) {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PROJECT_TERMS)))
                        },
                    )
                }
                OutlinedTextField(
                    value = address,
                    onValueChange = { address = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.hub_forwarder_address)) },
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.hub_forwarder_key)) },
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth(),
                )
                val changed = address != (own?.endpoint ?: "") || pin != (own?.pin ?: "")
                AccentButton(stringResource(R.string.hub_forwarder_save), enabled = changed && !busy, onClick = { act { model.setForwarder(address, pin) } })
                Text(stringResource(R.string.hub_disguise), fontWeight = FontWeight.SemiBold)
                // Strict networks: AmneziaWG for networks that block VPNs,
                // and VLESS over it for those that let only the web through.
                var disguiseTo by remember { mutableStateOf<HubOnPhone.Disguise?>(null) }
                val vpn = hub.disguise != HubOnPhone.Disguise.PLAIN
                val web = hub.disguise == HubOnPhone.Disguise.VLESS
                StrictSwitch(stringResource(R.string.hub_strict_vpn), vpn, !busy) {
                    disguiseTo = if (vpn) HubOnPhone.Disguise.PLAIN else HubOnPhone.Disguise.OBFUSCATE
                }
                StrictSwitch(stringResource(R.string.hub_strict_web), web, !busy && vpn) {
                    disguiseTo = if (web) HubOnPhone.Disguise.OBFUSCATE else HubOnPhone.Disguise.VLESS
                }
                Tip(R.string.hub_disguise_body)
                disguiseTo?.let { d ->
                    Confirm(
                        stringResource(R.string.hub_disguise_title), stringResource(R.string.hub_disguise_confirm), stringResource(R.string.hub_disguise_change),
                        dismiss = { disguiseTo = null },
                        confirm = {
                            disguiseTo = null
                            act { model.setHubDisguise(d) }
                        },
                    )
                }
                Row(
                    Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch, enabled = !busy) { act { model.setHubInBackground(!hub.background) } },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.hub_background), modifier = Modifier.weight(1f))
                    Switch(checked = hub.background, onCheckedChange = null, enabled = !busy)
                }
                if (hub.computers.isNotEmpty()) MoveHub(model, hub)
            }
            model.hubNote?.let { NoteText(it) }
            Tip(R.string.hub_body)
        }
    }
}

/** One switch of strict networks, which asks before it changes the hub. */
@Composable
private fun StrictSwitch(label: String, on: Boolean, enabled: Boolean, flip: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch, enabled = enabled, onClick = flip),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = on, onCheckedChange = null, enabled = enabled)
    }
}

/**
 * Moving the hub to a computer (docs/design.md, "Moving the hub to a
 * computer"): the suggestion of one that is always on, once, and a button
 * for each computer the hub can move to, each asking first.
 */
@Composable
private fun MoveHub(model: AppModel, hub: AppModel.Hub) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var asking by remember { mutableStateOf<Pair<String, String>?>(null) }
    val ready = hub.forwarder != null
    Text(stringResource(R.string.hub_move_title), fontWeight = FontWeight.SemiBold)
    if (!ready) Text(stringResource(R.string.hub_move_needs_forwarder), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
    hub.suggested?.let { s ->
        Text(stringResource(R.string.hub_suggest, s.second), style = MaterialTheme.typography.bodyMedium)
        AccentButton(stringResource(R.string.hub_suggest_yes), enabled = ready, onClick = { asking = s })
        QuietButton(stringResource(R.string.hub_suggest_keep), onClick = { scope.launch { model.keepPhoneHub() } })
    }
    Tip(R.string.hub_move_body)
    for (c in hub.computers.filter { it != hub.suggested }) {
        QuietButton(stringResource(R.string.hub_move_to, c.second), enabled = ready, onClick = { asking = c })
    }
    asking?.let { c ->
        AlertDialog(
            onDismissRequest = { asking = null },
            title = { Text(stringResource(R.string.hub_move_confirm_title, c.second)) },
            text = { Text(stringResource(R.string.hub_move_confirm_body, c.second)) },
            confirmButton = {
                TextButton(onClick = {
                    asking = null
                    scope.launch { model.moveHub(c.first) }
                }) { Text(stringResource(R.string.hub_move_confirm), color = palette.accent) }
            },
            dismissButton = { TextButton(onClick = { asking = null }) { Text(stringResource(R.string.cancel)) } },
            containerColor = palette.surface,
            titleContentColor = palette.text,
            textContentColor = palette.textDim,
        )
    }
}

/**
 * Home's + "Send an invitation": any admin makes one, on this phone while it
 * is the group's hub, else through a hub of the group it reaches; a phone
 * that is no admin says where to make one.
 */
@Composable
internal fun InviteSection(model: AppModel) {
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        if (model.isAdmin) {
            InviteFromAfar(model)
        } else {
            Text(stringResource(R.string.invite_on_hub), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/**
 * A remote invitation for a device far away (docs/protocol.md, section 12):
 * the button that opens it, then its QR code, its file to share as the
 * fallback, and the question about the device that used it, with the
 * fingerprint to compare.
 */
@Composable
private fun InviteFromAfar(model: AppModel) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Text(stringResource(R.string.invite_title), fontWeight = FontWeight.SemiBold)
    val invite = model.invite
    if (invite == null) {
        Tip(R.string.invite_body)
        QuietButton(stringResource(R.string.invite_open), onClick = { scope.launch { model.openInvite() } })
    } else {
        val until = DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).format(invite.expires.atZone(ZoneId.systemDefault()))
        val label = stringResource(R.string.invite_qr_label)
        QrCode(
            invite.text,
            Modifier.widthIn(max = 280.dp).fillMaxWidth().aspectRatio(1f)
                .clip(RoundedCornerShape(LocalStyle.current.radiusCard)).background(Color.White).padding(Tokens.spacingMedium)
                .semantics { contentDescription = label },
        )
        Text(stringResource(R.string.invite_open_until, until), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        QuietButton(stringResource(R.string.invite_share), onClick = { context.startActivity(Invitations.share(context, invite.file)) })
        QuietButton(stringResource(R.string.invite_cancel), onClick = model::cancelInvite)
        invite.request?.let { req ->
            AlertDialog(
                onDismissRequest = {},
                title = { Text(stringResource(R.string.invite_ask_title, req.info.name)) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                        Text(stringResource(R.string.invite_ask_body, req.info.os))
                        Text(req.fingerprint, fontFamily = FontFamily.Monospace, color = palette.text)
                    }
                },
                confirmButton = { TextButton(onClick = { model.answer(true) }) { Text(stringResource(R.string.invite_admit), color = palette.accent) } },
                dismissButton = { TextButton(onClick = { model.answer(false) }) { Text(stringResource(R.string.invite_decline)) } },
                containerColor = palette.surface,
                titleContentColor = palette.text,
                textContentColor = palette.textDim,
            )
        }
    }
    model.inviteNote?.let { NoteText(it) }
}

@Composable
internal fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Text(title, style = MaterialTheme.typography.titleSmall, color = LocalPalette.current.textDim)
    Column(Modifier.fillMaxWidth().card(), content = content)
}

@Composable
internal fun Choice(title: String, selected: Boolean, select: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().focusRing().clickable(role = Role.RadioButton, onClick = select).padding(horizontal = Tokens.spacingMedium, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, modifier = Modifier.weight(1f))
        RadioButton(selected = selected, onClick = null)
    }
}

// Parts

/** A page with a title and a way back. */
@Composable
internal fun Page(title: String, back: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Back points the way the screen came from: right in Arabic and Hebrew.
            IconText(if (LocalLayoutDirection.current == LayoutDirection.Rtl) "→" else "←", stringResource(R.string.back)) { back() }
            Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(start = Tokens.spacingMedium))
        }
        content()
    }
}

/** A round button with a symbol, and its name for TalkBack. */
@Composable
internal fun IconText(symbol: String, label: String, small: Boolean = false, onClick: () -> Unit) {
    val palette = LocalPalette.current
    Box(
        Modifier.size(if (small) 32.dp else 44.dp).clip(CircleShape).background(if (small) Color.Transparent else palette.surface)
            .focusRing(CircleShape).clickable(role = Role.Button, onClick = onClick).semantics { contentDescription = label },
        contentAlignment = Alignment.Center,
    ) {
        Text(symbol, color = if (small) palette.textDim else palette.text, style = glyph(if (small) 16.dp else 18.dp))
    }
}

/**
 * A symbol's style in a round button of a fixed size: its size does not
 * follow the font scale, which would push it out of its circle, and the
 * button's name for TalkBack carries the meaning.
 */
@Composable
internal fun glyph(size: Dp): TextStyle {
    val sp = with(LocalDensity.current) { size.toSp() }
    return MaterialTheme.typography.titleMedium.copy(fontSize = sp, lineHeight = sp)
}

/**
 * A tip in place of a long text under a setting: said once, until the
 * user closes it (docs/apps.md, Settings).
 */
@Composable
internal fun Tip(@StringRes text: Int, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val key = remember(text) { "tip." + context.resources.getResourceEntryName(text) }
    val prefs = remember { context.getSharedPreferences("tips", Context.MODE_PRIVATE) }
    var closed by remember(key) { mutableStateOf(prefs.getBoolean(key, false)) }
    if (closed) return
    val palette = LocalPalette.current
    Row(
        modifier.fillMaxWidth().clip(RoundedCornerShape(LocalStyle.current.radiusCard)).background(palette.accent.copy(alpha = 0.10f)).padding(Tokens.spacingSmall),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall),
    ) {
        Text("💡", modifier = Modifier.semantics { contentDescription = "" })
        Text(stringResource(text), style = MaterialTheme.typography.bodySmall, color = palette.text, modifier = Modifier.weight(1f))
        IconText("✕", stringResource(R.string.close_tip), small = true) {
            closed = true
            prefs.edit().putBoolean(key, true).apply()
        }
    }
}

/** The look: light, dark or the system's as icons, the colour, and the language. */
@Composable
private fun Appearance(model: AppModel) {
    val palette = LocalPalette.current
    val activity = LocalActivity.current
    Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
        Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            for (a in Appearance.entries) {
                val chosen = model.appearance == a
                val title = stringResource(a.title)
                Box(
                    Modifier.size(48.dp).clip(CircleShape).background(if (chosen) palette.accent else palette.surface)
                        .focusRing(CircleShape).clickable(role = Role.RadioButton) { model.choose(a) }
                        .semantics {
                            contentDescription = title
                            selected = chosen
                        },
                    contentAlignment = Alignment.Center,
                ) {
                    Text(a.symbol, style = MaterialTheme.typography.titleMedium, color = if (chosen) palette.onAccent else palette.text)
                }
            }
            Spacer(Modifier.weight(1f))
            var open by remember { mutableStateOf(false) }
            Box {
                val chosen = model.settings.language
                TextButton(onClick = { open = true }) {
                    Text("文A " + (chosen.ownName ?: stringResource(R.string.language_system)), color = palette.text)
                }
                DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                    for (l in LanguageChoice.entries) {
                        DropdownMenuItem(text = { Text(l.ownName ?: stringResource(R.string.language_system)) }, onClick = {
                            open = false
                            if (model.settings.language != l) {
                                model.settings.language = l
                                activity?.recreate()
                            }
                        })
                    }
                }
            }
        }
        ThemeSwatches(model.theme) { model.choose(it) }
    }
}

/** A note: the line, and the error underneath when details are on. */
@Composable
internal fun NoteText(note: AppModel.Note, dim: Boolean = false) {
    val palette = LocalPalette.current
    val color = if (note.error && !dim) palette.danger else palette.textDim
    Column(Modifier.fillMaxWidth()) {
        Text(stringResource(note.text), color = if (note.error) palette.danger else color)
        note.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = palette.textDim) }
    }
}

/**
 * The themes as swatches, five a row: each its background and its accent,
 * the chosen one ringed and ticked; Material You as a swatch of the
 * themes' accents.
 */
@Composable
private fun ThemeSwatches(selection: String, choose: (String) -> Unit) {
    val palette = LocalPalette.current
    Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
        for (row in ThemeChoice.offered.chunked(5)) {
            Row(Modifier.fillMaxWidth()) {
                for (name in row) {
                    val chosen = name == selection
                    val theme = themeNamed(name)
                    val swatch = if (palette.dark) theme.dark else theme.light
                    val fill = if (name == ThemeChoice.MATERIAL) {
                        Brush.sweepGradient(Tokens.themes.map { (if (palette.dark) it.dark else it.light).accent })
                    } else {
                        Brush.linearGradient(0.5f to swatch.background, 0.5f to swatch.accent)
                    }
                    Column(
                        Modifier.weight(1f).focusRing().clickable(role = Role.RadioButton) { choose(name) }
                            .semantics(mergeDescendants = true) { selected = chosen },
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Box(
                            Modifier.size(42.dp).border(2.dp, if (chosen) palette.accent else palette.line, CircleShape).padding(3.dp)
                                .clip(CircleShape).background(fill),
                            contentAlignment = Alignment.Center,
                        ) {
                            if (chosen) Text("✓", color = if (name == ThemeChoice.MATERIAL) swatch.onAccent else swatch.text, fontWeight = FontWeight.Bold, style = glyph(16.dp))
                        }
                        // As many lines as it takes: "Material You", the longer names in Spanish and Swahili, and large text.
                        Text(stringResource(ThemeChoice.title(name)), style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center, color = palette.textDim)
                    }
                }
                repeat(5 - row.size) { Spacer(Modifier.weight(1f)) }
            }
        }
    }
}

/** A switch for each kind of the group's events (GroupEvent.Kind). */
@Composable
private fun Notifications(notifier: Notifier) {
    val palette = LocalPalette.current
    Section(stringResource(R.string.notifications)) {
        GroupEvent.Kind.entries.forEachIndexed { i, kind ->
            if (i > 0) HorizontalDivider(color = palette.line)
            var on by remember { mutableStateOf(notifier.on(kind)) }
            Row(
                Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch) {
                    on = !on
                    notifier.set(kind, on)
                }.padding(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(kind.title), modifier = Modifier.weight(1f))
                Switch(checked = on, onCheckedChange = null)
            }
        }
    }
    Tip(R.string.notifications_body)
}

/** Keeps the activity's window out of screenshots and the recent apps' preview while shown. */
@Composable
internal fun SecureWindow() {
    val context = LocalContext.current
    DisposableEffect(context) {
        var c = context
        while (c is android.content.ContextWrapper && c !is android.app.Activity) c = c.baseContext
        val window = (c as? android.app.Activity)?.window
        window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE) }
    }
}
