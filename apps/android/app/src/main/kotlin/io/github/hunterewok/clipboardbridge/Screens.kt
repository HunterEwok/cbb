// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import io.github.hunterewok.clipboardbridge.kit.RemotePaste
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Picks the screen, and asks once for the local network, which finding the computers needs on Android 17. */
@Composable
fun Root(model: AppModel) {
    AppTheme(model.color, model.appearance) {
        AppBackground {
            LocalNetworkPermission(model)
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
 * No group yet: what clipboardbridge does, the note that this phone is
 * ready (once), connecting a device, and joining the group of a phone that
 * already uses clipboardbridge. Theme and language are a tap away.
 */
@Composable
private fun StartScreen(model: AppModel) {
    val palette = LocalPalette.current
    var adding by rememberSaveable { mutableStateOf(false) }
    var settings by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.prepare() }
    if (adding) {
        AddDeviceScreen(model) { adding = false }
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
            // The system's own language, not the one the app shows.
            val system = remember { android.content.res.Resources.getSystem().configuration.locales[0] }
            if (LanguageChoice.offeredOnStart(system)) StartLanguageMenu(model)
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
        Text(stringResource(R.string.tagline), textAlign = TextAlign.Center, color = palette.textDim)
        if (model.isTv) {
            // A TV has no camera to scan a code: it shows its own, for the phone.
            Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
            AccentButton(stringResource(R.string.join_tv), onClick = { model.startJoining() }, modifier = Modifier.widthIn(max = 480.dp))
            Text(stringResource(R.string.join_tv_hint), textAlign = TextAlign.Center, color = palette.textDim)
            model.message?.let { NoteText(it) }
            return@Column
        }
        if (model.welcome) WelcomeCard(model)
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            AccentButton(stringResource(R.string.connect_device), onClick = {
                model.dismissWelcome()
                adding = true
            })
            Text(
                stringResource(R.string.connect_hint),
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                color = palette.textDim,
            )
        }
        QuietButton(stringResource(R.string.join_other), onClick = { model.startJoining() })
        model.message?.let { NoteText(it) }
    }
}

/**
 * The language menu next to the gear when the system's language has no
 * translation; the app shows English then, so English is the one chosen.
 */
@Composable
private fun StartLanguageMenu(model: AppModel) {
    val activity = LocalActivity.current
    var open by remember { mutableStateOf(false) }
    val chosen = model.settings.language.takeIf { it != LanguageChoice.SYSTEM } ?: LanguageChoice.EN
    Box {
        TextButton(onClick = { open = true }, modifier = Modifier.card()) {
            Text("${chosen.ownName} ▾", color = LocalPalette.current.text)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (l in LanguageChoice.translations) {
                DropdownMenuItem(text = { Text(l.ownName ?: "") }, onClick = {
                    open = false
                    model.settings.language = l
                    activity?.recreate()
                })
            }
        }
    }
}

/** Said once, at the first launch: this phone has its own key now, and the next step is to connect a device. */
@Composable
private fun WelcomeCard(model: AppModel) {
    val palette = LocalPalette.current
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("✓ ", color = palette.accent, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.welcome_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            IconText("✕", stringResource(R.string.close), small = true) { model.dismissWelcome() }
        }
        Text(stringResource(R.string.welcome_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
    }
}

// Joining

/** Joining another phone's group: this phone's QR code, which the other phone scans in Add a device. */
@Composable
private fun JoinScreen(model: AppModel) {
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
                    .clip(RoundedCornerShape(Tokens.radiusCard)).background(Color.White).padding(Tokens.spacingMedium)
                    .semantics { contentDescription = label },
            )
            Text(stringResource(if (model.isTv) R.string.join_hint_tv else R.string.join_hint), textAlign = TextAlign.Center, color = palette.textDim)
        } else if (model.message == null) {
            CircularProgressIndicator(color = palette.accent)
        }
        model.message?.let { NoteText(it) }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        QuietButton(stringResource(R.string.cancel), onClick = { model.cancelJoin() })
    }
}

/** A QR code drawn module by module, black on the white behind it. */
@Composable
private fun QrCode(text: String, modifier: Modifier) {
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

/** The camera with a frame; the text of the QR code by hand when there is no camera or it is not allowed. */
@Composable
internal fun AddDeviceScreen(model: AppModel, close: () -> Unit) {
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
    val add = { text: String ->
        if (adding == null) {
            adding = scope.launch {
                try {
                    if (model.scanned(text)) close()
                } finally {
                    adding = null
                }
            }
        }
    }
    BackHandler { close() }
    Page(stringResource(R.string.add_device), close) {
        if (hasCamera && allowed) {
            QrScanner(
                onCode = { text -> scope.launch { if (!model.busy) add(text) } },
                modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(Tokens.radiusCard)),
            )
            Text(stringResource(R.string.scan_hint), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
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
        AccentButton(stringResource(R.string.add), enabled = typed.isNotBlank() && !model.busy, onClick = { add(typed) })
        if (model.busy) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                CircularProgressIndicator(Modifier.size(20.dp), color = palette.accent, strokeWidth = 2.dp)
                Text(stringResource(R.string.connecting))
            }
        } else {
            model.message?.let { NoteText(it) }
        }
    }
}

// Settings

/** Theme and colour, language, sending copies by themselves, sync away from home, notifications, about. */
@Composable
internal fun SettingsScreen(model: AppModel, back: () -> Unit) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val activity = LocalActivity.current
    BackHandler { back() }
    Page(stringResource(R.string.settings), back) {
        Section(stringResource(R.string.theme)) {
            for (a in Appearance.entries) {
                Choice(stringResource(a.title), model.appearance == a) { model.choose(a) }
            }
        }
        Section(stringResource(R.string.color)) { ColorSwatches(model.color) { model.choose(it) } }
        Section(stringResource(R.string.language)) {
            for (l in LanguageChoice.entries) {
                Choice(l.ownName ?: stringResource(R.string.language_system), model.settings.language == l) {
                    if (model.settings.language != l) {
                        model.settings.language = l
                        activity?.recreate()
                    }
                }
            }
        }
        // A TV sends no copies of its own: the service there is only the paste target.
        if (model.phase == AppModel.Phase.HOME && !model.isTv) AutoSend()
        if (model.phase == AppModel.Phase.HOME && !model.isTv) ShareAsk(model)
        if (model.phase == AppModel.Phase.HOME) RemotePasteSection(model.group.pastes, model.isTv)
        // A TV has nothing near it to type into.
        if (model.phase == AppModel.Phase.HOME && !model.isTv) KeyboardSection(model.group.keyboard, model.settings.showsErrorDetails)
        if (model.phase == AppModel.Phase.HOME) model.hub?.let { HubSection(model, it) }
        if (model.phase == AppModel.Phase.HOME) model.away?.let { if (model.hub?.on != true) AwayFromHomeSection(model, it) }
        if (model.phase == AppModel.Phase.HOME) model.blindRelay?.let { BlindRelaySection(model, it) }
        if (WatchLink.available && model.phase == AppModel.Phase.HOME && model.devices.any { it.isSelf && it.isRoot }) WatchSection(model)
        if (model.phase == AppModel.Phase.HOME) Notifications(model.notifier)
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
                    Text(stringResource(R.string.error_details_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
                }
            }
            HorizontalDivider(color = palette.grid)
            Text(
                stringResource(R.string.source),
                color = palette.accent,
                modifier = Modifier.fillMaxWidth().focusRing().clickable(role = Role.Button) {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/HunterEwok/clipboardbridge")))
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
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/HunterEwok/clipboardbridge/releases")))
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
            Text(stringResource(R.string.update_auto_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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
            Text(stringResource(R.string.share_ask_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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
            Text(stringResource(R.string.auto_send_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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
        runCatching { pastes.settings = new }.onFailure { Log.e("clipboardbridge", "saving the remote paste switches", it) }
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
            Text(stringResource(R.string.remote_paste_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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

/** Sync away from home: what it does, the switch, and where it stands. */
@Composable
private fun AwayFromHomeSection(model: AppModel, away: AppModel.Away) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    Section(stringResource(R.string.away_title)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            Row(
                Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch, enabled = !busy) {
                    busy = true
                    scope.launch {
                        model.setAway(!away.on)
                        busy = false
                    }
                },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.away_switch), modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                Switch(checked = away.on, onCheckedChange = null, enabled = !busy)
            }
            val status = when {
                !away.on -> R.string.away_off
                away.status == AwayFromHome.Status.AT_HOME -> R.string.away_at_home
                away.status == AwayFromHome.Status.CONNECTING -> R.string.away_connecting
                away.status == AwayFromHome.Status.CONNECTED -> R.string.away_connected
                else -> R.string.away_waiting
            }
            Text(stringResource(status), color = if (away.status == AwayFromHome.Status.CONNECTED) palette.accent else palette.textDim)
            away.error?.let { NoteText(it) }
            model.awayNote?.let { NoteText(it) }
            Text(stringResource(R.string.away_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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
            Text(stringResource(R.string.relay_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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
            if (hub.on) {
                Text(
                    stringResource(if (hub.home) R.string.hub_on_home else R.string.hub_not_home),
                    style = MaterialTheme.typography.bodyMedium,
                    color = palette.textDim,
                )
                if (!hub.home) QuietButton(stringResource(R.string.hub_add_home), onClick = { if (!busy) act { model.addHomeNetwork() } })
                var address by rememberSaveable(hub.forwarder) { mutableStateOf(hub.forwarder?.endpoint ?: "") }
                var pin by rememberSaveable(hub.forwarder) { mutableStateOf(hub.forwarder?.pin ?: "") }
                Text(stringResource(R.string.hub_forwarder), fontWeight = FontWeight.SemiBold)
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
                val changed = address != (hub.forwarder?.endpoint ?: "") || pin != (hub.forwarder?.pin ?: "")
                AccentButton(stringResource(R.string.hub_forwarder_save), enabled = changed && !busy, onClick = { act { model.setForwarder(address, pin) } })
                Row(
                    Modifier.fillMaxWidth().focusRing().clickable(role = Role.Switch, enabled = !busy) { act { model.setHubInBackground(!hub.background) } },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.hub_background), modifier = Modifier.weight(1f))
                    Switch(checked = hub.background, onCheckedChange = null, enabled = !busy)
                }
                if (hub.status == HubOnPhone.Status.REGISTERED) InviteFromAfar(model)
                if (hub.computers.isNotEmpty()) MoveHub(model, hub)
            }
            model.hubNote?.let { NoteText(it) }
            Text(stringResource(R.string.hub_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        }
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
    Text(stringResource(R.string.hub_move_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
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
 * A remote invitation for a device far away (docs/protocol.md, section 12):
 * the button that opens it, then its file to share, and the question about
 * the device that used it, with the fingerprint to compare.
 */
@Composable
private fun InviteFromAfar(model: AppModel) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Text(stringResource(R.string.invite_title), fontWeight = FontWeight.SemiBold)
    val invite = model.invite
    if (invite == null) {
        Text(stringResource(R.string.invite_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        QuietButton(stringResource(R.string.invite_open), onClick = { scope.launch { model.openInvite() } })
    } else {
        val until = DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).format(invite.expires.atZone(ZoneId.systemDefault()))
        Text(stringResource(R.string.invite_open_until, until), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        AccentButton(stringResource(R.string.invite_share), onClick = { context.startActivity(Invitations.share(context, invite.file)) })
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
            IconText("←", stringResource(R.string.back)) { back() }
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
        Text(symbol, color = if (small) palette.textDim else palette.text, style = MaterialTheme.typography.titleMedium)
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

/** The colours as round swatches, five a row, the chosen one ringed and ticked; Material You as a swatch of the wallpaper's colours. */
@Composable
private fun ColorSwatches(selection: String, choose: (String) -> Unit) {
    val palette = LocalPalette.current
    Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
        for (row in ColorChoice.offered.chunked(5)) {
            Row(Modifier.fillMaxWidth()) {
                for (name in row) {
                    val chosen = name == selection
                    val pair = paletteNamed(name)
                    val swatch = if (palette.dark) pair.dark else pair.light
                    val fill = if (name == ColorChoice.MATERIAL) {
                        Brush.sweepGradient(Tokens.colors.map { (if (palette.dark) it.dark else it.light).accent })
                    } else {
                        SolidColor(swatch.accent)
                    }
                    Column(
                        Modifier.weight(1f).focusRing().clickable(role = Role.RadioButton) { choose(name) }
                            .semantics(mergeDescendants = true) { selected = chosen },
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Box(
                            Modifier.size(42.dp).border(2.dp, if (chosen) swatch.accent else Color.Transparent, CircleShape).padding(3.dp)
                                .clip(CircleShape).background(fill),
                            contentAlignment = Alignment.Center,
                        ) {
                            if (chosen) Text("✓", color = swatch.onAccent, fontWeight = FontWeight.Bold)
                        }
                        Text(stringResource(ColorChoice.title(name)), style = MaterialTheme.typography.labelSmall, maxLines = 1, color = palette.textDim)
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
    Text(stringResource(R.string.notifications_body), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
}
