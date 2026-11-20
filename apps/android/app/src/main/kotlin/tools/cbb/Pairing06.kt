// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import java.time.Instant

/**
 * "Add a device" on 0.6 (docs/apps.md, "Add a device"): a phone without a
 * group makes one first and shows its recovery sheet; then the window is
 * open, its QR code on screen, and the code a device shows when it dials
 * waits for the person's "they match". Leaving the page closes the window.
 */
@Composable
internal fun WindowScreen(model: AppModel, close: () -> Unit) {
    val palette = LocalPalette.current
    LaunchedEffect(Unit) { if (model.addByWindow()) close() }
    BackHandler { close() }
    Page(stringResource(R.string.add_device), close) {
        val qr = model.windowQr
        val ask = model.pairAsk
        when {
            ask != null -> CodeQuestion(model, stringResource(R.string.window_asks, ask.name), ask.code)
            qr != null -> {
                val label = stringResource(R.string.join_qr_label)
                QrCode(
                    qr,
                    Modifier.widthIn(max = 280.dp).fillMaxWidth().aspectRatio(1f).align(Alignment.CenterHorizontally)
                        .clip(RoundedCornerShape(LocalStyle.current.radiusCard)).background(Color.White).padding(Tokens.spacingMedium)
                        .semantics { contentDescription = label },
                )
                Text(stringResource(R.string.window_hint), textAlign = TextAlign.Center, color = palette.textDim, modifier = Modifier.fillMaxWidth())
                Waiting(stringResource(R.string.window_waiting))
            }
            model.message == null -> Waiting(stringResource(R.string.connecting))
        }
        model.message?.let { NoteText(it) }
    }
    model.newSheet?.let { s -> RecoverySheetDialog(s, Instant.now()) { model.newSheet = null } }
}

/**
 * Joining a group of 0.6: the camera reads the QR code a phone of the group
 * shows in "Add a device" (or its text is pasted), this phone dials it, and
 * the code both screens show waits for the person's "they match".
 */
@Composable
internal fun JoinByWindowScreen(model: AppModel) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var joining by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val join = { text: String ->
        if (joining == null) {
            joining = scope.launch {
                try {
                    model.joinByWindow(text)
                } finally {
                    joining = null
                }
            }
        }
    }
    BackHandler {
        joining?.cancel()
        model.cancelJoin()
    }
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
        val ask = model.pairAsk
        when {
            ask != null -> CodeQuestion(model, stringResource(R.string.join_asks, ask.name), ask.code)
            joining != null -> Waiting(stringResource(R.string.connecting))
            else -> {
                ScanOrPaste(model) { join(it) }
                Text(stringResource(R.string.join_scan_hint), textAlign = TextAlign.Center, color = palette.textDim)
            }
        }
        model.message?.let { NoteText(it) }
        QuietButton(stringResource(R.string.cancel), onClick = {
            joining?.cancel()
            model.cancelJoin()
        })
    }
}

/** The code both screens show, and the person's answer. */
@Composable
private fun ColumnScope.CodeQuestion(model: AppModel, who: String, code: String) {
    Text(who, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
    Text(
        code,
        style = MaterialTheme.typography.headlineLarge,
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth().semantics { contentDescription = code.toList().joinToString(" ") },
    )
    Text(stringResource(R.string.code_question), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
    AccentButton(stringResource(R.string.code_match), onClick = { model.answerCode(true) }, modifier = Modifier.fillMaxWidth())
    QuietButton(stringResource(R.string.code_differ), onClick = { model.answerCode(false) }, modifier = Modifier.fillMaxWidth())
}

@Composable
private fun Waiting(text: String) {
    val palette = LocalPalette.current
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        CircularProgressIndicator(Modifier.size(20.dp), color = palette.accent, strokeWidth = 2.dp)
        Text(text)
    }
}

/** The camera, when there is one and it is allowed, and the QR code's text by hand. */
@Composable
private fun ScanOrPaste(model: AppModel, found: (String) -> Unit) {
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
    LaunchedEffect(Unit) { if (hasCamera && !allowed && !asked) launcher.launch(Manifest.permission.CAMERA) }
    var cameraError by remember { mutableStateOf<Exception?>(null) }
    if (hasCamera && allowed && cameraError == null) {
        QrScanner(
            onCode = { text -> if (!model.busy) found(text) },
            modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(LocalStyle.current.radiusCard)),
            onError = { cameraError = it },
        )
    } else if (cameraError != null) {
        NoteText(model.describe(cameraError!!, R.string.camera_failed, log = false))
    } else {
        Text(stringResource(if (hasCamera) R.string.camera_denied else R.string.paste_hint), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
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
    AccentButton(stringResource(R.string.join_go), enabled = typed.isNotBlank() && !model.busy, onClick = { found(typed) })
}
