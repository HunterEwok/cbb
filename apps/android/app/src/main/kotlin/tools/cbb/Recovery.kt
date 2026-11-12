// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import android.content.Context
import android.graphics.Paint
import android.graphics.Typeface
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import android.print.pdf.PrintedPdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import android.util.Log
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import tools.cbb.kit.Core
import kotlinx.coroutines.launch
import java.io.FileOutputStream
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * Settings' recovery key, on the root phone (docs/protocol.md, section 10,
 * "The recovery key"): whether the group has one and since when, making a
 * new one, which shows its sheet once, and removing it.
 */
@Composable
internal fun RecoverySection(model: AppModel) {
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var asking by remember { mutableStateOf<Int?>(null) }
    // The sheet just made, while it shows; nothing keeps it after.
    var sheet by remember { mutableStateOf<Pair<Core.RecoverySheet, Instant>?>(null) }
    var askingPin by remember { mutableStateOf(false) }
    var onCard by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    fun make() {
        busy = true
        scope.launch {
            sheet = model.makeRecovery()?.let { it to Instant.now() }
            busy = false
        }
    }
    Section(stringResource(R.string.recovery_title)) {
        Column(Modifier.padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            val made = model.recoveryMade
            if (made != null) {
                Text(stringResource(R.string.recovery_made, longDate(made)), fontWeight = FontWeight.SemiBold)
                QuietButton(stringResource(R.string.recovery_make_new), onClick = { asking = R.string.recovery_replace_title }, enabled = !busy)
                QuietButton(stringResource(R.string.yubikey_put), onClick = { askingPin = true }, enabled = !busy)
                TextButton(onClick = { asking = R.string.recovery_remove_title }, enabled = !busy) {
                    Text(stringResource(R.string.recovery_remove), color = palette.danger)
                }
            } else {
                Text(stringResource(R.string.recovery_none), color = palette.textDim)
                AccentButton(stringResource(R.string.recovery_make), onClick = ::make, enabled = !busy)
                QuietButton(stringResource(R.string.yubikey_put), onClick = { askingPin = true }, enabled = !busy)
            }
            model.recoveryNote?.let { NoteText(it) }
            Tip(R.string.recovery_body)
        }
    }
    when (asking) {
        R.string.recovery_replace_title -> Confirm(
            stringResource(R.string.recovery_replace_title),
            stringResource(R.string.recovery_replace_body),
            stringResource(R.string.recovery_replace_action),
            dismiss = { asking = null },
            confirm = ::make,
        )
        R.string.recovery_remove_title -> Confirm(
            stringResource(R.string.recovery_remove_title),
            stringResource(R.string.recovery_remove_body),
            stringResource(R.string.remove),
            dismiss = { asking = null },
            confirm = {
                busy = true
                scope.launch {
                    model.removeRecovery()
                    busy = false
                }
            },
        )
    }
    sheet?.let { (s, at) -> RecoverySheetDialog(s, at) { sheet = null } }
    if (askingPin) {
        YubiKeyPinDialog(
            stringResource(R.string.yubikey_put_title),
            stringResource(R.string.yubikey_put_body),
            dismiss = { askingPin = false },
        ) { pin ->
            busy = true
            onCard = scope.launch {
                try {
                    model.makeRecoveryOnCard(pin)
                } finally {
                    busy = false
                    onCard = null
                }
            }
        }
    }
    YubiKeyPrompt(model) { onCard?.cancel() }
}

/**
 * The recovery sheet, shown once and kept out of screenshots and the recent
 * apps: its QR code and text, printing it or saving it as a PDF through
 * Android's printing, and closing it, after which the phone has no copy.
 * Internal for the sheet of the dangerous screens (DangerousScreensTest).
 */
@Composable
internal fun RecoverySheetDialog(sheet: Core.RecoverySheet, made: Instant, done: () -> Unit) {
    val palette = LocalPalette.current
    val context = LocalContext.current
    var askingDone by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<AppModel.Note?>(null) }
    Dialog(
        onDismissRequest = { askingDone = true },
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
            securePolicy = SecureFlagPolicy.SecureOn,
            usePlatformDefaultWidth = false,
        ),
    ) {
        BackHandler { askingDone = true }
        Column(
            Modifier.fillMaxSize().background(palette.background).safeDrawingPadding().verticalScroll(rememberScrollState())
                .padding(Tokens.spacingLarge),
            verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(stringResource(R.string.recovery_title), style = MaterialTheme.typography.titleLarge, color = palette.text)
            Text(stringResource(R.string.recovery_show_once), textAlign = TextAlign.Center, color = palette.textDim)
            RecoveryPage(sheet, made, Modifier.widthIn(max = 520.dp).clip(RoundedCornerShape(Tokens.radiusCard)))
            AccentButton(stringResource(R.string.recovery_print), onClick = {
                failure = try {
                    printSheet(context, sheet, made)
                    null
                } catch (e: Exception) {
                    Log.e(TAG, "printing the recovery sheet", e)
                    AppModel.Note(R.string.recovery_print_failed, e.toString(), error = true)
                }
            }, modifier = Modifier.fillMaxWidth())
            failure?.let { NoteText(it) }
            QuietButton(stringResource(R.string.recovery_done), onClick = { askingDone = true }, modifier = Modifier.fillMaxWidth())
        }
        if (askingDone) {
            AlertDialog(
                onDismissRequest = { askingDone = false },
                title = { Text(stringResource(R.string.recovery_done_title)) },
                text = { Text(stringResource(R.string.recovery_done_body)) },
                confirmButton = { TextButton(onClick = done) { Text(stringResource(R.string.recovery_kept), color = palette.accent) } },
                dismissButton = { TextButton(onClick = { askingDone = false }) { Text(stringResource(R.string.back)) } },
                containerColor = palette.surface,
                titleContentColor = palette.text,
                textContentColor = palette.textDim,
            )
        }
    }
}

/** The page on screen: black on white, as printed. */
@Composable
private fun RecoveryPage(sheet: Core.RecoverySheet, made: Instant, modifier: Modifier) {
    val qr = stringResource(R.string.recovery_qr)
    Column(
        modifier.background(Color.White).padding(Tokens.spacingLarge),
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
    ) {
        Text(stringResource(R.string.recovery_page_title), color = Color.Black, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.recovery_made, longDate(made)), color = Color.Black)
        QrCode(sheet.qr, Modifier.fillMaxWidth(0.8f).aspectRatio(1f).align(Alignment.CenterHorizontally).semantics { contentDescription = qr })
        Text(keyRows(sheet.text), color = Color.Black, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.recovery_page_keep), color = Color.Black, style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.recovery_page_how), color = Color.Black, style = MaterialTheme.typography.bodyMedium)
    }
}

private const val TAG = "cbb"

private fun longDate(at: Instant): String =
    DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG).withZone(ZoneId.systemDefault()).format(at)

/** The key's groups of four, four groups to a line. */
internal fun keyRows(text: String): String =
    text.split("-").chunked(4).joinToString("\n") { it.joinToString(" ") }

/**
 * Hands the sheet to Android's printing, whose dialog also saves it as a
 * PDF; the page is drawn here, so no copy of it is left in the app's files.
 */
private fun printSheet(context: Context, sheet: Core.RecoverySheet, made: Instant) {
    val manager = context.getSystemService(PrintManager::class.java) ?: throw IllegalStateException("no printing on this device")
    val name = context.getString(R.string.recovery_page_title)
    val attributes = PrintAttributes.Builder()
        .setMediaSize(PrintAttributes.MediaSize.ISO_A4)
        .setColorMode(PrintAttributes.COLOR_MODE_MONOCHROME)
        .build()
    manager.print(name, SheetAdapter(context, sheet, made, name), attributes)
}

/** One page: the title, the date, the QR code, the key and what to do with it. */
private class SheetAdapter(
    private val context: Context,
    private val sheet: Core.RecoverySheet,
    private val made: Instant,
    private val name: String,
) : PrintDocumentAdapter() {
    private var attributes: PrintAttributes? = null

    override fun onLayout(old: PrintAttributes?, new: PrintAttributes, cancel: CancellationSignal?, callback: LayoutResultCallback, extras: Bundle?) {
        if (cancel?.isCanceled == true) return callback.onLayoutCancelled()
        attributes = new
        val info = PrintDocumentInfo.Builder("$name.pdf").setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(1).build()
        callback.onLayoutFinished(info, new != old)
    }

    override fun onWrite(pages: Array<out PageRange>, destination: ParcelFileDescriptor, cancel: CancellationSignal?, callback: WriteResultCallback) {
        val doc = PrintedPdfDocument(context, attributes ?: return callback.onWriteFailed("no layout"))
        try {
            val page = doc.startPage(0)
            draw(page.canvas, page.info.contentRect.width().toFloat())
            doc.finishPage(page)
            if (cancel?.isCanceled == true) return callback.onWriteCancelled()
            FileOutputStream(destination.fileDescriptor).use { doc.writeTo(it) }
            callback.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
        } catch (e: Exception) {
            Log.e(TAG, "writing the recovery sheet", e)
            callback.onWriteFailed(e.toString())
        } finally {
            doc.close()
        }
    }

    /** Draws the page in points, width wide from its top left. */
    private fun draw(canvas: android.graphics.Canvas, width: Float) {
        val margin = 36f
        val inner = (width - 2 * margin).toInt()
        var y = margin
        fun text(s: String, size: Float, bold: Boolean = false, mono: Boolean = false) {
            val paint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
                textSize = size
                color = android.graphics.Color.BLACK
                typeface = Typeface.create(if (mono) Typeface.MONOSPACE else Typeface.DEFAULT, if (bold) Typeface.BOLD else Typeface.NORMAL)
            }
            val layout = StaticLayout.Builder.obtain(s, 0, s.length, paint, inner).setAlignment(Layout.Alignment.ALIGN_NORMAL).build()
            canvas.save()
            canvas.translate(margin, y)
            layout.draw(canvas)
            canvas.restore()
            y += layout.height + 14f
        }
        text(context.getString(R.string.recovery_page_title), 20f, bold = true)
        text(context.getString(R.string.recovery_made, longDate(made)), 12f)
        val matrix = QRCodeWriter().encode(sheet.qr, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 0))
        val side = minOf(inner.toFloat(), 260f)
        val cell = side / matrix.width
        val left = margin + (inner - side) / 2
        val black = Paint().apply { color = android.graphics.Color.BLACK }
        for (my in 0 until matrix.height) for (mx in 0 until matrix.width) {
            if (matrix[mx, my]) canvas.drawRect(left + mx * cell, y + my * cell, left + (mx + 1) * cell, y + (my + 1) * cell, black)
        }
        y += side + 18f
        text(keyRows(sheet.text), 14f, bold = true, mono = true)
        text(context.getString(R.string.recovery_page_keep), 11f)
        text(context.getString(R.string.recovery_page_how), 11f)
    }
}
