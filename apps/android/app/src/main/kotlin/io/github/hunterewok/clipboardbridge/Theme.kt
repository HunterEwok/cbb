// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.os.Build
import androidx.annotation.StringRes
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * The colour the user picks in Settings: one of Tokens.colors by its name,
 * Terminal by default, or Material You, the wallpaper's colours (Android 12
 * and later).
 */
object ColorChoice {
    const val MATERIAL = "material"

    /** The names this phone offers, Material You only where Android has the wallpaper's colours. */
    val offered: List<String> get() = Tokens.colors.map { it.name } + if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) listOf(MATERIAL) else emptyList()

    @StringRes
    fun title(name: String): Int = when (name) {
        "midnight" -> R.string.color_midnight
        "amber" -> R.string.color_amber
        "ocean" -> R.string.color_ocean
        "teal" -> R.string.color_teal
        "coral" -> R.string.color_coral
        "rose" -> R.string.color_rose
        "lime" -> R.string.color_lime
        "graphite" -> R.string.color_graphite
        "ruby" -> R.string.color_ruby
        MATERIAL -> R.string.theme_material
        else -> R.string.color_terminal
    }
}

/** Light or dark, or as the system has it. */
enum class Appearance(val key: String, @StringRes val title: Int) {
    SYSTEM("system", R.string.theme_system),
    DARK("dark", R.string.theme_dark),
    LIGHT("light", R.string.theme_light),
    ;

    companion object {
        fun of(key: String?): Appearance = entries.firstOrNull { it.key == key } ?: SYSTEM
    }
}

val LocalPalette = staticCompositionLocalOf { Tokens.colors.first().dark }

/** The palette of a Material colour scheme, for Material You. */
private fun ColorScheme.palette(dark: Boolean) = Palette(
    dark = dark,
    background = background,
    surface = surfaceContainer,
    grid = outlineVariant.copy(alpha = 0.35f),
    text = onBackground,
    textDim = onSurfaceVariant,
    accent = primary,
    onAccent = onPrimary,
    danger = error,
)

/** The Material colour scheme of one of the app's palettes, for the platform's controls. */
private fun Palette.scheme(): ColorScheme {
    val base = if (dark) darkColorScheme() else lightColorScheme()
    return base.copy(
        primary = accent,
        onPrimary = onAccent,
        secondary = accent,
        onSecondary = onAccent,
        background = background,
        onBackground = text,
        surface = background,
        onSurface = text,
        surfaceVariant = surface,
        onSurfaceVariant = textDim,
        surfaceContainer = surface,
        surfaceContainerLow = surface,
        surfaceContainerHigh = surface,
        surfaceContainerHighest = surface,
        outline = textDim,
        error = danger,
    )
}

/** Applies the chosen colour and appearance to everything inside. */
@Composable
fun AppTheme(color: String, appearance: Appearance, content: @Composable () -> Unit) {
    val dark = when (appearance) {
        Appearance.SYSTEM -> isSystemInDarkTheme()
        Appearance.DARK -> true
        Appearance.LIGHT -> false
    }
    val context = LocalContext.current
    val (palette, scheme) = when {
        color == ColorChoice.MATERIAL && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val s = if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            s.palette(dark) to s
        }
        else -> {
            val p = paletteNamed(color).let { if (dark) it.dark else it.light }
            p to p.scheme()
        }
    }
    CompositionLocalProvider(LocalPalette provides palette) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/** The background: the deep colour with a glow of the accent from the top. */
@Composable
fun AppBackground(modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val palette = LocalPalette.current
    val radius = with(LocalDensity.current) { 520.dp.toPx() }
    Box(modifier.fillMaxSize().background(palette.background)) {
        Canvas(Modifier.fillMaxSize()) {
            drawRect(Brush.radialGradient(listOf(palette.soft, Color.Transparent), center = Offset(size.width / 2, 0f), radius = radius))
        }
        content()
    }
}

/** The one big button: rounded, generous, the accent colour. */
@Composable
fun AccentButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val palette = LocalPalette.current
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    Button(
        onClick = onClick,
        enabled = enabled,
        interactionSource = source,
        shape = RoundedCornerShape(Tokens.radiusButton),
        colors = ButtonDefaults.buttonColors(
            containerColor = palette.accent.copy(alpha = if (pressed) 0.8f else 1f),
            contentColor = palette.onAccent,
            disabledContainerColor = palette.accent.copy(alpha = 0.4f),
            disabledContentColor = palette.onAccent.copy(alpha = 0.5f),
        ),
        modifier = modifier.focusRing(RoundedCornerShape(Tokens.radiusButton)).fillMaxWidth().heightIn(min = 64.dp),
    ) {
        Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
    }
}

/** The quieter button next to the big one: the accent colour on a surface. */
@Composable
fun QuietButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val palette = LocalPalette.current
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(Tokens.radiusButton),
        colors = ButtonDefaults.outlinedButtonColors(containerColor = palette.surface.copy(alpha = 0.85f), contentColor = palette.accent),
        border = null,
        contentPadding = PaddingValues(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall),
        modifier = modifier.focusRing(RoundedCornerShape(Tokens.radiusButton)).fillMaxWidth().heightIn(min = 52.dp),
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, textAlign = TextAlign.Center)
    }
}

/** A card on glass: the palette's glass with a hairline, as the iPhone app draws it before Liquid Glass. */
@Composable
fun Modifier.card(radius: Dp = Tokens.radiusCard): Modifier {
    val palette = LocalPalette.current
    val shape = RoundedCornerShape(radius)
    return clip(shape).background(palette.glass).border(1.dp, palette.line, shape)
}

/**
 * A ring in the accent colour while this, or what is inside it, has the
 * focus: the cursor of a TV's D-pad, and of a keyboard. It goes before the
 * clickable it rings.
 */
@Composable
fun Modifier.focusRing(shape: Shape = RoundedCornerShape(Tokens.radiusCard)): Modifier {
    var focused by remember { mutableStateOf(false) }
    val color = LocalPalette.current.accent
    return onFocusChanged { focused = it.hasFocus }.then(if (focused) Modifier.border(3.dp, color, shape) else Modifier)
}

/** A tile of the devices: a card with the tiles' rounder corners. */
@Composable
fun Modifier.glassTile(): Modifier = card(Tokens.radiusTile)
