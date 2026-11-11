// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

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
import androidx.compose.material3.LocalContentColor
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
 * The theme the user picks in Settings: one of Tokens.themes by its name,
 * Blueprint by default, or Material You, the wallpaper's colours (Android 12
 * and later) in the Precise theme's shape.
 */
object ThemeChoice {
    const val MATERIAL = "material"

    /** The names this phone offers, Material You only where Android has the wallpaper's colours. */
    val offered: List<String> get() = Tokens.themes.map { it.name } + if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) listOf(MATERIAL) else emptyList()

    @StringRes
    fun title(name: String): Int = when (name) {
        "precise" -> R.string.theme_precise
        "glass" -> R.string.theme_glass
        "soft" -> R.string.theme_soft
        "swiss" -> R.string.theme_swiss
        "hardware" -> R.string.theme_hardware
        "deco" -> R.string.theme_deco
        "liquid" -> R.string.theme_liquid
        "terminal" -> R.string.theme_terminal
        "retro" -> R.string.theme_retro
        MATERIAL -> R.string.theme_material
        else -> R.string.theme_blueprint
    }
}

/** Light or dark, or as the system has it. */
enum class Appearance(val key: String, @StringRes val title: Int, val symbol: String) {
    SYSTEM("system", R.string.theme_system, "◐"),
    DARK("dark", R.string.theme_dark, "☾"),
    LIGHT("light", R.string.theme_light, "☀"),
    ;

    companion object {
        fun of(key: String?): Appearance = entries.firstOrNull { it.key == key } ?: SYSTEM
    }
}

val LocalPalette = staticCompositionLocalOf { Tokens.themes.first().dark }

/** The chosen theme's style: corners, lines, material. */
val LocalStyle = staticCompositionLocalOf { Tokens.themes.first().style }

/** The palette of a Material colour scheme, for Material You. */
private fun ColorScheme.palette(dark: Boolean) = Palette(
    dark = dark,
    background = background,
    surface = surfaceContainer,
    grid = outlineVariant.copy(alpha = 0.35f),
    line = outlineVariant,
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
        outlineVariant = line,
        error = danger,
    )
}

/** Applies the chosen theme and appearance to everything inside. */
@Composable
fun AppTheme(theme: String, appearance: Appearance, content: @Composable () -> Unit) {
    val dark = when (appearance) {
        Appearance.SYSTEM -> isSystemInDarkTheme()
        Appearance.DARK -> true
        Appearance.LIGHT -> false
    }
    val context = LocalContext.current
    val (palette, scheme) = when {
        theme == ThemeChoice.MATERIAL && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val s = if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            s.palette(dark) to s
        }
        else -> {
            val p = themeNamed(theme).let { if (dark) it.dark else it.light }
            p to p.scheme()
        }
    }
    val style = themeNamed(if (theme == ThemeChoice.MATERIAL) "precise" else theme).style
    CompositionLocalProvider(LocalPalette provides palette, LocalStyle provides style) {
        // MaterialTheme alone leaves a text without a colour black, which a
        // Surface would set: every screen's own text colour is the palette's.
        MaterialTheme(colorScheme = scheme) {
            CompositionLocalProvider(LocalContentColor provides palette.text, content = content)
        }
    }
}

/**
 * The background: the theme's colour, with a grid as on a drawing sheet
 * where the theme has one, or a glow of the accent from the top under glass.
 */
@Composable
fun AppBackground(modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val palette = LocalPalette.current
    val style = LocalStyle.current
    val density = LocalDensity.current
    val radius = with(density) { 520.dp.toPx() }
    val cell = with(density) { 24.dp.toPx() }
    Box(modifier.fillMaxSize().background(palette.background)) {
        Canvas(Modifier.fillMaxSize()) {
            if (style.grid) {
                var x = 0f
                while (x < size.width) {
                    drawLine(palette.grid, Offset(x, 0f), Offset(x, size.height))
                    x += cell
                }
                var y = 0f
                while (y < size.height) {
                    drawLine(palette.grid, Offset(0f, y), Offset(size.width, y))
                    y += cell
                }
            }
            if (style.material == Material.GLASS || style.material == Material.LIQUID) {
                drawRect(Brush.radialGradient(listOf(palette.soft, Color.Transparent), center = Offset(size.width / 2, 0f), radius = radius))
            }
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
        shape = RoundedCornerShape(LocalStyle.current.radiusButton),
        colors = ButtonDefaults.buttonColors(
            containerColor = palette.accent.copy(alpha = if (pressed) 0.8f else 1f),
            contentColor = palette.onAccent,
            disabledContainerColor = palette.accent.copy(alpha = 0.4f),
            disabledContentColor = palette.onAccent.copy(alpha = 0.5f),
        ),
        modifier = modifier.focusRing(RoundedCornerShape(LocalStyle.current.radiusButton)).fillMaxWidth().heightIn(min = 64.dp),
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
        shape = RoundedCornerShape(LocalStyle.current.radiusButton),
        colors = ButtonDefaults.outlinedButtonColors(containerColor = palette.surface.copy(alpha = 0.85f), contentColor = palette.accent),
        border = null,
        contentPadding = PaddingValues(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall),
        modifier = modifier.focusRing(RoundedCornerShape(LocalStyle.current.radiusButton)).fillMaxWidth().heightIn(min = 52.dp),
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, textAlign = TextAlign.Center)
    }
}

/** A card: glass in the glass themes, the theme's surface in the others, with the theme's line around it. */
@Composable
fun Modifier.card(radius: Dp = LocalStyle.current.radiusCard): Modifier {
    val palette = LocalPalette.current
    val style = LocalStyle.current
    val shape = RoundedCornerShape(radius)
    val fill = if (style.material == Material.GLASS || style.material == Material.LIQUID) palette.glass else palette.surface
    val clipped = clip(shape).background(fill)
    return if (style.stroke > 0.dp) clipped.border(style.stroke, palette.line, shape) else clipped
}

/**
 * A ring in the accent colour while this, or what is inside it, has the
 * focus: the cursor of a TV's D-pad, and of a keyboard. It goes before the
 * clickable it rings.
 */
@Composable
fun Modifier.focusRing(shape: Shape = RoundedCornerShape(LocalStyle.current.radiusCard)): Modifier {
    var focused by remember { mutableStateOf(false) }
    val color = LocalPalette.current.accent
    return onFocusChanged { focused = it.hasFocus }.then(if (focused) Modifier.border(3.dp, color, shape) else Modifier)
}

/** A tile of the devices: a card with the tiles' rounder corners. */
@Composable
fun Modifier.glassTile(): Modifier = card(LocalStyle.current.radiusTile)
