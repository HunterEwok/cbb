// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.ui.graphics.Color

/** One theme's colours (apps/design/tokens.json; Tokens.kt is generated from it). */
data class Palette(
    val dark: Boolean,
    val background: Color,
    val surface: Color,
    val grid: Color,
    val text: Color,
    val textDim: Color,
    val accent: Color,
    val onAccent: Color,
    val danger: Color,
)

/** One accent colour's palettes for the dark and the light appearance. */
data class PalettePair(val name: String, val dark: Palette, val light: Palette)

/** The colour named [name], or the default, Terminal. */
fun paletteNamed(name: String): PalettePair = Tokens.colors.firstOrNull { it.name == name } ?: Tokens.colors.first()

/** A card's or a tile's glass over the background. */
val Palette.glass: Color get() = if (dark) surface.copy(alpha = 0.78f) else Color.White.copy(alpha = 0.86f)

/** A faint wash of the accent, behind an icon or under the glow. */
val Palette.soft: Color get() = accent.copy(alpha = if (dark) 0.16f else 0.10f)

/** A hairline around glass. */
val Palette.line: Color get() = text.copy(alpha = if (dark) 0.12f else 0.10f)
