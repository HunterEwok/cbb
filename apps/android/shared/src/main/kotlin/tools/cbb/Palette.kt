// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp

/** One theme's colours for the dark or the light appearance (apps/design/tokens.json; Tokens.kt is generated from it). */
data class Palette(
    val dark: Boolean,
    val background: Color,
    val surface: Color,
    val grid: Color,
    /** The theme's lines: borders, dividers and the outline of what is off. */
    val line: Color,
    val text: Color,
    val textDim: Color,
    val accent: Color,
    val onAccent: Color,
    val danger: Color,
)

/** What a theme's surfaces are made of. */
enum class Material { FLAT, GLASS, LIQUID, METAL }

/**
 * What a theme draws besides its colours: the faces, the corners, the width
 * of its lines (0: none), its material, whether large surfaces show a grid,
 * whether something off or waiting is dashed and whether small labels are in
 * capitals. The system's own controls keep the system's look.
 */
data class ThemeStyle(
    val display: String,
    val body: String,
    val mono: String,
    val radiusButton: Dp,
    val radiusCard: Dp,
    val radiusTile: Dp,
    val radiusChip: Dp,
    val stroke: Dp,
    val material: Material,
    val grid: Boolean,
    val dashedOff: Boolean,
    val upperLabels: Boolean,
)

/** One of the themes the user picks in Settings: its style and its palettes. */
data class Theme(val name: String, val style: ThemeStyle, val dark: Palette, val light: Palette)

/** The theme named [name], or the default, Blueprint. */
fun themeNamed(name: String): Theme = Tokens.themes.firstOrNull { it.name == name } ?: Tokens.themes.first()

/** A card's or a tile's glass over the background. */
val Palette.glass: Color get() = if (dark) surface.copy(alpha = 0.78f) else Color.White.copy(alpha = 0.86f)

/** A faint wash of the accent, behind an icon or under the glow. */
val Palette.soft: Color get() = accent.copy(alpha = if (dark) 0.16f else 0.10f)
