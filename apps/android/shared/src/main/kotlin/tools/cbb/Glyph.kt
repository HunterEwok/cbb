// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp

/**
 * A device kind's outline by its form ("laptop", "phone", …; DeviceKind in
 * the app), drawn on a grid of 24 by 24, as the system's line icons are;
 * an unknown form is drawn as other.
 */
@Composable
fun FormGlyph(form: String, color: Color, size: Dp) {
    Canvas(Modifier.size(size)) {
        val u = this.size.minDimension / 24f
        val stroke = Stroke(width = 1.8f * u, cap = StrokeCap.Round)
        fun box(x: Float, y: Float, w: Float, h: Float, r: Float = 1.5f) =
            drawRoundRect(color, Offset(x * u, y * u), Size(w * u, h * u), CornerRadius(r * u), style = stroke)
        fun line(x1: Float, y1: Float, x2: Float, y2: Float) = drawLine(color, Offset(x1 * u, y1 * u), Offset(x2 * u, y2 * u), stroke.width, StrokeCap.Round)
        fun dot(x: Float, y: Float, r: Float = 1f) = drawCircle(color, r * u, Offset(x * u, y * u))
        when (form) {
            "laptop" -> { box(4f, 5f, 16f, 11f); line(2f, 19f, 22f, 19f) }
            "desktop" -> { box(3f, 4f, 18f, 12f); line(12f, 16f, 12f, 20f); line(8f, 20f, 16f, 20f) }
            "phone" -> { box(7f, 2.5f, 10f, 19f, 2.5f); line(10.5f, 18.5f, 13.5f, 18.5f) }
            "tablet" -> { box(4.5f, 2.5f, 15f, 19f, 2f); line(10.5f, 18.5f, 13.5f, 18.5f) }
            "tv" -> { box(2.5f, 5f, 19f, 12f); line(8f, 20.5f, 16f, 20.5f); line(9f, 2f, 12f, 5f); line(15f, 2f, 12f, 5f) }
            "board" -> {
                box(6f, 6f, 12f, 12f)
                box(9.5f, 9.5f, 5f, 5f, 0.8f)
                for (p in listOf(9f, 12f, 15f)) { line(p, 2.5f, p, 6f); line(p, 18f, p, 21.5f); line(2.5f, p, 6f, p); line(18f, p, 21.5f, p) }
            }
            "server" -> { box(4f, 3.5f, 16f, 7f); box(4f, 13.5f, 16f, 7f); dot(8f, 7f); dot(8f, 17f) }
            "router" -> { box(3f, 12f, 18f, 8f); line(7f, 12f, 5f, 4f); line(17f, 12f, 19f, 4f); dot(7.5f, 16f); dot(11f, 16f) }
            "console" -> {
                box(2.5f, 7f, 19f, 11f, 5f)
                line(7f, 10.5f, 7f, 14.5f); line(5f, 12.5f, 9f, 12.5f)
                dot(15.5f, 11f); dot(17.5f, 13.5f)
            }
            "watch" -> { box(7f, 6f, 10f, 12f, 3f); line(9f, 6f, 9.5f, 2.5f); line(15f, 6f, 14.5f, 2.5f); line(9f, 18f, 9.5f, 21.5f); line(15f, 18f, 14.5f, 21.5f) }
            "retro" -> {
                box(2f, 7f, 20f, 10f)
                for (x in listOf(6f, 9f, 12f, 15f, 18f)) dot(x, 10.5f, 0.8f)
                line(7f, 14f, 17f, 14f)
            }
            else -> { box(4f, 7f, 16f, 13f); line(4f, 11f, 20f, 11f); line(9f, 3.5f, 4f, 7f); line(15f, 3.5f, 20f, 7f); line(9f, 3.5f, 15f, 3.5f) }
        }
    }
}

/**
 * The two switches' outlines on the same grid (docs/apps.md, Home): "house"
 * for sync on this device, "globe" for Everywhere, sync away from home.
 */
@Composable
fun SwitchGlyph(name: String, color: Color, size: Dp) {
    Canvas(Modifier.size(size)) {
        val u = this.size.minDimension / 24f
        val stroke = Stroke(width = 1.8f * u, cap = StrokeCap.Round)
        fun line(x1: Float, y1: Float, x2: Float, y2: Float) = drawLine(color, Offset(x1 * u, y1 * u), Offset(x2 * u, y2 * u), stroke.width, StrokeCap.Round)
        when (name) {
            "house" -> {
                line(3f, 11.5f, 12f, 3.5f); line(12f, 3.5f, 21f, 11.5f)
                line(5.5f, 9.5f, 5.5f, 20.5f); line(18.5f, 9.5f, 18.5f, 20.5f); line(5.5f, 20.5f, 18.5f, 20.5f)
                line(10f, 20.5f, 10f, 15f); line(10f, 15f, 14f, 15f); line(14f, 15f, 14f, 20.5f)
            }
            else -> {
                drawCircle(color, 9f * u, Offset(12f * u, 12f * u), style = stroke)
                drawOval(color, Offset(8f * u, 3f * u), Size(8f * u, 18f * u), style = stroke)
                line(3f, 12f, 21f, 12f)
                line(4.5f, 7.5f, 19.5f, 7.5f); line(4.5f, 16.5f, 19.5f, 16.5f)
            }
        }
    }
}
