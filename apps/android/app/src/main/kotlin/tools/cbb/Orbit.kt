// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sin

/** How many devices the inner orbit holds; the rest go on the outer one. */
private const val INNER = 6

/**
 * The devices on orbits around this phone, which stands at the centre, a
 * dashed line to each one online; a device, this phone too, opens its
 * details beside them.
 */
@Composable
internal fun Orbit(
    devices: List<LiveGroup.Device>,
    selected: String?,
    select: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = LocalPalette.current
    val others = devices.filter { !it.isSelf }
    BoxWithConstraints(modifier) {
        val density = LocalDensity.current
        val w = with(density) { maxWidth.toPx() }
        val h = with(density) { maxHeight.toPx() }
        val center = Offset(w / 2, h / 2)
        val side = min(w, h)
        val inner = side * 0.28f
        val outer = side * 0.44f
        val spots = spots(others.size, center, inner, outer)
        Canvas(Modifier.fillMaxSize()) {
            val ring = Stroke(width = 1.dp.toPx())
            drawCircle(palette.line, inner, center, style = ring)
            if (others.size > INNER) drawCircle(palette.line, outer, center, style = ring)
            val dash = Stroke(width = 1.5.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(6.dp.toPx(), 6.dp.toPx())))
            others.forEachIndexed { i, d ->
                if (d.online) drawLine(palette.accent.copy(alpha = 0.5f), center, spots[i], dash.width, pathEffect = dash.pathEffect)
            }
        }
        // The centre: this phone, which opens its own details.
        devices.firstOrNull { it.isSelf }?.let { me ->
            val hub = 96.dp
            val hubPx = with(density) { hub.toPx() }
            val label = stringResource(R.string.this_phone)
            Box(
                Modifier.offset { IntOffset((center.x - hubPx / 2).roundToInt(), (center.y - hubPx / 2).roundToInt()) }
                    .size(hub).clip(CircleShape).background(palette.accent)
                    .then(if (me.id == selected) Modifier.border(3.dp, palette.text, CircleShape) else Modifier)
                    .focusRing().clickable(role = Role.Button) { select(me.id) }.semantics { contentDescription = label },
                contentAlignment = Alignment.Center,
            ) {
                DeviceGlyph(me.kind, palette.onAccent, 48.dp)
            }
        }
        val nodeW = 104.dp
        val nodeWPx = with(density) { nodeW.toPx() }
        val nodeHPx = with(density) { 84.dp.toPx() }
        others.forEachIndexed { i, d ->
            val p = spots[i]
            val label = "${d.name}, ${stringResource(if (d.online) R.string.online else R.string.offline)}"
            Column(
                Modifier.offset { IntOffset((p.x - nodeWPx / 2).roundToInt(), (p.y - nodeHPx / 2).roundToInt()) }
                    .width(nodeW).focusRing().clickable(role = Role.Button) { select(d.id) }.semantics(mergeDescendants = true) { contentDescription = label },
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Box(if (d.id == selected) Modifier.border(2.dp, palette.accent, CircleShape) else Modifier) { DeviceIcon(d, 52.dp) }
                Text(d.name, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center)
            }
        }
    }
}

/** Where each device stands: up to INNER on the inner orbit, the rest on the outer, from the top clockwise. */
private fun spots(n: Int, center: Offset, inner: Float, outer: Float): List<Offset> {
    val onInner = min(n, INNER)
    val onOuter = n - onInner
    fun ring(count: Int, radius: Float, turn: Double) = (0 until count).map {
        val a = -Math.PI / 2 + turn + 2 * Math.PI * it / count
        Offset(center.x + radius * cos(a).toFloat(), center.y + radius * sin(a).toFloat())
    }
    return ring(onInner, inner, 0.0) + ring(onOuter, outer, if (onOuter > 0) Math.PI / onOuter else 0.0)
}
