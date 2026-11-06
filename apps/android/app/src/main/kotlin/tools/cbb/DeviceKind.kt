// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import tools.cbb.kit.Pairing

/** What a device is, for its icon and its type; the same kinds as the iPhone app's. */
enum class DeviceKind(val form: String, @StringRes val title: Int) {
    LAPTOP("laptop", R.string.kind_laptop),
    DESKTOP("desktop", R.string.kind_desktop),
    PHONE("phone", R.string.kind_phone),
    TABLET("tablet", R.string.kind_tablet),
    TV("tv", R.string.kind_tv),
    BOARD("board", R.string.kind_board),
    SERVER("server", R.string.kind_server),
    ROUTER("router", R.string.kind_router),
    CONSOLE("console", R.string.kind_console),
    WATCH("watch", R.string.kind_watch),
    RETRO("retro", R.string.kind_retro),
    OTHER("other", R.string.kind_other),
    ;

    companion object {
        fun of(form: String?): DeviceKind? = entries.firstOrNull { it.form == form }
    }
}

/** Its kind as its hello says, or else as its role and system tell: a Mac is taken for a laptop, another computer for a desktop. */
val LiveGroup.Device.kind: DeviceKind
    get() = DeviceKind.of(device?.form) ?: when {
        role == "phone" -> DeviceKind.PHONE
        role == "lite" -> DeviceKind.BOARD
        role == "watch" -> DeviceKind.WATCH
        os == "macos" -> DeviceKind.LAPTOP
        Pairing.Info.isPhone(os ?: "") -> DeviceKind.PHONE
        else -> DeviceKind.DESKTOP
    }

/** The name of its operating system, the same in every language; null when the records do not tell. */
val LiveGroup.Device.system: String?
    get() = when (os) {
        "linux" -> "Linux"
        "windows" -> "Windows"
        "macos" -> "macOS"
        "ios" -> "iOS"
        "android" -> "Android"
        "aurora" -> "Aurora OS"
        "sailfish" -> "Sailfish OS"
        "watchos" -> "watchOS"
        "wearos" -> "Wear OS"
        else -> null
    }

/** Its system with the version its hello gives, as "macOS 15.1"; Linux names its distribution, which says more. */
val LiveGroup.Device.systemWithVersion: String?
    get() {
        val v = device?.osVersion
        val s = system ?: return v
        return when {
            v == null -> s
            os == "linux" -> v
            else -> "$s $v"
        }
    }

/** Its place in the group, in a word; null for a plain member. */
@get:StringRes
val LiveGroup.Device.standing: Int?
    get() = when {
        isSelf -> if (admin) R.string.this_phone_admin else R.string.this_phone
        frozen -> R.string.frozen
        isRoot -> R.string.root
        admin -> R.string.admin
        else -> null
    }

/** A device's icon on a soft square, bright while it is online. */
@Composable
fun DeviceIcon(d: LiveGroup.Device, size: Dp = 44.dp) {
    val palette = LocalPalette.current
    Box(
        Modifier.size(size).clip(RoundedCornerShape(size * 0.28f)).background(if (d.online) palette.soft else palette.line),
        contentAlignment = Alignment.Center,
    ) {
        DeviceGlyph(d.kind, if (d.online) palette.accent else palette.textDim, size * 0.56f)
    }
}

/** A live dot: the accent while online. */
@Composable
fun OnlineDot(online: Boolean, size: Dp = 8.dp) {
    val palette = LocalPalette.current
    Box(Modifier.size(size).clip(CircleShape).background(if (online) palette.accent else palette.textDim.copy(alpha = 0.4f)))
}

/** A kind's outline (FormGlyph, shared with the watch). */
@Composable
fun DeviceGlyph(kind: DeviceKind, color: Color, size: Dp) = FormGlyph(kind.form, color, size)
