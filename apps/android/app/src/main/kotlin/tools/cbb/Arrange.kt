// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.annotation.StringRes
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import tools.cbb.kit.Arrangement as Tiles

/**
 * Arrange mode, the drag and the name prompts, shared by Home and the
 * collections' pages (docs/apps.md, "Collections and the order of the
 * tiles").
 */
@Stable
internal class ArrangeState {
    /** Arrange mode: a tap does not open a tile, and a long press drags it. */
    var on by mutableStateOf(false)

    /** The tile being dragged, how far, and the tile under it. */
    var dragging by mutableStateOf<Tiles.Ref?>(null)
    var offset by mutableStateOf(Offset.Zero)
    var over by mutableStateOf<Tiles.Ref?>(null)

    /** The name prompt that is open. */
    var prompt by mutableStateOf<Prompt?>(null)

    /** Where each tile stands on the screen, to find the one under a drag. */
    val bounds = mutableMapOf<Tiles.Ref, Rect>()
    private var start = Offset.Zero

    sealed interface Prompt {
        /** A new collection of these devices. */
        data class New(val devices: List<String>) : Prompt
        data class Rename(val collection: String, val name: String) : Prompt
    }

    fun begin(ref: Tiles.Ref, at: Offset) {
        start = (bounds[ref]?.topLeft ?: Offset.Zero) + at
        dragging = ref
        offset = Offset.Zero
        over = null
    }

    fun drag(by: Offset) {
        val d = dragging ?: return
        offset += by
        val at = start + offset
        over = bounds.entries.firstOrNull { (ref, r) -> ref != d && r.contains(at) }?.key
    }

    /**
     * Ends the drag: a device dropped on a collection goes into it, and a
     * tile dropped on another of its level takes its place.
     */
    fun drop(model: AppModel, level: List<Tiles.Ref>) {
        val d = dragging
        val target = over
        dragging = null
        over = null
        offset = Offset.Zero
        if (d == null || target == null) return
        if (d is Tiles.Ref.Device && target is Tiles.Ref.Collection) {
            model.arrange(Tiles.Op.Into(d.id, target.id))
            return
        }
        val from = level.indexOf(d)
        val to = level.indexOf(target)
        if (from < 0 || to < 0) return
        model.arrange(Tiles.Op.Move(d, if (from < to) level.getOrNull(to + 1) else target))
    }

    fun cancel() {
        dragging = null
        over = null
        offset = Offset.Zero
    }
}

internal val LocalArrange = staticCompositionLocalOf { ArrangeState() }

/** The moves of a tile within its level, the same for the menu and for TalkBack. */
private class Moves(val ref: Tiles.Ref, val level: List<Tiles.Ref>, val model: AppModel) {
    private val index = level.indexOf(ref)
    val canMoveEarlier = index > 0
    val canMoveLater = index >= 0 && index + 1 < level.size

    fun toStart() {
        if (canMoveEarlier) model.arrange(Tiles.Op.Move(ref, level.first()))
    }

    fun toEnd() {
        if (canMoveLater) model.arrange(Tiles.Op.Move(ref, null))
    }

    fun earlier() {
        if (canMoveEarlier) model.arrange(Tiles.Op.Move(ref, level[index - 1]))
    }

    fun later() {
        if (canMoveLater) model.arrange(Tiles.Op.Move(ref, level.getOrNull(index + 2)))
    }
}

/**
 * The devices and collections in the user's order, this phone first until
 * it is moved, as tiles or a list; a device opens its details, a collection
 * its page.
 */
@Composable
internal fun ArrangedDevices(model: AppModel, layout: DeviceLayout, select: (String) -> Unit, openCollection: (String) -> Unit) {
    val items = model.arranged
    if (items.isEmpty()) {
        Text(stringResource(R.string.no_computers), color = LocalPalette.current.textDim)
        return
    }
    val level = items.map { it.ref }
    if (layout == DeviceLayout.LIST) {
        Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            for (item in items) {
                when (item) {
                    is AppModel.Arranged.Device -> Arrangeable(model, item.ref, level, item.device.name, Modifier.fillMaxWidth()) { m, open, menu ->
                        DeviceRow(item.device, m, open = if (open) ({ select(item.device.id) }) else null, menu = menu)
                    }
                    is AppModel.Arranged.Collection -> CollectionSection(model, item, level, select, openCollection)
                }
            }
        }
        return
    }
    TileGrid(items.map { it.key }) { key, m ->
        when (val item = items.first { it.key == key }) {
            is AppModel.Arranged.Device -> Arrangeable(model, item.ref, level, item.device.name, m) { inner, open, menu ->
                DeviceTile(item.device, inner, open = if (open) ({ select(item.device.id) }) else null, menu = menu)
            }
            is AppModel.Arranged.Collection -> Arrangeable(model, item.ref, level, item.collection.name, m) { inner, open, menu ->
                CollectionTile(item, inner, open = if (open) ({ openCollection(item.collection.id) }) else null, menu = menu)
            }
        }
    }
}

/**
 * Tiles in rows as wide as the screen allows; the row of a dragged tile
 * stands above the others so the tile passes over them.
 */
@Composable
private fun TileGrid(keys: List<String>, tile: @Composable (String, Modifier) -> Unit) {
    val arrange = LocalArrange.current
    val all = keys
    val dragged = arrange.dragging?.let { r ->
        when (r) {
            is Tiles.Ref.Device -> "d:" + r.id
            is Tiles.Ref.Collection -> "c:" + r.id
        }
    }
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val columns = maxOf(2, (maxWidth / 160.dp).toInt())
        Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            for (row in all.chunked(columns)) {
                Row(Modifier.zIndex(if (row.any { it == dragged }) 1f else 0f), horizontalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
                    for (key in row) tile(key, Modifier.weight(1f))
                    repeat(columns - row.size) { Spacer(Modifier.weight(1f)) }
                }
            }
        }
    }
}

/**
 * A device or a collection with its menu, its TalkBack actions and, in
 * Arrange mode, its drag and a button for its menu; level is the order it
 * moves in. content draws it with the modifier given, opens it when asked
 * to, and shows the menu on a long press.
 */
@Composable
private fun Arrangeable(
    model: AppModel,
    ref: Tiles.Ref,
    level: List<Tiles.Ref>,
    name: String,
    modifier: Modifier,
    content: @Composable (Modifier, Boolean, () -> Unit) -> Unit,
) {
    val arrange = LocalArrange.current
    val palette = LocalPalette.current
    var menu by remember { mutableStateOf(false) }
    val moves = Moves(ref, level, model)
    val dragged = arrange.dragging == ref
    val target = arrange.over == ref && arrange.dragging != null
    DisposableEffect(ref) { onDispose { arrange.bounds.remove(ref) } }
    val actions = if (!arrange.on) {
        emptyList<CustomAccessibilityAction>()
    } else {
        buildList {
            add(CustomAccessibilityAction(stringResource(R.string.move_earlier)) { moves.earlier(); true })
            add(CustomAccessibilityAction(stringResource(R.string.move_later)) { moves.later(); true })
            add(CustomAccessibilityAction(stringResource(R.string.move_start)) { moves.toStart(); true })
            add(CustomAccessibilityAction(stringResource(R.string.move_end)) { moves.toEnd(); true })
            if (ref is Tiles.Ref.Device && model.collectionHolding(ref.id) != null) {
                add(CustomAccessibilityAction(stringResource(R.string.collection_out)) { model.arrange(Tiles.Op.Out(ref.id)) })
            }
        }
    }
    Box(
        modifier
            .onGloballyPositioned { arrange.bounds[ref] = it.boundsInRoot() }
            .then(
                if (arrange.on) {
                    Modifier.pointerInput(ref, level) {
                        detectDragGesturesAfterLongPress(
                            onDragStart = { arrange.begin(ref, it) },
                            onDrag = { change, by ->
                                change.consume()
                                arrange.drag(by)
                            },
                            onDragEnd = { arrange.drop(model, level) },
                            onDragCancel = { arrange.cancel() },
                        )
                    }
                } else {
                    Modifier
                },
            )
            .zIndex(if (dragged) 1f else 0f)
            .graphicsLayer {
                if (dragged) {
                    translationX = arrange.offset.x
                    translationY = arrange.offset.y
                    alpha = 0.85f
                    scaleX = 1.04f
                    scaleY = 1.04f
                }
            },
    ) {
        val outline = if (arrange.on) Modifier.dashedOutline(if (target) palette.accent else palette.textDim) else Modifier
        content(outline.semantics { customActions = actions }, !arrange.on) { menu = true }
        if (arrange.on) {
            Box(Modifier.align(Alignment.BottomEnd)) {
                IconText("⋮", stringResource(R.string.arrange_menu, name), small = true) { menu = true }
            }
        }
        ArrangeMenu(model, ref, level, menu) { menu = false }
    }
}

/** A dashed outline around a tile in Arrange mode. */
private fun Modifier.dashedOutline(color: Color): Modifier = drawBehind {
    val r = Tokens.radiusTile.toPx()
    drawRoundRect(
        color,
        cornerRadius = CornerRadius(r, r),
        style = Stroke(width = 1.5.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(5.dp.toPx(), 4.dp.toPx()))),
    )
}

/** A tile's menu: Arrange, and every change a drag makes. */
@Composable
private fun ArrangeMenu(model: AppModel, ref: Tiles.Ref, level: List<Tiles.Ref>, open: Boolean, close: () -> Unit) {
    val arrange = LocalArrange.current
    val moves = Moves(ref, level, model)
    var into by remember { mutableStateOf(false) }
    DropdownMenu(expanded = open && !into, onDismissRequest = close) {
        if (!arrange.on) MenuItem(R.string.arrange, close) { arrange.on = true }
        when (ref) {
            is Tiles.Ref.Device -> {
                DropdownMenuItem(text = { Text(stringResource(R.string.collection_into) + " ›") }, onClick = { into = true })
                if (model.collectionHolding(ref.id) != null) MenuItem(R.string.collection_out, close) { model.arrange(Tiles.Op.Out(ref.id)) }
            }
            is Tiles.Ref.Collection -> {
                MenuItem(R.string.collection_rename, close) {
                    arrange.prompt = ArrangeState.Prompt.Rename(ref.id, model.collection(ref.id)?.collection?.name.orEmpty())
                }
                MenuItem(R.string.collection_ungroup, close) { model.arrange(Tiles.Op.Ungroup(ref.id)) }
            }
        }
        if (moves.canMoveEarlier) MenuItem(R.string.move_start, close) { moves.toStart() }
        if (moves.canMoveLater) MenuItem(R.string.move_end, close) { moves.toEnd() }
    }
    // Move to collection: each collection, or a new one.
    if (ref is Tiles.Ref.Device) {
        DropdownMenu(expanded = open && into, onDismissRequest = {
            into = false
            close()
        }) {
            for (c in model.collections(apartFrom = ref.id)) {
                DropdownMenuItem(text = { Text(c.name) }, onClick = {
                    into = false
                    close()
                    model.arrange(Tiles.Op.Into(ref.id, c.id))
                })
            }
            DropdownMenuItem(text = { Text(stringResource(R.string.collection_new)) }, onClick = {
                into = false
                close()
                arrange.prompt = ArrangeState.Prompt.New(listOf(ref.id))
            })
        }
    }
}

/** An item of a menu that closes it, then acts. */
@Composable
private fun MenuItem(@StringRes text: Int, close: () -> Unit, act: () -> Unit) {
    DropdownMenuItem(text = { Text(stringResource(text)) }, onClick = {
        close()
        act()
    })
}

/**
 * A collection as a tile: up to four of its devices' icons, its name and
 * how many are online, with a mark when one of them needs attention.
 */
@Composable
private fun CollectionTile(item: AppModel.Arranged.Collection, modifier: Modifier, open: (() -> Unit)?, menu: () -> Unit) {
    val palette = LocalPalette.current
    val devices = item.devices
    val online = devices.count { it.online }
    val attention = devices.any { it.needsAttention }
    val state = stringResource(if (attention) R.string.collection_state_attention else R.string.collection_state, online, devices.size)
    Column(
        modifier.glassTile().focusRing().tap(open, menu).padding(Tokens.spacingMedium).semantics(mergeDescendants = true) { stateDescription = state },
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall),
    ) {
        Row(verticalAlignment = Alignment.Top) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                for (row in 0 until 2) {
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        for (col in 0 until 2) {
                            val d = devices.getOrNull(row * 2 + col)
                            if (d != null) DeviceIcon(d, 20.dp) else Spacer(Modifier.size(20.dp))
                        }
                    }
                }
            }
            Spacer(Modifier.weight(1f))
            if (attention) AttentionMark()
        }
        Text(item.collection.name, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
        Text(
            if (devices.isEmpty()) stringResource(R.string.collection_drag_here) else stringResource(R.string.online_count, online, devices.size),
            style = MaterialTheme.typography.bodySmall,
            color = palette.textDim,
        )
    }
}

/** The danger colour's mark on a collection with a device that needs attention. */
@Composable
private fun AttentionMark() {
    Text("!", color = LocalPalette.current.danger, fontWeight = FontWeight.Bold)
}

/** A collection in the list: a header with its name and how many are online, then its devices. */
@Composable
private fun CollectionSection(
    model: AppModel,
    item: AppModel.Arranged.Collection,
    level: List<Tiles.Ref>,
    select: (String) -> Unit,
    openCollection: (String) -> Unit,
) {
    val palette = LocalPalette.current
    val inner = item.devices.map { Tiles.Ref.Device(it.id) }
    Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Arrangeable(model, item.ref, level, item.collection.name, Modifier.fillMaxWidth()) { m, open, menu ->
            Row(
                m.fillMaxWidth().heightIn(min = 44.dp).tap(if (open) ({ openCollection(item.collection.id) }) else null, menu)
                    .padding(top = Tokens.spacingSmall, end = Tokens.spacingLarge).semantics(mergeDescendants = true) {},
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall),
            ) {
                Text(item.collection.name, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (item.devices.any { it.needsAttention }) AttentionMark()
                Spacer(Modifier.weight(1f))
                Text(
                    stringResource(R.string.online_count, item.devices.count { it.online }, item.devices.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = palette.textDim,
                )
            }
        }
        for (d in item.devices) {
            Arrangeable(model, Tiles.Ref.Device(d.id), inner, d.name, Modifier.fillMaxWidth().padding(start = Tokens.spacingMedium)) { m, open, menu ->
                DeviceRow(d, m, open = if (open) ({ select(d.id) }) else null, menu = menu)
            }
        }
    }
}

/** A tap opens, a long press shows the menu; neither in Arrange mode, where open is null. */
@Composable
internal fun Modifier.tap(open: (() -> Unit)?, menu: (() -> Unit)?): Modifier =
    if (open == null) {
        this
    } else {
        combinedClickable(role = Role.Button, onClick = open, onLongClick = menu, onLongClickLabel = menu?.let { stringResource(R.string.arrange) })
    }

/** A collection's own page: its devices in their order, its menu, and Arrange mode for them. */
@Composable
internal fun CollectionPage(model: AppModel, id: String, back: () -> Unit, select: (String) -> Unit) {
    val arrange = LocalArrange.current
    val palette = LocalPalette.current
    val item = model.collection(id)
    // A collection that a move emptied goes away, and so does its page.
    if (item == null) {
        LaunchedEffect(Unit) { back() }
        return
    }
    val layout = model.settings.layout.takeIf { it != DeviceLayout.ORBIT } ?: DeviceLayout.TILES
    val level = item.devices.map { Tiles.Ref.Device(it.id) }
    var menu by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            IconText("‹", stringResource(R.string.back), onClick = back)
            Text(
                item.collection.name,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium),
            )
            Box {
                IconText("⋯", stringResource(R.string.arrange_menu, item.collection.name)) { menu = true }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(stringResource(if (arrange.on) R.string.arrange_done else R.string.arrange)) }, onClick = {
                        menu = false
                        arrange.on = !arrange.on
                    })
                    DropdownMenuItem(text = { Text(stringResource(R.string.collection_rename)) }, onClick = {
                        menu = false
                        arrange.prompt = ArrangeState.Prompt.Rename(id, item.collection.name)
                    })
                    DropdownMenuItem(text = { Text(stringResource(R.string.collection_ungroup)) }, onClick = {
                        menu = false
                        model.arrange(Tiles.Op.Ungroup(id))
                    })
                }
            }
        }
        if (arrange.on) ArrangeBar()
        model.message?.let { NoteText(it, dim = true) }
        if (item.devices.isEmpty()) {
            Text(stringResource(R.string.collection_empty), color = palette.textDim)
        } else if (layout == DeviceLayout.LIST) {
            Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
                for (d in item.devices) {
                    Arrangeable(model, Tiles.Ref.Device(d.id), level, d.name, Modifier.fillMaxWidth()) { m, open, more ->
                        DeviceRow(d, m, open = if (open) ({ select(d.id) }) else null, menu = more)
                    }
                }
            }
        } else {
            TileGrid(item.devices.map { "d:" + it.id }) { key, m ->
                val d = item.devices.first { "d:" + it.id == key }
                Arrangeable(model, Tiles.Ref.Device(d.id), level, d.name, m) { inner, open, more ->
                    DeviceTile(d, inner, open = if (open) ({ select(d.id) }) else null, menu = more)
                }
            }
        }
    }
}

/** Arrange mode's line at the top, with Done. */
@Composable
internal fun ArrangeBar() {
    val arrange = LocalArrange.current
    val palette = LocalPalette.current
    Row(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalAlignment = Alignment.CenterVertically) {
        Text(stringResource(R.string.arrange_bar), style = MaterialTheme.typography.bodySmall, color = palette.textDim, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(Tokens.spacingSmall))
        TextButton(onClick = { arrange.on = false }) { Text(stringResource(R.string.arrange_done), color = palette.accent, fontWeight = FontWeight.Bold) }
    }
}

/** The name prompts of Arrange mode: a new collection, or another name for one. */
@Composable
internal fun ArrangePrompt(model: AppModel) {
    val arrange = LocalArrange.current
    val palette = LocalPalette.current
    val prompt = arrange.prompt ?: return
    var name by remember(prompt) { mutableStateOf((prompt as? ArrangeState.Prompt.Rename)?.name.orEmpty()) }
    val dismiss = { arrange.prompt = null }
    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(if (prompt is ArrangeState.Prompt.Rename) R.string.collection_rename_title else R.string.collection_new_title)) },
        text = {
            OutlinedTextField(value = name, onValueChange = { name = it }, singleLine = true, label = { Text(stringResource(R.string.collection_name)) })
        },
        confirmButton = {
            TextButton(enabled = name.isNotBlank(), onClick = {
                dismiss()
                when (prompt) {
                    is ArrangeState.Prompt.New -> model.newCollection(name, prompt.devices)
                    is ArrangeState.Prompt.Rename -> model.arrange(Tiles.Op.Rename(prompt.collection, name))
                }
            }) { Text(stringResource(R.string.save), color = palette.accent) }
        },
        dismissButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.cancel)) } },
        containerColor = palette.surface,
        titleContentColor = palette.text,
        textContentColor = palette.textDim,
    )
}

/** Whether a device needs the user: an admin computer another admin froze. */
internal val LiveGroup.Device.needsAttention: Boolean get() = frozen
