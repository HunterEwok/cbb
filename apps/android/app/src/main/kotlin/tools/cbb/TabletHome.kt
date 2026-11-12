// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.Activity
import android.content.ClipDescription
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.annotation.StringRes
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.draganddrop.dragAndDropTarget
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draganddrop.DragAndDropEvent
import androidx.compose.ui.draganddrop.DragAndDropTarget
import androidx.compose.ui.draganddrop.mimeTypes
import androidx.compose.ui.draganddrop.toAndroidDragEvent
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * A part of Settings, which a big screen's sidebar lists and opens beside
 * it (docs/apps.md, "Big screens"); the phone's Settings page shows them
 * all, in this order.
 */
internal enum class SettingsPart(@StringRes val title: Int, val symbol: String) {
    LOOK(R.string.appearance, "◐"),
    NOTIFICATIONS(R.string.notifications, "🔔"),
    RECOVERY(R.string.recovery_title, "🔑"),
    AWAY(R.string.away_title, "🌐"),
    PASTE(R.string.remote_paste, "⌨"),
    GROUP(R.string.group, "👥"),
    WHY(R.string.why_screen, "?"),
    ABOUT(R.string.about, "ⓘ"),
    ;

    /** Whether the part has anything on this device. */
    fun shown(model: AppModel): Boolean {
        val home = model.phase == AppModel.Phase.HOME
        return when (this) {
            LOOK, ABOUT -> true
            NOTIFICATIONS, PASTE, GROUP, WHY -> home
            RECOVERY -> home && model.isRoot
            AWAY -> home && (model.hub != null || model.blindRelay != null)
        }
    }
}

/**
 * What the sidebar opens: the devices (all of them, those that need
 * attention, one collection) or a part of Settings. Kept as a string, so
 * that it outlives a turn of the screen.
 */
internal sealed interface TabletSection {
    data object All : TabletSection
    data object Attention : TabletSection
    data class Collection(val id: String) : TabletSection
    data class Settings(val part: SettingsPart) : TabletSection

    val key: String
        get() = when (this) {
            All -> "all"
            Attention -> "attention"
            is Collection -> "c:$id"
            is Settings -> "s:${part.name}"
        }

    companion object {
        fun of(key: String): TabletSection = when {
            key == "attention" -> Attention
            key.startsWith("c:") -> Collection(key.removePrefix("c:"))
            key.startsWith("s:") -> SettingsPart.entries.firstOrNull { it.name == key.removePrefix("s:") }?.let { Settings(it) } ?: All
            else -> All
        }

        /** The sidebar's sections in its order, for Ctrl+1 to 9. */
        fun order(model: AppModel): List<TabletSection> = buildList {
            add(All)
            if (model.devices.any { it.needsAttention }) add(Attention)
            for (a in model.arranged) if (a is AppModel.Arranged.Collection) add(Collection(a.collection.id))
            for (p in SettingsPart.entries) if (p.shown(model)) add(Settings(p))
        }
    }
}

/** The device whose details stand beside the tiles, which its tile marks. */
internal val LocalChosenDevice = staticCompositionLocalOf<String?> { null }

/** The model a tile hands a drop to (remote paste), on a big screen only. */
internal val LocalTileDrop = staticCompositionLocalOf<AppModel?> { null }

/**
 * Home on a big screen (docs/apps.md, "Big screens"), the same layout as
 * the iPad's: a sidebar with the group's line and its two switches, the
 * devices' sections and Settings' parts; beside it the chosen section, and
 * for the devices the chosen device's details in a pane at the trailing
 * edge. The window's width alone decides: the sidebar stands while there
 * is room for it, the tiles and the details, else it slides in from the
 * edge; the details stand beside the tiles while both fit, else they open
 * as a page of their own. Rights do not depend on any of it: they follow
 * how the device keeps its keys (Keys.guardsLikeAPhone).
 *
 * The keyboard: Ctrl+1 to 9 open the sidebar's sections, Ctrl+, Settings,
 * Ctrl+N adds a device, Ctrl+F finds one, the arrows choose the next
 * device and Esc closes its details. A right click on a tile opens its
 * menu; a text, a picture or files dropped on a tile paste there, and
 * dropped beside the tiles go to the group.
 */
@Composable
internal fun TabletHome(model: AppModel, open: (HomePage) -> Unit) {
    var sectionKey by rememberSaveable { mutableStateOf("all") }
    val section = TabletSection.of(sectionKey)
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    val arrange = LocalArrange.current
    val search = rememberDeviceSearch(model)
    val focus = remember { FocusRequester() }
    val choose = { s: TabletSection ->
        if (s != section) {
            // Another section closes the details, and Arrange mode, of the last.
            selected = null
            arrange.on = false
        }
        sectionKey = s.key
    }
    // A collection that a move or ungroup ended takes its section along.
    LaunchedEffect(model.arranged, model.devices) {
        if (section is TabletSection.Collection && model.collection(section.id) == null) choose(TabletSection.All)
        if (section == TabletSection.Attention && model.devices.none { it.needsAttention }) choose(TabletSection.All)
    }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    val fontScale = LocalDensity.current.fontScale.coerceIn(1f, 2f)
    val sidebarWidth = 300.dp * fontScale.coerceAtMost(1.3f)
    val devicesWidth = 360.dp * fontScale
    val cardWidth = minOf(400.dp * fontScale, 520.dp)
    BoxWithConstraints(
        Modifier.fillMaxSize().focusRequester(focus).focusable().onKeyEvent { e ->
            if (e.type != KeyEventType.KeyDown) return@onKeyEvent false
            val ctrl = e.isCtrlPressed || e.isMetaPressed
            val digit = digits.indexOf(e.key)
            when {
                ctrl && digit >= 0 -> {
                    TabletSection.order(model).getOrNull(digit)?.let(choose)
                    true
                }
                ctrl && e.key == Key.Comma -> {
                    choose(TabletSection.Settings(SettingsPart.LOOK))
                    true
                }
                ctrl && e.key == Key.N && model.isAdmin -> {
                    open(HomePage.ADD)
                    true
                }
                ctrl && e.key == Key.F && search.offered -> {
                    choose(TabletSection.All)
                    search.focus()
                    true
                }
                e.key == Key.Escape && selected != null -> {
                    selected = null
                    true
                }
                else -> false
            }
        },
    ) {
        val standing = maxWidth >= sidebarWidth + devicesWidth + cardWidth
        val drawer = rememberDrawerState(DrawerValue.Closed)
        val scope = rememberCoroutineScope()
        val detail: @Composable (Boolean) -> Unit = { menu ->
            when (section) {
                is TabletSection.Settings -> SettingsPane(model, section.part, if (menu) ({ scope.launch { drawer.open() } }) else null)
                else -> TabletDevices(
                    model, section, search, selected, { selected = it }, open,
                    roomBeside = { it >= devicesWidth + cardWidth },
                    cardWidth = cardWidth,
                    showSidebar = if (menu) ({ scope.launch { drawer.open() } }) else null,
                    openSection = choose,
                )
            }
        }
        val sidebar: @Composable () -> Unit = {
            TabletSidebar(model, section) {
                choose(it)
                scope.launch { drawer.close() }
            }
        }
        if (standing) {
            Row(Modifier.fillMaxSize()) {
                Box(Modifier.width(sidebarWidth).fillMaxHeight()) { sidebar() }
                VerticalDivider(color = LocalPalette.current.line)
                Box(Modifier.weight(1f).fillMaxHeight()) { detail(false) }
            }
        } else {
            ModalNavigationDrawer(
                drawerState = drawer,
                drawerContent = {
                    ModalDrawerSheet(Modifier.width(sidebarWidth), drawerContainerColor = LocalPalette.current.background) { sidebar() }
                },
            ) { detail(true) }
        }
    }
}

private val digits = listOf(Key.One, Key.Two, Key.Three, Key.Four, Key.Five, Key.Six, Key.Seven, Key.Eight, Key.Nine)

/** The sidebar: the group's line with its two switches, then the devices' sections and Settings' parts. */
@Composable
private fun TabletSidebar(model: AppModel, section: TabletSection, choose: (TabletSection) -> Unit) {
    val palette = LocalPalette.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingMedium),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            stringResource(R.string.cbb_name),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = Tokens.spacingSmall, vertical = Tokens.spacingSmall),
        )
        Column(Modifier.padding(horizontal = Tokens.spacingSmall), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) { Summary(model) }
        SidebarHeading(stringResource(R.string.devices))
        SidebarRow("▦", stringResource(R.string.all_devices), model.devices.size, section == TabletSection.All) { choose(TabletSection.All) }
        val attention = model.devices.count { it.needsAttention }
        if (attention > 0) {
            SidebarRow("!", stringResource(R.string.needs_attention), attention, section == TabletSection.Attention, danger = true) {
                choose(TabletSection.Attention)
            }
        }
        for (a in model.arranged) {
            if (a !is AppModel.Arranged.Collection) continue
            val s = TabletSection.Collection(a.collection.id)
            SidebarRow("▢", a.collection.name, a.devices.size, section == s) { choose(s) }
        }
        SidebarHeading(stringResource(R.string.settings))
        for (p in SettingsPart.entries) {
            if (!p.shown(model)) continue
            val s = TabletSection.Settings(p)
            SidebarRow(p.symbol, stringResource(p.title), null, section == s) { choose(s) }
        }
        Spacer(Modifier.heightIn(min = Tokens.spacingLarge))
        Text(
            stringResource(R.string.shortcuts_hint),
            style = MaterialTheme.typography.bodySmall,
            color = palette.textDim,
            modifier = Modifier.padding(horizontal = Tokens.spacingSmall),
        )
    }
}

@Composable
private fun SidebarHeading(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = LocalPalette.current.textDim,
        modifier = Modifier.padding(start = Tokens.spacingSmall, top = Tokens.spacingLarge, bottom = 4.dp).semantics { heading() },
    )
}

/** A row of the sidebar: a symbol, a name, how many devices it holds; the chosen one in the accent's tint. */
@Composable
private fun SidebarRow(symbol: String, title: String, count: Int?, chosen: Boolean, danger: Boolean = false, onClick: () -> Unit) {
    val palette = LocalPalette.current
    val shape = RoundedCornerShape(Tokens.radiusCard)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clip(shape)
            .background(if (chosen) palette.accent.copy(alpha = 0.16f) else palette.background.copy(alpha = 0f))
            .focusRing(shape)
            .clickable(role = Role.Tab, onClick = onClick)
            .semantics(mergeDescendants = true) { selected = chosen }
            .padding(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
    ) {
        Text(symbol, color = if (danger) palette.danger else if (chosen) palette.accent else palette.textDim, modifier = Modifier.widthIn(min = 20.dp))
        Text(
            title,
            color = if (chosen) palette.accent else palette.text,
            fontWeight = if (chosen) FontWeight.SemiBold else FontWeight.Normal,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        if (count != null) Text(count.toString(), style = MaterialTheme.typography.bodySmall, color = palette.textDim)
    }
}

/** The button that slides the sidebar in, while it does not stand. */
@Composable
private fun SidebarButton(show: (() -> Unit)?) {
    if (show == null) return
    IconText("☰", stringResource(R.string.menu), onClick = show)
    Spacer(Modifier.width(Tokens.spacingSmall))
}

/** A part of Settings beside the sidebar. */
@Composable
private fun SettingsPane(model: AppModel, part: SettingsPart, showSidebar: (() -> Unit)?) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge),
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SidebarButton(showSidebar)
            Text(stringResource(part.title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }
        Column(Modifier.widthIn(max = readableWidth), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            SettingsContent(model, part)
        }
    }
}

/**
 * The devices of a section, and the chosen one's details beside them when
 * both fit, else as a page of their own, which back closes.
 */
@Composable
private fun TabletDevices(
    model: AppModel,
    section: TabletSection,
    search: DeviceSearch,
    selected: String?,
    select: (String?) -> Unit,
    open: (HomePage) -> Unit,
    roomBeside: (Dp) -> Boolean,
    cardWidth: Dp,
    showSidebar: (() -> Unit)?,
    openSection: (TabletSection) -> Unit,
) {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val beside = roomBeside(maxWidth)
        if (!beside && selected != null) {
            // Too narrow for both: the details as a page, which back closes.
            BackHandler { select(null) }
            DeviceDetail(model, selected, back = { select(null) })
            return@BoxWithConstraints
        }
        Row(Modifier.fillMaxSize()) {
            Box(Modifier.weight(1f).fillMaxHeight().groupDrop(model)) {
                CompositionLocalProvider(LocalChosenDevice provides selected, LocalTileDrop provides model) {
                    DeviceSection(model, section, search, selected, select, open, beside, showSidebar, openSection)
                }
            }
            if (selected != null) {
                VerticalDivider(color = LocalPalette.current.line)
                Column(Modifier.width(cardWidth).fillMaxHeight()) {
                    DeviceDetail(model, selected, close = { select(null) }, back = { select(null) })
                }
            }
        }
    }
}

/** The devices' pane: its title with + and the view, what stands out, then the section's devices. */
@Composable
private fun DeviceSection(
    model: AppModel,
    section: TabletSection,
    search: DeviceSearch,
    selected: String?,
    select: (String?) -> Unit,
    open: (HomePage) -> Unit,
    beside: Boolean,
    showSidebar: (() -> Unit)?,
    openSection: (TabletSection) -> Unit,
) {
    val arrange = LocalArrange.current
    var layout by remember { mutableStateOf(model.settings.wideLayout) }
    val shown = shownDevices(model, section, search)
    Column(
        Modifier.fillMaxSize().padding(Tokens.spacingLarge).onKeyEvent { e ->
            // The arrows choose the next device while the details stand beside.
            if (e.type != KeyEventType.KeyDown || !beside || arrange.on || shown.isEmpty()) return@onKeyEvent false
            val step = when (e.key) {
                Key.DirectionLeft, Key.DirectionUp -> -1
                Key.DirectionRight, Key.DirectionDown -> 1
                else -> return@onKeyEvent false
            }
            val ids = shown.map { it.id }
            val at = ids.indexOf(selected)
            select(if (at < 0) (if (step > 0) ids.first() else ids.last()) else ids[(at + step).coerceIn(0, ids.size - 1)])
            true
        },
        verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            SidebarButton(showSidebar)
            Text(
                sectionTitle(model, section),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            DevicesMenu(model, section, layout) {
                layout = it
                model.settings.wideLayout = it
            }
            AddButton(model, open)
        }
        Alerts(model)
        LostPhoneCard(model)
        model.message?.let { NoteText(it, dim = true) }
        FallbackSend(model)
        // The orbit keeps the group's order; Arrange mode, a search and the other sections show tiles.
        if (section == TabletSection.All && layout == DeviceLayout.ORBIT && !arrange.on && !search.active) {
            Orbit(model.devices, selected, select = { select(it) }, modifier = Modifier.weight(1f).fillMaxWidth())
            return@Column
        }
        val tiles = if (layout == DeviceLayout.ORBIT) DeviceLayout.TILES else layout
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            when (section) {
                TabletSection.Attention -> DeviceCollection(model.devices.filter { it.needsAttention }, tiles) { select(it) }
                is TabletSection.Collection -> CollectionDevices(model, section.id, tiles) { select(it) }
                // A collection's tile opens its section.
                else -> Devices(model, search, tiles, { select(it) }) { openSection(TabletSection.Collection(it)) }
            }
        }
    }
}

/** The devices in the order the arrows go through them: the section's, as it shows them. */
private fun shownDevices(model: AppModel, section: TabletSection, search: DeviceSearch): List<LiveGroup.Device> = when (section) {
    TabletSection.Attention -> model.devices.filter { it.needsAttention }
    is TabletSection.Collection -> model.collection(section.id)?.devices.orEmpty()
    else -> if (search.active) {
        search.found(model.devices)
    } else {
        model.arranged.flatMap {
            when (it) {
                is AppModel.Arranged.Device -> listOf(it.device)
                is AppModel.Arranged.Collection -> it.devices
            }
        }
    }
}

@Composable
private fun sectionTitle(model: AppModel, section: TabletSection): String = when (section) {
    TabletSection.Attention -> stringResource(R.string.needs_attention)
    is TabletSection.Collection -> model.collection(section.id)?.collection?.name.orEmpty()
    is TabletSection.Settings -> stringResource(section.part.title)
    TabletSection.All -> stringResource(R.string.all_devices)
}

/** ⋯ of the devices' pane: the view, Arrange mode, and back to the group's order. */
@Composable
private fun DevicesMenu(model: AppModel, section: TabletSection, layout: DeviceLayout, choose: (DeviceLayout) -> Unit) {
    val arrange = LocalArrange.current
    var open by remember { mutableStateOf(false) }
    Box {
        IconText("⋯", stringResource(R.string.more)) { open = true }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            val layouts = if (section == TabletSection.All) DeviceLayout.entries.sortedBy { it != DeviceLayout.ORBIT } else listOf(DeviceLayout.TILES, DeviceLayout.LIST)
            for (l in layouts) {
                DropdownMenuItem(
                    text = { Text(stringResource(l.title), fontWeight = if (l == layout) FontWeight.Bold else FontWeight.Normal) },
                    leadingIcon = { Text(if (l == layout) "✓" else l.symbol) },
                    onClick = {
                        open = false
                        choose(l)
                    },
                )
            }
            if (section is TabletSection.Collection) {
                val name = model.collection(section.id)?.collection?.name.orEmpty()
                DropdownMenuItem(text = { Text(stringResource(R.string.collection_rename)) }, onClick = {
                    open = false
                    arrange.prompt = ArrangeState.Prompt.Rename(section.id, name)
                })
                DropdownMenuItem(text = { Text(stringResource(R.string.collection_ungroup)) }, onClick = {
                    open = false
                    model.arrange(tools.cbb.kit.Arrangement.Op.Ungroup(section.id))
                })
            }
            if (model.group.hasGroup && section != TabletSection.Attention) {
                DropdownMenuItem(
                    text = { Text(stringResource(if (arrange.on) R.string.arrange_done_long else R.string.arrange_devices)) },
                    leadingIcon = { Text("⇅") },
                    onClick = {
                        open = false
                        arrange.on = !arrange.on
                    },
                )
                if (model.customOrder) {
                    DropdownMenuItem(text = { Text(stringResource(R.string.arrange_reset)) }, onClick = {
                        open = false
                        model.arrange(tools.cbb.kit.Arrangement.Op.Reset)
                    })
                }
            }
        }
    }
}

/** + on an admin device: scan a code (Ctrl+N), or send an invitation. */
@Composable
private fun AddButton(model: AppModel, open: (HomePage) -> Unit) {
    if (!model.isAdmin) return
    var adding by remember { mutableStateOf(false) }
    Spacer(Modifier.width(Tokens.spacingSmall))
    Box {
        IconText("+", stringResource(R.string.add_device)) { adding = true }
        DropdownMenu(expanded = adding, onDismissRequest = { adding = false }) {
            DropdownMenuItem(text = { Text(stringResource(R.string.scan_code)) }, onClick = {
                adding = false
                open(HomePage.ADD)
            })
            DropdownMenuItem(text = { Text(stringResource(R.string.invite_send)) }, onClick = {
                adding = false
                open(HomePage.INVITE)
            })
        }
    }
}

/**
 * What a drop carries: its text, or the content URIs of its pictures and
 * files, which the app may read once Android grants it the drop.
 */
private class Dropped(val text: String?, val uris: List<Uri>)

private fun dropped(event: DragAndDropEvent, activity: Activity?): Dropped? {
    val e = event.toAndroidDragEvent()
    val clip = e.clipData ?: return null
    activity?.requestDragAndDropPermissions(e)
    val uris = (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
    if (uris.isNotEmpty()) return Dropped(null, uris)
    val text = (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).text?.toString() }.joinToString("\n").ifEmpty { return null }
    return Dropped(text, emptyList())
}

private fun acceptsDrop(event: DragAndDropEvent): Boolean =
    event.mimeTypes().any { it.startsWith("text/") || it.startsWith("image/") || it == ClipDescription.MIMETYPE_TEXT_URILIST || it.contains('/') }

/**
 * A text, a picture or files dropped beside the tiles go to the group, as
 * Share sends them; the pane's outline shows where a drop lands.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Modifier.groupDrop(model: AppModel): Modifier {
    val activity = LocalContext.current as? Activity
    val scope = rememberCoroutineScope()
    var over by remember { mutableStateOf(false) }
    val palette = LocalPalette.current
    val target = remember(model) {
        object : DragAndDropTarget {
            override fun onEntered(event: DragAndDropEvent) { over = true }
            override fun onExited(event: DragAndDropEvent) { over = false }
            override fun onEnded(event: DragAndDropEvent) { over = false }
            override fun onDrop(event: DragAndDropEvent): Boolean {
                over = false
                val d = dropped(event, activity) ?: return false
                scope.launch { if (d.text != null) model.syncFromOutside(d.text, waitMS = 0) else model.sendShared(d.uris, waitMS = 0) }
                return true
            }
        }
    }
    return dragAndDropTarget(shouldStartDragAndDrop = ::acceptsDrop, target = target)
        .then(if (over) Modifier.border(2.dp, palette.accent, RoundedCornerShape(Tokens.radiusCard)) else Modifier)
}

/**
 * A text, a picture or files dropped on a device's tile paste there
 * (remote paste), on an admin device and a device that takes pastes.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun Modifier.pasteDrop(d: LiveGroup.Device): Modifier {
    val model = LocalTileDrop.current ?: return this
    if (!model.isAdmin || !d.takesPaste) return this
    val activity = LocalContext.current as? Activity
    val scope = rememberCoroutineScope()
    var over by remember { mutableStateOf(false) }
    val palette = LocalPalette.current
    val target = remember(model, d.id) {
        object : DragAndDropTarget {
            override fun onEntered(event: DragAndDropEvent) { over = true }
            override fun onExited(event: DragAndDropEvent) { over = false }
            override fun onEnded(event: DragAndDropEvent) { over = false }
            override fun onDrop(event: DragAndDropEvent): Boolean {
                over = false
                val x = dropped(event, activity) ?: return false
                scope.launch {
                    if (x.text != null) model.paste(d.id, x.text, "paste", enter = false, secret = false) else model.pasteShared(d.id, x.uris, enter = false)
                }
                return true
            }
        }
    }
    return dragAndDropTarget(shouldStartDragAndDrop = ::acceptsDrop, target = target)
        .then(if (over) Modifier.border(2.dp, palette.accent, RoundedCornerShape(Tokens.radiusTile)) else Modifier)
}

/** The tile of the device whose details stand beside: the accent's outline, and selected for TalkBack. */
@Composable
internal fun Modifier.chosen(d: LiveGroup.Device): Modifier {
    if (LocalChosenDevice.current != d.id) return this
    return border(2.dp, LocalPalette.current.accent, RoundedCornerShape(Tokens.radiusTile)).semantics { selected = true }
}

/** Whether it takes remote paste: members, and Android and Aurora phones; iPhones and iPads cannot. */
internal val LiveGroup.Device.takesPaste: Boolean
    get() = !isSelf && (role == "member" || (role == "phone" && os in setOf("android", "aurora", "sailfish")))

/** The widest a part of Settings stands beside the sidebar, for lines a person reads at a glance. */
private val readableWidth = 640.dp
