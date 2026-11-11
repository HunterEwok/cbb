// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.ui.graphics.Color
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.border
import android.Manifest
import android.icu.text.MeasureFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import java.text.DateFormat
import java.util.Date
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import tools.cbb.kit.Arrangement as Tiles
import tools.cbb.kit.GroupAlert
import java.util.Locale
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Tiles or a list, as the toolbar sets it; on a big screen also the orbit. */
enum class DeviceLayout(val key: String, val symbol: String, @StringRes val title: Int) {
    TILES("tiles", "▦", R.string.layout_tiles),
    LIST("list", "☰", R.string.layout_list),
    ORBIT("orbit", "◎", R.string.layout_orbit),
    ;

    companion object {
        fun of(key: String?, default: DeviceLayout): DeviceLayout = entries.firstOrNull { it.key == key } ?: default
    }
}

private enum class HomePage { MAIN, DEVICE, SETTINGS, ADD, INVITE, COLLECTION }

/**
 * The one page (docs/apps.md, Home): the house and the globe beside how
 * many devices are online, an alert only when there is one, and every
 * device of the group as tiles or a list; a device opens its details. On a big
 * screen (a tablet, a foldable's inner screen) the devices may stand on
 * orbits around this phone, and the details open beside them.
 */
@Composable
internal fun HomeScreen(model: AppModel) {
    var page by rememberSaveable { mutableStateOf(HomePage.MAIN) }
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    // The collection whose page is open, which a device's details go back to.
    var collection by rememberSaveable { mutableStateOf<String?>(null) }
    val arrange = remember { ArrangeState() }
    LaunchedEffect(Unit) {
        // The live dots: which devices are connected now.
        while (true) {
            model.refresh()
            delay(2_000)
        }
    }
    LaunchedEffect(Unit) {
        model.group.renewOwnCertificate()
        model.group.finishTakeOverIfDue()
        model.group.signDue()
    }
    BackgroundSync()
    val wide = LocalConfiguration.current.screenWidthDp >= 720
    val main = { page = if (collection != null) HomePage.COLLECTION else HomePage.MAIN }
    CompositionLocalProvider(LocalArrange provides arrange, LocalModel provides model) {
        when (page) {
            HomePage.DEVICE -> {
                val id = selected
                BackHandler { main() }
                if (id == null || wide) {
                    // A big screen shows the details beside the devices.
                    LaunchedEffect(Unit) { main() }
                } else {
                    DeviceDetail(model, id, back = main)
                }
            }
            HomePage.SETTINGS -> SettingsScreen(model) { page = HomePage.MAIN }
            HomePage.ADD -> AddDeviceScreen(model) { page = HomePage.MAIN }
            HomePage.INVITE -> {
                BackHandler { page = HomePage.MAIN }
                Page(stringResource(R.string.invite_send), back = { page = HomePage.MAIN }) { InviteSection(model) }
            }
            HomePage.COLLECTION -> {
                val id = collection
                val leave = {
                    arrange.on = false
                    collection = null
                    page = HomePage.MAIN
                }
                BackHandler { leave() }
                if (id == null) {
                    LaunchedEffect(Unit) { leave() }
                } else if (wide) {
                    Beside(model, selected, { selected = it }) { CollectionPage(model, id, leave) { selected = it } }
                } else {
                    CollectionPage(model, id, leave) {
                        selected = it
                        page = HomePage.DEVICE
                    }
                }
            }
            HomePage.MAIN -> {
                val openCollection = { id: String ->
                    arrange.on = false
                    collection = id
                    page = HomePage.COLLECTION
                }
                if (wide) {
                    WideHome(model, selected, select = { selected = it }, open = { page = it }, openCollection)
                } else {
                    HomeMain(model, open = { page = it }, openCollection) {
                        selected = it
                        page = HomePage.DEVICE
                    }
                }
            }
        }
        ArrangePrompt(model)
    }
}

/** The phone's page. */
@Composable
private fun HomeMain(model: AppModel, open: (HomePage) -> Unit, openCollection: (String) -> Unit, select: (String) -> Unit) {
    var layout by remember { mutableStateOf(model.settings.layout.takeIf { it != DeviceLayout.ORBIT } ?: DeviceLayout.TILES) }
    val search = rememberDeviceSearch(model)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingLarge)) {
        TopBar(model, layout, listOf(DeviceLayout.TILES, DeviceLayout.LIST), open) {
            layout = it
            model.settings.layout = it
        }
        Summary(model)
        Alerts(model)
        LostPhoneCard(model)
        model.message?.let { NoteText(it, dim = true) }
        FallbackSend(model)
        Devices(model, search, layout, select, openCollection)
    }
}

/** The big screen's page: the devices, and the chosen one's details beside them. */
@Composable
private fun WideHome(model: AppModel, selected: String?, select: (String?) -> Unit, open: (HomePage) -> Unit, openCollection: (String) -> Unit) {
    var layout by remember { mutableStateOf(model.settings.wideLayout) }
    val search = rememberDeviceSearch(model)
    val arrange = LocalArrange.current
    Beside(model, selected, select) {
        Column(Modifier.fillMaxSize().padding(Tokens.spacingLarge), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            TopBar(model, layout, DeviceLayout.entries.sortedBy { it != DeviceLayout.ORBIT }, open) {
                layout = it
                model.settings.wideLayout = it
            }
            Summary(model)
            Alerts(model)
            LostPhoneCard(model)
            model.message?.let { NoteText(it, dim = true) }
            FallbackSend(model)
            // The orbit keeps the group's order; Arrange mode and a search show tiles.
            if (layout == DeviceLayout.ORBIT && !arrange.on && !search.active) {
                Orbit(
                    model.devices,
                    selected,
                    select = { select(it) },
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                )
            } else {
                Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
                    Devices(model, search, if (layout == DeviceLayout.ORBIT) DeviceLayout.TILES else layout, { select(it) }, openCollection)
                }
            }
        }
    }
}

/** A big screen's page, and the chosen device's details beside it. */
@Composable
private fun Beside(model: AppModel, selected: String?, select: (String?) -> Unit, content: @Composable () -> Unit) {
    Row(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f).fillMaxHeight()) { content() }
        if (selected != null) {
            VerticalDivider(color = LocalPalette.current.line)
            Column(Modifier.width(400.dp).fillMaxHeight()) {
                DeviceDetail(model, selected, close = { select(null) }, back = { select(null) })
            }
        }
    }
}

/** Home's search and filters, offered once there are more devices than fit a screen. */
@Stable
private class DeviceSearch {
    var query by mutableStateOf("")
    var filter by mutableStateOf<DeviceFilter?>(null)

    /** Whether Home offers them: more than 12 devices. */
    var offered = false
    val active: Boolean get() = offered && (query.isNotBlank() || filter != null)

    /** The devices the search and the filter leave, flat. */
    fun found(devices: List<LiveGroup.Device>): List<LiveGroup.Device> {
        val q = query.trim()
        return devices.filter { d ->
            (q.isEmpty() || d.name.contains(q, ignoreCase = true) || d.system?.contains(q, ignoreCase = true) == true) &&
                (filter != DeviceFilter.ONLINE || d.online) && (filter != DeviceFilter.ATTENTION || d.needsAttention)
        }
    }
}

private enum class DeviceFilter { ONLINE, ATTENTION }

@Composable
private fun rememberDeviceSearch(model: AppModel): DeviceSearch {
    val search = remember { DeviceSearch() }
    search.offered = model.devices.size > 12
    // Arrange mode is off while a search or a filter is on.
    val arrange = LocalArrange.current
    LaunchedEffect(search.active) { if (search.active) arrange.on = false }
    return search
}

/**
 * The devices: in the user's order with the collections, or flat while a
 * search or a filter is on.
 */
@Composable
private fun Devices(model: AppModel, search: DeviceSearch, layout: DeviceLayout, select: (String) -> Unit, openCollection: (String) -> Unit) {
    if (LocalArrange.current.on) ArrangeBar()
    if (search.offered) SearchBar(search)
    if (search.active) {
        val found = search.found(model.devices)
        if (found.isEmpty()) {
            Text(stringResource(R.string.no_devices_match), color = LocalPalette.current.textDim)
        } else {
            DeviceCollection(found, layout, select)
        }
    } else {
        ArrangedDevices(model, layout, select, openCollection)
    }
}

/** The search field and the two filters: Online and Needs attention; a second tap turns one off. */
@Composable
private fun SearchBar(search: DeviceSearch) {
    Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        OutlinedTextField(
            value = search.query,
            onValueChange = { search.query = it },
            singleLine = true,
            label = { Text(stringResource(R.string.search_devices)) },
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            for ((f, text) in listOf(DeviceFilter.ONLINE to R.string.filter_online, DeviceFilter.ATTENTION to R.string.needs_attention)) {
                FilterChip(
                    selected = search.filter == f,
                    onClick = { search.filter = if (search.filter == f) null else f },
                    label = { Text(stringResource(text)) },
                )
            }
        }
    }
}

/**
 * The name, then + on an admin phone (scan a code or send an invitation)
 * and ⋯ (the view, arranging the devices and Settings).
 */
@Composable
private fun TopBar(model: AppModel, layout: DeviceLayout, layouts: List<DeviceLayout>, open: (HomePage) -> Unit, choose: (DeviceLayout) -> Unit) {
    val arrange = LocalArrange.current
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            stringResource(R.string.cbb_name),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.weight(1f),
        )
        if (model.isAdmin) {
            var adding by remember { mutableStateOf(false) }
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
            Spacer(Modifier.width(Tokens.spacingSmall))
        }
        var more by remember { mutableStateOf(false) }
        Box {
            IconText("⋯", stringResource(R.string.more)) { more = true }
            DropdownMenu(expanded = more, onDismissRequest = { more = false }) {
                // The view: each choice shows the next one.
                val next = layouts[(layouts.indexOf(layout) + 1) % layouts.size]
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.view_next, stringResource(next.title))) },
                    leadingIcon = { Text(next.symbol) },
                    onClick = {
                        more = false
                        choose(next)
                    },
                )
                if (model.arrangement != null) {
                    DropdownMenuItem(text = { Text(stringResource(if (arrange.on) R.string.arrange_done_long else R.string.arrange_devices)) }, leadingIcon = { Text("⇅") }, onClick = {
                        more = false
                        arrange.on = !arrange.on
                    })
                    if (model.arrangement?.items?.isNotEmpty() == true) {
                        DropdownMenuItem(text = { Text(stringResource(R.string.arrange_reset)) }, onClick = {
                            more = false
                            model.arrange(Tiles.Op.Reset)
                        })
                    }
                }
                DropdownMenuItem(text = { Text(stringResource(R.string.settings)) }, leadingIcon = { Text("⚙") }, onClick = {
                    more = false
                    open(HomePage.SETTINGS)
                })
            }
        }
    }
}

/** How many devices are online, of how many, beside the house and the globe; under them what stands out. */
@Composable
private fun Summary(model: AppModel) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            stringResource(R.string.online_count, model.devices.count { it.online }, model.devices.size),
            style = MaterialTheme.typography.bodyMedium,
            color = LocalPalette.current.textDim,
            modifier = Modifier.weight(1f),
        )
        SyncSwitches(model)
    }
    model.syncOff?.let { off ->
        Text(
            off.until?.let { stringResource(R.string.sync_off_until, shortTime(it)) } ?: stringResource(R.string.sync_off),
            style = MaterialTheme.typography.bodySmall,
            color = LocalPalette.current.danger,
        )
    }
    // Everywhere while it connects, or once it fails.
    model.away?.takeIf { it.on && model.hub?.on != true }?.let { away ->
        val inUse = model.devices.firstOrNull { it.hub == LiveGroup.HubMark.IN_USE }
        val line = when {
            away.status == AwayFromHome.Status.CONNECTED && inUse != null -> stringResource(R.string.away_connected_to, inUse.name)
            away.status == AwayFromHome.Status.CONNECTED -> stringResource(R.string.away_connected)
            away.status == AwayFromHome.Status.CONNECTING -> stringResource(R.string.away_connecting)
            away.status == AwayFromHome.Status.AT_HOME -> null
            else -> stringResource(R.string.away_waiting)
        }
        line?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = LocalPalette.current.textDim) }
        away.error?.let { NoteText(it) }
    }
    model.awayNote?.let { NoteText(it) }
    // The phone as the hub works while the app is open: Home says so, as a fact, not a fault.
    model.hub?.takeIf { it.on }?.let { h ->
        Text(
            stringResource(if (h.background) R.string.hub_home_background else R.string.hub_home_note),
            style = MaterialTheme.typography.bodySmall,
            color = LocalPalette.current.textDim,
        )
    }
    // An admin's mute of this phone, which an admin ends.
    model.devices.firstOrNull { it.isSelf }?.muted?.let { m ->
        Text(
            m.until?.let { stringResource(R.string.muted_self_until, shortTime(it, date = true)) } ?: stringResource(R.string.muted_self),
            style = MaterialTheme.typography.bodySmall,
            color = LocalPalette.current.danger,
        )
    }
}

/** How long the quick switch keeps the group's copies out, or an admin's mute lasts; 0 for until it is lifted. */
internal enum class PauseTime(val ms: Long, @StringRes val title: Int) {
    QUARTER(900_000, R.string.pause_quarter),
    HOUR(3_600_000, R.string.pause_hour),
    EIGHT(28_800_000, R.string.pause_eight),
    EVER(0, R.string.pause_ever),
}

/** A time of day, with the date when asked, in the user's format. */
internal fun shortTime(ms: Long, date: Boolean = false): String {
    val f = if (date) DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT) else DateFormat.getTimeInstance(DateFormat.SHORT)
    return f.format(Date(ms))
}

/**
 * The two switches (docs/design.md, "Sync on and off"): the house turns
 * sync on this phone off or on with a tap, or off for a time with a long
 * press; the globe turns Everywhere, sync away from home, on or off, after
 * saying what it does, and waits while sync is off.
 */
@Composable
private fun SyncSwitches(model: AppModel) {
    val scope = rememberCoroutineScope()
    val off = model.syncOff
    var times by remember { mutableStateOf(false) }
    Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Box {
            SwitchFace(
                "house",
                on = off == null,
                label = if (off == null) stringResource(R.string.sync_on) else off.until?.let { stringResource(R.string.sync_off_until, shortTime(it)) } ?: stringResource(R.string.sync_off),
                clickLabel = stringResource(if (off == null) R.string.sync_turn_off else R.string.sync_turn_on),
                longClickLabel = stringResource(R.string.pause_for_a_time),
                onLongClick = { times = true },
            ) { scope.launch { model.turnSync(off != null) } }
            DropdownMenu(expanded = times, onDismissRequest = { times = false }) {
                for (t in PauseTime.entries) {
                    DropdownMenuItem(text = { Text(stringResource(t.title)) }, onClick = {
                        times = false
                        scope.launch { model.turnSync(false, t.ms) }
                    })
                }
            }
        }
        val away = model.away
        if (away != null && model.hub?.on != true) {
            var asking by remember { mutableStateOf(false) }
            val waits = off != null && !away.on
            SwitchFace(
                "globe",
                on = away.on,
                enabled = !waits && !model.busy,
                label = stringResource(if (away.on) R.string.away_is_on else if (waits) R.string.away_waits else R.string.away_is_off),
                clickLabel = stringResource(if (away.on) R.string.away_turn_off else R.string.away_turn_on),
            ) { if (away.on) scope.launch { model.setAway(false) } else asking = true }
            if (asking) {
                Confirm(
                    stringResource(R.string.away_ask_title),
                    stringResource(R.string.away_body),
                    stringResource(R.string.turn_on),
                    dismiss = { asking = false },
                ) {
                    asking = false
                    scope.launch { model.setAway(true) }
                }
            }
        }
    }
}

/** A switch's round face: filled with the accent while on; a tap switches it, a long press may offer more. */
@Composable
private fun SwitchFace(
    glyph: String,
    on: Boolean,
    label: String,
    clickLabel: String,
    enabled: Boolean = true,
    longClickLabel: String? = null,
    onLongClick: (() -> Unit)? = null,
    onClick: () -> Unit,
) {
    val palette = LocalPalette.current
    Box(
        Modifier.size(44.dp).clip(CircleShape).background(if (on) palette.accent else palette.surface)
            .focusRing(CircleShape)
            .combinedClickable(
                enabled = enabled,
                role = Role.Switch,
                onClickLabel = clickLabel,
                onClick = onClick,
                onLongClickLabel = longClickLabel,
                onLongClick = onLongClick,
            )
            .semantics {
                contentDescription = label
                stateDescription = label
            }
            .alpha(if (enabled) 1f else 0.5f),
        contentAlignment = Alignment.Center,
    ) {
        SwitchGlyph(glyph, if (on) palette.onAccent else palette.textDim, 24.dp)
    }
}

/**
 * What the group's records stop and what ends it: the stop, each conflict and
 * each claim (GroupAlert). On the root phone each comes with what ends it,
 * after the fingerprint or the screen lock: voiding both histories of a key,
 * cancelling a claim, or removing one of two admins that removed each other.
 */
@Composable
private fun Alerts(model: AppModel) {
    RemovedCard(model)
    Handed(model)
    if (model.alerts.isEmpty()) return
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        for (alert in model.alerts) {
            Text(
                alertText(alert),
                style = MaterialTheme.typography.bodyMedium,
                color = if (alert.kind == GroupAlert.Kind.NEWER) palette.text else palette.danger,
            )
            when (alert.kind) {
                GroupAlert.Kind.TWO_HISTORIES ->
                    if (model.isRoot) {
                        QuietButton(stringResource(R.string.void_both_histories), onClick = { scope.launch { model.resolve(alert) } })
                    } else {
                        RootDecides()
                    }
                GroupAlert.Kind.CLAIMS, GroupAlert.Kind.CLAIM_PENDING, GroupAlert.Kind.CLAIM_STOPPED ->
                    if (model.isRoot) {
                        QuietButton(stringResource(R.string.cancel_claim), onClick = { scope.launch { model.resolve(alert) } })
                    } else {
                        RootDecides()
                    }
                GroupAlert.Kind.ADMINS ->
                    if (model.isRoot) {
                        for ((id, name) in alert.devices.zip(alert.names)) {
                            QuietButton(stringResource(R.string.remove_device, name), onClick = { scope.launch { model.remove(id) } })
                        }
                    } else {
                        RootDecides()
                    }
                else -> {}
            }
        }
    }
}

/** The root handed the group to this phone (cbb handover): the button that takes it. */
@Composable
private fun Handed(model: AppModel) {
    if (!model.handedOver) return
    val palette = LocalPalette.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Text(stringResource(R.string.handed_title), style = MaterialTheme.typography.titleMedium, color = palette.text)
        Text(stringResource(R.string.handed_body), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
        AccentButton(stringResource(R.string.handed_take), enabled = !busy, onClick = {
            busy = true
            scope.launch {
                try {
                    model.takeHandedGroup()
                } finally {
                    busy = false
                }
            }
        })
    }
}

@Composable
private fun RootDecides() {
    Text(stringResource(R.string.alert_root_decides), style = MaterialTheme.typography.bodySmall, color = LocalPalette.current.textDim)
}

/** A wait in days, hours or minutes, in the user's language. */
private fun roughly(ms: Long): String {
    val h = ms / 3_600_000
    val m = when {
        h >= 48 -> Measure(h / 24, MeasureUnit.DAY)
        h >= 2 -> Measure(h, MeasureUnit.HOUR)
        else -> Measure(maxOf(1, ms / 60_000), MeasureUnit.MINUTE)
    }
    return MeasureFormat.getInstance(Locale.getDefault(), MeasureFormat.FormatWidth.WIDE).format(m)
}

/** The alert in a sentence. */
@Composable
private fun alertText(alert: GroupAlert): String {
    val who = if (alert.names.isEmpty()) stringResource(R.string.alert_unknown_devices) else alert.names.joinToString(", ")
    return when (alert.kind) {
        GroupAlert.Kind.STOPPED -> stringResource(R.string.alert_stopped)
        GroupAlert.Kind.SECRETS_STOPPED -> stringResource(R.string.alert_secrets_stopped)
        GroupAlert.Kind.TWO_HISTORIES -> stringResource(R.string.alert_two_histories, who)
        GroupAlert.Kind.ADMINS -> stringResource(R.string.alert_admins, who)
        GroupAlert.Kind.CLAIMS -> stringResource(R.string.alert_claims, who)
        GroupAlert.Kind.CLAIM_PENDING -> {
            val ms = alert.leftMS
            if (ms == null || ms <= 0) {
                stringResource(R.string.alert_claim_pending, who)
            } else {
                val left = roughly(ms)
                stringResource(R.string.alert_claim_pending_left, who, left)
            }
        }
        GroupAlert.Kind.CLAIM_STOPPED -> stringResource(R.string.alert_claim_stopped, who)
        GroupAlert.Kind.NEWER -> stringResource(R.string.alert_newer, alert.count)
    }
}

/**
 * "Lost phone?" on an admin phone that is the group's only admin: how a
 * second phone becomes an admin. Closed once, it stays closed.
 */
@Composable
private fun LostPhoneCard(model: AppModel) {
    if (!model.isAdmin || model.devices.count { it.admin } != 1) return
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("tips", android.content.Context.MODE_PRIVATE) }
    var closed by remember { mutableStateOf(prefs.getBoolean("lostPhoneCard", false)) }
    if (closed) return
    val palette = LocalPalette.current
    Column(Modifier.fillMaxWidth().card().padding(Tokens.spacingMedium), verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.lost_phone_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            IconText("✕", stringResource(R.string.close), small = true) {
                closed = true
                prefs.edit().putBoolean("lostPhoneCard", true).apply()
            }
        }
        Text(stringResource(R.string.lost_phone_note), style = MaterialTheme.typography.bodyMedium, color = palette.textDim)
    }
}

/**
 * When the app could not read what was copied as it opened (Android lets
 * only the app in front read it, and the user's own settings may stop it),
 * one small button sends it.
 */
@Composable
private fun FallbackSend(model: AppModel) {
    if (!model.sendFailed) return
    val scope = rememberCoroutineScope()
    QuietButton(stringResource(R.string.send_copy), enabled = !model.busy, onClick = { scope.launch { model.sync() } })
}

/** The devices as tiles or as a list; each one opens its details. */
@Composable
private fun DeviceCollection(devices: List<LiveGroup.Device>, layout: DeviceLayout, select: (String) -> Unit) {
    if (devices.isEmpty()) {
        Text(stringResource(R.string.no_computers), color = LocalPalette.current.textDim)
        return
    }
    if (layout == DeviceLayout.LIST) {
        Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall)) {
            for (d in devices) DeviceRow(d, open = { select(d.id) })
        }
        return
    }
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val columns = maxOf(2, (maxWidth / 160.dp).toInt())
        Column(verticalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
            for (row in devices.chunked(columns)) {
                Row(horizontalArrangement = Arrangement.spacedBy(Tokens.spacingMedium)) {
                    for (d in row) DeviceTile(d, Modifier.weight(1f), open = { select(d.id) })
                    repeat(columns - row.size) { Spacer(Modifier.weight(1f)) }
                }
            }
        }
    }
}

/** A device as a tile: its icon and live dot, its name, its system and where it stands. */
@Composable
internal fun DeviceTile(d: LiveGroup.Device, modifier: Modifier, open: (() -> Unit)?, menu: (() -> Unit)? = null) {
    val model = LocalModel.current
    val muted = model?.shownMuted(d) == true
    val corner = model?.mayMute(d) == true
    Box(modifier) {
        Column(
            Modifier.fillMaxWidth().glassTile()
                .then(if (muted) Modifier.dashedOutline(LocalPalette.current.danger, LocalStyle.current.radiusTile) else Modifier)
                .focusRing().tap(open, menu).padding(Tokens.spacingMedium).liveState(d),
            verticalArrangement = Arrangement.spacedBy(Tokens.spacingSmall),
        ) {
            Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                DeviceIcon(d)
                OnlineDot(d.online)
                Spacer(Modifier.weight(1f))
                if (corner) Spacer(Modifier.width(28.dp))
            }
            Text(d.name, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            DeviceSubtitle(d)
        }
        if (model != null && corner) MuteCorner(model, d, muted, Modifier.align(Alignment.TopEnd))
    }
}

/** The app's model for the tiles, which reach it through the composition. */
internal val LocalModel = staticCompositionLocalOf<AppModel?> { null }

/**
 * The small button in a tile's corner (docs/apps.md, "Muting from the
 * tile"): on this phone's own tile it turns sync off or on, on another
 * device's an admin mutes it for the group or unmutes it. A tap holds until
 * undone; a long press picks a time. The tile shows the new state at once.
 */
@Composable
private fun MuteCorner(model: AppModel, d: LiveGroup.Device, muted: Boolean, modifier: Modifier) {
    val palette = LocalPalette.current
    val style = LocalStyle.current
    val scope = rememberCoroutineScope()
    val haptics = LocalHapticFeedback.current
    var times by remember { mutableStateOf(false) }
    val label = when {
        d.isSelf && muted -> d.syncOff?.until?.let { stringResource(R.string.sync_off_until, shortTime(it)) } ?: stringResource(R.string.sync_off)
        d.isSelf -> stringResource(R.string.sync_on)
        muted -> stringResource(R.string.unmute)
        else -> stringResource(R.string.mute)
    }
    val shape = RoundedCornerShape(style.radiusChip)
    Box(modifier) {
        Box(
            Modifier.size(44.dp)
                .combinedClickable(
                    role = Role.Switch,
                    onClickLabel = label,
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.ToggleOn)
                        scope.launch { model.muteFromTile(d, !muted) }
                    },
                    onLongClickLabel = if (muted) null else stringResource(R.string.pause_for_a_time),
                    onLongClick = if (muted) null else ({ times = true }),
                )
                .semantics {
                    contentDescription = "$label, ${d.name}"
                    stateDescription = label
                },
            contentAlignment = Alignment.Center,
        ) {
            Box(
                Modifier.size(28.dp).clip(shape).background(if (muted) palette.danger else Color.Transparent)
                    .border(maxOf(style.stroke, 1.dp), if (muted) palette.danger else palette.line, shape),
                contentAlignment = Alignment.Center,
            ) {
                SwitchGlyph(if (muted) "speaker-off" else "speaker", if (muted) palette.onAccent else palette.textDim, 16.dp)
            }
        }
        DropdownMenu(expanded = times, onDismissRequest = { times = false }) {
            for (t in PauseTime.entries) {
                DropdownMenuItem(
                    text = { Text(stringResource(if (t == PauseTime.EVER && !d.isSelf) R.string.mute_ever else t.title)) },
                    onClick = {
                        times = false
                        scope.launch { model.muteFromTile(d, true, t.ms) }
                    },
                )
            }
        }
    }
}

/** A device as a row of the list. */
@Composable
internal fun DeviceRow(d: LiveGroup.Device, modifier: Modifier = Modifier, open: (() -> Unit)?, menu: (() -> Unit)? = null) {
    val palette = LocalPalette.current
    Row(
        modifier.fillMaxWidth().heightIn(min = 60.dp).card().focusRing().tap(open, menu)
            .padding(horizontal = Tokens.spacingMedium, vertical = Tokens.spacingSmall).liveState(d),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        DeviceIcon(d, 36.dp)
        Column(Modifier.weight(1f).padding(horizontal = Tokens.spacingMedium)) {
            Text(d.name, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            DeviceSubtitle(d)
        }
        OnlineDot(d.online)
        if (open != null) Text("›", color = palette.textDim, modifier = Modifier.padding(start = Tokens.spacingSmall))
    }
}

/** The system (or kind) of a device, then where it stands, on two lines when one is too narrow. */
@Composable
internal fun DeviceSubtitle(d: LiveGroup.Device) {
    val first = d.system ?: stringResource(d.kind.title)
    val standing = d.standing?.let { "$first · ${stringResource(it)}" } ?: first
    val text = when (d.hub) {
        LiveGroup.HubMark.IN_USE -> "$standing · ${stringResource(R.string.hub_in_use)}"
        LiveGroup.HubMark.HUB -> "$standing · ${stringResource(R.string.hub_mark)}"
        null -> standing
    }
    val palette = LocalPalette.current
    val off = d.syncOff?.takeIf { d.isSelf }
    val mark = when {
        d.muted != null -> stringResource(R.string.muted_mark)
        off != null -> off.until?.let { stringResource(R.string.sync_off_until, shortTime(it)) } ?: stringResource(R.string.sync_off)
        else -> null
    }
    if (mark != null) {
        // Muted, or this phone's sync off, shows in the danger colour, after where it stands.
        Text(
            buildAnnotatedString {
                append("$text · ")
                withStyle(SpanStyle(color = palette.danger)) { append(mark) }
            },
            style = MaterialTheme.typography.bodySmall, color = palette.textDim, maxLines = 2, overflow = TextOverflow.Ellipsis,
        )
        return
    }
    Text(text, style = MaterialTheme.typography.bodySmall, color = palette.textDim, maxLines = 2, overflow = TextOverflow.Ellipsis)
}

/** One element for TalkBack, which says whether it is online. */
@Composable
private fun Modifier.liveState(d: LiveGroup.Device): Modifier {
    val state = stringResource(if (d.online) R.string.online else R.string.offline)
    return semantics(mergeDescendants = true) { stateDescription = state }
}

/**
 * Keeps syncing in the background: the service, and on Android 13 and later
 * the permission for its notification, asked once.
 */
@Composable
private fun BackgroundSync() {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { SyncService.start(context) }
    LaunchedEffect(Unit) {
        val permission = Manifest.permission.POST_NOTIFICATIONS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED
        ) {
            launcher.launch(permission)
        } else {
            SyncService.start(context)
        }
    }
}
