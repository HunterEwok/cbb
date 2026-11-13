// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import UniformTypeIdentifiers

/// Tiles or a list, as the menu sets it; on a big screen also the orbit.
enum DeviceLayout: String {
    static let key = "deviceLayout"
    /// The choice on a big screen, which starts with the tiles and the
    /// chosen device's card beside them.
    static let wideKey = "deviceLayoutWide"

    case tiles, list, orbit
}

/// Home: the phone's one page, or on a big screen (an iPad, a foldable
/// iPhone's inner screen) the sidebar and the devices (PadHome). Both share
/// the sheets: adding a device, an invitation, the paste note, and remote
/// paste from a tile's menu. What was copied goes out as the app opens
/// (AppModel.sendOnOpen).
struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var adding = false
    @State private var inviting = false
    @AppStorage(AppModel.pasteChoiceKey) private var pasteChoice: String?
    @StateObject private var arrange = ArrangeState()

    /// The big screen's layout follows the window's width, not the device:
    /// an iPad in Slide Over or a third of the screen gets the phone's page.
    private var wide: Bool { sizeClass == .regular }

    var body: some View {
        Group {
            if wide {
                PadHome(adding: $adding, inviting: $inviting)
            } else {
                PhoneHome(adding: $adding, inviting: $inviting)
            }
        }
        .sheet(isPresented: $inviting) { InviteSheet() }
        .sheet(isPresented: Binding(get: { pasteChoice == nil && model.phase == .home }, set: { _ in })) { PasteNote() }
        .sheet(isPresented: $adding) { AddDeviceView() }
        .sheet(item: Binding(get: { arrange.pasting.flatMap { id in model.devices.first { $0.id == id } } },
                             set: { if $0 == nil { arrange.pasting = nil } })) { d in
            PasteView(device: d)
        }
        .modifier(ArrangePrompts())
        .task {
            // The live dots: which devices are connected now.
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
        .environmentObject(arrange)
    }
}

/// The phone's page: how many devices are online with the two switches,
/// sync (the house) and Everywhere (the globe), an alert only when there is
/// one, and every device of the group as tiles or a list; a device opens
/// its card on the next page.
struct PhoneHome: View {
    @Binding var adding: Bool
    @Binding var inviting: Bool
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette
    @AppStorage(DeviceLayout.key) private var layout = DeviceLayout.tiles
    @State private var settings = false
    @State private var query = ""
    @State private var filter: DeviceFilter?

    /// With more devices than fit a screen, Home offers a search and filters.
    private var many: Bool { model.devices.count > 12 }
    private var searching: Bool { many && (!query.isEmpty || filter != nil) }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    GroupHeader()
                    AlertsCard()
                    FallbackPaste()
                    if let message = model.message {
                        Text(message).foregroundStyle(palette.textDim)
                    }
                    if arrange.on { ArrangeBar() }
                    if many { DeviceFilters(filter: $filter) }
                    if searching {
                        let found = model.devices.filter { $0.matches(query) && filter.passes($0) }
                        if found.isEmpty {
                            Text("No devices match.").foregroundStyle(palette.textDim)
                        } else {
                            DeviceCollection(devices: found, layout: layout == .orbit ? .tiles : layout)
                        }
                    } else {
                        ArrangedDevices(layout: layout == .orbit ? .tiles : layout)
                    }
                    LostPhoneCard()
                }
                .padding(Tokens.spacingLarge)
            }
            .sensoryFeedback(.success, trigger: model.message)
            .modifier(DeviceSearch(on: many, query: $query))
            .background(AppBackground())
            .navigationTitle(Text("CBB"))
            .navigationDestination(for: AppModel.Computer.ID.self) { DeviceDetailView(id: $0) }
            .navigationDestination(for: CollectionRoute.self) { CollectionPage(id: $0.id) }
            .navigationDestination(isPresented: $settings) { SettingsView() }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { menu }
                ToolbarItem(placement: .primaryAction) { AddMenu(adding: $adding, inviting: $inviting) }
            }
            // Arrange mode is off while a search or a filter is on.
            .onChange(of: searching) { _, on in if on { arrange.on = false } }
        }
    }

    private var menu: some View {
        Menu {
            Picker(selection: $layout) {
                Label { Text("Tiles") } icon: { Image(systemName: "square.grid.2x2") }.tag(DeviceLayout.tiles)
                Label { Text("List") } icon: { Image(systemName: "list.bullet") }.tag(DeviceLayout.list)
            } label: {
                Text("View")
            }
            .pickerStyle(.inline)
            ArrangeMenuItems(disabled: searching)
            Button { settings = true } label: {
                Label { Text("Settings") } icon: { Image(systemName: "gearshape") }
            }
            .keyboardShortcut(",")
        } label: {
            Image(systemName: "ellipsis").accessibilityLabel(Text("Menu"))
        }
    }
}

/// "+" for an admin: scan a device's code, or send an invitation.
struct AddMenu: View {
    @Binding var adding: Bool
    @Binding var inviting: Bool
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.isAdmin {
            Menu {
                Button { adding = true } label: {
                    Label { Text("Scan a code") } icon: { Image(systemName: "qrcode.viewfinder") }
                }
                Button { inviting = true } label: {
                    Label { Text("Send an invitation") } icon: { Image(systemName: "envelope") }
                }
            } label: {
                Image(systemName: "plus").accessibilityLabel(Text("Add a device"))
            } primaryAction: {
                adding = true
            }
            .keyboardShortcut("n")
        }
    }
}

/// Arrange mode on or off, and back to the group's order, in a menu.
struct ArrangeMenuItems: View {
    var disabled = false
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState

    var body: some View {
        if model.group.hasGroup {
            Button { arrange.on.toggle() } label: {
                Label { arrange.on ? Text("Done arranging") : Text("Arrange devices") } icon: { Image(systemName: "square.grid.3x3.square") }
            }
            .disabled(disabled)
            if model.customOrder {
                Button { model.arrange(.reset) } label: {
                    Label { Text("Back to the group's order") } icon: { Image(systemName: "arrow.counterclockwise") }
                }
            }
        }
    }
}

extension AppModel.Computer {
    /// Whether the search's text is in its name or its system.
    func matches(_ query: String) -> Bool {
        query.isEmpty || name.localizedCaseInsensitiveContains(query) || (system?.localizedCaseInsensitiveContains(query) ?? false)
    }

    /// Whether it takes remote paste: members, and Android and Aurora
    /// phones; iPhones and iPads cannot.
    var takesPaste: Bool {
        !isSelf && (role == "member" || (role == "phone" && ["android", "aurora", "sailfish"].contains(os)))
    }
}

extension Optional where Wrapped == DeviceFilter {
    /// Whether a device passes the filter, or there is none.
    func passes(_ d: AppModel.Computer) -> Bool {
        switch self {
        case .some(.online): d.online
        case .some(.attention): d.needsAttention
        case .none: true
        }
    }
}

/// How many devices are online, of how many, with the two switches; under
/// it what holds now: this phone as the hub, an admin's mute.
struct GroupHeader: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        let online = model.devices.filter { $0.online || $0.isSelf }.count
        VStack(alignment: .leading, spacing: 2) {
            // The count above the switches when the two do not fit in a
            // line: a narrow sidebar, the largest text sizes.
            ViewThatFits(in: .horizontal) {
                HStack(spacing: Tokens.spacingMedium) {
                    Text("\(online) of \(model.devices.count) online").font(.title3.weight(.semibold))
                    Spacer()
                    SyncSwitches()
                }
                VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                    Text("\(online) of \(model.devices.count) online").font(.title3.weight(.semibold))
                    SyncSwitches()
                }
            }
            // The phone as the hub works while the app is open: Home says so, as a fact, not a fault.
            if model.hub?.on == true {
                Text("This phone is the hub: sync works while the app is open.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
            }
            // An admin's mute of this phone, which an admin ends.
            if let m = model.devices.first(where: \.isSelf)?.muted {
                (m.until.map { Text("An admin muted this phone until \($0.formatted(date: .abbreviated, time: .shortened)): its copies stay on it.") }
                    ?? Text("An admin muted this phone: its copies stay on it until an admin unmutes it."))
                    .font(.footnote)
                    .foregroundStyle(palette.danger)
            }
        }
    }
}

/// The system's paste button, only when iOS refused the app the clipboard
/// or its user chose not to let it read it: it hands the clipboard over
/// without asking (UIPasteControl).
struct FallbackPaste: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        if model.pasteRefused, model.syncOff == nil {
            PasteButton(supportedContentTypes: [.plainText, .image]) { providers in
                Task { @MainActor in await model.sync(board: await AppModel.Board.load(providers)) }
            }
            .labelStyle(.iconOnly)
            .buttonBorderShape(.capsule)
            .controlSize(.large)
            .tint(palette.accent)
            .frame(maxWidth: .infinity)
            .disabled(model.busy)
            .accessibilityLabel(Text("Send what you copied"))
        }
    }
}

/// The one admin of the group is told, once, how not to lose the group
/// with this phone: a card it closes for good.
struct LostPhoneCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @AppStorage("LostPhoneCardClosed") private var closed = false

    var body: some View {
        if model.isAdmin, !closed, model.devices.filter({ $0.admin }).count == 1 {
            HStack(alignment: .top, spacing: Tokens.spacingSmall) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Lost a phone?").font(.headline)
                    Text("Make a second phone an admin: on it, tap Join a group, then scan its code here with +.")
                        .font(.footnote)
                        .foregroundStyle(palette.textDim)
                }
                Spacer()
                Button { closed = true } label: {
                    Image(systemName: "xmark").foregroundStyle(palette.textDim)
                }
                .accessibilityLabel(Text("Close"))
            }
            .padding(Tokens.spacingMedium)
            .glassCard()
        }
    }
}

/// The two switches: the house turns sync on this phone off or on (a tap;
/// touch and hold for a time), the globe turns Everywhere, sync away from
/// home, on or off; the globe waits while sync is off (docs/design.md,
/// "Sync on and off").
struct SyncSwitches: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var askingAway = false

    var body: some View {
        HStack(spacing: Tokens.spacingSmall) {
            house
            if let away = model.away, model.hub?.on != true { globe(away.on) }
        }
        .alert(Text("Turn Everywhere on?"), isPresented: $askingAway) {
            Button { Task { await model.setAway(true) } } label: { Text("Turn on") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("When the phone is not on the home network, it syncs through the WireGuard tunnel of your own hub, encrypted end to end. Nothing goes anywhere else.")
        }
    }

    private var house: some View {
        let off = model.syncOff
        return Menu {
            ForEach(PauseTime.allCases) { t in
                Button { model.turnSync(false, forMS: t.ms) } label: { Text(t.title) }
            }
        } label: {
            SwitchFace(symbol: off == nil ? "house.fill" : "house", on: off == nil)
        } primaryAction: {
            model.turnSync(off != nil)
        }
        .accessibilityLabel(off == nil ? Text("Sync is on") : Text(verbatim: Self.syncOffTitle(until: off?.until)))
        .accessibilityHint(Text("Tap to turn sync off or on; touch and hold for a time"))
        .accessibilityAddTraits(off == nil ? .isSelected : [])
    }

    private func globe(_ on: Bool) -> some View {
        let waits = model.syncOff != nil && !on
        return Button {
            if on { Task { await model.setAway(false) } } else { askingAway = true }
        } label: {
            SwitchFace(symbol: "globe", on: on)
        }
        .buttonStyle(.plain)
        .disabled(waits || model.busy)
        .accessibilityLabel(on ? Text("Everywhere is on") : waits ? Text("Everywhere waits while sync is off") : Text("Everywhere is off"))
        .accessibilityAddTraits(on ? .isSelected : [])
    }

    static func syncOffTitle(until: Date?) -> String {
        guard let until else { return String(localized: "Sync off", bundle: .app) }
        return String(localized: "Sync off until \(until.formatted(date: .omitted, time: .shortened))", bundle: .app)
    }
}

/// A switch's round face: filled with the accent while on.
struct SwitchFace: View {
    let symbol: String
    let on: Bool
    @Environment(\.palette) private var palette
    @Environment(\.isEnabled) private var enabled

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 19, weight: .semibold))
            .foregroundStyle(on ? palette.onAccent : palette.textDim)
            .frame(width: 44, height: 44)
            .background(on ? palette.accent : palette.soft, in: Circle())
            .opacity(enabled ? 1 : 0.5)
            .contentShape(Circle())
    }
}

/// How long the house keeps sync off, or an admin's mute lasts.
enum PauseTime: Int64, CaseIterable, Identifiable {
    case quarter = 900_000
    case hour = 3_600_000
    case eight = 28_800_000
    case ever = 0

    var id: Int64 { rawValue }
    var ms: Int64 { rawValue }
    var title: LocalizedStringKey {
        switch self {
        case .quarter: "For 15 minutes"
        case .hour: "For an hour"
        case .eight: "For 8 hours"
        case .ever: "Until I turn it on"
        }
    }
}

/// The devices as tiles or as a list; each one opens its details: on the
/// next page, or beside them through select on a big screen.
struct DeviceCollection: View {
    let devices: [AppModel.Computer]
    let layout: DeviceLayout
    var select: ((AppModel.Computer.ID) -> Void)?
    @Environment(\.palette) private var palette
    /// The narrowest a tile may be, as the text size grows.
    @ScaledMetric(relativeTo: .body) private var tileWidth: CGFloat = 150

    /// The tiles' columns: at least 150 points wide at the usual text
    /// size and wider as the text grows, so that a device's name stays
    /// whole; a screen narrower than one column still gets one, as wide as
    /// the screen.
    static func columns(_ width: CGFloat) -> [GridItem] {
        [GridItem(.adaptive(minimum: width), spacing: Tokens.spacingMedium)]
    }

    var body: some View {
        if devices.isEmpty {
            Text("No computers connected.").foregroundStyle(palette.textDim)
        } else if layout == .list {
            VStack(spacing: Tokens.spacingSmall) {
                ForEach(devices) { d in Self.open(d, select: select) { DeviceRow(device: d) } }
            }
        } else {
            LazyVGrid(columns: DeviceCollection.columns(tileWidth), spacing: Tokens.spacingMedium) {
                ForEach(devices) { d in Self.open(d, select: select) { DeviceTile(device: d) } }
            }
        }
    }

    /// The device's tile or row as a way to its details.
    static func open<Content: View>(_ d: AppModel.Computer, select: ((AppModel.Computer.ID) -> Void)?,
                                    @ViewBuilder label: () -> Content) -> some View {
        DeviceLink(device: d, select: select, label: label())
    }
}

/// A device's tile or row as a way to its card: the next page on a phone,
/// the pane beside on a big screen, where the chosen one is outlined. The
/// pointer lifts it, and text, a picture or files dropped on it are pasted
/// there (PasteDrop).
struct DeviceLink<Content: View>: View {
    let device: AppModel.Computer
    let select: ((AppModel.Computer.ID) -> Void)?
    let label: Content
    @Environment(\.chosenDevice) private var chosen
    @Environment(\.themeStyle) private var style
    @Environment(\.palette) private var palette

    var body: some View {
        Group {
            if let select {
                Button { select(device.id) } label: {
                    label.overlay {
                        if chosen == device.id {
                            RoundedRectangle(cornerRadius: style.radiusTile, style: .continuous)
                                .strokeBorder(palette.accent, lineWidth: 2)
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(chosen == device.id ? .isSelected : [])
            } else {
                NavigationLink(value: device.id) { label }.buttonStyle(.plain)
            }
        }
        .hoverEffect(.lift)
        .modifier(PasteDrop(device: device))
    }
}

private struct ChosenDeviceKey: EnvironmentKey {
    static let defaultValue: AppModel.Computer.ID? = nil
}

extension EnvironmentValues {
    /// The device whose card stands beside the devices on a big screen.
    var chosenDevice: AppModel.Computer.ID? {
        get { self[ChosenDeviceKey.self] }
        set { self[ChosenDeviceKey.self] = newValue }
    }
}

/// A device as a tile: its icon and live dot, its name, its system and
/// where it stands.
struct DeviceTile: View {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    var body: some View {
        let muted = model.shownMuted(device)
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            HStack(alignment: .top, spacing: 6) {
                DeviceIcon(device: device)
                OnlineDot(online: device.online)
                Spacer(minLength: 0)
            }
            .padding(.trailing, model.mayMute(device) ? 28 : 0)
            Text(device.name)
                .font(.system(.headline, design: .monospaced))
                .lineLimit(1)
            DeviceSubtitle(device: device)
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassTile()
        // Muted, the tile's line turns dashed in the warning colour.
        .overlay {
            if muted {
                RoundedRectangle(cornerRadius: style.radiusTile, style: .continuous)
                    .strokeBorder(palette.danger, style: StrokeStyle(lineWidth: max(style.stroke, 1), dash: [5, 4]))
            }
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
        .overlay(alignment: .topTrailing) {
            if model.mayMute(device) { MuteCorner(device: device) }
        }
    }
}

/// The small button in a tile's corner (docs/apps.md, "Muting from the
/// tile"): on this phone's own tile it turns sync off or on, on another
/// device's an admin mutes it for the group or unmutes it. A tap holds
/// until undone; touch and hold picks a time. The tile shows the new state
/// at once.
struct MuteCorner: View {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    var body: some View {
        let muted = model.shownMuted(device)
        Menu {
            if !muted {
                ForEach(PauseTime.allCases) { t in
                    Button { set(true, forMS: t.ms) } label: {
                        t == .ever && !device.isSelf ? Text("Until an admin unmutes it") : Text(t.title)
                    }
                }
            }
        } label: {
            Image(systemName: muted ? "speaker.slash.fill" : "speaker.wave.2")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(muted ? palette.onAccent : palette.textDim)
                .frame(width: 28, height: 28)
                .background(muted ? palette.danger : Color.clear, in: RoundedRectangle(cornerRadius: style.radiusChip, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: style.radiusChip, style: .continuous)
                    .strokeBorder(muted ? palette.danger : palette.line, lineWidth: max(style.stroke, 1)))
                .frame(width: 44, height: 44)
                .contentShape(Rectangle())
        } primaryAction: {
            set(!muted, forMS: 0)
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .sensoryFeedback(.selection, trigger: muted)
        .accessibilityLabel(label(muted))
        .accessibilityHint(Text(verbatim: device.name))
        .accessibilityAddTraits(muted ? .isSelected : [])
    }

    private func label(_ muted: Bool) -> Text {
        if device.isSelf {
            return muted ? Text(verbatim: SyncSwitches.syncOffTitle(until: device.syncOff?.until)) : Text("Sync is on")
        }
        return muted ? Text("Unmute") : Text("Mute")
    }

    private func set(_ on: Bool, forMS: Int64) {
        if device.isSelf {
            model.turnSync(!on, forMS: forMS)
        } else {
            Task { await model.setMuted(device.id, on, forMS: forMS) }
        }
    }
}

/// A device as a row of the list.
struct DeviceRow: View {
    let device: AppModel.Computer
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingMedium) {
            DeviceIcon(device: device, size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.name).font(.system(.body, design: .monospaced).weight(.semibold)).lineLimit(1)
                DeviceSubtitle(device: device)
            }
            Spacer()
            OnlineDot(online: device.online)
            Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(palette.textDim)
        }
        .padding(.horizontal, Tokens.spacingMedium)
        .frame(minHeight: 60)
        .glassTile(.card)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
    }
}

/// The system (or kind) of a device, then where it stands: on one line
/// when it fits, else one under the other, so a narrow tile cuts nothing.
/// At the accessibility text sizes always one under the other, each part
/// free to take more lines: a line that fills the tile has no room left to
/// grow, and the longest one, the phone's own "This phone · admin", would
/// be cut.
struct DeviceSubtitle: View {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.dynamicTypeSize) private var textSize

    var body: some View {
        Group {
            if textSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: 2) { parts(dots: false) }
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 4) { parts(dots: true) }
                    VStack(alignment: .leading, spacing: 2) { parts(dots: false) }
                }
                .lineLimit(1)
            }
        }
        .font(.caption)
        .foregroundStyle(palette.textDim)
    }

    @ViewBuilder private func parts(dots: Bool) -> some View {
        if let system = device.system {
            Text(verbatim: system)
        } else {
            Text(device.kind.title)
        }
        if let standing = device.standing {
            if dots { Text(verbatim: "·") }
            Text(standing)
        }
        if let mark = model.hubMark(device) {
            if dots { Text(verbatim: "·") }
            Text(mark == .inUse ? "hub in use" : "hub")
                .foregroundStyle(mark == .inUse ? palette.accent : palette.textDim)
        }
        if device.isSelf, let off = device.syncOff {
            if dots { Text(verbatim: "·") }
            Text(verbatim: SyncSwitches.syncOffTitle(until: off.until))
                .foregroundStyle(palette.danger)
        }
        if device.muted != nil {
            if dots { Text(verbatim: "·") }
            Label { Text("muted") } icon: { Image(systemName: "speaker.slash") }
                .foregroundStyle(palette.danger)
        }
    }
}

/// The filters of a long list of devices.
enum DeviceFilter {
    case online, attention
}

/// Home's search, offered once there are many devices.
struct DeviceSearch: ViewModifier {
    let on: Bool
    @Binding var query: String

    @ViewBuilder func body(content: Content) -> some View {
        if on {
            content.searchable(text: $query, prompt: Text("Search devices"))
        } else {
            content
        }
    }
}

/// The two filter chips: Online and Needs attention; a second tap turns
/// one off.
struct DeviceFilters: View {
    @Binding var filter: DeviceFilter?
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingSmall) {
            chip(.online) { Text("Online") }
            chip(.attention) { Text("Needs attention") }
        }
    }

    private func chip(_ f: DeviceFilter, @ViewBuilder label: () -> Text) -> some View {
        Button { filter = filter == f ? nil : f } label: {
            label()
                .font(.footnote)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(filter == f ? palette.soft : palette.line, in: Capsule())
                .foregroundStyle(filter == f ? palette.accent : palette.text)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(filter == f ? .isSelected : [])
    }
}
