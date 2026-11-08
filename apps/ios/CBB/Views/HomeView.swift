// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import UniformTypeIdentifiers

/// Tiles or a list, as the menu sets it; on a big screen also the orbit.
enum DeviceLayout: String {
    static let key = "deviceLayout"
    /// The choice on a big screen, which starts with the orbit.
    static let wideKey = "deviceLayoutWide"

    case tiles, list, orbit
}

/// The one page: the big button, the result in one line, and every device
/// of the group as tiles or a list; a device opens its details. On a big
/// screen (an iPad, a foldable iPhone's inner screen) the devices may stand
/// on orbits around this phone, and the details open beside them.
struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.horizontalSizeClass) private var sizeClass
    @AppStorage(DeviceLayout.key) private var layout = DeviceLayout.tiles
    @AppStorage(DeviceLayout.wideKey) private var wideLayout = DeviceLayout.orbit
    @State private var adding = false
    @State private var settings = false
    /// The device whose details stand beside the devices on a big screen.
    @State private var selected: AppModel.Computer.ID?
    @StateObject private var arrange = ArrangeState()
    @State private var query = ""
    @State private var filter: DeviceFilter?

    private var wide: Bool { sizeClass == .regular }
    /// With more devices than fit a screen, Home offers a search and filters.
    private var many: Bool { model.devices.count > 12 }
    private var searching: Bool { many && (!query.isEmpty || filter != nil) }

    /// The devices the search and the filter leave, flat.
    private var found: [AppModel.Computer] {
        model.devices.filter { d in
            (query.isEmpty || d.name.localizedCaseInsensitiveContains(query) || (d.system?.localizedCaseInsensitiveContains(query) ?? false))
                && (filter != .online || d.online) && (filter != .attention || d.needsAttention)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if wide { wideBody } else { compactBody }
            }
            .modifier(DeviceSearch(on: many, query: $query))
            .background(AppBackground())
            .navigationTitle(Text("CBB"))
            .navigationDestination(for: AppModel.Computer.ID.self) { DeviceDetailView(id: $0) }
            .navigationDestination(for: CollectionRoute.self) { CollectionPage(id: $0.id) }
            .navigationDestination(isPresented: $settings) { SettingsView() }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { menu }
                // On a big screen the toolbar holds the sync button, which a
                // foldable iPhone puts in the strip at its right edge.
                if wide {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            Task { await model.sync() }
                        } label: {
                            Label { Text("Send or fetch") } icon: { Image(systemName: "arrow.up.arrow.down") }
                        }
                        .keyboardShortcut("r")
                        .disabled(model.busy)
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    if model.isAdmin {
                        Button { adding = true } label: {
                            Image(systemName: "plus").accessibilityLabel(Text("Add a device"))
                        }
                        .keyboardShortcut("n")
                    }
                }
            }
            .sheet(isPresented: $adding) { AddDeviceView() }
            .modifier(ArrangePrompts())
            // Arrange mode is off while a search or a filter is on.
            .onChange(of: searching) { _, on in if on { arrange.on = false } }
            .task {
                // The live dots: which devices are connected now.
                while !Task.isCancelled {
                    await model.refresh()
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
        .environmentObject(arrange)
    }

    /// The phone's page.
    private var compactBody: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                summary
                AlertsCard()
                // The system's paste button hands the clipboard over
                // without asking (UIPasteControl); a copy from another
                // device that waits comes in instead.
                PasteButton(supportedContentTypes: [.plainText, .image]) { providers in
                    Task { @MainActor in await model.sync(board: await AppModel.Board.load(providers)) }
                }
                .buttonBorderShape(.capsule)
                .controlSize(.large)
                .tint(palette.accent)
                .frame(maxWidth: .infinity)
                .disabled(model.busy)
                .sensoryFeedback(.success, trigger: model.message)
                Text("Paste sends what you copied to the other devices. A copy from another device comes into this phone's clipboard by itself.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
                ListenSwitch()

                if let message = model.message {
                    Text(message).foregroundStyle(palette.textDim)
                }
                devicesView(layout: layout == .orbit ? .tiles : layout, select: nil)
                hint
            }
            .padding(Tokens.spacingLarge)
        }
    }

    /// The big screen's page: the devices, and the chosen one's details
    /// beside them.
    private var wideBody: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                summary
                AlertsCard()
                ListenSwitch()
                if let message = model.message {
                    Text(message).foregroundStyle(palette.textDim)
                }
                if wideLayout == .orbit && !arrange.on && !searching {
                    if many { DeviceFilters(filter: $filter) }
                    OrbitView(devices: model.devices, selected: selected, busy: model.busy,
                              select: { selected = $0 }, sync: { Task { await model.sync() } })
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                            devicesView(layout: wideLayout == .orbit ? .tiles : wideLayout, select: { selected = $0 })
                        }
                    }
                }
                hint
            }
            .padding(Tokens.spacingLarge)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            if let id = selected {
                Divider().overlay(palette.line)
                DeviceDetailView(id: id, close: { selected = nil })
                    .frame(width: 400)
                    .transition(.move(edge: .trailing))
            }
        }
        .animation(.smooth, value: selected)
        .sensoryFeedback(.success, trigger: model.message)
    }

    /// The devices: in the user's order with the collections, or flat while
    /// a search or a filter is on.
    @ViewBuilder private func devicesView(layout: DeviceLayout, select: ((AppModel.Computer.ID) -> Void)?) -> some View {
        if arrange.on { ArrangeBar() }
        if many { DeviceFilters(filter: $filter) }
        if searching {
            if found.isEmpty {
                Text("No devices match.").foregroundStyle(palette.textDim)
            } else {
                DeviceCollection(devices: found, layout: layout, select: select)
            }
        } else {
            ArrangedDevices(layout: layout, select: select)
        }
    }

    /// How many devices are online, of how many.
    private var summary: some View {
        let online = model.devices.filter(\.online).count
        return VStack(alignment: .leading, spacing: 2) {
            Text("\(online) of \(model.devices.count) online")
                .font(.subheadline)
                .foregroundStyle(palette.textDim)
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

    private var menu: some View {
        Menu {
            Picker(selection: wide ? $wideLayout : $layout) {
                if wide {
                    Label { Text("Orbit") } icon: { Image(systemName: "circle.circle") }.tag(DeviceLayout.orbit)
                }
                Label { Text("Tiles") } icon: { Image(systemName: "square.grid.2x2") }.tag(DeviceLayout.tiles)
                Label { Text("List") } icon: { Image(systemName: "list.bullet") }.tag(DeviceLayout.list)
            } label: {
                Text("View")
            }
            .pickerStyle(.inline)
            if model.arrangement != nil {
                Button { arrange.on.toggle() } label: {
                    Label { arrange.on ? Text("Done arranging") : Text("Arrange devices") } icon: { Image(systemName: "square.grid.3x3.square") }
                }
                .disabled(searching)
                if model.arrangement?.items.isEmpty == false {
                    Button { model.arrange(.reset) } label: {
                        Label { Text("Back to the group's order") } icon: { Image(systemName: "arrow.counterclockwise") }
                    }
                }
            }
            Button { settings = true } label: {
                Label { Text("Settings") } icon: { Image(systemName: "gearshape") }
            }
            .keyboardShortcut(",")
        } label: {
            Image(systemName: "ellipsis").accessibilityLabel(Text("Menu"))
        }
    }

    @ViewBuilder private var hint: some View {
        if !model.isAdmin {
            Text("Only an admin phone can add or remove devices.").font(.footnote).foregroundStyle(palette.textDim)
        } else if model.devices.filter({ $0.admin }).count == 1 {
            Text("Lost a phone? Make a second phone an admin: on it, tap I already use CBB on another phone, then scan its code here with +.")
                .font(.footnote).foregroundStyle(palette.textDim)
        }
    }
}

/// The quick switch for taking copies from the group: a tap turns it off or
/// on again, a long press turns it off for a time. This phone's own copies
/// still go out (docs/design.md, "Muting a device").
struct ListenSwitch: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        let pause = model.pause
        Menu {
            ForEach(PauseTime.allCases) { t in
                Button { model.pauseReceiving(forMS: t.ms) } label: { Text(t.title) }
            }
        } label: {
            Label {
                if let pause { Text(verbatim: Self.pausedTitle(until: pause.until)) } else { Text("Taking copies from the group") }
            } icon: {
                Image(systemName: pause == nil ? "speaker.wave.2" : "speaker.slash")
            }
            .font(.subheadline)
            .foregroundStyle(pause == nil ? palette.textDim : palette.danger)
        } primaryAction: {
            model.pauseReceiving(forMS: pause == nil ? 0 : nil)
        }
        .accessibilityHint(Text("Tap to take no copies from the group, or to take them again; touch and hold for a time"))
    }

    static func pausedTitle(until: Date?) -> String {
        guard let until else { return String(localized: "Not taking copies from the group", bundle: .app) }
        return String(localized: "Not taking copies until \(until.formatted(date: .omitted, time: .shortened))", bundle: .app)
    }
}

/// How long the quick switch keeps the group's copies out, or an admin's
/// mute lasts.
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

    var body: some View {
        if devices.isEmpty {
            Text("No computers connected.").foregroundStyle(palette.textDim)
        } else if layout == .list {
            VStack(spacing: Tokens.spacingSmall) {
                ForEach(devices) { d in Self.open(d, select: select) { DeviceRow(device: d) } }
            }
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                ForEach(devices) { d in Self.open(d, select: select) { DeviceTile(device: d) } }
            }
        }
    }

    /// The device's tile or row as a way to its details.
    @ViewBuilder static func open<Content: View>(_ d: AppModel.Computer, select: ((AppModel.Computer.ID) -> Void)?,
                                                 @ViewBuilder label: () -> Content) -> some View {
        if let select {
            Button { select(d.id) } label: { label() }.buttonStyle(.plain)
        } else {
            NavigationLink(value: d.id) { label() }.buttonStyle(.plain)
        }
    }
}

/// A device as a tile: its icon and live dot, its name, its system and
/// where it stands.
struct DeviceTile: View {
    let device: AppModel.Computer

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            HStack(alignment: .top) {
                DeviceIcon(device: device)
                Spacer()
                OnlineDot(online: device.online)
            }
            Text(device.name)
                .font(.system(.headline, design: .monospaced))
                .lineLimit(1)
            DeviceSubtitle(device: device)
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassTile()
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
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
        .glassTile(cornerRadius: Tokens.radiusCard)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
    }
}

/// The system (or kind) of a device, then where it stands: on one line
/// when it fits, else one under the other, so a narrow tile cuts nothing.
struct DeviceSubtitle: View {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 4) { parts(dots: true) }
            VStack(alignment: .leading, spacing: 2) { parts(dots: false) }
        }
        .font(.caption)
        .foregroundStyle(palette.textDim)
        .lineLimit(1)
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
