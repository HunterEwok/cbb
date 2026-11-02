// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// How the window shows the devices; the toolbar switches.
enum DeviceLayout: String, CaseIterable, Identifiable {
    case tiles, list, orbit

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .tiles: "square.grid.2x2"
        case .list: "list.bullet"
        case .orbit: "circle.circle"
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .tiles: "Tiles"
        case .list: "List"
        case .orbit: "Orbit"
        }
    }
}

/// The one window: the group's devices as tiles, a list or orbits around
/// this Mac, a device's details beside them, and send and fetch at the
/// bottom (docs/apps.md, The Mac app).
struct MainView: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette
    @AppStorage("deviceLayout") private var layout = DeviceLayout.tiles.rawValue
    @State private var selected: String?
    @State private var adding = false
    @State private var turningAwayOn = false
    @StateObject private var arrange = ArrangeState()
    @State private var query = ""
    @State private var filter: DeviceFilter?

    /// With more devices than fit the window, it offers a search and filters.
    private var many: Bool { model.others.count > 12 }
    private var searching: Bool { many && (!query.isEmpty || filter != nil) }

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: Tokens.spacingMedium) {
                if let problem = model.problem {
                    Notice(symbol: "exclamationmark.triangle", title: "The service does not answer", text: Text(verbatim: problem))
                } else if model.status == nil {
                    ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if !model.inGroup {
                    Notice(symbol: "person.3", title: "This Mac is in no group yet", text: Text("Scan its QR code with the phone app after running cbb pair in Terminal, or make a group of computers with cbb new."))
                } else {
                    summary
                    GroupAlerts()
                    devices
                    syncBar
                }
            }
            .padding(Tokens.spacingLarge)
            .frame(minWidth: 460, maxWidth: .infinity, maxHeight: .infinity)
            if let id = selected {
                DeviceDetail(id: id) { selected = nil }
                    .frame(width: 340)
                    .transition(.move(edge: .trailing))
            }
        }
        .background(AppBackground())
        .animation(.snappy, value: selected)
        .toolbar {
            ToolbarItem {
                Picker(selection: $layout) {
                    ForEach(DeviceLayout.allCases) { l in
                        Label(l.title, systemImage: l.symbol).tag(l.rawValue)
                    }
                } label: { Text("Layout") }
                .pickerStyle(.segmented)
            }
            ToolbarItem {
                Menu {
                    Button { arrange.on.toggle() } label: { arrange.on ? Text("Done arranging") : Text("Arrange devices") }
                        .disabled(searching)
                    if model.arrangement?.items.isEmpty == false {
                        Button { model.arrange(.reset) } label: { Text("Back to the group's order") }
                    }
                } label: { Label("Arrange devices", systemImage: "square.grid.3x3.square") }
                .disabled(model.arrangement == nil)
            }
            ToolbarItem {
                Button { adding = true } label: { Label("Add a device", systemImage: "plus") }
            }
        }
        .sheet(isPresented: $adding) { AddDeviceSheet().modifier(Themed()) }
        .modifier(ArrangePrompts())
        .environmentObject(arrange)
        // Arrange mode is off while a search or a filter is on.
        .onChange(of: searching) { _, on in if on { arrange.on = false } }
        .task { model.start() }
    }

    /// The group in a line: how many devices are online, and sync away
    /// from home.
    private var summary: some View {
        // This Mac counts too, online as it is the one in front of the user.
        let online = model.devices.filter { $0.online || $0.isSelf }.count
        return HStack(spacing: Tokens.spacingMedium) {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(online) of \(model.devices.count) online").font(.title2.weight(.semibold))
                Text(verbatim: model.status?.group ?? "").font(.system(.caption, design: .monospaced)).foregroundStyle(palette.textDim)
            }
            Spacer()
            AwayBadge(away: model.status?.away)
            Toggle(isOn: Binding(get: { model.awayOn }, set: { on in
                if on { turningAwayOn = true } else { Task { await model.setAway(false) } }
            })) { Text("Away from home") }
                .toggleStyle(.switch)
                .disabled(model.busy)
        }
        .alert(Text("Turn sync away from home on?"), isPresented: $turningAwayOn) {
            Button { Task { await model.setAway(true) } } label: { Text("Turn on") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("This Mac then reaches the group's hub from the internet through the group's own WireGuard tunnel, the clipboard encrypted end to end. Its keys are files: keep FileVault on, keep the service's folder out of unencrypted backups, and remove the Mac at once if it is lost.")
        }
    }

    @ViewBuilder private var devices: some View {
        let others = model.others
        let shown = DeviceLayout(rawValue: layout) ?? .tiles
        if others.isEmpty {
            Notice(symbol: "plus.circle", title: "No other devices yet", text: Text("Add one with the + button."))
        } else if let id = arrange.opened {
            CollectionPage(id: id, layout: shown == .list ? .list : .tiles, selected: selected) { selected = $0 }
        } else if !searching && (shown != .orbit || arrange.on) {
            if many { DeviceSearchBar(query: $query, filter: $filter) }
            ArrangedDevices(layout: shown == .list ? .list : .tiles, selected: selected) { selected = $0 }
        } else if searching && found.isEmpty {
            DeviceSearchBar(query: $query, filter: $filter)
            Text("No devices match.").foregroundStyle(palette.textDim).frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            if many { DeviceSearchBar(query: $query, filter: $filter) }
            // A search shows the devices it finds, flat; the orbit keeps the
            // group's order around this Mac in the middle.
            let list = searching ? found : shown == .orbit ? others : model.devices
            switch searching && shown == .orbit ? DeviceLayout.tiles : shown {
            case .tiles:
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                        ForEach(list) { d in
                            Button { selected = d.id } label: { DeviceTile(device: d, selected: d.id == selected) }
                                .buttonStyle(.plain)
                        }
                    }
                }
            case .list:
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(Array(list.enumerated()), id: \.element.id) { i, d in
                            if i > 0 { Divider().overlay(palette.line) }
                            Button { selected = d.id } label: { DeviceRow(device: d, selected: d.id == selected) }
                                .buttonStyle(.plain)
                        }
                    }
                    .glassTile(cornerRadius: Tokens.radiusCard)
                }
            case .orbit:
                OrbitView(devices: list, selected: selected, busy: model.busy) { selected = $0 } sync: {
                    Task { await model.send() }
                }
            }
        }
    }

    /// The devices the search and the filter leave.
    private var found: [Control.Device] {
        model.devices.filter { d in
            (query.isEmpty || d.name.localizedCaseInsensitiveContains(query) || (d.system?.localizedCaseInsensitiveContains(query) ?? false))
                && (filter != .online || d.online) && (filter != .attention || d.frozen)
        }
    }

    private var syncBar: some View {
        VStack(spacing: Tokens.spacingSmall) {
            HStack(spacing: Tokens.spacingMedium) {
                Button { Task { await model.send() } } label: { Label("Send the clipboard", systemImage: "arrow.up.circle") }
                    .buttonStyle(AccentButtonStyle())
                Button { Task { await model.fetch() } } label: { Label("Fetch", systemImage: "arrow.down.circle") }
                    .buttonStyle(GlassButtonStyle())
                    .frame(maxWidth: 200)
            }
            .disabled(model.busy)
            if let message = model.message {
                Text(verbatim: message).font(.callout).foregroundStyle(palette.textDim).textSelection(.enabled)
            }
        }
    }
}

/// A tile: the icon, the name, the system and whether it is online.
struct DeviceTile: View {
    let device: Control.Device
    let selected: Bool
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            HStack {
                DeviceIcon(device: device)
                Spacer()
                OnlineDot(online: device.online)
            }
            Text(verbatim: device.name).font(.system(.headline, design: .monospaced)).lineLimit(1)
            Text(verbatim: device.system ?? "").font(.caption).foregroundStyle(palette.textDim)
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassTile()
        .overlay(RoundedRectangle(cornerRadius: Tokens.radiusTile, style: .continuous).stroke(selected ? palette.accent : .clear, lineWidth: 2))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

/// A row of the list.
struct DeviceRow: View {
    let device: Control.Device
    let selected: Bool
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingMedium) {
            DeviceIcon(device: device, size: 32)
            Text(verbatim: device.name).font(.system(.body, design: .monospaced))
            Spacer()
            Text(verbatim: device.system ?? "").foregroundStyle(palette.textDim)
            OnlineDot(online: device.online)
        }
        .padding(.horizontal, Tokens.spacingMedium)
        .frame(minHeight: 44)
        .background(selected ? palette.soft : .clear)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

/// Where sync away from home stands, in a word.
struct AwayBadge: View {
    let away: Control.Away?
    @Environment(\.palette) private var palette

    var body: some View {
        if let away {
            let text: Text = away.hub == true ? Text("hub") : away.through == true ? Text("through the tunnel") : away.error != nil ? Text("hub unreachable") : Text("at home")
            Label { text } icon: { Image(systemName: "network.badge.shield.half.filled") }
                .font(.caption.weight(.medium))
                .foregroundStyle(away.error != nil && away.hub != true ? palette.danger : palette.accent)
                .help(away.error ?? "")
        }
    }
}

/// A page-filling note with an icon, for an empty or a failed state.
struct Notice: View {
    let symbol: String
    let title: LocalizedStringKey
    let text: Text
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(spacing: Tokens.spacingMedium) {
            Image(systemName: symbol).font(.system(size: 40)).foregroundStyle(palette.accent)
            Text(title).font(.title3.weight(.semibold))
            text.foregroundStyle(palette.textDim).multilineTextAlignment(.center).textSelection(.enabled)
        }
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
