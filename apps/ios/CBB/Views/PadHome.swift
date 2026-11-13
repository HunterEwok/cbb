// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// What the big screen's sidebar opens: the devices (all of them, those
/// that need attention, one collection) or a part of the settings.
enum PadSection: Hashable {
    case all, attention
    case collection(String)
    case settings(SettingsPart)
}

/// Home on a big screen (docs/apps.md, "Big screens"): a sidebar with the
/// group's line and its two switches, the devices' sections and the
/// settings' parts; beside it the chosen section, and for the devices the
/// chosen device's card in a pane at the trailing edge. The split view
/// folds the sidebar away in portrait and in a narrow window, and the
/// window's width alone decides: Slide Over and a third of the screen get
/// the phone's page (PhoneHome). Rights do not depend on it: they follow
/// how the device keeps its key.
struct PadHome: View {
    @Binding var adding: Bool
    @Binding var inviting: Bool
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette
    @State private var section: PadSection? = .all
    @State private var selected: AppModel.Computer.ID?
    @State private var columns = NavigationSplitViewVisibility.automatic

    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            PadSidebar(section: $section)
                .navigationSplitViewColumnWidth(min: 280, ideal: 320, max: 400)
        } detail: {
            NavigationStack {
                detail
            }
        }
        .navigationSplitViewStyle(.balanced)
        .background { shortcuts }
        // The sidebar stands while the window is wide, as in landscape, and
        // folds away when it narrows, as in portrait; between the two the
        // user's own choice holds.
        .onGeometryChange(for: Bool.self) { $0.size.width >= 1100 } action: { wide in
            columns = wide ? .all : .detailOnly
        }
        // Another section closes the card, and Arrange mode, of the last.
        .onChange(of: section) { _, _ in
            selected = nil
            arrange.on = false
        }
        // A collection that a move or ungroup ended takes its section along.
        .onChange(of: model.arranged) { _, _ in
            if case .collection(let id) = section, model.collection(id) == nil { section = .all }
            if case .attention = section, !model.devices.contains(where: \.needsAttention) { section = .all }
        }
    }

    @ViewBuilder private var detail: some View {
        switch section ?? .all {
        case .settings(.why):
            WhyScreen()
        case .settings(let part):
            SettingsView(part: part)
        case let devices:
            PadDevices(section: devices, selected: $selected)
                .toolbar {
                    // In the detail's toolbar, which stays in portrait while
                    // the sidebar folds away.
                    ToolbarItem(placement: .primaryAction) { AddMenu(adding: $adding, inviting: $inviting) }
                }
        }
    }

    /// The keyboard's shortcuts to the sidebar's sections, Command-1 to 9 in
    /// its order, and Command-comma to the settings; holding Command lists
    /// them. Invisible buttons, as a split view has no menu bar of its own.
    private var shortcuts: some View {
        let order = PadSidebar.order(model)
        return ZStack {
            ForEach(Array(order.prefix(9).enumerated()), id: \.offset) { i, s in
                Button { section = s } label: { PadSidebar.title(s, model) }
                    .keyboardShortcut(KeyEquivalent(Character(String(i + 1))), modifiers: .command)
            }
            Button { section = .settings(.look) } label: { Text("Settings") }
                .keyboardShortcut(",", modifiers: .command)
        }
        .opacity(0)
        .frame(width: 0, height: 0)
        .accessibilityHidden(true)
    }
}

/// The sidebar: the group's line with the switches, then the devices'
/// sections and the settings' parts, each with its symbol.
struct PadSidebar: View {
    @Binding var section: PadSection?
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        List(selection: $section) {
            Section {
                GroupHeader()
                    .listRowBackground(palette.surface)
            }
            Section {
                ForEach(Self.devices(model), id: \.self) { s in
                    row(s).tag(s)
                        .contextMenu {
                            if case .collection(let id) = s {
                                ArrangeMenu(ref: .collection(id), level: model.arranged.map(\.ref))
                            }
                        }
                }
            } header: {
                Text("Devices")
            }
            Section {
                ForEach(Self.settings(model), id: \.self) { s in row(s).tag(s) }
            } header: {
                Text("Settings")
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(AppBackground())
        .navigationTitle(Text("CBB"))
    }

    private func row(_ s: PadSection) -> some View {
        HStack(spacing: Tokens.spacingSmall) {
            Label { Self.title(s, model) } icon: { Image(systemName: Self.symbol(s)) }
            Spacer()
            if let n = Self.count(s, model) {
                Text(verbatim: n.formatted())
                    .font(.subheadline)
                    .foregroundStyle(s == .attention ? palette.danger : palette.textDim)
            }
        }
        // The size of a touch, with or without a pointer.
        .frame(minHeight: 44)
    }

    /// The devices' sections: all, those that need attention (while any
    /// does), and each collection.
    static func devices(_ model: AppModel) -> [PadSection] {
        var out: [PadSection] = [.all]
        if model.devices.contains(where: \.needsAttention) { out.append(.attention) }
        for case let .collection(c, _) in model.arranged { out.append(.collection(c.id)) }
        return out
    }

    /// The settings' parts this device has.
    static func settings(_ model: AppModel) -> [PadSection] {
        SettingsPart.allCases.filter { $0.shown(model) }.map { .settings($0) }
    }

    static func order(_ model: AppModel) -> [PadSection] { devices(model) + settings(model) }

    static func title(_ s: PadSection, _ model: AppModel) -> Text {
        switch s {
        case .all: Text("All devices")
        case .attention: Text("Needs attention")
        case .collection(let id): Text(verbatim: model.collection(id)?.0.name ?? "")
        case .settings(let p): p.title
        }
    }

    static func symbol(_ s: PadSection) -> String {
        switch s {
        case .all: "square.grid.2x2"
        case .attention: "exclamationmark.triangle"
        case .collection: "folder"
        case .settings(let p): p.symbol
        }
    }

    static func count(_ s: PadSection, _ model: AppModel) -> Int? {
        switch s {
        case .all: model.devices.count
        case .attention: model.devices.filter(\.needsAttention).count
        case .collection(let id): model.collection(id)?.1.count
        case .settings: nil
        }
    }
}

/// A devices' section: the alerts, then the devices as tiles, a list or
/// orbits, and the chosen device's card at the trailing edge while the
/// window leaves it room; in a narrower one the card is the next page.
/// The arrow keys move the choice from device to device.
struct PadDevices: View {
    let section: PadSection
    @Binding var selected: AppModel.Computer.ID?
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.themeStyle) private var style
    @Environment(\.palette) private var palette
    @AppStorage(DeviceLayout.wideKey) private var layout = DeviceLayout.tiles
    @State private var query = ""
    @FocusState private var focused: Bool
    /// Whether something dragged from another app is over the devices.
    @State private var dropping = false
    /// The card's width, as the text size grows.
    @ScaledMetric(relativeTo: .body) private var cardWidth: CGFloat = 400
    /// The narrowest the devices may be beside the card.
    @ScaledMetric(relativeTo: .body) private var devicesWidth: CGFloat = 360
    /// Whether the window leaves the card room beside the devices.
    @State private var beside = true
    /// The card as the next page, chosen while there was no room beside.
    @State private var pushed: PadCard?

    var body: some View {
        HStack(spacing: 0) {
            devices
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            if beside, let id = selected {
                Divider().overlay(palette.line)
                DeviceDetailView(id: id, close: { selected = nil })
                    .frame(width: min(cardWidth, 520))
                    .transition(.move(edge: .trailing))
            }
        }
        // A change of width (a turn, Split View) keeps the card where it is
        // until there is room again; then the next page comes back beside.
        .onGeometryChange(for: Bool.self) { $0.size.width >= devicesWidth + min(cardWidth, 520) } action: { room in
            beside = room
            if room, let p = pushed {
                pushed = nil
                selected = p.id
            }
        }
        .navigationDestination(item: $pushed) { card in
            DeviceDetailView(id: card.id)
        }
        .animation(.smooth, value: selected)
        .environment(\.chosenDevice, selected)
        .searchable(text: $query, placement: .toolbar, prompt: Text("Search devices"))
        .onChange(of: query) { _, q in if !q.isEmpty { arrange.on = false } }
        .background(AppBackground())
        .navigationTitle(PadSidebar.title(section, model))
        .toolbar {
            ToolbarItem(placement: .secondaryAction) { viewMenu }
        }
        .sensoryFeedback(.success, trigger: model.message)
        .focusable()
        .focused($focused)
        .focusEffectDisabled()
        .onKeyPress(keys: [.leftArrow, .upArrow, .rightArrow, .downArrow]) { press in
            move(by: press.key == .leftArrow || press.key == .upArrow ? -1 : 1)
        }
        // Escape closes the card, as its cross's shortcut does; the
        // shortcut alone does not reach a pane while the devices hold focus.
        .onKeyPress(.escape) {
            guard selected != nil else { return .ignored }
            selected = nil
            return .handled
        }
        .onAppear { focused = true }
    }

    @ViewBuilder private var devices: some View {
        let orbit = layout == .orbit && section == .all && !arrange.on && query.isEmpty
        VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
            AlertsCard()
            FallbackPaste()
            if let message = model.message {
                Text(message).foregroundStyle(palette.textDim)
            }
            if orbit {
                OrbitView(devices: model.devices, selected: selected, select: choose)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                        if arrange.on { ArrangeBar() }
                        list
                    }
                    // Room for the focus ring and the lift of a tile.
                    .padding(.vertical, Tokens.spacingSmall)
                }
            }
            LostPhoneCard()
        }
        .padding(Tokens.spacingLarge)
        // Text or a picture dropped beside the tiles goes to the group, as
        // a copy here would; one dropped on a tile is pasted there.
        .onDrop(of: [.plainText, .image], isTargeted: $dropping) { providers in
            guard !providers.contains(where: { $0.hasItemConformingToTypeIdentifier(ArrangeState.tileType.identifier) })
            else { return false }
            Task { @MainActor in await model.sync(board: await AppModel.Board.load(providers)) }
            return true
        }
        .overlay {
            if dropping {
                RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous)
                    .strokeBorder(palette.accent, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                    .padding(Tokens.spacingSmall)
                    .allowsHitTesting(false)
            }
        }
    }

    @ViewBuilder private var list: some View {
        let tiles: DeviceLayout = layout == .orbit ? .tiles : layout
        if !query.isEmpty {
            let found = shown.filter { $0.matches(query) }
            if found.isEmpty {
                Text("No devices match.").foregroundStyle(palette.textDim)
            } else {
                DeviceCollection(devices: found, layout: tiles, select: choose)
            }
        } else if section == .all {
            ArrangedDevices(layout: tiles, select: choose)
        } else if case .collection(let id) = section, shown.isEmpty {
            Text("Drag devices here, or add them with Move to collection in a device's menu.").foregroundStyle(palette.textDim)
                .id(id)
        } else {
            DeviceCollection(devices: shown, layout: tiles, select: choose)
        }
    }

    /// The section's devices, in the order they stand.
    private var shown: [AppModel.Computer] {
        switch section {
        case .attention: model.devices.filter(\.needsAttention)
        case .collection(let id): model.collection(id)?.1 ?? []
        default:
            model.arranged.flatMap { item -> [AppModel.Computer] in
                switch item {
                case .device(let d): [d]
                case .collection(_, let ds): ds
                }
            }
        }
    }

    /// Opens a device's card: beside the devices, or as the next page in a
    /// window too narrow for both.
    private func choose(_ id: AppModel.Computer.ID) {
        if beside { selected = id } else { pushed = PadCard(id: id) }
        // A tap moves the keyboard's focus to the tile; the arrow keys and
        // Escape are the devices' own, so the focus comes back to them.
        focused = true
    }

    /// Moves the choice to the device before or after it, as they stand.
    private func move(by step: Int) -> KeyPress.Result {
        let ids = (query.isEmpty ? shown : shown.filter { $0.matches(query) }).map(\.id)
        guard beside, !ids.isEmpty, !arrange.on else { return .ignored }
        guard let at = selected.flatMap(ids.firstIndex(of:)) else {
            selected = step > 0 ? ids.first : ids.last
            return .handled
        }
        selected = ids[max(0, min(ids.count - 1, at + step))]
        return .handled
    }

    private var viewMenu: some View {
        Menu {
            Picker(selection: $layout) {
                Label { Text("Tiles") } icon: { Image(systemName: "square.grid.2x2") }.tag(DeviceLayout.tiles)
                Label { Text("List") } icon: { Image(systemName: "list.bullet") }.tag(DeviceLayout.list)
                Label { Text("Orbit") } icon: { Image(systemName: "circle.circle") }.tag(DeviceLayout.orbit)
            } label: {
                Text("View")
            }
            .pickerStyle(.inline)
            ArrangeMenuItems(disabled: !query.isEmpty)
        } label: {
            Label { Text("View") } icon: { Image(systemName: "rectangle.grid.2x2") }
        }
    }
}

/// The card shown as the next page in a narrow window.
private struct PadCard: Hashable {
    let id: AppModel.Computer.ID
}

/// Text, a picture or files dropped on a device's tile are pasted where its
/// keyboard focus is, as remote paste from its card does (PasteView): an
/// admin's tile of a device that takes remote paste, outlined while
/// something is over it. Arrange mode's own drag of a tile is left alone.
struct PasteDrop: ViewModifier {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.themeStyle) private var style
    @Environment(\.palette) private var palette
    @State private var over = false

    // Self.Content: the kit has a type Content of its own.
    func body(content: Self.Content) -> some View {
        if model.isAdmin, device.takesPaste {
            content
                .onDrop(of: [.image, .plainText, .fileURL, .data], isTargeted: $over) { providers in
                    // A tile dragged in Arrange mode is no paste.
                    guard !providers.contains(where: { $0.hasItemConformingToTypeIdentifier(ArrangeState.tileType.identifier) })
                    else { return false }
                    Task { await deliver(providers) }
                    return true
                }
                .overlay {
                    if over {
                        RoundedRectangle(cornerRadius: style.radiusTile, style: .continuous)
                            .strokeBorder(palette.accent, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                            .allowsHitTesting(false)
                    }
                }
        } else {
            content
        }
    }

    private func deliver(_ providers: [NSItemProvider]) async {
        // One picture as a picture, text as text, anything else as files.
        if providers.count == 1, let p = providers.first, p.hasItemConformingToTypeIdentifier(UTType.image.identifier),
           let data = await Self.data(p, UTType.image), let image = UIImage(data: data) {
            guard let copied = PasteView.image(data, image), Int64(copied.data.count) <= Images.maxCopy else {
                model.message = String(localized: "The picture could not be read, or is larger than 100 MB.", bundle: .app)
                return
            }
            await model.pasteMedia(device.id, parts: [.data(copied.data, type: copied.type)], enter: false)
            return
        }
        if providers.count == 1, let p = providers.first, p.hasItemConformingToTypeIdentifier(UTType.plainText.identifier),
           !p.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier),
           let data = await Self.data(p, UTType.plainText), let text = String(data: data, encoding: .utf8), !text.isEmpty {
            await model.paste(device.id, text: text, method: "paste", enter: false, secret: false)
            return
        }
        var parts: [CoreMember.Part] = []
        var total: Int64 = 0
        for p in providers {
            guard let file = await Self.file(p) else {
                model.message = String(localized: "\(p.suggestedName ?? "") could not be read.", bundle: .app)
                return
            }
            total += Int64(file.data.count)
            guard total <= Images.maxCopy else {
                model.message = String(localized: "The files are larger than 100 MB together.", bundle: .app)
                return
            }
            parts.append(.bytes(file.data, path: file.name))
        }
        if !parts.isEmpty { await model.pasteMedia(device.id, parts: parts, enter: false) }
    }

    private static func data(_ p: NSItemProvider, _ type: UTType) async -> Data? {
        await withCheckedContinuation { done in
            _ = p.loadDataRepresentation(forTypeIdentifier: type.identifier) { data, _ in done.resume(returning: data) }
        }
    }

    /// A dropped item as a file: its bytes, read while the system keeps it,
    /// and its name.
    private static func file(_ p: NSItemProvider) async -> (name: String, data: Data)? {
        // Read before the completion, which may not capture the provider.
        let suggested = p.suggestedName
        return await withCheckedContinuation { done in
            _ = p.loadFileRepresentation(forTypeIdentifier: UTType.data.identifier) { url, _ in
                guard let url, let data = try? Data(contentsOf: url) else { return done.resume(returning: nil) }
                done.resume(returning: (suggested.map { name in
                    url.pathExtension.isEmpty || name.hasSuffix("." + url.pathExtension) ? name : name + "." + url.pathExtension
                } ?? url.lastPathComponent, data))
            }
        }
    }
}
