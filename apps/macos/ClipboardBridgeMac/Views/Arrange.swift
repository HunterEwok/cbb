// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import UniformTypeIdentifiers

/// Arrange mode, the open collection and the name prompts of the window
/// (docs/apps.md, "Collections and the order of the tiles").
@MainActor
final class ArrangeState: ObservableObject {
    /// Arrange mode: a click does not select a tile, and tiles can be dragged.
    @Published var on = false
    /// The collection whose page the window shows.
    @Published var opened: String?
    /// The tile being dragged.
    @Published var dragging: Arrangement.Ref?
    /// The name prompt that is open.
    @Published var prompt: Prompt?
    @Published var name = ""

    enum Prompt: Equatable {
        /// A new collection of these devices.
        case new([String])
        case rename(String)
    }

    func ask(_ p: Prompt, name: String = "") {
        self.name = name
        prompt = p
    }

    /// The type of a dragged tile, which never leaves the app.
    static let tileType = UTType(exportedAs: "io.github.hunterewok.clipboardbridge.mac.tile")

    func provider(_ ref: Arrangement.Ref) -> NSItemProvider {
        dragging = ref
        let p = NSItemProvider()
        p.registerDataRepresentation(forTypeIdentifier: Self.tileType.identifier, visibility: .ownProcess) { done in
            done(Data(), nil)
            return nil
        }
        return p
    }
}

/// The devices and collections in the user's order, as tiles or a list;
/// in Arrange mode they can be dragged.
struct ArrangedDevices: View {
    let layout: DeviceLayout
    let selected: String?
    let select: (String) -> Void
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
        let items = model.arranged, me = model.this
        let refs = items.map(\.ref)
        ScrollView {
            VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                if arrange.on { ArrangeBar() }
                if layout == .list {
                    VStack(spacing: 0) {
                        // This Mac first, as on the phones; it stays out of the arrangement.
                        if let me {
                            Button { select(me.id) } label: { DeviceRow(device: me, selected: me.id == selected) }
                                .buttonStyle(.plain)
                        }
                        ForEach(Array(items.enumerated()), id: \.element.id) { i, item in
                            if i > 0 || me != nil { Divider().overlay(palette.line) }
                            switch item {
                            case .device(let d):
                                ArrangedTile(ref: item.ref, level: refs, select: select) { DeviceRow(device: d, selected: d.id == selected) }
                            case .collection(let c, let ds):
                                CollectionSection(collection: c, devices: ds, level: refs, selected: selected, select: select)
                            }
                        }
                    }
                    .glassTile(cornerRadius: Tokens.radiusCard)
                } else {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                        if let me {
                            Button { select(me.id) } label: { DeviceTile(device: me, selected: me.id == selected) }
                                .buttonStyle(.plain)
                        }
                        ForEach(items) { item in
                            switch item {
                            case .device(let d):
                                ArrangedTile(ref: item.ref, level: refs, select: select) { DeviceTile(device: d, selected: d.id == selected) }
                            case .collection(let c, let ds):
                                ArrangedTile(ref: item.ref, level: refs, select: select) { CollectionTile(collection: c, devices: ds) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A device or a collection with its menu, its VoiceOver actions and, in
/// Arrange mode, its drag and drop and the keys that move it; level is the
/// order it moves in.
struct ArrangedTile<Tile: View>: View {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    let select: (String) -> Void
    @ViewBuilder let label: () -> Tile
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
        let moves = Moves(ref: ref, level: level, model: model)
        Group {
            if arrange.on {
                label()
                    .overlay {
                        RoundedRectangle(cornerRadius: Tokens.radiusTile, style: .continuous)
                            .strokeBorder(palette.accent, style: StrokeStyle(lineWidth: 1.5, dash: [5, 4]))
                    }
                    .opacity(arrange.dragging == ref ? 0.4 : 1)
                    .onDrag { arrange.provider(ref) }
                    .onDrop(of: [ArrangeState.tileType], delegate: TileDrop(target: ref, level: level, model: model, arrange: arrange))
                    // Option and the arrow keys move the focused tile.
                    .focusable()
                    .onKeyPress(keys: [.leftArrow, .upArrow, .rightArrow, .downArrow, .home, .end], phases: .down) { press in
                        guard press.modifiers.contains(.option) else { return .ignored }
                        switch press.key {
                        case .leftArrow, .upArrow: moves.earlier()
                        case .rightArrow, .downArrow: moves.later()
                        case .home: moves.toStart()
                        default: moves.toEnd()
                        }
                        return .handled
                    }
            } else {
                Button {
                    switch ref {
                    case .device(let id): select(id)
                    case .collection(let id): arrange.opened = id
                    }
                } label: { label() }
                .buttonStyle(.plain)
            }
        }
        .contextMenu { ArrangeMenu(ref: ref, level: level) }
        .modifier(ArrangeActions(ref: ref, level: level))
    }
}

/// The moves of a tile within its level, the same for the menu, the keys
/// and VoiceOver.
@MainActor
struct Moves {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    let model: MacModel

    private var index: Int? { level.firstIndex(of: ref) }

    var canMoveEarlier: Bool { (index ?? 0) > 0 }
    var canMoveLater: Bool { index.map { $0 + 1 < level.count } ?? false }

    func toStart() { if canMoveEarlier { model.arrange(.move(ref, before: level.first)) } }
    func toEnd() { if canMoveLater { model.arrange(.move(ref, before: nil)) } }

    func earlier() {
        guard let i = index, i > 0 else { return }
        model.arrange(.move(ref, before: level[i - 1]))
    }

    func later() {
        guard let i = index, i + 1 < level.count else { return }
        model.arrange(.move(ref, before: i + 2 < level.count ? level[i + 2] : nil))
    }
}

/// A tile's menu on a right click: Arrange, and every change a drag makes.
struct ArrangeMenu: View {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var arrange: ArrangeState

    var body: some View {
        let moves = Moves(ref: ref, level: level, model: model)
        if !arrange.on {
            Button { arrange.on = true } label: { Text("Arrange") }
        }
        switch ref {
        case .device(let id):
            Menu {
                ForEach(model.collections(apartFrom: id), id: \.id) { c in
                    Button { model.arrange(.into(device: id, collection: c.id)) } label: { Text(verbatim: c.name) }
                }
                Button { arrange.ask(.new([id])) } label: { Text("New collection…") }
            } label: { Text("Move to collection") }
            if model.collection(holding: id) != nil {
                Button { model.arrange(.out(device: id)) } label: { Text("Take out of collection") }
            }
        case .collection(let id):
            Button { arrange.ask(.rename(id), name: model.collection(id)?.0.name ?? "") } label: { Text("Rename collection…") }
            Button { model.arrange(.ungroup(collection: id)) } label: { Text("Ungroup") }
        }
        if moves.canMoveEarlier {
            Button { moves.toStart() } label: { Text("Move to start") }
        }
        if moves.canMoveLater {
            Button { moves.toEnd() } label: { Text("Move to end") }
        }
    }
}

/// The same changes as VoiceOver's actions, in Arrange mode.
struct ArrangeActions: ViewModifier {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var arrange: ArrangeState

    @ViewBuilder func body(content: Content) -> some View {
        let moves = Moves(ref: ref, level: level, model: model)
        if arrange.on {
            content
                .accessibilityAction(named: Text("Move earlier")) { moves.earlier() }
                .accessibilityAction(named: Text("Move later")) { moves.later() }
                .accessibilityAction(named: Text("Move to start")) { moves.toStart() }
                .accessibilityAction(named: Text("Move to end")) { moves.toEnd() }
                .accessibilityAction(named: Text("Take out of collection")) {
                    if case .device(let id) = ref, model.collection(holding: id) != nil { _ = model.arrange(.out(device: id)) }
                }
        } else {
            content
        }
    }
}

/// Moves the dragged tile as it passes over the others, and puts a device
/// dropped on a collection into it.
@MainActor
struct TileDrop: DropDelegate {
    let target: Arrangement.Ref
    let level: [Arrangement.Ref]
    let model: MacModel
    let arrange: ArrangeState

    func validateDrop(info: DropInfo) -> Bool { arrange.dragging != nil }

    func dropEntered(info: DropInfo) {
        guard let d = arrange.dragging, d != target, level.contains(d) else { return }
        // A device over a collection goes into it on the drop, not before.
        if case .device = d, case .collection = target { return }
        guard let from = level.firstIndex(of: d), let to = level.firstIndex(of: target) else { return }
        withAnimation(.smooth) {
            _ = model.arrange(.move(d, before: from < to ? (to + 1 < level.count ? level[to + 1] : nil) : target))
        }
    }

    func dropUpdated(info: DropInfo) -> DropProposal? { DropProposal(operation: .move) }

    func performDrop(info: DropInfo) -> Bool {
        if case .device(let id) = arrange.dragging, case .collection(let c) = target {
            withAnimation(.smooth) { _ = model.arrange(.into(device: id, collection: c)) }
        }
        arrange.dragging = nil
        return true
    }
}

/// A collection as a tile: up to four of its devices' icons, its name and
/// how many are online, with a mark when one of them needs attention.
struct CollectionTile: View {
    let collection: Arrangement.Collection
    let devices: [Control.Device]
    @Environment(\.palette) private var palette

    private var online: Int { devices.filter(\.online).count }
    private var attention: Bool { devices.contains(where: \.frozen) }

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            HStack(alignment: .top) {
                Grid(horizontalSpacing: 4, verticalSpacing: 4) {
                    ForEach(0..<2, id: \.self) { row in
                        GridRow {
                            ForEach(0..<2, id: \.self) { col in
                                let i = row * 2 + col
                                if i < devices.count {
                                    DeviceIcon(device: devices[i], size: 20)
                                } else {
                                    Color.clear.frame(width: 20, height: 20)
                                }
                            }
                        }
                    }
                }
                Spacer()
                if attention { AttentionMark() }
            }
            Text(verbatim: collection.name).font(.system(.headline, design: .monospaced)).lineLimit(2)
            Group {
                if devices.isEmpty {
                    Text("Drag devices here")
                } else {
                    Text("\(online) of \(devices.count) online")
                }
            }
            .font(.caption)
            .foregroundStyle(palette.textDim)
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassTile()
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: collection.name))
        .accessibilityValue(attention ? Text("collection, \(online) of \(devices.count) online, needs attention")
                                      : Text("collection, \(online) of \(devices.count) online"))
    }
}

/// The danger colour's mark on a collection with a device that needs
/// attention.
struct AttentionMark: View {
    @Environment(\.palette) private var palette

    var body: some View {
        Image(systemName: "exclamationmark.circle.fill")
            .foregroundStyle(palette.danger)
            .accessibilityHidden(true)
    }
}

/// A collection in the list: a header with its name and how many are
/// online, then its devices.
struct CollectionSection: View {
    let collection: Arrangement.Collection
    let devices: [Control.Device]
    let level: [Arrangement.Ref]
    let selected: String?
    let select: (String) -> Void
    @Environment(\.palette) private var palette

    var body: some View {
        let refs = devices.map { Arrangement.Ref.device($0.id) }
        VStack(spacing: 0) {
            ArrangedTile(ref: .collection(collection.id), level: level, select: select) {
                HStack(spacing: Tokens.spacingSmall) {
                    Image(systemName: "folder").foregroundStyle(palette.textDim).accessibilityHidden(true)
                    Text(verbatim: collection.name).font(.system(.body, design: .monospaced).weight(.semibold))
                    if devices.contains(where: \.frozen) { AttentionMark() }
                    Spacer()
                    Text("\(devices.filter(\.online).count) of \(devices.count) online").font(.caption).foregroundStyle(palette.textDim)
                }
                .padding(.horizontal, Tokens.spacingMedium)
                .frame(minHeight: 44)
                .contentShape(Rectangle())
            }
            ForEach(devices) { d in
                Divider().overlay(palette.line)
                ArrangedTile(ref: .device(d.id), level: refs, select: select) { DeviceRow(device: d, selected: d.id == selected) }
                    .padding(.leading, Tokens.spacingLarge)
            }
        }
    }
}

/// A collection's own page: its devices in their order, its menu, and
/// Arrange mode for them.
struct CollectionPage: View {
    let id: String
    let layout: DeviceLayout
    let selected: String?
    let select: (String) -> Void
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
        ScrollView {
            if let found = model.collection(id) {
                let (c, devices) = found
                let refs = devices.map { Arrangement.Ref.device($0.id) }
                VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                    HStack(spacing: Tokens.spacingMedium) {
                        Button { close() } label: { Image(systemName: "chevron.left").accessibilityLabel(Text("Back")) }
                        Text(verbatim: c.name).font(.title3.weight(.semibold))
                        Spacer()
                        Menu {
                            Button { arrange.on.toggle() } label: { arrange.on ? Text("Done") : Text("Arrange") }
                            Button { arrange.ask(.rename(id), name: c.name) } label: { Text("Rename collection…") }
                            Button { model.arrange(.ungroup(collection: id)) } label: { Text("Ungroup") }
                        } label: { Image(systemName: "ellipsis.circle").accessibilityLabel(Text("Menu")) }
                        .fixedSize()
                    }
                    if arrange.on { ArrangeBar() }
                    if devices.isEmpty {
                        Text("Drag devices here, or add them with Move to collection in a device's menu.").foregroundStyle(palette.textDim)
                    } else if layout == .list {
                        VStack(spacing: 0) {
                            ForEach(Array(devices.enumerated()), id: \.element.id) { i, d in
                                if i > 0 { Divider().overlay(palette.line) }
                                ArrangedTile(ref: .device(d.id), level: refs, select: select) { DeviceRow(device: d, selected: d.id == selected) }
                            }
                        }
                        .glassTile(cornerRadius: Tokens.radiusCard)
                    } else {
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                            ForEach(devices) { d in
                                ArrangedTile(ref: .device(d.id), level: refs, select: select) { DeviceTile(device: d, selected: d.id == selected) }
                            }
                        }
                    }
                }
            }
        }
        // A collection that a move emptied goes away, and so does its page.
        .onChange(of: model.collection(id) == nil) { _, gone in if gone { close() } }
    }

    private func close() {
        arrange.on = false
        arrange.opened = nil
    }
}

/// Arrange mode's line at the top, with Done.
struct ArrangeBar: View {
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingSmall) {
            Text("Drag to arrange. Drop a device on a collection to put it in. Option and the arrow keys move the focused tile.")
                .font(.footnote)
                .foregroundStyle(palette.textDim)
            Spacer()
            Button { arrange.on = false } label: { Text("Done").bold() }
        }
        .padding(Tokens.spacingMedium)
        .glassCard()
    }
}

/// The name prompts of Arrange mode: a new collection, or another name for
/// one.
struct ArrangePrompts: ViewModifier {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var arrange: ArrangeState

    func body(content: Content) -> some View {
        content.alert(title, isPresented: Binding(get: { arrange.prompt != nil }, set: { if !$0 { arrange.prompt = nil } })) {
            TextField(text: $arrange.name) { Text("Collection name") }
            Button { save() } label: { Text("Save") }
            Button(role: .cancel) { arrange.prompt = nil } label: { Text("Cancel") }
        }
    }

    private var title: Text {
        if case .rename = arrange.prompt { return Text("Rename collection") }
        return Text("New collection")
    }

    private func save() {
        switch arrange.prompt {
        case .new(let ids): model.arrange(.new(name: arrange.name, devices: ids))
        case .rename(let id): model.arrange(.rename(collection: id, name: arrange.name))
        case nil: break
        }
        arrange.prompt = nil
    }
}

/// The filters of a long list of devices.
enum DeviceFilter {
    case online, attention
}

/// The search field and the two filters: Online and Needs attention; a
/// second click turns one off.
struct DeviceSearchBar: View {
    @Binding var query: String
    @Binding var filter: DeviceFilter?
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingSmall) {
            TextField(text: $query) { Text("Search devices") }
                .textFieldStyle(.roundedBorder)
            chip(.online) { Text("Online") }
            chip(.attention) { Text("Needs attention") }
        }
    }

    private func chip(_ f: DeviceFilter, @ViewBuilder label: () -> Text) -> some View {
        Button { filter = filter == f ? nil : f } label: {
            label()
                .font(.footnote)
                .padding(.horizontal, 12)
                .padding(.vertical, 4)
                .background(filter == f ? palette.soft : palette.line, in: Capsule())
                .foregroundStyle(filter == f ? palette.accent : palette.text)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(filter == f ? .isSelected : [])
    }
}
