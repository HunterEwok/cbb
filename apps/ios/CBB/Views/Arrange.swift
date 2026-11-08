// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI
import UniformTypeIdentifiers

/// Arrange mode and its prompts, shared by Home and the collections' pages
/// (docs/apps.md, "Collections and the order of the tiles").
@MainActor
final class ArrangeState: ObservableObject {
    /// Arrange mode: a tap does not open a tile, and tiles can be dragged.
    @Published var on = false
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

    /// The type of a dragged tile, which never leaves the app: other apps
    /// get nothing from it, and nothing from them drops on a tile.
    static let tileType = UTType(exportedAs: "tools.cbb.tile")

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

/// The page of a collection, as Home's navigation reaches it.
struct CollectionRoute: Hashable {
    let id: String
}

/// This phone first, then the devices and collections in the user's
/// order, as tiles or a list; in Arrange mode they can be dragged.
struct ArrangedDevices: View {
    let layout: DeviceLayout
    var select: ((AppModel.Computer.ID) -> Void)?
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
        content.sensoryFeedback(.selection, trigger: arrange.dragging)
    }

    @ViewBuilder private var content: some View {
        let items = model.arranged
        let refs = items.map(\.ref)
        if items.isEmpty {
            Text("No computers connected.").foregroundStyle(palette.textDim)
        } else if layout == .list {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                ForEach(items) { item in
                    switch item {
                    case .device(let d):
                        ArrangedTile(ref: item.ref, level: refs, select: select) { DeviceRow(device: d) }
                    case .collection(let c, let ds):
                        CollectionSection(collection: c, devices: ds, level: refs, select: select)
                    }
                }
            }
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                ForEach(items) { item in
                    switch item {
                    case .device(let d):
                        ArrangedTile(ref: item.ref, level: refs, select: select) { DeviceTile(device: d) }
                    case .collection(let c, let ds):
                        ArrangedTile(ref: item.ref, level: refs, select: select) { CollectionTile(collection: c, devices: ds) }
                    }
                }
            }
        }
    }
}

/// A device or a collection with its menu, its VoiceOver actions and, in
/// Arrange mode, its drag and drop; level is the order it moves in.
struct ArrangedTile<Content: View>: View {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    var select: ((AppModel.Computer.ID) -> Void)?
    @ViewBuilder let label: () -> Content
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
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
            } else {
                switch ref {
                case .device(let id):
                    if let d = model.devices.first(where: { $0.id == id }) {
                        DeviceCollection.open(d, select: select) { label() }
                    }
                case .collection(let id):
                    NavigationLink(value: CollectionRoute(id: id)) { label() }.buttonStyle(.plain)
                }
            }
        }
        .contextMenu { ArrangeMenu(ref: ref, level: level) }
        .modifier(ArrangeActions(ref: ref, level: level))
    }
}

/// The moves of a tile within its level, the same for the menu and for
/// VoiceOver.
@MainActor
struct Moves {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    let model: AppModel

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

/// A tile's menu on a long press: Arrange, and every change a drag makes.
struct ArrangeMenu: View {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState

    var body: some View {
        let moves = Moves(ref: ref, level: level, model: model)
        if !arrange.on {
            Button { arrange.on = true } label: {
                Label { Text("Arrange") } icon: { Image(systemName: "square.grid.3x3.square") }
            }
        }
        switch ref {
        case .device(let id):
            Menu {
                ForEach(model.collections(apartFrom: id), id: \.id) { c in
                    Button { model.arrange(.into(device: id, collection: c.id)) } label: { Text(verbatim: c.name) }
                }
                Button { arrange.ask(.new([id])) } label: { Text("New collection…") }
            } label: {
                Label { Text("Move to collection") } icon: { Image(systemName: "folder") }
            }
            if model.collection(holding: id) != nil {
                Button { model.arrange(.out(device: id)) } label: {
                    Label { Text("Take out of collection") } icon: { Image(systemName: "minus.circle") }
                }
            }
        case .collection(let id):
            Button { arrange.ask(.rename(id), name: model.collection(id)?.0.name ?? "") } label: {
                Label { Text("Rename collection…") } icon: { Image(systemName: "pencil") }
            }
            Button { model.arrange(.ungroup(collection: id)) } label: {
                Label { Text("Ungroup") } icon: { Image(systemName: "rectangle.3.group") }
            }
        }
        if moves.canMoveEarlier {
            Button { moves.toStart() } label: {
                Label { Text("Move to start") } icon: { Image(systemName: "arrow.up.to.line") }
            }
        }
        if moves.canMoveLater {
            Button { moves.toEnd() } label: {
                Label { Text("Move to end") } icon: { Image(systemName: "arrow.down.to.line") }
            }
        }
    }
}

/// The same changes as VoiceOver's actions, in Arrange mode.
struct ArrangeActions: ViewModifier {
    let ref: Arrangement.Ref
    let level: [Arrangement.Ref]
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState

    // Self.Content: the kit has a type Content of its own.
    @ViewBuilder func body(content: Self.Content) -> some View {
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
    let model: AppModel
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
    let devices: [AppModel.Computer]
    @Environment(\.palette) private var palette

    private var online: Int { devices.filter(\.online).count }
    private var attention: Bool { devices.contains(where: \.needsAttention) }

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
            Text(verbatim: collection.name)
                .font(.system(.headline, design: .monospaced))
                .lineLimit(2)
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
    let devices: [AppModel.Computer]
    let level: [Arrangement.Ref]
    var select: ((AppModel.Computer.ID) -> Void)?
    @Environment(\.palette) private var palette

    var body: some View {
        let refs = devices.map { Arrangement.Ref.device($0.id) }
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            ArrangedTile(ref: .collection(collection.id), level: level, select: select) {
                HStack(spacing: Tokens.spacingSmall) {
                    Image(systemName: "folder").foregroundStyle(palette.textDim).accessibilityHidden(true)
                    Text(verbatim: collection.name).font(.system(.subheadline, design: .monospaced).weight(.semibold))
                    if devices.contains(where: \.needsAttention) { AttentionMark() }
                    Spacer()
                    Text("\(devices.filter(\.online).count) of \(devices.count) online").font(.caption).foregroundStyle(palette.textDim)
                }
                .padding(.top, Tokens.spacingSmall)
                .contentShape(Rectangle())
            }
            ForEach(devices) { d in
                ArrangedTile(ref: .device(d.id), level: refs, select: select) { DeviceRow(device: d) }
                    .padding(.leading, Tokens.spacingMedium)
            }
        }
    }
}

/// A collection's own page: its devices in their order, its menu, and
/// Arrange mode for them.
struct CollectionPage: View {
    let id: String
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette
    @Environment(\.dismiss) private var dismiss
    @AppStorage(DeviceLayout.key) private var layout = DeviceLayout.tiles

    var body: some View {
        ScrollView {
            if let found = model.collection(id) {
                let (c, devices) = found
                let refs = devices.map { Arrangement.Ref.device($0.id) }
                VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                    if arrange.on { ArrangeBar() }
                    if devices.isEmpty {
                        Text("Drag devices here, or add them with Move to collection in a device's menu.").foregroundStyle(palette.textDim)
                    } else if layout == .list {
                        ForEach(devices) { d in
                            ArrangedTile(ref: .device(d.id), level: refs) { DeviceRow(device: d) }
                        }
                    } else {
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                            ForEach(devices) { d in
                                ArrangedTile(ref: .device(d.id), level: refs) { DeviceTile(device: d) }
                            }
                        }
                    }
                }
                .padding(Tokens.spacingLarge)
                .navigationTitle(Text(verbatim: c.name))
            }
        }
        .background(AppBackground())
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button { arrange.on.toggle() } label: {
                        Label { arrange.on ? Text("Done") : Text("Arrange") } icon: { Image(systemName: "square.grid.3x3.square") }
                    }
                    Button { arrange.ask(.rename(id), name: model.collection(id)?.0.name ?? "") } label: {
                        Label { Text("Rename collection…") } icon: { Image(systemName: "pencil") }
                    }
                    Button {
                        model.arrange(.ungroup(collection: id))
                        dismiss()
                    } label: {
                        Label { Text("Ungroup") } icon: { Image(systemName: "rectangle.3.group") }
                    }
                } label: {
                    Image(systemName: "ellipsis").accessibilityLabel(Text("Menu"))
                }
            }
        }
        // A collection that a move emptied goes away, and so does its page.
        .onChange(of: model.collection(id) == nil) { _, gone in if gone { dismiss() } }
    }
}

/// Arrange mode's line at the top, with Done.
struct ArrangeBar: View {
    @EnvironmentObject private var arrange: ArrangeState
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingSmall) {
            Text("Drag to arrange. Drop a device on a collection to put it in.")
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
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var arrange: ArrangeState

    func body(content: Self.Content) -> some View {
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
        case .new(let ids): _ = model.newCollection(arrange.name, devices: ids)
        case .rename(let id): _ = model.arrange(.rename(collection: id, name: arrange.name))
        case nil: break
        }
        arrange.prompt = nil
    }
}

extension AppModel.Computer {
    /// Whether it needs the user: an admin computer another admin froze.
    var needsAttention: Bool { frozen }
}
