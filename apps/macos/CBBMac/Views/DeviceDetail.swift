// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// One device beside the devices: a summary of what it is and where it
/// stands, then what an admin Mac may do with it, each asking for the
/// administrator's password (docs/apps.md, The Mac app).
struct DeviceDetail: View {
    let id: String
    let close: () -> Void
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette
    @State private var removing = false
    @State private var promoting = false
    @State private var freezing = false
    @State private var thawing = false
    @State private var renaming = false
    @State private var newName = ""

    private var device: Control.Device? { model.devices.first { $0.id == id } }

    var body: some View {
        ScrollView {
            if let d = device {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    header(d)
                    summary(d)
                    actions(d)
                }
                .padding(Tokens.spacingLarge)
            }
        }
        .background(palette.glass.opacity(0.6))
        .onChange(of: device == nil) { _, gone in
            // Removed here or by another admin.
            if gone { close() }
        }
        .confirmationDialog(Text("Remove \(device?.name ?? "")?"), isPresented: $removing) {
            Button(role: .destructive) { Task { await model.remove(id) } } label: { Text("Remove") }
        } message: {
            Text("It will no longer sync with your devices. To add it again, pair it again.")
        }
        .confirmationDialog(Text("Make \(device?.name ?? "") an admin?"), isPresented: $promoting) {
            Button { Task { await model.makeAdmin(id) } } label: { Text("Make it an admin") }
        } message: {
            Text("It can then add and remove devices with cbb pair and cbb remove. Its key is a file on the computer, so do this only for a computer you keep safe.")
        }
        .confirmationDialog(Text("Freeze \(device?.name ?? "")?"), isPresented: $freezing) {
            Button(role: .destructive) { Task { await model.freeze(id) } } label: { Text("Freeze") }
        } message: {
            Text("For a stolen admin computer: it changes nothing more and the others refuse it until the root unfreezes or removes it.")
        }
        .confirmationDialog(Text("Unfreeze \(device?.name ?? "")?"), isPresented: $thawing) {
            Button { Task { await model.unfreeze(id) } } label: { Text("Unfreeze") }
        } message: {
            Text("Unfreeze it only if it is in safe hands; otherwise remove it.")
        }
        .alert(Text("Rename \(device?.name ?? "")"), isPresented: $renaming) {
            TextField(text: $newName) { Text("Name") }
            Button { Task { await model.rename(id, to: newName) } } label: { Text("Rename") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("Every device of the group shows the new name.")
        }
    }

    private func header(_ d: Control.Device) -> some View {
        HStack(alignment: .top, spacing: Tokens.spacingMedium) {
            DeviceIcon(device: d, size: 56)
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: d.name).font(.system(.title2, design: .monospaced).weight(.bold)).lineLimit(2)
                HStack(spacing: 6) {
                    OnlineDot(online: d.online)
                    (d.online ? Text("online") : Text("offline")).foregroundStyle(d.online ? palette.accent : palette.textDim)
                }
                .font(.subheadline)
            }
            .accessibilityElement(children: .combine)
            Spacer()
            Button(action: close) { Image(systemName: "xmark").font(.body.weight(.semibold)) }
                .buttonStyle(.borderless)
                .keyboardShortcut(.cancelAction)
                .accessibilityLabel(Text("Close"))
        }
    }

    /// What the group knows of it, a row each.
    private func summary(_ d: Control.Device) -> some View {
        VStack(spacing: 0) {
            row(Text("Type"), Text(d.kind.title))
            if let system = d.systemWithVersion {
                line
                row(Text("Operating system"), Text(verbatim: system))
            }
            if let version = d.version {
                line
                row(Text("CBB"), Text(verbatim: version).monospaced())
            }
            if let mac = d.mac {
                line
                row(Text("MAC address"), Text(verbatim: mac).monospaced())
            } else if d.kind == .phone || d.kind == .tablet {
                line
                row(Text("MAC address"), Text("hidden by the system").foregroundStyle(palette.textDim))
            }
            line
            row(Text("Role"), Text(d.roleTitle))
            if let standing = d.standing {
                line
                row(Text("In the group"), Text(standing))
            }
            if let mode = d.mode.flatMap(SyncMode.init(rawValue:)) {
                line
                row(Text("Sync mode"), Text(mode.title))
            }
            if !d.online, d.lastSeenMS > 0 {
                line
                row(Text("Last seen"), Text(Date(timeIntervalSince1970: Double(d.lastSeenMS) / 1000), style: .relative))
            }
            line
            row(Text("Device ID"), Text(verbatim: d.id).monospaced())
        }
        .glassTile(cornerRadius: Tokens.radiusCard)
    }

    private var line: some View { Divider().overlay(palette.line) }

    private func row(_ label: Text, _ value: Text) -> some View {
        HStack {
            label.foregroundStyle(palette.textDim)
            Spacer()
            value.multilineTextAlignment(.trailing).lineLimit(2)
        }
        .padding(.horizontal, Tokens.spacingMedium)
        .frame(minHeight: 36)
        .accessibilityElement(children: .combine)
    }

    /// What this Mac may do with it: nothing unless it is an admin.
    @ViewBuilder private func actions(_ d: Control.Device) -> some View {
        if !model.isAdmin {
            Text("This Mac is no admin of the group: the phone or an admin computer adds and removes devices.")
                .font(.footnote).foregroundStyle(palette.textDim)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                action("pencil", "Rename") {
                    newName = d.name
                    renaming = true
                }
                if d.frozen, model.isRoot {
                    line
                    action("snowflake", "Unfreeze") { thawing = true }
                }
                if !d.isSelf, d.admin, !d.root, !d.frozen, d.role == "full" {
                    line
                    action("snowflake", "Freeze", danger: true) { freezing = true }
                }
                if model.isRoot, !d.admin, !d.frozen, d.role == "full" {
                    line
                    action("star", "Make it an admin") { promoting = true }
                }
                // The phones and lite members have no modes yet and refuse.
                if !d.isSelf, d.online, d.role == "full" {
                    line
                    Menu {
                        ForEach(SyncMode.allCases) { mode in
                            Button { Task { await model.setMode(mode, on: d.id) } } label: { Text(mode.title) }
                        }
                    } label: {
                        Label { Text("Sync mode") } icon: { Image(systemName: "arrow.left.arrow.right") }
                            .foregroundStyle(palette.accent)
                    }
                    .menuStyle(.borderlessButton)
                    .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
                    .padding(.horizontal, Tokens.spacingMedium)
                }
                if !d.isSelf {
                    line
                    action("xmark.circle", "Remove", danger: true) { removing = true }
                }
            }
            .glassTile(cornerRadius: Tokens.radiusCard)
            .disabled(model.busy)
            if let message = model.message {
                Text(verbatim: message).font(.callout).foregroundStyle(palette.textDim).textSelection(.enabled)
            }
        }
    }

    private func action(_ symbol: String, _ title: LocalizedStringKey, danger: Bool = false, perform: @escaping () -> Void) -> some View {
        Button(action: perform) {
            Label(title, systemImage: symbol)
                .foregroundStyle(danger ? palette.danger : palette.accent)
                .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
                .padding(.horizontal, Tokens.spacingMedium)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
