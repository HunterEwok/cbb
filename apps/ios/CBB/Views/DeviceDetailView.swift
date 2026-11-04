// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI

/// One device: a summary of what it is and where it stands, then what an
/// admin phone may do with it (docs/apps.md, Devices). A page of its own on
/// a phone; on a big screen a pane beside the devices, which close hides.
struct DeviceDetailView: View {
    let id: AppModel.Computer.ID
    var close: (() -> Void)?
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.dismiss) private var dismiss
    @State private var removing = false
    @State private var promoting = false
    @State private var thawing = false
    @State private var renaming = false
    @State private var newName = ""
    @State private var pasting = false
    @State private var confirmingAction: String?
    @State private var turningOff = false
    @State private var hubbing = false

    private var device: AppModel.Computer? { model.devices.first { $0.id == id } }

    var body: some View {
        ScrollView {
            if let d = device {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    header(d)
                    summary(d)
                    actions(d)
                    if let message = model.message {
                        Text(message).foregroundStyle(palette.textDim)
                    }
                }
                .padding(Tokens.spacingLarge)
            }
        }
        .background(AppBackground())
        .modifier(PageTitle(title: close == nil ? device?.name : nil))
        .onChange(of: device == nil) { _, gone in
            // Removed here or by another admin: back to the devices.
            if gone {
                if let close { close() } else { dismiss() }
            }
        }
        .confirmationDialog(Text("Remove \(device?.name ?? "")?"), isPresented: $removing, titleVisibility: .visible) {
            Button(role: .destructive) {
                Task { await model.remove(id) }
            } label: { Text("Remove") }
        } message: {
            if device?.isRoot == true {
                Text("It made the group. This phone takes the group over with a new key, and the other devices follow it.")
            } else {
                Text("It will no longer sync with your devices. To add it again, scan its QR code again.")
            }
        }
        .confirmationDialog(Text("Make \(device?.name ?? "") an admin?"), isPresented: $promoting, titleVisibility: .visible) {
            Button {
                Task { await model.makeAdmin(id) }
            } label: { Text("Make it an admin") }
        } message: {
            if device?.keysInFile != false, model.keyLevel != Records.levelFiles {
                Text("It can then add and remove devices with cbb pair and cbb remove. Its keys sit in a file on the computer: whoever copies that file can act as an admin until another admin removes it. Do this only for a computer you keep safe.")
                    + Text(verbatim: " ")
                    + Text("The group then lets keys in files be admins and hubs (Settings, Admin keys).")
            } else if device?.keysInFile != false {
                Text("It can then add and remove devices with cbb pair and cbb remove. Its keys sit in a file on the computer: whoever copies that file can act as an admin until another admin removes it. Do this only for a computer you keep safe.")
            } else {
                Text("It can then add and remove devices with cbb pair and cbb remove. Its keys are in its hardware, which never lets them out.")
            }
        }
        .confirmationDialog(Text("Make \(device?.name ?? "") a hub?"), isPresented: $hubbing, titleVisibility: .visible) {
            Button {
                Task { await model.makeHub(id) }
            } label: { Text("Make it a hub") }
        } message: {
            Text("Your devices then reach the group through it when they are away from home, through the project's forwarder at cbb.tools. Sync away from home must be on there already; only its own user turns it on.")
        }
        .alert(Text("Rename \(device?.name ?? "")"), isPresented: $renaming) {
            TextField(text: $newName) { Text("Name") }
            Button {
                Task { await model.rename(id, to: newName) }
            } label: { Text("Rename") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("Every device of the group shows the new name.")
        }
        .sheet(isPresented: $pasting) {
            if let d = device { PasteView(device: d) }
        }
        .confirmationDialog(Text("\(confirmingAction.map(Self.actionName) ?? "") \(device?.name ?? "")?"),
                            isPresented: Binding { confirmingAction != nil } set: { if !$0 { confirmingAction = nil } },
                            titleVisibility: .visible, presenting: confirmingAction) { name in
            Button(role: .destructive) {
                Task { await model.runAction(id, name: name) }
            } label: { Text(verbatim: Self.actionName(name)) }
        } message: { _ in
            Text("It happens a minute from now; until then, Cancel the reboot or shutdown stops it.")
        }
        .confirmationDialog(Text("Turn off the quick actions on \(device?.name ?? "")?"), isPresented: $turningOff, titleVisibility: .visible) {
            Button(role: .destructive) {
                Task { await model.actionsOff(id) }
            } label: { Text("Turn all off") }
        } message: {
            Text("No admin can run them there until its user turns them on again on the device itself.")
        }
        .confirmationDialog(Text("Unfreeze \(device?.name ?? "")?"), isPresented: $thawing, titleVisibility: .visible) {
            Button {
                Task { await model.unfreeze(id) }
            } label: { Text("Unfreeze") }
        } message: {
            Text("Another admin froze this computer, as one does with a stolen one: it changes nothing and the others refuse it. Unfreeze it only if it is in safe hands; otherwise remove it.")
        }
    }

    private func header(_ d: AppModel.Computer) -> some View {
        HStack(alignment: .top, spacing: Tokens.spacingMedium) {
            DeviceIcon(device: d, size: 64)
            VStack(alignment: .leading, spacing: 4) {
                Text(d.name).font(.system(.title2, design: .monospaced).weight(.bold)).lineLimit(2)
                HStack(spacing: 6) {
                    OnlineDot(online: d.online)
                    (d.online ? Text("online") : Text("offline"))
                        .foregroundStyle(d.online ? palette.accent : palette.textDim)
                }
                .font(.subheadline)
            }
            .accessibilityElement(children: .combine)
            Spacer()
            if let close {
                Button(action: close) {
                    Image(systemName: "xmark").font(.body.weight(.semibold)).foregroundStyle(palette.text).glassCircle()
                }
                .accessibilityLabel(Text("Close"))
                // Escape on an iPad's keyboard closes the pane.
                .keyboardShortcut(.cancelAction)
            }
        }
    }

    /// What the group knows of it, a row each.
    private func summary(_ d: AppModel.Computer) -> some View {
        VStack(spacing: 0) {
            row(Text("Type"), Text(d.kind.title))
            if let system = d.systemWithVersion {
                Divider().overlay(palette.line)
                row(Text("Operating system"), Text(verbatim: system))
            }
            if let version = d.device?.version {
                Divider().overlay(palette.line)
                row(Text("CBB"), Text(verbatim: version).monospaced())
            }
            if let mac = d.device?.mac {
                Divider().overlay(palette.line)
                row(Text("MAC address"), Text(verbatim: mac).monospaced())
            } else if d.kind == .phone || d.kind == .tablet {
                Divider().overlay(palette.line)
                row(Text("MAC address"), Text("hidden by the system").foregroundStyle(palette.textDim))
            }
            Divider().overlay(palette.line)
            row(Text("Role"), roleText(d))
            if let standing = d.standing {
                Divider().overlay(palette.line)
                row(Text("In the group"), Text(standing))
            }
            if let mark = model.hubMark(d) {
                Divider().overlay(palette.line)
                row(Text("Away from home"), mark == .inUse ? Text("The group's hub, in use now") : Text("The group's hub"))
            }
            if let mode = d.mode.flatMap(SyncMode.init(rawValue:)) {
                Divider().overlay(palette.line)
                row(Text("Sync mode"), Text(mode.title))
            }
        }
        .glassTile(cornerRadius: Tokens.radiusCard)
    }

    private func row(_ label: Text, _ value: Text) -> some View {
        HStack {
            label.foregroundStyle(palette.textDim)
            Spacer()
            value.multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, Tokens.spacingMedium)
        .frame(minHeight: 44)
        .accessibilityElement(children: .combine)
    }

    private func roleText(_ d: AppModel.Computer) -> Text {
        switch d.role {
        case "phone": Text("Phone app")
        case "lite": d.rootless ? Text("Lite member, rootless") : Text("Lite member")
        case "watch": Text("Watch")
        // A rootless install is never an admin or a hub (D-79).
        default: d.rootless ? Text("Full member, rootless") : Text("Full member")
        }
    }

    /// The actions an admin phone has for it; a phone that is no admin has
    /// only its own sync mode.
    @ViewBuilder private func actions(_ d: AppModel.Computer) -> some View {
        if !model.isAdmin, d.isSelf {
            modeMenu(d).glassTile(cornerRadius: Tokens.radiusCard)
        } else if model.isAdmin {
            VStack(spacing: 0) {
                action(Text("Rename"), "pencil") {
                    newName = d.name
                    renaming = true
                }
                if d.frozen {
                    Divider().overlay(palette.line)
                    action(Text("Unfreeze"), "snowflake") { thawing = true }
                }
                if d.canMakeAdmin {
                    Divider().overlay(palette.line)
                    action(Text("Make it an admin"), "person.badge.key") { promoting = true }
                }
                // An admin computer, or one the root makes an admin first;
                // this phone is the hub under Settings.
                if !d.isSelf, d.online, d.role == "full", !d.frozen, !d.rootless, d.mayHub || d.canMakeAdmin {
                    Divider().overlay(palette.line)
                    action(Text("Make it a hub"), "antenna.radiowaves.left.and.right") { hubbing = true }
                }
                if d.isSelf || d.online {
                    Divider().overlay(palette.line)
                    modeMenu(d)
                }
                // Computers, lite members and Android phones take pastes; iPhones cannot.
                if !d.isSelf, d.role == "full" || d.role == "lite" || (d.role == "phone" && d.os == "android") {
                    Divider().overlay(palette.line)
                    action(Text("Paste on it…"), "keyboard") { pasting = true }
                }
                // Computers run quick actions; the lite member reboots and restarts.
                if !d.isSelf, d.online, d.role == "full" || d.role == "lite" {
                    Divider().overlay(palette.line)
                    actionMenu(d)
                }
                if !d.isSelf {
                    Divider().overlay(palette.line)
                    action(Text("Remove"), "trash", destructive: true) { removing = true }
                }
            }
            .glassTile(cornerRadius: Tokens.radiusCard)
        } else {
            Text("Only an admin phone can add or remove devices.").font(.footnote).foregroundStyle(palette.textDim)
        }
    }

    /// The sync modes to pick from, with what each does, the device's own marked.
    private func modeMenu(_ d: AppModel.Computer) -> some View {
        Menu {
            ForEach(SyncMode.allCases) { mode in
                Button { Task { await model.setMode(id, to: mode.rawValue) } } label: {
                    if mode.rawValue == d.mode { Label { Text(mode.title) } icon: { Image(systemName: "checkmark") } } else { Text(mode.title) }
                    Text(mode.note)
                }
            }
        } label: {
            HStack(spacing: Tokens.spacingMedium) {
                Image(systemName: "arrow.left.arrow.right").frame(width: 24).accessibilityHidden(true)
                Text("Sync mode")
                Spacer()
            }
            .foregroundStyle(palette.accent)
            .padding(.horizontal, Tokens.spacingMedium)
            .frame(minHeight: 48)
            .contentShape(Rectangle())
        }
    }

    /// The quick actions a device's hello says are on (docs/protocol.md,
    /// section 15): one runs at a tap, reboot and shut down ask again. The
    /// device defines each; its user turns them on there, and any admin
    /// turns them all off from here.
    private func actionMenu(_ d: AppModel.Computer) -> some View {
        Menu {
            Section {
                ForEach(d.actions, id: \.self) { name in
                    Button {
                        if name == "reboot" || name == "shutdown" {
                            confirmingAction = name
                        } else {
                            Task { await model.runAction(id, name: name) }
                        }
                    } label: { Text(verbatim: Self.actionName(name)) }
                }
            } header: {
                if d.actions.isEmpty {
                    Text("\(d.name) has no quick action turned on. Its user turns them on there, with sudo cbb action enable.")
                } else {
                    Text("The computer defines what each action does, and runs it only for the admins its user allowed.")
                }
            }
            Button(role: .destructive) { turningOff = true } label: { Text("Turn all off") }
        } label: {
            HStack(spacing: Tokens.spacingMedium) {
                Image(systemName: "bolt").frame(width: 24).accessibilityHidden(true)
                Text("Quick actions")
                Spacer()
            }
            .foregroundStyle(palette.accent)
            .padding(.horizontal, Tokens.spacingMedium)
            .frame(minHeight: 48)
            .contentShape(Rectangle())
        }
    }

    /// The title of a quick action: the presets in words, the user's own by
    /// name.
    static func actionName(_ name: String) -> String {
        switch name {
        case "lock": String(localized: "Lock the screen", bundle: .app)
        case "sleep": String(localized: "Sleep", bundle: .app)
        case "reboot": String(localized: "Reboot", bundle: .app)
        case "shutdown": String(localized: "Shut down", bundle: .app)
        case "cancel-shutdown": String(localized: "Cancel the reboot or shutdown", bundle: .app)
        case "restart": String(localized: "Restart CBB", bundle: .app)
        case "keyboard-layout": String(localized: "Switch the keyboard's layout", bundle: .app)
        default: name
        }
    }

    private func action(_ title: Text, _ symbol: String, destructive: Bool = false, perform: @escaping () -> Void) -> some View {
        Button(action: perform) {
            HStack(spacing: Tokens.spacingMedium) {
                Image(systemName: symbol).frame(width: 24).accessibilityHidden(true)
                title
                Spacer()
            }
            .foregroundStyle(destructive ? palette.danger : palette.accent)
            .padding(.horizontal, Tokens.spacingMedium)
            .frame(minHeight: 48)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// The page's title on a phone; none in a pane, which leaves the page's.
private struct PageTitle: ViewModifier {
    let title: String?

    @ViewBuilder func body(content: Self.Content) -> some View {
        if let title {
            content.navigationTitle(Text(verbatim: title)).navigationBarTitleDisplayMode(.inline)
        } else {
            content
        }
    }
}
