// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI

/// One device's card: its name, badges and one line of what it is, the
/// house (its sync), a row of icons (paste on it, mute, quick actions), the
/// rest under More, and the menu of what an admin phone may do with it
/// (docs/apps.md, Devices). A page of its own on
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
    @AppStorage("AdvancedSettings") private var advanced = false
    @State private var hubbing = false
    @State private var more = false

    private var device: AppModel.Computer? { model.devices.first { $0.id == id } }

    var body: some View {
        ScrollView {
            if let d = device {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    header(d)
                    syncCard(d)
                    iconRow(d)
                    DisclosureGroup(isExpanded: $more) { summary(d).padding(.top, Tokens.spacingSmall) } label: { Text("More") }
                        .tint(palette.text)
                    if !model.isAdmin {
                        Text("Only an admin phone can add or remove devices.").font(.footnote).foregroundStyle(palette.textDim)
                    }
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
            if device?.role == "phone" {
                Text("It can then add and remove devices, and take the group over if this phone is lost.")
            } else if device?.keysInFile != false, model.keyLevel != Records.levelFiles {
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
            // A hub that reads the copies is an admin, whose keys the
            // group's key level checks; one that only passes them on is no
            // admin and needs no such keys.
            if let d = device, d.admin || d.canMakeAdmin {
                Button {
                    Task { await model.makeHub(id) }
                } label: { Text("A hub that reads the copies") }
            }
            if let d = device, !d.admin, !d.isRoot {
                Button {
                    Task { await model.makeHub(id, forwardOnly: true) }
                } label: { Text("A hub that only passes them on") }
            }
        } message: {
            Text("Your devices then reach the group through it when they are away from home, through the project's forwarder at cbb.tools. Sync away from home must be on there already; only its own user turns it on.")
                + Text(verbatim: " ")
                + Text("A hub that reads the copies is an admin. A hub that only passes them on cannot read them: they are sealed to your other devices only, so its keys need no hardware.")
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

    /// The name, badges and line, with the admin's menu; in a pane the
    /// menu and the cross stand on a row of their own above, so that the
    /// name has the pane's width.
    private func header(_ d: AppModel.Computer) -> some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            if let close {
                HStack(spacing: Tokens.spacingSmall) {
                    Spacer()
                    if model.isAdmin { menu(d) }
                    Button(action: close) {
                        Image(systemName: "xmark").font(.body.weight(.semibold)).foregroundStyle(palette.text).glassCircle()
                    }
                    .accessibilityLabel(Text("Close"))
                    .accessibilityIdentifier("padCardClose")
                    // Escape on an iPad's keyboard closes the pane.
                    .keyboardShortcut(.cancelAction)
                }
            }
            title(d)
        }
    }

    private func title(_ d: AppModel.Computer) -> some View {
        HStack(alignment: .top, spacing: Tokens.spacingMedium) {
            DeviceIcon(device: d, size: 64)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(d.name).font(.system(.title2, design: .monospaced).weight(.bold)).lineLimit(2)
                    OnlineDot(online: d.online)
                }
                (d.throughHub ? Text("online through the hub") : d.online ? Text("online") : Text("offline"))
                    .font(.subheadline)
                    .foregroundStyle(d.online ? palette.accent : palette.textDim)
                let badges = Self.badges(d, hub: model.hubMark(d) != nil)
                if !badges.isEmpty {
                    HStack(spacing: 4) {
                        ForEach(badges, id: \.self) { b in
                            Text(verbatim: b).font(.caption.weight(.medium))
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(palette.soft, in: Capsule())
                        }
                    }
                }
                let line = [d.systemWithVersion, d.device?.version.map { "CBB " + $0 }].compactMap { $0 }.joined(separator: " · ")
                if !line.isEmpty {
                    Text(verbatim: line).font(.caption).foregroundStyle(palette.textDim)
                }
            }
            .accessibilityElement(children: .combine)
            .layoutPriority(1)
            Spacer()
            if close == nil, model.isAdmin { menu(d) }
        }
    }

    /// Its badges: this phone, root or admin, hub, frozen.
    static func badges(_ d: AppModel.Computer, hub: Bool) -> [String] {
        var out: [String] = []
        if d.isSelf { out.append(String(localized: "This phone", bundle: .app)) }
        if d.isRoot { out.append(String(localized: "root", bundle: .app)) } else if d.admin { out.append(String(localized: "admin", bundle: .app)) }
        if hub { out.append(String(localized: "hub", bundle: .app)) }
        if d.frozen { out.append(String(localized: "frozen", bundle: .app)) }
        return out
    }

    /// The house: this phone's own sync, or, on an admin, a connected
    /// member's; the phones turn theirs on themselves.
    @ViewBuilder private func syncCard(_ d: AppModel.Computer) -> some View {
        if d.isSelf || d.mode != nil {
            let on = d.isSelf ? model.syncOff == nil : d.mode != "own"
            let mayTurn = d.isSelf || (model.isAdmin && d.online && d.role == "member")
            Toggle(isOn: Binding(get: { on }, set: { new in
                if d.isSelf { model.turnSync(new) } else { Task { await model.setSync(id, on: new) } }
            })) {
                Label { Text("Sync") } icon: { Image(systemName: on ? "house.fill" : "house") }
            }
            .tint(palette.accent)
            .disabled(!mayTurn || model.busy)
            .padding(Tokens.spacingMedium)
            .glassTile(cornerRadius: Tokens.radiusCard)
        }
    }

    /// The row of icons an admin has for it: paste on it, mute, quick
    /// actions.
    @ViewBuilder private func iconRow(_ d: AppModel.Computer) -> some View {
        if model.isAdmin {
            HStack(spacing: Tokens.spacingSmall) {
                if d.takesPaste {
                    Button { pasting = true } label: { IconLabel(symbol: "keyboard", title: Text("Paste")) }
                        .buttonStyle(.plain)
                }
                muteIcon(d)
                // Members run quick actions.
                if !d.isSelf, d.online, d.role == "member" {
                    actionMenu(d)
                }
            }
            .foregroundStyle(palette.accent)
        }
    }

    /// The menu of what an admin phone may do with it: rename, unfreeze,
    /// make it an admin or a hub, remove.
    private func menu(_ d: AppModel.Computer) -> some View {
        Menu {
            Button { newName = d.name; renaming = true } label: { Label { Text("Rename") } icon: { Image(systemName: "pencil") } }
            if d.frozen {
                Button { thawing = true } label: { Label { Text("Unfreeze") } icon: { Image(systemName: "snowflake") } }
            }
            if d.canMakeAdmin {
                Button { promoting = true } label: { Label { Text("Make it an admin") } icon: { Image(systemName: "person.badge.key") } }
            }
            // An admin member that may be a hub, or one the root makes an admin
            // first; this phone is the hub under Settings. A member that is no
            // admin can be a hub that only passes the copies on. The hub is
            // chosen by itself: making one is in the advanced settings.
            if advanced, !d.isSelf, d.online, !d.throughHub, d.can("hub"), !d.frozen, !d.rootless, d.mayHub || d.canMakeAdmin || !d.admin {
                Button { hubbing = true } label: { Label { Text("Make it a hub") } icon: { Image(systemName: "antenna.radiowaves.left.and.right") } }
            }
            if !d.isSelf {
                Button(role: .destructive) { removing = true } label: { Label { Text("Remove") } icon: { Image(systemName: "trash") } }
            }
        } label: {
            Image(systemName: "ellipsis").font(.body.weight(.semibold)).foregroundStyle(palette.text).glassCircle()
        }
        .accessibilityLabel(Text("Menu"))
    }

    /// What the group knows of it, a row each.
    private func summary(_ d: AppModel.Computer) -> some View {
        VStack(spacing: 0) {
            row(Text("Type"), Text(d.kind.title))
            if let mac = d.device?.mac {
                Divider().overlay(palette.line)
                row(Text("MAC address"), Text(verbatim: mac).monospaced())
            } else if d.kind == .phone || d.kind == .tablet {
                Divider().overlay(palette.line)
                row(Text("MAC address"), Text("hidden by the system").foregroundStyle(palette.textDim))
            }
            Divider().overlay(palette.line)
            row(Text("Role"), roleText(d))
            if d.forwardOnly {
                Divider().overlay(palette.line)
                row(Text("Copies"), Text("Passes them on, reads none"))
            }
            if let m = d.muted {
                Divider().overlay(palette.line)
                row(Text("Copies"), m.until.map { Text("Muted until \($0.formatted(date: .abbreviated, time: .shortened))") } ?? Text("Muted until an admin unmutes it"))
            }
            if let standing = d.standing {
                Divider().overlay(palette.line)
                row(Text("In the group"), Text(standing))
            }
            if let mark = model.hubMark(d) {
                Divider().overlay(palette.line)
                row(Text("Away from home"), mark == .inUse ? Text("The group's hub, in use now") : Text("The group's hub"))
            }
            Divider().overlay(palette.line)
            row(Text("Device ID"), Text(verbatim: d.id).monospaced())
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
        case "watch": Text("Watch")
        // A rootless install is never an admin or a hub (D-79).
        default: d.rootless ? Text("Member, rootless") : Text("Member")
        }
    }

    /// An admin mutes any device for the whole group, for a time or until
    /// an admin unmutes it, or ends its mute (docs/design.md, "Muting a
    /// device"): its copies then reach no device of the group, and it still
    /// takes theirs.
    @ViewBuilder private func muteIcon(_ d: AppModel.Computer) -> some View {
        if d.muted != nil {
            Button { Task { await model.setMuted(id, false) } } label: { IconLabel(symbol: "speaker.wave.2", title: Text("Unmute")) }
                .buttonStyle(.plain)
        } else if d.isSelf || d.online {
            Menu {
                Section {
                    ForEach(PauseTime.allCases) { t in
                        Button { Task { await model.setMuted(id, true, forMS: t.ms) } } label: {
                            t == .ever ? Text("Until an admin unmutes it") : Text(t.title)
                        }
                    }
                } header: {
                    Text("Its copies then reach no device of the group; it still takes theirs.")
                }
            } label: {
                IconLabel(symbol: "speaker.slash", title: Text("Mute"))
            }
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
            IconLabel(symbol: "bolt", title: Text("Quick actions"))
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
}

/// An icon over its name, a button of the card's row.
private struct IconLabel: View {
    let symbol: String
    let title: Text

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: symbol).font(.title3).accessibilityHidden(true)
            title.font(.caption).lineLimit(2).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 64)
        .padding(.vertical, Tokens.spacingSmall)
        .glassTile(cornerRadius: Tokens.radiusCard)
        .contentShape(Rectangle())
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
