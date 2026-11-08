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
    @State private var hubbing = false
    @State private var unhubbing = false
    @State private var leaving = false
    @State private var renaming = false
    @State private var newName = ""
    @State private var tunnelTo: MacModel.HubTunnel?
    @State private var changingForwarder = false
    @State private var forwarderAddress = ""
    @State private var forwarderKey = ""

    private var device: Control.Device? { model.devices.first { $0.id == id } }

    var body: some View {
        ScrollView {
            if let d = device {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    header(d)
                    summary(d)
                    actions(d)
                    hubSettings(d)
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
        .confirmationDialog(Text("Make \(device?.name ?? "") a hub?"), isPresented: $hubbing) {
            // A hub that reads the copies is an admin, whose keys the
            // group's key level checks; one that only passes them on is no
            // admin and needs no such keys.
            if let d = device, d.mayHub, !d.forwardOnly {
                Button { Task { await model.makeHub(d) } } label: { Text("A hub that reads the copies") }
            }
            if let d = device, mayPassOn(d) {
                Button { Task { await model.makeHub(d, forwardOnly: true) } } label: { Text("A hub that only passes them on") }
            }
        } message: {
            if device?.isSelf == true, !model.awayOn {
                Text("A hub needs sync away from home, which is off on this Mac, so this turns it on first. Your devices then reach the group through this Mac when they are away from home, through the project's forwarder at cbb.tools.")
            } else if device?.isSelf == true {
                Text("Your devices then reach the group through it when they are away from home, through the project's forwarder at cbb.tools.")
            } else {
                Text("Your devices then reach the group through it when they are away from home, through the project's forwarder at cbb.tools. Sync away from home must be on there already; only its own user turns it on.")
                    + Text(verbatim: " ")
                    + Text("A hub that reads the copies is an admin. A hub that only passes them on cannot read them: they are sealed to your other devices only, so its keys need no hardware.")
            }
        }
        .confirmationDialog(Text("Stop \(device?.name ?? "") being the hub?"), isPresented: $unhubbing) {
            Button(role: .destructive) { if let d = device { Task { await model.stopHub(d) } } } label: { Text("Stop being the hub") }
        } message: {
            if let d = device, model.otherHub(than: d) {
                Text("Your devices away from home then go through the group's next hub.")
            } else {
                Text("The group has no other hub: your devices away from home stop syncing until a device is a hub again. To keep them syncing, make another computer a hub first.")
            }
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
            if d.forwardOnly {
                line
                row(Text("Copies"), Text("Passes them on, reads none"))
            }
            if d.muted {
                line
                row(Text("Copies"), MacModel.date(ms: d.mutedUntilMS).map { Text("Muted until \($0.formatted(date: .abbreviated, time: .shortened))") } ?? Text("Muted until an admin unmutes it"))
            }
            if let standing = d.standing {
                line
                row(Text("In the group"), Text(standing))
            }
            if d.hub {
                line
                row(Text("Away from home"), model.status?.away?.hubDevice == d.id ? Text("The group's hub, in use now") : Text("The group's hub"))
            }
            if let mode = d.mode.flatMap(SyncMode.init(rawValue:)) {
                line
                row(Text("Sync"), Text(mode.title))
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

    /// This Mac's own settings as a hub: how its tunnel hides and its
    /// forwarder, kept apart from its addresses and port (cbb global hub
    /// -keep).
    @ViewBuilder private func hubSettings(_ d: Control.Device) -> some View {
        if d.isSelf, let away = model.status?.away, away.hub == true {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                Text("How the hub's tunnel hides").font(.footnote).foregroundStyle(palette.textDim)
                Picker(selection: Binding(get: { model.hubTunnel }, set: { if $0 != model.hubTunnel { tunnelTo = $0 } })) {
                    ForEach(MacModel.HubTunnel.allCases) { Text(verbatim: $0.title).tag($0) }
                } label: { EmptyView() }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                line
                row(Text("Forwarder"), away.forwarder.map { Text(verbatim: $0.endpoint).monospaced() } ?? Text("none"))
                if away.forwarder?.entriesStale == true {
                    Label {
                        Text("The list of the project's entry points is out of date, and the forwarder does not answer on the ways this Mac knows. Update CBB on a computer of the group, or import a new list there with cbb global entries import; the group passes it on.")
                    } icon: { Image(systemName: "exclamationmark.triangle") }
                        .font(.footnote)
                }
                Link(destination: URL(string: "https://cbb.tools/?p=terms.html")!) { Text("Terms of the project's servers") }
                    .font(.footnote)
                action("arrow.triangle.swap", "Change the forwarder…") {
                    (forwarderAddress, forwarderKey) = ("", "")
                    changingForwarder = true
                }
            }
            .padding(Tokens.spacingMedium)
            .glassTile(cornerRadius: Tokens.radiusCard)
            .disabled(model.busy)
            .confirmationDialog(Text("Change how the hub's tunnel hides?"), isPresented: Binding(get: { tunnelTo != nil }, set: { if !$0 { tunnelTo = nil } })) {
                Button {
                    if let t = tunnelTo { Task { await model.setHub(t) } }
                } label: { Text("Change") }
            } message: {
                if tunnelTo == .vless {
                    Text("Your devices then try AmneziaWG first and, where UDP does not pass, reach this hub over VLESS to its forwarder, which must take VLESS. They get the new settings the next time they meet this hub at home; until then they do not reach it away from home.")
                } else {
                    Text("Your devices get the new settings the next time they meet this hub at home; until then they do not reach it away from home.")
                }
            }
            .alert(Text("Change the forwarder"), isPresented: $changingForwarder) {
                TextField(text: $forwarderAddress) { Text(verbatim: "203.0.113.9:8764") }
                TextField(text: $forwarderKey) { Text("The key cbb forward prints") }
                Button {
                    Task { await model.setHub(model.hubTunnel, forwarder: forwarderAddress.trimmingCharacters(in: .whitespaces), key: forwarderKey.trimmingCharacters(in: .whitespaces)) }
                } label: { Text("Save") }
                    .disabled(forwarderAddress.trimmingCharacters(in: .whitespaces).isEmpty || forwarderKey.trimmingCharacters(in: .whitespaces).isEmpty)
                Button {
                    Task { await model.setHub(model.hubTunnel, forwarder: "default") }
                } label: { Text("The project's forwarder") }
                Button(role: .cancel) {} label: { Text("Cancel") }
            } message: {
                Text("Your own forwarder's address and key, as cbb forward prints them, or the project's forwarder at cbb.tools.")
            }
        }
    }

    /// Whether this Mac, an admin, can make d a hub that only passes the
    /// copies on: another computer that is no admin and not rootless.
    private func mayPassOn(_ d: Control.Device) -> Bool {
        !d.isSelf && !d.admin && !d.root && !d.frozen && d.role == "full" && d.store != "rootless"
    }

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
            if d.isSelf {
                VStack(alignment: .leading, spacing: 0) {
                    hubLine(d)
                    line
                    leaveAction
                }
                .glassTile(cornerRadius: Tokens.radiusCard)
                .disabled(model.busy)
            }
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
                line
                hubLine(d)
                // An admin turns sync on or off on a computer; the phones and
                // lite members refuse.
                if !d.isSelf, d.online, d.role == "full" {
                    line
                    Menu {
                        ForEach(SyncMode.allCases) { mode in
                            Button { Task { await model.setMode(mode, on: d.id) } } label: { Text(mode.title) }
                        }
                    } label: {
                        Label { Text("Sync") } icon: { Image(systemName: "arrow.left.arrow.right") }
                            .foregroundStyle(palette.accent)
                    }
                    .menuStyle(.borderlessButton)
                    .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
                    .padding(.horizontal, Tokens.spacingMedium)
                }
                line
                muteLine(d)
                if !d.isSelf {
                    line
                    action("xmark.circle", "Remove", danger: true) { removing = true }
                } else {
                    line
                    leaveAction
                }
            }
            .glassTile(cornerRadius: Tokens.radiusCard)
            .disabled(model.busy)
            if let message = model.message {
                Text(verbatim: message).font(.callout).foregroundStyle(palette.textDim).textSelection(.enabled)
            }
        }
    }

    /// An admin mutes any device for the whole group, for a time or until
    /// an admin unmutes it, or ends its mute (docs/design.md, "Muting a
    /// device").
    @ViewBuilder private func muteLine(_ d: Control.Device) -> some View {
        if d.muted {
            action("speaker.wave.2", "Unmute") { Task { await model.unmute(d.id) } }
        } else {
            Menu {
                ForEach(PauseTime.allCases) { t in
                    Button { Task { await model.mute(d.id, forMS: t.ms) } } label: { t == .ever ? Text("Until an admin unmutes it") : Text(t.title) }
                }
            } label: {
                Label { Text("Mute") } icon: { Image(systemName: "speaker.slash") }
                    .foregroundStyle(palette.danger)
            }
            .menuStyle(.borderlessButton)
            .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
            .padding(.horizontal, Tokens.spacingMedium)
            .help(Text("Its copies then reach no device of the group; it still takes theirs."))
        }
    }

    /// Whether it is a hub, and what this Mac may do about it: always
    /// there, so that a device that can never be a hub says why.
    @ViewBuilder private func hubLine(_ d: Control.Device) -> some View {
        if d.isSelf ? model.status?.away?.hub == true : d.hub {
            Label { Text("This is the group's hub") } icon: { Image(systemName: "antenna.radiowaves.left.and.right") }
                .foregroundStyle(palette.text)
                .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
                .padding(.horizontal, Tokens.spacingMedium)
            if model.isAdmin || d.isSelf {
                line
                action("antenna.radiowaves.left.and.right.slash", "Stop being the hub", danger: true) { unhubbing = true }
            }
        } else if let why = noHub(d) {
            VStack(alignment: .leading, spacing: 2) {
                Label { Text("Make it a hub") } icon: { Image(systemName: "antenna.radiowaves.left.and.right") }
                Text(why).font(.footnote)
            }
            .foregroundStyle(palette.textDim)
            .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
            .padding(.horizontal, Tokens.spacingMedium)
            .padding(.vertical, 6)
            .accessibilityElement(children: .combine)
        } else {
            action("antenna.radiowaves.left.and.right", "Make it a hub") { hubbing = true }
        }
    }

    /// Why d cannot be a hub, nil when it can: a phone only from its own
    /// app, never a lite member, a watch or a computer without root, and a
    /// computer only as the root or an admin with the hub power. Another
    /// computer turns sync away from home on itself, and is told so.
    private func noHub(_ d: Control.Device) -> LocalizedStringKey? {
        switch d.role {
        case "phone": return "A phone is a hub only from its own app's Settings, while the app is open."
        case "lite": return "A lite member is never a hub."
        case "watch": return "A watch is never a hub."
        default: break
        }
        if d.store == "rootless" { return "It runs without administrator rights, so it is never a hub." }
        if d.frozen { return "It is frozen: the root unfreezes it first." }
        // A hub that reads the copies is the root or an admin; an admin
        // makes any other computer a hub that only passes them on.
        if d.isSelf, !d.mayHub || d.forwardOnly { return "Only the group's root or an admin is a hub: the root makes this Mac an admin first." }
        if !d.isSelf, !model.isAdmin { return "Only an admin makes another device a hub." }
        if !d.isSelf, !d.mayHub || d.forwardOnly, !mayPassOn(d) { return "Only the group's root or an admin is a hub: make it an admin first." }
        return nil
    }

    /// This Mac leaves its group; the root only when it is alone, which
    /// the service checks.
    private var leaveAction: some View {
        action("rectangle.portrait.and.arrow.right", "Leave the group", danger: true) { leaving = true }
            .leaveDialog(isPresented: $leaving)
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
