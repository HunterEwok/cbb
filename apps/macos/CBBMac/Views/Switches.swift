// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import SwiftUI

/// The two switches in the window's header: the house turns sync on this
/// Mac off or on (a click; its menu turns it off for a time), the globe
/// turns Everywhere, sync away from home, on or off; the globe waits while
/// sync is off (docs/design.md, "Sync on and off").
struct SyncSwitches: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingSmall) {
            house
            globe
            AwayBadge(away: model.status?.away)
        }
        .alert(Text("Turn Everywhere on?"), isPresented: $model.askingAway) {
            Button { Task { await model.setAway(true) } } label: { Text("Turn on") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("This Mac then reaches the group's hub from the internet through the group's own WireGuard tunnel, the clipboard encrypted end to end. Its keys are files: keep FileVault on, keep the service's folder out of unencrypted backups, and remove the Mac at once if it is lost.")
        }
    }

    private var syncText: Text {
        model.syncOff ? Text(verbatim: Self.syncOffTitle(until: model.syncOffUntil)) : Text("Sync is on")
    }

    private var house: some View {
        Menu {
            ForEach(PauseTime.allCases) { t in
                Button { Task { await model.turnSync(false, forMS: t.ms) } } label: { Text(t.title) }
            }
        } label: {
            SwitchFace(symbol: model.syncOff ? "house" : "house.fill", on: !model.syncOff)
        } primaryAction: {
            Task { await model.turnSync(model.syncOff) }
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .disabled(model.busy)
        .help(Text("Sync: click to turn it off or on; hold it for a time"))
        .accessibilityLabel(syncText)
        .accessibilityAddTraits(model.syncOff ? [] : .isSelected)
    }

    private var globe: some View {
        let away = model.awayOn
        let text: Text = away ? Text("Everywhere is on") : model.syncOff ? Text("Everywhere waits while sync is off") : Text("Everywhere is off")
        return Button {
            if away { Task { await model.setAway(false) } } else { model.askingAway = true }
        } label: {
            SwitchFace(symbol: "globe", on: away)
        }
        .buttonStyle(.plain)
        .disabled(model.busy || (model.syncOff && !away))
        .help(text)
        .accessibilityLabel(text)
        .accessibilityAddTraits(away ? .isSelected : [])
    }

    static func syncOffTitle(until: Date?) -> String {
        guard let until else { return String(localized: "Sync off") }
        return String(localized: "Sync off until \(until.formatted(date: .omitted, time: .shortened))")
    }
}

/// A switch's round face: filled with the accent while on.
private struct SwitchFace: View {
    let symbol: String
    let on: Bool
    @Environment(\.palette) private var palette
    @Environment(\.isEnabled) private var enabled

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 17, weight: .semibold))
            .foregroundStyle(on ? palette.onAccent : palette.textDim)
            .frame(width: 38, height: 38)
            .background(on ? palette.accent : palette.soft, in: Circle())
            .opacity(enabled ? 1 : 0.5)
            .contentShape(Circle())
    }
}

/// A newer release the group passed around, as a card over the devices.
struct UpdateCard: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    var body: some View {
        if let version = model.status?.update, !version.isEmpty {
            HStack(spacing: Tokens.spacingMedium) {
                Image(systemName: "arrow.down.circle").font(.title2).foregroundStyle(palette.accent)
                Text("CBB \(version) is out.")
                Spacer()
                Button { Task { await model.update() } } label: { Text("Update to \(version)") }
                    .buttonStyle(AccentButtonStyle())
                    .fixedSize()
                    .disabled(model.busy)
            }
            .padding(Tokens.spacingMedium)
            .glassCard()
        }
    }
}

/// The start window out of a group: a group made here, one joined, or a
/// lost group claimed with its recovery key.
struct StartView: View {
    @Binding var recovering: Bool
    @Binding var joining: Bool
    @Binding var joiningByInvite: Bool
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 96, height: 96)
                .accessibilityHidden(true)
            Text(verbatim: "Copy Beyond Borders").font(.title.weight(.semibold))
            VStack(spacing: Tokens.spacingMedium) {
                Button { Task { await model.createGroup() } } label: { Text("Create a group").frame(maxWidth: .infinity) }
                    .buttonStyle(AccentButtonStyle())
                Button { joining = true } label: { Text("Join a group").frame(maxWidth: .infinity) }
                    .buttonStyle(GlassButtonStyle())
                Button { joiningByInvite = true } label: { Text("Join with an invitation").frame(maxWidth: .infinity) }
                    .buttonStyle(GlassButtonStyle())
            }
            .frame(width: 260)
            .disabled(model.busy)
            Button { recovering = true } label: { Text("Recovery key") }
                .buttonStyle(.link)
                .font(.callout)
            // Out of a group the message says here why a step failed.
            if let message = model.message {
                Text(verbatim: message).foregroundStyle(palette.textDim).multilineTextAlignment(.center).textSelection(.enabled)
            }
        }
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Moves the group to this Mac with its recovery key, for example when the
/// phone that was its main device is lost; this Mac must be in that group,
/// so out of a group it says so.
struct RecoverySheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var key = ""
    @State private var pin = ""
    @State private var card = false
    /// The devices that leave the group in the same act; the old main
    /// device starts among them.
    @State private var leave: Set<String> = []

    private var others: [Control.Device] { model.devices.filter { !$0.isSelf } }
    private var secret: String { (card ? pin : key).trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Move the group to this Mac").font(.title2.weight(.semibold))
            if model.inGroup {
                Text("Type the key from the sheet, or paste its QR code's text. This Mac becomes the group's main device at once.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Who stays in the group").font(.headline)
                ScrollView {
                    VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                        ForEach(others) { d in
                            Toggle(isOn: Binding(get: { !leave.contains(d.id) }, set: { stays in
                                if stays { leave.remove(d.id) } else { leave.insert(d.id) }
                            })) { Text(verbatim: d.name.isEmpty ? d.id : d.name) }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 180)
                Text("An unticked device is removed, and joins again only as a new device.")
                    .font(.caption).foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle(isOn: $card) { Text("Use a YubiKey instead") }
                if card {
                    SecureField(text: $pin) { Text("The YubiKey's PIN") }
                        .textFieldStyle(.roundedBorder)
                } else {
                    TextField(text: $key) { Text("The recovery key's text, as on the sheet") }
                        .font(.system(.body, design: .monospaced))
                        .textFieldStyle(.roundedBorder)
                }
            } else {
                Text("With the group's recovery key, this Mac becomes the main device, for example when the old one is lost. Join the group first, then move it here in Settings.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(role: .cancel) { dismiss() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
                if model.inGroup {
                    Button {
                        let (s, out, c) = (secret, Array(leave), card)
                        dismiss()
                        Task { await model.recover(s, leave: out, card: c) }
                    } label: { Text("Make this Mac the main device") }
                        .keyboardShortcut(.defaultAction)
                        .disabled(secret.isEmpty || model.busy)
                }
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 440)
        .background(AppBackground())
        .onAppear { leave = Set(others.filter(\.root).map(\.id)) }
    }
}
