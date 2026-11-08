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
                Button { Task { await model.joinGroup() } } label: { Text("Join a group").frame(maxWidth: .infinity) }
                    .buttonStyle(GlassButtonStyle())
            }
            .frame(width: 260)
            .disabled(model.busy || model.joining)
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

/// Claims a group whose phones are all lost with its recovery key; this Mac
/// must be in that group, so out of a group it says so.
struct RecoverySheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var key = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Recovery key").font(.title2.weight(.semibold))
            if model.inGroup {
                Text("Type the key from the sheet, or paste its QR code's text. The claim waits as a takeover does.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
                TextField(text: $key) { Text("Recovery key") }
                    .font(.system(.body, design: .monospaced))
                    .textFieldStyle(.roundedBorder)
            } else {
                Text("The recovery key claims a group whose phones are all lost. Join that group first, then claim it in Settings.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(role: .cancel) { dismiss() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
                if model.inGroup {
                    Button {
                        let k = key
                        dismiss()
                        Task { await model.recover(k) }
                    } label: { Text("Claim") }
                        .keyboardShortcut(.defaultAction)
                        .disabled(key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.busy)
                }
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 440)
        .background(AppBackground())
    }
}
