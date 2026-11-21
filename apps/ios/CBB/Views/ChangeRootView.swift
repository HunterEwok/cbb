// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import SwiftUI

/// Moving the group's main device to this phone with the recovery key
/// (docs/apps.md, "Changing the main device"): the key from the sheet's QR
/// code, its typed text or a YubiKey that holds it, then the list of who
/// stays, which the core
/// writes and the person only unticks, then Face ID. Each unticked device
/// is removed in the same act; the old main device starts unticked.
struct ChangeRootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var recovery: RecoveryInput?
    @State private var typed = ""
    @State private var preview: ChangePreview?
    @State private var leaveOut: Set<String> = []
    @State private var overWaiting = false
    @State private var loading = false
    @State private var askingCard = false
    @State private var pin = ""

    var body: some View {
        NavigationStack {
            Form {
                if let preview {
                    list(preview)
                } else {
                    key
                }
            }
            .navigationTitle(Text("Move the group to this phone"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button { dismiss() } label: { Text("Cancel") }
                }
            }
            .disabled(loading || model.busy)
            .alert(Text("Use the YubiKey with the recovery key"), isPresented: $askingCard) {
                YubiKeyPinField(pin: $pin)
                Button { openCard() } label: { Text("Hold the YubiKey") }.disabled(!YubiKeyPinField.fits(pin))
                Button(role: .cancel) { pin = "" } label: { Text("Cancel") }
            } message: {
                Text("Type the YubiKey's PIN, then hold the YubiKey to the phone until it is done.")
            }
        }
    }

    /// The recovery key: the sheet's QR code, or its text typed.
    @ViewBuilder private var key: some View {
        Section {
            if QRScanner.available {
                QRScanner { text in start(.qr(text)) }
                    .frame(height: 260)
                    .listRowInsets(EdgeInsets())
            }
            TextField(text: $typed, axis: .vertical) { Text("The recovery key's text, as on the sheet") }
                .lineLimit(4...6)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .font(.body.monospaced())
            Button { start(.text(typed)) } label: { Text("Next") }
                .disabled(typed.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            if YubiKeyNfc.available {
                Button { askingCard = true } label: { Text("Use a YubiKey instead") }
            }
        } footer: {
            Text("Scan the code on the group's recovery sheet, or type its text. The key stays on this phone only for this change.")
        }
    }

    /// Who stays, with a tick for each device the person may leave out.
    @ViewBuilder private func list(_ p: ChangePreview) -> some View {
        Section {
            ForEach(p.rows) { row in
                if row.outcome == "removed_earlier" {
                    VStack(alignment: .leading) {
                        Text(verbatim: row.name)
                        Text("Removed earlier").font(.footnote).foregroundStyle(palette.textDim)
                    }
                } else {
                    Toggle(isOn: Binding(get: { !leaveOut.contains(row.device) }, set: { stays in toggle(row.device, stays) })) {
                        VStack(alignment: .leading) {
                            Text(verbatim: row.name)
                            Self.outcome(row).font(.footnote).foregroundStyle(palette.textDim)
                        }
                    }
                }
            }
        } header: {
            Text("Who stays in the group")
        } footer: {
            Text("\(online) of \(model.devices.count) devices are connected now. The others learn of the change when they connect. An unticked device is removed, and joins again only as a new device.")
        }
        if p.waiting {
            Section {
                Toggle(isOn: $overWaiting) { Text("Write a new change over it") }
            } footer: {
                Text("A change of the main device is already on its way, and its records have not all arrived. Connect to your devices first; write over it only if that change will never arrive, for example because the phone that made it is lost.")
            }
        }
        Section {
            Button { change() } label: { Text("Make this phone the main device") }
                .disabled(p.waiting && !overWaiting)
        } footer: {
            Text("This cannot be undone. Face ID confirms it, and the group's devices follow this phone as soon as they connect.")
        }
    }

    private var online: Int { model.devices.filter(\.online).count }

    /// What the change does to a device, in words.
    static func outcome(_ row: ChangePreview.Row) -> Text {
        switch row.outcome {
        case "out": Text("Removed")
        case "admin_kept": Text("Stays, and stays an admin")
        case "admin_lost": Text("Stays, no longer an admin: make it an admin again later")
        case "frozen": Text("Stays, frozen until you unfreeze it")
        default: row.frozen ? Text("Stays, frozen until you unfreeze it") : Text("Stays")
        }
    }

    /// Reads the key: the first preview, with the old main device unticked.
    private func start(_ r: RecoveryInput) {
        guard recovery == nil, !loading else { return }
        loading = true
        Task {
            let old = model.devices.first(where: \.isRoot).map { [$0.id] } ?? []
            if let p = await model.changePreview(r, leaveOut: old) {
                (recovery, leaveOut, preview) = (r, Set(old), p)
            }
            loading = false
        }
    }

    /// Opens the recovery key on a YubiKey, then reads it as from the sheet.
    private func openCard() {
        let pin = pin
        self.pin = ""
        Task {
            if let secret = await model.openCard(pin: pin) { start(.secret(secret)) }
        }
    }

    /// The person ticked or unticked a device: the core writes the list again.
    private func toggle(_ device: String, _ stays: Bool) {
        guard let recovery else { return }
        if stays { leaveOut.remove(device) } else { leaveOut.insert(device) }
        let out = Array(leaveOut)
        Task {
            if let p = await model.changePreview(recovery, leaveOut: out) { preview = p }
        }
    }

    private func change() {
        guard let recovery else { return }
        let out = Array(leaveOut)
        Task {
            if await model.changeRoot(recovery, leaveOut: out, overWaiting: overWaiting) { dismiss() }
        }
    }
}
