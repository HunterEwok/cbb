// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI

/// "Add a device" on 0.6 (docs/apps.md, "Screens"): a phone without a group
/// makes one first and shows its recovery sheet; then the home window is
/// open, its QR code and six digits on screen. A device that scans the code,
/// or whose person types the digits, joins; nobody is asked. Leaving the
/// sheet closes the window.
struct WindowView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: Tokens.spacingLarge) {
                    if let qr = model.windowQr, let image = QRImage.make(qr) {
                        Image(uiImage: image)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: 260)
                            .padding(Tokens.spacingMedium)
                            .background(Color.white, in: RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous))
                            .accessibilityLabel(Text("QR code to join the group"))
                        if let digits = model.windowDigits, digits.count == 6 {
                            Text(verbatim: "\(digits.prefix(3)) \(digits.suffix(3))")
                                .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                                .accessibilityLabel(Text(verbatim: digits.map(String.init).joined(separator: " ")))
                        }
                        Text("On the new phone, open CBB, tap Join a group and scan this code. A device without a camera, such as a computer, asks for these six digits. Keep this screen open.")
                            .multilineTextAlignment(.center)
                            .foregroundStyle(palette.textDim)
                        ProgressView { Text("Waiting for the new device…") }
                    } else if model.message == nil {
                        ProgressView { Text("Connecting to the device…") }
                    }
                    if let message = model.message {
                        Text(message).foregroundStyle(palette.danger).multilineTextAlignment(.center)
                    }
                }
                .padding(Tokens.spacingLarge)
            }
            .background(AppBackground())
            .navigationTitle(Text("Add a device"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .task { if await model.addByWindow() { dismiss() } }
            .fullScreenCover(item: Binding(get: { model.newSheet.map(ShownSheet.init) }, set: { if $0 == nil { model.newSheet = nil } })) { s in
                RecoverySheetView(sheet: s.sheet, made: Date()) { model.newSheet = nil }
            }
        }
    }

    private struct ShownSheet: Identifiable {
        let sheet: Core.RecoverySheet
        var id: String { sheet.qr }
    }
}

/// Joining a group of 0.6: the camera reads the QR code a phone of the
/// group shows in "Add a device", or the person types the six digits under
/// it (or pastes the code's text), and this phone dials the window and
/// proves the digits; nobody is asked.
struct JoinByWindowView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style
    @State private var typed = ""
    @State private var joining: Task<Void, Never>?

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Text("Join a group")
                .font(.system(.title, design: .monospaced).weight(.bold))
                .foregroundStyle(palette.accent)
            if joining != nil {
                ProgressView { Text("Connecting to the device…") }
            } else {
                if QRScanner.available {
                    QRScanner { text in join(text) }
                        .clipShape(RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous))
                        .frame(maxHeight: 360)
                }
                // The digits, for when scanning fails or there is no camera.
                TextField(String(localized: "Six digits or the code's text", bundle: .app), text: $typed, axis: .vertical)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(Tokens.spacingMedium)
                    .glassCard()
                Button(String(localized: "Join a group", bundle: .app)) { join(typed) }
                    .buttonStyle(AccentButtonStyle())
                    .disabled(typed.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Text("On a phone of the group, tap + and scan the code it shows, or type the six digits under it. Keep both phones on the same network.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(palette.textDim)
            }
            if let message = model.message {
                Text(message).foregroundStyle(palette.danger).multilineTextAlignment(.center)
            }
            Spacer()
            Button("Cancel") {
                joining?.cancel()
                model.cancelJoin()
            }
            .buttonStyle(GlassButtonStyle())
        }
        .frame(maxWidth: Tokens.readableWidth)
        .padding(Tokens.spacingLarge)
        .frame(maxWidth: .infinity)
        .onDisappear { joining?.cancel() }
    }

    /// Dials the window of the scanned code or the typed digits, one at a
    /// time.
    private func join(_ text: String) {
        guard joining == nil else { return }
        joining = Task {
            _ = await model.joinByWindow(text)
            joining = nil
        }
    }
}
