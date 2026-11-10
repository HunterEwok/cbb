// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import CoreImage
import SwiftUI
import UniformTypeIdentifiers

/// Adding a device: the new device chooses Join a group and shows a QR code
/// and six digits; a phone of the group scans the code, and here, on the
/// root or an admin, the user types the digits, or pastes the code's text or
/// opens a picture of it (cbb pair -qr). A device far away gets an
/// invitation.
struct AddDeviceSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: MacModel
    @State private var qrText = ""
    @State private var qrError: String?
    @State private var asAdmin = false

    private var typed: Bool {
        let text = qrText.trimmingCharacters(in: .whitespacesAndNewlines)
        return MacModel.shownCode(text) != nil || MacModel.isWaitingJoiner(text)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Add a device").font(.title2.weight(.semibold))
            Text("On the new device, choose Join a group: it shows a QR code and six digits. A phone of the group scans the code; here, type the digits.")
                .foregroundStyle(palette.textDim)
                .fixedSize(horizontal: false, vertical: true)
            if model.isAdmin {
                admit
            } else {
                Text("This Mac is no admin of the group: add the device on the phone or on an admin computer.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if model.isAdmin {
                Button {
                    dismiss()
                    Task { await model.invite() }
                } label: { Text("Device far away? Send an invitation") }
                    .buttonStyle(.link)
                    .font(.callout)
            }
            HStack {
                Spacer()
                Button(role: .cancel) { dismiss() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
                if model.isAdmin {
                    Button {
                        let text = qrText, admin = asAdmin && model.isRoot
                        dismiss()
                        Task { await model.admit(text, asAdmin: admin) }
                    } label: { Text("Admit") }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!typed || model.busy)
                }
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 460)
        .background(AppBackground())
    }

    private var admit: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            TextField(text: $qrText, prompt: Text(verbatim: "123 456")) { Text("The six digits the new device shows") }
                .font(.system(.title2, design: .monospaced))
                .multilineTextAlignment(.center)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(Text("The six digits the new device shows"))
            // Only the group's root makes admins.
            if model.isRoot {
                Toggle(isOn: $asAdmin) { Text("Admit it as an admin: only for your own phone.") }
            }
            if let qrError { Text(qrError).foregroundStyle(palette.textDim) }
            Button { openPicture() } label: { Text("Open a picture of its QR code") }
                .buttonStyle(.link)
                .font(.callout)
        }
    }

    private func openPicture() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        switch Self.readQR(url) {
        case .some(let text) where MacModel.isWaitingJoiner(text):
            qrText = text
            qrError = nil
        case .some:
            qrError = String(localized: "This QR code is not of a device that waits to join.")
        case .none:
            qrError = String(localized: "No QR code was found in the picture.")
        }
    }

    /// The text of the QR code in the picture at url, through Core Image.
    static func readQR(_ url: URL) -> String? {
        guard let image = CIImage(contentsOf: url),
              let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        else { return nil }
        return detector.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
