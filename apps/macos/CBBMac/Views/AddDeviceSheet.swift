// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import CoreImage
import SwiftUI
import UniformTypeIdentifiers

/// How a device joins: the commands to copy for pairing in Terminal and, on
/// the root or an admin, admitting a device that shows a QR code and waits,
/// such as a phone with Aurora OS or Sailfish OS, from the code's text or a
/// picture of it.
struct AddDeviceSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: MacModel
    @State private var qrText = ""
    @State private var qrError: String?
    @State private var asAdmin = false

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Add a device").font(.title2.weight(.semibold))
            step("1", Text("On the new computer, run:"), command: "cbb pair")
            step("2", Text("In a group of the phone, scan the QR code it shows with the phone app. In a group of computers, run this on this Mac or another admin and type the code it shows on the new computer:"), command: "sudo cbb pair")
            Text("A phone joins from the start screen of its app.").foregroundStyle(palette.textDim)
            if model.isAdmin { admitByQR }
            HStack {
                Spacer()
                Button { dismiss() } label: { Text("Done") }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 480)
        .background(AppBackground())
    }

    private var admitByQR: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            Text("Admit by QR code").font(.headline)
            Text("A phone with Aurora OS or Sailfish OS shows a QR code and waits. Paste the code's text, or open a picture of it:")
                .foregroundStyle(palette.textDim)
                .fixedSize(horizontal: false, vertical: true)
            TextField(text: $qrText, prompt: Text(verbatim: "cbb://join?...")) { Text("The QR code's text") }
                .font(.system(.body, design: .monospaced))
                .textFieldStyle(.roundedBorder)
            // Only the group's root makes admins.
            if model.isRoot {
                Toggle(isOn: $asAdmin) {
                    Text("Admit it as an admin: it may then add, remove and renew devices and take the group over after the takeover delay. Only for your own phone.")
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let qrError { Text(qrError).foregroundStyle(palette.textDim) }
            HStack {
                Button { openPicture() } label: { Text("Open a picture") }
                Spacer()
                Button {
                    let text = qrText, admin = asAdmin && model.isRoot
                    dismiss()
                    Task { await model.admitByQR(text, asAdmin: admin) }
                } label: { Text("Admit") }
                    .disabled(!MacModel.isWaitingJoiner(qrText.trimmingCharacters(in: .whitespacesAndNewlines)) || model.busy)
            }
        }
        .padding(Tokens.spacingMedium)
        .glassTile(cornerRadius: Tokens.radiusCard)
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

    private func step(_ n: String, _ text: Text, command: String) -> some View {
        HStack(alignment: .top, spacing: Tokens.spacingMedium) {
            Text(verbatim: n).font(.headline).foregroundStyle(palette.onAccent).frame(width: 26, height: 26).background(palette.accent, in: Circle())
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                text.fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(verbatim: command).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .help(Text("Copy"))
                }
                .padding(Tokens.spacingSmall)
                .glassTile(cornerRadius: Tokens.radiusCard)
            }
        }
    }
}
