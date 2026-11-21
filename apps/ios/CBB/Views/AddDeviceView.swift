// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import VisionKit

/// "Add a device": the pairing window (WindowView). With restore, on a
/// phone without a group: the camera with a frame reads the recovery
/// sheet's QR code, or its text is pasted by hand.
struct AddDeviceView: View {
    let restore: Bool
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style
    @State private var typed = ""
    /// The restore under way; leaving the sheet cancels it.
    @State private var adding: Task<Void, Never>?
    @State private var askingCard = false
    @State private var pin = ""

    init(restore: Bool = false) { self.restore = restore }

    var body: some View {
        if !restore {
            WindowView()
        } else {
            scanner
        }
    }

    /// Scanning the recovery sheet's QR code.
    private var scanner: some View {
        NavigationStack {
            VStack(spacing: Tokens.spacingLarge) {
                if QRScanner.available {
                    QRScanner { text in add(text) }
                    .clipShape(RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous))
                    .frame(maxHeight: 360)
                    Text("Point the camera at the QR code on the recovery sheet. Keep this phone on the network of a computer of the group. This phone becomes the group's root when the group's waiting time ends, unless the old phone cancels it.")
                        .multilineTextAlignment(.center)
                } else {
                    Text("Paste the text of the recovery sheet's QR code.")
                        .multilineTextAlignment(.center)
                    TextField(String(localized: "QR code text", bundle: .app), text: $typed, axis: .vertical)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .padding(Tokens.spacingMedium)
                        .glassCard()
                    Button(String(localized: "Restore", bundle: .app)) { add(typed) }
                    .buttonStyle(AccentButtonStyle())
                    .disabled(typed.isEmpty || model.busy)
                }
                if YubiKeyNfc.available {
                    Button { askingCard = true } label: { Text("Use a YubiKey instead") }
                        .buttonStyle(GlassButtonStyle())
                        .disabled(model.busy)
                }
                if model.busy {
                    ProgressView { Text("Connecting to the device…") }
                } else if let message = model.message {
                    Text(message).foregroundStyle(palette.danger)
                }
                Spacer()
            }
            .padding(Tokens.spacingLarge)
            .background(AppBackground())
            .navigationTitle(Text("Restore the group"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .alert(Text("Restore with a YubiKey"), isPresented: $askingCard) {
                YubiKeyPinField(pin: $pin)
                Button { restoreWithCard() } label: { Text("Hold the YubiKey") }.disabled(!YubiKeyPinField.fits(pin))
                Button(role: .cancel) { pin = "" } label: { Text("Cancel") }
            } message: {
                Text("Type the YubiKey's PIN, then hold the YubiKey to the top of the phone: once for this phone's certificate and, once a computer of the group answered, again for the claim. Keep this phone on the network of a computer of the group.")
            }
            // The Home screen's last line is not this sheet's, as on Android.
            .onAppear { model.message = nil }
            .onDisappear { adding?.cancel() }
        }
    }

    /// Restores the group with the recovery key on a YubiKey.
    private func restoreWithCard() {
        guard adding == nil else { return }
        let pin = pin
        self.pin = ""
        adding = Task {
            if await model.restoreWithCard(pin: pin) { dismiss() }
            adding = nil
        }
    }

    /// Restores with the scanned or pasted text, one at a time.
    private func add(_ text: String) {
        guard adding == nil else { return }
        adding = Task {
            if await model.restore(text) { dismiss() }
            adding = nil
        }
    }
}

/// VisionKit's live QR code scanner.
struct QRScanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    @MainActor static var available: Bool { DataScannerViewController.isSupported && DataScannerViewController.isAvailable }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                           qualityLevel: .balanced, isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        try? vc.startScanning()
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for case let .barcode(code) in items {
                if let text = code.payloadStringValue { found(text) }
            }
        }
    }
}
