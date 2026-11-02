// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import VisionKit

/// The camera with a frame; the six digits by hand when there is no camera.
/// With restore, it reads the recovery sheet's QR code instead, on a phone
/// without a group, and the key may be pasted by hand.
struct AddDeviceView: View {
    var restore = false
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var typed = ""
    /// The device being admitted; leaving the sheet cancels it.
    @State private var adding: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            VStack(spacing: Tokens.spacingLarge) {
                if QRScanner.available {
                    QRScanner { text in add(text) }
                    .clipShape(RoundedRectangle(cornerRadius: Tokens.radiusCard, style: .continuous))
                    .frame(maxHeight: 360)
                    if restore {
                        Text("Point the camera at the QR code on the recovery sheet. Keep this phone on the network of a computer of the group. This phone becomes the group's root when the group's waiting time ends, unless the old phone cancels it.")
                            .multilineTextAlignment(.center)
                    } else {
                        Text("Point the camera at the QR code of cbb pair, or at the one your other phone shows.")
                            .multilineTextAlignment(.center)
                    }
                } else {
                    if restore {
                        Text("Paste the text of the recovery sheet's QR code.")
                            .multilineTextAlignment(.center)
                    } else {
                        Text("Paste the text of the QR code of cbb pair.")
                            .multilineTextAlignment(.center)
                    }
                    TextField(String(localized: "QR code text", bundle: .app), text: $typed, axis: .vertical)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .padding(Tokens.spacingMedium)
                        .glassCard()
                    Button(restore ? String(localized: "Restore", bundle: .app) : String(localized: "Add", bundle: .app)) { add(typed) }
                    .buttonStyle(AccentButtonStyle())
                    .disabled(typed.isEmpty || model.busy)
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
            .navigationTitle(restore ? Text("Restore the group") : Text("Add a device"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            // The Home screen's last line is not this sheet's, as on Android.
            .onAppear { model.message = nil }
            .onDisappear { adding?.cancel() }
        }
    }

    /// Admits the device of the scanned or pasted text, one at a time.
    private func add(_ text: String) {
        guard adding == nil else { return }
        adding = Task {
            if await (restore ? model.restore(text) : model.scanned(text)) { dismiss() }
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
