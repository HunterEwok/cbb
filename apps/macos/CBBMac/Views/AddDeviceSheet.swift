// SPDX-License-Identifier: AGPL-3.0-only

import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Adding a device: on the root or an admin the sheet opens a pairing
/// window (MacModel.openWindow) and shows its six digits, which a new
/// computer types, and its QR code, which a new phone scans (D-119).
/// Closing the sheet closes the window; a device that joins closes the
/// sheet. On the root, a toggle opens it again for a phone that joins as an
/// admin. A device far away gets an invitation.
struct AddDeviceSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: MacModel
    @State private var asAdmin = false

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Add a device").font(.title2.weight(.semibold))
            if model.isAdmin {
                window
                // Only the group's root makes admins.
                if model.isRoot {
                    Toggle(isOn: $asAdmin) { Text("Admit it as an admin: only for your own phone.") }
                }
                Button {
                    dismiss()
                    Task { await model.invite() }
                } label: { Text("Device far away? Send an invitation") }
                    .buttonStyle(.link)
                    .font(.callout)
            } else {
                Text("This Mac is no admin of the group: add the device on the phone or on an admin computer.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(role: .cancel) { dismiss() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 460)
        .background(AppBackground())
        // A new window for each choice: the last one closes first. The
        // window that ends by itself (a device joined, or it ran out)
        // closes the sheet.
        .task(id: asAdmin) {
            guard model.isAdmin else { return }
            if model.pairing {
                model.closeWindow()
                while model.pairing, !Task.isCancelled { try? await Task.sleep(for: .milliseconds(50)) }
            }
            if Task.isCancelled { return }
            await model.openWindow(asAdmin: asAdmin && model.isRoot)
            if !Task.isCancelled { dismiss() }
        }
        .onDisappear { model.closeWindow() }
    }

    @ViewBuilder private var window: some View {
        if let w = model.window, let digits = w.digits {
            VStack(spacing: Tokens.spacingMedium) {
                if let image = QRCode.image(w.qr) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 240, height: 240)
                        .padding(12)
                        .background(.white, in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityLabel(Text("QR code"))
                }
                Text(verbatim: digits)
                    .font(.system(size: 34, weight: .semibold, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityLabel(Text("The six digits: \(digits)"))
                Text("On the new computer, choose Join a group and type these six digits. A new phone scans this code.")
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let minutes = max(0, Int((w.ends.timeIntervalSince(context.date) / 60).rounded(.up)))
                    Text("The code is valid for \(minutes) more min.").font(.caption).foregroundStyle(palette.textDim)
                }
                if let refused = w.refused, !refused.isEmpty {
                    Text("A device did not pair: \(refused)").font(.caption).foregroundStyle(palette.textDim)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity)
        } else {
            HStack(spacing: Tokens.spacingMedium) {
                ProgressView().controlSize(.small)
                Text("Allow cbb to run as the administrator; the code shows next.").foregroundStyle(palette.textDim)
            }
        }
    }
}

/// QR codes the app draws: a pairing window's, an invitation's.
enum QRCode {
    /// The QR code of text, one pixel a module; the view scales it up
    /// without smoothing.
    static func image(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage,
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: output.extent.width, height: output.extent.height))
    }
}
