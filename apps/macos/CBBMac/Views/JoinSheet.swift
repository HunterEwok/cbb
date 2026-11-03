// SPDX-License-Identifier: AGPL-3.0-only

import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Joining a phone's group from the app: the QR code the phone scans,
/// which cbb pair -app writes once it runs as the administrator
/// (MacModel.joinPhone). Cancel removes the file, and cbb hangs up.
struct JoinSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Join a phone's group").font(.title2.weight(.semibold))
            if let join = model.join {
                VStack(spacing: Tokens.spacingMedium) {
                    Text("In the CBB app on the phone, tap \"Connect a new device\" and scan this code:")
                        .fixedSize(horizontal: false, vertical: true)
                    if let image = Self.qrImage(join.qr) {
                        Image(nsImage: image)
                            .interpolation(.none)
                            .resizable()
                            .frame(width: 240, height: 240)
                            .padding(12)
                            .background(.white, in: RoundedRectangle(cornerRadius: 8))
                            .accessibilityLabel(Text("QR code"))
                    }
                    Text("Without a camera, paste this into the app:").font(.caption).foregroundStyle(palette.textDim)
                    Text(verbatim: join.qr)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let minutes = max(0, Int((join.ends.timeIntervalSince(context.date) / 60).rounded(.up)))
                        Text("The code is valid for \(minutes) more min.").font(.caption).foregroundStyle(palette.textDim)
                    }
                    Text("If the phone cannot connect, the firewall must let it reach TCP port \(join.port) here.")
                        .font(.caption).foregroundStyle(palette.textDim)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                HStack(spacing: Tokens.spacingMedium) {
                    ProgressView().controlSize(.small)
                    Text("Allow cbb to run as the administrator; the QR code shows next.").foregroundStyle(palette.textDim)
                }
            }
            HStack {
                Spacer()
                Button { model.cancelJoin() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 420)
        .background(AppBackground())
    }

    /// The QR code of text, one pixel a module; the view scales it up
    /// without smoothing.
    static func qrImage(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage,
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: output.extent.width, height: output.extent.height))
    }
}
