// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Joining another phone's group: this phone's QR code, which the other
/// phone scans in "Add a device" (docs/apps.md, Add a device); or, with an
/// accepted invitation, the fingerprint the inviting admin compares while
/// the phone joins from afar.
struct JoinView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.themeStyle) private var style

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Spacer()
            Text(model.joiningInvite != nil ? LocalizedStringKey("Join with an invitation") : LocalizedStringKey("Join a group"))
                .font(.system(.title, design: .monospaced).weight(.bold))
                .foregroundStyle(palette.accent)
            if model.joiningInvite != nil {
                if let fp = model.inviteFingerprint, model.message == nil {
                    Text(verbatim: fp)
                        .font(.system(.title2, design: .monospaced).weight(.bold))
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                    Text("Whoever invited you sees these words on their device and admits this phone if they match. Keep this screen open.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(palette.textDim)
                    ProgressView()
                } else if model.message == nil {
                    ProgressView { Text("Connecting to the group's hub…") }
                }
            } else if let code = model.joinCode, let image = QRImage.make(code.qrText) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 260)
                    .padding(Tokens.spacingMedium)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: style.radiusCard, style: .continuous))
                    .accessibilityLabel(Text("QR code to join the group"))
                Text(verbatim: code.grouped)
                    .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                    .textSelection(.enabled)
                    .accessibilityLabel(Text(verbatim: code.code.map(String.init).joined(separator: " ")))
                Text("On a phone of the group, tap + and scan this code. On a computer of the group, tap + and type the numbers. Keep this screen open.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(palette.textDim)
            } else if model.message == nil {
                ProgressView()
            }
            if let message = model.message {
                Text(message).foregroundStyle(palette.danger).multilineTextAlignment(.center)
            }
            Spacer()
            Button("Cancel") { model.cancelJoin() }
                .buttonStyle(GlassButtonStyle())
        }
        // A column a hand's width on a big screen, as a phone's.
        .frame(maxWidth: Tokens.readableWidth)
        .padding(Tokens.spacingLarge)
        .frame(maxWidth: .infinity)
        .task {
            if model.joiningInvite != nil { await model.joinByInvite() } else { await model.join() }
        }
    }
}

/// A QR code as an image, from Core Image's generator.
enum QRImage {
    static func make(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let out = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(out, from: out.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
