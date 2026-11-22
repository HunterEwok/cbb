// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Joining another phone's group: by the pairing window of a phone of the
/// group (JoinByWindowView); or, with an accepted invitation, the
/// fingerprint the inviting admin compares while the phone joins from afar.
struct JoinView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        // On 0.6 the new phone dials a window (docs/protocol.md, section 6,
        // "The window and who dials").
        if model.joiningInvite == nil {
            JoinByWindowView()
        } else {
            byInvite
        }
    }

    /// Joining by an invitation.
    private var byInvite: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Spacer()
            Text("Join with an invitation")
                .font(.system(.title, design: .monospaced).weight(.bold))
                .foregroundStyle(palette.accent)
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
        .task { await model.joinByInvite() }
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
