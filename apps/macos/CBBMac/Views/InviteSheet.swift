// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import SwiftUI

/// A remote invitation for a device far away (docs/protocol.md, section
/// 12): its QR code, which cbb invite -app writes once it runs as the
/// administrator (MacModel.invite), with its text as the fallback, and the
/// question about the device that uses it, which the user admits only if
/// it shows the same fingerprint. Cancel removes the file, and cbb hangs up.
struct InviteSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Send an invitation").font(.title2.weight(.semibold))
            if let inv = model.invitation {
                if let j = inv.joining {
                    VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                        Text("\(j.name) (\(j.os)) used the invitation. Admit it only if the device shows the same fingerprint:")
                            .fixedSize(horizontal: false, vertical: true)
                        Text(verbatim: j.fingerprint)
                            .font(.system(.title3, design: .monospaced))
                            .textSelection(.enabled)
                        HStack {
                            Spacer()
                            Button { model.answerInvite(false) } label: { Text("Not this one") }
                            Button { model.answerInvite(true) } label: { Text("Admit") }.keyboardShortcut(.defaultAction)
                        }
                    }
                } else {
                    VStack(spacing: Tokens.spacingMedium) {
                        if let image = JoinSheet.qrImage(inv.invite) {
                            Image(nsImage: image)
                                .interpolation(.none)
                                .resizable()
                                .frame(width: 240, height: 240)
                                .padding(12)
                                .background(.white, in: RoundedRectangle(cornerRadius: 8))
                                .accessibilityLabel(Text("The invitation's QR code"))
                        }
                        Text("On a new phone, open CBB, tap Join with an invitation and scan the code. On a computer, run cbb pair -invite with its text. Show or send it only to the person who joins.")
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                        DisclosureGroup {
                            Text(verbatim: inv.invite)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        } label: { Text("The invitation's text").font(.caption).foregroundStyle(palette.textDim) }
                        Text("The invitation is valid until \(inv.ends.formatted(date: .omitted, time: .shortened)).")
                            .font(.caption).foregroundStyle(palette.textDim)
                    }
                }
            } else {
                HStack(spacing: Tokens.spacingMedium) {
                    ProgressView().controlSize(.small)
                    Text("Allow cbb to run as the administrator; the invitation opens on the group's hub next.").foregroundStyle(palette.textDim)
                }
            }
            HStack {
                Spacer()
                Button { model.cancelInvite() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 420)
        .background(AppBackground())
    }
}
