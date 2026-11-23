// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import SwiftUI

/// Joining a group far away with an invitation (MacModel.joinInvite): its
/// text, which cbb pair -invite takes as the administrator, then this Mac's
/// key fingerprint, which whoever invited it compares before admitting it.
struct JoinInviteSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: MacModel
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Join with an invitation").font(.title2.weight(.semibold))
            if !model.joiningByInvite {
                Text("Paste the invitation you got. A device that joins with one syncs away from home through the group's hub, so sync away from home is turned on here.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
                TextField(text: $text, prompt: Text(verbatim: "cbb://join#…"), axis: .vertical) { Text("Invitation text") }
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(3...6)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(Text("Invitation text"))
            } else if let fp = model.joinFingerprint {
                Text("Key fingerprint").font(.headline)
                Text(verbatim: fp)
                    .font(.system(.title3, design: .monospaced))
                    .textSelection(.enabled)
                Text("Whoever invited you sees these words on their device and admits this Mac if they match. Keep this window open.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Allow cbb to run as the administrator; this Mac's key fingerprint shows next.")
                    .foregroundStyle(palette.textDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(role: .cancel) {
                    model.cancelJoin()
                    dismiss()
                } label: { Text("Cancel") }
                    .keyboardShortcut(.cancelAction)
                if !model.joiningByInvite {
                    Button {
                        let invitation = text
                        text = ""
                        Task {
                            await model.joinInvite(invitation)
                            dismiss()
                        }
                    } label: { Text("Join") }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("cbb://join#") || model.busy)
                }
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 460)
        .background(AppBackground())
    }
}
