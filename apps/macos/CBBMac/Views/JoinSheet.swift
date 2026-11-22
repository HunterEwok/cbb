// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Joining a group from the app: the six digits of a pairing window open on
/// a device of the group, which cbb pair -code takes as the administrator
/// (MacModel.joinGroup). On 0.6 a device in no group dials the window
/// (D-119).
struct JoinSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: MacModel
    @State private var digits = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Join a group").font(.title2.weight(.semibold))
            Text("On a device of the group, open a pairing window: tap + there. Then type the six digits it shows.")
                .foregroundStyle(palette.textDim)
                .fixedSize(horizontal: false, vertical: true)
            TextField(text: $digits, prompt: Text(verbatim: "123 456")) { Text("The six digits") }
                .font(.system(.title2, design: .monospaced))
                .multilineTextAlignment(.center)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(Text("The six digits"))
            HStack {
                Spacer()
                Button(role: .cancel) { dismiss() } label: { Text("Cancel") }.keyboardShortcut(.cancelAction)
                Button {
                    let text = digits
                    dismiss()
                    Task { await model.joinGroup(text) }
                } label: { Text("Join") }
                    .keyboardShortcut(.defaultAction)
                    .disabled(MacModel.shownCode(digits) == nil || model.busy)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 420)
        .background(AppBackground())
    }
}
