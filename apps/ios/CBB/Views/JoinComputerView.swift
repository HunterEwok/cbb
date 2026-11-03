// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Joining a computer's group: the six-digit code that cbb pair shows on
/// the group's root, typed here; the phone finds the computer by itself
/// (docs/protocol.md, section 6, "A phone joins a computer's group").
struct JoinComputerView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var code = ""
    @State private var joining: Task<Void, Never>?

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Spacer()
            Text("Join a computer's group")
                .font(.system(.title, design: .monospaced).weight(.bold))
                .foregroundStyle(palette.accent)
                .multilineTextAlignment(.center)
            Text("On the computer that created the group, run cbb pair, then type the six-digit code it shows. Keep this phone on the same network.")
                .multilineTextAlignment(.center)
                .foregroundStyle(palette.textDim)
            TextField(text: $code) { Text("Code") }
                .keyboardType(.numberPad)
                .textContentType(.oneTimeCode)
                .font(.system(.title2, design: .monospaced))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 220)
                .padding(Tokens.spacingSmall)
                .background(palette.surface, in: RoundedRectangle(cornerRadius: Tokens.radiusCard, style: .continuous))
                .disabled(model.busy)
                .onChange(of: code) { _, new in
                    let digits = String(new.filter(\.isNumber).prefix(6))
                    if digits != new { code = digits }
                }
            if model.busy {
                ProgressView()
                Text("Looking for the computer…").foregroundStyle(palette.textDim)
            } else {
                Button("Join") {
                    let typed = code
                    joining = Task { await model.joinComputer(code: typed) }
                }
                .buttonStyle(AccentButtonStyle())
                .disabled(code.count != 6)
            }
            if let message = model.message {
                Text(message).foregroundStyle(palette.danger).multilineTextAlignment(.center)
            }
            Spacer()
            Button("Cancel") {
                joining?.cancel()
                model.cancelJoin()
            }
            .buttonStyle(GlassButtonStyle())
        }
        .padding(Tokens.spacingLarge)
        .onDisappear { joining?.cancel() }
    }
}
