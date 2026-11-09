// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The bug report's question in release mode (docs/core-api.md, "Bug
/// reports"): "Oops, something broke", Allow and Cancel, "Always allow"
/// after the user allowed twice, and a small "Technical details" link that
/// shows the report as it would go.
struct BugSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette
    let offer: MacModel.BugOffer
    @State private var always = false
    @State private var details = false

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
            Text("Oops, something broke").font(.title2.weight(.semibold))
            Text("Sorry! Allow us to send a short report so that we can fix it? It holds only what broke, the versions of CBB and the system, the device's model and CBB's own records. Your texts, files, keys, device names and addresses are not in it. The report is anonymous.")
                .foregroundStyle(palette.textDim)
                .fixedSize(horizontal: false, vertical: true)
            if !offer.fixedIn.isEmpty {
                Text("Version \(offer.fixedIn) fixes this: update CBB.")
            }
            if offer.offerAlways {
                Toggle(isOn: $always) { Text("Always allow") }
            }
            Button { details.toggle() } label: { Text("Technical details").font(.footnote) }
                .buttonStyle(.link)
            if details {
                ScrollView {
                    Text(verbatim: offer.report)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 240)
            }
            HStack {
                Spacer()
                Button(role: .cancel) { Task { await model.cancelBug() } } label: { Text("Cancel") }
                    .keyboardShortcut(.cancelAction)
                Button { Task { await model.allowBug(always: always) } } label: { Text("Allow") }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(Tokens.spacingLarge)
        .frame(width: 460)
    }
}
