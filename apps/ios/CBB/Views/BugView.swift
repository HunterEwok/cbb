// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import SwiftUI

/// The bug report's question in release mode (docs/core-api.md, "Bug
/// reports"): "Oops, something broke", Allow and Cancel, "Always allow"
/// after the user allowed twice, and a small "Technical details" link that
/// shows the report as it would go.
struct BugView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    let offer: BugReports.Offer
    @State private var always = false
    @State private var details = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                    Text("Sorry! Allow us to send a short report so that we can fix it? It holds only what broke, the versions of CBB and the system, the device's model and CBB's own records. Your texts, files, keys, device names and addresses are not in it. The report is anonymous.")
                        .foregroundStyle(palette.textDim)
                    if !offer.fixed_in.isEmpty {
                        Text("Version \(offer.fixed_in) fixes this: update CBB.")
                    }
                    if offer.offer_always {
                        Toggle(isOn: $always) { Text("Always allow") }
                    }
                    Button { model.allowBug(always: always) } label: {
                        Text("Allow").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    Button(role: .cancel) { model.cancelBug() } label: {
                        Text("Cancel").frame(maxWidth: .infinity)
                    }
                    Button { details.toggle() } label: { Text("Technical details").font(.footnote) }
                    if details {
                        Text(offer.report.text)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                .padding(Tokens.spacingLarge)
            }
            .navigationTitle(Text("Oops, something broke"))
            .navigationBarTitleDisplayMode(.inline)
        }
        .interactiveDismissDisabled(false)
    }
}
