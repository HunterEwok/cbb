// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Leaving the group (D-83, docs/design.md, "Leaving the group"): the
/// button and its question, in Settings and on the card of a removed phone.
struct LeaveButton: View {
    @EnvironmentObject private var model: AppModel
    @State private var asking = false

    var body: some View {
        Button(role: .destructive) { asking = true } label: { Text("Leave the group") }
            .disabled(model.busy)
            .confirmationDialog(Text("Leave the group?"), isPresented: $asking, titleVisibility: .visible) {
                Button(role: .destructive) {
                    Task { _ = await model.leave() }
                } label: {
                    Text("Leave the group")
                }
            } message: {
                Text("This phone's keys and the group's data here are deleted; the settings stay. It can then join this group again or another one. The group keeps listing it until an admin removes it.")
            }
    }
}

/// On Home, when the group removed this phone: it syncs with nobody, so
/// the card offers to leave and join again.
struct RemovedCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            Text("This phone was removed from the group")
                .font(.headline)
                .foregroundStyle(palette.danger)
            Text("The group's devices refuse it now. Leave the group to delete its keys here; then it can join a group again.")
                .font(.subheadline)
                .foregroundStyle(palette.textDim)
            LeaveButton()
                .buttonStyle(GlassButtonStyle())
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard()
    }
}
