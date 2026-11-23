// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI

/// What Home shows above the devices about the group itself: a group from
/// before 0.6, this phone removed, a change of root, and the member's
/// notices.
struct AlertsCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.before06 {
            Before06Card()
        }
        if model.removed {
            RemovedCard()
        }
        RootChangedCard()
        NoticesCard()
    }
}

/// The saved group was made before 0.6, which this version no longer runs
/// (D-126): what that means, and Leave, which alone deletes its keys and
/// files, when the person chooses it.
struct Before06Card: View {
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            Text("A group from before 0.6")
                .font(.headline)
                .foregroundStyle(palette.text)
            Text("This phone is in a group made before 0.6, which this version no longer runs. Leave it on this phone, then make a new group or join one. Nothing is deleted until you leave.")
                .font(.subheadline)
                .foregroundStyle(palette.textDim)
                // Wraps to its full height instead of being clipped.
                .fixedSize(horizontal: false, vertical: true)
            LeaveButton()
                .buttonStyle(GlassButtonStyle())
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard()
    }
}
