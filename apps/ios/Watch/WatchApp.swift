// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The Apple Watch app: the group's devices as the phone sees them, the
/// latest events and the switch for sync away from home (docs/apps.md,
/// Apple Watch). It works only through the paired iPhone.
@main
struct WatchApp: App {
    @StateObject private var model = WatchModel()

    var body: some Scene {
        WindowGroup {
            WatchHome()
                .environmentObject(model)
                .environment(\.palette, ThemeChoice.theme(model.state.theme).dark)
                .tint(ThemeChoice.theme(model.state.theme).dark.accent)
        }
    }
}
