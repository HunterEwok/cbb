// SPDX-License-Identifier: AGPL-3.0-only

import AppIntents

/// The action of the home-screen widget and the Control Center control:
/// it opens the app, since iOS lets an app read the clipboard only in the
/// foreground, and syncs as the Home button does. The widget extension
/// carries it too; with openAppWhenRun the app runs it.
struct OpenAndSyncIntent: AppIntent {
    static let title: LocalizedStringResource = "Sync clipboard"
    static let description = IntentDescription("Opens CBB and sends what this phone copied to your computers, or fetches what a computer copied a moment ago.")
    static let openAppWhenRun = true
    static let isDiscoverable = false

    @MainActor
    func perform() async throws -> some IntentResult {
        #if CBB_APP
        _ = await AppModel.shared.syncFromShortcut()
        #endif
        return .result()
    }
}
