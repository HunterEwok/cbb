// SPDX-License-Identifier: AGPL-3.0-only

import AppIntents

/// The Home button as an action of the Shortcuts app, for Back Tap, the
/// Action button and Siri: it sends or fetches by the same rule and says
/// what it did, without opening the app.
struct SyncClipboardIntent: AppIntent, ProgressReportingIntent {
    static let title: LocalizedStringResource = "Sync clipboard"
    static let description = IntentDescription("Sends what this phone copied to your computers, or fetches what a computer copied a moment ago.")
    static let openAppWhenRun = false

    /// While it waits for a computer, the system shows its progress (and,
    /// with Live Activities, the Dynamic Island says it connects).
    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        progress.totalUnitCount = 2
        let said = await AppModel.shared.syncFromShortcut(progress: progress)
        return .result(dialog: "\(said)")
    }
}

/// Offers the action in Shortcuts and Spotlight as soon as the app is
/// installed, without the user building a shortcut.
struct ClipboardBridgeShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: SyncClipboardIntent(),
                    phrases: ["Sync clipboard with \(.applicationName)", "\(.applicationName) sync"],
                    shortTitle: "Sync clipboard",
                    systemImageName: "arrow.up.arrow.down")
    }
}
