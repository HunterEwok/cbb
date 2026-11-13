// SPDX-License-Identifier: AGPL-3.0-only

import AppIntents

/// The Home button as an action of the Shortcuts app, for Back Tap, the
/// Action button and Siri: it fetches a copy from another device that
/// waits, or sends Text, by the same rule, and says what it did, without
/// opening the app. An app in the background cannot read the clipboard, so
/// a shortcut hands it over with Get Clipboard.
struct SyncClipboardIntent: AppIntent, ProgressReportingIntent {
    static let title: LocalizedStringResource = "Sync clipboard"
    static let description = IntentDescription("Fetches what another device copied in the last minute, or sends the text, as from Get Clipboard, to your devices.")
    static let openAppWhenRun = false
    /// It fetches a copy into the pasteboard and says where it came from,
    /// so it runs only on an unlocked phone: on a locked one, Siri and the
    /// Shortcuts app ask for Face ID or the passcode first.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    @Parameter(title: "Text")
    var text: String?

    /// While it waits for a computer, the system shows its progress (and,
    /// with Live Activities, the Dynamic Island says it connects).
    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        progress.totalUnitCount = 2
        let said = await AppModel.shared.syncFromShortcut(text: text, progress: progress)
        return .result(dialog: "\(said)")
    }
}

/// Offers the action in Shortcuts and Spotlight as soon as the app is
/// installed, without the user building a shortcut.
struct CBBShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: SyncClipboardIntent(),
                    phrases: ["Sync clipboard with \(.applicationName)", "\(.applicationName) sync"],
                    shortTitle: "Sync clipboard",
                    systemImageName: "arrow.up.arrow.down")
    }
}
