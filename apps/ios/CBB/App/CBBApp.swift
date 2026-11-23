// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import TipKit
import UserNotifications

@main
struct CBBApp: App {
    @StateObject private var model = AppModel.shared
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    init() {
        UNUserNotificationCenter.current().delegate = ForegroundNotifications.shared
        // Early, for a watch that asks while the app is not running.
        WatchLink.shared.start()
        // A recovery sheet's PDF that an ended app left behind.
        RecoveryPage.removePDF()
        // The settings' tips, each shown until it is closed.
        try? Tips.configure()
    }

    @Environment(\.scenePhase) private var scenePhase
    /// Whether the app was in the background (or not started) since it was
    /// last active.
    @State private var wasAway = true

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
        // The member follows the app to the front and to the background.
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.group.setForeground(phase == .active)
            model.group.setBackground(phase == .background)
            // The app's opening (D-128): what was copied here goes out, or
            // the group's copy comes in. Only from the background or at the
            // start: Control Center, a notification or a system prompt over
            // the app makes it inactive, and coming back from that is no
            // opening.
            if phase == .active, wasAway {
                Task { await model.opened() }
            }
            if phase == .active { wasAway = false }
            if phase == .background { wasAway = true }
            if phase == .background { BackgroundRefresh.schedule() }
        }
        .backgroundTask(.appRefresh(BackgroundRefresh.id)) {
            BackgroundRefresh.schedule()
            await AppModel.shared.refreshInBackground()
        }
    }
}
