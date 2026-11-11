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

    var body: some Scene {
        WindowGroup {
            // TEMPORARY: the restore link's variants for one test run.
            if ProcessInfo.processInfo.arguments.contains("-restoreLinkExperiment") {
                RestoreLinkExperiment()
            } else {
                RootView()
                    .environmentObject(model)
            }
        }
        // The phone is the group's hub while the app is open (D-64).
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.group.setForeground(phase == .active)
            model.group.setBackground(phase == .background)
            // A copy from another device that waits comes in as the app
            // opens, and what was copied here goes out.
            if phase == .active {
                Task {
                    await model.takePending()
                    await model.sendOnOpen()
                }
            }
            if phase == .background { BackgroundRefresh.schedule() }
        }
        .backgroundTask(.appRefresh(BackgroundRefresh.id)) {
            BackgroundRefresh.schedule()
            await AppModel.shared.refreshInBackground()
        }
    }
}
