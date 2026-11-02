// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI
import UserNotifications

@main
struct ClipboardBridgeApp: App {
    @StateObject private var model = AppModel.shared
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    init() {
        Appearance.migrate()
        UNUserNotificationCenter.current().delegate = ForegroundNotifications.shared
        // Early, for a watch that asks while the app is not running.
        WatchLink.shared.start()
    }

    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
        // The phone is the group's hub while the app is open (D-64).
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.group.setForeground(phase == .active)
            if phase == .background { BackgroundRefresh.schedule() }
        }
        .backgroundTask(.appRefresh(BackgroundRefresh.id)) {
            BackgroundRefresh.schedule()
            await AppModel.shared.refreshInBackground()
        }
    }
}
