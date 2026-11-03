// SPDX-License-Identifier: AGPL-3.0-only

import BackgroundTasks
import os

private let log = Logger(subsystem: "tools.cbb", category: "refresh")

/// Background app refresh: until the app has push notifications (they need
/// the Apple developer account), iOS now and then runs it for a few seconds
/// in the background, at times it picks from how the phone is used, and the
/// app hears of the group's events then (docs/apps.md, Notifications). iOS
/// runs none with Background App Refresh off or in Low Power Mode.
enum BackgroundRefresh {
    /// The task's identifier, in Info.plist's BGTaskSchedulerPermittedIdentifiers.
    static let id = "tools.cbb.refresh"

    /// The soonest the app asks to run again; iOS decides when it does.
    static let interval: TimeInterval = 15 * 60

    /// Asks iOS for the next run, in place of one asked before.
    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: id)
        request.earliestBeginDate = Date(timeIntervalSinceNow: interval)
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            // In the simulator, and with Background App Refresh off.
            log.notice("background refresh not scheduled: \(error.localizedDescription, privacy: .public)")
        }
    }
}
