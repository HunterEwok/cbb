// SPDX-License-Identifier: AGPL-3.0-only

import AppIntents
import Foundation
import WidgetKit

/// The house in Control Center (docs/apps.md): sync on this phone, which
/// the app keeps in the shared settings so the control shows it.
enum SyncSwitch {
    static let kind = "tools.cbb.sync-control"
    private static let key = "SyncOn"

    /// Whether sync is on on this phone; nil without a group.
    static var isOn: Bool? { Shared.defaults.object(forKey: key) as? Bool }

    /// Keeps the app's state for the control, nil without a group, and
    /// asks Control Center to draw it again when it changed.
    static func publish(_ on: Bool?) {
        guard isOn != on else { return }
        if let on { Shared.defaults.set(on, forKey: key) } else { Shared.defaults.removeObject(forKey: key) }
        if #available(iOS 18.0, *) { ControlCenter.shared.reloadControls(ofKind: kind) }
    }
}

/// A tap on the house in Control Center turns sync on or off. As a Live
/// Activity intent it runs in the app's process, which iOS starts in the
/// background when it is not running, so the member changes at once.
/// Without a group it changes nothing.
struct SetSyncIntent: SetValueIntent, LiveActivityIntent {
    static let title: LocalizedStringResource = "Sync"
    static let isDiscoverable = false

    @Parameter(title: "Sync")
    var value: Bool

    init() {}

    @MainActor
    func perform() async throws -> some IntentResult {
        #if CBB_APP
        if AppModel.shared.group.hasGroup { AppModel.shared.turnSync(value) }
        #endif
        return .result()
    }
}
