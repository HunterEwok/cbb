// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import Foundation
import os
import UIKit
import UserNotifications

/// Push to this phone while the app is closed (docs/core-api.md, "Push"):
/// asks iOS for the device token, keeps each group's registration in the
/// push keychain group the notification extension shares (`PushVault`),
/// and answers the notification's Copy button. The member's sync sends the
/// saved registration to the group's members (the seam in
/// member/src/pusher.rs).
@MainActor
final class PushSetup {
    static let shared = PushSetup()

    /// The user's switch in Settings, on unless turned off.
    static let onKey = "push.on"
    /// The notification's category with the Copy button, and the button.
    static let copyCategory = "copy"
    nonisolated static let copyAction = "copy"

    private static let log = Logger(subsystem: "tools.cbb", category: "push")

    /// The push keychain group: set in release builds, empty in debug ones
    /// signed ad hoc, which have neither the entitlement nor push.
    nonisolated static var accessGroup: String? {
        (Bundle.main.object(forInfoDictionaryKey: "CBBPushKeychain") as? String).flatMap { $0.isEmpty ? nil : $0 }
    }

    let vault = PushVault(accessGroup: PushSetup.accessGroup)
    private var token: Data?
    private var group: (tag: String, me: Data)?
    /// The last problem, shown in Settings under the switch.
    private(set) var problem: String?

    var on: Bool { UserDefaults.standard.object(forKey: Self.onKey) as? Bool ?? true }

    /// At launch: the Copy button, and the token when on.
    func start() {
        let center = UNUserNotificationCenter.current()
        let copy = UNNotificationAction(identifier: Self.copyAction, title: String(localized: "Copy", bundle: .app), options: [])
        center.setNotificationCategories([UNNotificationCategory(identifier: Self.copyCategory, actions: [copy],
                                                                 intentIdentifiers: [], options: [])])
        // The app ran: copies are shown again, not only hints.
        Shared.defaults.removeObject(forKey: Self.hintsOnlyKey)
        guard Self.accessGroup != nil else { return }
        if on { ask() } else { refresh() }
    }

    /// The user turned the switch.
    func set(on: Bool) {
        UserDefaults.standard.set(on, forKey: Self.onKey)
        if on { ask() } else { refresh() }
    }

    private func ask() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            Task { @MainActor in
                if let error { self.fail(error) }
                if granted { UIApplication.shared.registerForRemoteNotifications() }
            }
        }
    }

    /// iOS gave the device token.
    func got(token: Data) {
        self.token = token
        refresh()
    }

    func failed(_ error: Error) { fail(error) }

    /// The group and this phone's device ID in it (hex), as the app knows
    /// them; nil when it has no group.
    func group(tag: String?, me: String?) {
        guard let tag, let me, let id = Data(hex: me), id.count == 16 else {
            group = nil
            return
        }
        if group?.tag == tag, group?.me == id { return }
        group = (tag, id)
        refresh()
    }

    /// The group's registration frame in base64, for the test tool.
    func testFrame() -> String? {
        guard let group else { return nil }
        return (try? vault.load(group.tag))?.frame?.base64EncodedString()
    }

    /// The phone applied a removal, a new root or a stop: a new push key, so
    /// a removed member's bodies open nothing here.
    func membershipChanged() { refresh(newKey: true) }

    private func refresh(newKey: Bool = false) {
        guard Self.accessGroup != nil, let group else { return }
        do {
            if on, let token {
                try vault.register(group.tag, me: group.me, token: token, env: Self.env(), kinds: [.copies, .events],
                                   newKey: newKey)
            } else if (try? vault.load(group.tag).kinds) ?? 0 != 0 {
                try vault.register(group.tag, me: group.me, token: nil, env: nil, kinds: [])
            }
            problem = nil
        } catch {
            fail(error)
        }
    }

    private func fail(_ error: Error) {
        problem = AppModel.describe(error, summary: String(localized: "Notifications while the app is closed could not be set up.", bundle: .app))
        Self.log.error("push: \(String(reflecting: error), privacy: .public)")
    }

    /// The APNs environment this build was signed for: the provisioning
    /// profile says `development` for a development build; App Store and
    /// TestFlight builds carry no profile and use production.
    nonisolated static func env() -> UInt64 {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .isoLatin1),
              let key = text.range(of: "<key>aps-environment</key>") else { return Push.Env.apns }
        let rest = text[key.upperBound...].prefix(80)
        return rest.contains("<string>development</string>") ? Push.Env.apnsSandbox : Push.Env.apns
    }

    /// Set by the extension after an event of removal, a new root or a stop;
    /// cleared when the app runs (app group defaults, nothing secret).
    nonisolated static let hintsOnlyKey = "push.hintsOnly"

    /// The Copy button of a notification: its text to the clipboard
    /// (ForegroundNotifications, the center's delegate, hands it here).
    nonisolated static func answered(_ response: UNNotificationResponse) async {
        guard response.actionIdentifier == copyAction,
              let text = response.notification.request.content.userInfo["text"] as? String else { return }
        await MainActor.run { UIPasteboard.general.string = text }
    }
}

extension Data {
    /// Bytes from hex; nil for anything else.
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        self = out
    }
}
