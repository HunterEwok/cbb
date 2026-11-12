// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import Foundation
import UserNotifications

/// Opens a push body when it arrives with the app closed (docs/core-api.md,
/// "Push"): it tries each group's push keys from the push keychain group,
/// which holds what opens a body and a copy (the push keys, the send key,
/// the sealing secrets of the epochs in the group's window) and nothing
/// that signs a record, and shows what `push_open` found. Only a copy whose
/// origin's signature holds shows its text, never a secret's; the rest says
/// "open the app". The words are the app's translations (apps/l10n, place
/// `ios-push`), never a string from the body.
final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var content: UNMutableNotificationContent?

    /// The push app group's defaults (`PushMarks.appGroup`, the
    /// extension's only app group): the IDs already shown and the
    /// hints-only marks, nothing secret.
    private static let defaults = PushMarks.defaults
    private static let shownKey = "push.shown"
    private static let shownMax = 200

    override func didReceive(_ request: UNNotificationRequest, withContentHandler handler: @escaping (UNNotificationContent) -> Void) {
        self.handler = handler
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        self.content = content
        let info = request.content.userInfo
        Self.neutral(content)
        // A challenge beside the body: kept only for this phone's send key.
        if let k = info["k"] as? String, let challenge = Data(base64Encoded: k) {
            _ = try? Self.vault.keep(challenge: challenge)
        }
        if let b64 = info["c"] as? String, let body = Data(base64Encoded: b64),
           let (group, opened) = Self.open(body) {
            Self.show(opened, group: group, in: content)
        }
        handler(content)
        self.handler = nil
    }

    override func serviceExtensionTimeWillExpire() {
        guard let handler, let content else { return }
        Self.neutral(content)
        handler(content)
        self.handler = nil
    }

    private static var vault: PushVault {
        let group = (Bundle.main.object(forInfoDictionaryKey: "CBBPushKeychain") as? String).flatMap { $0.isEmpty ? nil : $0 }
        return PushVault(accessGroup: group)
    }

    /// The body opened with the first group whose keys open it.
    static func open(_ body: Data) -> (String, Push.Opened)? {
        let vault = vault
        for group in (try? vault.groups()) ?? [] {
            guard let g = try? vault.load(group),
                  let c = g.context(hintsOnly: PushMarks.hintsOnly(group, g, in: defaults))
            else { continue }
            if let o = try? Push.open(body, in: c) { return (group, o) }
        }
        return nil
    }

    static func neutral(_ c: UNMutableNotificationContent) {
        c.title = ""
        c.body = String(localized: "New in your group. Open the app.")
        c.categoryIdentifier = ""
        c.userInfo = [:]
    }

    static func show(_ o: Push.Opened, group: String, in c: UNMutableNotificationContent) {
        // A body seen before says nothing new: the neutral hint.
        if let id = o.id {
            if shown(id) { return }
            remember(id)
            c.threadIdentifier = id.base64EncodedString()
        }
        switch o.kind {
        case "copy":
            c.title = String(localized: "New copy")
            if o.secret == true {
                c.body = String(localized: "A secret was copied. Open the app to see it.")
            } else if o.type == "text", let text = o.text, !text.isEmpty {
                c.body = String(text.prefix(300))
                c.userInfo = ["text": text]
                c.categoryIdentifier = "copy"
            } else {
                c.body = String(localized: "A copy is waiting. Open the app.")
            }
        case "waits":
            c.body = String(localized: "A copy is waiting. Open the app.")
        case "event":
            c.body = event(o.event ?? 0)
            // A removal, a new root or a stop: hints only until the app has
            // applied it and drawn a new push key.
            if [2, 4, 6].contains(o.event ?? 0) {
                PushMarks.mark(group, event: o.event ?? 0, device: o.device, in: defaults)
            }
        default:
            break
        }
    }

    static func event(_ e: UInt64) -> String {
        switch e {
        case 1: String(localized: "A device joined your group. Open the app to see it.")
        case 2: String(localized: "A device was removed from your group. Open the app to check.")
        case 3: String(localized: "A device is waiting to join your group. Open the app.")
        case 4: String(localized: "Your group's root changed. Open the app to check.")
        case 5: String(localized: "This device's record changed. Open the app to check.")
        case 6: String(localized: "Your group stopped. Open the app to check.")
        default: String(localized: "New in your group. Open the app.")
        }
    }

    private static func shown(_ id: Data) -> Bool {
        (defaults?.stringArray(forKey: shownKey) ?? []).contains(id.base64EncodedString())
    }

    private static func remember(_ id: Data) {
        var list = defaults?.stringArray(forKey: shownKey) ?? []
        list.append(id.base64EncodedString())
        defaults?.set(Array(list.suffix(shownMax)), forKey: shownKey)
    }
}
