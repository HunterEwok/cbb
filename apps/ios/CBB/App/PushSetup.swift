// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import Foundation
import os
import Security
import UIKit
import UserNotifications

/// Push to this phone while the app is closed (docs/core-api.md, "Push"):
/// asks iOS for the device token, keeps each group's registration in the
/// push keychain group the notification extension shares (`PushVault`),
/// keeps the push service's challenges for this phone's send key, and
/// answers the notification's Copy button. The member's sync sends the
/// saved registration to the group's members (the seam in
/// member/src/pusher.rs). A registration is made again only when what it
/// says changed (the token, the switch, a challenge, a membership change)
/// or a member asks (`push-renew`), never just because the app ran.
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
    private var group: (tag: String, me: Data, devices: PushVault.Devices, face: Data?)?
    /// The last problem, shown in Settings under the switch.
    private(set) var problem: String?

    var on: Bool { UserDefaults.standard.object(forKey: Self.onKey) as? Bool ?? true }

    /// At launch: the Copy button, and the token when on.
    func start() {
        let center = UNUserNotificationCenter.current()
        let copy = UNNotificationAction(identifier: Self.copyAction, title: String(localized: "Copy", bundle: .app), options: [])
        center.setNotificationCategories([UNNotificationCategory(identifier: Self.copyCategory, actions: [copy],
                                                                 intentIdentifiers: [], options: [])])
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

    /// The group, this phone's device ID in it and the group's devices
    /// (hex IDs, the root's among them), as the app applied them; nil when
    /// it has no group. A device gone or a new root draws a new push key,
    /// so a removed member's bodies open nothing here. `face` is the
    /// group's face for the push service (the `group` of the period's hubs'
    /// credential, 16 bytes), which every registration names; until the
    /// group gives one nothing is registered (a debug build draws one of
    /// its own, for the test tool).
    func group(tag: String?, me: String?, devices: [String] = [], root: String? = nil, face: Data? = nil) {
        guard let tag, let me, let id = Data(hex: me), id.count == 16 else {
            group = nil
            return
        }
        let applied = PushVault.Devices(members: devices.compactMap { Data(hex: $0) }, root: root.flatMap { Data(hex: $0) })
        let face = face ?? Self.testFace(tag)
        if group?.tag == tag, group?.me == id, group?.devices == applied, group?.face == face { return }
        group = (tag, id, applied, face)
        refresh()
    }

    /// The group's records are synced since `at` with `peers` (the hex IDs
    /// of members that stayed connected a while), and applied: a hints-only
    /// mark from before then is spent when those records say its change did
    /// not happen (PushMarks.synced).
    func synced(at: Date, peers: Set<String>) {
        guard let group, let g = try? vault.load(group.tag) else { return }
        PushMarks.synced(group.tag, at: at, peers: Set(peers.compactMap { Data(hex: $0) }), state: g,
                         in: PushMarks.defaults)
    }

    /// The phone is about to leave its group: the registration that turns
    /// push off there, saved as the group's frame for the members while the
    /// phone can still reach them.
    @discardableResult
    func leaving() -> Data? {
        guard Self.accessGroup != nil, let group else { return nil }
        do {
            return try vault.leaving(group.tag)?.frame
        } catch {
            fail(error)
            return nil
        }
    }

    /// Leaving failed: the phone stays, and push goes on as before.
    func stayed() { refresh() }

    /// The phone left its group: the group's push keys, slot, secrets and
    /// marks go, and the send key with them, so that what the left group's
    /// members hold stops being good (PushVault.left); the token stays.
    func left() {
        guard let group else { return }
        if Self.accessGroup != nil {
            do { try vault.left(group.tag) } catch { fail(error) }
        }
        PushMarks.forget(group.tag, in: PushMarks.defaults)
        self.group = nil
    }

    /// A debug build's face for a group that has not given one, so that the
    /// test tool has a registration to show; nil in a release build.
    private static func testFace(_ tag: String) -> Data? {
        #if DEBUG
        let key = "push.testFace.\(tag)"
        if let d = UserDefaults.standard.data(forKey: key), d.count == 16 { return d }
        var d = Data(count: 16)
        let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) } == errSecSuccess
        guard ok else { return nil }
        UserDefaults.standard.set(d, forKey: key)
        return d
        #else
        return nil
        #endif
    }

    #if DEBUG
    /// The group's registration frame in base64, for the test tool; never
    /// in a release build.
    func testFrame() -> String? {
        guard let group else { return nil }
        return (try? vault.load(group.tag))?.frame?.base64EncodedString()
    }
    #endif

    /// A challenge from the push service (24 bytes, from the notification's
    /// "k"): kept when it is for this phone's send key, and then the group
    /// registers again with it.
    func challenge(_ k: Data) {
        guard Self.accessGroup != nil else { return }
        if (try? vault.keep(challenge: k)) == true { refresh() }
    }

    /// A member asked for the registration of the group with this slot
    /// (`push-renew`): the push service lost it, or with `ahead` found its
    /// number more than a day past its clock, and the next one starts again
    /// from the phone's clock.
    func renew(slot: Data, ahead: Bool = false) {
        guard let group, (try? vault.group(slot: slot)) == group.tag else { return }
        refresh(reasons: ahead ? [.renew, .ahead] : .renew)
    }

    /// What opens a copy here, which the app writes on every rotation of
    /// its sealing key and whenever the group's devices change: the sealing
    /// secrets of the epochs in the group's window (any other is erased),
    /// the devices as origins, the window and whether the group is halted.
    func opening(sealing: [Push.Sealing], origins: [Push.Origin], windowMS: UInt64?, halted: Bool) {
        guard Self.accessGroup != nil, let group else { return }
        do {
            try vault.opening(group.tag, sealing: sealing, origins: origins, windowMS: windowMS, halted: halted)
        } catch {
            fail(error)
        }
    }

    private func refresh(reasons: PushVault.Reasons = []) {
        guard Self.accessGroup != nil, let group else { return }
        do {
            if on, let token {
                guard let face = group.face else {
                    // Nothing to name yet: the group registers once it gives
                    // its face. Not a problem to show.
                    Self.log.info("push: no face for the group yet, nothing registered")
                    return
                }
                try vault.register(group.tag, me: group.me, token: token, env: Self.env(), kinds: [.copies, .events],
                                   face: face, reasons: reasons, devices: group.devices)
            } else {
                try vault.register(group.tag, me: group.me, token: nil, env: nil, kinds: [], devices: group.devices)
            }
            // A hints-only mark whose change is now applied, with its new
            // key in place, is spent.
            PushMarks.spend(group.tag, try vault.load(group.tag), in: PushMarks.defaults)
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
