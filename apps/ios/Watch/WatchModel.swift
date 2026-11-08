// SPDX-License-Identifier: AGPL-3.0-only

import CryptoKit
import Foundation
import LocalAuthentication
import os
import WatchConnectivity
import WatchKit

private let log = Logger(subsystem: "tools.cbb.watch", category: "watch")

/// The group as the phone last told it, and the away switch, which asks
/// the phone; the watch's admin key, which the root phone certifies when
/// asked (WatchKey).
@MainActor
final class WatchModel: NSObject, ObservableObject {
    @Published private(set) var state = WatchState()
    /// Whether the phone answers now; the state may be old without it.
    @Published private(set) var reachable = false
    @Published private(set) var switching = false
    /// What the last switch said, when it failed.
    @Published private(set) var note: String?
    /// The admin CA the root gave this watch, if it did.
    @Published private(set) var admission = WatchKey.admission
    /// Whether an emergency action is on its way, and what the last one said.
    @Published private(set) var acting = false
    @Published private(set) var actionNote: String?
    @Published private(set) var actionDone = false

    enum ActionFailure: Error {
        /// The phone's body says something else than the watch asked.
        case mismatch
        case refused(String)
    }

    /// Runs an emergency action (docs/protocol.md, section 10, "Watches"): the
    /// phone builds the body, the watch checks that it says what was asked,
    /// checks that it is on the wrist, signs with its admin key, and the
    /// phone brings the result into the group.
    func run(_ action: String, on device: String, name: String? = nil) async {
        guard let a = admission else { return }
        acting = true
        actionNote = nil
        actionDone = false
        defer { acting = false }
        do {
            guard WCSession.default.isReachable else {
                actionNote = String(localized: "Open CBB on the iPhone, then try again.")
                return
            }
            let ask = WatchState.Ask(action: action, device: device, name: name, watch: a.device)
            let reply = try await send([WatchState.askKey: try JSONEncoder().encode(ask)])
            guard let body = reply[WatchState.bodyKey] as? Data else {
                throw ActionFailure.refused(reply[WatchState.refusedKey] as? String ?? "")
            }
            try Self.check(body, ask: ask, admission: a)
            let ok = try await LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithWristDetection,
                                                          localizedReason: String(localized: "Sign the action with this watch's key"))
            guard ok, let key = try WatchKey.adminKey() else { throw WatchKey.Failure.notProtected }
            let signed = WatchState.Signed(body: body, signature: try key.signature(for: body).derRepresentation, adminCA: a.adminCA)
            let done = try await send([WatchState.signedKey: try JSONEncoder().encode(signed)])
            guard done[WatchState.doneKey] as? Bool == true else {
                throw ActionFailure.refused(done[WatchState.refusedKey] as? String ?? "")
            }
            actionDone = true
            actionNote = String(localized: "Done.")
        } catch ActionFailure.refused(let why) {
            actionNote = why.isEmpty ? String(localized: "The iPhone did not do it. Try again.") : why
        } catch {
            log.error("emergency action failed: \(String(reflecting: error), privacy: .public)")
            actionNote = String(localized: "The action was not signed. Keep the watch on your wrist, then try again.")
        }
    }

    /// Whether body, which the phone built, says what the watch asked: the
    /// type, the group, the watch as its signer and, for a command, its
    /// device and quick action. The keys a freeze or a removal names are
    /// the phone's to pick; the watch cannot check them.
    nonisolated static func check(_ body: Data, ask: WatchState.Ask, admission a: WatchState.Admission) throws {
        guard let o = try JSONSerialization.jsonObject(with: body) as? [String: Any] else { throw ActionFailure.mismatch }
        let type = ask.action == "remove" ? "revoke" : ask.action
        guard o["type"] as? String == type, o["group"] as? String == a.group, o["by"] as? String == a.device else {
            throw ActionFailure.mismatch
        }
        if type != "freeze", type != "revoke" {
            guard o["to"] as? String == ask.device else { throw ActionFailure.mismatch }
            if type == "action", o["action"] as? String != ask.name { throw ActionFailure.mismatch }
        }
    }

    private func send(_ message: [String: Any]) async throws -> [String: Any] {
        nonisolated(unsafe) let m = message
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<[String: Any], Error>) in
            WCSession.default.sendMessage(m, replyHandler: { reply in
                nonisolated(unsafe) let r = reply
                c.resume(returning: r)
            }, errorHandler: { c.resume(throwing: $0) })
        }
    }

    override init() {
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }

    /// Turns the phone's sync away from home on or off, as its globe does.
    func setAway(_ on: Bool) { ask(WatchState.awayKey, on) }

    /// Turns the phone's sync on or off, as its house does.
    func setSync(_ on: Bool) { ask(WatchState.syncKey, on) }

    /// Asks the phone to turn a switch, and takes its new state.
    private func ask(_ key: String, _ on: Bool) {
        let session = WCSession.default
        guard session.isReachable else {
            note = String(localized: "Open CBB on the iPhone, then try again.")
            return
        }
        switching = true
        note = nil
        session.sendMessage([key: on], replyHandler: { reply in
            let s = WatchState(reply)
            Task { @MainActor in
                if let s {
                    self.state = s
                    self.forgetIfLeft(s)
                }
                self.switching = false
            }
        }, errorHandler: { error in
            log.error("\(key, privacy: .public) not switched: \(String(reflecting: error), privacy: .public)")
            Task { @MainActor in
                self.switching = false
                self.note = String(localized: "The iPhone did not answer. Try again.")
            }
        })
    }

    /// Answers the root phone: a new key to certify, or the admin CA it
    /// certified.
    fileprivate func answer(_ message: [String: Any]) -> [String: Any] {
        if message[WatchState.certifyKey] != nil {
            do {
                let r = try WatchKey.request(name: WKInterfaceDevice.current().name)
                return [WatchState.requestKey: try JSONEncoder().encode(r)]
            } catch let e as WatchKey.Failure where e == .notProtected {
                return [WatchState.refusedKey: WatchState.notProtected]
            } catch let e as WatchKey.Failure where e == .noSecureEnclave {
                return [WatchState.refusedKey: WatchState.noSecureEnclave]
            } catch {
                log.error("no admin key made: \(String(reflecting: error), privacy: .public)")
                return [WatchState.refusedKey: String(reflecting: error)]
            }
        }
        if let d = message[WatchState.admittedKey] as? Data {
            do {
                try WatchKey.admit(try JSONDecoder().decode(WatchState.Admission.self, from: d))
                admission = WatchKey.admission
                return [WatchState.admittedKey: true]
            } catch {
                log.error("admission not kept: \(String(reflecting: error), privacy: .public)")
                return [WatchState.refusedKey: String(reflecting: error)]
            }
        }
        return [:]
    }

    private func take(_ context: [String: Any]) {
        if let s = WatchState(context) {
            state = s
            forgetIfLeft(s)
        }
    }

    /// Forgets the admin key once the phone is in no group or in another
    /// one than the root certified the key in: the phone left its group
    /// (D-83), and the key signs for nothing any more.
    private func forgetIfLeft(_ s: WatchState) {
        guard let a = admission, !s.hasGroup || (s.group != nil && s.group != a.group) else { return }
        WatchKey.forget()
        admission = nil
        log.notice("the phone left the group: the watch's admin key is deleted")
    }
}

extension WatchModel: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {
        if let error { log.error("watch session: \(String(reflecting: error), privacy: .public)") }
        let context = session.receivedApplicationContext, reachable = session.isReachable
        nonisolated(unsafe) let c = context
        Task { @MainActor in
            self.take(c)
            self.reachable = reachable
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext context: [String: Any]) {
        nonisolated(unsafe) let c = context
        Task { @MainActor in self.take(c) }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        nonisolated(unsafe) let m = message, reply = replyHandler
        Task { @MainActor in reply(self.answer(m)) }
    }

    nonisolated func sessionReachabilityDidChange(_ session: WCSession) {
        let reachable = session.isReachable
        Task { @MainActor in self.reachable = reachable }
    }
}
