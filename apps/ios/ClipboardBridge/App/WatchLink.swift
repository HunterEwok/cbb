// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import Foundation
import os
import UIKit
import WatchConnectivity

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "watch")

/// The phone's side of the Apple Watch app: it hands the watch the group as
/// the app sees it, and turns sync away from home on or off when the watch
/// asks (docs/apps.md, Apple Watch); on the root phone it asks the watch for
/// its admin key and hands it the admin CA (docs/protocol.md, section 10,
/// rule 8).
@MainActor
final class WatchLink: NSObject {
    static let shared = WatchLink()

    private var session: WCSession? { WCSession.isSupported() ? WCSession.default : nil }
    private var last: WatchState?

    /// Starts the session once; a phone without a paired watch has nothing
    /// to send to.
    func start() {
        guard let session, session.delegate == nil else { return }
        session.delegate = self
        session.activate()
    }

    /// Sends the state when it changed and a watch app is there to read it.
    func update(_ model: AppModel) {
        start()
        let state = Self.state(model)
        guard state != last, let session, session.activationState == .activated, session.isWatchAppInstalled else { return }
        do {
            try session.updateApplicationContext(state.data)
            last = state
        } catch {
            log.error("watch not updated: \(String(reflecting: error), privacy: .public)")
        }
    }

    enum Failure: Error {
        /// No paired watch with the app open.
        case notReachable
        /// The watch has no passcode, or its wrist detection is off.
        case notProtected
        case noSecureEnclave
        case refused(String)
    }

    /// Whether a paired watch has the app.
    var watchApp: Bool {
        guard let session, session.activationState == .activated else { return false }
        return session.isPaired && session.isWatchAppInstalled
    }

    /// Asks the watch, whose app must be open, to make a new admin key.
    func keyRequest() async throws -> WatchState.KeyRequest {
        let reply = try await send([WatchState.certifyKey: true])
        if let d = reply[WatchState.requestKey] as? Data { return try JSONDecoder().decode(WatchState.KeyRequest.self, from: d) }
        switch reply[WatchState.refusedKey] as? String {
        case WatchState.notProtected: throw Failure.notProtected
        case WatchState.noSecureEnclave: throw Failure.noSecureEnclave
        case let why: throw Failure.refused(why ?? "")
        }
    }

    /// Hands the watch the admin CA the root issued for its key.
    func admit(_ a: WatchState.Admission) async throws {
        let reply = try await send([WatchState.admittedKey: try JSONEncoder().encode(a)])
        guard reply[WatchState.admittedKey] as? Bool == true else { throw Failure.refused(reply[WatchState.refusedKey] as? String ?? "") }
    }

    private func send(_ message: [String: Any]) async throws -> [String: Any] {
        start()
        guard let session, session.isReachable else { throw Failure.notReachable }
        nonisolated(unsafe) let m = message
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<[String: Any], Error>) in
            session.sendMessage(m, replyHandler: { reply in
                nonisolated(unsafe) let r = reply
                c.resume(returning: r)
            }, errorHandler: { c.resume(throwing: $0) })
        }
    }

    func eventsChanged() {
        update(AppModel.shared)
    }

    static func state(_ model: AppModel) -> WatchState {
        var s = WatchState()
        s.hasGroup = model.phase == .home
        // In the user's order, a collection's devices one after another.
        let arranged: [(AppModel.Computer, String?)] = model.arranged.flatMap { item -> [(AppModel.Computer, String?)] in
            switch item {
            case .device(let d): [(d, nil)]
            case .collection(let c, let ds): ds.map { ($0, c.name) }
            }
        }
        // The phone itself first, as the phone's own list has it.
        let me = model.devices.first(where: \.isSelf).map {
            WatchState.Device(id: $0.id, name: $0.name, symbol: $0.kind.symbol, online: true, can: [], phone: true)
        }
        s.devices = (me.map { [$0] } ?? []) + arranged.map { d, c in
            WatchState.Device(id: d.id, name: d.name, symbol: d.kind.symbol, online: d.online,
                              can: model.group.watchActions(for: d.id), actions: d.actions, collection: c)
        }
        s.away = model.away.map { a in
            guard a.on else { return .off }
            switch a.status {
            case .atHome: return .atHome
            case .connecting: return .connecting
            case .connected: return .connected
            case .off, .waitingForHub: return .waiting
            }
        }
        s.events = Notifier.shared.recent
        s.color = UserDefaults.standard.string(forKey: AccentChoice.key) ?? Tokens.colors[0].name
        return s
    }
}

extension WatchLink {
    /// The body of the emergency action the watch asks for.
    static func body(for data: Data) -> [String: Any] {
        do {
            let ask = try JSONDecoder().decode(WatchState.Ask.self, from: data)
            return [WatchState.bodyKey: try AppModel.shared.group.watchBody(ask)]
        } catch {
            return [WatchState.refusedKey: AppModel.describe(error)]
        }
    }

    /// Brings what the watch signed into the group, in a background task:
    /// the watch may have woken the app.
    static func deliver(_ data: Data) async -> [String: Any] {
        let task = UIApplication.shared.beginBackgroundTask(withName: "watch action")
        defer { UIApplication.shared.endBackgroundTask(task) }
        do {
            let signed = try JSONDecoder().decode(WatchState.Signed.self, from: data)
            try await AppModel.shared.group.deliverFromWatch(signed)
            await AppModel.shared.refresh()
            return [WatchState.doneKey: true]
        } catch MemberNode.Failure.notConnected {
            return [WatchState.refusedKey: String(localized: "The iPhone is not connected to that device. Open Clipboard Bridge on the iPhone, then try again.", bundle: .app)]
        } catch {
            return [WatchState.refusedKey: AppModel.describe(error)]
        }
    }
}

extension WatchLink: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {
        if let error { log.error("watch session: \(String(reflecting: error), privacy: .public)") }
        Task { @MainActor in self.update(AppModel.shared) }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    /// After the user switches to another watch.
    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }

    /// The watch's away switch: the same as the one in Settings.
    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        nonisolated(unsafe) let reply = replyHandler
        if let d = message[WatchState.askKey] as? Data {
            Task { @MainActor in reply(Self.body(for: d)) }
            return
        }
        if let d = message[WatchState.signedKey] as? Data {
            Task { @MainActor in reply(await Self.deliver(d)) }
            return
        }
        guard let on = message[WatchState.awayKey] as? Bool else { return replyHandler([:]) }
        Task { @MainActor in
            let model = AppModel.shared
            await model.setAway(on)
            reply(Self.state(model).data)
        }
    }
}
