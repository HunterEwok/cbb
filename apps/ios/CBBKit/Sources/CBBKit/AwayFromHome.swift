// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// What sync away from home keeps on the phone (docs/protocol.md, section
/// 11): its WireGuard private key, made on the phone, the preshared key it
/// chose for its tunnels, which its hellos offer every hub, and the last
/// offer of each of the group's hubs, by the hub's device ID.
public struct AwayState: Codable, Equatable, Sendable {
    /// A hub's offer, as the phone keeps it.
    public struct Hub: Codable, Equatable, Sendable {
        public var device: String
        public var offer: Member.TunnelOffer

        public init(device: String, offer: Member.TunnelOffer) { (self.device, self.offer) = (device, offer) }
    }

    /// The most hubs whose offers the phone keeps.
    public static let maxHubs = 255

    public var key: Data
    public var psk: Data
    public var hubs: [Hub]

    public init(key: Data, psk: Data = AwayState.newPSK(), hubs: [Hub] = []) {
        (self.key, self.psk, self.hubs) = (key, psk, hubs)
    }

    /// The offer of the hub hub, or nil.
    public func offer(_ hub: String) -> Member.TunnelOffer? { hubs.first { $0.device == hub }?.offer }

    /// The same with offer as hub's, in place of its earlier one.
    public func with(_ hub: String, offer: Member.TunnelOffer) -> AwayState {
        var s = self
        if let i = s.hubs.firstIndex(where: { $0.device == hub }) {
            s.hubs[i].offer = offer
        } else {
            s.hubs = Array((s.hubs + [Hub(device: hub, offer: offer)]).suffix(Self.maxHubs))
        }
        return s
    }

    /// The same without the offer of hub.
    public func without(_ hub: String) -> AwayState {
        var s = self
        s.hubs.removeAll { $0.device == hub }
        return s
    }

    public func encoded() throws -> Data { try JSONEncoder().encode(self) }

    /// The state in data, or nil when it is not one this version wrote.
    public static func decode(_ data: Data) -> AwayState? {
        guard let s = try? JSONDecoder().decode(AwayState.self, from: data), s.key.count == 32, s.psk.count == 32,
              s.hubs.allSatisfy(\.offer.isValid) else { return nil }
        return s
    }

    public static func newPSK() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }
}

/// A running tunnel to the hub: a loopback port that leads to the hub's
/// member port.
public protocol OpenTunnel: AnyObject, Sendable {
    var port: UInt16 { get }
    func setEndpoint(_ endpoint: String) throws
    func close()
}

/// Makes keys and tunnels; the app's come from mobile/cbbtun, the tests'
/// from a fake.
public protocol Tunnels: Sendable {
    func newKey() throws -> Data
    func publicKey(_ privateKey: Data) throws -> Data
    /// Starts a tunnel; obfuscation is the offer's settings as JSON, "" for
    /// plain WireGuard, and vless its way over VLESS as JSON, "" without it.
    func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String,
               obfuscation: String, vless: String) throws -> OpenTunnel
}

/// Sync away from home on this phone: off until the user turns it on. Then
/// the hellos offer the phone's WireGuard key and its preshared key, every
/// hub's answer is kept, and while no hub is on the home network the phone
/// reaches the first hub in the group's order that answers through the
/// tunnel, in the app's own process, with the same member TLS as at home
/// (docs/design.md, "Sync away from home"; docs/protocol.md, section 11,
/// "Several hubs"). On a hub below the first it tries the ones above again
/// every upCheck. It fails closed: without a tunnel there is no connection.
public actor AwayFromHome {
    /// What the screens show.
    public enum Status: Sendable { case off, waitingForHub, atHome, connecting, connected }

    public typealias Dial = @Sendable (_ port: UInt16, _ hub: String) async throws -> ClosableTransport
    public typealias Serve = @Sendable (ClosableTransport, _ hub: String) async throws -> Void

    private let device: String
    private let tunnels: Tunnels
    private let save: @Sendable (AwayState?) throws -> Void
    private let atHome: @Sendable (String) async -> Bool
    private let dial: Dial
    private let serve: Serve
    private let mayHost: @Sendable (String) -> Bool
    private let order: @Sendable () -> [String]
    private let log: @Sendable (String, Error) -> Void
    private let firstWait: Duration
    private let maxWait: Duration
    private let isPhone: @Sendable (String) -> Bool
    private let phoneWait: Duration
    private let homeCheck: Duration
    private let upCheck: Duration

    private var state: AwayState?
    private var tunnel: OpenTunnel?
    /// The hub and offer the open tunnel goes to.
    private var tunnelTo: AwayState.Hub?
    /// The hub the phone reaches now, through the tunnel or at home.
    private var using: String?
    /// Which of the endpoints the next try takes, for each hub and each
    /// of its keys: the hub with its next key comes right after it in the
    /// list, and one count for both would give each key only every other
    /// endpoint.
    private var endpointOf: [String: Int] = [:]
    /// The connection to the hub in use, which a new offer closes.
    private var conn: ClosableTransport?
    private var runner: Task<Void, Never>?
    private var nap: Task<Void, Never>?
    /// Counts the changes the loop waits for: the loop notes the count as
    /// it reads the state and waits only while it is the same, so a change
    /// made while the loop is not waiting (as it connects, or serves a
    /// connection that the change then closes) is not missed.
    private var changes = 0
    private var seen = 0

    public private(set) var status = Status.off
    public private(set) var lastError: Error?

    /// state is what load read; save keeps each change, nil when it is
    /// turned off. atHome tells whether a hub is found on the home
    /// network, where it is dialed directly; dial reaches the hub's member
    /// TLS through the loopback port, checking that the peer is the hub;
    /// serve runs a connection until it ends; mayHost tells whether a device
    /// may be a hub: the group's root or an admin (RecordSet.mayHost);
    /// order gives the group's hubs, highest first (RecordSet.hubOrder),
    /// and only these are tried; isPhone tells whether a hub is a phone,
    /// there only while its app is open (docs/design.md, "The phone as the
    /// hub"), tried at least every phoneWait; upCheck is how long the phone
    /// stays on a hub below the first before it tries the ones above again.
    public init(device: String, tunnels: Tunnels, state: AwayState?, save: @escaping @Sendable (AwayState?) throws -> Void,
                atHome: @escaping @Sendable (String) async -> Bool, dial: @escaping Dial, serve: @escaping Serve,
                mayHost: @escaping @Sendable (String) -> Bool,
                order: @escaping @Sendable () -> [String],
                log: @escaping @Sendable (String, Error) -> Void = { _, _ in },
                firstWait: Duration = .seconds(1), maxWait: Duration = .seconds(30),
                isPhone: @escaping @Sendable (String) -> Bool = { _ in false }, phoneWait: Duration = .seconds(5),
                homeCheck: Duration = .seconds(5), upCheck: Duration = .seconds(300)) {
        (self.device, self.tunnels, self.state, self.save) = (device, tunnels, state, save)
        (self.atHome, self.dial, self.serve, self.log, self.mayHost, self.order) = (atHome, dial, serve, log, mayHost, order)
        (self.firstWait, self.maxWait, self.homeCheck, self.upCheck) = (firstWait, maxWait, homeCheck, upCheck)
        (self.isPhone, self.phoneWait) = (isPhone, phoneWait)
    }

    public var isOn: Bool { state != nil }

    /// The public key the hellos offer the hubs; nil while it is off.
    public var publicKey: Data? {
        guard let k = state?.key else { return nil }
        return try? tunnels.publicKey(k)
    }

    /// The preshared key the hellos offer with the public key; nil while it is off.
    public var psk: Data? { state?.psk }

    /// Turns it on with new keys; the hubs' offers come at home, on the
    /// next connection to them.
    public func turnOn() throws {
        let s = AwayState(key: try tunnels.newKey())
        try save(s)
        state = s
        poke()
    }

    /// Turns it off: forgets the keys and the offers and closes the tunnel.
    public func turnOff() throws {
        try save(nil)
        state = nil
        closeTunnel()
        poke()
    }

    /// Keeps the offer a peer sent for this phone's key (docs/protocol.md,
    /// section 11, "Several hubs"): from a hub, the group's root or an
    /// admin, its own or another hub's that it passes on, for each hub in
    /// place of its earlier one. An offer marked moved makes the phone
    /// forget the sender's own. A new offer for the hub in use, or one for
    /// a hub above it, starts the tunnel again.
    public func keep(from: String?, offer received: Member.TunnelOffer) {
        guard let from, received.isValid, mayHost(from), let s = state else { return }
        let hub = received.hub ?? from
        guard hub != device, mayHost(hub) else { return }
        let offer = received.with(psk: received.psk, hub: nil)
        let forgot = received.moved && from != hub && s.offer(from) != nil
        var n = forgot ? s.without(from) : s
        if n.offer(hub) != offer { n = n.with(hub, offer: offer) }
        guard n != s else { return }
        state = n
        let o = order()
        if using == nil || using == hub || Self.rank(o, hub) < Self.rank(o, using ?? "") || forgot && using == from {
            // The hub in use changed, or one above it came: try again.
            closeTunnel()
            poke()
        }
        do { try save(n) } catch { log("cannot keep the hub's offer", error) }
    }

    /// The hub the phone reaches now, or else the first in the group's
    /// order whose offer it keeps; nil without one.
    public var hub: String? {
        guard let s = state else { return nil }
        return using ?? Self.hubsToTry(order(), s).first?.device ?? s.hubs.first?.device
    }

    /// The hub the phone reaches now, through the tunnel or at home; nil
    /// while it reaches none.
    public var inUse: String? { using }

    /// The group's hubs whose offers the phone keeps, highest first, as the
    /// screens list them; empty while it is off.
    public var hubs: [String] {
        guard let s = state else { return [] }
        let o = order()
        return s.hubs.map(\.device).filter { Self.rank(o, $0) < o.count }.sorted { Self.rank(o, $0) < Self.rank(o, $1) }
    }

    /// Starts the loop that reaches a hub through the tunnel while the hubs
    /// are away.
    public func start() {
        guard runner == nil else { return }
        runner = Task { await self.run() }
    }

    public func stop() {
        runner?.cancel()
        runner = nil
        closeTunnel()
        poke()
    }

    private func closeTunnel() {
        conn?.close()
        conn = nil
        tunnel?.close()
        tunnel = nil
        tunnelTo = nil
    }

    private func run() async {
        var wait = firstWait
        while !Task.isCancelled {
            seen = changes
            guard let s = state else {
                status = .off
                using = nil
                await idle(nil)
                continue
            }
            let hubs = Self.hubsToTry(order(), s)
            guard !hubs.isEmpty else {
                status = .waitingForHub
                using = nil
                closeTunnel()
                await idle(nil)
                continue
            }
            var home: String?
            for h in hubs {
                if await atHome(h.device) {
                    home = h.device
                    break
                }
            }
            guard state == s, !Task.isCancelled else { continue }
            if let home {
                // At home with a hub: the phone dials the members directly.
                status = .atHome
                using = home
                closeTunnel()
                wait = firstWait
                await idle(homeCheck)
                continue
            }
            var served: Duration?
            for h in hubs {
                served = await tryHub(s, h, up: h.device != hubs[0].device)
                if served != nil || Task.isCancelled || state != s { break }
            }
            if Task.isCancelled { break }
            if let served {
                // A connection that lasted starts the waits again; one that
                // ended at once waits as a failure.
                if served > maxWait { wait = firstWait } else { wait = await backoff(wait, hubs[0].device) }
                continue
            }
            using = nil
            if state != s { continue }
            wait = await backoff(wait, hubs[0].device)
        }
        status = .off
    }

    /// Reaches the hub h through the tunnel at the next of its endpoints
    /// and serves the connection until it ends, or for upCheck when up is
    /// set, so the hubs above are tried again; returns how long it served
    /// the connection, or nil when it did not reach the hub.
    private func tryHub(_ s: AwayState, _ h: AwayState.Hub, up: Bool) async -> Duration? {
        status = .connecting
        let offer = h.offer
        let slot = h.device + ":" + offer.hubKey.base64EncodedString()
        let n = endpointOf[slot] ?? 0
        // With VLESS the hub's endpoints are tried over UDP only when it
        // speaks AmneziaWG, never in plain WireGuard, and VLESS comes after
        // them, in the same turn; the way that works is kept until it fails
        // (docs/protocol.md, section 11, "VLESS").
        let udp = offer.vless == nil || offer.obfuscation != nil ? offer.endpoints.count : 0
        let way = n % (udp + (offer.vless != nil ? 1 : 0))
        let overVLESS = way >= udp
        let t: OpenTunnel
        if let open = tunnel, tunnelTo == h {
            t = open
        } else {
            closeTunnel()
            do {
                t = try tunnels.start(privateKey: s.key, psk: offer.psk, hubKey: offer.hubKey, device: device, hub: h.device,
                                      endpoint: offer.endpoints[overVLESS ? 0 : way],
                                      obfuscation: try offer.obfuscation?.jsonText() ?? "",
                                      vless: overVLESS ? try offer.vless?.jsonText() ?? "" : "")
            } catch {
                fail("the tunnel to the hub could not start", error)
                return nil
            }
            guard state == s, !Task.isCancelled else {
                t.close()
                return nil
            }
            (tunnel, tunnelTo) = (t, h)
        }
        let c: ClosableTransport
        do {
            c = try await dial(t.port, h.device)
        } catch {
            fail("the hub does not answer through the tunnel", error)
            // The next of the hub's endpoints, in turn, on a new tunnel:
            // iOS takes back the sockets of an app it suspends, the
            // tunnel's loopback port and UDP socket among them, and the
            // old tunnel would then refuse every dial.
            endpointOf[slot] = n + 1
            if tunnel === t { closeTunnel() }
            return nil
        }
        guard state == s, tunnel === t, !Task.isCancelled else {
            c.close()
            return nil
        }
        (conn, using, status, lastError) = (c, h.device, .connected, nil)
        // On a hub below the first, the connection ends after upCheck.
        let check = upCheck
        let timer = up ? Task {
            if (try? await Task.sleep(for: check)) != nil { c.close() }
        } : nil
        let began = ContinuousClock.now
        do {
            try await serve(c, h.device)
        } catch {
            fail("the connection to the hub ended", error)
        }
        timer?.cancel()
        if conn === c { conn = nil }
        return ContinuousClock.now - began
    }

    private func fail(_ what: String, _ error: Error) {
        lastError = error
        log(what, error)
    }

    private func backoff(_ wait: Duration, _ hub: String) async -> Duration {
        await idle(wait)
        return min(wait * 2, isPhone(hub) ? phoneWait : maxWait)
    }

    /// Waits for d, or until something changes after the loop last read
    /// the state; nil waits for a change only.
    private func idle(_ d: Duration?) async {
        guard !Task.isCancelled, changes == seen else { return }
        let t = Task { _ = try? await Task.sleep(for: d ?? .seconds(86_400)) }
        nap = t
        await t.value
        nap = nil
    }

    /// Ends the current wait, or the next one, after a change.
    private func poke() {
        changes += 1
        nap?.cancel()
    }

    /// Where hub is in order; order.count when it is not there.
    static func rank(_ order: [String], _ hub: String) -> Int { order.firstIndex(of: hub) ?? order.count }

    /// The kept offers the phone tries, of the hubs in the group's order and
    /// with endpoints, highest first; a hub that gave its key for the next
    /// period comes again right after, with that key: it may have moved on
    /// to it while the phone was away (section 11, "The hub's key").
    static func hubsToTry(_ order: [String], _ s: AwayState) -> [AwayState.Hub] {
        s.hubs.filter { rank(order, $0.device) < order.count && !$0.offer.endpoints.isEmpty }.sorted { rank(order, $0.device) < rank(order, $1.device) }
            .flatMap { h in [h] + (h.offer.withNextKey.map { [AwayState.Hub(device: h.device, offer: $0)] } ?? []) }
    }
}
