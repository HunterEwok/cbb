// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// What the phone keeps as the group's hub (docs/design.md, "The phone as
/// the hub", D-64): whether it is on, its WireGuard private key, the
/// forwarder it registers with, the home networks where it takes members
/// and publishes itself, and its clients.
public struct HubState: Codable, Equatable, Sendable {
    /// The forwarder: its endpoint, "ip:port", and the pin of its key:
    /// SHA-256 of its key in standard base64.
    public struct Forwarder: Codable, Equatable, Sendable {
        public var endpoint: String
        public var pin: String
        public init(endpoint: String, pin: String) { (self.endpoint, self.pin) = (endpoint, pin) }

        /// The project's forwarder, which the hub uses unless the user
        /// gives their own: its name with the port, looked up when it is
        /// set, and the pin of its key, as cbb has them
        /// (internal/forward/project.go).
        public static let projectHost = "cbb.tools:8764"
        public static let projectPin = "efzUG2YzJBqS8FfojZGwqioECt46VzQcFo3oWpPru/g="

        /// Whether this is the project's forwarder.
        public var isProject: Bool { pin == Self.projectPin }
    }

    public var key: Data
    public var on = false
    public var forwarder: Forwarder?
    public var homes: [String] = []
    public var clients: [PhoneHub.Client] = []

    /// The most home networks the phone remembers; the oldest goes first.
    public static let maxHomes = 8

    public init(key: Data, on: Bool = false, forwarder: Forwarder? = nil, homes: [String] = [], clients: [PhoneHub.Client] = []) {
        (self.key, self.on, self.forwarder, self.homes, self.clients) = (key, on, forwarder, homes, clients)
    }

    public func encoded() throws -> Data { try JSONEncoder().encode(self) }

    /// The state in data, or nil when it is not one this version wrote.
    public static func decode(_ data: Data) -> HubState? {
        guard let s = try? JSONDecoder().decode(HubState.self, from: data), s.key.count == 32 else { return nil }
        return s
    }

    /// Whether pin is the pin of a forwarder's key, as `cbb forward` prints
    /// it.
    public static func validPin(_ pin: String) -> Bool {
        guard let b = Data(base64Encoded: pin), b.count == 32 else { return false }
        return b.base64EncodedString() == pin
    }

    /// The forwarder's endpoint as cbbtun takes it, "ip:port", when s is an
    /// IPv4 or a bracketed IPv6 address with its port; a name is not looked
    /// up here.
    public static func endpoint(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard let colon = t.lastIndex(of: ":"), let port = UInt16(t[t.index(after: colon)...]), port > 0 else { return nil }
        let host = t[..<colon]
        if host.hasPrefix("[") && host.hasSuffix("]") {
            let inner = host.dropFirst().dropLast()
            return !inner.isEmpty && inner.allSatisfy { $0.isHexDigit || $0 == ":" } && inner.contains(":") ? t : nil
        }
        let b = host.split(separator: ".", omittingEmptySubsequences: false)
        return b.count == 4 && b.allSatisfy { UInt8($0) != nil } ? t : nil
    }

    /// A network as the hub remembers it: its gateway's address and the
    /// network of the phone's IPv4 address on it, as "192.168.0.1
    /// 192.168.0.0/24". Wi-Fi in a café has another, so the phone neither
    /// takes members nor publishes itself there (as D-63 on the computers).
    public static func networkKey(gateway: String?, address: String?, prefixLength: Int) -> String? {
        guard let gateway, let address, (0...32).contains(prefixLength) else { return nil }
        let b = address.split(separator: ".").compactMap { UInt8($0) }
        guard b.count == 4 else { return nil }
        var v = b.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        v &= prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
        let net = (0..<4).map { String((v >> (24 - 8 * $0)) & 0xff) }.joined(separator: ".")
        return "\(gateway) \(net)/\(prefixLength)"
    }
}

/// A running hub of mobile/cbbtun.
public protocol HubTunnel: AnyObject, Sendable {
    func setClients(_ json: String) throws
    func register(endpoint: String, pin: String, chain: [Data], sign: @escaping @Sendable (Data) throws -> Data, records: String) throws
    func setRecords(_ records: String) throws
    /// cbbtun's Status JSON.
    func status() -> String
    /// Opens a remote invitation's guest tunnel (cbbtun's Hub.Invite).
    func invite(group: String, endpoints: String, lifetime: Int, guestPort: UInt16) throws -> HubGuest
    func close()
}

/// The guest tunnel of a remote invitation, cbbtun's Guest.
public protocol HubGuest: AnyObject, Sendable {
    /// The invitation's text, cbb://invite#….
    var text: String { get }
    var secret: Data { get }
    /// When it expires.
    var expires: Date { get }
    /// The window admitted the device: its first member connection goes to
    /// the member port.
    func admitted()
    func close()
}

/// Starts hubs; the app's come from mobile/cbbtun, the tests' from a fake.
public protocol HubTunnels: Sendable {
    func newKey() throws -> Data
    func publicKey(_ privateKey: Data) throws -> Data
    func start(privateKey: Data, device: String, memberPort: UInt16, clients: String) throws -> HubTunnel
}

/// The phone as the group's hub while its app is open (D-64). At home it
/// takes the members on its member port, which the app publishes by
/// Bonjour; from afar its clients reach it through its forwarder, with
/// which it registers by its member key and the group's authority records
/// (docs/protocol.md, section 13). It admits a client by the tunnel key its
/// hello offers, as a computer's hub (PhoneHub), and answers with its
/// offer, whose endpoint is the forwarder's: without a forwarder it is a
/// hub at home only and offers nothing. Its methods are thread-safe, so
/// MemberNode's hub can call offer.
public final class HubOnPhone: @unchecked Sendable {
    /// What the screens show.
    public enum Status: Sendable, Equatable { case off, paused, homeOnly, registering, registered, failed }

    /// The forwarder's address is no "ip:port", or its key no pin.
    /// badForwarder: not a forwarder's address and key; notRunning: an
    /// invitation needs the hub's tunnel and its forwarder.
    public enum Failure: Error, Equatable { case badForwarder, notRunning }

    /// What a running hub needs from the group: the member listener's
    /// port, the member chain, the member key's signer of SHA-256 digests,
    /// the authority records.
    public struct Group: Sendable {
        public var memberPort: UInt16
        public var chain: [Data]
        public var sign: @Sendable (Data) throws -> Data
        public var records: [Member.Record]
        public init(memberPort: UInt16, chain: [Data], sign: @escaping @Sendable (Data) throws -> Data, records: [Member.Record]) {
            (self.memberPort, self.chain, self.sign, self.records) = (memberPort, chain, sign, records)
        }
    }

    private let device: String
    private let tunnels: HubTunnels
    private let save: @Sendable (HubState?) throws -> Void
    private let log: @Sendable (String, Error?) -> Void
    private let lock = NSLock()
    private var state: HubState?
    private var hub: PhoneHub?
    private var tunnel: HubTunnel?
    private var failure: String?

    public init(device: String, tunnels: HubTunnels, state: HubState?, save: @escaping @Sendable (HubState?) throws -> Void,
                log: @escaping @Sendable (String, Error?) -> Void = { _, _ in }) {
        (self.device, self.tunnels, self.state, self.save, self.log) = (device, tunnels, state, save, log)
        hub = state.flatMap(phoneHub)
    }

    public var isOn: Bool { lock.withLock { state?.on == true } }
    public var forwarder: HubState.Forwarder? { lock.withLock { state?.forwarder } }
    public var running: Bool { lock.withLock { tunnel != nil } }

    /// The clients' devices, for the screens.
    public var clients: [String] { lock.withLock { hub?.clients.map(\.device) ?? [] } }

    /// The clients with their keys, which a hub command hands to the new
    /// hub (docs/protocol.md, section 11, "Moving the hub").
    public var handover: [PhoneHub.Client] { lock.withLock { hub?.clients ?? [] } }

    /// The offer the client device gets when the hub moves to newHub, as
    /// PhoneHub.movedOffer.
    public func movedOffer(device: String, newHub: String, offer: Member.TunnelOffer) -> Member.TunnelOffer? {
        lock.withLock { hub }?.movedOffer(device: device, newHub: newHub, offer: offer)
    }

    private func phoneHub(_ s: HubState) -> PhoneHub? {
        do {
            let h = PhoneHub(publicKey: try tunnels.publicKey(s.key), clients: s.clients)
            h.endpoints = s.forwarder.map { [$0.endpoint] } ?? []
            return h
        } catch {
            log("cannot make the hub", error)
            return nil
        }
    }

    private func change(_ f: (inout HubState) -> Void) throws {
        let next: HubState = try lock.withLock {
            let old = try state ?? HubState(key: tunnels.newKey())
            var s = old
            f(&s)
            state = s
            if hub == nil || s.key != old.key { hub = phoneHub(s) }
            hub?.endpoints = s.forwarder.map { [$0.endpoint] } ?? []
            return s
        }
        try save(next)
    }

    /// Turns it on, remembering home, the network the phone is on now, as
    /// a home network.
    public func turnOn(home: String?) throws {
        try change { s in
            s.on = true
            s.homes = Self.withHome(s.homes, home)
        }
    }

    /// Turns it off; the key and the clients stay, so turning it on again
    /// keeps the clients' tunnels.
    public func turnOff() throws {
        try change { $0.on = false }
        stop()
    }

    /// Sets the forwarder, or none.
    public func setForwarder(_ f: HubState.Forwarder?) throws {
        if let f, !HubState.validPin(f.pin) || HubState.endpoint(f.endpoint) == nil { throw Failure.badForwarder }
        try change { $0.forwarder = f }
        stop() // the next start registers with it
    }

    /// Remembers home as a home network.
    public func addHome(_ home: String) throws {
        try change { $0.homes = Self.withHome($0.homes, home) }
    }

    /// Whether the phone takes members and publishes itself on the network
    /// home names.
    public func isHome(_ home: String?) -> Bool {
        guard let home else { return false }
        return lock.withLock { state?.homes.contains(home) == true }
    }

    private static func withHome(_ homes: [String], _ home: String?) -> [String] {
        guard let home, !homes.contains(home) else { return homes }
        return Array((homes + [home]).suffix(HubState.maxHomes))
    }

    /// The hub while it is on and has a forwarder, as it offers and shares.
    private var offering: PhoneHub? { lock.withLock { state?.on == true && state?.forwarder != nil ? hub : nil } }

    /// The offers for a member whose hello offered key and psk, for
    /// MemberNode's hub: this hub's own, then the group's other hubs' it
    /// passes on, in order (docs/protocol.md, section 11, "Several hubs");
    /// none while the hub is off or has no forwarder, or when the key is
    /// refused. admitted runs once a new client is kept: the other hubs
    /// take this hub's clients from what it shares, so it shares again, as
    /// a computer does.
    public func offers(device: String, key: Data, psk: Data? = nil, order: [String] = [],
                       admitted: () -> Void = {}) -> [Member.TunnelOffer] {
        guard let h = offering else { return [] }
        return h.offers(device: device, key: key, psk: psk, order: order, changed: { self.clientsChanged($0); admitted() },
                        refused: { self.log("refused a client", $0) })
    }

    /// The offer for a member whose hello offered key, as offers gives it
    /// first; nil without one.
    public func offer(device: String, key: Data) -> Member.TunnelOffer? { offers(device: device, key: key).first }

    /// The offers a connected client device gets, after another hub's offer
    /// changed; none for a device that is no client.
    public func offers(for device: String, order: [String]) -> [Member.TunnelOffer] {
        guard let h = offering, let c = h.clients.first(where: { $0.device == device }) else { return [] }
        return h.offers(for: c, order: order)
    }

    /// What this hub shares with another of the group's hubs: that it
    /// serves, its offer and its clients; nil while it is off or has no
    /// forwarder. The phone serves whenever it is on: it does not yet give
    /// way to a hub above it.
    public func share() -> Member.HubShare? { offering?.share() }

    /// Takes what another hub, from, shared: the clients the records know
    /// (known), which this hub can then serve too, and the offer it passes
    /// on to its clients. It returns whether that offer changed, so the
    /// connected clients get it.
    @discardableResult
    public func shared(from: String, _ share: Member.HubShare, known: (String) -> Bool) -> Bool {
        guard let h = offering else { return false }
        var changed = false
        for c in share.clients where c.device != device && known(c.device) {
            do {
                if try h.take(c) { changed = true }
            } catch {
                log("refused a client \(from) shared", error)
            }
        }
        if changed { clientsChanged(h.clients) }
        return h.setOther(from, offer: share.offer.flatMap { $0.hubKey.count == 32 && $0.endpoints.count <= 8 ? $0 : nil })
    }

    private func clientsChanged(_ clients: [PhoneHub.Client]) {
        guard let changed = lock.withLock({ () -> (HubState, HubTunnel?)? in
            guard var s = state else { return nil }
            s.clients = clients
            state = s
            return (s, tunnel)
        }) else { return }
        let (next, t) = changed
        do { try save(next) } catch { log("cannot keep the hub's clients", error) }
        guard let t else { return }
        do {
            try t.setClients(String(decoding: try JSONEncoder().encode(clients.map(\.shared)), as: UTF8.self))
        } catch {
            log("cannot hand the clients to the tunnel", error)
        }
    }

    /// Forgets the clients whose devices keep refuses, removed devices;
    /// returns them.
    @discardableResult
    public func prune(keep: (String) -> Bool) -> [String] {
        guard let h = lock.withLock({ hub }) else { return [] }
        let gone = h.prune { keep($0.device) }
        if !gone.isEmpty { clientsChanged(h.clients) }
        return gone
    }

    /// Starts the tunnel and the registration when the hub is on and has a
    /// forwarder; nothing when it runs already.
    public func start(_ g: Group) {
        guard let ready = lock.withLock({ () -> (HubState, PhoneHub)? in
            guard tunnel == nil, let s = state, s.on, let h = hub else { return nil }
            return (s, h)
        }) else { return }
        let (s, h) = ready
        guard let fw = s.forwarder else { return }
        let t: HubTunnel
        do {
            t = try tunnels.start(privateKey: s.key, device: device, memberPort: g.memberPort, clients: try h.clientsJSON())
            try t.register(endpoint: fw.endpoint, pin: fw.pin, chain: g.chain, sign: g.sign, records: try Self.json(g.records))
        } catch {
            log("the hub could not start", error)
            lock.withLock { failure = String(describing: error) }
            return
        }
        let kept = lock.withLock {
            guard tunnel == nil, state?.on == true else { return false }
            (tunnel, failure) = (t, nil)
            return true
        }
        if !kept { t.close() }
    }

    /// Stops the tunnel and the registration; the clients come back at the
    /// next start.
    public func stop() {
        let t = lock.withLock { () -> HubTunnel? in
            defer { tunnel = nil }
            return tunnel
        }
        t?.close()
    }

    /// Opens a remote invitation's guest tunnel to the window on guestPort
    /// (docs/protocol.md, section 12), with the forwarder as the hub's
    /// address away from home; throws while the hub does not run.
    public func invite(group: String, lifetime: Int, guestPort: UInt16) throws -> HubGuest {
        let (t, fw) = lock.withLock { (tunnel, state?.forwarder) }
        guard let t, let fw else { throw Failure.notRunning }
        let endpoints = String(decoding: try JSONEncoder().encode([fw.endpoint]), as: UTF8.self)
        return try t.invite(group: group, endpoints: endpoints, lifetime: lifetime, guestPort: guestPort)
    }

    /// Hands the forwarder new authority records at the next registration,
    /// after a removal or a new admin.
    public func setRecords(_ records: [Member.Record]) {
        guard let t = lock.withLock({ tunnel }) else { return }
        do { try t.setRecords(try Self.json(records)) } catch { log("cannot hand the records to the tunnel", error) }
    }

    /// Where it stands, and why it failed, for the screens; paused tells
    /// that the app is in the background.
    public func status(paused: Bool) -> (Status, String?) {
        let (s, t, f) = lock.withLock { (state, tunnel, failure) }
        guard let s, s.on else { return (.off, nil) }
        guard s.forwarder != nil else { return (.homeOnly, nil) }
        guard let t else { return f != nil && !paused ? (.failed, f) : (.paused, nil) }
        struct Report: Decodable {
            var registered: Bool?
            var error: String?
        }
        guard let r = try? JSONDecoder().decode(Report.self, from: Data(t.status().utf8)) else { return (.registering, nil) }
        if r.registered == true { return (.registered, nil) }
        if let e = r.error { return (.failed, e) }
        return (.registering, nil)
    }

    private static func json(_ rs: [Member.Record]) throws -> String {
        String(decoding: try JSONEncoder().encode(rs), as: UTF8.self)
    }
}
