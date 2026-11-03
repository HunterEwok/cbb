// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// What the phone keeps to meet its group at a blind relay (docs/design.md,
/// "Blind relay", D-68): its WireGuard private key, made on the phone, and
/// the relay, its endpoint and the pin of its key, as `cbb relay` prints
/// them. The user turned it on after reading what a relay learns, so the
/// settings are the consent too: without them the phone meets nobody there.
public struct RelaySettings: Codable, Equatable, Sendable {
    public var key: Data
    public var relay: HubState.Forwarder

    public init(key: Data, relay: HubState.Forwarder) { (self.key, self.relay) = (key, relay) }

    public func encoded() throws -> Data { try JSONEncoder().encode(self) }

    /// The settings in data, or nil when they are not ones this version wrote.
    public static func decode(_ data: Data) -> RelaySettings? {
        guard let s = try? JSONDecoder().decode(RelaySettings.self, from: data), s.key.count == 32,
              HubState.validPin(s.relay.pin), HubState.endpoint(s.relay.endpoint) != nil else { return nil }
        return s
    }
}

/// What mobile/cbbtun's relay link asks of the kit (cbbtun's RelayEvents).
public protocol RelayLinkEvents: AnyObject, Sendable {
    /// The relay joined a connection to peer: the kit dials 127.0.0.1:port,
    /// which takes one connection, as the TLS client expecting peer.
    func dial(peer: String, port: UInt16)
    /// peer called: its connection comes to the member listener from
    /// 127.0.0.1:localPort.
    func calling(peer: String, localPort: UInt16)
    /// Whether to connect to peer through the relay now.
    func wanted(peer: String) -> Bool
    /// The link stands as the JSON state says, RelayOnPhone.Report.
    func changed(_ state: String)
}

/// A running link of mobile/cbbtun to a blind relay.
public protocol RelayLink: AnyObject, Sendable {
    func setRecords(_ records: String) throws
    /// cbbtun's Relay.SetCredentials: an empty creds goes back to the
    /// member certificate.
    func setCredentials(serverKey: Data, sign: @escaping @Sendable (Data) throws -> Data, creds: String, roots: String, names: String) throws
    func close()
}

/// Starts links to relays; the app's come from mobile/cbbtun, the tests'
/// from a fake.
public protocol RelayLinks: Sendable {
    func newKey() throws -> Data
    func start(privateKey: Data, device: String, endpoint: String, pin: String, chain: [Data],
               sign: @escaping @Sendable (Data) throws -> Data, records: String, memberPort: UInt16,
               events: RelayLinkEvents) throws -> RelayLink
}

/// The phone at a blind relay while the app is open (docs/protocol.md,
/// section 14): it registers by its member key and the group's authority
/// records, or, once the group's server credentials list its server key,
/// with them under a pseudonym (section 18), and the relay joins its member connections to the other
/// devices of the group there, which the relay cannot read: member TLS
/// runs end to end. The device with the lower ID dials, so the phone both
/// dials and answers. An answered call comes to the loopback member
/// listener, which serves it only when the client certificate names the
/// device the relay said calls (caller), so the relay cannot pose as
/// another device of the group. Its methods are thread-safe.
public final class RelayOnPhone: RelayLinkEvents, @unchecked Sendable {
    /// What the screens show.
    public enum Status: Sendable, Equatable { case off, paused, connecting, connected, failed }

    /// The relay's address is no "ip:port", or its key no pin.
    public enum Failure: Error, Equatable { case badRelay }

    /// How the link stands, as cbbtun reports it: registered, the other
    /// devices of the group at the relay, the connections through it, and
    /// why it is not connected.
    public struct Report: Decodable, Equatable, Sendable {
        public var connected: Bool
        public var online: [String]
        public var through: Int
        public var error: String?

        public init(connected: Bool = false, online: [String] = [], through: Int = 0, error: String? = nil) {
            (self.connected, self.online, self.through, self.error) = (connected, online, through, error)
        }
    }

    /// What the phone registers with in place of its member certificate:
    /// its server key for the period, SubjectPublicKeyInfo DER, how it
    /// signs a SHA-256 digest with it, and the registration the credentials
    /// give.
    public struct Credentials: Sendable {
        public var serverKey: Data
        public var sign: @Sendable (Data) throws -> Data
        public var registration: CredentialStore.Registration

        public init(serverKey: Data, sign: @escaping @Sendable (Data) throws -> Data, registration: CredentialStore.Registration) {
            (self.serverKey, self.sign, self.registration) = (serverKey, sign, registration)
        }

        var creds: String { json(registration.credentials) }
        var roots: String { json(registration.roots) }
        var names: String { json(registration.names) }

        /// What the relay sees of it, to tell whether it changed.
        var shown: String { [serverKey.base64EncodedString(), creds, roots, names].joined(separator: "\n") }

        private func json<T: Encodable>(_ v: T) -> String {
            let e = JSONEncoder()
            e.outputFormatting = .sortedKeys
            return String(decoding: (try? e.encode(v)) ?? Data(), as: UTF8.self)
        }
    }

    public typealias Dial = @Sendable (_ port: UInt16, _ peer: String) async throws -> ClosableTransport
    public typealias Serve = @Sendable (ClosableTransport, _ peer: String) async throws -> Void

    /// The most calls whose callers it keeps before their connections come.
    static let maxCalls = 64

    private let device: String
    private let links: RelayLinks
    private let save: @Sendable (RelaySettings?) throws -> Void
    private let dialPeer: Dial
    private let serve: Serve
    private let elsewhere: @Sendable (String) -> Bool
    private let log: @Sendable (String, Error?) -> Void
    private let lock = NSLock()
    private var settings: RelaySettings?
    private var link: RelayLink?
    private var report = Report()
    private var failure: String?
    private var credentials: Credentials?
    /// What the running link registers with: Credentials.shown, or nil with
    /// the member certificate.
    private var applied: String?
    /// The callers by the source port of their loopback connections, oldest first.
    private var calls: [(port: UInt16, peer: String)] = []

    /// settings is what load read; save keeps each change, nil when it is
    /// turned off. dial reaches peer's member TLS through the port of a
    /// dialed connection, checking that the peer is peer, and serve runs a
    /// connection until it ends; elsewhere tells whether the phone reaches
    /// a device another way now, as on the home network.
    public init(device: String, links: RelayLinks, settings: RelaySettings?, save: @escaping @Sendable (RelaySettings?) throws -> Void,
                dial: @escaping Dial, serve: @escaping Serve, elsewhere: @escaping @Sendable (String) -> Bool,
                log: @escaping @Sendable (String, Error?) -> Void = { _, _ in }) {
        (self.device, self.links, self.settings, self.save) = (device, links, settings, save)
        (dialPeer, self.serve, self.elsewhere, self.log) = (dial, serve, elsewhere, log)
    }

    public var isOn: Bool { lock.withLock { settings != nil } }
    public var relay: HubState.Forwarder? { lock.withLock { settings?.relay } }
    public var running: Bool { lock.withLock { link != nil } }

    /// Turns it on with the relay at endpoint, "ip:port", whose key pin
    /// pins, keeping the phone's key when it had one; the next start
    /// registers there.
    public func turnOn(endpoint: String, pin: String) throws {
        guard HubState.validPin(pin), let ep = HubState.endpoint(endpoint) else { throw Failure.badRelay }
        let r = HubState.Forwarder(endpoint: ep, pin: pin)
        let old = lock.withLock { settings }
        let s = RelaySettings(key: try old?.key ?? links.newKey(), relay: r)
        try save(s)
        lock.withLock { settings = s }
        if old != s { stop() }
    }

    /// Turns it off: forgets the relay and the phone's key there.
    public func turnOff() throws {
        try save(nil)
        lock.withLock { settings = nil }
        stop()
    }

    /// Starts the link while it is on; nothing when it runs already. g is
    /// what a hub takes: the loopback member listener's port, the member
    /// chain with the roots after it, the member key's signer, the records.
    public func start(_ g: HubOnPhone.Group) {
        guard let s = lock.withLock({ link == nil ? settings : nil }) else { return }
        let l: RelayLink
        do {
            l = try links.start(privateKey: s.key, device: device, endpoint: s.relay.endpoint, pin: s.relay.pin, chain: g.chain,
                                sign: g.sign, records: try Self.json(g.records), memberPort: g.memberPort, events: self)
        } catch {
            log("the link to the relay could not start", error)
            lock.withLock { failure = String(describing: error) }
            return
        }
        let kept = lock.withLock {
            guard link == nil, settings == s else { return false }
            (link, failure, report, applied) = (l, nil, Report(), nil)
            return true
        }
        if kept { applyCredentials() } else { l.close() }
    }

    /// Registers with the credentials c from now on, or with the member
    /// certificate when nil; the link registers again only when they
    /// changed.
    public func setCredentials(_ c: Credentials?) {
        lock.withLock { credentials = c }
        applyCredentials()
    }

    private func applyCredentials() {
        let next = lock.withLock { () -> (RelayLink, Credentials?)? in
            guard let l = link, credentials?.shown != applied else { return nil }
            applied = credentials?.shown
            return (l, credentials)
        }
        guard let (l, c) = next else { return }
        do {
            if let c {
                try l.setCredentials(serverKey: c.serverKey, sign: c.sign, creds: c.creds, roots: c.roots, names: c.names)
            } else {
                try l.setCredentials(serverKey: Data(), sign: { $0 }, creds: "", roots: "", names: "")
            }
        } catch {
            log("cannot hand the server credentials to the relay", error)
            lock.withLock { if link === l { applied = nil } }
        }
    }

    /// Leaves the relay; the next start registers again.
    public func stop() {
        let l = lock.withLock { () -> RelayLink? in
            defer { (link, calls, report) = (nil, [], Report()) }
            return link
        }
        l?.close()
    }

    /// Hands the relay new authority records at the next registration,
    /// after a removal or a new admin.
    public func setRecords(_ records: [Member.Record]) {
        guard let l = lock.withLock({ link }) else { return }
        do { try l.setRecords(try Self.json(records)) } catch { log("cannot hand the records to the relay", error) }
    }

    /// The device the relay said calls from the loopback port, once: the
    /// member listener serves that connection only when its certificate
    /// names this device; nil for a connection the relay did not announce.
    public func caller(port: UInt16) -> String? {
        lock.withLock {
            guard let i = calls.firstIndex(where: { $0.port == port }) else { return nil }
            return calls.remove(at: i).peer
        }
    }

    /// Where it stands, and why it failed, for the screens; paused tells
    /// that the app is in the background.
    public func status(paused: Bool) -> (Status, Report, String?) {
        let (s, l, r, f) = lock.withLock { (settings, link, report, failure) }
        guard s != nil else { return (.off, r, nil) }
        guard l != nil else { return f != nil && !paused ? (.failed, r, f) : (.paused, r, nil) }
        if r.connected { return (.connected, r, nil) }
        if let e = r.error { return (.failed, r, e) }
        return (.connecting, r, nil)
    }

    // MARK: RelayLinkEvents

    public func dial(peer: String, port: UInt16) {
        let (dialPeer, serve, log) = (dialPeer, serve, log)
        Task {
            do {
                let t = try await dialPeer(port, peer)
                try await serve(t, peer)
            } catch {
                log("a connection through the relay to \(peer) failed", error)
            }
        }
    }

    public func calling(peer: String, localPort: UInt16) {
        lock.withLock {
            calls.removeAll { $0.port == localPort }
            calls.append((localPort, peer))
            if calls.count > Self.maxCalls { calls.removeFirst(calls.count - Self.maxCalls) }
        }
    }

    public func wanted(peer: String) -> Bool { !elsewhere(peer) }

    public func changed(_ state: String) {
        guard let r = try? JSONDecoder().decode(Report.self, from: Data(state.utf8)) else {
            return log("the relay's state does not decode: \(state)", nil)
        }
        lock.withLock { report = r }
    }

    private static func json(_ rs: [Member.Record]) throws -> String {
        String(decoding: try JSONEncoder().encode(rs), as: UTF8.self)
    }
}
