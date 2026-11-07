// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Crypto
import Foundation

/// The phones' tunnel in Rust (lite/ffi/src/tunnel.rs, the library's
/// feature `tunnel`): the tunnel to the hub, the phone as the group's hub
/// with its remote invitations and its registration with the forwarder, and
/// the link to the blind relay, under the same protocols as mobile/cbbtun's,
/// which they replace (Tunnels, HubTunnels, RelayLinks).
public enum RustTunnel {
    /// A request the tunnel refused, or an answer it could not give.
    public struct Failure: Error, Equatable, CustomStringConvertible {
        public var message: String
        public var details: String

        public var description: String { details.isEmpty ? "tunnel: \(message)" : "tunnel: \(message): \(details)" }
    }

    /// Sends one request to cbb_tunnel and returns its `ok`.
    static func call(_ request: [String: Any]) throws -> [String: Any] {
        try answer(request) { r, n in cbb_tunnel(r.baseAddress, r.count, n) }
    }

    /// Encodes request, hands it to f with a place for the answer's length,
    /// and decodes the answer f gives.
    static func answer(_ request: [String: Any],
                       _ f: (UnsafeBufferPointer<UInt8>, UnsafeMutablePointer<Int>) -> UnsafeMutablePointer<UInt8>?) throws -> [String: Any] {
        let body = try JSONSerialization.data(withJSONObject: request)
        var count = 0
        let p: UnsafeMutablePointer<UInt8>? = body.withUnsafeBytes { raw in
            f(raw.bindMemory(to: UInt8.self), &count)
        }
        guard let p else { throw Failure(message: "the tunnel gave no answer", details: "") }
        let data = Data(bytes: p, count: count)
        cbb_free(p, count)
        guard let a = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure(message: "the tunnel's answer does not read", details: "")
        }
        if let e = a["error"] as? [String: Any] {
            throw Failure(message: e["message"] as? String ?? "unknown", details: e["details"] as? String ?? "")
        }
        return a["ok"] as? [String: Any] ?? [:]
    }

    /// A JSON value from text the protocols carry: "" for none.
    static func json(_ s: String) throws -> Any? {
        guard !s.isEmpty else { return nil }
        return try JSONSerialization.jsonObject(with: Data(s.utf8), options: [.fragmentsAllowed])
    }

    /// The public point (SEC1, uncompressed) of a P-256 key, from its
    /// SubjectPublicKeyInfo or from the certificate that holds it.
    static func point(spki: Data) throws -> Data {
        try P256.Signing.PublicKey(derRepresentation: spki).x963Representation
    }

    static func point(certificate der: Data) throws -> Data {
        try point(spki: CertificateInfo(der: der).publicKey)
    }

    /// A whole number in JSON, as JSONSerialization gives it on Apple's
    /// platforms (NSNumber) and on Linux (Int).
    static func number(_ v: Any?) -> Int64? {
        switch v {
        case let n as Int: return Int64(n)
        case let n as Int64: return n
        case let n as UInt64: return Int64(exactly: n)
        case let n as Double: return Int64(exactly: n)
        case let n as NSNumber: return n.int64Value
        default: return nil
        }
    }

    /// The id the tunnel gave a started tunnel, hub, link or guest.
    static func id(_ ok: [String: Any], _ key: String = "id") throws -> Int {
        guard let n = number(ok[key]), let id = Int(exactly: n), id >= 0 else {
            throw Failure(message: "the tunnel gave no \(key)", details: "")
        }
        return id
    }

    static func port(_ ok: [String: Any], _ key: String) throws -> UInt16 {
        guard let n = number(ok[key]), let p = UInt16(exactly: n), p != 0 else {
            throw Failure(message: "the tunnel gave no \(key)", details: "")
        }
        return p
    }
}

/// What a callback of the tunnel reaches: the key that signs, and for a
/// relay link where its events go. The library keeps it until the hub or
/// link stops, or registers again, and the kit releases it after that.
final class TunnelCallbacks: @unchecked Sendable {
    let sign: @Sendable (Data) throws -> Data
    let event: (@Sendable ([String: Any]) -> Void)?

    init(sign: @escaping @Sendable (Data) throws -> Data, event: (@Sendable ([String: Any]) -> Void)? = nil) {
        (self.sign, self.event) = (sign, event)
    }

    /// Retains the callbacks for the library; release() gives them up.
    func retained() -> UnsafeMutableRawPointer { Unmanaged.passRetained(self).toOpaque() }

    static func release(_ p: UnsafeMutableRawPointer?) {
        if let p { Unmanaged<TunnelCallbacks>.fromOpaque(p).release() }
    }

    static func of(_ p: UnsafeMutableRawPointer?) -> TunnelCallbacks? {
        p.map { Unmanaged<TunnelCallbacks>.fromOpaque($0).takeUnretainedValue() }
    }
}

/// The tunnel's signing callback (cbb_sign_fn): the key signs the 32-byte
/// digest; the signature, DER, goes into sig's 72 bytes.
private func tunnelSign(_ ctx: UnsafeMutableRawPointer?, _ digest: UnsafePointer<UInt8>?, _ sig: UnsafeMutablePointer<UInt8>?,
                        _ sigLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let digest, let sig, let sigLen, let c = TunnelCallbacks.of(ctx),
          let s = try? c.sign(Data(bytes: digest, count: 32)), s.count <= 72 else { return 1 }
    s.copyBytes(to: sig, count: s.count)
    sigLen.pointee = s.count
    return 0
}

/// The relay link's event callback (cbb_event_fn), on one of its threads.
private func tunnelEvent(_ ctx: UnsafeMutableRawPointer?, _ event: UnsafePointer<UInt8>?, _ len: Int) {
    guard let event, let c = TunnelCallbacks.of(ctx),
          let e = try? JSONSerialization.jsonObject(with: Data(bytes: event, count: len)) as? [String: Any] else { return }
    c.event?(e)
}

/// Tunnels to the hub (Tunnels).
public struct RustTunnels: Tunnels {
    public init() {}

    public func newKey() throws -> Data {
        guard let k = try RustTunnel.call(["op": "new_key"])["key"] as? String, let d = Data(base64Encoded: k) else {
            throw RustTunnel.Failure(message: "the tunnel gave no key", details: "")
        }
        return d
    }

    public func publicKey(_ privateKey: Data) throws -> Data {
        let ok = try RustTunnel.call(["op": "public_key", "key": privateKey.base64EncodedString()])
        guard let k = ok["public"] as? String, let d = Data(base64Encoded: k) else {
            throw RustTunnel.Failure(message: "the tunnel gave no public key", details: "")
        }
        return d
    }

    public func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String,
                      obfuscation: String, vless: String) throws -> OpenTunnel {
        var offer: [String: Any] = ["hub_key": hubKey.base64EncodedString(), "psk": psk.base64EncodedString(),
                                    "endpoints": endpoint.isEmpty ? [] : [endpoint]]
        if let o = try RustTunnel.json(obfuscation) { offer["obfuscation"] = o }
        if let v = try RustTunnel.json(vless) { offer["vless"] = v }
        let ok = try RustTunnel.call(["op": "start", "key": privateKey.base64EncodedString(), "device": device, "hub": hub,
                                      "offer": offer])
        return RustOpenTunnel(id: try RustTunnel.id(ok), port: try RustTunnel.port(ok, "port"))
    }
}

/// A running tunnel to the hub.
final class RustOpenTunnel: OpenTunnel, @unchecked Sendable {
    let id: Int
    let port: UInt16
    private let lock = NSLock()
    private var closed = false

    init(id: Int, port: UInt16) { (self.id, self.port) = (id, port) }

    deinit { close() }

    func setEndpoint(_ endpoint: String) throws {
        _ = try RustTunnel.call(["op": "set_endpoint", "id": id, "endpoint": endpoint])
    }

    func close() {
        let first: Bool = lock.withLock {
            defer { closed = true }
            return !closed
        }
        if first { _ = try? RustTunnel.call(["op": "stop", "id": id]) }
    }
}

/// The phone as the group's hub (HubTunnels).
public struct RustHubTunnels: HubTunnels {
    public init() {}

    public func newKey() throws -> Data { try RustTunnels().newKey() }

    public func publicKey(_ privateKey: Data) throws -> Data { try RustTunnels().publicKey(privateKey) }

    public func start(privateKey: Data, device: String, memberPort: UInt16, obfuscation: String, clients: String) throws -> HubTunnel {
        var req: [String: Any] = ["op": "hub_start", "key": privateKey.base64EncodedString(), "device": device,
                                  "member_port": Int(memberPort), "clients": try RustTunnel.json(clients) ?? [Any]()]
        if let o = try RustTunnel.json(obfuscation) { req["obfuscation"] = o }
        return RustHub(id: try RustTunnel.id(try RustTunnel.call(req)))
    }

    public func newObfuscation() throws -> Member.Obfuscation {
        let ok = try RustTunnel.call(["op": "new_obfuscation"])
        return try JSONDecoder().decode(Member.Obfuscation.self,
                                        from: try JSONSerialization.data(withJSONObject: ok["obfuscation"] ?? [String: Any]()))
    }

    public func newVLESSID() throws -> String {
        guard let id = try RustTunnel.call(["op": "new_vless_id"])["id"] as? String else {
            throw RustTunnel.Failure(message: "the tunnel gave no VLESS ID", details: "")
        }
        return id
    }
}

/// A running hub.
final class RustHub: HubTunnel, @unchecked Sendable {
    let id: Int
    private let lock = NSLock()
    private var closed = false
    /// The callbacks of the registration with the forwarder, which the
    /// library holds until the hub stops or registers again.
    private var registration: UnsafeMutableRawPointer?

    init(id: Int) { self.id = id }

    deinit { close() }

    func setClients(_ json: String) throws {
        _ = try RustTunnel.call(["op": "hub_set_clients", "id": id, "clients": try RustTunnel.json(json) ?? [Any]()])
    }

    func register(endpoint: String, pin: String, chain: [Data], sign: @escaping @Sendable (Data) throws -> Data, records: String, vlessID: String) throws {
        guard let leaf = chain.first else { throw RustTunnel.Failure(message: "the member certificate is missing", details: "") }
        var req: [String: Any] = ["id": id, "endpoint": endpoint, "pins": [pin],
                                  "chain": chain.map { $0.base64EncodedString() },
                                  "public": try RustTunnel.point(certificate: leaf).base64EncodedString()]
        if let r = try RustTunnel.json(records) { req["records"] = r }
        if !vlessID.isEmpty { req["vless_id"] = vlessID }
        let ctx = TunnelCallbacks(sign: sign).retained()
        do {
            _ = try RustTunnel.answer(req) { r, n in cbb_tunnel_register(r.baseAddress, r.count, tunnelSign, ctx, n) }
        } catch {
            // A refused registration keeps the one before, and its
            // callbacks.
            TunnelCallbacks.release(ctx)
            throw error
        }
        let old: UnsafeMutableRawPointer? = lock.withLock {
            defer { registration = ctx }
            return registration
        }
        TunnelCallbacks.release(old)
    }

    func setRecords(_ records: String) throws {
        _ = try RustTunnel.call(["op": "hub_set_records", "id": id, "records": try RustTunnel.json(records) ?? [Any]()])
    }

    func setProjectWays(_ ways: String) throws {
        _ = try RustTunnel.call(["op": "hub_set_project_ways", "id": id, "ways": try RustTunnel.json(ways) ?? [Any]()])
    }

    /// The forwarder's report as cbbtun's Status gave it: {} before the
    /// registration.
    func status() -> String {
        guard let ok = try? RustTunnel.call(["op": "hub_status", "id": id]),
              let f = ok["forwarder"] as? [String: Any],
              let d = try? JSONSerialization.data(withJSONObject: f) else { return "{}" }
        return String(decoding: d, as: UTF8.self)
    }

    func invite(group: String, endpoints: String, lifetime: Int, guestPort: UInt16) throws -> HubGuest {
        let ok = try RustTunnel.call(["op": "hub_invite", "id": id, "group": group, "endpoints": try RustTunnel.json(endpoints) ?? [Any](),
                                      "lifetime": lifetime, "guest_port": Int(guestPort)])
        guard let text = ok["text"] as? String, let s = ok["secret"] as? String, let secret = Data(base64Encoded: s),
              let expires = RustTunnel.number(ok["expires"]) else {
            throw RustTunnel.Failure(message: "the tunnel's invitation does not read", details: "")
        }
        return RustGuest(hub: id, guest: try RustTunnel.id(ok, "guest"), text: text, secret: secret,
                         expires: Date(timeIntervalSince1970: TimeInterval(expires)))
    }

    func close() {
        let (first, ctx): (Bool, UnsafeMutableRawPointer?) = lock.withLock {
            defer { (closed, registration) = (true, nil) }
            return (!closed, registration)
        }
        guard first else { return }
        _ = try? RustTunnel.call(["op": "hub_stop", "id": id])
        // The hub has stopped, and its registration with it: no callback
        // comes after this.
        TunnelCallbacks.release(ctx)
    }
}

/// The guest tunnel of a remote invitation.
final class RustGuest: HubGuest, @unchecked Sendable {
    let hub: Int
    let guest: Int
    let text: String
    let secret: Data
    let expires: Date

    init(hub: Int, guest: Int, text: String, secret: Data, expires: Date) {
        (self.hub, self.guest, self.text, self.secret, self.expires) = (hub, guest, text, secret, expires)
    }

    func admitted() { _ = try? RustTunnel.call(["op": "guest_admitted", "id": hub, "guest": guest]) }

    func close() { _ = try? RustTunnel.call(["op": "guest_close", "id": hub, "guest": guest]) }
}

/// Links to a blind relay (RelayLinks).
public struct RustRelayLinks: RelayLinks {
    public init() {}

    public func newKey() throws -> Data { try RustTunnels().newKey() }

    public func start(privateKey: Data, device: String, endpoint: String, pin: String, chain: [Data],
                      sign: @escaping @Sendable (Data) throws -> Data, records: String, memberPort: UInt16,
                      events: RelayLinkEvents) throws -> RelayLink {
        guard let leaf = chain.first else { throw RustTunnel.Failure(message: "the member certificate is missing", details: "") }
        var req: [String: Any] = ["key": privateKey.base64EncodedString(), "device": device, "endpoint": endpoint,
                                  "pins": [pin], "chain": chain.map { $0.base64EncodedString() },
                                  "public": try RustTunnel.point(certificate: leaf).base64EncodedString(),
                                  "member_port": Int(memberPort)]
        if let r = try RustTunnel.json(records) { req["records"] = r }
        let link = RustRelay(events: events)
        let ctx = TunnelCallbacks(sign: sign) { [weak link] e in link?.event(e) }.retained()
        let ok: [String: Any]
        do {
            ok = try RustTunnel.answer(req) { r, n in cbb_tunnel_relay(r.baseAddress, r.count, tunnelSign, tunnelEvent, ctx, n) }
        } catch {
            TunnelCallbacks.release(ctx)
            throw error
        }
        link.started(id: try RustTunnel.id(ok), callbacks: ctx)
        return link
    }
}

/// A running link to a blind relay. The library asks which devices are
/// connected another way, where cbbtun asked whether each one is wanted:
/// the link asks the kit about each device on the relay whenever the
/// relay's list changes and every few seconds, and tells the library.
final class RustRelay: RelayLink, @unchecked Sendable {
    private let events: RelayLinkEvents
    private let lock = NSLock()
    private var id: Int?
    private var callbacks: UnsafeMutableRawPointer?
    private var credentials: UnsafeMutableRawPointer?
    private var online: [String] = []
    private var connected: Set<String> = []
    private var closed = false
    private var timer: DispatchSourceTimer?

    /// How often the link asks the kit again which devices it wants.
    static let wantCheck: DispatchTimeInterval = .seconds(2)

    init(events: RelayLinkEvents) { self.events = events }

    deinit { close() }

    func started(id: Int, callbacks: UnsafeMutableRawPointer) {
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + Self.wantCheck, repeating: Self.wantCheck)
        t.setEventHandler { [weak self] in self?.askWanted() }
        lock.withLock { (self.id, self.callbacks, timer) = (id, callbacks, t) }
        t.resume()
        askWanted()
    }

    /// An event of the library, on one of its threads.
    func event(_ e: [String: Any]) {
        let peer = e["peer"] as? String ?? ""
        let port = RustTunnel.number(e["port"]).flatMap { UInt16(exactly: $0) } ?? 0
        switch e["type"] as? String {
        case "dial": events.dial(peer: peer, port: port)
        case "calling": events.calling(peer: peer, localPort: port)
        case "changed":
            var state = e
            state["type"] = nil
            let on = state["online"] as? [String] ?? []
            lock.withLock { online = on }
            if let d = try? JSONSerialization.data(withJSONObject: state) { events.changed(String(decoding: d, as: UTF8.self)) }
            askWanted()
        default: break
        }
    }

    /// Tells the library the devices on the relay the kit does not want
    /// through it now.
    private func askWanted() {
        let (id, on): (Int?, [String]) = lock.withLock { (closed ? nil : self.id, online) }
        guard let id else { return }
        let other = Set(on.filter { !events.wanted(peer: $0) })
        let changed: Bool = lock.withLock {
            defer { connected = other }
            return connected != other
        }
        if changed { _ = try? RustTunnel.call(["op": "relay_set_connected", "id": id, "devices": Array(other)]) }
    }

    func setRecords(_ records: String) throws {
        guard let id = lock.withLock({ id }) else { return }
        _ = try RustTunnel.call(["op": "relay_set_records", "id": id, "records": try RustTunnel.json(records) ?? [Any]()])
    }

    func setCredentials(serverKey: Data, sign: @escaping @Sendable (Data) throws -> Data, creds: String, roots: String, names: String) throws {
        guard let id = lock.withLock({ id }) else { return }
        var req: [String: Any] = ["id": id, "credentials": try RustTunnel.json(creds) ?? [Any](),
                                  "roots": try RustTunnel.json(roots) ?? [Any](), "names": try RustTunnel.json(names) ?? [String: Any]()]
        if !creds.isEmpty { req["public"] = try RustTunnel.point(spki: serverKey).base64EncodedString() }
        let ctx = TunnelCallbacks(sign: sign).retained()
        do {
            _ = try RustTunnel.answer(req) { r, n in cbb_tunnel_relay_credentials(r.baseAddress, r.count, tunnelSign, ctx, n) }
        } catch {
            TunnelCallbacks.release(ctx)
            throw error
        }
        // The callbacks of the credentials before stay with the library
        // while a registration may still sign with them: they go with the
        // link.
        lock.withLock {
            if let old = credentials { retired.append(old) }
            credentials = ctx
        }
    }

    /// Callbacks of credentials replaced, released when the link stops.
    private var retired: [UnsafeMutableRawPointer] = []

    func close() {
        let (id, ctxs, t): (Int?, [UnsafeMutableRawPointer], DispatchSourceTimer?) = lock.withLock {
            defer {
                closed = true
                (callbacks, credentials, retired, timer) = (nil, nil, [], nil)
            }
            return (closed ? nil : self.id, [callbacks, credentials].compactMap { $0 } + retired, timer)
        }
        t?.cancel()
        guard let id else { return }
        _ = try? RustTunnel.call(["op": "relay_stop", "id": id])
        // The link has stopped: no callback comes after this.
        ctxs.forEach(TunnelCallbacks.release)
    }
}
