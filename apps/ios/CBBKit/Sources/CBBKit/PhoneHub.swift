// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The phone as the group's hub while its app is open (docs/design.md, "The
/// phone as the hub", D-64): the clients it admits by the tunnel keys their
/// hellos offer, and the offers it answers with (docs/protocol.md, section
/// 11), by the same rules as a computer's hub. The tunnel itself is
/// cbbtun's Hub, which takes clientsJSON. It is thread-safe.
public final class PhoneHub: @unchecked Sendable {
    /// A client: its device ID, the tunnel key it offered and its
    /// preshared key, and whether this hub met it itself (by its hello)
    /// rather than only taking it from another hub.
    public struct Client: Codable, Equatable, Sendable {
        public var device: String
        public var key: Data
        public var psk: Data
        public var met: Bool

        public init(device: String, key: Data, psk: Data, met: Bool = false) { (self.device, self.key, self.psk, self.met) = (device, key, psk, met) }

        /// The same without met, as cbbtun and the other hubs take it.
        public var shared: Client { Client(device: device, key: key, psk: psk) }

        enum CodingKeys: String, CodingKey { case device, key, psk, met }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            device = try c.decode(String.self, forKey: .device)
            key = try c.decode(Data.self, forKey: .key)
            psk = try c.decode(Data.self, forKey: .psk)
            met = try c.decodeIfPresent(Bool.self, forKey: .met) ?? false
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(device, forKey: .device)
            try c.encode(key, forKey: .key)
            try c.encode(psk, forKey: .psk)
            if met { try c.encode(true, forKey: .met) }
        }
    }

    public enum Refused: Error, Equatable { case badDevice, badKey, keyOfAnother(String), tooManyClients }

    /// The most clients a hub keeps, as a computer's hub.
    public static let maxClients = 256

    /// The hub's WireGuard public key.
    public let publicKey: Data
    private let lock = NSLock()
    private var list: [Client]
    private var link = Link()
    /// The other hubs' offers without a preshared key, by device, which
    /// this hub passes on to its clients.
    private var others: [String: Member.TunnelOffer] = [:]

    /// What the offers carry besides the keys.
    struct Link {
        var endpoints: [String] = []
        var obfuscation: Member.Obfuscation?
        var vlessOnly = false
        var vless: Member.VLESS?
    }

    public init(publicKey: Data, clients: [Client] = []) {
        precondition(publicKey.count == 32, "a WireGuard key is 32 bytes")
        (self.publicKey, list) = (publicKey, clients)
    }

    public var clients: [Client] { lock.withLock { list } }

    /// Where the clients reach the hub away from home, "ip:port": the
    /// forwarder's endpoint, which the offers carry.
    public var endpoints: [String] {
        get { lock.withLock { link.endpoints } }
        set { lock.withLock { link.endpoints = newValue } }
    }

    /// The group's obfuscation settings, nil for plain WireGuard.
    public var obfuscation: Member.Obfuscation? {
        get { lock.withLock { link.obfuscation } }
        set { lock.withLock { link.obfuscation = newValue } }
    }

    /// Whether the clients may come only over VLESS: the offers then wait
    /// for vless, the way to the forwarder that its answer gives (cbbtun's
    /// Status).
    public var vlessOnly: Bool {
        get { lock.withLock { link.vlessOnly } }
        set { lock.withLock { link.vlessOnly = newValue } }
    }

    /// The way to the forwarder over VLESS, nil without it.
    public var vless: Member.VLESS? {
        get { lock.withLock { link.vless } }
        set { lock.withLock { link.vless = newValue } }
    }

    /// Admits device with the tunnel key and the preshared key it offered
    /// (nil from an older member), as Go's State.Admit: the client's own
    /// preshared key when it offers one, so every hub of the group uses the
    /// same (docs/protocol.md, section 11, "Several hubs"); otherwise a
    /// client that keeps its key keeps its preshared key, and a new key
    /// gets a new one. changed tells whether the clients must be saved and
    /// handed to the tunnel again. It refuses a key that is not 32 bytes,
    /// the hub's own, or another client's, and a 257th client.
    public func admit(device: String, key: Data, psk: Data? = nil) throws -> (client: Client, changed: Bool) {
        try lock.withLock {
            guard GroupCertificates.isDeviceID(device) else { throw Refused.badDevice }
            guard key.count == 32, key.contains(where: { $0 != 0 }), key != publicKey else { throw Refused.badKey }
            let own = psk.flatMap { $0.count == 32 && $0.contains(where: { $0 != 0 }) ? $0 : nil }
            let i = list.firstIndex { $0.device == device }
            if let other = list.enumerated().first(where: { $0.offset != i && $0.element.key == key }) {
                throw Refused.keyOfAnother(other.element.device)
            }
            if let i {
                let c = list[i]
                if c.met && c.key == key && (own == nil || own == c.psk) { return (c, false) }
                list[i] = Client(device: device, key: key, psk: own ?? (c.key == key ? c.psk : Self.newPSK()), met: true)
                return (list[i], true)
            }
            guard list.count < Self.maxClients else { throw Refused.tooManyClients }
            let c = Client(device: device, key: key, psk: own ?? Self.newPSK(), met: true)
            list.append(c)
            return (c, true)
        }
    }

    /// Takes a client another hub shared or handed over, with the keys it
    /// has, as Go's State.Take: a client this hub met itself stays as it
    /// is; one only taken before gets the new keys. It returns whether the
    /// clients changed, and refuses as admit.
    @discardableResult
    public func take(_ c: Client) throws -> Bool {
        try lock.withLock {
            guard GroupCertificates.isDeviceID(c.device) else { throw Refused.badDevice }
            guard c.key.count == 32, c.psk.count == 32, c.key.contains(where: { $0 != 0 }), c.psk.contains(where: { $0 != 0 }),
                  c.key != publicKey else { throw Refused.badKey }
            let i = list.firstIndex { $0.device == c.device }
            if let other = list.enumerated().first(where: { $0.offset != i && $0.element.key == c.key }) {
                throw Refused.keyOfAnother(other.element.device)
            }
            if let i {
                let o = list[i]
                if o.met || o.key == c.key && o.psk == c.psk { return false }
                list[i] = c.shared
                return true
            }
            guard list.count < Self.maxClients else { throw Refused.tooManyClients }
            list.append(c.shared)
            return true
        }
    }

    /// Keeps the offer of another hub, from what it shared, to pass on;
    /// nil forgets it. It returns whether it changed.
    @discardableResult
    public func setOther(_ device: String, offer: Member.TunnelOffer?) -> Bool {
        lock.withLock {
            guard let offer, offer.hubKey != publicKey else { return others.removeValue(forKey: device) != nil }
            let o = offer.with(psk: Data(), hub: nil)
            defer { others[device] = o }
            return others[device] != o
        }
    }

    /// The offers the client c gets: this hub's own, then the other hubs'
    /// with c's preshared key and the hub named, highest first in order.
    public func offers(for c: Client, order: [String] = []) -> [Member.TunnelOffer] {
        guard let own = offer(for: c) else { return [] }
        func rank(_ d: String) -> Int { order.firstIndex(of: d) ?? order.count }
        let rest = lock.withLock { others }
            .filter { $0.key != c.device }
            .sorted { (rank($0.key), $0.key) < (rank($1.key), $1.key) }
            .map { $0.value.with(psk: c.psk, hub: $0.key) }
        return [own] + rest
    }

    /// What this hub shares with the group's other hubs: that it serves,
    /// its offer without a preshared key and its clients; nil while its
    /// offers wait for VLESS.
    public func share() -> Member.HubShare? {
        let l = lock.withLock { link }
        if l.vlessOnly && l.vless == nil { return nil }
        let o = Member.TunnelOffer(hubKey: publicKey, psk: Data(), endpoints: Array(l.endpoints.prefix(8)), obfuscation: l.obfuscation, vless: l.vless)
        return Member.HubShare(serving: true, offer: o, clients: clients.map(\.shared))
    }

    /// The offer for a client admitted with admit, or nil while the offers
    /// wait for VLESS.
    public func offer(for c: Client) -> Member.TunnelOffer? {
        let l = lock.withLock { link }
        if l.vlessOnly && l.vless == nil { return nil }
        return Member.TunnelOffer(hubKey: publicKey, psk: c.psk, endpoints: Array(l.endpoints.prefix(8)), obfuscation: l.obfuscation, vless: l.vless)
    }

    /// Admits a peer and returns its offer, for MemberNode's hub: nil when
    /// it is refused (refused tells why) or the offers wait. changed gets
    /// the clients when they changed.
    public func offer(device: String, key: Data, changed: ([Client]) -> Void = { _ in },
                      refused: (Error) -> Void = { _ in }) -> Member.TunnelOffer? {
        offers(device: device, key: key, psk: nil, changed: changed, refused: refused).first
    }

    /// Admits a peer with the keys its hello offers and returns its offers,
    /// this hub's own first, for MemberNode's hub: none when it is refused
    /// (refused tells why) or the offers wait. changed gets the clients
    /// when they changed.
    public func offers(device: String, key: Data, psk: Data?, order: [String] = [], changed: ([Client]) -> Void = { _ in },
                       refused: (Error) -> Void = { _ in }) -> [Member.TunnelOffer] {
        let admitted: (client: Client, changed: Bool)
        do {
            admitted = try admit(device: device, key: key, psk: psk)
        } catch {
            refused(error)
            return []
        }
        if admitted.changed { changed(clients) }
        return offers(for: admitted.client, order: order)
    }

    /// The offer the client device gets when the hub moves to newHub,
    /// whose offer without a preshared key is offer (a hub command's
    /// result): with the client's own preshared key and newHub named
    /// (docs/protocol.md, section 11, "Moving the hub"); nil for a device
    /// that is no client, or newHub itself.
    public func movedOffer(device: String, newHub: String, offer: Member.TunnelOffer) -> Member.TunnelOffer? {
        guard device != newHub, let c = clients.first(where: { $0.device == device }) else { return nil }
        return offer.with(psk: c.psk, hub: newHub, moved: true)
    }

    /// Forgets the clients keep refuses, removed devices for one, and
    /// returns their devices.
    @discardableResult
    public func prune(keep: (Client) -> Bool) -> [String] {
        lock.withLock {
            let gone = list.filter { !keep($0) }.map(\.device)
            list.removeAll { !keep($0) }
            return gone
        }
    }

    /// The clients as cbbtun's StartHub and SetClients take them.
    public func clientsJSON() throws -> String {
        String(decoding: try JSONEncoder().encode(clients.map(\.shared)), as: UTF8.self)
    }

    /// The clients clientsJSON gave.
    public static func clients(json: String) throws -> [Client] {
        json.isEmpty ? [] : try JSONDecoder().decode([Client].self, from: Data(json.utf8))
    }

    private static func newPSK() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }
}
