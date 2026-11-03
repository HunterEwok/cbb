// SPDX-License-Identifier: AGPL-3.0-only

import Cbbtun
import ClipboardBridgeKit
import Foundation
import Security

/// The tunnel of mobile/cbbtun, WireGuard in the app's process, bound by
/// gomobile into Cbbtun.xcframework (mobile/cbbtun/bind.sh ios).
struct GoTunnels: Tunnels {
    /// A call that failed without saying why.
    struct Failure: Error { let call: String }

    func newKey() throws -> Data { try Self.call("NewKey") { CbbtunNewKey($0) } }

    func publicKey(_ privateKey: Data) throws -> Data { try Self.call("PublicKey") { CbbtunPublicKey(privateKey, $0) } }

    func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String,
               obfuscation: String, vless: String) throws -> OpenTunnel {
        GoTunnel(try Self.call("Start") { CbbtunStart(privateKey, psk, hubKey, device, hub, endpoint, obfuscation, vless, $0) })
    }

    private static func call<T>(_ name: String, _ f: (NSErrorPointer) -> T?) throws -> T {
        var error: NSError?
        if let v = f(&error) { return v }
        throw error ?? Failure(call: name)
    }
}

/// A running tunnel of mobile/cbbtun.
final class GoTunnel: OpenTunnel, @unchecked Sendable {
    private let tunnel: CbbtunTunnel
    let port: UInt16

    init(_ tunnel: CbbtunTunnel) {
        self.tunnel = tunnel
        port = UInt16(clamping: tunnel.port())
    }

    func setEndpoint(_ endpoint: String) throws { try tunnel.setEndpoint(endpoint) }

    func close() { try? tunnel.close() }
}

/// The hub of mobile/cbbtun, WireGuard in the app's process.
struct GoHubTunnels: HubTunnels {
    func newKey() throws -> Data { try GoTunnels().newKey() }

    func publicKey(_ privateKey: Data) throws -> Data { try GoTunnels().publicKey(privateKey) }

    func start(privateKey: Data, device: String, memberPort: UInt16, clients: String) throws -> HubTunnel {
        var error: NSError?
        guard let h = CbbtunStartHub(privateKey, device, Int(memberPort), "", clients, &error) else {
            throw error ?? GoTunnels.Failure(call: "StartHub")
        }
        return GoHub(h)
    }
}

/// A running hub of mobile/cbbtun.
final class GoHub: HubTunnel, @unchecked Sendable {
    private let hub: CbbtunHub

    init(_ hub: CbbtunHub) { self.hub = hub }

    func setClients(_ json: String) throws { try hub.setClients(json) }

    func register(endpoint: String, pin: String, chain: [Data], sign: @escaping @Sendable (Data) throws -> Data, records: String) throws {
        let ders = String(decoding: try JSONEncoder().encode(chain), as: UTF8.self)
        try hub.register(endpoint, pin: pin, chain: ders, signer: DigestSigner(sign), records: records, vlessID: "")
    }

    func setRecords(_ records: String) throws { try hub.setRecords(records) }

    func status() -> String { hub.status() }

    func invite(group: String, endpoints: String, lifetime: Int, guestPort: UInt16) throws -> HubGuest {
        GoGuest(try hub.invite(group, endpoints: endpoints, lifetime: lifetime, guestPort: Int(guestPort)))
    }

    func close() { try? hub.close() }
}

/// cbbtun's guest tunnel of a remote invitation.
final class GoGuest: HubGuest, @unchecked Sendable {
    private let guest: CbbtunGuest
    let text: String
    let secret: Data
    let expires: Date

    init(_ g: CbbtunGuest) {
        guest = g
        (text, secret, expires) = (g.text(), g.secret() ?? Data(), Date(timeIntervalSince1970: TimeInterval(g.expires())))
    }

    func admitted() { guest.admitted() }

    func close() { guest.close() }
}

/// The links of mobile/cbbtun to a blind relay.
struct GoRelayLinks: RelayLinks {
    func newKey() throws -> Data { try GoTunnels().newKey() }

    func start(privateKey: Data, device: String, endpoint: String, pin: String, chain: [Data],
               sign: @escaping @Sendable (Data) throws -> Data, records: String, memberPort: UInt16,
               events: RelayLinkEvents) throws -> RelayLink {
        let ders = String(decoding: try JSONEncoder().encode(chain), as: UTF8.self)
        var error: NSError?
        guard let r = CbbtunStartRelay(privateKey, device, endpoint, pin, ders, DigestSigner(sign), records, Int(memberPort),
                                       GoRelayEvents(events), &error) else {
            throw error ?? GoTunnels.Failure(call: "StartRelay")
        }
        return GoRelay(r)
    }
}

/// A running link of mobile/cbbtun to a blind relay.
final class GoRelay: RelayLink, @unchecked Sendable {
    private let relay: CbbtunRelay

    init(_ relay: CbbtunRelay) { self.relay = relay }

    func setRecords(_ records: String) throws { try relay.setRecords(records) }

    func setCredentials(serverKey: Data, sign: @escaping @Sendable (Data) throws -> Data, creds: String, roots: String, names: String) throws {
        try relay.setCredentials(serverKey, signer: DigestSigner(sign), creds: creds, roots: roots, names: names)
    }

    func close() { relay.close() }
}

/// The kit's RelayLinkEvents as cbbtun's RelayEvents.
final class GoRelayEvents: NSObject, CbbtunRelayEventsProtocol, @unchecked Sendable {
    private let events: RelayLinkEvents

    init(_ events: RelayLinkEvents) { self.events = events }

    func dial(_ peer: String?, port: Int) { events.dial(peer: peer ?? "", port: UInt16(clamping: port)) }

    func calling(_ peer: String?, localPort: Int) { events.calling(peer: peer ?? "", localPort: UInt16(clamping: localPort)) }

    func wanted(_ peer: String?) -> Bool { events.wanted(peer: peer ?? "") }

    func changed(_ state: String?) { events.changed(state ?? "") }
}

/// The member key as cbbtun's Signer: it signs the digests of the hub's
/// TLS to its forwarder, without the user.
final class DigestSigner: NSObject, CbbtunSignerProtocol, @unchecked Sendable {
    private let sign: @Sendable (Data) throws -> Data

    init(_ sign: @escaping @Sendable (Data) throws -> Data) { self.sign = sign }

    func signDigest(_ digest: Data?) throws -> Data { try sign(digest ?? Data()) }
}

/// A small item in the keychain: readable after the first unlock, so the
/// app syncs in the background as at home, and never in a backup or on
/// another device.
enum KeychainData {
    enum Failure: Error { case keychain(OSStatus) }

    private static func query(_ service: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "state"]
    }

    static func load(_ service: String) -> Data? {
        var q = query(service)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    /// Keeps data; nil deletes it.
    static func save(_ service: String, _ data: Data?) throws {
        guard let data else {
            let status = SecItemDelete(query(service) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
            return
        }
        let attrs: [String: Any] = [kSecValueData as String: data,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var status = SecItemUpdate(query(service) as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query(service).merging(attrs) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }
}

/// The state of sync away from home in the keychain.
enum AwayKeychain {
    static let service = "tools.cbb.away"

    static func load() -> AwayState? { KeychainData.load(service).flatMap(AwayState.decode) }

    /// Keeps s; nil deletes it.
    static func save(_ s: AwayState?) throws { try KeychainData.save(service, try s.map { try $0.encoded() }) }
}

/// The phone's state as the group's hub in the keychain.
enum HubKeychain {
    static let service = "tools.cbb.hub"

    static func load() -> HubState? { KeychainData.load(service).flatMap(HubState.decode) }

    /// Keeps s; nil deletes it.
    static func save(_ s: HubState?) throws { try KeychainData.save(service, try s.map { try $0.encoded() }) }
}

/// The phone's settings for a blind relay in the keychain.
enum RelayKeychain {
    static let service = "tools.cbb.relay"

    static func load() -> RelaySettings? { KeychainData.load(service).flatMap(RelaySettings.decode) }

    /// Keeps s; nil deletes it.
    static func save(_ s: RelaySettings?) throws { try KeychainData.save(service, try s.map { try $0.encoded() }) }
}
