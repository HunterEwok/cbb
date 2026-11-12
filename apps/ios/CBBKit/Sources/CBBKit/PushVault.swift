// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security)
import Foundation
import Security

/// What the app keeps for push, per group, in a keychain access group of
/// its own that the notification extension shares (docs/core-api.md,
/// "Push"): never the member key's group, so the extension cannot reach the
/// member key, the sealing secret or an admin's or the root's key. The app
/// writes it; the extension only reads it.
///
/// Per group: the push keys (the current one first, the previous one kept
/// for late bodies), the send key and the token it was drawn for, the last
/// registration (its seq and frame, which the member's sync sends to the
/// group's members), and what `push_open` needs to check a copy.
public final class PushVault: @unchecked Sendable {
    public enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus)
        case unreadable

        public var description: String {
            switch self {
            case let .keychain(s): "the keychain refused the push keys (\(s))"
            case .unreadable: "the push keys in the keychain do not read"
            }
        }
    }

    /// One group's push state.
    public struct Group: Codable, Equatable {
        public var keys: [Push.KeyAndSeq] = []
        public var sendKey: Data?
        /// The token and platform the send key was drawn for.
        public var token: Data?
        public var env: UInt64?
        public var kinds: UInt64 = 0
        public var seq: UInt64?
        public var frame: Data?
        /// This phone's device ID in the group.
        public var me: Data?
        public var origins: [Push.Origin] = []
        public var sealing: [Push.Sealing] = []
        public var tooOld = false
        public var halted = false
        /// The phone heard of a removal, a new root or a stop since the app
        /// last ran: copies show only as hints until it runs.
        public var hintsOnly = false
        public var windowMS: UInt64?

        public init() {}

        /// What `push_open` is given, or nil when push is off here.
        public var context: Push.Context? {
            guard let me, !keys.isEmpty else { return nil }
            return Push.Context(keys: keys, me: me, origins: origins, sealing: sealing, tooOld: tooOld, halted: halted,
                                hintsOnly: hintsOnly, windowMS: windowMS)
        }
    }

    public static let service = "tools.cbb.push"

    /// The access group; nil uses the default one (an ad hoc build without
    /// the entitlement, where push is off anyway, and the tests).
    let accessGroup: String?
    let service: String
    private let lock = NSLock()

    public init(accessGroup: String?, service: String = PushVault.service) {
        self.accessGroup = accessGroup
        self.service = service
    }

    private func query(_ group: String) -> [CFString: Any] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: group]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        return q
    }

    /// The group's state; an empty one when there is none.
    public func load(_ group: String) throws -> Group {
        var q = query(group)
        q[kSecReturnData] = true
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return Group() }
        guard s == errSecSuccess, let d = out as? Data else { throw Failure.keychain(s) }
        guard let g = try? JSONDecoder().decode(Group.self, from: d) else { throw Failure.unreadable }
        return g
    }

    /// Every group with push state.
    public func groups() throws -> [String] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                  kSecMatchLimit: kSecMatchLimitAll, kSecReturnAttributes: true]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return [] }
        guard s == errSecSuccess, let items = out as? [[CFString: Any]] else { throw Failure.keychain(s) }
        return items.compactMap { $0[kSecAttrAccount] as? String }.sorted()
    }

    public func save(_ group: String, _ g: Group?) throws {
        SecItemDelete(query(group) as CFDictionary)
        guard let g else { return }
        var add = query(group)
        add[kSecValueData] = try JSONEncoder().encode(g)
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let s = SecItemAdd(add as CFDictionary, nil)
        guard s == errSecSuccess else { throw Failure.keychain(s) }
    }

    /// Changes one group's state under the lock.
    @discardableResult
    public func update(_ group: String, _ change: (inout Group) throws -> Void) throws -> Group {
        lock.lock()
        defer { lock.unlock() }
        var g = try load(group)
        try change(&g)
        try save(group, g)
        return g
    }

    /// Makes the group's registration for `token` of `env` with `kinds`
    /// (empty: push off). A new token gets a new send key; `newKey` (the
    /// phone applied a removal, push was turned on again, a new period)
    /// draws a new push key and keeps the previous one for late bodies. The
    /// seq is saved with the frame, so the next one is higher.
    @discardableResult
    public func register(_ group: String, me: Data, token: Data?, env: UInt64?, kinds: Push.Kinds, newKey: Bool = false,
                         now: Date = Date()) throws -> Push.Registration {
        var made: Push.Registration?
        try update(group) { g in
            g.me = me
            if kinds.isEmpty {
                let r = try Push.registration(savedSeq: g.seq, now: now, kinds: [], env: nil, token: nil, key: nil, sendKey: nil)
                g.kinds = 0
                g.seq = r.seq
                g.frame = r.frame
                made = r
                return
            }
            guard let token, let env else { throw Failure.unreadable }
            if g.sendKey == nil || g.token != token || g.env != env {
                g.sendKey = try Push.newKeys().sendKey
                g.token = token
                g.env = env
            }
            // The body's seq is in its associated data: the key under the
            // previous seq stays for bodies already on their way, one entry.
            let previous = g.keys.first
            let drew = g.keys.isEmpty || newKey || g.kinds == 0
            let key = drew ? try Push.newKeys().key : g.keys[0].key
            let r = try Push.registration(savedSeq: g.seq, now: now, kinds: kinds, env: env, token: token,
                                          key: key, sendKey: g.sendKey)
            g.keys = [Push.KeyAndSeq(key: key, seq: r.seq)] + (previous.map { [$0] } ?? [])
            g.kinds = kinds.rawValue
            g.seq = r.seq
            g.frame = r.frame
            made = r
        }
        return made!
    }
}
#endif
