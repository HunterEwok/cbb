// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security)
import Foundation
import Security

/// What the app keeps for push in a keychain access group of its own that
/// the notification extension shares (docs/core-api.md, "Push"), this
/// device only, readable after the first unlock. The app writes it; the
/// extension writes nothing but a challenge for this phone's own send key
/// (`keep(challenge:)`).
///
/// It holds what opens a body and a copy in it, and nothing that signs a
/// record: the push keys, the send key (which signs only registrations to
/// the push service), and the phone's sealing secrets of the epochs still
/// in the group's window, with the origins and the window. Never the member
/// key, an admin's or the root's key, or the recovery secret: those stay in
/// the member key's own access group, which the extension does not have.
///
/// One sender per token, for every group: the token, its platform, the send
/// key drawn for it, the key's hint and the last challenge the push service
/// sent to it. Per group: the push keys (the current one first; the
/// previous one kept for late bodies, but not after a membership change),
/// the slot, the last registration (its seq and frame, which the member's
/// sync sends to the group's members), the highest seq given, and what
/// `push_open` needs.
public final class PushVault: @unchecked Sendable {
    public enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus)
        case unreadable
        case incomplete
        case noFace

        public var description: String {
            switch self {
            case let .keychain(s): "the keychain refused the push keys (\(s))"
            case .unreadable: "the push keys in the keychain do not read"
            case .incomplete: "push needs a token and its platform"
            case .noFace: "push needs the group's face for the push service, which this group has not given yet"
            }
        }
    }

    /// The token's sender, shared by every group.
    public struct Sender: Codable, Equatable {
        public var token: Data?
        public var env: UInt64?
        /// The send key (PKCS #8), drawn with each new token.
        public var sendKey: Data?
        /// The first 8 bytes of the send key's hash, which the push service
        /// puts beside each challenge.
        public var keyHint: Data?
        /// The last challenge the push service sent to this token for this
        /// send key; the next registrations carry it.
        public var challenge: Data?

        public init() {}
    }

    /// One group's push state.
    public struct Group: Codable, Equatable {
        public var keys: [Push.KeyAndSeq] = []
        /// The group's slot, kept for as long as the group is.
        public var slot: Data?
        public var kinds: UInt64 = 0
        /// The last registration's seq, and the highest one given (higher
        /// when a member said the number was ahead and the phone started
        /// again from its clock).
        public var seq: UInt64?
        public var highest: UInt64?
        public var frame: Data?
        /// What the last registration said: a new one is made only when
        /// this changes, never just because the app ran.
        public var registered: Registered?
        /// When the current push key was drawn (the phone's clock): a
        /// membership change the extension heard of before it is applied.
        public var keyDrawnMS: UInt64?
        /// This phone's device ID in the group.
        public var me: Data?
        /// The group's devices and its root as the app last applied them:
        /// a hints-only mark of a change already applied is spent.
        public var members: [Data]?
        public var root: Data?
        public var origins: [Push.Origin] = []
        public var sealing: [Push.Sealing] = []
        public var tooOld = false
        public var halted = false
        public var windowMS: UInt64?

        public init() {}

        /// What `push_open` is given, or nil when push is off here.
        public func context(hintsOnly: Bool) -> Push.Context? {
            guard let me, !keys.isEmpty else { return nil }
            return Push.Context(keys: keys, me: me, origins: origins, sealing: sealing, tooOld: tooOld, halted: halted,
                                hintsOnly: hintsOnly, windowMS: windowMS)
        }
    }

    /// What a registration was made of.
    public struct Registered: Codable, Equatable {
        public var token: Data?
        public var env: UInt64?
        public var kinds: UInt64
        public var key: Data?
        public var sendKey: Data?
        public var face: Data?
        public var challenge: Data?
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

    /// The sender's item lives under a service of its own, so that
    /// `groups()` lists only groups.
    private var senderService: String { service + ".sender" }
    private static let senderAccount = "sender"

    private func query(_ service: String, _ account: String) -> [CFString: Any] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        return q
    }

    private func read<T: Decodable>(_ service: String, _ account: String, as _: T.Type) throws -> T? {
        var q = query(service, account)
        q[kSecReturnData] = true
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return nil }
        guard s == errSecSuccess, let d = out as? Data else { throw Failure.keychain(s) }
        guard let v = try? JSONDecoder().decode(T.self, from: d) else { throw Failure.unreadable }
        return v
    }

    private func write<T: Encodable>(_ service: String, _ account: String, _ v: T?) throws {
        SecItemDelete(query(service, account) as CFDictionary)
        guard let v else { return }
        var add = query(service, account)
        add[kSecValueData] = try JSONEncoder().encode(v)
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let s = SecItemAdd(add as CFDictionary, nil)
        guard s == errSecSuccess else { throw Failure.keychain(s) }
    }

    /// The group's state; an empty one when there is none.
    public func load(_ group: String) throws -> Group {
        try read(service, group, as: Group.self) ?? Group()
    }

    public func save(_ group: String, _ g: Group?) throws {
        try write(service, group, g)
    }

    /// The token's sender; an empty one when there is none.
    public func sender() throws -> Sender {
        try read(senderService, Self.senderAccount, as: Sender.self) ?? Sender()
    }

    public func save(sender: Sender?) throws {
        try write(senderService, Self.senderAccount, sender)
    }

    /// Every group with push state.
    public func groups() throws -> [String] {
        try accounts(service)
    }

    private func accounts(_ service: String) throws -> [String] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                  kSecMatchLimit: kSecMatchLimitAll, kSecReturnAttributes: true]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return [] }
        guard s == errSecSuccess, let items = out as? [[CFString: Any]] else { throw Failure.keychain(s) }
        return items.compactMap { $0[kSecAttrAccount] as? String }.sorted()
    }

    /// Every item the vault wrote, as stored: what the extension can read.
    public func items() throws -> [Data] {
        var out: [Data] = []
        for (service, accounts) in [(service, try accounts(service)), (senderService, try accounts(senderService))] {
            for a in accounts {
                var q = query(service, a)
                q[kSecReturnData] = true
                var d: CFTypeRef?
                let s = SecItemCopyMatching(q as CFDictionary, &d)
                guard s == errSecSuccess, let data = d as? Data else { throw Failure.keychain(s) }
                out.append(data)
            }
        }
        return out
    }

    /// Removes the group: its push keys, slot, secrets and origins. The
    /// sender stays while the token does, so the next group registers under
    /// the same send key, whose binding the push service has confirmed.
    public func forget(_ group: String) throws {
        lock.lock()
        defer { lock.unlock() }
        try save(group, nil)
    }

    /// The phone is leaving the group: the registration that turns push
    /// off there, which the member's sync sends to the group's members
    /// while the phone still can (nil when push is already off there).
    public func leaving(_ group: String, now: Date = Date()) throws -> Push.Registration? {
        let g = try load(group)
        guard let me = g.me, g.kinds != 0 else { return nil }
        return try register(group, me: me, token: nil, env: nil, kinds: [], now: now)
    }

    /// The phone left the group: the group goes, and so does the send key,
    /// so that the registration the left group's members hold stops being
    /// good once the phone's other groups confirm the new one; the next
    /// registration draws the new send key. With no group left the sender
    /// goes whole, token and all, and the answer is true: the app gives the
    /// token up, since no other group would confirm a new key.
    @discardableResult
    public func left(_ group: String) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        try save(group, nil)
        if try groups().isEmpty {
            try save(sender: nil)
            return true
        }
        var s = try sender()
        guard s.sendKey != nil else { return false }
        s.sendKey = nil
        s.keyHint = nil
        s.challenge = nil
        try save(sender: s)
        return false
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

    /// What opens a copy in a body, which the app writes on every rotation
    /// of its sealing key and whenever the group's devices change: the
    /// sealing secrets of the epochs still in the window (any other is
    /// erased here), the devices as origins, the window, and whether the
    /// group is halted or the records too old.
    public func opening(_ group: String, sealing: [Push.Sealing], origins: [Push.Origin], windowMS: UInt64?,
                        halted: Bool, tooOld: Bool = false) throws {
        try update(group) { g in
            g.sealing = sealing
            g.origins = origins
            g.windowMS = windowMS
            g.halted = halted
            g.tooOld = tooOld
        }
    }

    /// Keeps a challenge the push service sent (24 bytes: the value, then
    /// the hint of the send key it is for) when it is for this phone's send
    /// key, and says whether it kept it. Any other is dropped: a challenge
    /// of another key or token confirms nothing.
    @discardableResult
    public func keep(challenge: Data) throws -> Bool {
        guard challenge.count == 24 else { return false }
        lock.lock()
        defer { lock.unlock() }
        var s = try sender()
        guard let hint = s.keyHint, hint == challenge.suffix(8), s.sendKey != nil else { return false }
        let value = Data(challenge.prefix(16))
        if s.challenge == value { return false }
        s.challenge = value
        try save(sender: s)
        return true
    }

    /// The group's devices (their IDs) and its root, as the app applied
    /// them.
    public struct Devices: Equatable, Sendable {
        public var members: [Data]
        public var root: Data?
        public init(members: [Data], root: Data?) {
            self.members = members
            self.root = root
        }
    }

    /// Why a group registers again.
    public struct Reasons: OptionSet, Sendable {
        public let rawValue: Int
        public init(rawValue: Int) { self.rawValue = rawValue }
        /// The phone applied a removal, a new root or a stop: a new push
        /// key, and the previous one is not kept.
        public static let membership = Reasons(rawValue: 1)
        /// A member asked for it (`push-renew`): the push service lost the
        /// registration.
        public static let renew = Reasons(rawValue: 2)
        /// A member's `push-renew` said the push service found the number
        /// more than a day past its clock: the next one starts again from
        /// the phone's clock, once.
        public static let ahead = Reasons(rawValue: 4)
    }

    /// The group's registration for `token` of `env` with `kinds` (empty:
    /// push off), made again only when something in it changed or for
    /// `reasons`; nil when the saved one still says it all. `face` is the
    /// group's face for the push service, which the registration names: a
    /// new face makes a new registration. A new token gets a new send key,
    /// which drops the challenge of the old one. The highest seq is saved
    /// with the frame, so the next one is higher.
    @discardableResult
    public func register(_ group: String, me: Data, token: Data?, env: UInt64?, kinds: Push.Kinds, face: Data? = nil,
                         reasons: Reasons = [], devices: Devices? = nil, now: Date = Date()) throws -> Push.Registration? {
        lock.lock()
        defer { lock.unlock() }
        var g = try load(group)
        var s = try sender()
        g.me = me
        // A device gone or a new root: a membership change. The new key and
        // the devices are saved together, so a mark of the change is spent
        // only once both are in place.
        var reasons = reasons
        if let devices {
            if let old = g.members, !Set(old).subtracting(devices.members).isEmpty { reasons.insert(.membership) }
            if let old = g.root, let root = devices.root, old != root { reasons.insert(.membership) }
            g.members = devices.members
            g.root = devices.root ?? g.root
        }
        if reasons.contains(.membership), kinds.isEmpty || g.kinds == 0 {
            // Push is off: no key is kept for bodies from before the change;
            // turning it on again draws a new one.
            g.keys = []
            g.keyDrawnMS = UInt64(max(0, now.timeIntervalSince1970 * 1000))
        }
        if kinds.isEmpty {
            let off = Registered(kinds: 0)
            if g.registered == off || (g.registered == nil && g.kinds == 0) {
                try save(group, g)
                return nil
            }
            let r = try Push.registration(highestSeq: g.highest ?? g.seq, restart: reasons.contains(.ahead), now: now,
                                          kinds: [], env: nil, token: nil, key: nil, sendKey: nil, slot: nil, face: nil)
            g.kinds = 0
            g.seq = r.seq
            g.highest = r.highest
            g.frame = r.frame
            g.registered = off
            try save(group, g)
            return r
        }
        guard let token, let env else { throw Failure.incomplete }
        guard let face else { throw Failure.noFace }
        if s.sendKey == nil || s.token != token || s.env != env {
            s.sendKey = try Push.newKeys().sendKey
            s.token = token
            s.env = env
            s.keyHint = nil
            s.challenge = nil
        }
        if g.slot == nil { g.slot = try Push.newKeys().slot }
        let drew = g.keys.isEmpty || g.kinds == 0 || reasons.contains(.membership)
        let key = drew ? try Push.newKeys().key : g.keys[0].key
        let wanted = Registered(token: token, env: env, kinds: kinds.rawValue, key: key, sendKey: s.sendKey, face: face,
                                challenge: s.challenge)
        if !drew, reasons.isDisjoint(with: [.renew, .ahead]), g.registered == wanted {
            try save(group, g)
            return nil
        }
        let r = try Push.registration(highestSeq: g.highest ?? g.seq, restart: reasons.contains(.ahead), now: now,
                                      kinds: kinds, env: env, token: token, key: key, sendKey: s.sendKey, slot: g.slot,
                                      face: face, challenge: s.challenge)
        // The body's seq is in its associated data: the key under the
        // previous seq stays for bodies already on their way, one entry;
        // after a membership change none, so a removed member's bodies open
        // nothing here.
        let previous = reasons.contains(.membership) || g.kinds == 0 ? nil : g.keys.first
        g.keys = [Push.KeyAndSeq(key: key, seq: r.seq)] + (previous.map { [$0] } ?? [])
        if drew { g.keyDrawnMS = UInt64(max(0, now.timeIntervalSince1970 * 1000)) }
        g.kinds = kinds.rawValue
        g.seq = r.seq
        g.highest = r.highest
        g.frame = r.frame
        g.registered = wanted
        s.keyHint = r.keyHint ?? s.keyHint
        try save(sender: s)
        try save(group, g)
        return r
    }

    /// The group whose slot this is, for a `push-renew`.
    public func group(slot: Data) throws -> String? {
        try groups().first { (try? load($0).slot) == slot }
    }
}
#endif
