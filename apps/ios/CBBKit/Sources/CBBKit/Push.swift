// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// Push to the phone whose app is closed (docs/core-api.md, "Push"): the
/// core's four calls. The app draws the keys and makes each group's
/// registration; the notification extension opens what arrives. No number
/// of the format lives here: the core answers them.
public enum Push {
    /// A new push key and slot (one per group) and send key (one per
    /// token, for every group).
    public struct Keys: Codable, Equatable {
        public var key: Data
        public var sendKey: Data
        public var slot: Data

        enum CodingKeys: String, CodingKey {
            case key, slot
            case sendKey = "send_key"
        }
    }

    public static func newKeys() throws -> Keys { try Core.run("push_key") }

    /// What the core knows of a platform.
    public struct Limits: Decodable, Equatable {
        public var known: Bool
        public var body: Int?
        public var token: Int?
        public var kinds: UInt64?
    }

    public static func limits(env: UInt64) throws -> Limits {
        struct Args: Encodable { var env: UInt64 }
        return try Core.run("push_limits", Args(env: env))
    }

    /// The platforms as the env registry numbers them; the core checks each.
    public enum Env {
        public static let apns: UInt64 = 1
        public static let apnsSandbox: UInt64 = 2
    }

    /// The kinds a phone asks for, as bits.
    public struct Kinds: OptionSet, Codable, Hashable {
        public let rawValue: UInt64
        public init(rawValue: UInt64) { self.rawValue = rawValue }
        public static let copies = Kinds(rawValue: 1)
        public static let events = Kinds(rawValue: 2)
    }

    /// A registration made: the frame of message `push` for the group's
    /// members and the number it carries, which the app saves first, and
    /// with push on the send key's hint, which the push service puts beside
    /// each challenge.
    public struct Registration: Codable, Equatable {
        public var frame: Data
        public var seq: UInt64
        public var keyHint: Data?

        enum CodingKeys: String, CodingKey {
            case frame, seq
            case keyHint = "key_hint"
        }
    }

    /// Makes the registration for one group: its slot, and the last
    /// challenge the push service sent to the token, if any. With `kinds`
    /// empty push is off and the rest is not read.
    public static func registration(savedSeq: UInt64?, now: Date = Date(), kinds: Kinds, env: UInt64?,
                                    token: Data?, key: Data?, sendKey: Data?, slot: Data?,
                                    challenge: Data? = nil) throws -> Registration {
        struct Args: Encodable {
            var saved_seq: UInt64?
            var now_ms: UInt64
            var kinds: UInt64
            var env: UInt64?
            var token: Data?
            var key: Data?
            var send_key: Data?
            var slot: Data?
            var challenge: Data?
        }
        let on = !kinds.isEmpty
        return try Core.run("push_registration", Args(
            saved_seq: savedSeq, now_ms: UInt64(max(0, now.timeIntervalSince1970 * 1000)), kinds: kinds.rawValue,
            env: on ? env : nil, token: on ? token : nil, key: on ? key : nil, send_key: on ? sendKey : nil,
            slot: on ? slot : nil, challenge: on ? challenge : nil))
    }

    /// A push key with the registration number it was sent with.
    public struct KeyAndSeq: Codable, Equatable {
        public var key: Data
        public var seq: UInt64
        public init(key: Data, seq: UInt64) {
            self.key = key
            self.seq = seq
        }
    }

    /// A device the app last saved, as `push_open` checks an origin.
    public struct Origin: Codable, Equatable {
        public var key: Data
        public var rights: UInt64
        public var frozen: Bool
        public init(key: Data, rights: UInt64, frozen: Bool = false) {
            self.key = key
            self.rights = rights
            self.frozen = frozen
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            key = try c.decode(Data.self, forKey: .key)
            rights = try c.decode(UInt64.self, forKey: .rights)
            frozen = try c.decodeIfPresent(Bool.self, forKey: .frozen) ?? false
        }

        enum CodingKeys: String, CodingKey { case key, rights, frozen }
    }

    /// One of the phone's copy-opening secrets.
    public struct Sealing: Codable, Equatable {
        public var epoch: UInt64
        public var secret: Data
        public init(epoch: UInt64, secret: Data) {
            self.epoch = epoch
            self.secret = secret
        }
    }

    /// What a body said. Only `copy` states a fact; the rest is shown as
    /// "open the app".
    public struct Opened: Decodable, Equatable {
        public var kind: String
        public var keyIndex: Int
        public var id: Data?
        public var origin: Data?
        public var type: String?
        public var secret: Bool?
        public var ttlMS: UInt64?
        public var text: String?
        public var event: UInt64?
        public var device: Data?
        public var timeMS: UInt64?

        enum CodingKeys: String, CodingKey {
            case kind, id, origin, type, secret, text, event, device
            case keyIndex = "key_index"
            case ttlMS = "ttl_ms"
            case timeMS = "time_ms"
        }
    }

    /// The group as the extension sees it when a body arrives.
    public struct Context: Codable, Equatable {
        public var keys: [KeyAndSeq]
        public var me: Data
        public var origins: [Origin]
        public var sealing: [Sealing]
        public var tooOld: Bool
        public var halted: Bool
        public var hintsOnly: Bool
        public var windowMS: UInt64?

        public init(keys: [KeyAndSeq], me: Data, origins: [Origin] = [], sealing: [Sealing] = [], tooOld: Bool = false,
                    halted: Bool = false, hintsOnly: Bool = false, windowMS: UInt64? = nil) {
            self.keys = keys
            self.me = me
            self.origins = origins
            self.sealing = sealing
            self.tooOld = tooOld
            self.halted = halted
            self.hintsOnly = hintsOnly
            self.windowMS = windowMS
        }
    }

    /// Opens a body with the group's keys; throws a `Core.Refusal` (code 18)
    /// when none opens it.
    public static func open(_ body: Data, in c: Context, now: Date = Date()) throws -> Opened {
        struct Args: Encodable {
            var keys: [KeyAndSeq]
            var body: Data
            var me: Data
            var origins: [Origin]
            var sealing: [Sealing]
            var too_old: Bool
            var halted: Bool
            var hints_only: Bool
            var now_ms: UInt64
            var window_ms: UInt64?
        }
        return try Core.run("push_open", Args(
            keys: c.keys, body: body, me: c.me, origins: c.origins, sealing: c.sealing, too_old: c.tooOld,
            halted: c.halted, hints_only: c.hintsOnly, now_ms: UInt64(max(0, now.timeIntervalSince1970 * 1000)),
            window_ms: c.windowMS))
    }
}
