// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The member protocol of docs/protocol.md, sections 4 and 5, as the Rust core
/// speaks it (core/src/wire.rs, core/src/clip.rs, core/src/hlc.rs): frames of a
/// 4-byte big-endian length and a JSON message, a hello first, then events,
/// pings, records and goodbyes.
public enum Member {
    /// The ALPN protocol of member connections.
    public static let alpn = "cbb/3"
    /// The feature of the hello (section 4, "Hello") that says the sender
    /// serves the content of media events, and how many names of the
    /// hello's features a receiver reads.
    static let featureMedia = "media"
    static let maxFeatures = 32
    /// The most device IDs of a reach message (section 4, "Reach").
    static let maxReach = 256
    /// Frames larger than this close the connection.
    public static let maxFrame = 7 << 20
    /// The most bytes of a part one chunk carries (section 4, "Content").
    public static let chunkSize = 256 << 10
    /// The most bytes one get asks for.
    public static let getWindow: Int64 = 1 << 20
    /// A chunk's frame is padded to a multiple of this, so the network
    /// learns less of the parts' sizes.
    public static let chunkPad = 16 << 10
    /// The start of a chunk's frame: the part's SHA-256, the offset and the
    /// data's length.
    public static let chunkHead = 32 + 8 + 4
    /// The largest chunk frame, padding included; a longer one closes the
    /// connection.
    public static let maxChunkFrame = (chunkHead + chunkSize + chunkPad - 1) / chunkPad * chunkPad
    /// The top bit of a frame's length marks a binary chunk frame.
    static let binaryFrame: UInt32 = 1 << 31
    /// A side that wrote nothing for this long sends a ping.
    public static let pingEvery: TimeInterval = 5
    /// A connection silent for this long is dead.
    public static let timeout: TimeInterval = 15
    /// Texts are at most this many bytes of UTF-8.
    public static let maxText = 1 << 20

    /// What kind of member is at the other end: `member` is any device
    /// with the service or the firmware, `phone` a phone's app; its system
    /// is the hello's `os`.
    public enum Role: String, Codable, Sendable { case member, phone }

    /// The kind of an event: a secret is kept only briefly (section 5);
    /// media is images or files, of which the kit takes the text.
    public enum Kind: String, Codable, Sendable { case text, secret, media }

    /// How a text reached the member that made the event.
    public enum Via: String, Codable, Sendable {
        case copy
        /// Sent from a phone's app.
        case phone
        case universalClipboard = "universal-clipboard"

        public init(from decoder: Decoder) throws {
            let s = try decoder.singleValueContainer().decode(String.self)
            guard let via = Via(rawValue: s) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown via \(s)"))
            }
            self = via
        }
    }

    /// A hybrid logical clock timestamp: milliseconds since the Unix epoch
    /// and a counter, written as "<wall>.<logical>".
    public struct Timestamp: Comparable, Hashable, Sendable, Codable, CustomStringConvertible {
        public var wall: UInt64
        public var logical: UInt32
        /// The last millisecond of 9999.
        public static let maxWall: UInt64 = 253_402_300_799_999
        public static let zero = Timestamp(wall: 0, logical: 0)

        public init(wall: UInt64, logical: UInt32) { (self.wall, self.logical) = (wall, logical) }

        /// Parses the text form: two decimal numbers and a dot, no sign or
        /// spaces, the wall time at most maxWall.
        public init?(text: String) {
            let parts = text.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { (0x30...0x39).contains($0) } }),
                  let w = UInt64(parts[0]), let l = UInt32(parts[1]), w <= Timestamp.maxWall else { return nil }
            (wall, logical) = (w, l)
        }

        public var description: String { "\(wall).\(logical)" }
        public var isZero: Bool { self == .zero }

        public static func < (a: Timestamp, b: Timestamp) -> Bool {
            a.wall != b.wall ? a.wall < b.wall : a.logical < b.logical
        }

        public init(from decoder: Decoder) throws {
            let s = try decoder.singleValueContainer().decode(String.self)
            guard let t = Timestamp(text: s) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "bad timestamp \(s)"))
            }
            self = t
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.singleValueContainer()
            try c.encode(description)
        }
    }

    /// One copy as the engine holds it: its header, and its content once
    /// this member opened it. It travels sealed (Sealed).
    public struct Event: Codable, Equatable, Sendable {
        public var id: String
        public var origin: String
        public var via: Via
        public var time: Timestamp
        /// Milliseconds since the copy, as of the moment the frame is written.
        public var ageMS: Int64
        public var kind: Kind
        /// The text; "" only in the mark of a secret, and in images or files
        /// without one.
        public var text: String
        /// The content of a media event, which only it has.
        public var media: Media.Manifest?
        /// The copy as it travels, sealed end to end (docs/protocol.md,
        /// section 4); nil for an event of an engine without keys, as in
        /// tests of the engine alone.
        public var sealed: Sealed?
        /// Whether this member does not know the event's content: a mark,
        /// or a copy not sealed to this member. kind, via, text and media
        /// are then empty, and the event is current only for ordering.
        public var unread = false
        /// The copy's key, which opens its blob, when this member opened it.
        public var key: Data?

        enum CodingKeys: String, CodingKey { case id, origin, via, time, ageMS = "age_ms", kind, text, media, wraps }

        public init(id: String, origin: String, via: Via = .copy, time: Timestamp, ageMS: Int64 = 0, kind: Kind, text: String,
                    media: Media.Manifest? = nil) {
            (self.id, self.origin, self.via, self.time, self.ageMS, self.kind, self.text) = (id, origin, via, time, ageMS, kind, text)
            self.media = media
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            // On the wire a copy is sealed.
            if c.contains(.wraps) {
                self = Event(sealed: try Sealed(from: decoder))
                return
            }
            id = try c.decode(String.self, forKey: .id)
            origin = try c.decode(String.self, forKey: .origin)
            via = try c.decodeIfPresent(Via.self, forKey: .via) ?? .copy
            time = try c.decode(Timestamp.self, forKey: .time)
            ageMS = try c.decodeIfPresent(Int64.self, forKey: .ageMS) ?? 0
            kind = try c.decode(Kind.self, forKey: .kind)
            text = try c.decodeIfPresent(String.self, forKey: .text) ?? ""
            media = try c.decodeIfPresent(Media.Manifest.self, forKey: .media)
        }

        public func encode(to encoder: Encoder) throws {
            if var s = sealed {
                s.ageMS = ageMS
                try s.encode(to: encoder)
                return
            }
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(id, forKey: .id)
            try c.encode(origin, forKey: .origin)
            if via != .copy { try c.encode(via, forKey: .via) } // absent means copy
            try c.encode(time, forKey: .time)
            try c.encode(ageMS, forKey: .ageMS)
            try c.encode(kind, forKey: .kind)
            try c.encode(text, forKey: .text)
            try c.encodeIfPresent(media, forKey: .media)
        }

        /// Whether it is the mark of a secret: the event without its
        /// payload, or, unsealed, without its text.
        public var isMark: Bool { sealed.map(\.isMark) ?? (kind == .secret && text.isEmpty) }

        /// The mark of this event: a secret without its payload and text,
        /// as a hello carries it.
        public var mark: Event {
            var m = self
            if kind == .secret && !unread {
                (m.text, m.key) = ("", nil)
                m.sealed = sealed?.mark
            }
            return m
        }

        /// Whether f carries the payload whose hash this mark has.
        func samePayload(_ f: Event) -> Bool {
            guard let s = sealed, let t = f.sealed else { return true }
            return t.payload != nil && s.payloadHash == t.payloadHash
        }

        /// Checks an event received from another member, as Go's
        /// Event.Validate does.
        public var isValid: Bool {
            guard GroupCertificates.isDeviceID(id), GroupCertificates.isDeviceID(origin),
                  !time.isZero, time.wall <= Timestamp.maxWall, ageMS >= 0 else { return false }
            if let sealed, !sealed.isValid || sealed.id != id || sealed.origin != origin || sealed.time != time { return false }
            if unread { return sealed != nil }
            if (kind == .media) != (media != nil) { return false }
            if isMark { return true }
            if let media {
                return media.isValid && (text.isEmpty || text.utf8.count <= Media.maxAltText)
            }
            return !text.isEmpty && text.utf8.count <= Member.maxText
        }

        /// Whether it sorts after f: by time, then by ID, so every member
        /// orders any two events the same way.
        public func isLater(than f: Event) -> Bool {
            time != f.time ? time > f.time : id > f.id
        }
    }

    /// The first message of each side.
    public struct Hello: Equatable, Sendable {
        /// The sender's wall clock, milliseconds since the Unix epoch; for
        /// skew reports only.
        public var wallMS: Int64
        /// The sender's current event; a secret only as its mark. nil when
        /// there is none, or when it did not decode.
        public var current: Event?
        /// The digest of the sender's records (section 10).
        public var records: String?
        /// The sender's device name.
        public var name: String?
        /// The sender's operating system: "linux", "windows", "macos",
        /// "ios", "android", "aurora", "sailfish" or "none"; shown, never trusted.
        public var os: String?
        /// From a computer that is no admin yet: the SubjectPublicKeyInfo of
        /// its admin key, for the root to certify (section 10, "A computer
        /// as admin").
        public var adminKey: Data?
        /// The sender's WireGuard public key, 32 bytes, for the group's
        /// hub (section 11).
        public var tunnelKey: Data?
        /// With tunnelKey, the preshared key the sender chose for its
        /// tunnels, 32 bytes, so every hub of the group uses the same one
        /// (section 11, "Several hubs"); nil from an older member.
        public var tunnelPSK: Data?
        /// What the sender says about its device, for showing.
        public var device: DeviceInfo?
        /// The sender's sync mode: "own", "shared", "receive" or "send";
        /// nil from a member without one, which shares.
        public var mode: String?
        /// Where the sender says its keys live: Records.file,
        /// Records.hardware or Records.rootless; nil when it does not say.
        public var keyStore: String?
        /// The sender's quick actions that are on, for the buttons
        /// (section 15).
        public var actions: [String]
        /// Whether the sender serves the content of media events (section
        /// 4, "Content").
        public var media: Bool
        /// The group's first root, DER, which a computer sends on a
        /// records-only connection with a device no record names yet, as a
        /// new phone restoring the group with the recovery key (section 10,
        /// "The recovery key").
        public var groupCA: Data?
        /// The seq of the newest entries.json the sender holds and of the
        /// keys.json it came with (section 16, "Entry points"); nil for none.
        public var entriesSeq: UInt64?
        public var entriesKeysSeq: UInt64?
        /// Whether an admin muted the sender, whose copies then do not
        /// reach the group, and for how long still in milliseconds, 0 for
        /// until an admin unmutes it (section 4; design.md, "Muting a
        /// device").
        public var muted = false
        public var mutedForMS: Int64 = 0

        public init(wallMS: Int64, current: Event? = nil, records: String? = nil, name: String? = nil, os: String? = nil,
                    adminKey: Data? = nil, tunnelKey: Data? = nil, tunnelPSK: Data? = nil, device: DeviceInfo? = nil, mode: String? = nil,
                    keyStore: String? = nil, actions: [String] = [], media: Bool = false, groupCA: Data? = nil,
                    entriesSeq: UInt64? = nil, entriesKeysSeq: UInt64? = nil) {
            (self.wallMS, self.current, self.records, self.name, self.os, self.adminKey, self.tunnelKey) =
                (wallMS, current, records, name, os, adminKey, tunnelKey)
            (self.tunnelPSK, self.device, self.mode, self.keyStore, self.actions, self.media) = (tunnelPSK, device, mode, keyStore, actions, media)
            (self.groupCA, self.entriesSeq, self.entriesKeysSeq) = (groupCA, entriesSeq, entriesKeysSeq)
        }

        /// The hello with an admin's mute as a peer's hello says it: a time
        /// out of range counts as 30 days, as Go reads it.
        func with(muted: Bool, forMS: Int64) -> Hello {
            var h = self
            h.muted = muted
            h.mutedForMS = muted ? min(max(forMS, 0), Commands.maxMuteMS) : 0
            return h
        }
    }

    /// The sync modes (design.md, "Sync modes").
    public static let modes: Set<String> = ["own", "shared", "receive", "send"]

    /// Whether a device in sync mode mode takes the group's copies into its
    /// clipboard by itself; a device without a mode (nil) shares.
    public static func receives(_ mode: String?) -> Bool { mode == nil || mode == "shared" || mode == "receive" }

    /// Whether a device in sync mode mode sends its own copies to the group by itself.
    public static func sends(_ mode: String?) -> Bool { mode == nil || mode == "shared" || mode == "send" }

    /// The longest reason a result carries, in UTF-8 bytes (section 15).
    public static let maxReason = 256

    /// A result's reason made fit to show: a control character (escape
    /// included) becomes a space and it is cut to `maxReason` bytes at a
    /// character boundary. The member that answers is a peer, so the member
    /// that shows the reason cleans it.
    public static func cleanReason(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var bytes = 0
        for u in s.unicodeScalars {
            let c: Unicode.Scalar = u.properties.generalCategory == .control ? " " : u
            let size = String(c).utf8.count
            if bytes + size > maxReason { break }
            out.append(c)
            bytes += size
        }
        return String(out)
    }

    /// The answer to a command (section 15): its ID, "done", "refused" or
    /// "failed", and why for the last two.
    public struct CommandResult: Codable, Equatable, Sendable {
        public var id: String
        public var status: String
        public var reason: String?
        /// In the result of a hub command, the new hub's offer without a
        /// preshared key (section 11, "Moving the hub").
        public var tunnel: TunnelOffer?
        /// The device that answered, the command's receiver; a member that
        /// passes the result back leaves it as it is.
        public var by: String?

        public init(id: String, status: String, reason: String? = nil, tunnel: TunnelOffer? = nil, by: String? = nil) {
            (self.id, self.status, self.reason, self.tunnel, self.by) = (id, status, reason, tunnel, by)
        }

        public var done: Bool { status == "done" }
    }

    /// What a hello says about the sender's device (section 4, "Device"):
    /// its form, its system's version, its own version and its network
    /// card's MAC address. Shown, never trusted; any field may be absent.
    public struct DeviceInfo: Codable, Equatable, Sendable {
        /// The forms a device may name, for its icon.
        public static let forms = ["laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"]

        public var form: String?
        public var osVersion: String?
        public var version: String?
        public var mac: String?

        enum CodingKeys: String, CodingKey { case form, osVersion = "os_version", version, mac }

        public init(form: String? = nil, osVersion: String? = nil, version: String? = nil, mac: String? = nil) {
            (self.form, self.osVersion, self.version, self.mac) = (form, osVersion, version, mac)
        }

        /// The same without its invalid fields: an unknown form, a version
        /// longer than 32 bytes or with control characters, a MAC address
        /// other than six lowercase hex bytes with colons; nil when nothing
        /// is left.
        public var cleaned: DeviceInfo? {
            func short(_ s: String?) -> String? {
                guard let s, !s.isEmpty, s.utf8.count <= 32, !s.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
                return s
            }
            let hex = Set("0123456789abcdef")
            let parts = mac?.split(separator: ":", omittingEmptySubsequences: false) ?? []
            let macOK = parts.count == 6 && parts.allSatisfy { $0.count == 2 && $0.allSatisfy(hex.contains) }
            let d = DeviceInfo(form: form.flatMap { Self.forms.contains($0) ? $0 : nil }, osVersion: short(osVersion), version: short(version),
                               mac: macOK ? mac : nil)
            return d == DeviceInfo() ? nil : d
        }
    }

    /// The group's hub's answer to the tunnel key a hello carried (section
    /// 11): the hub's WireGuard public key, this member's own preshared key,
    /// the hub's addresses away from home, "ip:port" or "[ipv6]:port", the
    /// group's obfuscation settings, nil for plain WireGuard, and the way to
    /// the hub's forwarder over VLESS, nil without it.
    public struct TunnelOffer: Codable, Equatable, Sendable {
        public var hubKey: Data
        public var psk: Data
        public var endpoints: [String]
        public var obfuscation: Obfuscation?
        public var vless: VLESS?
        /// In an offer the hub passes on when it hands the hub over, the
        /// device that is the hub now (section 11, "Moving the hub"); nil
        /// when the sender is the hub.
        public var hub: String?
        /// Whether the sender is no hub any more and hands its clients over
        /// to hub: the client forgets the sender's own offer.
        public var moved: Bool
        /// The key the hub serves with in the next period of the group's
        /// server credentials, which the client tries after hubKey (section
        /// 11, "The hub's key"); nil for none.
        public var nextKey: Data?

        public init(hubKey: Data, psk: Data, endpoints: [String] = [], obfuscation: Obfuscation? = nil, vless: VLESS? = nil, hub: String? = nil,
                    moved: Bool = false, nextKey: Data? = nil) {
            (self.hubKey, self.psk, self.endpoints, self.obfuscation, self.vless, self.hub) = (hubKey, psk, endpoints, obfuscation, vless, hub)
            (self.moved, self.nextKey) = (moved, nextKey)
        }

        /// Whether it is an offer a tunnel can take, as Go checks one: keys
        /// of 32 bytes that are not all zeros, at most 8 endpoints, each
        /// with a port that is not 0.
        public var isValid: Bool {
            hubKey.count == 32 && psk.count == 32 && endpoints.count <= 8 && (nextKey?.count ?? 32) == 32
                && hubKey.contains { $0 != 0 } && psk.contains { $0 != 0 } && endpoints.allSatisfy(Self.hasPort)
        }

        /// Whether endpoint ends in a port from 1 to 65535, as in
        /// "192.0.2.1:8764" or "[2001:db8::1]:8764".
        static func hasPort(_ endpoint: String) -> Bool {
            guard let colon = endpoint.lastIndex(of: ":"), colon != endpoint.startIndex else { return false }
            let digits = endpoint[endpoint.index(after: colon)...]
            guard !digits.isEmpty, digits.utf8.allSatisfy({ (0x30...0x39).contains($0) }), let port = UInt16(digits) else { return false }
            return port != 0
        }

        /// The offer with the next key as the hub's key, or nil without one.
        public var withNextKey: TunnelOffer? {
            guard let nextKey else { return nil }
            var o = self
            (o.hubKey, o.nextKey) = (nextKey, nil)
            return o
        }

        /// The same offer with another preshared key and hub, and moved set.
        public func with(psk: Data, hub: String?, moved: Bool = false) -> TunnelOffer {
            var o = self
            (o.psk, o.hub, o.moved) = (psk, hub, moved)
            return o
        }

        enum CodingKeys: String, CodingKey { case hub_key, psk, endpoints, obfuscation, vless, hub, moved, next_key }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            hubKey = try c.decodeIfPresent(Data.self, forKey: .hub_key) ?? Data()
            psk = try c.decodeIfPresent(Data.self, forKey: .psk) ?? Data()
            endpoints = try c.decodeIfPresent([String].self, forKey: .endpoints) ?? []
            obfuscation = try c.decodeIfPresent(Obfuscation.self, forKey: .obfuscation)
            vless = try c.decodeIfPresent(VLESS.self, forKey: .vless)
            hub = try c.decodeIfPresent(String.self, forKey: .hub)
            moved = try c.decodeIfPresent(Bool.self, forKey: .moved) ?? false
            nextKey = try c.decodeIfPresent(Data.self, forKey: .next_key).flatMap { $0.isEmpty ? nil : $0 }
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(hubKey, forKey: .hub_key)
            try c.encode(psk, forKey: .psk)
            if !endpoints.isEmpty { try c.encode(endpoints, forKey: .endpoints) }
            try c.encodeIfPresent(obfuscation, forKey: .obfuscation)
            try c.encodeIfPresent(vless, forKey: .vless)
            try c.encodeIfPresent(hub, forKey: .hub)
            if moved { try c.encode(true, forKey: .moved) }
            try c.encodeIfPresent(nextKey, forKey: .next_key)
        }
    }

    /// What a hub tells the group's other hubs (section 11, "Several
    /// hubs"): whether it serves as the hub now, its offer without a
    /// preshared key, and its clients, itself among them, with their keys.
    public struct HubShare: Codable, Equatable, Sendable {
        public var serving: Bool
        public var offer: TunnelOffer?
        public var clients: [PhoneHub.Client]

        public init(serving: Bool = false, offer: TunnelOffer? = nil, clients: [PhoneHub.Client] = []) {
            (self.serving, self.offer, self.clients) = (serving, offer, clients)
        }

        enum CodingKeys: String, CodingKey { case serving, offer, clients }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            serving = try c.decodeIfPresent(Bool.self, forKey: .serving) ?? false
            offer = try c.decodeIfPresent(TunnelOffer.self, forKey: .offer)
            clients = try c.decodeIfPresent([PhoneHub.Client].self, forKey: .clients) ?? []
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            if serving { try c.encode(true, forKey: .serving) }
            try c.encodeIfPresent(offer, forKey: .offer)
            if !clients.isEmpty { try c.encode(clients, forKey: .clients) }
        }
    }

    /// The way to the hub's forwarder over VLESS (section 11, "VLESS"), over
    /// XHTTP behind the forwarder's web server (`transport` "xhttp"); with
    /// it, the only way to the hub. The kit only carries it: the tunnel
    /// (RustTunnel) checks and uses it, and refuses a transport it does not
    /// take, such as an older forwarder's REALITY.
    public struct VLESS: Codable, Equatable, Sendable {
        public var transport: String
        public var endpoint: String
        public var serverName: String
        public var path: String
        public var id: String

        public init(transport: String = "xhttp", endpoint: String, serverName: String, path: String, id: String) {
            (self.transport, self.endpoint, self.serverName, self.path, self.id) = (transport, endpoint, serverName, path, id)
        }

        enum CodingKeys: String, CodingKey {
            case transport, endpoint, path, id
            case serverName = "server_name"
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            transport = try c.decodeIfPresent(String.self, forKey: .transport) ?? ""
            endpoint = try c.decode(String.self, forKey: .endpoint)
            serverName = try c.decode(String.self, forKey: .serverName)
            path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
            id = try c.decode(String.self, forKey: .id)
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            if !transport.isEmpty { try c.encode(transport, forKey: .transport) }
            try c.encode(endpoint, forKey: .endpoint)
            try c.encode(serverName, forKey: .serverName)
            if !path.isEmpty { try c.encode(path, forKey: .path) }
            try c.encode(id, forKey: .id)
        }

        /// The settings as JSON, for the tunnel.
        public func jsonText() throws -> String {
            String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
        }
    }

    /// A group's AmneziaWG settings (section 11, "Obfuscation"), with
    /// AmneziaWG's own names. The kit only carries them: the tunnel in
    /// RustTunnel checks and uses them.
    public struct Obfuscation: Codable, Equatable, Sendable {
        public var jc, jmin, jmax: Int
        public var s1, s2, s3, s4: Int
        public var h1, h2, h3, h4: String
        public var headerProtectionKey: Data

        enum CodingKeys: String, CodingKey {
            case jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4
            case headerProtectionKey = "header_protection_key"
        }

        /// The settings as JSON, for the tunnel.
        public func jsonText() throws -> String {
            String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
        }
    }

    /// A signed record of the group (section 10), carried as it came.
    public struct Record: Codable, Equatable, Sendable {
        public var body: Data
        public var sig: Data
        public var chain: [Data]?

        public init(body: Data, sig: Data, chain: [Data]? = nil) { (self.body, self.sig, self.chain) = (body, sig, chain) }

        /// The records of one message at most, well below the frame limit:
        /// a set is sent in messages of about 1 MiB (section 10, "Exchange
        /// in the member protocol"), as Go's chunkRecords does.
        static let chunk = 1 << 20

        /// rs in the messages that carry them, in order, each of about
        /// chunk bytes at most unless one record alone is larger.
        public static func chunks(_ rs: [Record]) -> [[Record]] {
            var out: [[Record]] = []
            var cur: [Record] = []
            var size = 0
            for r in rs {
                // base64 and the JSON around it
                let n = (r.body.count + r.sig.count + (r.chain ?? []).reduce(0) { $0 + $1.count }) * 4 / 3 + 64
                if !cur.isEmpty && size + n > chunk {
                    out.append(cur)
                    (cur, size) = ([], 0)
                }
                cur.append(r)
                size += n
            }
            if !cur.isEmpty { out.append(cur) }
            return out
        }
    }

    /// An attestation of one of a device's keys (section 17, "Evidence"):
    /// format android with the Keystore's chain, leaf first, for the key
    /// member, made with the challenge of groupTag (nil outside a group) and
    /// salt.
    public struct Evidence: Codable, Equatable, Sendable {
        public static let android = "android-key"
        public static let member = "member"

        public var format: String
        public var key: String
        public var groupTag: String?
        public var salt: Data
        public var chain: [Data]

        public init(format: String, key: String, groupTag: String?, salt: Data, chain: [Data]) {
            (self.format, self.key, self.groupTag, self.salt, self.chain) = (format, key, groupTag, salt, chain)
        }

        enum CodingKeys: String, CodingKey {
            case format, key, salt, chain
            case groupTag = "group_tag"
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            format = try c.decodeIfPresent(String.self, forKey: .format) ?? ""
            key = try c.decodeIfPresent(String.self, forKey: .key) ?? ""
            groupTag = try c.decodeIfPresent(String.self, forKey: .groupTag).flatMap { $0.isEmpty ? nil : $0 }
            salt = try c.decodeIfPresent(Data.self, forKey: .salt) ?? Data()
            chain = try c.decodeIfPresent([Data].self, forKey: .chain) ?? []
        }
    }

    /// One message of the protocol.
    /// A range of a part of images or files, by its SHA-256 (section 4,
    /// "Content"); length 0 cancels the sender's gets of the part.
    public struct Get: Codable, Equatable, Sendable {
        public var sha256: Data
        public var offset: Int64
        public var length: Int64

        public init(sha256: Data, offset: Int64, length: Int64) { (self.sha256, self.offset, self.length) = (sha256, offset, length) }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            sha256 = try c.decodeIfPresent(Data.self, forKey: .sha256) ?? Data()
            offset = try c.decodeIfPresent(Int64.self, forKey: .offset) ?? 0
            length = try c.decodeIfPresent(Int64.self, forKey: .length) ?? 0
        }

        /// Whether a server takes it: a 32-byte hash and a range of at most
        /// getWindow.
        public var isValid: Bool { sha256.count == 32 && offset >= 0 && (0...Member.getWindow).contains(length) }
    }

    /// A piece of a part, in a binary frame.
    public struct Chunk: Equatable, Sendable {
        public var sha256: Data
        public var offset: Int64
        public var data: Data

        public init(sha256: Data, offset: Int64, data: Data) { (self.sha256, self.offset, self.data) = (sha256, offset, data) }
    }

    public enum Message: Equatable, Sendable {
        case hello(Role, Hello)
        /// An event; nil when it did not decode, for example from a newer
        /// version, which is dropped without ending the connection.
        case event(Event?)
        case ping
        case bye
        /// A renewed member certificate for the receiver, DER, and the
        /// admin CA that issued it when an admin phone did.
        case cert(Data, issuer: Data? = nil)
        case records([Record])
        /// The group's server credentials the sender keeps, or new ones it
        /// passes on (section 18).
        case credentials([ServerCredentials.Credential])
        /// The newest signed entry points the sender holds (section 16,
        /// "Entry points").
        case entries(Releases.EntriesSet)
        /// From the root: the receiver's admin CA, DER, for the admin key
        /// its hello offered.
        case admin(Data)
        /// From the group's hub: its offer for the tunnel key the
        /// receiver's hello carried; nil when absent or when it did not
        /// decode.
        case tunnel(TunnelOffer?)
        /// Between the group's hubs (section 11, "Several hubs"): whether
        /// the sender serves as the hub, its offer without a preshared key,
        /// and its clients with their keys, so any hub can take them.
        case hubs(HubShare)
        /// From an admin: a command signed for the receiver (section 15).
        case command(Record)
        /// The answer to a command.
        case result(CommandResult)
        /// An attestation of one of the sender's keys (section 17).
        case evidence(Evidence)
        /// Asks for a range of a part the receiver serves.
        case get(Get)
        /// Answers a get for a part the sender does not hold whole, and
        /// ends that fetch.
        case missing(Get)
        /// A piece of a part, in a binary frame.
        case chunk(Chunk)
        /// From a computer: the device IDs of the other members it is
        /// connected to now (section 4, "Reach"), its valid ones, at most
        /// maxReach.
        case reach([String])
        /// A type from a newer version, ignored.
        case unknown(String)
    }

    public enum WireError: Error, Equatable {
        case tooLarge, short, notAMessage, badHello(String)
    }

    /// Encodes a message as a frame: the length, then the JSON, or for a
    /// chunk its binary frame.
    public static func encode(_ m: Message) throws -> Data {
        if case let .chunk(c) = m { return try encode(chunk: c) }
        let enc = JSONEncoder()
        enc.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        let body = try enc.encode(WireOut(m))
        guard body.count <= maxFrame else { throw WireError.tooLarge }
        var n = UInt32(body.count).bigEndian
        return Data(bytes: &n, count: 4) + body
    }

    /// The length a frame header announces, or an error when too large.
    public static func length(header: Data) throws -> Int {
        guard header.count == 4 else { throw WireError.short }
        let n = header.reduce(0) { $0 << 8 | Int($1) }
        guard n <= maxFrame else { throw WireError.tooLarge }
        return n
    }

    /// The length a member frame's header announces and whether it is a
    /// binary chunk frame, or an error when too large for its kind.
    public static func header(_ header: Data) throws -> (length: Int, binary: Bool) {
        guard header.count == 4 else { throw WireError.short }
        let n = header.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        if n & binaryFrame != 0 {
            let l = Int(n & ~binaryFrame)
            guard l <= maxChunkFrame else { throw WireError.tooLarge }
            return (l, true)
        }
        guard n <= maxFrame else { throw WireError.tooLarge }
        return (Int(n), false)
    }

    /// The frame of a chunk: the binary length, the part's SHA-256, the
    /// offset and the data's length, the data, and zeros up to a multiple
    /// of chunkPad.
    public static func encode(chunk c: Chunk) throws -> Data {
        guard c.sha256.count == 32, c.data.count <= chunkSize, c.offset >= 0 else { throw WireError.notAMessage }
        let padded = (chunkHead + c.data.count + chunkPad - 1) / chunkPad * chunkPad
        var f = Data(capacity: 4 + padded)
        func put<T: FixedWidthInteger>(_ v: T) { withUnsafeBytes(of: v.bigEndian) { f.append(contentsOf: $0) } }
        put(UInt32(padded) | binaryFrame)
        f.append(c.sha256)
        put(UInt64(c.offset))
        put(UInt32(c.data.count))
        f.append(c.data)
        f.append(Data(count: 4 + padded - f.count))
        return f
    }

    /// Reads the body of a chunk frame.
    public static func decodeChunk(body: Data) throws -> Chunk {
        let b = [UInt8](body)
        guard b.count >= chunkHead else { throw WireError.short }
        let offset = b[32..<40].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let n = Int(b[40..<44].reduce(UInt32(0)) { $0 << 8 | UInt32($1) })
        guard offset <= UInt64(Int64.max), n <= chunkSize, chunkHead + n <= b.count else { throw WireError.notAMessage }
        return Chunk(sha256: Data(b[0..<32]), offset: Int64(offset), data: Data(b[chunkHead..<(chunkHead + n)]))
    }

    /// Decodes the body of a frame. A hello whose role is unknown or whose
    /// hello object does not decode is an error; an event that does not
    /// decode is .event(nil).
    public static func decode(body: Data) throws -> Message {
        guard Strict.integersOnly(body), let w = try? JSONDecoder().decode(WireIn.self, from: body) else { throw WireError.notAMessage }
        switch w.t {
        case "hello":
            guard let r = w.role, let role = Role(rawValue: r) else { throw WireError.badHello("unknown role") }
            guard let h = w.hello else { throw WireError.badHello("no hello object") }
            return .hello(role, Hello(wallMS: h.wall_ms ?? 0, current: h.current?.value, records: h.records, name: h.name,
                                      os: h.os, adminKey: h.admin_key, tunnelKey: h.tunnel_key, tunnelPSK: h.tunnel_psk, device: h.device?.value,
                                      mode: h.mode.flatMap { modes.contains($0) ? $0 : nil },
                                      keyStore: h.key_store.flatMap { $0 == Records.file || $0 == Records.hardware || $0 == Records.rootless ? $0 : nil },
                                      actions: Array((h.actions?.value ?? []).filter(Commands.validActionName).prefix(Commands.maxHelloActions)),
                                      media: (h.features?.value ?? []).prefix(Member.maxFeatures).contains(Member.featureMedia),
                                      groupCA: h.group_ca, entriesSeq: h.entries_seq, entriesKeysSeq: h.entries_keys_seq)
                .with(muted: h.muted ?? false, forMS: h.muted_for_ms ?? 0))
        case "event": return .event(w.event?.value)
        case "ping": return .ping
        case "bye": return .bye
        case "cert": return .cert(w.cert ?? Data(), issuer: w.issuer)
        case "records": return .records(w.records ?? [])
        case "credentials": return .credentials(w.credentials ?? [])
        case "entries": return w.entries?.value.map { .entries($0) } ?? .unknown(w.t)
        case "admin": return .admin(w.admin_ca ?? Data())
        case "tunnel": return .tunnel(w.tunnel?.value)
        case "hubs": return w.hubs?.value.map { .hubs($0) } ?? .unknown(w.t)
        case "command": return w.command?.value.map { .command($0) } ?? .unknown(w.t)
        case "result": return w.result?.value.map { .result($0) } ?? .unknown(w.t)
        case "evidence": return w.evidence?.value.map { .evidence($0) } ?? .unknown(w.t)
        case "get": return w.get?.value.map { .get($0) } ?? .unknown(w.t)
        case "missing": return w.get?.value.map { .missing($0) } ?? .unknown(w.t)
        case "reach": return .reach(Array((w.reach?.value ?? []).filter(GroupCertificates.isDeviceID).prefix(maxReach)))
        default: return .unknown(w.t)
        }
    }

    /// Keeps a value that may not decode, for parts of a message that a
    /// newer version may change.
    struct Lenient<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    struct WireHello: Decodable {
        var wall_ms: Int64?
        var current: Lenient<Event>?
        var records: String?
        var name: String?
        var os: String?
        var admin_key: Data?
        var tunnel_key: Data?
        var tunnel_psk: Data?
        var device: Lenient<DeviceInfo>?
        var mode: String?
        var key_store: String?
        var actions: Lenient<[String]>?
        var features: Lenient<[String]>?
        var group_ca: Data?
        var entries_seq: UInt64?
        var entries_keys_seq: UInt64?
        var muted: Bool?
        var muted_for_ms: Int64?
    }

    struct WireIn: Decodable {
        var t: String
        var role: String?
        var hello: WireHello?
        var event: Lenient<Event>?
        var cert: Data?
        var issuer: Data?
        var records: [Record]?
        var credentials: [ServerCredentials.Credential]?
        var admin_ca: Data?
        var tunnel: Lenient<TunnelOffer>?
        var hubs: Lenient<HubShare>?
        var command: Lenient<Record>?
        var result: Lenient<CommandResult>?
        var evidence: Lenient<Evidence>?
        var get: Lenient<Get>?
        var entries: Lenient<Releases.EntriesSet>?
        var reach: Lenient<[String]>?
    }

    struct WireOut: Encodable {
        let m: Message
        init(_ m: Message) { self.m = m }

        enum Keys: String, CodingKey { case t, role, hello, event, cert, issuer, records, credentials, admin_ca, tunnel, hubs, command, result, evidence, get, entries, reach }
        enum HelloKeys: String, CodingKey { case wall_ms, current, records, name, os, device, admin_key, tunnel_key, tunnel_psk, mode, key_store, actions, features, group_ca, entries_seq, entries_keys_seq, muted, muted_for_ms }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Keys.self)
            switch m {
            case let .hello(role, h):
                try c.encode("hello", forKey: .t)
                try c.encode(role, forKey: .role)
                var hc = c.nestedContainer(keyedBy: HelloKeys.self, forKey: .hello)
                try hc.encode(h.wallMS, forKey: .wall_ms)
                try hc.encodeIfPresent(h.current, forKey: .current)
                try hc.encodeIfPresent(h.records, forKey: .records)
                try hc.encodeIfPresent(h.name, forKey: .name)
                try hc.encodeIfPresent(h.os, forKey: .os)
                try hc.encodeIfPresent(h.device, forKey: .device)
                try hc.encodeIfPresent(h.adminKey, forKey: .admin_key)
                try hc.encodeIfPresent(h.tunnelKey, forKey: .tunnel_key)
                try hc.encodeIfPresent(h.tunnelPSK, forKey: .tunnel_psk)
                try hc.encodeIfPresent(h.mode, forKey: .mode)
                try hc.encodeIfPresent(h.keyStore, forKey: .key_store)
                if !h.actions.isEmpty { try hc.encode(h.actions, forKey: .actions) }
                if h.media { try hc.encode([Member.featureMedia], forKey: .features) }
                try hc.encodeIfPresent(h.groupCA, forKey: .group_ca)
                try hc.encodeIfPresent(h.entriesSeq, forKey: .entries_seq)
                try hc.encodeIfPresent(h.entriesKeysSeq, forKey: .entries_keys_seq)
                if h.muted {
                    try hc.encode(true, forKey: .muted)
                    try hc.encode(h.mutedForMS, forKey: .muted_for_ms)
                }
            case let .event(e):
                try c.encode("event", forKey: .t)
                try c.encodeIfPresent(e, forKey: .event)
            case .ping: try c.encode("ping", forKey: .t)
            case .bye: try c.encode("bye", forKey: .t)
            case let .cert(d, issuer):
                try c.encode("cert", forKey: .t)
                try c.encode(d, forKey: .cert)
                try c.encodeIfPresent(issuer, forKey: .issuer)
            case let .records(rs):
                try c.encode("records", forKey: .t)
                try c.encode(rs, forKey: .records)
            case let .credentials(cs):
                try c.encode("credentials", forKey: .t)
                try c.encode(cs, forKey: .credentials)
            case let .entries(e):
                try c.encode("entries", forKey: .t)
                try c.encode(e, forKey: .entries)
            case let .admin(ca):
                try c.encode("admin", forKey: .t)
                try c.encode(ca, forKey: .admin_ca)
            case let .tunnel(o):
                try c.encode("tunnel", forKey: .t)
                try c.encodeIfPresent(o, forKey: .tunnel)
            case let .hubs(h):
                try c.encode("hubs", forKey: .t)
                try c.encode(h, forKey: .hubs)
            case let .command(r):
                try c.encode("command", forKey: .t)
                try c.encode(r, forKey: .command)
            case let .result(r):
                try c.encode("result", forKey: .t)
                try c.encode(r, forKey: .result)
            case let .evidence(e):
                try c.encode("evidence", forKey: .t)
                try c.encode(e, forKey: .evidence)
            case let .get(g):
                try c.encode("get", forKey: .t)
                try c.encode(g, forKey: .get)
            case let .missing(g):
                try c.encode("missing", forKey: .t)
                try c.encode(g, forKey: .get)
            case let .reach(ids):
                try c.encode("reach", forKey: .t)
                if !ids.isEmpty { try c.encode(ids, forKey: .reach) }
            case .chunk:
                throw WireError.notAMessage // a binary frame
            case let .unknown(t): try c.encode(t, forKey: .t)
            }
        }
    }
}
