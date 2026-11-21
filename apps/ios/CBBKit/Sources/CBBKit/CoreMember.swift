// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Crypto
import Foundation

/// The phone as a member of its group, run by the Rust core inside the app
/// (ffi/, docs/core-api.md, "The member"): the Rust member's node on
/// threads of its own, with the phone's member key where the app keeps it,
/// which signs through a callback. It dials the members the app hands in
/// (Bonjour, the tunnel's and the relay's loopback ports), syncs with them,
/// and tells the app what happens through `events`; the app asks it
/// everything else through the calls below. The calls that wait for the
/// network (`fetch`, `command`, `wait`) are async and run off the caller's
/// thread.
public final class CoreMember: @unchecked Sendable {
    /// What the member starts from (cbb_member_start).
    public struct Config: Encodable, Sendable {
        /// Where the core keeps the records, the clock's mark, the entry
        /// points and the images and files: a folder of its own.
        public var dir: String
        public var name: String
        public var os: String
        public var osVersion: String
        public var version: String
        /// Where the member key lives: hardware (the keychain, the Secure
        /// Enclave) or file.
        public var keyStore: String
        public var device: String
        /// The member key's public point, uncompressed.
        public var publicKey: Data
        /// The secret for sealed messages (SealKey.secret).
        public var seal: Data
        public var cert: Data
        public var issuer: Data?
        public var groupCA: Data
        public var roots: [Data]
        /// Members to dial at host:port besides those the app finds.
        public var peers: [String]
        /// Whether the core finds the members by mDNS itself; the apps find
        /// them with their own browsers and hand them in.
        public var mdns: Bool
        /// The SubjectPublicKeyInfo of the phone's admin key, which the
        /// hellos offer while it is no admin, for the root to make it one.
        public var adminKey: Data?

        enum CodingKeys: String, CodingKey {
            case dir, name, os, osVersion = "os_version", version, keyStore = "key_store", device, publicKey = "public", seal, cert, issuer
            case groupCA = "group_ca", roots, peers, mdns, adminKey = "admin_key"
        }

        /// publicKeyDER is the member key's SubjectPublicKeyInfo, as
        /// CertificateSigner gives it.
        public init(dir: URL, name: String, os: String = "ios", osVersion: String = "", version: String = "", keyStore: String = "hardware",
                    device: String, publicKeyDER: Data, seal: Data, cert: Data, issuer: Data?, groupCA: Data, roots: [Data],
                    peers: [String] = [], mdns: Bool = false, adminKey: Data? = nil) throws {
            (self.dir, self.name, self.os, self.osVersion, self.version, self.keyStore) = (dir.path, name, os, osVersion, version, keyStore)
            (self.device, self.seal, self.cert, self.issuer, self.groupCA, self.roots) = (device, seal, cert, issuer, groupCA, roots)
            (self.peers, self.mdns, self.adminKey) = (peers, mdns, adminKey)
            publicKey = try P256.Signing.PublicKey(derRepresentation: publicKeyDER).x963Representation
        }
    }

    /// A copy as the core shows it: its header, its content when this phone
    /// opened it, and the key the button compares it by.
    public struct Copy: Decodable, Equatable, Sendable {
        public var id: String
        public var origin: String
        public var ageMS: Int64
        public var kind: Member.Kind
        public var via: Member.Via
        public var text: String
        public var media: Media.Manifest?
        public var unread: Bool
        public var key: String

        enum CodingKeys: String, CodingKey { case id, origin, ageMS = "age_ms", kind, via, text, media, unread, key }

        public init(id: String, origin: String, ageMS: Int64 = 0, kind: Member.Kind = .text, via: Member.Via = .copy, text: String,
                    media: Media.Manifest? = nil, unread: Bool = false, key: String = "") {
            (self.id, self.origin, self.ageMS, self.kind, self.via, self.text) = (id, origin, ageMS, kind, via, text)
            (self.media, self.unread, self.key) = (media, unread, key)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            origin = try c.decode(String.self, forKey: .origin)
            ageMS = try c.decodeIfPresent(Int64.self, forKey: .ageMS) ?? 0
            kind = try c.decodeIfPresent(Member.Kind.self, forKey: .kind) ?? .text
            via = (try? c.decodeIfPresent(Member.Via.self, forKey: .via)) ?? .copy
            text = try c.decodeIfPresent(String.self, forKey: .text) ?? ""
            media = try? c.decodeIfPresent(Media.Manifest.self, forKey: .media)
            unread = try c.decodeIfPresent(Bool.self, forKey: .unread) ?? false
            key = try c.decodeIfPresent(String.self, forKey: .key) ?? ""
        }

        /// The copy as the kit's event, for the code that reads one.
        public var event: Member.Event {
            var e = Member.Event(id: id, origin: origin, via: via, time: .zero, ageMS: ageMS, kind: kind, text: text, media: media)
            e.unread = unread
            return e
        }
    }

    /// A connected member as its hello and reach messages present it.
    public struct Peer: Decodable, Equatable, Sendable {
        public var device: String
        public var name: String
        public var role: String
        public var os: String
        public var keyStore: String
        public var mode: String
        public var muted: Bool
        public var mutedForMS: Int64
        public var actions: [String]
        public var info: Member.DeviceInfo?
        /// The admin key a member that is no admin yet offers, DER.
        public var adminKey: Data?
        /// The tunnel key and preshared key it offers the group's hubs.
        public var tunnelKey: Data?
        public var tunnelPSK: Data?
        /// The members it says it is connected to.
        public var reach: [String]
        /// Whether its connection carries records only.
        public var recordsOnly: Bool
        public var features: [String]
        /// Its certificate chain as the handshake checked it, leaf first.
        public var chain: [Data]

        enum CodingKeys: String, CodingKey {
            case device, name, role, os, keyStore = "key_store", mode, muted, mutedForMS = "muted_for_ms", actions, info
            case adminKey = "admin_key", tunnelKey = "tunnel_key", tunnelPSK = "tunnel_psk", reach, recordsOnly = "records_only", features, chain
        }

        public init(device: String, name: String = "", role: String = "member", os: String = "", keyStore: String = "", mode: String = "",
                    muted: Bool = false, mutedForMS: Int64 = 0, actions: [String] = [], info: Member.DeviceInfo? = nil, adminKey: Data? = nil,
                    tunnelKey: Data? = nil, tunnelPSK: Data? = nil, reach: [String] = [], recordsOnly: Bool = false, features: [String] = [],
                    chain: [Data] = []) {
            (self.device, self.name, self.role, self.os, self.keyStore, self.mode) = (device, name, role, os, keyStore, mode)
            (self.muted, self.mutedForMS, self.actions, self.info, self.adminKey) = (muted, mutedForMS, actions, info, adminKey)
            (self.tunnelKey, self.tunnelPSK, self.reach, self.recordsOnly, self.features, self.chain) =
                (tunnelKey, tunnelPSK, reach, recordsOnly, features, chain)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            func s(_ k: CodingKeys) -> String { ((try? c.decodeIfPresent(String.self, forKey: k)) ?? nil) ?? "" }
            device = try c.decode(String.self, forKey: .device)
            (name, role, os, keyStore, mode) = (s(.name), s(.role), s(.os), s(.keyStore), s(.mode))
            muted = (try? c.decodeIfPresent(Bool.self, forKey: .muted)) ?? false
            mutedForMS = ((try? c.decodeIfPresent(Int64.self, forKey: .mutedForMS)) ?? nil) ?? 0
            actions = ((try? c.decodeIfPresent([String].self, forKey: .actions)) ?? nil) ?? []
            info = (try? c.decodeIfPresent(Member.DeviceInfo.self, forKey: .info))?.flatMap { $0.cleaned }
            adminKey = (try? c.decodeIfPresent(Data.self, forKey: .adminKey)) ?? nil
            tunnelKey = (try? c.decodeIfPresent(Data.self, forKey: .tunnelKey)) ?? nil
            tunnelPSK = (try? c.decodeIfPresent(Data.self, forKey: .tunnelPSK)) ?? nil
            reach = ((try? c.decodeIfPresent([String].self, forKey: .reach)) ?? nil) ?? []
            recordsOnly = ((try? c.decodeIfPresent(Bool.self, forKey: .recordsOnly)) ?? nil) ?? false
            features = ((try? c.decodeIfPresent([String].self, forKey: .features)) ?? nil) ?? []
            chain = ((try? c.decodeIfPresent([Data].self, forKey: .chain)) ?? nil) ?? []
        }

        /// Whether it serves the images and files of its copies.
        public var servesMedia: Bool { features.contains("media") }

        /// Until when it is muted, in Unix milliseconds, 0 for until an
        /// admin lifts it; nil while it is not muted.
        public func mutedUntilMS(now: Date = Date()) -> Int64? {
            guard muted else { return nil }
            return mutedForMS == 0 ? 0 : Int64(now.timeIntervalSince1970 * 1000) + mutedForMS
        }
    }

    /// A message a peer sent that the core leaves to the app.
    public enum Message: Sendable {
        /// The admin CA the root issued for this phone's admin key.
        case admin(ca: Data)
        /// The group's server credentials it keeps.
        case credentials([ServerCredentials.Credential])
        /// An attestation of one of its keys.
        case evidence(Member.Evidence)
        /// A message this kit does not read, by its type.
        case other(String)
    }

    /// What the member tells the app, on the main actor's stream.
    public enum Event: Sendable {
        /// A text for the phone's clipboard, as the core's own clipboard
        /// rule decides it; ttlMS bounds how long a secret may stay.
        case write(text: String, kind: Member.Kind, ttlMS: UInt64?)
        /// A copy that became the group's current one from another member.
        case copy(Copy)
        case message(from: String, Message)
        case log(String)
        /// An admin renewed this phone's certificate, or a takeover made a
        /// new root: the app keeps them in its group file.
        case identity(cert: Data, issuer: Data?, roots: [Data])
        /// A peer whose hello the core took.
        case peer(Peer)
        /// A tunnel offer of the group's root or an admin.
        case tunnel(from: String, offer: Member.TunnelOffer)
        /// A command for this phone itself, which the app checks against
        /// the records, carries out and answers with `answer(_:result:)`
        /// within ten seconds, or the phone refuses it.
        case command(token: UInt64, from: String, command: Member.Record)
        /// A call to the relay's port from the loopback port port, whose
        /// certificate names device: the app names the caller the relay
        /// announced from there with `caller(_:device:)` within five
        /// seconds, or the call is closed.
        case caller(token: UInt64, port: UInt16, device: String)
        /// An admin muted this phone for forMS milliseconds (0 for until an
        /// admin lifts it), or ended its mute (muted false): the member
        /// carried the command out and keeps it.
        case mute(muted: Bool, forMS: Int64, by: String)
        /// An admin turned this phone's sync off (off true) or on again:
        /// the member of 0.6 carried the command out and keeps it.
        case sync(off: Bool, by: String)
        /// The group's state changed (a record came, a device joined or
        /// left).
        case state(GroupState)
        /// A new notice about the group.
        case notice(Notice)
        /// The group's root changed by its recovery key: every device shows
        /// it and cannot turn it off, with "This wasn't me". from and to are
        /// the old and new root's devices, seq the change's step.
        case rootChanged(from: String, to: String, seq: UInt64)
        /// The member needs a key of the phone's (kind spare_admin): the app
        /// makes it and answers with `keyMade(_:public:)` and the token.
        case needKey(token: UInt64, kind: String)
        /// The member no longer needs the key public (a point): the app may
        /// delete it.
        case keyDone(public: Data)
        /// Something in the member broke (docs/core-api.md, "Panics"):
        /// details say what and where. The app logs it, shows it and
        /// starts the member again.
        case panic(details: String)
    }

    /// A part of images or files the app hands in: clipboard data with its
    /// bytes, or a file or folder with the file on the phone.
    public struct Part: Encodable, Sendable {
        public var type: String?
        public var path: String?
        public var dir: Bool
        public var data: Data?
        public var file: String?

        public static func data(_ data: Data, type: String) -> Part { Part(type: type, path: nil, dir: false, data: data, file: nil) }
        public static func file(_ url: URL, path: String) -> Part { Part(type: nil, path: path, dir: false, data: nil, file: url.path) }
        public static func folder(path: String) -> Part { Part(type: nil, path: path, dir: true, data: nil, file: nil) }
        /// A file's bytes, at path in the copy.
        public static func bytes(_ data: Data, path: String) -> Part { Part(type: nil, path: path, dir: false, data: data, file: nil) }
    }

    /// A part of a copy the core fetched and opened, where it is.
    public struct Fetched: Decodable, Equatable, Sendable {
        public var type: String?
        public var path: String?
        public var dir: Bool
        public var size: Int64
        public var file: String

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            type = try c.decodeIfPresent(String.self, forKey: .type).flatMap { $0.isEmpty ? nil : $0 }
            path = try c.decodeIfPresent(String.self, forKey: .path).flatMap { $0.isEmpty ? nil : $0 }
            dir = try c.decodeIfPresent(Bool.self, forKey: .dir) ?? false
            size = try c.decodeIfPresent(Int64.self, forKey: .size) ?? 0
            file = try c.decode(String.self, forKey: .file)
        }

        enum CodingKeys: String, CodingKey { case type, path, dir, size, file }
    }

    /// The member was stopped.
    public struct Stopped: Error, CustomStringConvertible {
        public var description: String { "the member stopped" }
    }

    /// The refusals the app tells apart, read from the member's answer;
    /// every other one comes as a Core.Refusal.
    public enum Failure: Error, Equatable {
        /// The receiver of a command is not connected, nor a hub that
        /// passes it on.
        case notConnected
        /// The receiver did not answer in time.
        case timedOut
        /// An admin muted this phone: its copies do not reach the group.
        case muted
        /// The copy is no longer the group's current one.
        case gone

        static func of(_ r: Core.Refusal) -> Error {
            let m = r.message
            if m.contains("is not connected, nor is a hub") { return Failure.notConnected }
            if m.contains("did not answer in time") { return Failure.timedOut }
            if m.contains("this device is muted") { return Failure.muted }
            if m.contains("no longer the group's") { return Failure.gone }
            return r
        }
    }

    /// The callbacks' context, which the core keeps for the rest of the
    /// process: the signer and where the events go.
    private final class Context: @unchecked Sendable {
        let sign: @Sendable (Data) throws -> Data
        let lock = NSLock()
        var continuation: AsyncStream<Event>.Continuation?

        init(sign: @escaping @Sendable (Data) throws -> Data) { self.sign = sign }

        func send(_ e: Event) { _ = lock.withLock { continuation }?.yield(e) }

        func finish() {
            let c: AsyncStream<Event>.Continuation? = lock.withLock {
                defer { continuation = nil }
                return continuation
            }
            c?.finish()
        }
    }

    /// The member's handle, which a pairing window or an invitation
    /// (CorePairing.Window, CorePairing.Inviting) runs on.
    let handle: OpaquePointer
    private let context: Context
    private let lock = NSLock()
    private var stopped = false
    /// Every event, in the order the core sent them.
    public let events: AsyncStream<Event>

    /// Starts the member; sign signs a SHA-256 digest with the member key,
    /// ECDSA P-256, DER (SecKeySigner.signature(digest:)). A start the
    /// core refuses throws its Refusal.
    public init(_ config: Config, sign: @escaping @Sendable (Data) throws -> Data) throws {
        let got = Int(cbb_abi())
        guard got == Core.abi else { throw Core.Mismatch(reason: "the linked core speaks ABI \(got), not \(Core.abi)") }
        let ctx = Context(sign: sign)
        let (stream, continuation) = AsyncStream<Event>.makeStream(bufferingPolicy: .unbounded)
        ctx.continuation = continuation
        let request = try JSONEncoder().encode(config)
        var answer: UnsafeMutablePointer<UInt8>?
        var count = 0
        // The core keeps the context for the rest of the process, as
        // cbb_core.h asks: it is never released.
        let raw = Unmanaged.passRetained(ctx).toOpaque()
        let m: OpaquePointer? = request.withUnsafeBytes { r in
            cbb_member_start(r.bindMemory(to: UInt8.self).baseAddress, r.count, coreMemberSign, coreMemberEvent, raw, &answer, &count)
        }
        let reply = answer.map { Data(bytes: $0, count: count) } ?? Data()
        if let answer { cbb_free(answer, count) }
        guard let m else {
            ctx.finish()
            if let e = try? JSONDecoder().decode(Reply<Empty>.self, from: reply).error { throw e.refusal }
            throw Core.Mismatch(reason: "the member did not start")
        }
        (handle, context, events) = (m, ctx, stream)
    }

    deinit { stop() }

    /// Stops the member and closes its connections; the events end. A call
    /// after it throws Stopped.
    public func stop() {
        let first: Bool = lock.withLock {
            defer { stopped = true }
            return !stopped
        }
        guard first else { return }
        cbb_member_stop(handle)
        context.finish()
    }

    // MARK: Calls

    private struct Request<A: Encodable>: Encodable {
        var op: String
        var args: A?
    }

    private struct Reply<R: Decodable>: Decodable {
        var ok: R?
        var error: Refused?
    }

    /// The member's error answer: a sentence for the user and the causes
    /// under it, as a Refusal of the core.
    private struct Refused: Decodable {
        var message: String
        var details: String?
        var refusal: Core.Refusal { Core.Refusal(code: 0, name: "member", message: message, details: details) }
    }

    private struct Empty: Codable {}

    /// Asks the member op with args and decodes its answer's ok.
    func run<A: Encodable, R: Decodable>(_ op: String, _ args: A?, as _: R.Type = R.self) throws -> R {
        guard !lock.withLock({ stopped }) else { throw Stopped() }
        let request = try JSONEncoder().encode(Request(op: op, args: args))
        var count = 0
        let answer: UnsafeMutablePointer<UInt8>? = request.withUnsafeBytes { r in
            cbb_member_call(handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, &count)
        }
        guard let answer else { throw Core.Mismatch(reason: "the member gave no answer to \(op)") }
        defer { cbb_free(answer, count) }
        let reply: Reply<R>
        do {
            reply = try JSONDecoder().decode(Reply<R>.self, from: Data(bytes: answer, count: count))
        } catch {
            throw Core.Mismatch(reason: "the member's answer to \(op) does not read: \(error)")
        }
        if let e = reply.error { throw Failure.of(e.refusal) }
        guard let ok = reply.ok else { throw Core.Mismatch(reason: "the member's answer to \(op) has neither ok nor error") }
        return ok
    }

    private func run<A: Encodable>(_ op: String, _ args: A?) throws {
        _ = try run(op, args, as: Empty.self)
    }

    private func run(_ op: String) throws {
        _ = try run(op, Optional<Empty>.none, as: Empty.self)
    }

    /// run off the caller's thread, for the calls that wait for the network.
    private func detached<A: Encodable & Sendable, R: Decodable & Sendable>(_ op: String, _ args: A?, as _: R.Type) async throws -> R {
        try await Task.detached(priority: .userInitiated) { try self.run(op, args, as: R.self) }.value
    }

    private struct CopyAnswer: Decodable { var copy: Copy? }

    /// Sends a text the user handed to the app; board says it came from the
    /// phone's clipboard, which the button then compares with it.
    public func copy(_ text: String, secret: Bool = false, board: Bool = true) throws {
        struct A: Encodable { var text: String, kind: String, board: Bool }
        try run("copy", A(text: text, kind: secret ? "secret" : "text", board: board))
    }

    /// Sends images or files: clipboard data (board true when it came from
    /// the clipboard) or files and folders, with a plain-text alternative.
    @discardableResult
    public func copyMedia(_ parts: [Part], text: String = "", board: Bool = false) throws -> Copy {
        struct A: Encodable { var text: String, parts: [Part], board: Bool }
        guard let c = try run("copy_media", A(text: text, parts: parts, board: board), as: CopyAnswer.self).copy else {
            throw Core.Mismatch(reason: "copy_media gave no copy")
        }
        return c
    }

    /// The group's current copy, nil for none.
    public func current() throws -> Copy? { try run("current", Optional<Empty>.none, as: CopyAnswer.self).copy }

    /// The copy from another device that waits for this phone (the button's
    /// first case), nil for none.
    public func waiting() throws -> Copy? { try run("waiting", Optional<Empty>.none, as: CopyAnswer.self).copy }

    /// The app took the copy id into the clipboard, or saved its files.
    public func took(_ id: String) throws {
        struct A: Encodable { var id: String }
        try run("took", A(id: id))
    }

    /// Whether the button sends what the clipboard holds, by its key (the
    /// button's second case).
    public func sends(board: String) throws -> Bool {
        struct A: Encodable { var board: String }
        struct R: Decodable { var sends: Bool }
        return try run("sends", A(board: board), as: R.self).sends
    }

    /// Fetches the images or files of the group's copy id, unless its sealed
    /// blob is larger than max bytes, and opens them into out, a new
    /// folder; each part with where it is.
    public func fetch(_ id: String, max: Int64, into out: URL) async throws -> [Fetched] {
        struct A: Encodable, Sendable { var id: String, max: Int64, out: String }
        struct R: Decodable, Sendable { var parts: [Fetched] }
        return try await detached("fetch", A(id: id, max: max, out: out.path), as: R.self).parts
    }

    /// How far the peers read the sealed blob of the group's copy id that
    /// this phone made, and its size; zeros for a copy that is no longer
    /// the group's or holds no bytes.
    public func served(_ id: String) throws -> (served: Int64, size: Int64) {
        struct A: Encodable { var id: String }
        struct R: Decodable { var served: Int64, size: Int64 }
        let r = try run("served", A(id: id), as: R.self)
        return (r.served, r.size)
    }

    /// Dials the member the app found as key at addrs (host:port); device
    /// is its device ID when known.
    public func found(_ key: String, addrs: [String], device: String? = nil) throws {
        struct A: Encodable { var key: String, addrs: [String], device: String? }
        try run("found", A(key: key, addrs: addrs, device: device))
    }

    /// Stops dialing the member the app lost.
    public func lost(_ key: String) throws {
        struct A: Encodable { var key: String }
        try run("lost", A(key: key))
    }

    /// What a member port is for.
    public enum Listen: String, Encodable, Sendable {
        /// The home network, while the phone is the hub: every address;
        /// the app publishes the port with r=phone.
        case home
        /// The hub's tunnel, on the loopback address.
        case tunnel
        /// A blind relay's calls, on the loopback address: each is served
        /// only when the app names its caller (the caller event) and its
        /// certificate names the same device.
        case relay
    }

    /// Opens a member port for what on port (0 for any); the port. A port
    /// already open for what stays.
    public func listen(_ what: Listen = .home, port: UInt16 = 0) throws -> UInt16 {
        struct A: Encodable { var port: UInt16, kind: Listen }
        struct R: Decodable { var port: UInt16 }
        return try run("listen", A(port: port, kind: what), as: R.self).port
    }

    /// A hub's registration with its forwarder, as `away_status` gives it.
    public struct ForwarderState: Decodable, Equatable, Sendable {
        public var endpoint = "", registered = false, seen = "", entriesStale = false, error = "", detail = ""

        enum CodingKeys: String, CodingKey { case endpoint, registered, seen, entriesStale = "entries_stale", error, detail }

        public init(endpoint: String = "", registered: Bool = false, seen: String = "", entriesStale: Bool = false, error: String = "", detail: String = "") {
            (self.endpoint, self.registered, self.seen, self.entriesStale, self.error, self.detail) = (endpoint, registered, seen, entriesStale, error, detail)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            endpoint = try c.decodeIfPresent(String.self, forKey: .endpoint) ?? ""
            registered = try c.decodeIfPresent(Bool.self, forKey: .registered) ?? false
            seen = try c.decodeIfPresent(String.self, forKey: .seen) ?? ""
            entriesStale = try c.decodeIfPresent(Bool.self, forKey: .entriesStale) ?? false
            error = try c.decodeIfPresent(String.self, forKey: .error) ?? ""
            detail = try c.decodeIfPresent(String.self, forKey: .detail) ?? ""
        }
    }

    /// This phone's link to the group's relay, as `away_status` gives it.
    public struct RelayState: Decodable, Equatable, Sendable {
        public var endpoint = "", connected = false, online: [String] = [], error = "", detail = ""

        public init(endpoint: String = "", connected: Bool = false, online: [String] = [], error: String = "", detail: String = "") {
            (self.endpoint, self.connected, self.online, self.error, self.detail) = (endpoint, connected, online, error, detail)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            endpoint = try c.decodeIfPresent(String.self, forKey: .endpoint) ?? ""
            connected = try c.decodeIfPresent(Bool.self, forKey: .connected) ?? false
            online = try c.decodeIfPresent([String].self, forKey: .online) ?? []
            error = try c.decodeIfPresent(String.self, forKey: .error) ?? ""
            detail = try c.decodeIfPresent(String.self, forKey: .detail) ?? ""
        }

        enum CodingKeys: String, CodingKey { case endpoint, connected, online, error, detail }
    }

    /// Sync away from home on a group of 0.6, as the member runs it
    /// (`away_status`, docs/core-api.md): a hub (standing by while a hub
    /// above it serves) with its port, clients, endpoints and forwarder;
    /// else the hub it reaches and whether through the tunnel now; the
    /// relay link; the last error with its detail.
    public struct AwayState: Decodable, Equatable, Sendable {
        public var hub = false, standby = false, port = 0, clients = 0, obfuscated = false, vless = false
        public var endpoints: [String] = [], hubDevice = "", through = false, keysInFile = false
        public var forwarder: ForwarderState?, relay: RelayState?
        public var error = "", detail = ""

        /// Sync away from home is on: the member keeps its tunnel keys; a
        /// failure while it is off shows only error.
        public var isOn: Bool { keysInFile }

        enum CodingKeys: String, CodingKey {
            case hub, standby, port, clients, obfuscated, vless, endpoints, hubDevice = "hub_device", through, keysInFile = "keys_in_file"
            case forwarder, relay, error, detail
        }

        public init(hub: Bool = false, hubDevice: String = "", through: Bool = false, keysInFile: Bool = true, clients: Int = 0,
                    forwarder: ForwarderState? = nil, relay: RelayState? = nil, error: String = "", detail: String = "") {
            (self.hub, self.hubDevice, self.through, self.keysInFile, self.clients) = (hub, hubDevice, through, keysInFile, clients)
            (self.forwarder, self.relay, self.error, self.detail) = (forwarder, relay, error, detail)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            hub = try c.decodeIfPresent(Bool.self, forKey: .hub) ?? false
            standby = try c.decodeIfPresent(Bool.self, forKey: .standby) ?? false
            port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 0
            clients = try c.decodeIfPresent(Int.self, forKey: .clients) ?? 0
            obfuscated = try c.decodeIfPresent(Bool.self, forKey: .obfuscated) ?? false
            vless = try c.decodeIfPresent(Bool.self, forKey: .vless) ?? false
            endpoints = try c.decodeIfPresent([String].self, forKey: .endpoints) ?? []
            hubDevice = try c.decodeIfPresent(String.self, forKey: .hubDevice) ?? ""
            through = try c.decodeIfPresent(Bool.self, forKey: .through) ?? false
            keysInFile = try c.decodeIfPresent(Bool.self, forKey: .keysInFile) ?? false
            forwarder = try c.decodeIfPresent(ForwarderState.self, forKey: .forwarder)
            relay = try c.decodeIfPresent(RelayState.self, forKey: .relay)
            error = try c.decodeIfPresent(String.self, forKey: .error) ?? ""
            detail = try c.decodeIfPresent(String.self, forKey: .detail) ?? ""
        }
    }

    private struct AwayAnswer: Decodable { var away: AwayState? }

    /// The forwarder the group's root set for this phone as a hub: its address and its key's pin.
    public struct RootForwarder: Codable, Equatable, Sendable {
        public var endpoint: String
        public var key: String

        public init(endpoint: String, key: String) { (self.endpoint, self.key) = (endpoint, key) }
    }

    /// Where the group's server credentials stand on the root phone of a
    /// group of 0.6: due when they need its root key (`renewPeriod`),
    /// overdue when they expired, so that the group's relay and its hubs'
    /// forwarders take nobody; both false elsewhere.
    public struct Periods: Decodable, Equatable, Sendable {
        public var due = false
        public var overdue = false

        public init(due: Bool = false, overdue: Bool = false) { (self.due, self.overdue) = (due, overdue) }

        enum CodingKeys: String, CodingKey { case due = "period_due", overdue = "period_overdue" }

        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            due = try c.decodeIfPresent(Bool.self, forKey: .due) ?? false
            overdue = try c.decodeIfPresent(Bool.self, forKey: .overdue) ?? false
        }
    }

    /// On the root phone of a group of 0.6: where the group's server credentials stand.
    public func periods() throws -> Periods {
        try run("away_status", Optional<Empty>.none, as: Periods.self)
    }

    /// On the root phone of a group of 0.6: renews the group's server
    /// credentials with the root key, signed through sign; where they stand after.
    @discardableResult
    public func renewPeriod(public: Data, sign: @escaping (Data) throws -> Data) throws -> Periods {
        struct A: Encodable { var action = "period", `public`: Data }
        return try manage(A(public: try Self.point(`public`)), sign: sign, as: Periods.self)
    }

    /// On a group of 0.6: the group's face toward the push service that the
    /// newest keys.json the member holds names (16 bytes), which every
    /// registration names; nil until one does.
    public func pushFace() throws -> Data? {
        struct R: Decodable { var face: Data? }
        return try run("push_face", Optional<Empty>.none, as: R.self).face.flatMap { $0.count == 16 ? $0 : nil }
    }

    /// On a group of 0.6: this phone's registration for push, message
    /// `push` as `PushVault` made it, which the member sends to every
    /// member connected now and to each one that connects later; nil stops it.
    public func setPush(_ frame: Data?) throws {
        struct A: Encodable { var frame: Data? }
        try run("push", A(frame: frame))
    }

    /// A `push-renew` a member sent: the group with this slot registers
    /// again, from the phone's clock when `ahead`.
    public struct Renewal: Decodable, Equatable, Sendable {
        public var slot: Data
        public var ahead: Bool
    }

    /// On a group of 0.6: the `push-renew` messages members sent since the
    /// last call, one per slot.
    public func pushRenewals() throws -> [Renewal] {
        struct R: Decodable { var renewals: [Renewal] }
        return try run("push_renewals", Optional<Empty>.none, as: R.self).renewals
    }

    /// On a group of 0.6: the forwarder the group's root set for this phone
    /// as a hub, which it serves through; nil while the root set none.
    public func rootForwarder() throws -> RootForwarder? {
        struct R: Decodable {
            var rootForwarder: RootForwarder?
            enum CodingKeys: String, CodingKey { case rootForwarder = "root_forwarder" }
        }
        return try run("away_status", Optional<Empty>.none, as: R.self).rootForwarder
    }

    /// On a group of 0.6: sync away from home as the member runs it, nil while it is off.
    public func awayStatus() throws -> AwayState? {
        try run("away_status", Optional<Empty>.none, as: AwayAnswer.self).away
    }

    /// On a group of 0.6: turns sync away from home on, with new tunnel keys, or off.
    @discardableResult
    public func setAway(_ on: Bool) throws -> AwayState? {
        struct A: Encodable { var on: Bool }
        return try run("away", A(on: on), as: AwayAnswer.self).away
    }

    /// On a group of 0.6, serves as a hub of the group (the records must
    /// make this phone one: an admin key), as the computers' hub: reached
    /// away from home through the forwarder at forwarder (`host:port`, its
    /// key's pin key, or `default` for the project's), or at addrs
    /// ("ip:port") on the UDP port (0 for any free one), hidden as
    /// obfuscateOff and vlessOff say. Its clients and the guests of
    /// invitations come in through its tunnel.
    @discardableResult
    public func serveAsHub(port: UInt16 = 0, addrs: [String] = [], forwarder: String = "", key: String = "",
                           obfuscateOff: Bool = false, vlessOff: Bool = false) throws -> AwayState? {
        struct A: Encodable {
            var port: UInt16, addrs: [String], forwarder: String, key: String
            var obfuscateOff: Bool, vlessOff: Bool
            enum CodingKeys: String, CodingKey { case port, addrs, forwarder, key, obfuscateOff = "obfuscate_off", vlessOff = "vless_off" }
        }
        return try run("hub", A(port: port, addrs: addrs, forwarder: forwarder, key: key, obfuscateOff: obfuscateOff, vlessOff: vlessOff),
                       as: AwayAnswer.self).away
    }

    /// On a group of 0.6: stops serving as a hub; its clients go to the
    /// next hub in the group's order.
    @discardableResult
    public func stopHub() throws -> AwayState? {
        try run("hub_off", Optional<Empty>.none, as: AwayAnswer.self).away
    }

    /// Closes the member port for what, or every one with nil.
    public func unlisten(_ what: Listen? = nil) throws {
        struct A: Encodable { var kind: Listen? }
        try run("unlisten", A(kind: what))
    }

    /// Answers a caller event: the device the relay announced from the
    /// call's loopback port, nil for a call it did not announce.
    public func caller(_ token: UInt64, device: String?) throws {
        struct A: Encodable { var token: UInt64, device: String? }
        try run("caller", A(token: token, device: device))
    }

    /// Closes every connection and makes none until resume: the app went to
    /// the background.
    public func pause() throws { try run("pause") }

    public func resume() throws { try run("resume") }

    /// Waits up to timeout for a member to connect.
    public func wait(timeout: Duration) async throws -> Bool {
        struct A: Encodable, Sendable { var timeout_ms: Int64 }
        struct R: Decodable, Sendable { var connected: Bool }
        let ms = timeout.components.seconds * 1000 + timeout.components.attoseconds / 1_000_000_000_000_000
        return try await detached("wait", A(timeout_ms: ms), as: R.self).connected
    }

    /// Turns the phone's sync on, or off for forMS milliseconds, 0 for
    /// until it is turned on (design.md, "Sync on and off"); the members see
    /// it at the next connection. A time with sync on is refused.
    public func setSync(on: Bool, forMS: Int64 = 0) throws {
        struct A: Encodable { var on: Bool; var for_ms: Int64 }
        try run("sync", A(on: on, for_ms: forMS))
    }

    /// Mutes the phone until untilMS (0: until an admin lifts it), or nil
    /// to unmute.
    public func setMute(untilMS: Int64?) throws {
        struct A: Encodable {
            var until_ms: Int64?
            func encode(to encoder: Encoder) throws {
                var c = encoder.container(keyedBy: CodingKeys.self)
                try c.encode(until_ms, forKey: .until_ms)
            }
            enum CodingKeys: CodingKey { case until_ms }
        }
        try run("set_mute", A(until_ms: untilMS))
    }

    /// Why the phone does not sync, the reason that stops the most first
    /// (docs/apps.md, "Why it does not sync"); empty when everything syncs.
    /// away is where the app's own tunnel stands, nil while it is off.
    public func why(away: WhyAway? = nil) throws -> [WhyReason] {
        struct A: Encodable { var away: WhyAway? }
        struct R: Decodable { var why: [WhyReason] }
        return try run("why", A(away: away), as: R.self).why
    }

    /// The members connected now; all adds those that carry records only.
    public func peers(all: Bool = false) throws -> [Peer] {
        struct A: Encodable { var all: Bool }
        struct R: Decodable { var peers: [Peer] }
        return try run("peers", A(all: all), as: R.self).peers
    }

    /// A device as a tile of the member's view names it.
    public struct TileDevice: Decodable, Sendable, Equatable {
        public var id: String
        public init(id: String) { self.id = id }
    }

    /// The device tiles in the user's order, with the user's change op
    /// applied and kept first (docs/apps.md, "What the member shows"); a
    /// change that does not fit throws and changes nothing. Its warnings
    /// are `why(away:)`'s reasons, with away the app's own tunnel.
    public func view(_ op: Arrangement.Op? = nil, away: WhyAway? = nil) throws -> Arrangement.View<TileDevice> {
        struct A: Encodable { var arrange: Arrangement.Op?; var away: WhyAway? }
        struct R: Decodable { var view: Arrangement.View<TileDevice> }
        return try run(op == nil ? "view" : "arrange", A(arrange: op, away: away), as: R.self).view
    }

    /// The group's records the core holds.
    public func records() throws -> [Member.Record] {
        struct R: Decodable { var records: [Member.Record] }
        return try run("records", Optional<Empty>.none, as: R.self).records
    }

    /// Takes records the app's root or admin key signed, keeps them and
    /// sends them to every peer.
    public func addRecords(_ records: [Member.Record]) throws {
        guard !records.isEmpty else { return }
        struct A: Encodable { var records: [Member.Record] }
        try run("add_records", A(records: records))
    }

    /// Sends a command the app's admin key signed and waits for its result:
    /// to its receiver, or to the group's hubs connected, which pass it on.
    public func command(_ command: Member.Record, timeout: Duration = .seconds(10)) async throws -> Member.CommandResult {
        struct A: Encodable, Sendable { var command: Member.Record, timeout_ms: Int64 }
        struct R: Decodable, Sendable { var result: Member.CommandResult }
        let ms = timeout.components.seconds * 1000
        return try await detached("command", A(command: command, timeout_ms: ms), as: R.self).result
    }

    private struct Sent: Decodable { var sent: Bool }
    private struct To: Decodable { var to: [String] }

    /// Sends a renewed member certificate to the member to.
    @discardableResult
    public func sendCert(to: String, cert: Data, issuer: Data?) throws -> Bool {
        struct A: Encodable { var to: String, cert: Data, issuer: Data? }
        return try run("send_cert", A(to: to, cert: cert, issuer: issuer), as: Sent.self).sent
    }

    /// Sends a member the admin CA for the admin key its hello offers.
    @discardableResult
    public func sendAdminCA(to: String, ca: Data) throws -> Bool {
        struct A: Encodable { var to: String, ca: Data }
        return try run("send_admin_ca", A(to: to, ca: ca), as: Sent.self).sent
    }

    /// Sends the group's server credentials to the member to only (a peer
    /// that just connected), or to every member but except (the one that
    /// sent them); those it went to.
    @discardableResult
    public func sendCredentials(_ credentials: [ServerCredentials.Credential], to: String? = nil, except: String? = nil) throws -> [String] {
        guard !credentials.isEmpty else { return [] }
        struct A: Encodable { var credentials: [ServerCredentials.Credential], to: String?, except: String? }
        return try run("send_credentials", A(credentials: credentials, to: to, except: except), as: To.self).to
    }

    /// Answers a command event: the result its sender gets.
    public func answer(_ token: UInt64, result: Member.CommandResult) throws {
        struct A: Encodable { var token: UInt64, status: String, reason: String }
        try run("answer", A(token: token, status: result.status, reason: result.reason ?? ""))
    }

    /// Sets the attestations of the phone's keys every peer gets after its
    /// hello.
    public func setEvidence(_ evidence: [Member.Evidence]) throws {
        struct A: Encodable { var evidence: [Member.Evidence] }
        try run("evidence", A(evidence: evidence))
    }

    /// Ends the connection to device with a goodbye; it is dialed again
    /// later.
    public func disconnect(_ device: String) throws {
        struct A: Encodable { var device: String }
        try run("disconnect", A(device: device))
    }

    /// The devices connected now, by ID.
    public func connected() -> Set<String> { Set(((try? peers()) ?? []).map(\.device)) }

    // MARK: The group in 0.6

    // The member keeps and evaluates the records (docs/core-api.md, "The
    // member"); the app reads what it shows and asks for what the person
    // decides.

    /// The group as the member sees it now.
    public func group() throws -> GroupState { try run("group", Optional<Empty>.none, as: GroupState.self) }

    /// The member's notices about the group, newest first.
    public func notices() throws -> [Notice] {
        struct R: Decodable { var notices: [Notice] }
        return try run("notices", Optional<Empty>.none, as: R.self).notices
    }

    /// Hides the notice id until something about it changes.
    public func dismiss(_ id: String) throws {
        struct A: Encodable { var id: String }
        try run("dismiss", A(id: id))
    }

    /// Tells the member the person kept the recovery key: "sheet" or
    /// "yubikey".
    public func recoverySaved(_ how: String) throws {
        struct A: Encodable { var how: String }
        try run("recovery_saved", A(how: how))
    }

    /// Answers `Event.needKey`: the app made the key public (DER).
    public func keyMade(_ token: UInt64, public: Data) throws {
        struct A: Encodable { var token: UInt64, `public`: Data }
        try run("key_made", A(token: token, public: try Self.point(`public`)))
    }

    /// Who stays after a change of root with the recovery key, before
    /// anything is signed: the core writes the list; leaveOut are the
    /// devices the person unticked. The recovery keys are derived inside
    /// the call and dropped at its end.
    public func changePreview(_ recovery: RecoveryInput, leaveOut: [String] = []) throws -> ChangePreview {
        struct A: Encodable { var action = "change_preview", recovery: RecoveryInput, leave_out: [String] }
        return try manage(A(recovery: recovery, leave_out: leaveOut), sign: { _ in throw Core.Mismatch(reason: "a preview signs nothing") },
                          as: ChangePreview.self)
    }

    /// Changes the group's root to this phone's new root key rootPublic
    /// (DER), which sign signs with (Face ID before each use): the recovery
    /// key signs the change, the new root its first records, and leaveOut
    /// are removed in the same act. overWaiting writes over a change whose
    /// records never came; offer it only after a sync failed. It returns
    /// the change's step.
    @discardableResult
    public func changeRoot(_ recovery: RecoveryInput, leaveOut: [String], rootPublic: Data, dropHubs: Bool = false, overWaiting: Bool = false,
                           sign: @escaping (Data) throws -> Data) throws -> UInt64 {
        struct A: Encodable {
            var action = "change_root", recovery: RecoveryInput, leave_out: [String], drop_hubs: Bool, over_waiting: Bool, `public`: Data
        }
        struct R: Decodable { var seq: UInt64? }
        return try manage(A(recovery: recovery, leave_out: leaveOut, drop_hubs: dropHubs, over_waiting: overWaiting,
                            public: try Self.point(rootPublic)), sign: sign, as: R.self).seq ?? 0
    }

    // MARK: Taking the group over

    /// Where a claim to take the group over stands, as finish_takeover
    /// answers.
    public struct Takeover: Decodable, Sendable {
        /// none, pending, cancelled, void, competing, disputed or effective.
        public var state: String
        /// How long the claim still waits, while pending.
        public var leftMS: Int64
        /// The phone's member certificate from the new root, once effective.
        public var cert: Data?

        enum CodingKeys: String, CodingKey { case state, leftMS = "left_ms", cert }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            state = try c.decode(String.self, forKey: .state)
            leftMS = try c.decodeIfPresent(Int64.self, forKey: .leftMS) ?? 0
            cert = try c.decodeIfPresent(Data.self, forKey: .cert)
        }
    }

    /// Who claims the group (docs/protocol.md, section 10, "Handing the
    /// group over").
    public enum Claim: String, Sendable {
        /// An admin phone, from the lost root's device.
        case takeOver = "take_over"
        /// The admin phone the root handed the group to.
        case takeHandedOver = "take_handed_over"
        /// The group's recovery key, under its admin CA.
        case recover
    }

    /// The uncompressed point of a SubjectPublicKeyInfo, as the member's
    /// manage requests name a key.
    private static func point(_ der: Data) throws -> Data {
        try P256.Signing.PublicKey(derRepresentation: der).x963Representation
    }

    /// A root CA for a new key of this phone, before a claim
    /// (cbb_member_manage's root_ca): public is the new key, DER, which sign
    /// signs a digest with. The app keeps the CA and the key until the
    /// claim takes effect or ends.
    public func rootCA(public: Data, sign: @escaping (Data) throws -> Data) throws -> Data {
        struct A: Encodable { var action = "root_ca", `public`: Data }
        struct R: Decodable { var root_ca: Data? }
        guard let ca = try manage(A(public: try Self.point(`public`)), sign: sign, as: R.self).root_ca else {
            throw Core.Mismatch(reason: "the member's root CA is missing")
        }
        return ca
    }

    /// Claims the group for rootCA, signed with the key public (DER) under
    /// its CA ca (the admin key and admin CA, or the recovery key and its
    /// CA); the member adds the claim to its records and sends it. lost is
    /// the lost root's device for Claim.takeOver.
    public func claim(_ kind: Claim, rootCA: Data, public: Data, ca: Data, sign: @escaping (Data) throws -> Data, lost: String? = nil) throws {
        struct A: Encodable { var action: String, device: String?, root_ca: Data, `public`: Data, admin_ca: Data }
        _ = try manage(A(action: kind.rawValue, device: lost, root_ca: rootCA, public: try Self.point(`public`), admin_ca: ca),
                       sign: sign, as: Empty.self)
    }

    /// Finishes this phone's claim for rootCA once it took effect: the
    /// member signs, with the new root key public (DER) through sign, the
    /// phone's member certificate from the new root and the records a new
    /// root starts with, adds and sends them. While the claim waits, or
    /// after it ended, it signs nothing and only says where the claim
    /// stands, so the app may ask again.
    public func finishTakeover(rootCA: Data, public: Data, name: String, os: String = "ios", store: String, seal: Data?,
                               sign: @escaping (Data) throws -> Data) throws -> Takeover {
        struct A: Encodable { var action = "finish_takeover", root_ca: Data, `public`: Data, name: String, os: String, store: String, seal: Data? }
        return try manage(A(root_ca: rootCA, public: try Self.point(`public`), name: name, os: os, store: store, seal: seal),
                          sign: sign, as: Takeover.self)
    }

    // The root's own records (cbb_core::root): the member builds and checks
    // each, signs it with the root key public (DER) through sign, adds it to
    // its records and sends it; the app then takes the member's records.

    /// Sets how long a claim waits before it takes effect (0 to 7 days),
    /// keeping the key level.
    public func setTakeoverDelay(ms: Int64, public: Data, sign: @escaping (Data) throws -> Data) throws {
        struct A: Encodable { var action = "takeover_delay", delay_ms: Int64, `public`: Data }
        _ = try manage(A(delay_ms: ms, public: try Self.point(`public`)), sign: sign, as: Empty.self)
    }

    /// Sets the group's key level (proven, hardware or files), keeping the
    /// takeover delay; never a level this phone's own keys do not pass. It
    /// returns the admins and hubs whose keys the level would not let in, by
    /// device ID: they stay until the user removes them.
    @discardableResult
    public func setKeyLevel(_ level: String, public: Data, sign: @escaping (Data) throws -> Data) throws -> [String] {
        struct A: Encodable { var action = "key_level", level: String, `public`: Data }
        struct R: Decodable { var below: [String]? }
        return try manage(A(level: level, public: try Self.point(`public`)), sign: sign, as: R.self).below ?? []
    }

    /// On the root of a group of 0.6: the group's relays, each "address
    /// pin", or "default" alone; none meets at no relay. It answers their
    /// addresses.
    @discardableResult
    public func setRelays(_ relays: [String], public: Data, sign: @escaping (Data) throws -> Data) throws -> [String] {
        struct A: Encodable { var action = "relay", relays: [String], `public`: Data }
        struct R: Decodable { var relays: [String]? }
        return try manage(A(relays: relays, public: try Self.point(`public`)), sign: sign, as: R.self).relays ?? []
    }

    /// On the root of a group of 0.6: names the forwarder of device, an
    /// admin phone or a computer that may be a hub, at forwarder
    /// (`host:port`, or `default` for the project's) with its key's pin
    /// key, which the device takes as its forwarder setting and serves
    /// through once its hub is on. The device's answer: done, refused or
    /// failed, and why.
    public func nameForwarder(_ device: String, forwarder: String, key: String, public: Data,
                              sign: @escaping (Data) throws -> Data) throws -> (status: String, reason: String) {
        struct A: Encodable { var action = "forwarder", device: String, forwarder: String, key: String, `public`: Data }
        struct R: Decodable { var status: String?, reason: String? }
        let r = try manage(A(device: device, forwarder: forwarder, key: key, public: try Self.point(`public`)), sign: sign, as: R.self)
        return (r.status ?? "", r.reason ?? "")
    }

    /// Hands the group to the admin device, whose claim then takes effect at once.
    public func handOver(to device: String, public: Data, sign: @escaping (Data) throws -> Data) throws {
        struct A: Encodable { var action = "hand_over", device: String, `public`: Data }
        _ = try manage(A(device: device, public: try Self.point(`public`)), sign: sign, as: Empty.self)
    }

    /// Makes the group's recovery key, which replaces the one before it, and
    /// returns its sheet; nothing of the key stays in the core.
    public func makeRecovery(public: Data, sign: @escaping (Data) throws -> Data) throws -> Core.RecoverySheet {
        struct A: Encodable { var action = "make_recovery", `public`: Data }
        return try manage(A(public: try Self.point(`public`)), sign: sign, as: Core.RecoverySheet.self)
    }

    /// Removes the group's recovery key: the root revokes it, and a sheet
    /// printed for it no longer works.
    public func removeRecovery(public: Data, sign: @escaping (Data) throws -> Data) throws {
        struct A: Encodable { var action = "remove_recovery", `public`: Data }
        _ = try manage(A(public: try Self.point(`public`)), sign: sign, as: Empty.self)
    }

    /// The signer of one manage call, which the core calls during it only.
    fileprivate final class Signing {
        let sign: (Data) throws -> Data
        init(_ sign: @escaping (Data) throws -> Data) { self.sign = sign }
    }

    /// Asks the member for an admin's change or a step of a takeover
    /// (cbb_member_manage), signed through sign during this call; decodes
    /// its answer's ok.
    func manage<A: Encodable, R: Decodable>(_ request: A, sign: @escaping (Data) throws -> Data, as _: R.Type) throws -> R {
        guard !lock.withLock({ stopped }) else { throw Stopped() }
        let bytes = try JSONEncoder().encode(request)
        let signing = Signing(sign)
        var count = 0
        // Held until the call is over: the core calls it during the call.
        let answer: UnsafeMutablePointer<UInt8>? = withExtendedLifetime(signing) {
            let raw = Unmanaged.passUnretained(signing).toOpaque()
            return bytes.withUnsafeBytes { r in
                cbb_member_manage(handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, coreManageSign, raw, &count)
            }
        }
        guard let answer else { throw Core.Mismatch(reason: "the member gave no answer to manage") }
        defer { cbb_free(answer, count) }
        let reply: Reply<R>
        do {
            reply = try JSONDecoder().decode(Reply<R>.self, from: Data(bytes: answer, count: count))
        } catch {
            throw Core.Mismatch(reason: "the member's answer to manage does not read: \(error)")
        }
        if let e = reply.error { throw Failure.of(e.refusal) }
        guard let ok = reply.ok else { throw Core.Mismatch(reason: "the member's answer to manage has neither ok nor error") }
        return ok
    }

    // MARK: Events

    /// An event as the core sends it.
    struct Wire: Decodable {
        var type: String
        var text: String?
        var kind: String?
        var ttl_ms: UInt64?
        var line: String?
        var copy: Copy?
        var from: String?
        var message: WireMessage?
        var cert: Data?
        var issuer: Data?
        var roots: [Data]?
        var peer: Peer?
        var offer: Member.TunnelOffer?
        var token: UInt64?
        var command: Member.Record?
        var port: UInt16?
        var device: String?
        var muted: Bool?
        var off: Bool?
        var for_ms: Int64?
        var by: String?
        var details: String?
        var state: GroupState?
        var notice: Notice?
        var to: String?
        var seq: UInt64?
        var `public`: Data?
    }

    struct WireMessage: Decodable {
        var t: String
        var admin_ca: Data?
        var credentials: [ServerCredentials.Credential]?
        var evidence: Member.Evidence?
    }

    /// The event the core sent as JSON, nil for one this kit does not read.
    static func event(_ data: Data) -> Event? {
        guard let w = try? JSONDecoder().decode(Wire.self, from: data) else {
            return .log("cbb: an event of the member does not read: \(String(decoding: data.prefix(200), as: UTF8.self))")
        }
        switch w.type {
        case "write":
            guard let text = w.text else { return nil }
            return .write(text: text, kind: w.kind.flatMap(Member.Kind.init(rawValue:)) ?? .text, ttlMS: w.ttl_ms)
        case "log": return w.line.map { .log($0) }
        case "copy": return w.copy.map { .copy($0) }
        case "identity":
            guard let cert = w.cert else { return nil }
            return .identity(cert: cert, issuer: w.issuer, roots: w.roots ?? [])
        case "peer": return w.peer.map { .peer($0) }
        case "tunnel":
            guard let from = w.from, let offer = w.offer else { return nil }
            return .tunnel(from: from, offer: offer)
        case "command":
            guard let token = w.token, let from = w.from, let command = w.command else { return nil }
            return .command(token: token, from: from, command: command)
        case "mute":
            guard let muted = w.muted else { return nil }
            return .mute(muted: muted, forMS: w.for_ms ?? 0, by: w.by ?? "")
        case "sync":
            guard let off = w.off else { return nil }
            return .sync(off: off, by: w.by ?? "")
        case "state": return w.state.map { .state($0) }
        case "notice": return w.notice.map { .notice($0) }
        case "root_changed": return .rootChanged(from: w.from ?? "", to: w.to ?? "", seq: w.seq ?? 0)
        case "need_key":
            guard let token = w.token, let kind = w.kind else { return nil }
            return .needKey(token: token, kind: kind)
        case "key_done": return w.public.map { .keyDone(public: $0) }
        case "panic": return .panic(details: w.details ?? "")
        case "caller":
            guard let token = w.token, let port = w.port, let device = w.device else { return nil }
            return .caller(token: token, port: port, device: device)
        case "message":
            guard let from = w.from, let m = w.message else { return nil }
            switch m.t {
            case "admin": return m.admin_ca.map { .message(from: from, .admin(ca: $0)) }
            case "credentials": return m.credentials.map { .message(from: from, .credentials($0)) }
            case "evidence": return m.evidence.map { .message(from: from, .evidence($0)) }
            default: return .message(from: from, .other(m.t))
            }
        default:
            return nil
        }
    }

    fileprivate static func deliver(_ ctx: UnsafeMutableRawPointer?, _ data: Data) {
        guard let ctx, let e = event(data) else { return }
        Unmanaged<Context>.fromOpaque(ctx).takeUnretainedValue().send(e)
    }

    fileprivate static func sign(_ ctx: UnsafeMutableRawPointer?, _ digest: Data) -> Data? {
        guard let ctx else { return nil }
        return try? Unmanaged<Context>.fromOpaque(ctx).takeUnretainedValue().sign(digest)
    }
}

/// The member's signing callback (cbb_sign_fn): the member key signs the
/// 32-byte digest; the signature, DER, goes into sig's 72 bytes.
private func coreMemberSign(_ ctx: UnsafeMutableRawPointer?, _ digest: UnsafePointer<UInt8>?, _ sig: UnsafeMutablePointer<UInt8>?,
                            _ sigLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let digest, let sig, let sigLen else { return 1 }
    guard let s = CoreMember.sign(ctx, Data(bytes: digest, count: 32)), s.count <= 72 else { return 1 }
    s.copyBytes(to: sig, count: s.count)
    sigLen.pointee = s.count
    return 0
}

/// The member's event callback (cbb_event_fn), on one of its threads.
private func coreMemberEvent(_ ctx: UnsafeMutableRawPointer?, _ event: UnsafePointer<UInt8>?, _ len: Int) {
    guard let event else { return }
    CoreMember.deliver(ctx, Data(bytes: event, count: len))
}

/// The signing callback of one manage call (cbb_sign_fn): its signer signs
/// the 32-byte digest; the signature, DER, goes into sig's 72 bytes.
private func coreManageSign(_ ctx: UnsafeMutableRawPointer?, _ digest: UnsafePointer<UInt8>?, _ sig: UnsafeMutablePointer<UInt8>?,
                            _ sigLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let ctx, let digest, let sig, let sigLen else { return 1 }
    let signing = Unmanaged<CoreMember.Signing>.fromOpaque(ctx).takeUnretainedValue()
    guard let s = try? signing.sign(Data(bytes: digest, count: 32)), s.count <= 72 else { return 1 }
    s.copyBytes(to: sig, count: s.count)
    sigLen.pointee = s.count
    return 0
}
