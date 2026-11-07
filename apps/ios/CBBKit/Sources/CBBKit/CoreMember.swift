// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Crypto
import Foundation

/// The phone as a member of its group, run by the Rust core inside the app
/// (ffi/, docs/core-api.md, "The member"): the lite member's node on
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

        enum CodingKeys: String, CodingKey {
            case dir, name, os, osVersion = "os_version", version, keyStore = "key_store", device, publicKey = "public", seal, cert, issuer
            case groupCA = "group_ca", roots, peers, mdns
        }

        /// publicKeyDER is the member key's SubjectPublicKeyInfo, as
        /// CertificateSigner gives it.
        public init(dir: URL, name: String, os: String = "ios", osVersion: String = "", version: String = "", keyStore: String = "hardware",
                    device: String, publicKeyDER: Data, seal: Data, cert: Data, issuer: Data?, groupCA: Data, roots: [Data],
                    peers: [String] = [], mdns: Bool = false) throws {
            (self.dir, self.name, self.os, self.osVersion, self.version, self.keyStore) = (dir.path, name, os, osVersion, version, keyStore)
            (self.device, self.seal, self.cert, self.issuer, self.groupCA, self.roots) = (device, seal, cert, issuer, groupCA, roots)
            (self.peers, self.mdns) = (peers, mdns)
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
        /// The admin key a full member that is no admin yet offers, DER.
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

        public init(device: String, name: String = "", role: String = "full", os: String = "", keyStore: String = "", mode: String = "",
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
        /// What a hub shares with the group's other hubs.
        case hubs(Member.HubShare)
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

    private let handle: OpaquePointer
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
        struct A: Encodable { var text: String, secret: Bool, board: Bool }
        try run("copy", A(text: text, secret: secret, board: board))
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

    /// Sets the sync mode the hellos say.
    public func setMode(_ mode: String) throws {
        struct A: Encodable { var mode: String }
        try run("mode", A(mode: mode))
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
        try run("mute", A(until_ms: untilMS))
    }

    /// The members connected now; all adds those that carry records only.
    public func peers(all: Bool = false) throws -> [Peer] {
        struct A: Encodable { var all: Bool }
        struct R: Decodable { var peers: [Peer] }
        return try run("peers", A(all: all), as: R.self).peers
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

    /// Sends a full member the admin CA for the admin key its hello offers.
    @discardableResult
    public func sendAdminCA(to: String, ca: Data) throws -> Bool {
        struct A: Encodable { var to: String, ca: Data }
        return try run("send_admin_ca", A(to: to, ca: ca), as: Sent.self).sent
    }

    /// Sends the member to a tunnel offer of this hub's, or of another it
    /// passes on.
    @discardableResult
    public func sendTunnel(to: String, offer: Member.TunnelOffer) throws -> Bool {
        struct A: Encodable { var to: String, offer: Member.TunnelOffer }
        return try run("send_tunnel", A(to: to, offer: offer), as: Sent.self).sent
    }

    /// Sends what this hub shares to the group's other hubs connected, or
    /// to the member to only; those it went to.
    @discardableResult
    public func sendHubs(_ share: Member.HubShare, to: String? = nil) throws -> [String] {
        struct A: Encodable { var share: Member.HubShare, to: String? }
        return try run("send_hubs", A(share: share, to: to), as: To.self).to
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

    /// Sets the tunnel key and preshared key the hellos offer the group's
    /// hubs, nil while sync away from home is off.
    public func setTunnelKey(_ key: Data?, psk: Data?) throws {
        struct A: Encodable { var key: Data?, psk: Data? }
        try run("tunnel_key", key == nil || psk == nil ? A(key: nil, psk: nil) : A(key: key, psk: psk))
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

    // MARK: Events

    /// An event as the core sends it.
    struct Wire: Decodable {
        var type: String
        var text: String?
        var kind: Member.Kind?
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
        var for_ms: Int64?
        var by: String?
    }

    struct WireMessage: Decodable {
        var t: String
        var admin_ca: Data?
        var hubs: Member.HubShare?
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
            return .write(text: text, kind: w.kind ?? .text, ttlMS: w.ttl_ms)
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
        case "caller":
            guard let token = w.token, let port = w.port, let device = w.device else { return nil }
            return .caller(token: token, port: port, device: device)
        case "message":
            guard let from = w.from, let m = w.message else { return nil }
            switch m.t {
            case "admin": return m.admin_ca.map { .message(from: from, .admin(ca: $0)) }
            case "hubs": return m.hubs.map { .message(from: from, .hubs($0)) }
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
