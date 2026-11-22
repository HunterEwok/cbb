// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Crypto
import Foundation

/// Pairing in the Rust core (docs/core-api.md, "Joining and admitting"): a
/// phone that makes a group (`newGroup`, `newGroup06`), opens a pairing
/// window for a device at home (`Window`), joins a group by a window's QR
/// code (`Joiner`), or makes a remote invitation (`Inviting`). The core runs
/// the exchange inside its own TLS and asks for each signature through a
/// callback, so the keys stay in the keychain and the Secure Enclave.
public enum CorePairing {
    /// Why a pairing failed: the core's message and details, and whether
    /// the code was wrong.
    public struct Failure: Error, Equatable, CustomStringConvertible {
        public var message: String
        public var details: String?
        public var wrongCode: Bool

        public init(_ message: String, details: String? = nil, wrongCode: Bool = false) {
            (self.message, self.details, self.wrongCode) = (message, details, wrongCode)
        }

        public var description: String {
            guard let details, !details.isEmpty else { return "CorePairing.Failure: \(message)" }
            return "CorePairing.Failure: \(message)\n\(details)"
        }
    }

    /// A group of 0.6 this phone made: its ID, this phone's device ID and
    /// the recovery sheet, which the person keeps and the app keeps nowhere.
    public struct Made: Decodable, Sendable {
        public struct Sheet: Decodable, Sendable {
            public var qr: String
            public var text: [String]
        }

        public var group: String
        public var device: String
        public var recovery: Sheet
    }

    /// Makes a group of 0.6 with this phone's root key (cbb_group_new): the core writes this phone's record under the root and keeps
    /// the set in dir, where the member then reads it. rootPublic and
    /// publicKey are the root and member keys (SubjectPublicKeyInfo or
    /// point), store where the member key lives (Records.hardware or
    /// Records.file); signRoot signs a digest with the root key, during
    /// this call only.
    public static func newGroup(dir: URL, name: String, os: String = "ios", store: String, rootPublic: Data, publicKey: Data,
                                signRoot: @escaping (Data) throws -> Data) throws -> Made {
        struct Request: Encodable {
            var dir: String, name: String, os: String, store: String, root_public: Data, `public`: Data
        }
        let request = try JSONEncoder().encode(Request(dir: dir.path, name: name, os: os, store: store, root_public: try point(rootPublic),
                                                       public: try point(publicKey)))
        let signer = Signer(signRoot)
        let raw = Unmanaged.passRetained(signer).toOpaque()
        defer { Unmanaged<Signer>.fromOpaque(raw).release() }
        var count = 0
        let answer: UnsafeMutablePointer<UInt8>? = request.withUnsafeBytes { r in
            cbb_group_new(r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, raw, &count)
        }
        return try ok("new group", take(answer, count), as: Made.self)
    }

    /// A remote invitation an admin phone makes (docs/protocol.md, section
    /// 12) through member: its guest tunnel opens on this phone when it is
    /// the group's hub, else through a connected hub of the group (hub
    /// names one, empty for any). publicKey is the key sign holds (the admin
    /// key or the root's key); sign is called when a device the user confirmed is
    /// admitted. expires is in seconds: an hour when 0, a day at most. It
    /// waits for the hub, so the app makes it off its main thread.
    public final class Inviting: @unchecked Sendable {
        private let handle: OpaquePointer
        private let signer: UnsafeMutableRawPointer
        /// The member stays running until the invitation is freed.
        private let member: CoreMember
        /// Guards closed and calls: close frees the invitation once no call
        /// is in it.
        private let lock = NSCondition()
        private var closed = false
        private var calls = 0

        /// The invitation's text, cbb://invite#..., for its QR code.
        public let text: String
        /// How long it is valid from when it was made, in seconds.
        public let expires: Int

        /// A device that proved the invitation's secret: the app asks the
        /// user whether its fingerprint matches what the device shows.
        public struct Request: Decodable, Equatable, Sendable {
            public var device: String
            public var name: String
            public var os: String
            public var fingerprint: String
        }

        /// Where the invitation is: open, joining (answer about request),
        /// done (name joined) or failed.
        public struct State: Sendable {
            public var version: UInt64
            public var state: String
            public var request: Request?
            public var name: String
            public var failure: Failure?
        }

        /// kind is the device invited on a group of 0.6: "computer" (or
        /// empty) or "phone".
        public init(member: CoreMember, publicKey: Data, expires: Int, hub: String = "", kind: String = "",
                    sign: @escaping (Data) throws -> Data) throws {
            struct Args: Encodable { var `public`: Data, expires: Int, hub: String, kind: String }
            struct Answer: Decodable { var invite: String?, expires: Int? }
            let request = try JSONEncoder().encode(Args(public: try point(publicKey), expires: expires, hub: hub,
                                                        kind: kind))
            let s = Unmanaged.passRetained(Signer(sign)).toOpaque()
            var answer: UnsafeMutablePointer<UInt8>?
            var count = 0
            let h: OpaquePointer? = request.withUnsafeBytes { r in
                cbb_invite_new(member.handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, s, &answer, &count)
            }
            let o: Answer
            do {
                guard let h else {
                    _ = try ok("invite", take(answer, count), as: Answer.self)
                    throw Core.Mismatch(reason: "the core made no invitation")
                }
                handle = h
                o = try ok("invite", take(answer, count), as: Answer.self)
            } catch {
                if let h { cbb_invite_free(h) }
                Unmanaged<Signer>.fromOpaque(s).release()
                throw error
            }
            (signer, self.member, text, self.expires) = (s, member, o.invite ?? "", o.expires ?? 0)
        }

        deinit { close() }

        /// Waits up to timeout for a state past version; it blocks, so the
        /// app calls it off its main thread.
        public func next(after version: UInt64, timeout: Duration = .seconds(1)) throws -> State {
            struct Answer: Decodable {
                var version: UInt64?, state: String?, joining: Request?, name: String?, error: Refused?
            }
            let ms = UInt64(max(0, timeout.components.seconds)) * 1000 + UInt64(timeout.components.attoseconds / 1_000_000_000_000_000)
            try enter()
            defer { leave() }
            let a = try ok("invite", call { cbb_invite_next(handle, version, ms, &$0) }, as: Answer.self)
            return State(version: a.version ?? version, state: a.state ?? "open", request: a.joining, name: a.name ?? "",
                         failure: a.error.map { Failure($0.message, details: $0.details) })
        }

        /// The user's answer about the device that asks to join.
        public func answer(_ yes: Bool) {
            guard (try? enter()) != nil else { return }
            defer { leave() }
            cbb_invite_answer(handle, yes ? 1 : 0)
        }

        private func enter() throws {
            lock.lock()
            defer { lock.unlock() }
            guard !closed else { throw Failure("the invitation is closed") }
            calls += 1
        }

        private func leave() {
            lock.lock()
            calls -= 1
            lock.broadcast()
            lock.unlock()
        }

        /// Ends the invitation; it waits a moment for its window to close.
        public func close() {
            lock.lock()
            let first = !closed
            closed = true
            while calls > 0 { lock.wait() }
            lock.unlock()
            guard first else { return }
            cbb_invite_free(handle)
            Unmanaged<Signer>.fromOpaque(signer).release()
        }
    }

    /// A home window of a phone of 0.6 (docs/protocol.md, "Pairing in 0.6"):
    /// the member port listens, the app shows the QR code and the six
    /// digits, the new device dials and proves the digits; nobody is asked.
    /// publicKey is the admitting key sign holds (the admin key, or the
    /// root's); addrs the phone's home addresses without a port; expires in
    /// seconds (five minutes when 0, an hour at most). The app announces the
    /// window with Bonjour (p=1, f=fingerprint, i=id), never the digits.
    public final class Window: @unchecked Sendable {
        private let handle: OpaquePointer
        private let signer: UnsafeMutableRawPointer
        private let member: CoreMember
        private let lock = NSCondition()
        private var closed = false
        private var calls = 0

        /// The QR code's text, cbb://pair?addr=…&fp=…&i=…&c=….
        public let qr: String
        /// The six digits to show, for a device that types them.
        public let digits: String
        /// The window's ID in hex, as the QR code's i and the mDNS i.
        public let id: String
        /// The hash of the phone's member key in hex, as the QR code's fp
        /// and the mDNS f.
        public let fingerprint: String
        public let expires: Int

        /// open, joining (a device pairs), done (name joined; the window is
        /// closed), failed (that attempt; the window stays open) or closed
        /// (its time is up, or three wrong codes: failure).
        public struct State: Sendable {
            public var version: UInt64
            public var state: String
            public var name: String
            public var device: String
            public var failure: Failure?
        }

        public init(member: CoreMember, publicKey: Data, addrs: [String], expires: Int = 0,
                    sign: @escaping (Data) throws -> Data) throws {
            struct Args: Encodable { var `public`: Data, addrs: [String], expires: Int, mdns: Bool }
            struct Answer: Decodable { var qr: String?, digits: String?, id: String?, fingerprint: String?, expires: Int? }
            let request = try JSONEncoder().encode(Args(public: try point(publicKey), addrs: addrs, expires: expires, mdns: false))
            let s = Unmanaged.passRetained(Signer(sign)).toOpaque()
            var answer: UnsafeMutablePointer<UInt8>?
            var count = 0
            let h: OpaquePointer? = request.withUnsafeBytes { r in
                cbb_window_new(member.handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, s, &answer, &count)
            }
            let o: Answer
            do {
                guard let h else {
                    _ = try ok("window", take(answer, count), as: Answer.self)
                    throw Core.Mismatch(reason: "the core opened no window")
                }
                handle = h
                o = try ok("window", take(answer, count), as: Answer.self)
            } catch {
                if let h { cbb_window_free(h) }
                Unmanaged<Signer>.fromOpaque(s).release()
                throw error
            }
            (signer, self.member) = (s, member)
            (qr, digits, id) = (o.qr ?? "", o.digits ?? "", o.id ?? "")
            (fingerprint, self.expires) = (o.fingerprint ?? "", o.expires ?? 0)
        }

        deinit { close() }

        /// Waits up to timeout for a state past version; it blocks, so the
        /// app calls it off its main thread.
        public func next(after version: UInt64, timeout: Duration = .seconds(1)) throws -> State {
            struct Answer: Decodable {
                var version: UInt64?, state: String?, name: String?, device: String?, error: Refused?
            }
            try enter()
            defer { leave() }
            let a = try ok("window", call { cbb_window_next(handle, version, millis(timeout), &$0) }, as: Answer.self)
            return State(version: a.version ?? version, state: a.state ?? "open", name: a.name ?? "", device: a.device ?? "",
                         failure: a.error.map { Failure($0.message, details: $0.details) })
        }

        private func enter() throws {
            lock.lock()
            defer { lock.unlock() }
            guard !closed else { throw Failure("the window is closed") }
            calls += 1
        }

        private func leave() {
            lock.lock()
            calls -= 1
            lock.broadcast()
            lock.unlock()
        }

        /// Closes the window.
        public func close() {
            lock.lock()
            let first = !closed
            closed = true
            while calls > 0 { lock.wait() }
            lock.unlock()
            guard first else { return }
            cbb_window_free(handle)
            Unmanaged<Signer>.fromOpaque(signer).release()
        }
    }

    /// A new phone that joins a group of 0.6 by a home window's QR code, or
    /// by the six digits the person typed (qr empty: the one window the
    /// core finds by mDNS; the iPhone app builds the code from its own
    /// Bonjour browse instead, `Discovery.windowLink`): it dials, proves the
    /// digits, and the group is kept in dir, where the app then starts its
    /// member. publicKey is the member key sign holds. With invite, a remote
    /// invitation's text, it joins from afar through the invitation's guest
    /// tunnel instead, and `fingerprint` is what the phone shows for the
    /// inviting admin to compare. With admin, the phone offers its admin
    /// key (its public key and its signer): the root keeps it and makes the
    /// phone an admin with it later.
    public final class Joiner: @unchecked Sendable {
        private let handle: OpaquePointer
        private let signer: UnsafeMutableRawPointer
        private let adminSigner: UnsafeMutableRawPointer?
        private let lock = NSCondition()
        private var closed = false
        private var calls = 0
        /// By an invitation: the fingerprint of the phone's key.
        public let fingerprint: String

        /// dialing, done (group, device, and name, the member that let the
        /// phone in) or failed; by an invitation, answered once the hub
        /// answered through the guest tunnel.
        public struct State: Sendable {
            public var version: UInt64
            public var state: String
            public var group: String
            public var device: String
            public var name: String
            public var failure: Failure?
            public var answered: Bool = false
        }

        public init(dir: URL, qr: String, digits: String = "", invite: String = "", name: String, os: String, publicKey: Data,
                    admin: (publicKey: Data, sign: (Data) throws -> Data)? = nil,
                    sign: @escaping (Data) throws -> Data) throws {
            struct Args: Encodable {
                var dir: String, qr: String, digits: String, invite: String, name: String, os: String, `public`: Data
                var admin_public: Data?
            }
            let request = try JSONEncoder().encode(Args(dir: dir.path, qr: qr, digits: digits, invite: invite, name: name, os: os,
                                                        public: try point(publicKey),
                                                        admin_public: try admin.map { try point($0.publicKey) }))
            let s = Unmanaged.passRetained(Signer(sign)).toOpaque()
            let a = admin.map { Unmanaged.passRetained(Signer($0.sign)).toOpaque() }
            var answer: UnsafeMutablePointer<UInt8>?
            var count = 0
            let h: OpaquePointer? = request.withUnsafeBytes { r in
                if let a {
                    return cbb_joiner_new_admin(r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, s,
                                                corePairingSign, a, &answer, &count)
                }
                return cbb_joiner_new(r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, s, &answer, &count)
            }
            struct Answer: Decodable { var state: String?, fingerprint: String? }
            do {
                guard let h else {
                    _ = try ok("join", take(answer, count), as: Answer.self)
                    throw Core.Mismatch(reason: "the core started no joining")
                }
                handle = h
                fingerprint = try ok("join", take(answer, count), as: Answer.self).fingerprint ?? ""
            } catch {
                if let h { cbb_joiner_free(h) }
                Unmanaged<Signer>.fromOpaque(s).release()
                if let a { Unmanaged<Signer>.fromOpaque(a).release() }
                throw error
            }
            (signer, adminSigner) = (s, a)
        }

        deinit { close() }

        /// Waits up to timeout for a state past version; it blocks, so the
        /// app calls it off its main thread.
        public func next(after version: UInt64, timeout: Duration = .seconds(1)) throws -> State {
            struct Answer: Decodable {
                var version: UInt64?, state: String?, group: String?, device: String?, name: String?, error: Refused?
                var answered: Bool?
            }
            try enter()
            defer { leave() }
            let a = try ok("join", call { cbb_joiner_next(handle, version, millis(timeout), &$0) }, as: Answer.self)
            return State(version: a.version ?? version, state: a.state ?? "dialing", group: a.group ?? "",
                         device: a.device ?? "", name: a.name ?? "",
                         failure: a.error.map { Failure($0.message, details: $0.details) }, answered: a.answered ?? false)
        }

        private func enter() throws {
            lock.lock()
            defer { lock.unlock() }
            guard !closed else { throw Failure("joining ended") }
            calls += 1
        }

        private func leave() {
            lock.lock()
            calls -= 1
            lock.broadcast()
            lock.unlock()
        }

        /// Ends joining.
        public func close() {
            lock.lock()
            let first = !closed
            closed = true
            while calls > 0 { lock.wait() }
            lock.unlock()
            guard first else { return }
            cbb_joiner_free(handle)
            Unmanaged<Signer>.fromOpaque(signer).release()
            if let adminSigner { Unmanaged<Signer>.fromOpaque(adminSigner).release() }
        }
    }

    /// A duration in whole milliseconds, for the core's waits.
    static func millis(_ d: Duration) -> UInt64 {
        UInt64(max(0, d.components.seconds)) * 1000 + UInt64(max(0, d.components.attoseconds) / 1_000_000_000_000_000)
    }

    // MARK: The core's answers

    /// The uncompressed point of a P-256 public key given as a
    /// SubjectPublicKeyInfo or as the point itself.
    static func point(_ key: Data) throws -> Data {
        if key.count == 65, key.first == 4 { return key }
        return try P256.Signing.PublicKey(derRepresentation: key).x963Representation
    }

    /// The signer a callback's context holds.
    fileprivate final class Signer {
        let sign: (Data) throws -> Data
        init(_ sign: @escaping (Data) throws -> Data) { self.sign = sign }
    }

    /// The answer's bytes, given back to the core.
    private static func take(_ answer: UnsafeMutablePointer<UInt8>?, _ count: Int) throws -> Data {
        guard let answer else { throw Core.Mismatch(reason: "the core gave no answer") }
        defer { cbb_free(answer, count) }
        return Data(bytes: answer, count: count)
    }

    /// Calls f with the answer's length and takes the answer it returns.
    private static func call(_ f: (inout Int) -> UnsafeMutablePointer<UInt8>?) throws -> Data {
        var count = 0
        let answer = f(&count)
        return try take(answer, count)
    }

    private struct Refused: Decodable {
        var message: String
        var details: String?
    }

    private struct Reply<R: Decodable>: Decodable {
        var ok: R?
        var error: Refused?
    }

    /// The answer's ok; its error throws Failure.
    private static func ok<R: Decodable>(_ what: String, _ bytes: Data, as _: R.Type) throws -> R {
        let reply: Reply<R>
        do {
            reply = try JSONDecoder().decode(Reply<R>.self, from: bytes)
        } catch {
            throw Core.Mismatch(reason: "the core's answer to \(what) does not read: \(error)")
        }
        if let e = reply.error { throw Failure(e.message, details: e.details) }
        guard let ok = reply.ok else { throw Core.Mismatch(reason: "the core's answer to \(what) has neither ok nor error") }
        return ok
    }
}

/// The pairing's signing callback (cbb_sign_fn): the key signs the 32-byte
/// digest; the signature, DER, goes into sig's 72 bytes.
private func corePairingSign(_ ctx: UnsafeMutableRawPointer?, _ digest: UnsafePointer<UInt8>?, _ sig: UnsafeMutablePointer<UInt8>?,
                             _ sigLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let ctx, let digest, let sig, let sigLen else { return 1 }
    let signer = Unmanaged<CorePairing.Signer>.fromOpaque(ctx).takeUnretainedValue()
    guard let s = try? signer.sign(Data(bytes: digest, count: 32)), !s.isEmpty, s.count <= 72 else { return 1 }
    s.copyBytes(to: sig, count: s.count)
    sigLen.pointee = s.count
    return 0
}
