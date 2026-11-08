// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Crypto
import Foundation

/// A connection that a pairing runs on: the bytes the core sends go out
/// with send, and receive gives what arrived, empty once the peer closed.
public protocol CorePairingStream: AnyObject {
    func send(_ data: Data) async throws
    func receive() async throws -> Data
}

/// Pairing in the Rust core (docs/core-api.md, "Joining and admitting"): a
/// phone that makes a group (`newGroup`), joins one by its QR code as the
/// joiner that listens (`Joining`), or admits a device by the device's QR
/// code as an admin (`Admitting`). The core runs the exchange inside its own
/// TLS and asks for each signature through a callback, so the keys stay in
/// the keychain and the Secure Enclave; the app does the sockets and hands
/// each connection to these classes, which pass its bytes to the core until
/// the exchange ends.
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

    /// The connection closed before the exchange ended.
    public struct Closed: Error, CustomStringConvertible {
        public var description: String { "the connection closed during pairing" }
    }

    /// A group this phone is in, as the core made or joined it: its device
    /// ID, member certificate and the admin CA that issued it, the group
    /// CA, the later roots, the records file and, for a phone made an
    /// admin, its admin CA.
    public struct Group: Decodable, Equatable, Sendable {
        public var device: String
        public var cert: Data
        public var issuer: Data?
        public var groupCA: Data
        public var roots: [Data]
        public var records: Data
        public var adminCA: Data?

        enum CodingKeys: String, CodingKey { case device, cert, issuer, groupCA = "group_ca", roots, records, adminCA = "admin_ca" }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            device = try c.decode(String.self, forKey: .device)
            cert = try c.decode(Data.self, forKey: .cert)
            issuer = try c.decodeIfPresent(Data.self, forKey: .issuer)
            groupCA = try c.decode(Data.self, forKey: .groupCA)
            roots = try c.decodeIfPresent([Data].self, forKey: .roots) ?? []
            records = try c.decodeIfPresent(Data.self, forKey: .records) ?? Data()
            adminCA = try c.decodeIfPresent(Data.self, forKey: .adminCA)
        }
    }

    /// Makes a group with this phone's root key (cbb_group_new): its root
    /// CA, this phone's member certificate and its device record. rootPublic
    /// and publicKey are the root and member keys (SubjectPublicKeyInfo or
    /// point), store where the member key lives (Records.hardware or
    /// Records.file), seal the phone's public key for sealed messages;
    /// signRoot signs a digest with the root key, during this call only.
    public static func newGroup(name: String, os: String = "ios", store: String, rootPublic: Data, publicKey: Data, seal: Data?,
                                signRoot: @escaping (Data) throws -> Data) throws -> Group {
        struct Request: Encodable {
            var name: String, os: String, store: String, root_public: Data, `public`: Data, seal: Data?
        }
        let request = try JSONEncoder().encode(Request(name: name, os: os, store: store, root_public: try point(rootPublic),
                                                       public: try point(publicKey), seal: seal))
        let signer = Signer(signRoot)
        let raw = Unmanaged.passRetained(signer).toOpaque()
        defer { Unmanaged<Signer>.fromOpaque(raw).release() }
        var count = 0
        let answer: UnsafeMutablePointer<UInt8>? = request.withUnsafeBytes { r in
            cbb_group_new(r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, raw, &count)
        }
        return try ok("new group", take(answer, count), as: Group.self)
    }

    /// Runs one connection's exchange: sends what the core gives, reads
    /// what comes and hands it in, until feed says the exchange ended. A
    /// connection that closes before then throws Closed.
    private static func exchange(_ stream: CorePairingStream, first: Data, feed: (Data) throws -> (send: Data, done: Bool)) async throws {
        if !first.isEmpty { try await stream.send(first) }
        while true {
            let data = try await stream.receive()
            if data.isEmpty { throw Closed() }
            let (send, done) = try feed(data)
            if !send.isEmpty { try await stream.send(send) }
            if done { return }
        }
    }

    /// One step of an exchange as the core answers it.
    private struct Step: Decodable {
        var send: Data?
        var state: String?
        var wrongCode: Bool?
        var joined: Group?
        var device: Device?
        var confirmed: Bool?
        var error: Refused?

        enum CodingKeys: String, CodingKey { case send, state, wrongCode = "wrong_code", joined, device, confirmed, error }

        struct Device: Decodable {
            var device: String?, name: String?, os: String?, role: String?, admin: Bool?
        }

        /// The failure a failed step names.
        var failure: Failure {
            Failure(error?.message ?? "the pairing failed", details: error?.details, wrongCode: wrongCode ?? false)
        }
    }

    /// Joining a group as the joiner that listens (docs/protocol.md,
    /// section 6): makes the device ID, the code and the QR code for addrs,
    /// the addresses the app listens on, and takes each connection the app
    /// accepts with `attempt` until an admin admits this phone. With
    /// adminPublic and signAdmin the phone offers an admin key, whose proof
    /// the core signs on the connection.
    public final class Joining: @unchecked Sendable {
        private let handle: OpaquePointer
        private let signer: UnsafeMutableRawPointer
        private let adminSigner: UnsafeMutableRawPointer?
        private let lock = NSLock()
        private var closed = false

        /// This phone's device ID, the six-digit code, the certificate's
        /// fingerprint and the QR code's text.
        public let device: String
        public let code: String
        public let fingerprint: String
        public let qr: String

        public init(name: String, os: String = "ios", publicKey: Data, seal: Data?, addrs: [String], sign: @escaping (Data) throws -> Data,
                    adminPublic: Data? = nil, signAdmin: ((Data) throws -> Data)? = nil, code: String = "") throws {
            precondition((adminPublic == nil) == (signAdmin == nil), "the admin key needs both its public key and its signer")
            struct Request: Encodable {
                var name: String, os: String, `public`: Data, admin_public: Data?, seal: Data?, addrs: [String], code: String
            }
            struct Answer: Decodable { var device: String?, code: String?, fingerprint: String?, qr: String? }
            let request = try JSONEncoder().encode(Request(name: name, os: os, public: try point(publicKey),
                                                           admin_public: try adminPublic.map(point), seal: seal, addrs: addrs, code: code))
            let s = Unmanaged.passRetained(Signer(sign)).toOpaque()
            let a = signAdmin.map { Unmanaged.passRetained(Signer($0)).toOpaque() }
            var answer: UnsafeMutablePointer<UInt8>?
            var count = 0
            let h: OpaquePointer? = request.withUnsafeBytes { r in
                let p = r.bindMemory(to: UInt8.self).baseAddress
                if let a { return cbb_join_new_admin(p, r.count, corePairingSign, s, corePairingSign, a, &answer, &count) }
                return cbb_join_new(p, r.count, corePairingSign, s, &answer, &count)
            }
            let o: Answer
            do {
                guard let h else {
                    _ = try ok("join", take(answer, count), as: Answer.self)
                    throw Core.Mismatch(reason: "the core made no joiner")
                }
                handle = h
                o = try ok("join", take(answer, count), as: Answer.self)
            } catch {
                if let h { cbb_join_free(h) }
                Unmanaged<Signer>.fromOpaque(s).release()
                if let a { Unmanaged<Signer>.fromOpaque(a).release() }
                throw error
            }
            (signer, adminSigner) = (s, a)
            (device, self.code, fingerprint, qr) = (o.device ?? "", o.code ?? "", o.fingerprint ?? "", o.qr ?? "")
        }

        deinit { close() }

        /// Runs the exchange on a connection the app accepted. Returns the
        /// group when an admin admitted this phone, after save stored it
        /// (true when it did, which the core tells the admin); a failure
        /// throws Failure, with wrongCode for a wrong code, and a dropped
        /// connection Closed or the stream's error.
        public func attempt(_ stream: CorePairingStream, save: (Group) -> Bool) async throws -> Group {
            guard !lock.withLock({ closed }) else { throw Failure("the joiner is closed") }
            _ = try ok("join", call { cbb_join_accept(handle, &$0) }, as: Step.self)
            var joined: Group?
            var failed: Failure?
            try await exchange(stream, first: Data()) { data in
                let step = try data.withUnsafeBytes { r in
                    try ok("join", call { cbb_join_feed(handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, 0, &$0) }, as: Step.self)
                }
                let send = step.send ?? Data()
                switch step.state {
                case "joined":
                    guard let g = step.joined else { throw Core.Mismatch(reason: "the join has no group") }
                    let saved = save(g)
                    let last = try ok("join", call { cbb_join_finish(handle, saved ? 1 : 0, &$0) }, as: Step.self)
                    joined = saved ? g : nil
                    return (send + (last.send ?? Data()), true)
                case "failed":
                    // The refusal goes out first, so the admin hears why.
                    failed = step.failure
                    return (send, true)
                default:
                    return (send, false)
                }
            }
            if let failed { throw failed }
            guard let joined else { throw Failure("the group could not be saved") }
            return joined
        }

        public func close() {
            let first: Bool = lock.withLock {
                defer { closed = true }
                return !closed
            }
            guard first else { return }
            cbb_join_free(handle)
            Unmanaged<Signer>.fromOpaque(signer).release()
            if let adminSigner { Unmanaged<Signer>.fromOpaque(adminSigner).release() }
        }
    }

    /// A device the core admitted: its ID, name, system, role ("member" or
    /// "phone"), whether it became an admin, and whether it said it stored
    /// its identity.
    public struct Admitted: Equatable, Sendable {
        public var device: String
        public var name: String
        public var os: String
        public var role: String
        public var admin: Bool
        public var confirmed: Bool
    }

    /// Admitting a device by its QR code as an admin (docs/protocol.md,
    /// section 6, "The joiner listens"), through member, the phone's running
    /// member, whose records the device's record joins. publicKey is the key
    /// sign holds: the admin key with adminCA, or the root's key without;
    /// makeAdmin, for the root only, makes a phone that offers an admin key
    /// an admin. `addrs` are the QR code's addresses, which the app dials
    /// and hands to `admit` one at a time.
    public final class Admitting: @unchecked Sendable {
        private let handle: OpaquePointer
        private let signer: UnsafeMutableRawPointer
        /// The member stays running until the admission is freed.
        private let member: CoreMember
        private let lock = NSLock()
        private var closed = false

        /// The addresses of the QR code, host:port, in its order.
        public let addrs: [String]

        public init(member: CoreMember, qr: String, publicKey: Data, adminCA: Data?, makeAdmin: Bool, sign: @escaping (Data) throws -> Data) throws {
            struct Request: Encodable { var qr: String, `public`: Data, admin_ca: Data?, make_admin: Bool }
            struct Answer: Decodable { var addrs: [String]? }
            let request = try JSONEncoder().encode(Request(qr: qr, public: try point(publicKey), admin_ca: adminCA, make_admin: makeAdmin))
            let s = Unmanaged.passRetained(Signer(sign)).toOpaque()
            var answer: UnsafeMutablePointer<UInt8>?
            var count = 0
            let h: OpaquePointer? = request.withUnsafeBytes { r in
                cbb_admit_new(member.handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, corePairingSign, s, &answer, &count)
            }
            let o: Answer
            do {
                guard let h else {
                    _ = try ok("admit", take(answer, count), as: Answer.self)
                    throw Core.Mismatch(reason: "the core made no admission")
                }
                handle = h
                o = try ok("admit", take(answer, count), as: Answer.self)
            } catch {
                if let h { cbb_admit_free(h) }
                Unmanaged<Signer>.fromOpaque(s).release()
                throw error
            }
            (signer, self.member, addrs) = (s, member, o.addrs ?? [])
        }

        deinit { close() }

        /// Runs the exchange on a connection the app dialed to one of
        /// addrs. Returns the admitted device; a refusal throws Failure,
        /// with wrongCode for a wrong code, and a dropped connection Closed
        /// or the stream's error. Once the device is admitted its record is
        /// in the group, whatever the rest of the exchange does.
        public func admit(_ stream: CorePairingStream) async throws -> Admitted {
            guard !lock.withLock({ closed }) else { throw Failure("the admission is closed") }
            var device: Step.Device?
            var confirmed = false
            var failed: Failure?
            func step(_ o: Step) -> (send: Data, done: Bool) {
                let send = o.send ?? Data()
                switch o.state {
                case "admitted":
                    device = o.device
                    return (send, false)
                case "done":
                    confirmed = o.confirmed ?? false
                    return (send, true)
                case "failed":
                    // The device is in the group once admitted; only its answer is missing.
                    if device == nil { failed = o.failure }
                    return (send, true)
                default:
                    return (send, false)
                }
            }
            let (hello, ended) = step(try ok("admit", call { cbb_admit_dial(handle, &$0) }, as: Step.self))
            if !ended {
                try await exchange(stream, first: hello) { data in
                    step(try data.withUnsafeBytes { r in
                        try ok("admit", call { cbb_admit_feed(handle, r.bindMemory(to: UInt8.self).baseAddress, r.count, 0, &$0) }, as: Step.self)
                    })
                }
            }
            if let failed { throw failed }
            guard let d = device else { throw Failure("the device was not admitted") }
            return Admitted(device: d.device ?? "", name: d.name ?? "", os: d.os ?? "", role: d.role ?? "member", admin: d.admin ?? false,
                            confirmed: confirmed)
        }

        public func close() {
            let first: Bool = lock.withLock {
                defer { closed = true }
                return !closed
            }
            guard first else { return }
            cbb_admit_free(handle)
            Unmanaged<Signer>.fromOpaque(signer).release()
        }
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

#if canImport(Network)
import Network

extension CorePairing {
    /// A plain TCP connection for a pairing, whose TLS the core runs: one
    /// the phone dials to a device's address, or one a Listener accepted.
    public final class Connection: CorePairingStream, @unchecked Sendable {
        let connection: NWConnection
        private let queue = DispatchQueue(label: "cbb.pairing")

        /// Dials host:port; start connects, failing after timeout seconds.
        public init(host: String, port: UInt16, timeout: Int = 5) {
            let tcp = NWProtocolTCP.Options()
            tcp.connectionTimeout = timeout
            connection = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!),
                                      using: NWParameters(tls: nil, tcp: tcp))
        }

        init(accepted: NWConnection) { connection = accepted }

        /// Connects, or throws why it could not.
        public func start() async throws {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                let once = TLSTransport.Once()
                connection.stateUpdateHandler = { [weak self] state in
                    switch state {
                    case .ready:
                        if once.claim() { c.resume() }
                    case .failed(let e), .waiting(let e):
                        guard once.claim() else { return }
                        self?.connection.cancel()
                        c.resume(throwing: TLSTransport.failure(e))
                    case .cancelled:
                        if once.claim() { c.resume(throwing: TLSTransport.Failure.closed) }
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        }

        public func send(_ data: Data) async throws {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                connection.send(content: data, completion: .contentProcessed { e in
                    if let e { c.resume(throwing: e) } else { c.resume() }
                })
            }
        }

        public func receive() async throws -> Data {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, _, e in
                    if let data, !data.isEmpty {
                        c.resume(returning: data)
                    } else if let e {
                        c.resume(throwing: e)
                    } else {
                        // Closed: complete with nothing more to read.
                        c.resume(returning: Data())
                    }
                }
            }
        }

        public func close() { connection.cancel() }
    }

    /// Listens for the plain TCP connections of a pairing, as a phone does
    /// while it shows its join QR code; the core runs their TLS.
    public final class Listener: @unchecked Sendable {
        let listener: NWListener
        private let queue = DispatchQueue(label: "cbb.pairing.listener")
        private let connections: AsyncStream<Connection>
        private let yield: AsyncStream<Connection>.Continuation

        /// Listens on a port the system picks; only on the loopback address
        /// when loopback is true.
        public init(loopback: Bool = false) throws {
            let params = NWParameters.tcp
            params.includePeerToPeer = false
            if loopback { params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any) }
            listener = try NWListener(using: params)
            (connections, yield) = AsyncStream.makeStream(of: Connection.self)
        }

        /// Starts listening and returns the port once it is ready.
        public func start() async throws -> UInt16 {
            let yield = yield
            let queue = queue
            listener.newConnectionHandler = { c in
                c.start(queue: queue)
                yield.yield(Connection(accepted: c))
            }
            return try await withCheckedThrowingContinuation { (c: CheckedContinuation<UInt16, Error>) in
                let once = TLSTransport.Once()
                listener.stateUpdateHandler = { [weak self] state in
                    switch state {
                    case .ready:
                        guard once.claim() else { return }
                        c.resume(returning: self?.listener.port?.rawValue ?? 0)
                    case .failed(let e), .waiting(let e):
                        guard once.claim() else { return }
                        self?.listener.cancel()
                        c.resume(throwing: TLSTransport.Failure.notReady("\(e)"))
                    case .cancelled:
                        yield.finish()
                        guard once.claim() else { return }
                        c.resume(throwing: TLSTransport.Failure.closed)
                    default:
                        break
                    }
                }
                listener.start(queue: queue)
            }
        }

        /// The next connection a device made; nil once the listener stopped.
        public func next() async -> Connection? {
            var it = connections.makeAsyncIterator()
            return await it.next()
        }

        /// Publishes the listener by Bonjour under name with that TXT record,
        /// in the type of the members (docs/protocol.md, section 3), as a
        /// phone does while it waits to join, once it knows its device ID.
        public func advertise(name: String, txt: [String: String]) {
            listener.service = NWListener.Service(name: name, type: Discovery.serviceType, domain: nil,
                                                  txtRecord: NWTXTRecord(txt))
        }

        public func stop() { listener.cancel() }
    }
}
#endif
