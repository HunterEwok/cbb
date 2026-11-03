// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// A TLS 1.3 connection with Network.framework that carries frames: pairing
/// with a listening device, member connections, and a pairing connection
/// that TLSListener accepted.
public final class TLSTransport: ClosableTransport, @unchecked Sendable {
    public enum Failure: Error { case notReady(String), closed, peerRejected, timedOut }

    /// How long dialling takes at most before TCP gives up, and the whole
    /// handshake before start does: a peer that drops the packets, or
    /// accepts and never answers, fails then instead of hanging.
    public static let connectTimeout = 5
    public static let handshakeTimeout: TimeInterval = 10

    let connection: NWConnection
    let queue = DispatchQueue(label: "cbb.tls")
    /// The ALPN protocol the handshake must agree on; nil only for tests'
    /// own parameters.
    let alpn: String?
    /// The peer's certificate chain, DER, leaf first, once the handshake is
    /// done.
    public private(set) var peerChain: [Data] = []
    /// The peer's leaf certificate, DER, once the handshake is done.
    public var peerCertificate: Data? { peerChain.first }

    /// Dials host:port with TLS 1.3 and the ALPN protocol, presenting
    /// identity, followed by chain (DER, such as the admin CA that issued
    /// it). verify gets the peer's leaf certificate (DER) and decides
    /// whether to trust it: for pairing, against the QR code's fingerprint.
    public convenience init(host: String, port: UInt16, alpn: String, identity: SecIdentity, chain: [Data] = [],
                            verify: @escaping @Sendable (Data) -> Bool) {
        self.init(endpoint: .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!),
                  alpn: alpn, identity: identity, chain: chain, verifyChain: { verify($0[0]) })
    }

    /// Dials an endpoint, such as a service that BonjourBrowser found, the
    /// same way; verifyChain gets the peer's whole chain (DER, leaf first,
    /// never empty), for a leaf that an admin CA issued.
    public init(endpoint: NWEndpoint, alpn: String, identity: SecIdentity, chain: [Data] = [],
                verifyChain: @escaping @Sendable ([Data]) -> Bool) {
        let tls = Self.options(alpn: alpn, identity: identity, chain: chain, verifyChain: verifyChain)
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = Self.connectTimeout
        connection = NWConnection(to: endpoint, using: NWParameters(tls: tls, tcp: tcp))
        self.alpn = alpn
    }

    /// A connection a TLSListener with the ALPN protocol alpn accepted;
    /// start runs its handshake.
    init(accepted: NWConnection, alpn: String) { (connection, self.alpn) = (accepted, alpn) }

    /// A connection with parameters of its own, for tests.
    init(endpoint: NWEndpoint, parameters: NWParameters) {
        connection = NWConnection(to: endpoint, using: parameters)
        alpn = nil
    }

    /// TLS 1.3 options with the ALPN protocol and identity, presenting
    /// chain after the identity's certificate, and verifyChain deciding on
    /// the peer's chain; a server requires the client's certificate.
    static func options(alpn: String, identity: SecIdentity, chain: [Data], server: Bool = false,
                        verifyChain: @escaping @Sendable ([Data]) -> Bool) -> NWProtocolTLS.Options {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(sec, alpn)
        // No session resumes without the peer's certificate (docs/protocol.md,
        // section 4, "TLS"): no tickets, no resumption.
        sec_protocol_options_set_tls_tickets_enabled(sec, false)
        sec_protocol_options_set_tls_resumption_enabled(sec, false)
        var leaf: SecCertificate?
        SecIdentityCopyCertificate(identity, &leaf)
        let extra = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let id = leaf != nil && !extra.isEmpty
            ? sec_identity_create_with_certificates(identity, ([leaf!] + extra) as CFArray)
            : sec_identity_create(identity)
        if let id { sec_protocol_options_set_local_identity(sec, id) }
        if server { sec_protocol_options_set_peer_authentication_required(sec, true) }
        sec_protocol_options_set_verify_block(sec, { _, trust, complete in
            let t = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(t) as? [SecCertificate], !chain.isEmpty else {
                complete(false)
                return
            }
            complete(verifyChain(chain.map { SecCertificateCopyData($0) as Data }))
        }, DispatchQueue(label: "cbb.tls.verify"))
        return tls
    }

    /// Starts the connection and waits for the handshake, at most timeout
    /// seconds (Failure.timedOut); cancelling the task cancels it.
    public func start(timeout: TimeInterval = TLSTransport.handshakeTimeout) async throws {
        try Task.checkCancellation()
        let once = Once()
        try await withTaskCancellationHandler {
            try await handshake(once: once, timeout: timeout)
        } onCancel: {
            connection.cancel()
        }
    }

    private func handshake(once: Once, timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard once.claim() else { return }
                self?.connection.cancel()
                c.resume(throwing: Failure.timedOut)
            }
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    guard once.claim() else { return }
                    guard let self else { return c.resume(throwing: Failure.closed) }
                    // Both sides check the protocol agreed on: a peer that
                    // offers none ends the handshake without one.
                    if let alpn = self.alpn, self.negotiatedProtocol != alpn {
                        self.connection.cancel()
                        return c.resume(throwing: Failure.notReady("the peer did not agree on the protocol \(alpn)"))
                    }
                    self.peerChain = self.certificateChain()
                    c.resume()
                case .failed(let e), .waiting(let e):
                    guard once.claim() else { return }
                    self?.connection.cancel()
                    c.resume(throwing: Self.failure(e))
                case .cancelled:
                    guard once.claim() else { return }
                    c.resume(throwing: Failure.closed)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    /// timedOut for a peer that did not answer, notReady with the error
    /// otherwise.
    static func failure(_ e: NWError) -> Failure {
        if case .posix(.ETIMEDOUT) = e { return .timedOut }
        return .notReady("\(e)")
    }

    /// Lets the first of several callbacks through.
    final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func claim() -> Bool {
            lock.withLock {
                defer { done = true }
                return !done
            }
        }
    }

    public func close() { connection.cancel() }

    /// The peer's port, as an accepted connection names its client: on the
    /// loopback address it tells whose connection a relay call is.
    public var remotePort: UInt16? {
        guard case .hostPort(_, let port) = connection.endpoint else { return nil }
        return port.rawValue
    }

    var tlsMetadata: sec_protocol_metadata_t? {
        (connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata)?.securityProtocolMetadata
    }

    /// The ALPN protocol the handshake agreed on, nil when none.
    var negotiatedProtocol: String? {
        guard let meta = tlsMetadata, let p = sec_protocol_metadata_get_negotiated_protocol(meta) else { return nil }
        return String(cString: p)
    }

    func certificateChain() -> [Data] {
        guard let meta = tlsMetadata else { return [] }
        var chain: [Data] = []
        sec_protocol_metadata_access_peer_certificate_chain(meta) { cert in
            chain.append(SecCertificateCopyData(sec_certificate_copy_ref(cert).takeRetainedValue()) as Data)
        }
        return chain
    }

    /// The TLS exporter's output for label with an empty context, as Go's
    /// ExportKeyingMaterial(label, nil, length) gives it.
    public func exportKeyingMaterial(label: String, length: Int) -> [UInt8]? {
        guard let meta = tlsMetadata,
              let secret = sec_protocol_metadata_create_secret(meta, label.utf8.count, label, length) else { return nil }
        return Array(secret as DispatchData)
    }

    public func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { e in
                if let e { c.resume(throwing: e) } else { c.resume() }
            })
        }
    }

    public func read(exactly n: Int) async throws -> Data {
        if n == 0 { return Data() }
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: n, maximumLength: n) { data, _, complete, e in
                if let e {
                    c.resume(throwing: e)
                } else if let data, data.count == n {
                    c.resume(returning: data)
                } else {
                    c.resume(throwing: complete ? Failure.closed : Failure.notReady("short read"))
                }
            }
        }
    }
}
/// Listens for TLS 1.3 connections, as a phone does while it shows its
/// join QR code (docs/protocol.md, section 6, "The joiner listens") and
/// while it is the group's hub (MemberListener). It requires a client
/// certificate and lets verifyChain decide on it.
public final class TLSListener: @unchecked Sendable {
    let listener: NWListener
    let queue = DispatchQueue(label: "cbb.tls.listener")
    let alpn: String
    private let connections: AsyncStream<TLSTransport>
    private let yield: AsyncStream<TLSTransport>.Continuation

    /// Listens on port, or on one the system picks when it is 0; only on
    /// the loopback address when loopback is true. chain is what follows
    /// the identity's certificate, as TLSTransport takes it. With service it
    /// publishes itself by Bonjour under that name with that TXT record, in
    /// the type of the members (docs/protocol.md, section 3).
    public init(port: UInt16 = 0, alpn: String, identity: SecIdentity, chain: [Data] = [], loopback: Bool = false,
                service: (name: String, txt: [String: String])? = nil,
                verifyChain: @escaping @Sendable ([Data]) -> Bool) throws {
        self.alpn = alpn
        let tls = TLSTransport.options(alpn: alpn, identity: identity, chain: chain, server: true, verifyChain: verifyChain)
        let params = NWParameters(tls: tls)
        params.includePeerToPeer = false
        if loopback {
            params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: port == 0 ? .any : NWEndpoint.Port(rawValue: port)!)
        }
        listener = try port == 0 ? NWListener(using: params) : NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
        if let service {
            listener.service = NWListener.Service(name: service.name, type: Discovery.serviceType, domain: nil,
                                                  txtRecord: NWTXTRecord(service.txt))
        }
        (connections, yield) = AsyncStream.makeStream(of: TLSTransport.self)
    }

    /// Starts listening and returns the port once it is ready.
    public func start() async throws -> UInt16 {
        let yield = yield
        let alpn = alpn
        listener.newConnectionHandler = { yield.yield(TLSTransport(accepted: $0, alpn: alpn)) }
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

    /// The next connection a device made, its handshake not yet run; nil
    /// once the listener stopped.
    public func next() async -> TLSTransport? {
        var it = connections.makeAsyncIterator()
        return await it.next()
    }

    public func stop() { listener.cancel() }
}
#endif
