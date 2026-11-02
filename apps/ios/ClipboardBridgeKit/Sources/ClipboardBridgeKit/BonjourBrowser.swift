// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import Foundation
import Network
import Security

/// Browses for the Linux members with Network.framework: the services of
/// type _clipboardbridge._tcp in local., with their TXT records. The app's
/// Info.plist must list the type under NSBonjourServices and explain the use
/// in NSLocalNetworkUsageDescription.
public final class BonjourBrowser: @unchecked Sendable {
    let queue = DispatchQueue(label: "clipboardbridge.browse")
    private let lock = NSLock()
    private let onChange: @Sendable (Set<FoundMember>) -> Void
    private let log: @Sendable (String) -> Void
    private var browser: NWBrowser?
    private var endpoints: [String: NWEndpoint] = [:]
    private var running = false
    private var retry: TimeInterval = BonjourBrowser.firstRetry

    /// The first and the longest wait before browsing starts again after
    /// the system stopped it.
    static let firstRetry: TimeInterval = 1
    static let maxRetry: TimeInterval = 30

    /// onChange gets the members found now, after every change; log gets
    /// the browser's states other than ready.
    public init(log: @escaping @Sendable (String) -> Void = { _ in }, onChange: @escaping @Sendable (Set<FoundMember>) -> Void) {
        (self.onChange, self.log) = (onChange, log)
    }

    /// Starts browsing. Until the user allows the local network, iOS keeps
    /// the browser waiting (PolicyDenied) and does not always let it go on
    /// once they allow it, as on the first launch, where the question comes
    /// while the app already browses; so a browser that waits or fails is
    /// replaced by a new one, after 1 s, doubling to 30 s.
    public func start() {
        lock.withLock { running = true }
        queue.async { self.begin() }
    }

    public func stop() {
        let b: NWBrowser? = lock.withLock {
            running = false
            defer { browser = nil }
            return browser
        }
        b?.cancel()
    }

    /// Browses again at once, as when the app comes back to the front
    /// without a member found.
    public func restart() {
        guard lock.withLock({ running }) else { return }
        queue.async {
            self.lock.withLock { self.retry = Self.firstRetry }
            self.begin()
        }
    }

    /// Replaces the browser with a new one; on the queue.
    private func begin() {
        let old: NWBrowser? = lock.withLock { running ? browser : nil }
        old?.cancel()
        guard lock.withLock({ running }) else { return }
        let params = NWParameters()
        params.includePeerToPeer = false
        let b = NWBrowser(for: .bonjourWithTXTRecord(type: Discovery.serviceType, domain: "local."), using: params)
        b.browseResultsChangedHandler = { [weak self, weak b] results, _ in
            guard let self, let b, self.lock.withLock({ self.browser === b }) else { return }
            var found = Set<FoundMember>()
            var eps: [String: NWEndpoint] = [:]
            for r in results {
                guard case let .service(name, _, _, _) = r.endpoint else { continue }
                var txt: [String: String] = [:]
                if case let .bonjour(record) = r.metadata { txt = record.dictionary }
                if let m = Discovery.member(instance: name, txt: txt) {
                    found.insert(m)
                    eps[m.device] = r.endpoint
                }
            }
            self.lock.withLock { self.endpoints = eps }
            self.onChange(found)
        }
        b.stateUpdateHandler = { [weak self, weak b] state in
            guard let self, let b, self.lock.withLock({ self.browser === b }) else { return }
            switch state {
            case .ready:
                self.lock.withLock { self.retry = Self.firstRetry }
            case .waiting(let e), .failed(let e):
                self.log("browsing stopped (\(e)); browsing again")
                let wait: TimeInterval = self.lock.withLock {
                    defer { self.retry = min(self.retry * 2, Self.maxRetry) }
                    return self.retry
                }
                self.queue.asyncAfter(deadline: .now() + wait) { [weak self, weak b] in
                    guard let self, let b, self.lock.withLock({ self.browser === b }) else { return }
                    self.begin()
                }
            default:
                break
            }
        }
        lock.withLock { browser = b }
        b.start(queue: queue)
    }

    /// The endpoint of a found member, to dial.
    public func endpoint(of device: String) -> NWEndpoint? { lock.withLock { endpoints[device] } }

    /// A dial function for MemberDialer: TLS 1.3 to the member's endpoint
    /// with the member ALPN protocol and this phone's identity, followed by
    /// chain (the admin CA that issued its certificate, if one did),
    /// accepting only that device's certificate from one of roots, the
    /// group's roots (docs/protocol.md, section 10, "Roots"). A member
    /// browsing does not find is dialed at the addresses known gives for
    /// it, one after another.
    public func dialer(identity: SecIdentity, chain: [Data] = [], roots: [Data],
                       known: @escaping @Sendable (String) -> [String] = { _ in [] }) -> MemberDialer.Dial {
        { [weak self] m in
            let eps = self?.endpoint(of: m.device).map { [$0] } ?? JoinCode.ordered(known(m.device)).compactMap { a -> NWEndpoint? in
                guard let (host, port) = JoinCode.split(a), let p = NWEndpoint.Port(rawValue: port) else { return nil }
                return .hostPort(host: NWEndpoint.Host(host), port: p)
            }
            var failure: Error = TLSTransport.Failure.notReady("not found")
            for ep in eps {
                let t = TLSTransport(endpoint: ep, alpn: Member.alpn, identity: identity, chain: chain) { chain in
                    (try? GroupCertificates.verifyMember(chain: chain, roots: roots, now: Date())) == m.device
                }
                do {
                    try await t.start()
                    return t
                } catch {
                    t.close()
                    failure = error
                }
            }
            throw failure
        }
    }
}
#endif
