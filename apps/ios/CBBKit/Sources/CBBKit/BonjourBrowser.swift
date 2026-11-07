// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
import dnssd
import Foundation
import Network

/// Browses for the Linux members with Network.framework: the services of
/// type _cbb._tcp in local., with their TXT records. The app's
/// Info.plist must list the type under NSBonjourServices and explain the use
/// in NSLocalNetworkUsageDescription.
public final class BonjourBrowser: @unchecked Sendable {
    let queue = DispatchQueue(label: "cbb.browse")
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

    /// The addresses of a found member, host:port with numeric hosts, IPv4
    /// first, as the core's member dials them; empty when it cannot be
    /// resolved within timeout.
    public func addresses(of device: String, timeout: TimeInterval = 3) async -> [String] {
        guard case let .service(name, type, domain, _)? = endpoint(of: device) else { return [] }
        return await Task.detached { Self.resolve(name: name, type: type, domain: domain, timeout: timeout) }.value
    }

    /// Resolves a DNS-SD service instance to its host and port, then the
    /// host to its addresses: IPv4 first, then IPv6 that is not link-local.
    static func resolve(name: String, type: String, domain: String, timeout: TimeInterval) -> [String] {
        final class Box { var host: String?, port: UInt16 = 0 }
        let box = Box()
        var ref: DNSServiceRef?
        let ctx = Unmanaged.passUnretained(box).toOpaque()
        let err = DNSServiceResolve(&ref, 0, 0, name, type, domain.isEmpty ? "local." : domain, { _, _, _, code, _, host, port, _, _, ctx in
            guard code == kDNSServiceErr_NoError, let host, let ctx else { return }
            let b = Unmanaged<Box>.fromOpaque(ctx).takeUnretainedValue()
            (b.host, b.port) = (String(cString: host), UInt16(bigEndian: port))
        }, ctx)
        guard err == kDNSServiceErr_NoError, let ref else { return [] }
        defer { DNSServiceRefDeallocate(ref) }
        let fd = DNSServiceRefSockFD(ref)
        let deadline = Date().addingTimeInterval(timeout)
        while box.host == nil {
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { return [] }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, Int32(left * 1000)) > 0, DNSServiceProcessResult(ref) == kDNSServiceErr_NoError else { return [] }
        }
        guard let host = box.host else { return [] }
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(box.port), &hints, &list) == 0, let first = list else { return [] }
        defer { freeaddrinfo(first) }
        var v4: [String] = [], v6: [String] = []
        var next: UnsafeMutablePointer<addrinfo>? = first
        while let ai = next {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: buf)
                if ai.pointee.ai_family == AF_INET {
                    v4.append("\(ip):\(box.port)")
                } else if ai.pointee.ai_family == AF_INET6, !ip.contains("%"), !ip.lowercased().hasPrefix("fe80") {
                    v6.append("[\(ip)]:\(box.port)")
                }
            }
            next = ai.pointee.ai_next
        }
        var seen = Set<String>()
        return (v4 + v6).filter { seen.insert($0).inserted }
    }
}
#endif
