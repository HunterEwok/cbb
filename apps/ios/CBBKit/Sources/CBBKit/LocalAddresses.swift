// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// This device's addresses on the home network, for the join QR code a
/// phone shows (docs/protocol.md, section 6, "The joiner listens"): private
/// IPv4 addresses first, then unique local IPv6 ones, never loopback,
/// link-local or a cellular carrier's address, at most four.
public enum LocalAddresses {
    public static func current() -> [String] {
        #if canImport(Darwin)
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var v4: [String] = [], v6: [String] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = p.pointee.ifa_flags
            guard flags & UInt32(IFF_UP) != 0, flags & UInt32(IFF_LOOPBACK) == 0, let sa = p.pointee.ifa_addr else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                guard getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
                else { continue }
                let s = String(cString: host)
                if isHome(ipv4: s), !v4.contains(s) { v4.append(s) }
            case AF_INET6:
                guard getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in6>.size), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
                else { continue }
                let s = String(cString: host)
                if isHome(ipv6: s), !v6.contains(s) { v6.append(s) }
            default:
                continue
            }
        }
        return Array((v4 + v6).prefix(JoinCode.maxAddrs))
        #else
        return [] // only the phone shows a join QR code
        #endif
    }

    /// The IPv4 address of the interface named name, such as en0, and the
    /// length of its network's prefix, for the hub's home networks
    /// (HubState.networkKey); nil when it has none.
    public static func ipv4(interface name: String) -> (address: String, prefixLength: Int)? {
        #if canImport(Darwin)
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard String(cString: p.pointee.ifa_name) == name, let sa = p.pointee.ifa_addr, Int32(sa.pointee.sa_family) == AF_INET,
                  let mask = p.pointee.ifa_netmask else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }
            let bits = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr).nonzeroBitCount }
            return (String(cString: host), bits)
        }
        return nil
        #else
        return nil
        #endif
    }

    /// Whether an IPv4 address is a private one (RFC 1918).
    static func isHome(ipv4 s: String) -> Bool {
        let b = s.split(separator: ".").compactMap { UInt8($0) }
        guard b.count == 4 else { return false }
        return b[0] == 10 || (b[0] == 172 && (16...31).contains(b[1])) || (b[0] == 192 && b[1] == 168)
    }

    /// Whether an IPv6 address is a unique local one (fc00::/7), without a
    /// zone.
    static func isHome(ipv6 s: String) -> Bool {
        let l = s.lowercased()
        return !l.contains("%") && (l.hasPrefix("fc") || l.hasPrefix("fd"))
    }
}
