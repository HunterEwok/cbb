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

    /// Whether an IPv4 address is a private one (RFC 1918). Only an address
    /// in its one spelling is judged (`octets`).
    static func isHome(ipv4 s: String) -> Bool {
        guard let b = octets(s) else { return false }
        return b[0] == 10 || (b[0] == 172 && (16...31).contains(b[1])) || (b[0] == 192 && b[1] == 168)
    }

    /// Whether an IPv6 address is a unique local one (fc00::/7), without a
    /// zone. The text is read as an address first (`bytes(ipv6:)`); an
    /// IPv4 address written as IPv6 (::ffff:a.b.c.d) is not one of these, as
    /// the format's `addr` has no such spelling.
    static func isHome(ipv6 s: String) -> Bool {
        guard let b = bytes(ipv6: s) else { return false }
        return b[0] & 0xfe == 0xfc
    }

    /// The four numbers of an IPv4 address in its one spelling: four parts
    /// of one to three decimal digits, none above 255, without a sign or a
    /// leading zero. Nil for a name and for every other spelling.
    static func octets(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for p in parts {
            let u = Array(p.utf8)
            guard (1...3).contains(u.count), u.allSatisfy({ (0x30...0x39).contains($0) }), u.count == 1 || u[0] != 0x30,
                  let b = UInt8(p) else { return nil }
            out.append(b)
        }
        return out
    }

    /// The 16 bytes of an IPv6 address written as text (RFC 4291: groups of
    /// one to four hex digits, "::" once at most, an IPv4 tail), without a
    /// zone. Nil for a name and for anything else.
    static func bytes(ipv6 s: String) -> [UInt8]? {
        guard !s.isEmpty, s.utf8.count <= 45 else { return nil }
        let halves = s.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ t: String, last: Bool) -> [UInt8]? {
            if t.isEmpty { return [] }
            var out: [UInt8] = []
            let parts = t.split(separator: ":", omittingEmptySubsequences: false)
            for (i, p) in parts.enumerated() {
                if last, i == parts.count - 1, p.contains(".") {
                    guard let v4 = octets(String(p)) else { return nil }
                    out += v4
                    continue
                }
                let u = Array(p.utf8)
                let hex = u.allSatisfy { (0x30...0x39).contains($0) || (0x41...0x46).contains($0) || (0x61...0x66).contains($0) }
                guard (1...4).contains(u.count), hex, let g = UInt16(p, radix: 16) else { return nil }
                out += [UInt8(g >> 8), UInt8(g & 0xff)]
            }
            return out
        }
        if halves.count == 1 {
            guard let all = groups(halves[0], last: true), all.count == 16 else { return nil }
            return all
        }
        guard let head = groups(halves[0], last: false), let tail = groups(halves[1], last: true),
              head.count + tail.count <= 14 else { return nil }
        return head + [UInt8](repeating: 0, count: 16 - head.count - tail.count) + tail
    }
}
