// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The few DER encodings an X.509 certificate needs.
enum DER {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.insert(UInt8(v & 0xff), at: 0)
            v >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func sequence(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x30, parts.flatMap { $0 }) }
    static func set(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x31, parts.flatMap { $0 }) }
    static func bool(_ v: Bool) -> [UInt8] { tlv(0x01, [v ? 0xff : 0x00]) }
    static func octetString(_ v: [UInt8]) -> [UInt8] { tlv(0x04, v) }
    static func utf8String(_ s: String) -> [UInt8] { tlv(0x0c, Array(s.utf8)) }
    /// A context-specific tag: constructed (explicit) or primitive (implicit).
    static func context(_ n: UInt8, constructed: Bool, _ content: [UInt8]) -> [UInt8] {
        tlv((constructed ? 0xa0 : 0x80) | n, content)
    }

    /// A BIT STRING with the given number of unused bits in its last byte.
    static func bitString(_ bytes: [UInt8], unused: UInt8 = 0) -> [UInt8] { tlv(0x03, [unused] + bytes) }

    /// A non-negative INTEGER from big-endian bytes, in its minimal form.
    static func integer(unsigned bytes: [UInt8]) -> [UInt8] {
        var b = Array(bytes.drop { $0 == 0 })
        if b.isEmpty { b = [0] }
        if b[0] & 0x80 != 0 { b.insert(0, at: 0) }
        return tlv(0x02, b)
    }

    static func integer(_ v: Int) -> [UInt8] {
        precondition(v >= 0)
        var bytes: [UInt8] = []
        var x = v
        repeat {
            bytes.insert(UInt8(x & 0xff), at: 0)
            x >>= 8
        } while x > 0
        return integer(unsigned: bytes)
    }

    /// An OBJECT IDENTIFIER from its dotted form.
    static func oid(_ dotted: String) -> [UInt8] {
        let arcs = dotted.split(separator: ".").map { UInt64($0)! }
        var out: [UInt8] = [UInt8(arcs[0] * 40 + arcs[1])]
        for arc in arcs.dropFirst(2) {
            var chunk: [UInt8] = [UInt8(arc & 0x7f)]
            var v = arc >> 7
            while v > 0 {
                chunk.insert(UInt8(v & 0x7f) | 0x80, at: 0)
                v >>= 7
            }
            out += chunk
        }
        return tlv(0x06, out)
    }

    /// UTCTime for the years 1950 to 2049, GeneralizedTime otherwise, as
    /// RFC 5280 requires.
    static func time(_ d: Date) -> [UInt8] {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let c = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: d)
        let year = c.year!
        let rest = String(format: "%02d%02d%02d%02d%02dZ", c.month!, c.day!, c.hour!, c.minute!, c.second!)
        if (1950..<2050).contains(year) {
            return tlv(0x17, Array((String(format: "%02d", year % 100) + rest).utf8))
        }
        return tlv(0x18, Array((String(format: "%04d", year) + rest).utf8))
    }
}
