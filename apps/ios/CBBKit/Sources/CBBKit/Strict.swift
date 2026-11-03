// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The strict form of signed bodies (docs/protocol.md, section 1, "Signed
/// bodies"), which every member reads alike, as Go's checkStrict.
enum Strict {
    /// How deeply a signed body nests arrays and objects at most.
    static let maxDepth = 16

    struct Invalid: Error, Equatable { var reason: String }

    /// Checks that b is one JSON object in valid UTF-8; member names of 1 to
    /// 64 of a-z, 0-9 and _, without escapes, none twice in one object; no
    /// null; integers only, without fraction or exponent, in the range of
    /// Int64; a surrogate escape only as one half of a pair. Each name in
    /// required must be a member of the object.
    static func check(_ data: Data, required: [String]) throws {
        let b = [UInt8](data)
        guard validUTF8(b) else { throw Invalid(reason: "a signed body is not valid UTF-8") }
        var p = Parser(b: b)
        p.space()
        guard p.peek() == UInt8(ascii: "{") else { throw Invalid(reason: "a signed body is not a JSON object") }
        let names: Set<String>
        do {
            names = try p.object(depth: 0)
        } catch let e as Invalid {
            throw Invalid(reason: "a signed body: \(e.reason)")
        }
        p.space()
        guard p.i == b.count else { throw Invalid(reason: "a signed body has more after its object") }
        for n in required where !names.contains(n) { throw Invalid(reason: "a signed body has no \(n)") }
    }

    /// Whether data is a body that check takes.
    static func ok(_ data: Data, required: [String]) -> Bool { (try? check(data, required: required)) != nil }

    /// Whether every number in data, outside the strings, is an integer as
    /// check takes it. JSONDecoder reads "-0", "1.0" and "1e0" as integers,
    /// other readers do not, so every frame of the member protocol passes
    /// this first, members a reader does not know included, as in the other
    /// implementations. It only scans: whether data is JSON is for the
    /// decoder.
    static func integersOnly(_ data: Data) -> Bool {
        let b = [UInt8](data)
        var i = 0
        while i < b.count {
            let c = b[i]
            if c == UInt8(ascii: "\"") {
                i += 1
                while i < b.count, b[i] != UInt8(ascii: "\"") { i += b[i] == UInt8(ascii: "\\") ? 2 : 1 }
                i += 1
            } else if c == UInt8(ascii: "-") || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c) {
                var p = Parser(b: b)
                p.i = i
                guard (try? p.integer()) != nil else { return false }
                i = p.i
            } else {
                i += 1
            }
        }
        return true
    }

    /// Decodes s, standard base64 with padding, only when s is the one
    /// encoding of its bytes.
    static func base64(_ s: String) -> Data? {
        guard let d = Data(base64Encoded: s), d.base64EncodedString() == s else { return nil }
        return d
    }

    /// Whether b is UTF-8 by the Unicode standard (table 3-7): no overlong
    /// forms, no surrogates, nothing past U+10FFFF.
    static func validUTF8(_ b: [UInt8]) -> Bool {
        var i = 0
        func cont(_ k: Int, _ lo: UInt8 = 0x80, _ hi: UInt8 = 0xbf) -> Bool { k < b.count && b[k] >= lo && b[k] <= hi }
        while i < b.count {
            let c = b[i]
            switch c {
            case 0x00...0x7f: i += 1
            case 0xc2...0xdf where cont(i + 1): i += 2
            case 0xe0 where cont(i + 1, 0xa0) && cont(i + 2): i += 3
            case 0xe1...0xec where cont(i + 1) && cont(i + 2): i += 3
            case 0xee...0xef where cont(i + 1) && cont(i + 2): i += 3
            case 0xed where cont(i + 1, 0x80, 0x9f) && cont(i + 2): i += 3
            case 0xf0 where cont(i + 1, 0x90) && cont(i + 2) && cont(i + 3): i += 4
            case 0xf1...0xf3 where cont(i + 1) && cont(i + 2) && cont(i + 3): i += 4
            case 0xf4 where cont(i + 1, 0x80, 0x8f) && cont(i + 2) && cont(i + 3): i += 4
            default: return false
            }
        }
        return true
    }

    private struct Parser {
        let b: [UInt8]
        var i = 0

        func peek() -> UInt8? { i < b.count ? b[i] : nil }

        mutating func space() {
            while let c = peek(), c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d { i += 1 }
        }

        mutating func value(depth: Int) throws {
            space()
            guard let c = peek() else { throw Invalid(reason: "it ends early") }
            switch c {
            case UInt8(ascii: "{"), UInt8(ascii: "["):
                guard depth < Strict.maxDepth else { throw Invalid(reason: "it nests too deeply") }
                if c == UInt8(ascii: "{") { _ = try object(depth: depth + 1) } else { try array(depth: depth + 1) }
            case UInt8(ascii: "\""): try string()
            case UInt8(ascii: "t"): try literal("true")
            case UInt8(ascii: "f"): try literal("false")
            case UInt8(ascii: "n"): throw Invalid(reason: "it has a null")
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): try integer()
            default: throw Invalid(reason: "an unexpected character")
            }
        }

        mutating func object(depth: Int) throws -> Set<String> {
            i += 1 // {
            var names: Set<String> = []
            space()
            if peek() == UInt8(ascii: "}") {
                i += 1
                return names
            }
            while true {
                space()
                guard names.insert(try name()).inserted else { throw Invalid(reason: "a member is there twice") }
                space()
                guard peek() == UInt8(ascii: ":") else { throw Invalid(reason: "a member has no value") }
                i += 1
                try value(depth: depth)
                space()
                switch peek() {
                case UInt8(ascii: ","): i += 1
                case UInt8(ascii: "}"):
                    i += 1
                    return names
                case nil: throw Invalid(reason: "it ends early")
                default: throw Invalid(reason: "an unexpected character in an object")
                }
            }
        }

        /// A member name: 1 to 64 of a-z, 0-9 and _ in quotes.
        mutating func name() throws -> String {
            guard peek() == UInt8(ascii: "\"") else { throw Invalid(reason: "a member has no name") }
            i += 1
            let start = i
            while true {
                guard let c = peek() else { throw Invalid(reason: "it ends early") }
                if c == UInt8(ascii: "\"") { break }
                guard (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(c) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c) || c == UInt8(ascii: "_") else {
                    throw Invalid(reason: "a member name is not of a-z, 0-9 and _")
                }
                i += 1
            }
            let name = String(decoding: b[start..<i], as: UTF8.self)
            i += 1
            guard !name.isEmpty, name.utf8.count <= 64 else { throw Invalid(reason: "a member name is not 1 to 64 characters") }
            return name
        }

        mutating func array(depth: Int) throws {
            i += 1 // [
            space()
            if peek() == UInt8(ascii: "]") {
                i += 1
                return
            }
            while true {
                try value(depth: depth)
                space()
                switch peek() {
                case UInt8(ascii: ","): i += 1
                case UInt8(ascii: "]"):
                    i += 1
                    return
                case nil: throw Invalid(reason: "it ends early")
                default: throw Invalid(reason: "an unexpected character in an array")
                }
            }
        }

        mutating func string() throws {
            i += 1 // "
            while true {
                guard let c = peek() else { throw Invalid(reason: "it ends early") }
                if c == UInt8(ascii: "\"") {
                    i += 1
                    return
                }
                guard c >= 0x20 else { throw Invalid(reason: "a string holds a control character") }
                i += 1
                guard c == UInt8(ascii: "\\") else { continue }
                guard let e = peek() else { throw Invalid(reason: "it ends early") }
                switch e {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"), UInt8(ascii: "b"), UInt8(ascii: "f"),
                     UInt8(ascii: "n"), UInt8(ascii: "r"), UInt8(ascii: "t"):
                    i += 1
                case UInt8(ascii: "u"):
                    let r = try hex4()
                    if (0xd800..<0xdc00).contains(r) {
                        guard i + 1 < b.count, b[i] == UInt8(ascii: "\\"), b[i + 1] == UInt8(ascii: "u") else {
                            throw Invalid(reason: "a string has half a surrogate pair")
                        }
                        i += 1
                        guard (0xdc00...0xdfff).contains(try hex4()) else { throw Invalid(reason: "a string has half a surrogate pair") }
                    } else if (0xdc00...0xdfff).contains(r) {
                        throw Invalid(reason: "a string has half a surrogate pair")
                    }
                default: throw Invalid(reason: "a string has an unknown escape")
                }
            }
        }

        /// The u and four hex digits of an escape.
        mutating func hex4() throws -> Int {
            guard i + 5 <= b.count else { throw Invalid(reason: "it ends early") }
            var v = 0
            for k in i + 1..<i + 5 {
                guard let d = Int(String(UnicodeScalar(b[k])), radix: 16) else { throw Invalid(reason: "a string has a wrong escape") }
                v = v * 16 + d
            }
            i += 5
            return v
        }

        mutating func literal(_ s: String) throws {
            let l = Array(s.utf8)
            guard i + l.count <= b.count, Array(b[i..<i + l.count]) == l else { throw Invalid(reason: "an unknown literal") }
            i += l.count
        }

        /// -?[1-9][0-9]*|0, in the range of Int64; "-0" is refused.
        mutating func integer() throws {
            let start = i
            if peek() == UInt8(ascii: "-") { i += 1 }
            let digits = i
            while let c = peek(), (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c) { i += 1 }
            guard i > digits else { throw Invalid(reason: "a number has no digits") }
            guard !(b[digits] == UInt8(ascii: "0") && i > digits + 1) else { throw Invalid(reason: "a number has a leading zero") }
            guard !(b[digits] == UInt8(ascii: "0") && digits > start) else { throw Invalid(reason: "a number is a negative zero") }
            if let c = peek(), c == UInt8(ascii: ".") || c == UInt8(ascii: "e") || c == UInt8(ascii: "E") {
                throw Invalid(reason: "a number is not an integer")
            }
            guard Int64(String(decoding: b[start..<i], as: UTF8.self)) != nil else { throw Invalid(reason: "a number is out of range") }
        }
    }
}
