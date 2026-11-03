// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The manifest of a media event: images or files (docs/protocol.md,
/// section 4, "Media"), checked as Go's package clip does. The kit takes the
/// event and its plain-text alternative; fetching the content comes later.
public enum Media {
    /// The largest copy, all its parts together, that the group carries.
    public static let maxMedia: Int64 = 1 << 30
    public static let maxParts = 10_000
    public static let maxTypes = 8
    public static let maxPaths = 512 << 10
    public static let maxPath = 4096
    public static let maxName = 255
    /// The largest plain-text alternative of a media event, in bytes of UTF-8.
    public static let maxAltText = 256 << 10
    public static let types: Set<String> = ["image/png", "image/jpeg", "text/html"]

    /// What a media event's content is.
    public struct Manifest: Codable, Equatable, Sendable {
        public var size: Int64
        public var parts: [Part]

        public init(size: Int64, parts: [Part]) { (self.size, self.parts) = (size, parts) }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            size = try c.decodeIfPresent(Int64.self, forKey: .size) ?? 0
            parts = try c.decodeIfPresent([Part].self, forKey: .parts) ?? []
        }

        /// Whether it is a copy of files, not clipboard data.
        public var isFiles: Bool { parts.first?.path != nil }

        /// Whether it passes Go's Manifest.Validate.
        public var isValid: Bool {
            guard !parts.isEmpty, parts.count <= Media.maxParts else { return false }
            let files = isFiles
            if !files && parts.count > Media.maxTypes { return false }
            var total: Int64 = 0
            var paths = 0
            // Paths compare byte for byte, as the spec says, not as Swift
            // compares strings: two names in NFC and NFD are two paths. They
            // compare as a receiver writes them: two that savePath makes one
            // would land in one place.
            var seen = Set<[UInt8]>()
            for p in parts {
                let key: String
                if files {
                    guard let path = p.path, p.type == nil, Media.checkPath(path) else { return false }
                    paths += path.utf8.count
                    key = Media.savePath(path)
                } else {
                    guard let type = p.type, !p.dir, Media.types.contains(type) else { return false }
                    key = type
                }
                guard seen.insert(Array(key.utf8)).inserted else { return false }
                if p.dir {
                    if p.size != 0 || p.sha256 != nil { return false }
                    continue
                }
                guard p.sha256?.count == 32, p.size >= 0, p.size <= Media.maxMedia else { return false }
                total += p.size
            }
            guard paths <= Media.maxPaths, total == size, total <= Media.maxMedia else { return false }
            if files {
                // No file is inside another, by the paths as a receiver
                // writes them.
                let saved = parts.map { (Array(Media.savePath($0.path!).utf8), $0.dir) }
                var dirs: [[UInt8]: Bool] = [:]
                for (path, dir) in saved { dirs[path] = dir }
                for (path, _) in saved {
                    for (i, b) in path.enumerated() where b == 0x2F {
                        if dirs[Array(path[..<i])] == false { return false }
                    }
                }
            }
            return true
        }
    }

    /// One item of a manifest: clipboard data of a type, or a file or
    /// folder at a path.
    public struct Part: Codable, Equatable, Sendable {
        public var type: String?
        public var path: String?
        public var dir: Bool
        public var size: Int64
        public var sha256: Data?

        enum CodingKeys: String, CodingKey { case type, path, dir, size, sha256 }

        public init(type: String? = nil, path: String? = nil, dir: Bool = false, size: Int64 = 0, sha256: Data? = nil) {
            (self.type, self.path, self.dir, self.size, self.sha256) = (type, path, dir, size, sha256)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            type = try c.decodeIfPresent(String.self, forKey: .type).flatMap { $0.isEmpty ? nil : $0 }
            path = try c.decodeIfPresent(String.self, forKey: .path).flatMap { $0.isEmpty ? nil : $0 }
            dir = try c.decodeIfPresent(Bool.self, forKey: .dir) ?? false
            size = try c.decodeIfPresent(Int64.self, forKey: .size) ?? 0
            // An empty hash stays: a folder has none, as in Go, not even an empty one.
            sha256 = try c.decodeIfPresent(Data.self, forKey: .sha256)
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encodeIfPresent(type, forKey: .type)
            try c.encodeIfPresent(path, forKey: .path)
            if dir { try c.encode(true, forKey: .dir) }
            if size != 0 { try c.encode(size, forKey: .size) }
            try c.encodeIfPresent(sha256, forKey: .sha256)
        }
    }

    /// Whether path is names joined by "/", each one checkName takes, at
    /// most maxPath bytes as a receiver writes it (savePath).
    public static func checkPath(_ path: String) -> Bool {
        // Split on the byte "/": a "/" that a combining mark follows is one
        // Character for Swift but still a separator.
        !path.isEmpty && path.utf8.count <= maxPath && savePath(path).utf8.count <= maxPath
            && path.utf8.split(separator: 0x2F, omittingEmptySubsequences: false).allSatisfy { checkName(String(decoding: $0, as: UTF8.self)) }
    }

    /// Whether a name of a path is one every system can hold, as Go's
    /// clip.CheckName decides: 1 to 255 bytes, as a receiver writes it too
    /// (saveName), not "." or "..", no control
    /// characters, separators or characters Windows does not allow, no dot
    /// or space at the end, no name Windows reserves.
    public static func checkName(_ name: String) -> Bool {
        let n = name.utf8.count
        guard n > 0, n <= maxName, saveName(name).utf8.count <= maxName, name != ".", name != ".." else { return false }
        if name.unicodeScalars.contains(where: { "/\\:*?\"<>|".unicodeScalars.contains($0) || $0.value < 0x20 || (0x7f...0x9f).contains($0.value) }) {
            return false
        }
        if name.hasSuffix(".") || name.hasSuffix(" ") { return false }
        return !reserved(name)
    }

    /// Whether name, before its first dot, is a device name of Windows
    /// that a manifest may not hold: CON, PRN, AUX, NUL, COM1 to COM9 and
    /// LPT1 to LPT9, in any case of ASCII letters, as Go's clip.reserved.
    static func reserved(_ name: String) -> Bool {
        let base = upperASCII(baseBytes(name))
        if [Array("CON".utf8), Array("PRN".utf8), Array("AUX".utf8), Array("NUL".utf8)].contains(base) { return true }
        return base.count == 4 && (base.starts(with: "COM".utf8) || base.starts(with: "LPT".utf8)) && (0x31...0x39).contains(base[3])
    }

    /// Whether name is a device name of Windows, as Go's clip.device:
    /// before its first dot, and without the spaces that end that part, one
    /// of CON, PRN, AUX, NUL, CONIN$, CONOUT$, or COM or LPT followed by one
    /// digit 0 to 9 or one of the superscripts ¹, ² and ³, in any case of
    /// ASCII letters.
    static func device(_ name: String) -> Bool {
        var base = upperASCII(baseBytes(name))
        while base.last == 0x20 { base.removeLast() }
        if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].map({ Array($0.utf8) }).contains(base) { return true }
        guard base.starts(with: "COM".utf8) || base.starts(with: "LPT".utf8) else { return false }
        let n = Array(base.dropFirst(3))
        return (n.count == 1 && (0x30...0x39).contains(n[0])) || ["\u{B9}", "\u{B2}", "\u{B3}"].map({ Array($0.utf8) }).contains(n)
    }

    /// The name under which a receiver writes a name that checkName took,
    /// as Go's clip.SaveName: a device name of Windows gets "_" after its
    /// base, the part before its first dot, and any other name stays as it
    /// is.
    public static func saveName(_ name: String) -> String {
        device(name) ? withUnderscore(name) : name
    }

    /// saveName for each name of a path, as Go's clip.SavePath; split on
    /// the byte "/", as checkPath splits.
    public static func savePath(_ path: String) -> String {
        path.utf8.split(separator: 0x2F, omittingEmptySubsequences: false)
            .map { saveName(String(decoding: $0, as: UTF8.self)) }.joined(separator: "/")
    }

    /// The bytes of name before its first dot, the byte ".": a dot that a
    /// combining mark follows is one Character for Swift but still a dot.
    private static func baseBytes(_ name: String) -> [UInt8] {
        Array(name.utf8.prefix { $0 != 0x2E })
    }

    private static func upperASCII(_ b: [UInt8]) -> [UInt8] {
        b.map { (0x61...0x7A).contains($0) ? $0 - 0x20 : $0 }
    }

    /// Puts "_" after a name's base: CON.txt becomes CON_.txt, as Windows
    /// reserves the base with any extension.
    private static func withUnderscore(_ name: String) -> String {
        let b = Array(name.utf8)
        let base = baseBytes(name)
        let out: [UInt8] = base + [0x5F] + Array(b[base.count...])
        return String(decoding: out, as: UTF8.self)
    }

    /// A name that checkName takes, made of one a system gave, as Go's
    /// clip.CleanName: the characters it does not allow become "_", a
    /// device name of Windows gets "_" after its base and one that ends in
    /// a dot or a space gets "_" after it.
    public static func cleanName(_ given: String) -> String {
        var scalars = String.UnicodeScalarView()
        for u in given.unicodeScalars {
            let bad = u.value < 0x20 || (0x7f...0x9f).contains(u.value) || "/\\:*?\"<>|".unicodeScalars.contains(u)
            scalars.append(bad ? "_" : u)
        }
        // What fixName adds can take the name past maxName, so the name
        // loses characters at its end until the fixed name fits.
        while true {
            let name = String(scalars)
            if name.isEmpty || name == "." || name == ".." { return "_" }
            let fixed = fixName(name)
            if fixed.utf8.count <= maxName { return fixed }
            scalars.removeLast()
        }
    }

    /// Gives a device name of Windows "_" after its base and one that ends
    /// in a dot or a space "_" after it.
    private static func fixName(_ given: String) -> String {
        var name = given
        if device(name) { name = withUnderscore(name) }
        if name.hasSuffix(".") || name.hasSuffix(" ") { name += "_" }
        return name
    }
}
