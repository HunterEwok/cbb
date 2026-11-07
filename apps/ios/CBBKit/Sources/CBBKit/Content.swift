// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// The images and files a member holds whole, which it serves to its peers
/// (docs/protocol.md, section 4, "Content"), as Go's node.Content: only the
/// sealed blobs of copies, never the parts in the open.
public protocol ContentStore: Sendable {
    /// The blob whose SHA-256 is sha256, or nil when this phone does not
    /// hold all of it. The node closes it.
    func open(sha256: Data) -> ContentSource?
    /// Seals the parts of m, which the store holds, into the blob of a new
    /// copy under a new key, and keeps the blob to serve it; nil when m
    /// holds no bytes (docs/protocol.md, section 4, "The blob").
    func sealBlob(_ m: Media.Manifest) throws -> (key: Data, blob: Media.Blob)?
}

public extension ContentStore {
    func sealBlob(_ m: Media.Manifest) throws -> (key: Data, blob: Media.Blob)? {
        guard m.size == 0 else { throw Content.Failure.noParts }
        return nil
    }
}

/// One part a ContentStore opened.
public protocol ContentSource {
    var size: Int64 { get }
    /// Reads length bytes from offset, which are all there.
    func read(offset: Int64, length: Int) throws -> Data
    func close()
}

public extension ContentSource {
    func close() {}
}

/// A ContentStore in memory, for the phone's own copies: it keeps the
/// parts and the blobs it was given last, at most maxBytes together, twice
/// for the blob of each copy, and serves only the blobs.
public final class MemoryContent: ContentStore, @unchecked Sendable {
    private let lock = NSLock()
    private var parts: [(sum: Data, bytes: Data, blob: Bool)] = []
    private let maxBytes: Int64

    public init(maxBytes: Int64 = Media.maxMedia) { self.maxBytes = maxBytes }

    /// Keeps the bytes of a part, or of a sealed blob, dropping the oldest
    /// beyond twice maxBytes; it returns its SHA-256.
    @discardableResult
    public func put(_ bytes: Data, blob: Bool = false) -> Data {
        let sum = Data(SHA256.hash(data: bytes))
        lock.withLock {
            parts.removeAll { $0.sum == sum }
            parts.append((sum, bytes, blob))
            var total = parts.reduce(Int64(0)) { $0 + Int64($1.bytes.count) }
            while total > 2 * maxBytes, parts.count > 1 {
                total -= Int64(parts.removeFirst().bytes.count)
            }
        }
        return sum
    }

    /// The bytes of a part or a blob it keeps.
    public func bytes(sha256: Data) -> Data? { lock.withLock { parts.first { $0.sum == sha256 }?.bytes } }

    public func open(sha256: Data) -> ContentSource? {
        lock.withLock { parts.first { $0.sum == sha256 && $0.blob }.map { Bytes(data: $0.bytes) } }
    }

    public func sealBlob(_ m: Media.Manifest) throws -> (key: Data, blob: Media.Blob)? {
        guard m.size > 0 else { return nil }
        let data = try m.parts.filter { !$0.dir && $0.size > 0 }.map { p in
            guard let sum = p.sha256, let b = bytes(sha256: sum), Int64(b.count) == p.size else { throw Content.Failure.noParts }
            return b
        }
        let key = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
        let (blob, sealed) = try Media.sealBlob(key: key, parts: data)
        put(sealed, blob: true)
        return (key, blob)
    }

    struct Bytes: ContentSource {
        let data: Data
        var size: Int64 { Int64(data.count) }
        func read(offset: Int64, length: Int) throws -> Data {
            let start = data.startIndex + Int(offset)
            return data.subdata(in: start..<(start + length))
        }
    }
}

/// Fetching the content of media events from the connected members.
public enum Content {
    /// The manifest of clipboard data: one part per type, such as an image
    /// as "image/png" or "image/jpeg", whose bytes store keeps to serve
    /// them.
    public static func manifest(store: MemoryContent, data: [(type: String, bytes: Data)]) -> Media.Manifest {
        let parts = data.map { Media.Part(type: $0.type, size: Int64($0.bytes.count), sha256: store.put($0.bytes)) }
        return Media.Manifest(size: parts.reduce(0) { $0 + $1.size }, parts: parts)
    }

    /// The manifest of files the user shared, side by side without
    /// folders, whose bytes store keeps to serve them: each name made one
    /// every system takes (Media.cleanName), and a name taken already, in
    /// any case, given " (2)" and so on before its extension.
    public static func files(store: MemoryContent, files: [(name: String, bytes: Data)]) -> Media.Manifest {
        var taken = Set<String>()
        let parts = files.map { f -> Media.Part in
            let clean = Media.cleanName(f.name)
            var name = clean
            var n = 2
            while !taken.insert(name.lowercased()).inserted {
                let dot = clean.lastIndex(of: ".").flatMap { $0 > clean.startIndex ? $0 : nil } ?? clean.endIndex
                name = Media.cleanName(String(clean[..<dot]) + " (\(n))" + String(clean[dot...]))
                n += 1
            }
            return Media.Part(path: name, size: Int64(f.bytes.count), sha256: store.put(f.bytes))
        }
        return Media.Manifest(size: parts.reduce(0) { $0 + $1.size }, parts: parts)
    }

    public enum Failure: Error, Equatable {
        /// The copy is over the receiver's limit.
        case tooLarge(size: Int64, limit: Int64)
        case noPeer, mismatch, folder
        /// The copy is not sealed to this phone, or names no blob.
        case unread
        /// The store does not hold the parts of a copy to seal.
        case noParts
    }
}
