// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// The images and files a member holds whole, which it serves to its peers
/// (docs/protocol.md, section 4, "Content"), as Go's node.Content.
public protocol ContentStore: Sendable {
    /// The part whose SHA-256 is sha256, or nil when this phone does not
    /// hold all of it. The node closes it.
    func open(sha256: Data) -> ContentSource?
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
/// parts it was given last, at most maxBytes together.
public final class MemoryContent: ContentStore, @unchecked Sendable {
    private let lock = NSLock()
    private var parts: [(sum: Data, bytes: Data)] = []
    private let maxBytes: Int64

    public init(maxBytes: Int64 = Media.maxMedia) { self.maxBytes = maxBytes }

    /// Keeps the bytes of a part, dropping the oldest beyond maxBytes; it
    /// returns its SHA-256.
    @discardableResult
    public func put(_ bytes: Data) -> Data {
        let sum = Data(SHA256.hash(data: bytes))
        lock.withLock {
            parts.removeAll { $0.sum == sum }
            parts.append((sum, bytes))
            var total = parts.reduce(Int64(0)) { $0 + Int64($1.bytes.count) }
            while total > maxBytes, parts.count > 1 {
                total -= Int64(parts.removeFirst().bytes.count)
            }
        }
        return sum
    }

    public func open(sha256: Data) -> ContentSource? {
        lock.withLock { parts.first { $0.sum == sha256 }.map { Bytes(data: $0.bytes) } }
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
        /// The part is over the receiver's limit.
        case tooLarge(size: Int64, limit: Int64)
        case noPeer, mismatch, folder
    }

    /// Fetches part of event from the connected members that serve
    /// content, its origin first, passing the pieces to sink after start,
    /// which begins each attempt, and checks its hash. It throws when no
    /// member has it whole, the part is over limit or does not match.
    public static func fetch(from node: MemberNode, event: Member.Event, part: Media.Part, limit: Int64 = Media.maxMedia,
                             start: () throws -> Void = {}, sink: (Data) throws -> Void) async throws {
        guard let sum = part.sha256 else { throw Failure.folder }
        guard part.size <= limit else { throw Failure.tooLarge(size: part.size, limit: limit) }
        let peers = await node.mediaPeers.sorted { $0 == event.origin && $1 != event.origin }
        guard !peers.isEmpty else { throw Failure.noPeer }
        var last: Error = Failure.noPeer
        for p in peers {
            var h = SHA256()
            do {
                try start()
                try await node.fetch(from: p, sha256: sum, size: part.size) { _, data in
                    h.update(data: data)
                    try sink(data)
                }
                if Data(h.finalize()) == sum { return }
                last = Failure.mismatch
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                last = error
            }
        }
        throw last
    }

    /// The bytes of part of event, as fetch gets them.
    public static func data(from node: MemberNode, event: Member.Event, part: Media.Part, limit: Int64 = Media.maxMedia) async throws -> Data {
        var d = Data()
        try await fetch(from: node, event: event, part: part, limit: limit, start: { d = Data() }, sink: { d.append($0) })
        return d
    }
}
