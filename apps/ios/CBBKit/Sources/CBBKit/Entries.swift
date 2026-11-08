// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The newest signed entry points this phone holds (docs/protocol.md,
/// section 16, "Entry points"), kept in a file: the computers of the group
/// send them after the hello, the phone's member in the core keeps them
/// there (reload reads them again), and the phone's hub registers with the
/// project's forwarder through the ways in they name. The signature is what
/// the phone trusts, so any peer may send them.
public final class EntriesFile: @unchecked Sendable {
    private let url: URL
    private let roots: [Data]
    private let now: @Sendable () -> Date
    private let log: @Sendable (String) -> Void
    private let lock = NSLock()
    private var held: (set: Releases.EntriesSet, entries: Releases.Entries, seen: Releases.Seen)?

    public init(url: URL, roots: [Data] = Releases.roots, now: @escaping @Sendable () -> Date = { Date() },
                log: @escaping @Sendable (String) -> Void = { _ in }) {
        (self.url, self.roots, self.now, self.log) = (url, roots, now, log)
        reload()
    }

    /// Reads the file again: the phone's member in the core keeps the
    /// entry points the computers send there and passes them on.
    public func reload() {
        guard let data = try? Data(contentsOf: url), let set = try? JSONDecoder().decode(Releases.EntriesSet.self, from: data) else { return }
        do {
            let (e, seen) = try Releases.checkEntries(set, roots: roots, nowMS: nowMS, seen: Releases.Seen())
            lock.withLock { held = (set, e, seen) }
        } catch {
            log("the entry points kept in \(url.lastPathComponent): \(error)")
        }
    }

    private var nowMS: Int64 { Int64(now().timeIntervalSince1970 * 1000) }

    /// The list held, nil for none or for one that has expired.
    public var current: Releases.Entries? {
        lock.withLock { held.flatMap { nowMS < $0.entries.expires_ms ? $0.entries : nil } }
    }

    /// When the list held expires, nil for none.
    public var expires: Date? {
        lock.withLock { held.map { Date(timeIntervalSince1970: TimeInterval($0.entries.expires_ms) / 1000) } }
    }

    /// The ways in over VLESS the list names for the forwarder name
    /// (host:port), as the hub's setProjectWays takes them.
    public func ways(for name: String) -> [Releases.EntryVLESS] { current?.forwarder(name)?.vless ?? [] }

    public var order: (keys: UInt64, seq: UInt64)? {
        lock.withLock {
            held.flatMap { h -> (keys: UInt64, seq: UInt64)? in
                nowMS < h.entries.expires_ms ? (h.seen.keys_seq, h.entries.seq) : nil
            }
        }
    }

    public func add(_ set: Releases.EntriesSet) {
        lock.lock()
        defer { lock.unlock() }
        let live = held.flatMap { nowMS < $0.entries.expires_ms ? $0 : nil }
        do {
            let (e, seen) = try Releases.checkEntries(set, roots: roots, nowMS: nowMS, seen: live?.seen ?? Releases.Seen())
            if let h = live, seen.keys_seq == h.seen.keys_seq, e.seq <= h.entries.seq { return }
            try JSONEncoder().encode(set).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            held = (set, e, seen)
        } catch {
            log("dropped the entry points a peer sent: \(error)")
        }
    }

    /// Forgets the list, when the phone leaves its group.
    public func remove() {
        lock.withLock { held = nil }
        try? FileManager.default.removeItem(at: url)
    }
}
