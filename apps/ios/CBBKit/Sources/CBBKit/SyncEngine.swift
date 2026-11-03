// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The hybrid logical clock of docs/protocol.md, section 5, as
/// internal/hlc implements it. A timestamp more than `maxAheadMS` ahead of
/// it is refused (`ahead`).
public final class HybridClock: @unchecked Sendable {
    private let lock = NSLock()
    private var last: Member.Timestamp
    private let wallMS: () -> UInt64

    /// floor is a timestamp the clock must not go below, such as the last
    /// one this device issued before a restart.
    public init(floor: Member.Timestamp = .zero, wallMS: @escaping () -> UInt64 = { UInt64(max(0, Date().timeIntervalSince1970 * 1000)) }) {
        (last, self.wallMS) = (floor, wallMS)
    }

    /// The last timestamp issued or observed.
    public var latest: Member.Timestamp { lock.withLock { last } }

    /// A timestamp for a local event, later than every one before it.
    public func now() -> Member.Timestamp {
        lock.withLock {
            let pt = min(wallMS(), Member.Timestamp.maxWall)
            if pt > last.wall {
                last = .init(wall: pt, logical: 0)
            } else if last.logical == .max {
                last = .init(wall: min(last.wall + 1, Member.Timestamp.maxWall), logical: 0)
            } else {
                last.logical += 1
            }
            return last
        }
    }

    /// Takes in the timestamp of an event received for the first time.
    public func observe(_ r: Member.Timestamp) {
        lock.withLock {
            let pt = min(wallMS(), Member.Timestamp.maxWall)
            let w = max(last.wall, r.wall, pt)
            if w == last.wall && w == r.wall {
                last.logical = Self.inc(max(last.logical, r.logical))
            } else if w == last.wall {
                last.logical = Self.inc(last.logical)
            } else if w == r.wall {
                last = .init(wall: r.wall, logical: Self.inc(r.logical))
            } else {
                last = .init(wall: w, logical: 0)
            }
        }
    }

    /// How far a received timestamp may be ahead of the clock: 7 days.
    public static let maxAheadMS: UInt64 = 7 * 24 * 3600 * 1000

    /// 2026-01-01: before it the clock is not trusted to refuse anything.
    static let plausible: UInt64 = 1_767_225_600_000

    /// Whether r is more than `maxAheadMS` ahead of this clock's wall time,
    /// as Go's Ahead: the timestamps it issued or observed do not move that
    /// limit. A clock that reads before 2026 refuses nothing.
    public func ahead(_ r: Member.Timestamp) -> Bool {
        lock.withLock {
            let ref = wallMS()
            return ref >= Self.plausible && r.wall > ref + Self.maxAheadMS
        }
    }

    private static func inc(_ l: UInt32) -> UInt32 { l == .max ? l : l + 1 }
}

/// The phone's sync engine: the group's current event, the IDs seen, and
/// the forwarding rules of docs/protocol.md, section 5 ("wire" parts). The
/// local policy is the phone's own: the app syncs while it is open, so it
/// has no rejoin window, and what it shows is simply the current event while
/// it is live. Not safe for concurrent use; MemberNode serializes it.
public final class SyncEngine {
    /// How many event IDs are remembered.
    public static let rememberIDs = 4096
    /// How long a secret is usable after its copy.
    public static let secretTTL: TimeInterval = 60

    public let device: String
    let clock: HybridClock
    let uptime: () -> TimeInterval

    private(set) var current: Member.Event?
    /// When the current event was copied, on the uptime clock.
    private var copiedAt: TimeInterval = 0
    private var seen = Set<String>()
    private var seenOrder: [String] = []

    public init(device: String, clock: HybridClock, uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        (self.device, self.clock, self.uptime) = (device, clock, uptime)
    }

    /// What to do with a received event.
    public struct Result: Equatable {
        /// The event to send to the other connections, if any.
        public var forward: Member.Event?
        /// Whether it became the current event, or the current event got
        /// its text.
        public var changed: Bool
    }

    /// The current event with its age as of now.
    public var currentEvent: Member.Event? {
        guard var e = current else { return nil }
        e.ageMS = Self.ms(max(0, uptime() - copiedAt))
        return e
    }

    /// The current text while it is usable: a text, a secret younger than
    /// the secret lifetime, or the text of images or files, as a text.
    public var usable: (text: String, kind: Member.Kind)? {
        guard let e = current, !e.isMark else { return nil }
        if e.kind == .secret && uptime() - copiedAt >= Self.secretTTL { return nil }
        if e.kind == .media { return e.text.isEmpty ? nil : (e.text, .text) }
        return (e.text, e.kind)
    }

    /// The hello for a new connection: the current event, a secret only as
    /// its mark.
    public func hello(name: String?, wallMS: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Member.Hello {
        Member.Hello(wallMS: wallMS, current: currentEvent?.mark, name: name)
    }

    /// Makes an event of a text this phone copied or sent, or with media of
    /// images or files and text their plain-text alternative, which becomes
    /// the current event. It goes to every connection.
    public func local(text: String, kind: Member.Kind, via: Member.Via = .phone, media: Media.Manifest? = nil) -> Member.Event {
        let e = Member.Event(id: Self.newID(), origin: device, via: via, time: clock.now(), ageMS: 0, kind: media != nil ? .media : kind,
                             text: text, media: media)
        remember(e.id)
        current = e
        copiedAt = uptime()
        return e
    }

    /// Takes in an event from a connection, or the current event of a
    /// hello. An event that is not valid, or more than 7 days ahead of the
    /// clock, changes nothing.
    public func received(_ e: Member.Event) -> Result {
        guard e.isValid, !clock.ahead(e.time) else { return Result(forward: nil, changed: false) }
        if seen.contains(e.id) {
            // Seen before: only a mark that gets its text matters.
            if let cur = current, cur.id == e.id, cur.isMark, !e.isMark {
                current = e
                copiedAt = uptime() - Double(min(e.ageMS, Self.maxAgeMS)) / 1000
                return Result(forward: e, changed: true)
            }
            return Result(forward: nil, changed: false)
        }
        clock.observe(e.time)
        remember(e.id)
        var changed = false
        if current == nil || e.isLater(than: current!) {
            current = e
            copiedAt = uptime() - Double(min(e.ageMS, Self.maxAgeMS)) / 1000
            changed = true
        }
        return Result(forward: e, changed: changed)
    }

    /// Takes in a peer's hello. A hello that carries a secret's text is a
    /// protocol error and closes the connection.
    public func reconcile(_ h: Member.Hello) throws -> Result {
        guard let cur = h.current else { return Result(forward: nil, changed: false) }
        if cur.kind == .secret && !cur.text.isEmpty { throw Failure.secretInHello }
        guard cur.isValid else { throw Failure.badHello }
        return received(cur)
    }

    public enum Failure: Error { case secretInHello, badHello }

    /// Ages are capped at 365 days.
    static let maxAgeMS: Int64 = 365 * 24 * 3600 * 1000

    private func remember(_ id: String) {
        guard seen.insert(id).inserted else { return }
        seenOrder.append(id)
        if seenOrder.count > Self.rememberIDs {
            seen.remove(seenOrder.removeFirst())
        }
    }

    static func ms(_ t: TimeInterval) -> Int64 { Int64((t * 1000).rounded(.down)) }

    /// A new event ID: 128 random bits as 32 lowercase hex characters.
    public static func newID() -> String {
        var rng = SystemRandomNumberGenerator()
        return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &rng)) }.joined()
    }
}
