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

extension Member {
    /// How long a secret stays in the clipboard, as the computers keep it.
    public static let secretTTL: TimeInterval = 60

    /// A new device or event ID: 128 random bits as 32 lowercase hex
    /// characters.
    public static func newID() -> String {
        var rng = SystemRandomNumberGenerator()
        return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &rng)) }.joined()
    }
}
