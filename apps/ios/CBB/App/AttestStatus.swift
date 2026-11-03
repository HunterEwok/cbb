// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import Foundation
import os

private let log = Logger(subsystem: "tools.cbb", category: "keys")

/// The revocation list of Android attestations that a root phone checks
/// evidence against (docs/protocol.md, section 17, "Revoked attestations"):
/// keys.json and attest-status.json from the mirror, kept in a directory
/// and fetched again at most once a day. It does nothing while no root keys
/// are pinned (Releases.roots).
actor AttestStatus {
    private static let mirror = URL(string: "https://cbb.tools/attest/")!
    private static let keysName = "keys.json"
    private static let statusName = "attest-status.json"

    private let dir: URL
    private let roots: [Data]
    private(set) var revoked: Set<String> = []
    private var seen = Releases.Seen()
    private var fetchedAt: Date?

    init(dir: URL, roots: [Data] = Releases.roots) {
        self.dir = dir
        self.roots = roots
        guard !roots.isEmpty,
              let k = try? Data(contentsOf: dir.appendingPathComponent(Self.keysName)),
              let s = try? Data(contentsOf: dir.appendingPathComponent(Self.statusName)),
              let keys = try? JSONDecoder().decode(Releases.File.self, from: k),
              let status = try? JSONDecoder().decode(Releases.File.self, from: s),
              let taken = try? Releases.checkStatus(keys: keys, status: status, roots: roots,
                                                    nowMS: Int64(Date().timeIntervalSince1970 * 1000), seen: Releases.Seen())
        else { return }
        revoked = Set(taken.0.android_revoked)
        seen = taken.1
    }

    /// Fetches the mirror's list, unless that was done in the last day.
    func refreshIfDue() async {
        if roots.isEmpty { return }
        if let at = fetchedAt, Date().timeIntervalSince(at) < 24 * 3600 { return }
        fetchedAt = Date()
        do {
            let k = try await get(Self.keysName)
            let s = try await get(Self.statusName)
            let keys = try JSONDecoder().decode(Releases.File.self, from: k)
            let status = try JSONDecoder().decode(Releases.File.self, from: s)
            let (st, next) = try Releases.checkStatus(keys: keys, status: status, roots: roots,
                                                      nowMS: Int64(Date().timeIntervalSince1970 * 1000), seen: seen)
            if next == seen { return }
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try k.write(to: dir.appendingPathComponent(Self.keysName), options: .atomic)
            try s.write(to: dir.appendingPathComponent(Self.statusName), options: .atomic)
            revoked = Set(st.android_revoked)
            seen = next
            log.info("took the revocation list of Android attestations, \(st.android_revoked.count) certificates")
        } catch {
            log.error("fetching the revocation list: \(String(reflecting: error), privacy: .public)")
        }
    }

    private func get(_ name: String) async throws -> Data {
        let (data, resp) = try await URLSession.shared.data(from: Self.mirror.appendingPathComponent(name))
        guard (resp as? HTTPURLResponse)?.statusCode == 200, data.count <= 2 * Releases.maxBody else {
            throw URLError(.badServerResponse)
        }
        return data
    }
}
