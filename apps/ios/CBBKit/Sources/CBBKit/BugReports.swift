// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The bug report (docs/core-api.md, "Bug reports"): the core builds and
/// seals the report and keeps the state; this class keeps that state where
/// `load` and `save` say (the app's settings), posts with `post` and sends
/// again what waits. `post` takes the URL and the body and returns the
/// server's answer, or throws when the report did not go.
public final class BugReports: @unchecked Sendable {
    /// Where reports go (`cbb_core::bug::URL`).
    public static let url = "https://bug.cbb.tools/"

    /// What the app keeps between reports, as the core gives it.
    public struct State: Codable, Equatable, Sendable {
        public struct Sent: Codable, Equatable, Sendable {
            public var fingerprint: String
            public var version: String
            public var fixed_in: String?
        }

        public struct Queued: Codable, Equatable, Sendable {
            public var fingerprint: String
            public var version: String
            public var post: String
            public var at_ms: Int64
        }

        public var sent: [Sent] = []
        public var allowed: UInt32 = 0
        public var always = false
        public var queue: [Queued] = []

        public init() {}

        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            sent = try c.decodeIfPresent([Sent].self, forKey: .sent) ?? []
            allowed = try c.decodeIfPresent(UInt32.self, forKey: .allowed) ?? 0
            always = try c.decodeIfPresent(Bool.self, forKey: .always) ?? false
            queue = try c.decodeIfPresent([Queued].self, forKey: .queue) ?? []
        }
    }

    /// The report as it is sealed, and as "Technical details" shows it.
    public struct Report: Codable, Equatable, Sendable {
        public var v: Int
        public var kind: String
        public var code: Int64
        public var name: String
        public var `where`: String
        public var message: String
        public var details: String
        public var app: String
        public var version: String
        public var build: String
        public var os: String
        public var os_version: String
        public var model: String
        public var arch: String
        public var day: String
        public var log: [String]

        /// The report as readable text, for "Technical details".
        public var text: String {
            let e = JSONEncoder()
            e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            return (try? e.encode(self)).map { String(decoding: $0, as: UTF8.self) } ?? ""
        }
    }

    /// What the core made of a break: the report, the body to post, what
    /// the app does (`ask`, `send` or `skip`), whether the dialog offers
    /// "Always allow", and the version that fixes this break.
    public struct Offer: Decodable, Sendable, Identifiable {
        public var report: Report
        public var fingerprint: String
        public var post: String
        public var url: String
        public var action: String
        public var offer_always: Bool
        public var fixed_in: String
        public var id: String { fingerprint }
    }

    /// The break the app tells.
    public struct Input: Encodable, Sendable {
        public var kind: String
        public var code: Int
        public var name: String
        public var message: String
        public var details: String
        public var app: String
        public var version: String
        public var build = ""
        public var os = ""
        public var os_version = ""
        public var model = ""
        public var arch = ""
        public var log: [String] = []
        public var names: [String] = []
        public var now_ms: Int64 = 0

        public init(kind: String, code: Int, name: String, message: String, details: String, app: String, version: String) {
            (self.kind, self.code, self.name, self.message, self.details, self.app, self.version) =
                (kind, code, name, message, details, app, version)
        }
    }

    private let load: () -> Data?
    private let save: (Data) -> Void
    private let post: (String, Data) throws -> Data
    private let now: () -> Int64
    private let lock = NSLock()

    public init(load: @escaping () -> Data?, save: @escaping (Data) -> Void, post: @escaping (String, Data) throws -> Data,
                now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) {
        (self.load, self.save, self.post, self.now) = (load, save, post, now)
    }

    private var state: State {
        load().flatMap { try? JSONDecoder().decode(State.self, from: $0) } ?? State()
    }

    private func keep(_ s: State) {
        if let d = try? JSONEncoder().encode(s) { save(d) }
    }

    private struct WithState: Decodable { var state: State }

    /// What the core makes of a break.
    public func offer(_ input: Input) throws -> Offer {
        struct Args: Encodable { var input: Input; var state: State }
        var i = input
        i.now_ms = now()
        lock.lock()
        defer { lock.unlock() }
        return try Core.run("bug_report", Args(input: i, state: state))
    }

    /// The user allowed a report, and maybe always.
    public func allow(always: Bool) throws {
        struct Args: Encodable { var state: State; var always: Bool }
        lock.lock()
        defer { lock.unlock() }
        keep(try Core.run("bug_allow", Args(state: state, always: always), as: WithState.self).state)
    }

    /// Posts the report; one that does not go waits for `resend`. Returns
    /// the version the server says fixes the break, empty when none, or nil
    /// when the report did not go.
    @discardableResult
    public func send(_ o: Offer) -> String? { send(o.fingerprint, o.report.version, o.post, o.url) }

    private func send(_ fingerprint: String, _ version: String, _ body: String, _ url: String) -> String? {
        guard !body.isEmpty else { return nil }
        struct Answer: Decodable { var fixed_in: String? }
        let fixed: String? = (try? post(url, Data(body.utf8))).map { (try? JSONDecoder().decode(Answer.self, from: $0))?.fixed_in ?? "" }
        struct Args: Encodable {
            var state: State
            var fingerprint, version, post: String
            var ok: Bool
            var fixed_in: String
            var now_ms: Int64
        }
        lock.lock()
        defer { lock.unlock() }
        if let s = try? Core.run("bug_sent", Args(state: state, fingerprint: fingerprint, version: version, post: body,
                                                 ok: fixed != nil, fixed_in: fixed ?? "", now_ms: now()), as: WithState.self) {
            keep(s.state)
        }
        return fixed
    }

    /// Sends the reports that wait, as when the network is back; returns
    /// how many went.
    @discardableResult
    public func resend(url: String = BugReports.url) -> Int {
        struct Args: Encodable { var state: State; var now_ms: Int64 }
        struct Pending: Decodable { var queue: [State.Queued]; var state: State }
        lock.lock()
        let pending = try? Core.run("bug_pending", Args(state: state, now_ms: now()), as: Pending.self)
        if let pending { keep(pending.state) }
        lock.unlock()
        return (pending?.queue ?? []).filter { send($0.fingerprint, $0.version, $0.post, url) != nil }.count
    }
}
