// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// One phone of a test group: its member in the Rust core (CoreMember), its
/// keys, and the events it got.
final class CorePhone: @unchecked Sendable {
    let member: CoreMember
    let device: String
    let cert: Data
    let key: SoftwareSigner
    private let lock = NSLock()
    private var got: [CoreMember.Event] = []
    private var reader: Task<Void, Never>?
    /// The port it listens on as the hub, once it does.
    var port: UInt16?

    struct Timeout: Error, CustomStringConvertible {
        let what: String
        var description: String { "no \(what) within 15 s" }
    }

    init(_ member: CoreMember, device: String, cert: Data, key: SoftwareSigner) {
        (self.member, self.device, self.cert, self.key) = (member, device, cert, key)
        reader = Task { [weak self] in
            for await e in member.events { self?.lock.withLock { self?.got.append(e) } }
        }
    }

    /// Every event f picks so far.
    func all<T>(_ f: (CoreMember.Event) -> T?) -> [T] { lock.withLock { got.compactMap(f) } }

    /// The first event that f picks, waiting up to 15 s.
    func next<T>(_ what: String, _ f: (CoreMember.Event) -> T?) async throws -> T {
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if let t: T = lock.withLock({ got.lazy.compactMap(f).first }) { return t }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw Timeout(what: what)
    }

    /// Waits up to 15 s until f holds.
    func until(_ what: String, _ f: () throws -> Bool) async throws {
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if try f() { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw Timeout(what: what)
    }

    /// The copy with text that became the group's here.
    func copy(_ text: String) async throws -> CoreMember.Copy {
        try await next("the copy \(text)") { if case let .copy(c) = $0, c.text == text { return c }; return nil }
    }

    /// The peer device's hello, once it came.
    func peer(_ device: String) async throws -> CoreMember.Peer {
        try await next("the hello of \(device)") { if case let .peer(p) = $0, p.device == device { return p }; return nil }
    }

    deinit {
        reader?.cancel()
        member.stop()
    }
}

/// A group of phones whose members run in the Rust core: the root phone
/// (phones[0]) made it, and certified the others, each with a device record
/// that seals the copies to it.
struct CoreGroup {
    var g: PhoneGroup
    let ca: SoftwareSigner
    var phones: [CorePhone]

    /// The core keeps the secret for sealed messages for the process, as an
    /// app runs one member with one secret: every phone of every test has it.
    static let seal = Data((0..<32).map { _ in UInt8.random(in: 0...255) })

    var root: CorePhone { phones[0] }

    /// Makes the group and starts each phone's member, its folder removed
    /// when test ends.
    init(_ n: Int = 2, test: XCTestCase) throws {
        let now = Date()
        let ca = SoftwareSigner(), rootKey = SoftwareSigner()
        let sealKey = try Core.sealPublic(Self.seal)
        var g = try PhoneGroup.create(caSigner: ca, memberKey: rootKey.publicKeyDER, seal: sealKey, now: now)
        var made: [(String, Data, SoftwareSigner)] = [(g.device, g.memberCert, rootKey)]
        for i in 1..<max(n, 1) {
            let k = SoftwareSigner(), id = Member.newID()
            let cert = try GroupCertificates.member(device: id, publicKey: k.publicKeyDER, ca: g.groupCA, caSigner: ca, now: now)
            _ = try g.record(device: id, name: "Phone \(i)", role: "phone", os: "ios", key: Records.keyHash(spki: k.publicKeyDER),
                             store: Records.hardware, seal: sealKey, caSigner: ca, now: now)
            made.append((id, cert, k))
        }
        let top = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-core-group-\(UUID().uuidString)")
        test.addTeardownBlock { try? FileManager.default.removeItem(at: top) }
        var phones: [CorePhone] = []
        for (i, (id, cert, k)) in made.enumerated() {
            let dir = top.appendingPathComponent("\(i)")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let m = try CoreMember(.init(dir: dir, name: i == 0 ? "Root phone" : "Phone \(i)", device: id, publicKeyDER: k.publicKeyDER,
                                         seal: Self.seal, cert: cert, issuer: nil, groupCA: g.groupCA, roots: g.trusted)) { try k.signature(digest: $0) }
            try m.addRecords(g.records.records)
            phones.append(CorePhone(m, device: id, cert: cert, key: k))
        }
        (self.g, self.ca, self.phones) = (g, ca, phones)
    }

    /// Phone i dials phone hub, which listens as the group's hub, and both
    /// wait for the other's hello.
    func connect(_ i: Int, to hub: Int) async throws {
        let h = phones[hub]
        if h.port == nil { h.port = try h.member.listen() }
        try phones[i].member.found("phone \(hub)", addrs: ["127.0.0.1:\(h.port!)"], device: h.device)
        _ = try await phones[i].peer(h.device)
        _ = try await h.peer(phones[i].device)
    }
}
