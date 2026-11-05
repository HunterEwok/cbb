// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation

/// A group of a phone and a computer whose copies are sealed end to end,
/// for tests of two nodes: each side's CopyKeys over the same records.
struct TestCopies {
    let a: CopyKeys, b: CopyKeys
    var idA: String { a.device }
    var idB: String { b.device }

    init(roleB: String = "full") throws {
        let now = Date()
        let ca = SoftwareSigner(), ka = SoftwareSigner(), kb = SoftwareSigner()
        func secret() -> Data { Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }
        let (sa, sb) = (secret(), secret())
        var g = try PhoneGroup.create(caSigner: ca, memberKey: ka.publicKeyDER, seal: try Core.sealPublic(sa), now: now)
        let idB = SyncEngine.newID()
        let certB = try GroupCertificates.member(device: idB, publicKey: kb.publicKeyDER, ca: g.groupCA, caSigner: ca, now: now)
        _ = try g.record(device: idB, name: "pi", role: roleB, os: "linux", key: Records.keyHash(spki: kb.publicKeyDER),
                         store: Records.file, seal: try Core.sealPublic(sb), caSigner: ca, now: now)
        let set = g.records
        a = CopyKeys(device: g.device, cert: g.memberCert, issuer: nil, signer: ka, secret: sa, records: { set })
        b = CopyKeys(device: idB, cert: certB, issuer: nil, signer: kb, secret: sb, records: { set })
    }
}
