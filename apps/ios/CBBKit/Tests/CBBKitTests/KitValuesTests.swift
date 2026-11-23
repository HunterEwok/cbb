// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Crypto
import Foundation
import XCTest

/// The values the kit reads from the member and the core and hands them:
/// the records' names and levels, a hello's device and a key's evidence,
/// manifests and names as Go checks them, notices and the list a change of
/// root shows, the reasons why a phone does not sync, the home network's
/// addresses, and the keys that sign.
final class KitValuesTests: XCTestCase {
    private func decode<T: Decodable>(_: T.Type, _ json: String) throws -> T { try JSONDecoder().decode(T.self, from: Data(json.utf8)) }

    func testRecordsLevelsAndStores() {
        XCTAssertFalse(Records.levelAllows(Records.levelFiles, store: Records.rootless, consent: true))
        XCTAssertTrue(Records.levelAllows(Records.proven, store: Records.proven, consent: false))
        XCTAssertTrue(Records.levelAllows(Records.levelFiles, store: Records.file, consent: true))
        XCTAssertFalse(Records.levelAllows(Records.levelFiles, store: Records.file, consent: false))
        XCTAssertFalse(Records.levelAllows(Records.hardware, store: Records.file, consent: true))
        XCTAssertTrue(Records.levelAllows(Records.hardware, store: Records.hardware, consent: false))
        XCTAssertFalse(Records.levelAllows(Records.proven, store: Records.hardware, consent: false))
        XCTAssertEqual(Records.store(Records.proven, role: "computer"), Records.proven)
        XCTAssertEqual(Records.store(nil, role: "phone"), Records.hardware)
        XCTAssertEqual(Records.store("tpm", role: "watch"), Records.hardware)
        XCTAssertEqual(Records.store(nil, role: "computer"), Records.file)
        XCTAssertEqual(Records.keyLevels, [Records.proven, Records.hardware, Records.levelFiles])
        XCTAssertEqual(Records.keyHash(spki: Data([1])).count, 32)
        XCTAssertEqual(Records.ms(Date(timeIntervalSince1970: 1.5)), 1500)
        XCTAssertTrue(Records.ttlBounds.contains(Records.defaultTtlMS))
        XCTAssertTrue(Records.secretTtlBounds.contains(Records.defaultSecretTtlMS))
    }

    func testAHellosDeviceAndAKeysEvidence() throws {
        let good = Member.DeviceInfo(form: "laptop", osVersion: "14.2", version: "0.6.0", mac: "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(good.cleaned, good)
        XCTAssertEqual(try JSONDecoder().decode(Member.DeviceInfo.self, from: JSONEncoder().encode(good)), good)
        XCTAssertTrue(Member.DeviceInfo.forms.contains("watch"))
        XCTAssertEqual(try decode(Member.Via.self, #""universal-clipboard""#), .universalClipboard)
        XCTAssertThrowsError(try decode(Member.Via.self, #""telepathy""#))

        let e = Member.Evidence(format: Member.Evidence.android, key: Member.Evidence.member, groupTag: "tag", salt: Data([1, 2]), chain: [Data([3])])
        XCTAssertEqual(try JSONDecoder().decode(Member.Evidence.self, from: JSONEncoder().encode(e)), e)
        let outside = try decode(Member.Evidence.self, #"{"group_tag":""}"#)
        XCTAssertNil(outside.groupTag)
        XCTAssertEqual([outside.format, outside.key], ["", ""])
        XCTAssertTrue(outside.salt.isEmpty && outside.chain.isEmpty)
    }

    private let sum = Data(repeating: 7, count: 32)

    /// Files: each path checked as a receiver writes it, no folder twice, no file inside another file.
    func testAManifestOfFilesFollowsGo() throws {
        typealias P = Media.Part
        func file(_ path: String, size: Int64 = 1, sha: Data? = nil, type: String? = nil) -> P {
            P(type: type, path: path, dir: false, size: size, sha256: sha ?? sum)
        }
        func folder(_ path: String, size: Int64 = 0, sha: Data? = nil) -> P { P(type: nil, path: path, dir: true, size: size, sha256: sha) }
        func valid(_ parts: P...) -> Bool { Media.Manifest(size: parts.reduce(0) { $0 + $1.size }, parts: parts).isValid }
        let ok = Media.Manifest(size: 3, parts: [folder("dir"), file("dir/a.txt", size: 3)])
        XCTAssertTrue(ok.isFiles && ok.isValid)
        XCTAssertEqual(try JSONDecoder().decode(Media.Manifest.self, from: JSONEncoder().encode(ok)), ok)
        XCTAssertFalse(valid(file("a/../b")), "a path with ..")
        XCTAssertFalse(valid(file("a", type: "image/png")), "a file with a type")
        XCTAssertFalse(valid(file("con.txt")), "a reserved name")
        XCTAssertFalse(valid(file("a"), file("a/b")), "a file in a file")
        XCTAssertFalse(valid(folder("d", size: 1)), "a folder with bytes")
        XCTAssertFalse(valid(folder("d", sha: sum)), "a folder with a hash")
        XCTAssertFalse(valid(file("a", sha: Data(count: 31))), "a short hash")
        XCTAssertFalse(valid(file("a"), file("a")), "a path twice")
        XCTAssertFalse(Media.Manifest(size: 2, parts: [file("a")]).isValid, "a size that is not the parts'")
        XCTAssertTrue(valid(file("COM1x")))
        let empty = try decode(Media.Manifest.self, "{}")
        XCTAssertEqual(empty.size, 0)
        XCTAssertFalse(empty.isValid)
    }

    func testAManifestOfClipboardDataFollowsGo() throws {
        let png = Media.Part(type: "image/png", path: nil, dir: false, size: 2, sha256: sum)
        XCTAssertTrue(Media.Manifest(size: 2, parts: [png]).isValid)
        XCTAssertFalse(Media.Manifest(size: 2, parts: [Media.Part(type: "image/webp", path: nil, dir: false, size: 2, sha256: sum)]).isValid)
        XCTAssertFalse(Media.Manifest(size: 4, parts: [png, png]).isValid, "a type twice")
        XCTAssertFalse(Media.Manifest(size: 0, parts: [Media.Part(type: "image/png", path: nil, dir: true, size: 0, sha256: nil)]).isValid)
        XCTAssertEqual(try JSONDecoder().decode(Media.Part.self, from: JSONEncoder().encode(png)), png)
        let d = Media.Part(type: nil, path: "d", dir: true, size: 0, sha256: nil)
        let folder = try JSONSerialization.jsonObject(with: JSONEncoder().encode(d)) as? [String: Any]
        XCTAssertEqual(folder?["dir"] as? Bool, true)
        XCTAssertNil(folder?["size"], "a folder writes no size")
        XCTAssertEqual(try JSONDecoder().decode(Media.Part.self, from: JSONEncoder().encode(d)), d)
        XCTAssertEqual(Media.blobSize(0), 0)
        XCTAssertEqual(Media.blobSize(1), Media.sealedSegment)
        XCTAssertEqual(Media.blobSize(Int64(Media.segment) + 1), 2 * Media.sealedSegment)
    }

    func testNamesAreMadeOnesEverySystemTakes() {
        XCTAssertEqual(Media.cleanName("a/b"), "a_b")
        XCTAssertEqual(Media.cleanName("CON.txt"), "CON_.txt")
        XCTAssertEqual(Media.cleanName("name."), "name._")
        XCTAssertEqual(Media.cleanName(".."), "_")
        XCTAssertEqual(Media.cleanName(""), "_")
        XCTAssertLessThanOrEqual(Media.cleanName(String(repeating: "é", count: 400)).utf8.count, Media.maxName)
        XCTAssertEqual(Media.saveName("COM\u{b9}"), "COM\u{b9}_")
        XCTAssertEqual(Media.savePath("LPT3.log"), "LPT3_.log")
        XCTAssertFalse(Media.checkName("trailing "))
        XCTAssertFalse(Media.checkName("LPT9"))
        XCTAssertTrue(Media.checkName("LPT10"))
        XCTAssertFalse(Media.checkName("a\u{7f}"))
        XCTAssertFalse(Media.checkPath(""))
    }

    func testNoticesAndTheListOfAChangeOfRoot() throws {
        let n = try decode(Notice.self, #"{"id":"n1","kind":"admins_silent","args":{"days":35,"who":"Mac","sure":true,"x":null}}"#)
        XCTAssertEqual(n.args, ["days": "35", "who": "Mac", "sure": "true", "x": ""])
        XCTAssertTrue(n.dismissable)
        XCTAssertEqual(try decode(Notice.self, "{}").kind, "")
        let p = try decode(ChangePreview.self, #"{"rows":[{"device":"d","name":"Mac","os":"macos","outcome":"stays","frozen":true},{}],"waiting":true}"#)
        XCTAssertTrue(p.waiting)
        XCTAssertEqual(p.rows.map(\.id), ["d", ""])
        XCTAssertTrue(p.rows[0].frozen)
        XCTAssertEqual(p.rows[1].outcome, "")
        XCTAssertEqual(try decode(ChangePreview.self, "{}").rows, [])
        for (input, key) in [(RecoveryInput.qr("q"), "qr"), (.text("t"), "text"), (.secret(Data([1])), "secret")] {
            XCTAssertTrue(String(decoding: try JSONEncoder().encode(input), as: UTF8.self).contains("\"\(key)\""))
        }
    }

    func testWhyReadsTheCoresReasonsAndHandsItTheTunnels() throws {
        let r = try decode(WhyReason.self, #"{"code":"muted","level":"warn","until_ms":5000,"device":"hub","devices":["a"],"value":"3","detail":"d"}"#)
        XCTAssertEqual(r, WhyReason(code: "muted", level: "warn", untilMS: 5000, device: "hub", devices: ["a"], value: "3", detail: "d"))
        XCTAssertEqual(r.until, Date(timeIntervalSince1970: 5))
        XCTAssertNil(WhyReason(code: "c", level: "info", untilMS: 0).until)
        var away = WhyAway()
        away.hubDevice = "d"
        away.entriesStale = true
        let o = try JSONSerialization.jsonObject(with: JSONEncoder().encode(away)) as? [String: Any]
        XCTAssertEqual(o?["hub_device"] as? String, "d")
        XCTAssertEqual(o?["entries_stale"] as? Bool, true)
        XCTAssertEqual(o?.count, 11)
        XCTAssertEqual(try JSONDecoder().decode(WhyAway.self, from: JSONEncoder().encode(away)), away)
    }

    func testTheHomeNetworksAddresses() {
        XCTAssertEqual(LocalAddresses.ordered(["[fd00::1]:1", "10.0.0.1:1", "[fd00::2]:2"]), ["10.0.0.1:1", "[fd00::1]:1", "[fd00::2]:2"])
        XCTAssertTrue(LocalAddresses.isHome("192.168.1.2:8764"))
        XCTAssertTrue(LocalAddresses.isHome("172.16.0.1:1"))
        XCTAssertFalse(LocalAddresses.isHome("172.32.0.1:1"))
        XCTAssertFalse(LocalAddresses.isHome("8.8.8.8:53"))
        XCTAssertFalse(LocalAddresses.isHome("010.0.0.1:1"), "a leading zero")
        XCTAssertFalse(LocalAddresses.isHome("10.0.0.1"), "no port")
        XCTAssertTrue(LocalAddresses.isHome("[fd12:3456::1]:8764"))
        XCTAssertTrue(LocalAddresses.isHome("[fc00:0:0:0:0:0:0:1]:1"))
        XCTAssertFalse(LocalAddresses.isHome("[fe80::1]:1"), "link-local")
        XCTAssertFalse(LocalAddresses.isHome("[::ffff:10.0.0.1]:1"), "IPv4 written as IPv6")
        XCTAssertFalse(LocalAddresses.isHome("[fd00::1:1"), "no closing bracket")
        XCTAssertEqual(LocalAddresses.bytes(ipv6: "::"), [UInt8](repeating: 0, count: 16))
        XCTAssertEqual(LocalAddresses.bytes(ipv6: "::1")?.last, 1)
        XCTAssertEqual(LocalAddresses.bytes(ipv6: "1:2:3:4:5:6:7:8")?.count, 16)
        XCTAssertEqual(LocalAddresses.bytes(ipv6: "::ffff:1.2.3.4")?.suffix(4), [1, 2, 3, 4])
        XCTAssertEqual(LocalAddresses.bytes(ipv6: "1:2:3:4:5:6:1.2.3.4")?.count, 16)
        for bad in ["", "1::2::3", "1:2:3", "12345::", "g::", "1:2:3:4:5:6:7:8:9", "::1.2.3", "1:2:3:4:5:6:7::8:9", String(repeating: "a", count: 46)] {
            XCTAssertNil(LocalAddresses.bytes(ipv6: bad), bad)
        }
        XCTAssertNil(LocalAddresses.octets("1.2.3"))
        XCTAssertNil(LocalAddresses.octets("1.2.3.256"))
        XCTAssertNil(LocalAddresses.split(":1"))
        XCTAssertEqual(LocalAddresses.split("[fd00::1]:2")?.0, "fd00::1")
        XCTAssertFalse(LocalAddresses.hasPort("a:0"))
        XCTAssertFalse(LocalAddresses.hasPort("a:b:1"))
        // This computer's own: home addresses only, at most four.
        let mine = LocalAddresses.current()
        XCTAssertLessThanOrEqual(mine.count, LocalAddresses.maxAddrs)
        XCTAssertTrue(mine.allSatisfy { LocalAddresses.isHome(ipv4: $0) || LocalAddresses.isHome(ipv6: $0) })
    }

    func testKeysThatSign() throws {
        struct WholeOnly: CertificateSigner {
            let k = SoftwareSigner()
            var publicKeyDER: Data { k.publicKeyDER }
            func signature(for data: Data) throws -> Data { try k.signature(for: data) }
        }
        XCTAssertThrowsError(try WholeOnly().signature(digest: Data(count: 32))) { XCTAssertTrue($0 is WholeDataOnly) }
        XCTAssertFalse(WholeDataOnly().description.isEmpty)
        let k = SoftwareSigner()
        let digest = Data(SHA256.hash(data: Data("data".utf8)))
        let sig = try P256.Signing.ECDSASignature(derRepresentation: k.signature(digest: digest))
        XCTAssertTrue(k.key.publicKey.isValidSignature(sig, for: Data("data".utf8)))
        XCTAssertEqual(Core.Mismatch(reason: "r").description, "core: r")
    }

    #if canImport(Security) && canImport(Network)
    /// A software key as a SecKey signs as the keychain's keys do, whole data and a digest.
    func testASecKeySigns() throws {
        let soft = P256.Signing.PrivateKey()
        let s = try SecKeySigner(KeychainIdentity.secKey(soft))
        XCTAssertEqual(s.publicKeyDER, soft.publicKey.derRepresentation)
        let data = Data("data".utf8)
        let whole = try P256.Signing.ECDSASignature(derRepresentation: s.signature(for: data))
        XCTAssertTrue(soft.publicKey.isValidSignature(whole, for: data))
        let digest = try P256.Signing.ECDSASignature(derRepresentation: s.signature(digest: Data(SHA256.hash(data: data))))
        XCTAssertTrue(soft.publicKey.isValidSignature(digest, for: data))
        XCTAssertEqual(KeychainIdentity.inGroup([kSecAttrLabel: "x"]).count, KeychainIdentity.accessGroup == nil ? 1 : 2)
        XCTAssertNil(try KeychainIdentity.loadKey(label: "cbb-test-no-such-key-\(UUID().uuidString)"))
    }
    #endif
}
