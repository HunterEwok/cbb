// SPDX-License-Identifier: AGPL-3.0-only

// cbb-interop plays the phone against the Go code in tests
// (internal/pair, TestSwiftMemberAdmitsGoJoiner): it creates a group as the
// app does (PhoneGroup, a root CA with path length 1), dials
// a Go joiner over plain TCP, exchanges certificates in place of a TLS
// handshake, and admits the joiner with PairingMember.
//
//   cbb-interop admit HOST PORT CODE
//   cbb-interop admit-tls HOST PORT CODE FINGERPRINT   (macOS: real TLS)
//
// It prints the group CA in base64 on success.
//
//   cbb-interop member-tls HOST PORT PEER   (macOS)
//
// plays the phone as a member (internal/node, TestSwiftMemberTLS): it makes
// a key in the keychain and prints "key <SubjectPublicKeyInfo, base64>",
// reads "cert <DER, base64>" and "ca <DER, base64>" from standard input,
// dials the Go member PEER through the phone's member in the Rust core
// (CoreMember), sends "from swift", waits for "from
// go", then for Go's picture "go picture", which it fetches, sends its
// bytes reversed as "phone picture", which Go fetches, waits for "done",
// and prints "ok".
//
//   cbb-interop join-tls HOST PORT CODE   (macOS)
//
// joins a computer's group through the pairing window that `cbb pair`
// opened at HOST:PORT (internal/pair, TestSwiftJoinsComputerRoot), as a
// phone with an admin key, and prints the group CA and then the admin CA
// the root issued, each in base64 on a line.
//
//   cbb-interop invite-window SECRET yes|no   (macOS)
//
// opens a remote invitation's pairing window (InvitationWindow) with SECRET
// (base64), as the phone that is the hub does (internal/pair,
// TestSwiftHubAdmitsInvitedGoJoiner), and prints "port N"; for the device
// that proves it knows the secret it prints "fingerprint F" and admits it or
// not; then it prints the group CA in base64, or fails with the first failed
// attempt. Test use only.
//
//   cbb-interop restore-tls HOST PORT KEY CERT GROUP   (macOS)
//
// restores the group of the Go member at HOST:PORT on a new phone with the
// group's recovery key (internal/node, TestSwiftRestoresWithRecoveryKey):
// KEY (its 32 bytes) and CERT (its admin CA, DER), both base64, and GROUP,
// the group's tag, make the sheet's QR code, which the tool reads as the
// app does. It takes the records, checks them, claims the group for a new
// root through its member in the Rust core, sends the claim on a second
// connection, and prints its device ID,
// then the new root in base64. Test use only.

import CBBKit
import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

final class SocketTransport: FrameTransport {
    let fd: Int32

    init(host: String, port: UInt16) throws {
        #if canImport(Glibc)
        let stream = Int32(SOCK_STREAM.rawValue) // an enum in Glibc
        #else
        let stream = SOCK_STREAM
        #endif
        fd = socket(AF_INET, stream, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        #if !canImport(Glibc)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard ok == 0 else { throw POSIXError(.ECONNREFUSED) }
    }

    func write(_ data: Data) async throws {
        try data.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = send(fd, buf.baseAddress! + off, buf.count - off, 0)
                guard n > 0 else { throw POSIXError(.EPIPE) }
                off += n
            }
        }
    }

    func read(exactly n: Int) async throws -> Data {
        var out = Data(count: n)
        try out.withUnsafeMutableBytes { buf in
            var off = 0
            while off < n {
                let got = recv(fd, buf.baseAddress! + off, n - off, 0)
                guard got > 0 else { throw POSIXError(.ECONNRESET) }
                off += got
            }
        }
        return out
    }

    func writeBlob(_ d: Data) async throws {
        var len = UInt32(d.count).bigEndian
        try await write(Data(bytes: &len, count: 4) + d)
    }

    func readBlob() async throws -> Data {
        let n = try await read(exactly: 4).reduce(0) { $0 << 8 | Int($1) }
        return try await read(exactly: n)
    }
}

#if canImport(Network)
func memberTLS(host: String, port: UInt16, peer: String) async throws {
    let label = "cbb-interop-member-\(Member.newID())"
    let signer = try SecKeySigner(try KeychainIdentity.makeKey(label: label))
    let secret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    print("key \(signer.publicKeyDER.base64EncodedString())")
    print("seal \(try Core.sealPublic(secret).base64EncodedString())")
    fflush(stdout)
    func field(_ name: String) throws -> Data {
        guard let line = readLine(), line.hasPrefix(name + " "), let d = Data(base64Encoded: String(line.dropFirst(name.count + 1))) else {
            throw TLSTransport.Failure.notReady("no \(name) on standard input")
        }
        return d
    }
    let cert = try field("cert"), ca = try field("ca")
    let records = try JSONDecoder().decode([Member.Record].self, from: try field("records"))
    guard let me = try CertificateInfo(der: cert).commonName else { throw TLSTransport.Failure.notReady("no device ID") }
    // The phone's member in the Rust core, as the app runs it: it dials the
    // Go member at the address handed in and signs with the keychain key.
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-interop-\(Member.newID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let member = try CoreMember(.init(dir: dir.appendingPathComponent("member"), name: "iPhone", device: me, publicKeyDER: signer.publicKeyDER,
                                      seal: secret, cert: cert, issuer: nil, groupCA: ca, roots: [ca])) { try signer.signature(digest: $0) }
    defer { member.stop() }
    try member.addRecords(records)
    try member.found("go", addrs: ["\(host):\(port)"], device: peer)
    let timeout = Task {
        try await Task.sleep(nanoseconds: 30_000_000_000)
        member.stop()
    }
    defer { timeout.cancel() }
    var events = member.events.makeAsyncIterator()
    func waitFor(_ text: String) async throws -> CoreMember.Copy {
        while let e = await events.next() {
            if case let .copy(c) = e, c.text == text { return c }
        }
        throw TLSTransport.Failure.notReady("no \"\(text)\" within 30 s")
    }
    guard try await member.wait(timeout: .seconds(15)) else { throw TLSTransport.Failure.notReady("the Go member did not connect") }
    try member.copy("from swift")
    _ = try await waitFor("from go")
    // Go's picture, fetched, goes back reversed for Go to fetch.
    let picture = try await waitFor("go picture")
    guard picture.media?.parts.count == 1 else { throw TLSTransport.Failure.notReady("Go's picture has no part") }
    let parts = try await member.fetch(picture.id, max: Media.blobSize(Media.maxMedia), into: dir.appendingPathComponent("picture"))
    guard let file = parts.first?.file else { throw TLSTransport.Failure.notReady("Go's picture did not open") }
    let png = try Data(contentsOf: URL(fileURLWithPath: file))
    try member.copyMedia([.data(Data(png.reversed()), type: "image/png")], text: "phone picture")
    _ = try await waitFor("done")
    print("ok")
}

func joinTLS(host: String, port: UInt16, code: String) async throws {
    let label = "cbb-interop-joiner-\(Member.newID())"
    let signer = try SecKeySigner(try KeychainIdentity.makeKey(label: label))
    let cert = try GroupCertificates.selfSigned(device: Member.newID(), signer: signer)
    let identity = try KeychainIdentity.identity(certificate: cert, key: signer.key, label: label, storeKey: false)
    // The window's certificate is checked by the code's exchange, not here.
    let tls = TLSTransport(host: host, port: port, alpn: Pairing.alpn, identity: identity) { _ in true }
    try await tls.start()
    guard let leaf = tls.peerCertificate,
          let sid = tls.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else {
        throw TLSTransport.Failure.notReady("no peer certificate or exporter")
    }
    let admin = SoftwareSigner()
    let info = try Pairing.Info(name: "iPhone", os: "ios", adminKey: admin.publicKeyDER).proving(sessionID: sid, with: admin)
    let joined = try await PairingJoiner.join(over: tls, code: code, info: info, memberCert: leaf, joinerCert: cert,
                                              sessionID: sid, now: Date()) { _ = PhoneGroup.joined($0) }
    tls.close()
    guard let adminCA = joined.welcome.adminCA else { throw TLSTransport.Failure.notReady("the welcome carries no admin CA") }
    print(joined.welcome.groupCA.base64EncodedString())
    print(adminCA.base64EncodedString())
}

func restoreTLS(host: String, port: UInt16, key: Data, cert: Data, tag: String) async throws {
    let qr = try Core.recoverySheet(key: key, cert: cert, group: tag).qr
    guard case let .key(sheet) = try Core.readRecoverySheet(qr) else { throw TLSTransport.Failure.notReady("the sheet's QR code does not read") }
    let label = "cbb-interop-restore-\(Member.newID())"
    let signer = try SecKeySigner(try KeychainIdentity.makeKey(label: label))
    let now = Date()
    let r = try Restore(key: sheet, memberKey: signer.publicKeyDER, now: now)
    let identity = try KeychainIdentity.identity(certificate: r.memberCert, key: signer.key, label: label, storeKey: false)
    func dial() async throws -> TLSTransport {
        // The handshake takes any certificate; Restore.group checks the computer's against the records.
        let tls = TLSTransport(host: host, port: port, alpn: Member.alpn, identity: identity, chain: [r.adminCA]) { _ in true }
        try await tls.start()
        return tls
    }
    var g = try r.group(try await Restore.exchange(try await dial(), name: "iPhone", os: "ios", now: now), now: now)
    // The core's member signs the claim, as in the app; it goes out on a records-only connection.
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-interop-restore-\(Member.newID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let member = try CoreMember(.init(dir: dir, name: "iPhone", device: r.device, publicKeyDER: signer.publicKeyDER, seal: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
                                      cert: r.memberCert, issuer: r.adminCA, groupCA: g.groupCA, roots: g.trusted)) { try signer.signature(digest: $0) }
    defer { member.stop() }
    try member.addRecords(g.records.records)
    let newRootKey = SoftwareSigner()
    let newRoot = try member.rootCA(public: newRootKey.publicKeyDER) { try newRootKey.signature(digest: $0) }
    try r.claim(&g, member: member, newRoot: newRoot)
    guard let claim = g.claimRecord(in: try member.records()) else { throw TLSTransport.Failure.notReady("the member holds no claim") }
    _ = try await Restore.exchange(try await dial(), name: "iPhone", os: "ios", now: Date(), send: [claim])
    print(r.device)
    print(newRoot.base64EncodedString())
}

/// The group the window's attempts change.
final class GroupBox: @unchecked Sendable {
    var group: PhoneGroup
    init(_ g: PhoneGroup) { group = g }
}

func inviteWindow(secret: Data, yes: Bool) async throws {
    let now = Date()
    let caSigner = SoftwareSigner()
    let label = "cbb-interop-hub-\(Member.newID())"
    let signer = try SecKeySigner(try KeychainIdentity.makeKey(label: label))
    let box = GroupBox(try PhoneGroup.create(caSigner: caSigner, memberKey: signer.publicKeyDER, now: now))
    let identity = try KeychainIdentity.identity(certificate: box.group.memberCert, key: signer.key, label: label, storeKey: false)
    let invitation = PairingMember.Invitation(secret: secret) { req in
        print("fingerprint \(req.fingerprint)")
        fflush(stdout)
        return yes
    }
    let (ended, cont) = AsyncStream<Result<PairingMember.Admitted, Error>>.makeStream()
    let window = try InvitationWindow(identity: identity, expires: now.addingTimeInterval(60), admit: { t, joinerCert, sid in
        var g = box.group
        let a = try await g.admit(over: t, code: "", joinerCert: joinerCert, sessionID: sid, caSigner: caSigner, invitation: invitation, now: Date())
        box.group = g
        return a
    }, onEnd: { cont.yield($0) }, onError: { cont.yield(.failure($0)) })
    let port = try await window.start()
    print("port \(port)")
    fflush(stdout)
    var it = ended.makeAsyncIterator()
    guard let result = await it.next() else { throw TLSTransport.Failure.closed }
    let admitted = try result.get()
    guard admitted.confirmed, box.group.computers.map(\.device) == [admitted.device] else {
        throw TLSTransport.Failure.notReady("the joiner did not confirm")
    }
    print(box.group.groupCA.base64EncodedString())
}
#endif

let args = CommandLine.arguments
if args.count == 4, args[1] == "invite-window", let secret = Data(base64Encoded: args[2]) {
    #if canImport(Network)
    do {
        try await inviteWindow(secret: secret, yes: args[3] == "yes")
        exit(0)
    } catch {
        FileHandle.standardError.write("cbb-interop: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
    #else
    FileHandle.standardError.write("invite-window needs Network.framework\n".data(using: .utf8)!)
    exit(2)
    #endif
}
if args.count == 7, args[1] == "restore-tls", let port = UInt16(args[3]), let key = Data(base64Encoded: args[4]),
   let cert = Data(base64Encoded: args[5]) {
    #if canImport(Network)
    do {
        try await restoreTLS(host: args[2], port: port, key: key, cert: cert, tag: args[6])
        exit(0)
    } catch {
        FileHandle.standardError.write("cbb-interop: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
    #else
    FileHandle.standardError.write("restore-tls needs Network.framework\n".data(using: .utf8)!)
    exit(2)
    #endif
}
if args.count == 5, args[1] == "join-tls", let port = UInt16(args[3]) {
    #if canImport(Network)
    do {
        try await joinTLS(host: args[2], port: port, code: args[4])
        exit(0)
    } catch {
        FileHandle.standardError.write("cbb-interop: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
    #else
    FileHandle.standardError.write("join-tls needs Network.framework\n".data(using: .utf8)!)
    exit(2)
    #endif
}
if args.count == 5, args[1] == "member-tls", let port = UInt16(args[3]) {
    #if canImport(Network)
    do {
        try await memberTLS(host: args[2], port: port, peer: args[4])
        exit(0)
    } catch {
        FileHandle.standardError.write("cbb-interop: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
    #else
    FileHandle.standardError.write("member-tls needs Network.framework\n".data(using: .utf8)!)
    exit(2)
    #endif
}
guard args.count >= 5, let port = UInt16(args[3]),
      args[1] == "admit" && args.count == 5 || args[1] == "admit-tls" && args.count == 6 else {
    FileHandle.standardError.write("usage: cbb-interop admit HOST PORT CODE | admit-tls HOST PORT CODE FINGERPRINT\n".data(using: .utf8)!)
    exit(2)
}

do {
    let now = Date()
    let caSigner = SoftwareSigner()
    let t: FrameTransport
    let joinerCert: Data
    let sid: [UInt8]
    var group: PhoneGroup
    if args[1] == "admit-tls" {
        #if canImport(Network)
        let fp = args[5]
        // The member key is made in the keychain, as the app makes it, and
        // the group's certificate is issued for it.
        let label = "cbb-interop-\(Member.newID())"
        let signer = try SecKeySigner(try KeychainIdentity.makeKey(label: label))
        group = try PhoneGroup.create(caSigner: caSigner, memberKey: signer.publicKeyDER, now: now)
        let identity = try KeychainIdentity.identity(certificate: group.memberCert, key: signer.key, label: label, storeKey: false)
        let tls = TLSTransport(host: args[2], port: port, alpn: Pairing.alpn, identity: identity) { leaf in
            Pairing.fingerprint(cert: leaf) == fp
        }
        try await tls.start()
        guard let leaf = tls.peerCertificate,
              let exported = tls.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else {
            throw TLSTransport.Failure.notReady("no peer certificate or exporter")
        }
        (t, joinerCert, sid) = (tls, leaf, exported)
        #else
        FileHandle.standardError.write("admit-tls needs Network.framework\n".data(using: .utf8)!)
        exit(2)
        #endif
    } else {
        group = try PhoneGroup.create(caSigner: caSigner, memberKey: SoftwareSigner().publicKeyDER, now: now)
        let s = try SocketTransport(host: args[2], port: port)
        // In place of the TLS handshake: the member's certificate, then the
        // joiner's; the session ID is fixed.
        try await s.writeBlob(group.memberCert)
        (t, joinerCert, sid) = (s, try await s.readBlob(), [UInt8](repeating: 0, count: 32))
    }
    let admitted = try await group.admit(over: t, code: args[4], joinerCert: joinerCert, sessionID: sid, caSigner: caSigner, now: now)
    guard admitted.confirmed, group.computers.map(\.device) == [admitted.device] else {
        FileHandle.standardError.write("the joiner did not confirm\n".data(using: .utf8)!)
        exit(1)
    }
    print(group.groupCA.base64EncodedString())
} catch {
    FileHandle.standardError.write("cbb-interop: \(error)\n".data(using: .utf8)!)
    exit(1)
}
