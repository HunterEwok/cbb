// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The phones' tunnel in Rust under the kit's protocols: a hub and a
/// client on the loopback address, a remote invitation, a refused request
/// and a relay link that reports why it is not connected. The tunnel's
/// path itself is tested against Go's hub, forwarder and relay in Go
/// (internal/tunnel, TestRustPhone*).
final class RustTunnelTests: XCTestCase {
    let phone = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    let hubID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

    func testHubAndClient() throws {
        let tunnels = RustTunnels()
        let hubs = RustHubTunnels()
        let hubKey = try hubs.newKey()
        let clientKey = try tunnels.newKey()
        XCTAssertEqual(hubKey.count, 32)
        XCTAssertNotEqual(hubKey, clientKey)
        let psk = AwayState.newPSK()
        let client = String(decoding: try JSONEncoder().encode([
            ["device": phone, "key": try tunnels.publicKey(clientKey).base64EncodedString(), "psk": psk.base64EncodedString()],
        ]), as: UTF8.self)

        let member = try XCTUnwrap(Self.listener())
        defer { close(member.fd) }
        let hub = try hubs.start(privateKey: hubKey, device: hubID, memberPort: member.port, obfuscation: "", clients: client)
        defer { hub.close() }
        XCTAssertEqual(hub.status(), "{}", "no forwarder before the registration")
        try hub.setClients(client)
        let udp = try XCTUnwrap(RustTunnel.number(try RustTunnel.call(["op": "hub_status", "id": (hub as! RustHub).id])["udp_port"]))

        let t = try tunnels.start(privateKey: clientKey, psk: psk, hubKey: try hubs.publicKey(hubKey), device: phone, hub: hubID,
                                  endpoint: "127.0.0.1:\(udp)", obfuscation: "", vless: "")
        defer { t.close() }
        XCTAssertNotEqual(t.port, 0)
        XCTAssertTrue(CoreMemberTests.connects("127.0.0.1", t.port), "the tunnel's loopback port takes a connection")

        let guest = try hub.invite(group: "0123456789abcdef", endpoints: "[\"192.0.2.1:3276\"]", lifetime: 600, guestPort: member.port)
        XCTAssertTrue(guest.text.hasPrefix("cbb://invite#"), guest.text)
        XCTAssertEqual(guest.secret.count, 16)
        XCTAssertGreaterThan(guest.expires, Date())
        guest.admitted()
        guest.close()
    }

    func testRefusals() throws {
        XCTAssertThrowsError(try RustTunnels().publicKey(Data(count: 5))) { e in
            XCTAssertTrue(e is RustTunnel.Failure, "\(e)")
        }
        XCTAssertThrowsError(try RustHubTunnels().start(privateKey: Data(count: 32), device: hubID, memberPort: 0, obfuscation: "", clients: ""))
    }

    func testRelayReportsWhyItIsNotConnected() throws {
        final class Events: RelayLinkEvents, @unchecked Sendable {
            let lock = NSLock()
            var states: [String] = []
            func dial(peer: String, port: UInt16) {}
            func calling(peer: String, localPort: UInt16) {}
            func wanted(peer: String) -> Bool { true }
            func changed(_ state: String) { lock.withLock { states.append(state) } }
        }
        let root = SoftwareSigner(), key = SoftwareSigner()
        let groupCA = try GroupCertificates.groupCA(signer: root, now: Date(), pathLength: 1)
        let leaf = try GroupCertificates.member(device: phone, publicKey: key.publicKeyDER, ca: groupCA, caSigner: root, now: Date())
        let events = Events()
        let link = try RustRelayLinks().start(privateKey: try RustTunnels().newKey(), device: phone, endpoint: "127.0.0.1:9",
                                              pin: Data(count: 32).base64EncodedString(), chain: [leaf, groupCA],
                                              sign: { try key.signature(digest: $0) },
                                              records: "", memberPort: 9, events: events)
        defer { link.close() }
        let until = Date().addingTimeInterval(10)
        while Date() < until, events.lock.withLock({ events.states.isEmpty }) { Thread.sleep(forTimeInterval: 0.05) }
        let first = try XCTUnwrap(events.lock.withLock { events.states.first })
        let report = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(first.utf8)) as? [String: Any])
        XCTAssertNil(report["type"], "the kit gets the report as cbbtun gave it")
        XCTAssertNotNil(report["error"] as? String, first)
    }

    /// A TCP listener on the loopback address that takes nothing: the hub's
    /// member port.
    static func listener() -> (fd: Int32, port: UInt16)? {
        #if os(Linux)
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #else
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #endif
        guard fd >= 0 else { return nil }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 }
        } && listen(fd, 8) == 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard ok, withUnsafeMutablePointer(to: &addr, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) == 0 }
        }) else {
            close(fd)
            return nil
        }
        return (fd, UInt16(bigEndian: addr.sin_port))
    }
}
