// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
#if canImport(Network)
import Network
#endif
import XCTest

final class DiscoveryTests: XCTestCase {
    let dev = "0123456789abcdef0123456789abcdef"

    func testTXT() {
        XCTAssertEqual(Discovery.member(instance: dev, txt: ["v=1", "g=0011223344556677", "p=1"]),
                       FoundMember(device: dev, group: "0011223344556677", pairing: true))
        // Keys without regard to case, the value after the first "=", the
        // first of a repeated key.
        XCTAssertEqual(Discovery.member(instance: dev, txt: ["G=a=b", "g=other", "x"]),
                       FoundMember(device: dev, group: "a=b", pairing: false))
        XCTAssertEqual(Discovery.member(instance: dev, txt: [])?.group, nil)
        XCTAssertEqual(Discovery.member(instance: dev, txt: ["g": "77", "p": "0"]), FoundMember(device: dev, group: "77"))
        XCTAssertNil(Discovery.member(instance: "printer", txt: ["g=77"]))
        XCTAssertNil(Discovery.member(instance: dev.uppercased(), txt: ["g=77"]))
    }

    func testWithKnown() {
        let other = "fedcba9876543210fedcba9876543210"
        let found: Set = [FoundMember(device: dev, group: "g1", pairing: true)]
        // A member browsing finds stays as found; one it does not find is
        // added by its known address.
        XCTAssertEqual(Discovery.withKnown(found, known: [dev, other], group: "g1"), found.union([FoundMember(device: other, group: "g1")]))
        XCTAssertEqual(Discovery.withKnown(found, known: [], group: "g1"), found)
        XCTAssertTrue(JoinCode.isHome("10.1.2.3:8764"))
        XCTAssertFalse(JoinCode.isHome("100.64.0.1:8764"))
        XCTAssertFalse(JoinCode.isHome("[fd00::5]"))
    }

    #if canImport(Network) && os(macOS)
    /// Publishes a service as a Linux member does and finds it with
    /// BonjourBrowser, through the system's mDNSResponder.
    func testBonjourBrowser() async throws {
        let device = Member.newID()
        let listener = try NWListener(using: .tcp)
        listener.service = NWListener.Service(name: device, type: Discovery.serviceType, domain: "local.",
                                              txtRecord: NWTXTRecord(["v": "1", "g": "0011223344556677"]))
        listener.newConnectionHandler = { $0.cancel() }
        listener.start(queue: .main)
        defer { listener.cancel() }
        let seen = Seen()
        let browser = BonjourBrowser { seen.set($0) }
        browser.start()
        defer { browser.stop() }
        for _ in 0..<200 where !seen.has(device) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(seen.get(device), FoundMember(device: device, group: "0011223344556677"))
        XCTAssertNotNil(browser.endpoint(of: device))
        // The core's member dials it at the addresses it resolves to.
        let port = try XCTUnwrap(listener.port?.rawValue)
        let addrs = await browser.addresses(of: device)
        XCTAssertFalse(addrs.isEmpty)
        XCTAssertTrue(addrs.allSatisfy { $0.hasSuffix(":\(port)") }, "\(addrs)")
        let none = await browser.addresses(of: "none")
        XCTAssertEqual(none, [])
        // A phone that is the hub publishes itself, and is found too.
        let hubPhone = Member.newID()
        let published = try BonjourPublisher(name: hubPhone, port: port, txt: ["v": "1", "g": "0011223344556677", "r": "phone"])
        for _ in 0..<200 where !seen.has(hubPhone) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(seen.get(hubPhone), FoundMember(device: hubPhone, group: "0011223344556677"))
        published.stop()
        // Browsing again from the start finds it again.
        seen.set([])
        browser.restart()
        for _ in 0..<200 where !seen.has(device) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertTrue(seen.has(device))
        // Stopped, it does not start again on restart.
        browser.stop()
        browser.restart()
        XCTAssertNil(browser.endpoint(of: "none"))
    }

    final class Seen: @unchecked Sendable {
        let lock = NSLock()
        var members: Set<FoundMember> = []
        func set(_ m: Set<FoundMember>) { lock.withLock { members = m } }
        func get(_ d: String) -> FoundMember? { lock.withLock { members.first { $0.device == d } } }
        func has(_ d: String) -> Bool { get(d) != nil }
    }
    #endif
}
