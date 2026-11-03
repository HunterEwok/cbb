// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Network)
@testable import CBBKit
import Foundation
import Network
import XCTest

/// A peer that takes the TCP connection and never answers must not hang
/// the handshake: a computer whose firewall or service misbehaves.
final class TLSTimeoutTests: XCTestCase {
    /// Listens on loopback, accepts TCP connections and never sends a byte.
    private func silentListener() async throws -> (NWListener, UInt16) {
        let listener = try NWListener(using: .tcp)
        listener.newConnectionHandler = { $0.start(queue: .global()) }
        let port: UInt16 = try await withCheckedThrowingContinuation { c in
            let once = TLSTransport.Once()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: if once.claim() { c.resume(returning: listener.port?.rawValue ?? 0) }
                case .failed(let e): if once.claim() { c.resume(throwing: e) }
                default: break
                }
            }
            listener.start(queue: .global())
        }
        return (listener, port)
    }

    private func dial(_ port: UInt16) -> TLSTransport {
        TLSTransport(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!),
                     parameters: NWParameters(tls: NWProtocolTLS.Options()))
    }

    func testSilentPeerTimesOut() async throws {
        let (listener, port) = try await silentListener()
        defer { listener.cancel() }
        let t = dial(port)
        let started = Date()
        do {
            try await t.start(timeout: 1)
            XCTFail("the handshake finished with a silent peer")
        } catch TLSTransport.Failure.timedOut {
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func testCancellingStopsTheHandshake() async throws {
        let (listener, port) = try await silentListener()
        defer { listener.cancel() }
        let t = dial(port)
        let task = Task { try await t.start(timeout: 30) }
        try await Task.sleep(for: .milliseconds(200))
        let started = Date()
        task.cancel()
        do {
            try await task.value
            XCTFail("the handshake finished with a silent peer")
        } catch {
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }
}
#endif
