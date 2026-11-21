// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBB
import CBBKit
import Security
import XCTest

/// The app's own TLS identity, a keychain key with its certificate, must
/// sign the handshake: a computer asks for the client's certificate.
final class KeychainTLSTests: XCTestCase {
    private var labels: [String] = []

    override func tearDown() {
        for label in labels {
            KeychainIdentity.removeCertificates(label: label)
            KeychainIdentity.removeKey(label: label)
        }
    }

    /// A keychain key and a self-signed certificate under a fresh label, as
    /// LiveGroup makes them, and the identity they give.
    private func identity() throws -> (SecIdentity, Data) {
        let label = "tools.cbb.test-\(UUID().uuidString)"
        labels.append(label)
        let key = try KeychainIdentity.makeKey(label: label)
        let signer = try SecKeySigner(key)
        let cert = try GroupCertificates.selfSigned(device: Member.newID(), signer: signer)
        return (try KeychainIdentity.identity(certificate: cert, key: key, label: label, storeKey: false), cert)
    }

    func testHandshakeWithKeychainIdentity() async throws {
        let (server, _) = try identity()
        let (client, _) = try identity()
        try await handshake(server: server, client: client)
    }

    /// A key stored as makeKey stored it before, its public key beside it
    /// under the same label, still signs once the identity is made.
    func testHandshakeWithAnOldKey() async throws {
        let (server, _) = try identity()
        let label = "tools.cbb.test-\(UUID().uuidString)"
        labels.append(label)
        var error: Unmanaged<CFError>?
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256,
                                      kSecAttrIsPermanent: true, kSecAttrLabel: label]
        let key = try XCTUnwrap(SecKeyCreateRandomKey(attrs as CFDictionary, &error))
        let cert = try GroupCertificates.selfSigned(device: Member.newID(), signer: SecKeySigner(key))
        let client = try KeychainIdentity.identity(certificate: cert, key: key, label: label, storeKey: false)
        try await handshake(server: server, client: client)
    }

    /// A failure that names the side it came from, so that a timeout says
    /// whether the listener got no connection, or which handshake hung.
    struct Side: Error, CustomStringConvertible {
        let side: String
        let error: Error
        var description: String { "\(side): \(error)" }
    }

    private func handshake(server: SecIdentity, client: SecIdentity) async throws {
        let listener = try TLSListener(alpn: "cbb-test", identity: server) { _ in true }
        let port = try await listener.start()
        defer { listener.stop() }
        let accepted = Task {
            guard let t = await listener.next() else { throw Side(side: "listener", error: TLSTransport.Failure.closed) }
            do { try await t.start() } catch { throw Side(side: "the accepted connection's handshake", error: error) }
            return t.peerCertificate
        }
        let t = TLSTransport(host: "127.0.0.1", port: port, alpn: "cbb-test", identity: client) { _ in true }
        do { try await t.start() } catch {
            accepted.cancel()
            throw Side(side: "the client's handshake", error: error)
        }
        defer { t.close() }
        let seen = try await accepted.value
        XCTAssertNotNil(seen, "the listener got no client certificate")
    }
}
