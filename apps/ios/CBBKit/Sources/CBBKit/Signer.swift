// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// A P-256 key that signs for the member: a software key in tests, a key
/// in the Secure Enclave in the app, which never leaves it.
public protocol CertificateSigner {
    /// The public key as a SubjectPublicKeyInfo, DER.
    var publicKeyDER: Data { get }
    /// An ECDSA signature with SHA-256 over data, DER.
    func signature(for data: Data) throws -> Data
    /// An ECDSA signature, DER, of a SHA-256 digest: what the Rust core's
    /// signing callback asks for; not every key gives one.
    func signature(digest: Data) throws -> Data
}

/// What a key that signs only whole data answers for a digest.
public struct WholeDataOnly: Error, CustomStringConvertible {
    public var description: String { "this key signs only whole data" }
}

public extension CertificateSigner {
    func signature(digest _: Data) throws -> Data { throw WholeDataOnly() }
}

/// A software P-256 key as a CertificateSigner.
public struct SoftwareSigner: CertificateSigner, Sendable {
    public let key: P256.Signing.PrivateKey
    public init(_ key: P256.Signing.PrivateKey = .init()) { self.key = key }
    public var publicKeyDER: Data { key.publicKey.derRepresentation }
    public func signature(for data: Data) throws -> Data { try key.signature(for: data).derRepresentation }

    /// An ECDSA signature, DER, of a SHA-256 digest, as the core's member
    /// asks its key for one (the core's sign_digest).
    public func signature(digest: Data) throws -> Data {
        struct Args: Encodable { var pkcs8: Data, digest: Data }
        struct Answer: Decodable { var sig: Data }
        return try Core.run("sign_digest", Args(pkcs8: key.derRepresentation, digest: digest), as: Answer.self).sig
    }
}
