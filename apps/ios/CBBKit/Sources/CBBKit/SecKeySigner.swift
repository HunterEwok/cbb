// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security) && canImport(Network)
import Crypto
import Foundation
import Security

/// A keychain or Secure Enclave key as a CertificateSigner: the key never
/// leaves the keychain, and the Secure Enclave signs.
public struct SecKeySigner: CertificateSigner {
    public let key: SecKey
    public let publicKeyDER: Data

    public init(_ key: SecKey) throws {
        guard let pub = SecKeyCopyPublicKey(key) else { throw KeychainIdentity.Failure.noIdentity }
        var error: Unmanaged<CFError>?
        guard let x963 = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        self.key = key
        publicKeyDER = try P256.Signing.PublicKey(x963Representation: x963).derRepresentation
    }

    public func signature(for data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return sig // DER, as X9.62 specifies
    }

    /// An ECDSA signature, DER, of a SHA-256 digest: the member key signs
    /// the hub's TLS to its forwarder so (cbbtun's Signer).
    public func signature(digest: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return sig
    }
}
#endif
