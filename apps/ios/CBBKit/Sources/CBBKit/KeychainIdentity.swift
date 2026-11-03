// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security) && canImport(Network)
import Crypto
import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
import Security

/// Turns a certificate and its private key into the SecIdentity that TLS
/// presents. On a device the key lives in the Secure Enclave; the keychain
/// pairs it with its certificate.
public enum KeychainIdentity {
    public enum Failure: Error { case keychain(OSStatus), noIdentity }

    /// A SecKey for a software P-256 key, for tests and tools.
    public static func secKey(_ key: P256.Signing.PrivateKey) throws -> SecKey {
        var error: Unmanaged<CFError>?
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let k = SecKeyCreateWithData(key.x963Representation as CFData, attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return k
    }

    /// Creates a P-256 key in the keychain under label: in the Secure
    /// Enclave with secureEnclave (on a device), a keychain key otherwise.
    /// With userPresence, a Secure Enclave key signs only after Face ID,
    /// Touch ID or the passcode (an evaluated LAContext that loadKey takes)
    /// and only while the phone is unlocked; without it the key also signs
    /// while the phone is locked, once it was unlocked after starting, so
    /// that the member key syncs in the background.
    public static func makeKey(label: String, secureEnclave: Bool = false, userPresence: Bool = false) throws -> SecKey {
        // Only the private key is stored: a public key under the same label
        // and key hash can pair with the certificate in an identity, and TLS
        // then fails to sign with it.
        var privateAttrs: [CFString: Any] = [kSecAttrIsPermanent: true, kSecAttrLabel: label]
        var attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPublicKeyAttrs: [kSecAttrIsPermanent: false] as [CFString: Any],
        ]
        if secureEnclave {
            // A Secure Enclave key needs an access control that allows
            // signing; it stays on this device.
            var error: Unmanaged<CFError>?
            let flags: SecAccessControlCreateFlags = userPresence ? [.privateKeyUsage, .userPresence] : .privateKeyUsage
            let when = userPresence ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            guard let access = SecAccessControlCreateWithFlags(nil, when, flags, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            attrs[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            privateAttrs[kSecAttrAccessControl] = access
        } else {
            #if !os(macOS)
            privateAttrs[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            #endif
        }
        attrs[kSecPrivateKeyAttrs] = privateAttrs
        #if os(macOS)
        if !secureEnclave { attrs[kSecUseDataProtectionKeychain] = false }
        #endif
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    /// The key that makeKey created under label, or nil.
    public static func loadKey(label: String) throws -> SecKey? { try loadKey(label: label, context: nil) }

    /// The same, signing with an authentication context: one that the
    /// user already passed signs without asking again, and one that does
    /// not allow interaction makes a key that needs the user fail instead
    /// of asking.
    public static func loadKey(label: String, context: AnyObject?) throws -> SecKey? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrLabel: label,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecReturnRef: true,
        ]
        #if canImport(LocalAuthentication)
        if let context = context as? LAContext { query[kSecUseAuthenticationContext] = context }
        #endif
        #if os(macOS)
        query[kSecUseDataProtectionKeychain] = false
        #endif
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let out else { throw Failure.keychain(status) }
        return (out as! SecKey)
    }

    /// Removes the key stored under label, before a new one replaces it.
    public static func removeKey(label: String) {
        var query: [CFString: Any] = [kSecClass: kSecClassKey, kSecAttrLabel: label]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain] = false
        #endif
        SecItemDelete(query as CFDictionary)
    }

    /// Removes public keys stored under label, as makeKey stored them
    /// before: they could stand in for the private key in an identity.
    public static func removePublicKeys(label: String) {
        var query: [CFString: Any] = [kSecClass: kSecClassKey, kSecAttrLabel: label, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain] = false
        #endif
        SecItemDelete(query as CFDictionary)
    }

    /// Removes the certificates stored under label, before a new one
    /// replaces them.
    public static func removeCertificates(label: String) {
        var query: [CFString: Any] = [kSecClass: kSecClassCertificate, kSecAttrLabel: label]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain] = false
        #endif
        SecItemDelete(query as CFDictionary)
    }

    /// Stores the key (unless it is in the keychain already, as a Secure
    /// Enclave key is) and the certificate under label, and returns the
    /// identity they make.
    public static func identity(certificate der: Data, key: SecKey, label: String, storeKey: Bool = true) throws -> SecIdentity {
        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else { throw Failure.noIdentity }
        // On macOS a tool without entitlements may only use the file
        // keychain; the app on iOS uses the data protection keychain.
        #if os(macOS)
        let where_: [CFString: Any] = [kSecUseDataProtectionKeychain: false]
        #else
        // TLS finds the identity while the phone is locked, after the
        // first unlock, as the member key signs then.
        let where_: [CFString: Any] = [kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        #endif
        if storeKey {
            let item: [CFString: Any] = [kSecClass: kSecClassKey, kSecValueRef: key, kSecAttrLabel: label]
            let add = item.merging(where_) { a, _ in a }
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess || status == errSecDuplicateItem else { throw Failure.keychain(status) }
        }
        let item: [CFString: Any] = [kSecClass: kSecClassCertificate, kSecValueRef: cert, kSecAttrLabel: label]
        let add = item.merging(where_) { a, _ in a }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else { throw Failure.keychain(status) }
        #if !os(macOS)
        // A certificate stored before was readable only while unlocked.
        if status == errSecDuplicateItem {
            SecItemUpdate([kSecClass: kSecClassCertificate, kSecAttrLabel: label] as CFDictionary, where_ as CFDictionary)
        }
        #endif
        #if os(macOS)
        var identity: SecIdentity?
        let s = SecIdentityCreateWithCertificate(nil, cert, &identity)
        guard s == errSecSuccess, let identity else { throw Failure.keychain(s) }
        return identity
        #else
        removePublicKeys(label: label)
        var out: CFTypeRef?
        let s = SecItemCopyMatching([kSecClass: kSecClassIdentity, kSecAttrLabel: label, kSecReturnRef: true] as CFDictionary, &out)
        guard s == errSecSuccess, let out else { throw Failure.keychain(s) }
        return out as! SecIdentity
        #endif
    }
}
#endif
