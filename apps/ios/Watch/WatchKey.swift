// SPDX-License-Identifier: AGPL-3.0-only

import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The watch's admin key (docs/protocol.md, section 10, "Watches"): a P-256
/// key in the watch's Secure Enclave, usable only while the watch is
/// unlocked, which the root phone certifies as an admin CA with the role
/// watch. The key's blob, which only this Secure Enclave can use, sits in
/// the keychain; the admin CA the root gave it in the defaults.
enum WatchKey {
    enum Failure: Error, Equatable {
        /// The watch has no passcode, or its wrist detection is off.
        case notProtected
        /// No Secure Enclave here, as in the simulator.
        case noSecureEnclave
        case keychain(OSStatus)
    }

    private static let service = "tools.cbb.watch"
    /// The key the watch offered and the root has not certified yet, and
    /// the certified one.
    private static let pendingAccount = "admin-key-pending", adminAccount = "admin-key"
    private static let pendingDeviceKey = "watchPendingDevice", admissionKey = "watchAdmission"

    /// Whether the watch has a passcode and is on the wrist with wrist
    /// detection on: watchOS fails this policy once the watch noticed it
    /// left the wrist, and without a passcode.
    static func protected() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithWristDetection, error: &error)
    }

    /// Makes a new key for the root to certify, under a new device ID, and
    /// returns what the phone needs: the ID, the watch's name and the key's
    /// SubjectPublicKeyInfo. An earlier pending key goes; a certified one
    /// stays until the new one is certified.
    static func request(name: String) throws -> WatchState.KeyRequest {
        guard protected() else { throw Failure.notProtected }
        guard SecureEnclave.isAvailable else { throw Failure.noSecureEnclave }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) else {
            throw error.map { $0.takeRetainedValue() as Error } ?? Failure.noSecureEnclave
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try store(key.dataRepresentation, account: pendingAccount)
        let device = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        UserDefaults.standard.set(device, forKey: pendingDeviceKey)
        return WatchState.KeyRequest(device: device, name: name, key: key.publicKey.derRepresentation)
    }

    /// Takes the root's answer to the pending request: the pending key
    /// becomes the admin key. An answer for another request is refused.
    static func admit(_ a: WatchState.Admission) throws {
        guard a.device == UserDefaults.standard.string(forKey: pendingDeviceKey), let blob = load(account: pendingAccount) else {
            throw Failure.keychain(errSecItemNotFound)
        }
        try store(blob, account: adminAccount)
        remove(account: pendingAccount)
        UserDefaults.standard.removeObject(forKey: pendingDeviceKey)
        UserDefaults.standard.set(try JSONEncoder().encode(a), forKey: admissionKey)
    }

    /// What the root certified, when it did.
    static var admission: WatchState.Admission? {
        UserDefaults.standard.data(forKey: admissionKey).flatMap { try? JSONDecoder().decode(WatchState.Admission.self, from: $0) }
    }

    /// The certified key, for signing; nil without one.
    static func adminKey() throws -> SecureEnclave.P256.Signing.PrivateKey? {
        guard let blob = load(account: adminAccount) else { return nil }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    }

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    private static func store(_ data: Data, account: String) throws {
        remove(account: account)
        var q = query(account)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }

    private static func load(account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        var out: AnyObject?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    private static func remove(account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }
}
