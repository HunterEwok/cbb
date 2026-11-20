// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security)
import Foundation
import Security

/// This phone's secret for sealed messages (docs/protocol.md, section 15,
/// "Sealed commands"): 32 random bytes in the keychain, on this device
/// only, and its public key, the `seal` the phone's pairing and device
/// record carry, which the commands for it are sealed to.
public enum SealKey {
    public enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus)
        case random(OSStatus)

        public var description: String {
            switch self {
            case let .keychain(s): "the keychain refused the key for sealed messages (\(s))"
            case let .random(s): "the system gave no random bytes for the key for sealed messages (\(s))"
            }
        }
    }

    static let service = "tools.cbb.seal"

    /// In the app's own access group, never the push group's.
    private static func query(_ account: String) -> [CFString: Any] {
        KeychainIdentity.inGroup([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account])
    }

    /// The secret under account, made and kept on its first use.
    public static func secret(account: String = "seal") throws -> Data {
        var q = query(account)
        q[kSecReturnData] = true
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecSuccess, let d = out as? Data, d.count == 32 { return d }
        guard s == errSecItemNotFound || s == errSecSuccess else { throw Failure.keychain(s) }
        if s == errSecSuccess { remove(account: account) }
        var bytes = Data(count: 32)
        let r = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard r == errSecSuccess else { throw Failure.random(r) }
        var add = query(account)
        add[kSecValueData] = bytes
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let a = SecItemAdd(add as CFDictionary, nil)
        guard a == errSecSuccess else { throw Failure.keychain(a) }
        return bytes
    }

    /// The public key of the secret under account.
    public static func publicKey(account: String = "seal") throws -> Data {
        try Core.sealPublic(secret(account: account))
    }

    /// Removes the secret under account, as when the phone leaves its group.
    public static func remove(account: String = "seal") {
        SecItemDelete(query(account) as CFDictionary)
    }
}
#endif
