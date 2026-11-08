// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import Foundation
import Security

/// A small item in the keychain: readable after the first unlock, so the
/// app syncs in the background as at home, and never in a backup or on
/// another device.
enum KeychainData {
    enum Failure: Error { case keychain(OSStatus) }

    private static func query(_ service: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "state"]
    }

    static func load(_ service: String) -> Data? {
        var q = query(service)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    /// Keeps data; nil deletes it.
    static func save(_ service: String, _ data: Data?) throws {
        guard let data else {
            let status = SecItemDelete(query(service) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.keychain(status) }
            return
        }
        let attrs: [String: Any] = [kSecValueData as String: data,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var status = SecItemUpdate(query(service) as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query(service).merging(attrs) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }
}

/// The state of sync away from home in the keychain.
enum AwayKeychain {
    static let service = "tools.cbb.away"

    static func load() -> AwayState? { KeychainData.load(service).flatMap(AwayState.decode) }

    /// Keeps s; nil deletes it.
    static func save(_ s: AwayState?) throws { try KeychainData.save(service, try s.map { try $0.encoded() }) }
}

/// The phone's state as the group's hub in the keychain.
enum HubKeychain {
    static let service = "tools.cbb.hub"

    static func load() -> HubState? { KeychainData.load(service).flatMap(HubState.decode) }

    /// Keeps s; nil deletes it.
    static func save(_ s: HubState?) throws { try KeychainData.save(service, try s.map { try $0.encoded() }) }
}

/// The phone's settings for a blind relay in the keychain.
enum RelayKeychain {
    static let service = "tools.cbb.relay"

    static func load() -> RelaySettings? { KeychainData.load(service).flatMap(RelaySettings.decode) }

    /// Keeps s; nil deletes it.
    static func save(_ s: RelaySettings?) throws { try KeychainData.save(service, try s.map { try $0.encoded() }) }
}
