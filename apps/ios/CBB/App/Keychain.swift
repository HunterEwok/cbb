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

    /// In the app's own access group, never the push group's.
    private static func query(_ service: String) -> [String: Any] {
        let q = KeychainIdentity.inGroup([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: "state"])
        return Dictionary(uniqueKeysWithValues: q.map { ($0.key as String, $0.value) })
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

/// What the user chose for the hub on a group of 0.6 (AwayOn06.Prefs) in
/// the keychain; the Live member keeps the hub's keys and clients itself.
enum Hub06Keychain {
    static let service = "tools.cbb.hub06"

    static func load() -> AwayOn06.Prefs? { KeychainData.load(service).flatMap(AwayOn06.Prefs.decode) }

    /// Keeps p; nil deletes it.
    static func save(_ p: AwayOn06.Prefs?) throws { try KeychainData.save(service, try p.map { try $0.encoded() }) }
}
