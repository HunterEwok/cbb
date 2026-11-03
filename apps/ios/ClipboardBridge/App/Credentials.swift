// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import ClipboardBridgeKit
import CryptoKit
import Foundation
import os

private let credentialLog = Logger(subsystem: "tools.cbb", category: "credentials")

/// The keys for the servers of each period (docs/protocol.md, section 18),
/// the server key and on the root the period key: in the Secure Enclave on
/// a device, without user presence, since they sign in the background.
/// The labels made are kept in the defaults, so keep can drop the others.
final class PhoneKeys: PeriodKeys, @unchecked Sendable {
    private static let prefix = "clipboardbridge.period."
    private static let made = "periodKeyLabels"
    private let lock = NSLock()

    private func label(_ kind: String, _ tag: String) -> String { "\(Self.prefix)\(kind).\(tag)" }

    private var labels: [String] {
        get { UserDefaults.standard.stringArray(forKey: Self.made) ?? [] }
        set { UserDefaults.standard.set(newValue, forKey: Self.made) }
    }

    func get(_ kind: String, tag: String) throws -> CertificateSigner {
        try lock.withLock {
            let l = label(kind, tag)
            if let k = try KeychainIdentity.loadKey(label: l) { return try SecKeySigner(k) }
            let k = try KeychainIdentity.makeKey(label: l, secureEnclave: LiveGroup.secureEnclave)
            labels = labels.filter { $0 != l } + [l]
            return try SecKeySigner(k)
        }
    }

    func has(_ kind: String, tag: String) -> Bool {
        lock.withLock { (try? KeychainIdentity.loadKey(label: label(kind, tag))) != nil }
    }

    func keep(_ tag: String) {
        lock.withLock {
            let (kept, gone) = (labels.filter { $0.hasSuffix(".\(tag)") }, labels.filter { !$0.hasSuffix(".\(tag)") })
            for l in gone { KeychainIdentity.removeKey(label: l) }
            labels = kept
        }
    }

    /// Drops every key for the servers, as when the phone makes or joins
    /// another group.
    func clear() { keep("") }
}

/// The group's server credentials for the node, which keeps them with
/// every member, in credentials.json beside the group.
final class CredentialBox: CredentialKeeper, @unchecked Sendable {
    private let lock = NSLock()
    private let url: URL
    private var store: CredentialStore
    private var _group: PhoneGroup
    /// Gets new credentials a peer sent, off the main actor.
    var onAdd: (@Sendable () -> Void)?

    init(url: URL, group: PhoneGroup) {
        (self.url, _group) = (url, group)
        var s = CredentialStore(groupCA: group.groupCA)
        if let data = try? Data(contentsOf: url), let saved = try? JSONDecoder().decode([ServerCredentials.Credential].self, from: data),
           let (root, isMember) = Self.root(group) {
            s.add(root: root, isMember: isMember, saved)
        }
        store = s
    }

    /// The group as it is now, for the lists and the current root.
    var group: PhoneGroup {
        get { lock.withLock { _group } }
        set { lock.withLock { _group = newValue } }
    }

    private static func root(_ g: PhoneGroup) -> (Data, (Data) -> Bool)? {
        guard let root = try? CertificateInfo(der: g.currentRoot).publicKey else { return nil }
        let devices = g.records.devices
        return (root, { k in devices.contains { !$0.frozen && $0.keys.contains(k) } })
    }

    private func saveLocked() {
        do {
            try JSONEncoder().encode(store.all).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            credentialLog.error("saving the server credentials: \(String(reflecting: error), privacy: .public)")
        }
    }

    var all: [ServerCredentials.Credential] { lock.withLock { store.all } }

    func add(_ credentials: [ServerCredentials.Credential]) -> [ServerCredentials.Credential] {
        let fresh: [ServerCredentials.Credential] = lock.withLock {
            guard let (root, isMember) = Self.root(_group) else { return [] }
            let (fresh, errors) = store.add(root: root, isMember: isMember, credentials)
            for e in errors { credentialLog.notice("dropped a server credential: \(e, privacy: .public)") }
            if !fresh.isEmpty { saveLocked() }
            return fresh
        }
        if !fresh.isEmpty { onAdd?() }
        return fresh
    }

    /// What the phone registers with at a blind relay once the members'
    /// credential lists its server key, so the relay knows it only by a
    /// pseudonym; nil until then.
    func relayCredentials(keys: PhoneKeys) -> RelayOnPhone.Credentials? {
        lock.withLock {
            guard let root = try? CertificateInfo(der: _group.currentRoot).publicKey,
                  let tag = store.period(root: root)?.1.tag, keys.has(PeriodKeyKind.serverKey, tag: tag),
                  let k = (try? keys.get(PeriodKeyKind.serverKey, tag: tag)) as? SecKeySigner,
                  let reg = store.registration(records: _group.records, root: root, mine: Data(SHA256.hash(data: k.publicKeyDER)))
            else { return nil }
            return RelayOnPhone.Credentials(serverKey: k.publicKeyDER, sign: { try k.signature(digest: $0) }, registration: reg)
        }
    }

    /// Brings the credentials up to date as far as this phone can
    /// (CredentialRefresh) and returns what it signed, for the peers.
    func refresh(member: CertificateSigner, keys: PeriodKeys, rootSigner: (() -> CertificateSigner?)?) -> [ServerCredentials.Credential] {
        lock.withLock {
            let g = _group
            do {
                let signed = try CredentialRefresh.refresh(&store, records: g.records, groupCA: g.groupCA, root: g.currentRoot, member: member,
                                                           keys: keys, nowMS: Int64(Date().timeIntervalSince1970 * 1000), rootSigner: rootSigner)
                if !signed.isEmpty { saveLocked() }
                return signed
            } catch {
                credentialLog.error("signing the server credentials: \(String(reflecting: error), privacy: .public)")
                return []
            }
        }
    }
}
