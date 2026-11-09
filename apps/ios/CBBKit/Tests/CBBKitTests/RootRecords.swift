// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Crypto
import Foundation

// The root's own records as the kit built them before the core did
// (cbb_core::root): the tests build their groups with these, while the
// app asks the phone's member in the core (CoreMember.setKeyLevel and the
// rest).
extension PhoneGroup {
    /// Sets how long a claim waits before it takes effect (0 to 7 days;
    /// 72 hours without a settings record), as the current root. It
    /// returns the record to send.
    mutating func setTakeoverDelay(ms: Int64, rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        guard (0...7 * 24 * 3600 * 1000).contains(ms) else { throw Failure.invalidDelay }
        var b = Records.Body(type: "settings", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        // The newest settings record counts whole, so this one keeps the level.
        (b.takeover_delay_ms, b.key_level) = (ms, settings(of: Self.signer(rootSigner)).level)
        return try sign(b, caSigner: rootSigner)
    }

    /// Sets the group's key level (Records.keyLevels), as the current root,
    /// keeping the takeover delay; never a level this phone's own key does
    /// not pass. It returns the record to send. The admins whose keys the
    /// new level would not let in stay until the user removes them
    /// (belowKeyLevel lists them).
    mutating func setKeyLevel(_ level: String, rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        guard Records.keyLevels.contains(level) else { throw Failure.invalidKeyLevel }
        let own = devices.first { $0.id == device }?.store ?? Records.hardware
        guard Records.levelAllows(level, store: own, consent: true) else { throw Failure.belowKeyLevel }
        var b = Records.Body(type: "settings", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        (b.takeover_delay_ms, b.key_level) = (settings(of: Self.signer(rootSigner)).delay, level)
        return try sign(b, caSigner: rootSigner)
    }

    /// The admins, other than this phone, whose keys the level would not
    /// let in, by device ID.
    func belowKeyLevel(_ level: String) -> [String] {
        devices.filter { $0.id != device && $0.adminKey != nil && !Records.levelAllows(level, store: $0.store, consent: true) }
            .map(\.id)
    }

    /// What the newest settings record of the root whose key hash is root
    /// set, so that a new one keeps what it does not change.
    func settings(of root: Data) -> (delay: Int64?, level: String?) {
        var seq: Int64 = -1
        var out: (delay: Int64?, level: String?) = (nil, nil)
        for r in records.authorityRecords {
            guard let o = try? JSONSerialization.jsonObject(with: r.body) as? [String: Any], o["type"] as? String == "settings",
                  let s = o["signer"] as? String, Data(base64Encoded: s) == root,
                  let q = (o["seq"] as? NSNumber)?.int64Value, q > seq else { continue }
            seq = q
            out = ((o["takeover_delay_ms"] as? NSNumber)?.int64Value, o["key_level"] as? String)
        }
        return out
    }

    /// A new recovery key (docs/protocol.md, section 10, "The recovery
    /// key"): its 32 bytes, the admin CA the root issued it, the
    /// `recovery` record to send and the sheet to print. The app shows the
    /// sheet once and then forgets the key; nothing of it stays here.
    struct Recovery: Sendable {
        var key: Data
        var adminCA: Data
        var record: Member.Record
        var sheet: Core.RecoverySheet
    }

    /// Makes the group's recovery key, as the root: a new P-256 key, an
    /// admin CA for it under the current root (its CN names a random ID,
    /// since the key has no device) and the `recovery` record that names
    /// it, which replaces the recovery key before it.
    mutating func makeRecovery(rootSigner: CertificateSigner, now: Date) throws -> Recovery {
        guard isRoot else { throw Failure.notRoot }
        let key = P256.Signing.PrivateKey()
        let (ca, r) = try recovery(for: key.publicKey.derRepresentation, rootSigner: rootSigner, now: now)
        let sheet = try Core.recoverySheet(key: key.rawRepresentation, cert: ca, group: tag)
        return Recovery(key: key.rawRepresentation, adminCA: ca, record: r, sheet: sheet)
    }

    /// Makes the group's recovery key from a key a YubiKey made (publicKey,
    /// a SubjectPublicKeyInfo; Piv.generate), as the root: its admin CA,
    /// which goes into the YubiKey's slot, and the `recovery` record that
    /// names it.
    mutating func makeRecoveryOnCard(publicKey: Data, rootSigner: CertificateSigner, now: Date) throws -> (adminCA: Data, record: Member.Record) {
        guard isRoot else { throw Failure.notRoot }
        return try recovery(for: publicKey, rootSigner: rootSigner, now: now)
    }

    private mutating func recovery(for publicKey: Data, rootSigner: CertificateSigner, now: Date) throws -> (adminCA: Data, record: Member.Record) {
        let ca = try GroupCertificates.adminCA(device: Member.newID(), publicKey: publicKey, root: currentRoot, rootSigner: rootSigner)
        var b = Records.Body(type: "recovery", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        (b.admin, b.cert) = (try Records.keyHash(cert: ca), ca)
        return (ca, try sign(b, caSigner: rootSigner))
    }

    /// Removes the group's recovery key, as the root: a revocation of its
    /// key. It returns the record to send.
    mutating func removeRecovery(rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        guard let k = records.recovery else { throw Failure.noRecovery }
        var b = Records.Body(type: "revoke", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        b.keys = [k]
        return try sign(b, caSigner: rootSigner)
    }
}
