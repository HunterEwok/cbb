// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation

/// Record bodies of version 2 for the tests, signed through the set.
extension Records.Body {
    static func device(_ device: String, name: String, role: String, key: Data, admin: Data? = nil, powers: [String]? = nil,
                       commands: [String]? = nil, holdsRoot: Bool = false, caps: [String]? = nil, signer: CertificateSigner, now: Date) -> Records.Body {
        var b = Records.Body(type: "device", signer: Records.keyHash(spki: signer.publicKeyDER), timeMS: Records.ms(now))
        (b.device, b.name, b.role, b.key, b.admin) = (device, name, role, key, admin)
        b.caps = caps ?? (role == "member" ? Records.caps : nil)
        if admin != nil {
            let g = PhoneGroup.grants(role: role)
            (b.powers, b.commands) = (powers ?? g.powers, commands ?? g.commands)
        }
        if holdsRoot { b.holds_root = true }
        return b
    }

    static func revoke(_ keys: [Data], signer: CertificateSigner, now: Date) -> Records.Body {
        var b = Records.Body(type: "revoke", signer: Records.keyHash(spki: signer.publicKeyDER), timeMS: Records.ms(now))
        b.keys = keys
        return b
    }
}

extension RecordSet {
    /// Signs body as the signer's next record and adds it; returns the record.
    @discardableResult
    mutating func signed(_ body: Records.Body, _ signer: CertificateSigner, adminCA: Data? = nil, groupCA: Data) throws -> Member.Record {
        if self.groupCA == nil { self.groupCA = groupCA }
        let r = try sign(body, with: signer, adminCA: adminCA)
        add(r, groupCA: groupCA)
        return r
    }
}
