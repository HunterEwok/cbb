// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.time.Instant

/** Record bodies of version 2 for the tests, signed through the set. */
object V2 {
    fun device(
        device: String,
        name: String,
        role: String,
        key: ByteArray,
        signer: CertificateSigner,
        now: Instant,
        admin: ByteArray? = null,
        powers: List<String>? = null,
        holdsRoot: Boolean = false,
    ): Records.Body {
        val b = Records.Body.of("device", signer, now)
        b.device = device
        b.name = name
        b.role = role
        b.key = key
        b.admin = admin
        if (admin != null) {
            val (p, c) = Records.grants(role)
            b.powers = powers ?: p
            b.commands = c
        }
        b.holdsRoot = holdsRoot
        return b
    }

    fun revoke(keys: List<ByteArray>, signer: CertificateSigner, now: Instant): Records.Body {
        val b = Records.Body.of("revoke", signer, now)
        b.keys = keys
        return b
    }

    fun claim(root: ByteArray, signer: CertificateSigner, now: Instant): Records.Body {
        val b = Records.Body.of("claim", signer, now)
        b.root = root
        return b
    }
}

/** Signs body as the signer's next record and adds it; returns the record. */
fun RecordSet.signed(body: Records.Body, signer: CertificateSigner, groupCA: ByteArray, adminCA: ByteArray? = null): Member.Record {
    if (this.groupCA == null) this.groupCA = groupCA
    val r = sign(body, signer, adminCA)
    add(r, groupCA)
    return r
}
