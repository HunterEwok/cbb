// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.time.Instant

// The root's own records as the kit signed them before the core took them
// over (cbb_core::root, through CoreMember): the tests build their groups
// with them. The apps ask the core's member for these records.

const val INVALID_DELAY = "the delay before a claim takes effect is 0 to 7 days"
const val INVALID_KEY_LEVEL = "the key level is proven, hardware or files"

/**
 * Sets how long a claim waits before it takes effect (0 to 7 days; 72
 * hours without a settings record), as the current root. It returns the
 * record to send.
 */
fun PhoneGroup.setTakeoverDelay(ms: Long, rootSigner: CertificateSigner, now: Instant): Member.Record {
    if (!isRoot) throw PhoneGroup.Failure("only the root does that")
    if (ms !in 0..7L * 24 * 3600 * 1000) throw PhoneGroup.Failure(INVALID_DELAY)
    val b = Records.Body.of("settings", rootSigner, now)
    b.takeoverDelayMS = ms
    // The newest settings record counts whole, so this one keeps the level.
    b.keyLevel = settings(b.signer).second
    return sign(b, rootSigner)
}

/**
 * Sets the group's key level (Records.KEY_LEVELS), as the current root,
 * keeping the takeover delay; never a level this phone's own key does
 * not pass. It returns the record to send. The admins whose keys the new
 * level would not let in stay until the user removes them (belowKeyLevel
 * lists them).
 */
fun PhoneGroup.setKeyLevel(level: String, rootSigner: CertificateSigner, now: Instant): Member.Record {
    if (!isRoot) throw PhoneGroup.Failure("only the root does that")
    if (level !in Records.KEY_LEVELS) throw PhoneGroup.Failure(INVALID_KEY_LEVEL)
    val own = devices.firstOrNull { it.id == device }?.store ?: Records.HARDWARE
    if (!Records.levelAllows(level, own, true)) throw PhoneGroup.BelowKeyLevel()
    val b = Records.Body.of("settings", rootSigner, now)
    b.takeoverDelayMS = settings(b.signer).first
    b.keyLevel = level
    return sign(b, rootSigner)
}

/** The admins, other than this phone, whose keys the level would not let in, by device ID. */
fun PhoneGroup.belowKeyLevel(level: String): List<String> =
    devices.filter { it.id != device && it.adminKey != null && !Records.levelAllows(level, it.store, true) }.map { it.id }

/** What the newest settings record of the root whose key hash is root set, so that a new one keeps what it does not change. */
fun PhoneGroup.settings(root: ByteArray): Pair<Long?, String?> {
    var seq = -1L
    var out: Pair<Long?, String?> = null to null
    for (r in records.authorityRecords) {
        runCatching {
            val o = Wire.parse(r.body) ?: return@runCatching
            val q = o.optLong("seq") ?: return@runCatching
            if (o.optString("type") != "settings" || o.optBytes("signer")?.contentEquals(root) != true || q <= seq) return@runCatching
            seq = q
            out = o.optLong("takeover_delay_ms") to o.optString("key_level")
        }
    }
    return out
}

/**
 * A new recovery key (docs/protocol.md, section 10, "The recovery key"):
 * its 32 bytes, the admin CA the root issued it, the `recovery` record to
 * send and the sheet to print. The app shows the sheet once and then
 * forgets the key; nothing of it stays here.
 */
class Recovery(val key: ByteArray, val adminCA: ByteArray, val record: Member.Record, val sheet: Core.RecoverySheet)

/**
 * Makes the group's recovery key, as the root: a new P-256 key, an admin
 * CA for it under the current root (its CN names a random ID, since the
 * key has no device) and the `recovery` record that names it, which
 * replaces the recovery key before it.
 */
fun PhoneGroup.makeRecovery(rootSigner: CertificateSigner, now: Instant): Recovery {
    if (!isRoot) throw PhoneGroup.Failure("only the root makes the recovery key")
    val pair = SoftwareSigner.generate()
    val s = (pair.private as java.security.interfaces.ECPrivateKey).s.toByteArray().takeLast(32)
    val key = ByteArray(32 - s.size) + s.toByteArray()
    val (ca, r) = recoveryFor(pair.public.encoded, rootSigner, now)
    return Recovery(key, ca, r, Core.recoverySheet(key, ca, tag))
}

/**
 * Makes the group's recovery key from a key a YubiKey made (publicKey, a
 * SubjectPublicKeyInfo; [Piv.generate]), as the root: its admin CA,
 * which goes into the YubiKey's slot, and the `recovery` record that
 * names it.
 */
fun PhoneGroup.makeRecoveryOnCard(publicKey: ByteArray, rootSigner: CertificateSigner, now: Instant): Pair<ByteArray, Member.Record> {
    if (!isRoot) throw PhoneGroup.Failure("only the root makes the recovery key")
    return recoveryFor(publicKey, rootSigner, now)
}

private fun PhoneGroup.recoveryFor(publicKey: ByteArray, rootSigner: CertificateSigner, now: Instant): Pair<ByteArray, Member.Record> {
    val ca = GroupCertificates.adminCA(SyncEngine.newID(), publicKey, currentRoot, rootSigner)
    val b = Records.Body.of("recovery", rootSigner, now)
    b.admin = Records.keyHashOfCert(ca)
    b.cert = ca
    return ca to sign(b, rootSigner)
}

/** Removes the group's recovery key, as the root: a revocation of its key. It returns the record to send. */
fun PhoneGroup.removeRecovery(rootSigner: CertificateSigner, now: Instant): Member.Record {
    if (!isRoot) throw PhoneGroup.Failure("only the root removes the recovery key")
    val k = records.recovery ?: throw PhoneGroup.Failure("the group has no recovery key")
    val b = Records.Body.of("revoke", rootSigner, now)
    b.keys = listOf(k)
    return sign(b, rootSigner)
}
