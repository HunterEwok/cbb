// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.io.File
import java.time.Instant

/**
 * A phone group (docs/protocol.md, sections 9 and 10) as this phone holds
 * it: the group CA, the phone's own member certificate, the computers it
 * admitted and the records. The phone is the root, which made the group,
 * an admin with an admin CA under the root, or a member without either.
 * The keys stay outside, in the Android Keystore. It is saved as JSON next
 * to the app's other data.
 */
class PhoneGroup internal constructor(
    /** This phone's device ID. */
    val device: String,
    /** The group root CA, DER; path length 1. The group's first root, which names it for good. */
    val groupCA: ByteArray,
    /** This phone's member certificate, DER, from one of the roots or from memberIssuer. */
    var memberCert: ByteArray,
) {
    /** The roots that took the group over from groupCA, in order, DER; the last is the current root (section 10, "Roots"). */
    var roots: List<ByteArray> = emptyList()
        internal set

    /** The admin CA that issued memberCert, which the phone sends after it in TLS handshakes; null when a root did. */
    var memberIssuer: ByteArray? = null
        internal set

    /** Whether this phone holds the current root's key: it made the group, or took it over. */
    var isRoot = true
        internal set

    /** This phone's admin CA when it is an admin but not the root. */
    var adminCA: ByteArray? = null
        internal set

    val computers = mutableListOf<Computer>()

    /** The group's signed device and revocation records; admins sign them, and they spread to every member. */
    var records = RecordSet()
        internal set

    /**
     * The admin CAs this phone, as the root, issued to computers, DER, by
     * device ID: sent again to a computer that offers the same admin key
     * (section 10, "A computer as admin").
     */
    val computerAdmins = mutableMapOf<String, ByteArray>()

    /**
     * The new root of this admin's claim to take the group over, DER, while
     * the claim waits (docs/protocol.md, section 10, "Handing the group over"); its
     * key stays in the Keystore until the claim takes effect or ends.
     */
    var claim: ByteArray? = null
        internal set

    /** The device of the root that claim takes the group over from, which the new root removes. */
    var claimedFrom: String? = null
        internal set

    /** A computer this phone admitted. */
    data class Computer(
        val device: String,
        val name: String,
        /** "linux", "windows" or "macos", as its pairing Info says. */
        val os: String,
        val cert: ByteArray,
        val admitted: Instant,
        /**
         * Its addresses on the home network from the QR code, the one that
         * answered first: dialed when mDNS does not find it, as in another
         * subnet (docs/protocol.md, section 9).
         */
        val addrs: List<String> = emptyList(),
    ) {
        override fun equals(other: Any?): Boolean =
            other is Computer && device == other.device && name == other.name && os == other.os && cert.contentEquals(other.cert) &&
                admitted == other.admitted && addrs == other.addrs

        override fun hashCode(): Int = device.hashCode()
    }

    class Failure(message: String) : Exception(message)

    /**
     * The computer keeps its keys in a file, which a thief with it can copy
     * and then act as an admin: the user allows it after a warning
     * (docs/protocol.md, section 17).
     */
    class FileKey : Exception("its keys sit in a file")

    /** The computer is a rootless install, which is never an admin (D-79). */
    class Rootless : Exception("it is installed without root")

    /** An admin, or the root's own device, reads the copies: it is no hub that only passes them on. */
    class ReadsCopies : Exception("it reads the copies")

    /** The group's key level does not let the device's keys be an admin or the root; the root sets another level first. */
    class BelowKeyLevel : Exception("the group's key level does not let these keys in")

    /** Whether this phone may admit devices, renew certificates and remove devices: the root and the admins. */
    val isAdmin: Boolean get() = isRoot || adminCA != null

    /** The certificate chain this phone presents in TLS, leaf first. */
    val memberChain: List<ByteArray> get() = listOf(memberCert) + listOfNotNull(memberIssuer)

    /** The current root: the last of roots, or the group CA. */
    val currentRoot: ByteArray get() = roots.lastOrNull() ?: groupCA

    /** Every root the group had, the group CA first: member certificates and admin CAs from any of them verify. */
    val trusted: List<ByteArray> get() = listOf(groupCA) + roots

    /** The CA whose key signs for this phone: the current root, or its admin CA. */
    internal val signingCA: ByteArray get() = adminCA ?: currentRoot

    /** The home network addresses of the computers this phone admitted, by device ID, best first. */
    val addresses: Map<String, List<String>> get() = computers.filter { it.addrs.isNotEmpty() }.associate { it.device to it.addrs }

    /** The group tag the computers publish. */
    val tag: String get() = GroupCertificates.tag(groupCA)

    /** The devices of the group, from the records. */
    val devices: List<RecordSet.Device> get() = records.devices

    /** Adds records from other members, then follows the roots they lead to when they differ from this phone's; returns the new records. */
    fun add(rs: List<Member.Record>): List<Member.Record> {
        val fresh = records.addAll(rs, groupCA)
        adoptRoots()
        return fresh
    }

    /**
     * Takes the roots of the records when they differ from roots, compared by content, so a root the records do not
     * name never stays trusted; an empty set says nothing yet.
     */
    fun adoptRoots() {
        val path = records.roots
        if (records.records.isNotEmpty() && (path.size != roots.size || path.zip(roots).any { (a, b) -> !a.contentEquals(b) })) roots = path
    }

    /** Signs body with caSigner, the root's own key or this phone's admin key, and adds it to the set. */
    internal fun sign(body: Records.Body, caSigner: CertificateSigner): Member.Record {
        if (records.groupCA == null) records.groupCA = groupCA
        val r = records.sign(body, caSigner, if (isRoot) null else adminCA)
        records.add(r, groupCA)
        return r
    }

    /**
     * Signs and adds a device record. A record that makes an admin gives it
     * the powers of its role unless powers names them, and the root's record
     * of its own device says that it holds the root.
     */
    internal fun record(
        device: String,
        name: String,
        role: String,
        key: ByteArray,
        caSigner: CertificateSigner,
        now: Instant,
        admin: ByteArray? = null,
        os: String? = null,
        store: String? = null,
        kind: String? = null,
        proof: String? = null,
        powers: List<String>? = null,
        commands: List<String>? = null,
        seal: ByteArray? = null,
        forwardOnly: Boolean = false,
    ): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val b = Records.Body.of("device", caSigner, now)
        b.device = device
        b.name = name
        b.role = role
        b.os = os
        b.key = key
        b.admin = admin
        b.store = store
        b.kind = kind
        b.proof = proof
        b.seal = seal
        b.forwardOnly = forwardOnly
        if (admin != null) {
            val (p, c) = Records.grants(role)
            b.powers = powers ?: p
            b.commands = commands ?: c
        }
        if (isRoot && device == this.device) b.holdsRoot = true
        return sign(b, caSigner)
    }

    /** record for d again, with its powers when it is an admin. */
    private fun recordAgain(d: RecordSet.Device, caSigner: CertificateSigner, now: Instant, name: String = d.name, store: String = d.store, kind: String? = d.kind, proof: String? = d.proof, admin: ByteArray? = d.adminKey): Member.Record =
        record(
            d.id, name, d.role, d.key, caSigner, now, admin, d.os, store, kind, proof,
            d.powers.takeIf { admin != null && admin.contentEqualsOrNull(d.adminKey) && it.isNotEmpty() },
            d.commands.takeIf { admin != null && admin.contentEqualsOrNull(d.adminKey) && it.isNotEmpty() },
            d.seal,
            d.forwardOnly,
        )

    /**
     * Claims the group for this admin phone when the root phone lost is gone
     * (docs/protocol.md, section 10, "Handing the group over"): a claim, signed with
     * this phone's admin key (adminSigner), that hands the group to newRoot,
     * a root CA for a new key of this phone. The claim waits the group's
     * delay (72 hours unless the root set another), and the root cancels it
     * meanwhile if it is still in use; [finishTakeOver] then makes this phone
     * the root. It returns the record to send.
     */
    fun takeOver(lost: String, adminSigner: CertificateSigner, newRoot: ByteArray, now: Instant): Member.Record {
        if (adminCA == null || isRoot) throw Failure("this phone is no admin")
        if (lost != records.rootDevice || lost == device) throw Failure("that phone does not hold the root")
        return makeClaim(lost, adminSigner, newRoot, now)
    }

    /**
     * Whether the group's root handed the group to this phone's admin key
     * (`cbb handover`, docs/protocol.md, section 10, "Handing the group
     * over"), and this phone has not claimed it yet.
     */
    val handedToMe: Boolean
        get() {
            val ca = adminCA ?: return false
            if (isRoot || claim != null) return false
            val to = records.handedTo ?: return false
            return runCatching { Records.keyHashOfCert(ca) }.getOrNull()?.contentEquals(to) == true
        }

    /**
     * Takes the group the root handed to this phone: a claim, as in
     * [takeOver], that takes effect at once because the root signed a
     * handover for this phone's admin key; [finishTakeOver] then makes this
     * phone the root. The old root's device stays in the group. It returns
     * the record to send.
     */
    fun takeHandedOver(adminSigner: CertificateSigner, newRoot: ByteArray, now: Instant): Member.Record {
        if (!handedToMe) throw Failure("the group was not handed to this phone")
        return makeClaim(null, adminSigner, newRoot, now)
    }

    /**
     * Claims the group with its recovery key (docs/protocol.md, section
     * 10, "The recovery key"), on a new phone that [Restore] made a member
     * of it under the key's admin CA: a claim, signed with the recovery key
     * (recoverySigner), that hands the group to newRoot, as in [takeOver].
     * The lost root's device goes when it takes effect. It returns the
     * record to send.
     */
    internal fun claimWithRecovery(recoverySigner: CertificateSigner, newRoot: ByteArray, now: Instant): Member.Record {
        val ca = adminCA ?: throw Failure("this phone holds no recovery key")
        if (isRoot) throw Failure("this phone is the group's root already")
        if (claim != null) throw Failure(CLAIM_WAITING)
        if (records.recovery?.contentEquals(Records.keyHashOfCert(ca)) != true) throw Failure(Restore.NOT_THE_KEY)
        val b = Records.Body.of("claim", recoverySigner, now)
        b.root = newRoot
        val r = sign(b, recoverySigner)
        claim = newRoot
        claimedFrom = records.rootDevice
        return r
    }

    private fun makeClaim(lost: String?, adminSigner: CertificateSigner, newRoot: ByteArray, now: Instant): Member.Record {
        if (claim != null) throw Failure(CLAIM_WAITING)
        val me = devices.firstOrNull { it.id == device }
        if (me == null || !me.may("takeover")) throw Failure(NO_TAKEOVER)
        val b = Records.Body.of("claim", adminSigner, now)
        b.root = newRoot
        val r = sign(b, adminSigner)
        claim = newRoot
        claimedFrom = lost
        return r
    }

    /** The state of this phone's claim, as the records say ("pending", "effective", "cancelled", "void" and the others); null without one. */
    val claimState: String?
        get() {
            val c = claim ?: return null
            val k = runCatching { Records.keyHashOfCert(c) }.getOrNull() ?: return null
            return records.claims.lastOrNull { it.root.contentEquals(k) }?.state
        }

    /** Drops this phone's claim when the root cancelled it or it became void; reports whether it did. */
    fun dropEndedClaim(): Boolean {
        val st = claimState
        if (st != "cancelled" && st != "void") return false
        claim = null
        claimedFrom = null
        return true
    }

    /**
     * Makes this phone the root once the records make its claim's new root
     * the current root, and signs what a new root starts with: its own device
     * that holds the root, the admins it keeps, and a removal of the lost
     * root's device. rootSigner is the new root's key. A
     * phone that claimed with the recovery key has no device record yet: the
     * new root signs one, under name, with seal. This phone's member
     * certificate is reissued from the new root, as a root admits only with
     * a certificate of its own. A claim that was cancelled or became void is
     * dropped. It returns the records to send; none while the claim waits.
     */
    fun finishTakeOver(rootSigner: CertificateSigner, now: Instant, name: String = "Android", seal: ByteArray? = null): List<Member.Record> {
        records.refresh()
        adoptRoots()
        val c = claim ?: return emptyList()
        if (!currentRoot.contentEquals(c)) {
            dropEndedClaim()
            return emptyList()
        }
        val lost = claimedFrom
        val list = devices
        isRoot = true
        claim = null
        claimedFrom = null
        val out = mutableListOf<Member.Record>()
        val memberKey = CertificateInfo(memberCert).publicKey
        memberCert = GroupCertificates.member(device, memberKey, currentRoot, rootSigner, now)
        memberIssuer = null
        val me = list.firstOrNull { it.id == device }
        out += if (me != null) {
            record(device, me.name, "phone", me.key, rootSigner, now, os = me.os ?: "android", store = me.store, kind = me.kind, proof = me.proof, seal = me.seal)
        } else {
            record(device, validName(name), "phone", Records.keyHash(memberKey), rootSigner, now, os = "android", store = Records.HARDWARE, seal = seal)
        }
        val revoke = mutableListOf<ByteArray>()
        for (d in list) {
            if (d.id == device) continue
            val admin = d.adminKey
            if (d.id == lost) {
                revoke += d.keys
            } else if (admin != null && !d.frozen) {
                out += record(d.id, d.name, d.role, d.key, rootSigner, now, admin, d.os, d.store, d.kind, d.proof, d.powers, d.commands, d.seal, d.forwardOnly)
            }
        }
        if (revoke.isNotEmpty()) {
            val b = Records.Body.of("revoke", rootSigner, now)
            b.keys = revoke.distinctBy { it.toHex() }.sortedWith { a, b2 -> compareBytes(a, b2) }
            out += sign(b, rootSigner)
        }
        // The state counts only the current root's settings: the old root's
        // go on under this one, the takeover delay and key level.
        val old = Records.keyHashOfCert(if (roots.size >= 2) roots[roots.size - 2] else groupCA)
        val (delay, level) = settings(old)
        if (delay != null || level != null) {
            val b = Records.Body.of("settings", rootSigner, now)
            b.takeoverDelayMS = delay
            b.keyLevel = level
            out += sign(b, rootSigner)
        }
        adminCA = null
        return out
    }

    /**
     * Cancels claims, or ends a conflict, as the current root
     * (docs/protocol.md, section 10, "Chains and numbers"): a resolve that voids the records with
     * the IDs ids. It returns the record to send.
     */
    fun resolve(ids: List<ByteArray>, rootSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isRoot) throw Failure("only the root does that")
        val b = Records.Body.of("resolve", rootSigner, now)
        b.records = ids
        return sign(b, rootSigner)
    }

    /**
     * Sets how long a claim waits before it takes effect (0 to 7 days; 72
     * hours without a settings record), as the current root. It returns the
     * record to send.
     */
    fun setTakeoverDelay(ms: Long, rootSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isRoot) throw Failure("only the root does that")
        if (ms !in 0..7L * 24 * 3600 * 1000) throw Failure(INVALID_DELAY)
        val b = Records.Body.of("settings", rootSigner, now)
        b.takeoverDelayMS = ms
        // The newest settings record counts whole, so this one keeps the level.
        b.keyLevel = settings(b.signer).second
        return sign(b, rootSigner)
    }

    /** The group's key level: which keys may be its root, an admin or a hub. */
    val keyLevel: String get() = records.keyLevel

    /** How long a copy from another device stays live after it arrives, in milliseconds: written to the clipboard until then, never after. */
    val incomingMS: Long get() = records.incomingMS

    /**
     * Sets how long a copy from another device stays live after it arrives
     * (5 s to 1 h), as the root or an admin: a copies record
     * (docs/protocol.md, section 10, "The copies setting"). It returns the
     * record to send.
     */
    fun setIncoming(ms: Long, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        if (ms !in Records.INCOMING_BOUNDS) throw Failure(INVALID_INCOMING)
        val b = Records.Body.of("copies", caSigner, now)
        b.incomingMS = ms
        return sign(b, caSigner)
    }

    /**
     * Sets the group's key level (Records.KEY_LEVELS), as the current root,
     * keeping the takeover delay; never a level this phone's own key does
     * not pass. It returns the record to send. The admins whose keys the new
     * level would not let in stay until the user removes them (belowKeyLevel
     * lists them).
     */
    fun setKeyLevel(level: String, rootSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isRoot) throw Failure("only the root does that")
        if (level !in Records.KEY_LEVELS) throw Failure(INVALID_KEY_LEVEL)
        val own = devices.firstOrNull { it.id == device }?.store ?: Records.HARDWARE
        if (!Records.levelAllows(level, own, true)) throw BelowKeyLevel()
        val b = Records.Body.of("settings", rootSigner, now)
        b.takeoverDelayMS = settings(b.signer).first
        b.keyLevel = level
        return sign(b, rootSigner)
    }

    /** The admins, other than this phone, whose keys the level would not let in, by device ID. */
    fun belowKeyLevel(level: String): List<String> =
        devices.filter { it.id != device && it.adminKey != null && !Records.levelAllows(level, it.store, true) }.map { it.id }

    /** What the newest settings record of the root whose key hash is root set, so that a new one keeps what it does not change. */
    internal fun settings(root: ByteArray): Pair<Long?, String?> {
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
     * Renews this phone's own member certificate when it is due; reports
     * whether it did, after which the TLS identity must be made again. An
     * admin issues it from its own admin CA, a phone without one cannot.
     */
    fun renewOwnCertificate(caSigner: CertificateSigner, now: Instant): Boolean {
        if (!isAdmin || !GroupCertificates.isDue(memberCert, signingCA, now)) return false
        if (runCatching { GroupCertificates.verifyMember(memberChain, trusted, now) }.getOrNull() != device) return false
        memberCert = GroupCertificates.member(device, CertificateInfo(memberCert).publicKey, signingCA, caSigner, now)
        memberIssuer = adminCA
        return true
    }

    /** A renewed member certificate for a peer, DER, and the admin CA that issued it; null when a root did. */
    class Renewal(val cert: ByteArray, val issuer: ByteArray? = null)

    /**
     * A renewed certificate for a peer's chain (leaf first) when it is due
     * and this phone is an admin: the root issues it from its root, an admin
     * from its admin CA, which the cert message carries, whoever issued the
     * old one (as a removed admin did).
     */
    fun renewal(chain: List<ByteArray>, caSigner: CertificateSigner, now: Instant): Renewal? {
        if (!isAdmin) return null
        val cert = runCatching { GroupCertificates.renewal(chain, trusted, caSigner, now, adminCA) }.getOrNull() ?: return null
        return Renewal(cert, adminCA)
    }

    /**
     * Removes a device from the group: signs a revocation of every key it
     * had, and of its admin key for an admin, which every member then
     * refuses, and returns the record to send. What an admin signed before
     * stays (docs/protocol.md, section 10, "Removals and freezes keep what the author
     * saw"). The root phone is taken over with takeOver instead.
     */
    fun revoke(device: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        if (device == this.device) throw Failure("this phone cannot remove itself")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (device == records.rootDevice) throw Failure("the root phone is removed by taking the group over")
        val keys = d.keys.toMutableList()
        d.adminKey?.let { a -> if (keys.none { it.contentEquals(a) }) keys.add(a) }
        val b = Records.Body.of("revoke", caSigner, now)
        b.keys = keys
        val r = sign(b, caSigner)
        computers.removeAll { it.device == device }
        computerAdmins.remove(device)
        return r
    }

    /**
     * Gives a device another name: a device record like its newest one with
     * that name, which names it everywhere, since the newest record of a
     * device counts (section 10). An admin renames any device, itself and
     * the root included. name is trimmed; it must have 1 to 64 bytes and no
     * control characters.
     */
    fun rename(device: String, name: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        val n = name.trim()
        if (n.isEmpty() || validName(n) != n) throw Failure(INVALID_NAME)
        return recordAgain(d, caSigner, now, name = n)
    }

    /**
     * Signs the device record that makes a computer that is no admin a hub
     * that only passes the copies on (docs/protocol.md, section 11, "Two
     * kinds of hub"): `forward_only`, which no key level limits; from then
     * on no copy is sealed to it. null when its record says so already.
     */
    fun markForwardOnly(device: String, caSigner: CertificateSigner, now: Instant): Member.Record? {
        if (!isAdmin) throw Failure("this phone is no admin")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (d.forwardOnly) return null
        if (d.role != "full") throw Failure("not a computer")
        if (d.frozen) throw Failure("frozen: unfreeze it or remove it")
        if (d.store == Records.ROOTLESS) throw Rootless()
        if (d.adminKey != null || device == records.rootDevice) throw ReadsCopies()
        return record(d.id, d.name, d.role, d.key, caSigner, now, null, d.os, d.store, d.kind, d.proof, seal = d.seal, forwardOnly = true)
    }

    /** The key for sealed messages that the device record of to names, which an admin's commands for it are sealed to (section 15, "Sealed commands"); null when it has none. */
    internal fun sealKey(to: String): ByteArray? = devices.firstOrNull { it.id == to }?.seal

    /**
     * A command that sets a computer's sync mode (docs/protocol.md,
     * section 15), signed with this phone's root or admin key; the caller
     * sends it to that computer alone.
     */
    fun modeCommand(to: String, mode: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.mode(to, mode, tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /**
     * A paste command that puts text where the focus of the member to is
     * (docs/protocol.md, section 15; design.md, "Remote paste"), by method
     * "paste" or "type", then Enter when enter is set; signed as
     * modeCommand.
     */
    fun pasteCommand(to: String, text: String, method: String, enter: Boolean, secret: Boolean, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.paste(to, text, method, enter, if (secret) "secret" else "text", tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /**
     * An action command that runs the quick action name on the member to,
     * signed with this phone's root or admin key; the member defines what
     * it does.
     */
    fun actionCommand(to: String, name: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.action(to, name, tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /** An actions-off command that turns every quick action off on the member to. */
    fun actionsOffCommand(to: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.actionsOff(to, tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /**
     * A mute command that keeps the copies of the member to from the whole group for forMS milliseconds, 0 for
     * until an unmute command (design.md, "Muting a device"); any admin phone signs one.
     */
    fun muteCommand(to: String, forMS: Long, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.mute(to, forMS, tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /** An unmute command that ends an admin's mute of the member to. */
    fun unmuteCommand(to: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        return Commands.unmute(to, tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /**
     * A hub command that makes the admin computer to the group's hub in
     * place of this phone (docs/protocol.md, section 11, "Moving the hub"),
     * signed with this phone's root or admin key, with the hub's clients
     * and its forwarder ("ip:port" and the pin of its key).
     */
    fun hubCommand(
        to: String,
        forwarder: Pair<String, String>?,
        clients: List<PhoneHub.Client>,
        caSigner: CertificateSigner,
        now: Instant,
    ): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        if (!records.mayHost(to)) throw Failure("only the group's root or an admin can be its hub")
        return Commands.hub(to, forwarder, emptyList(), clients.filter { it.device != to }, tag, device, now, caSigner, adminCA, seal = sealKey(to))
    }

    /**
     * Unfreezes an admin computer that another admin froze (section 10,
     * rule 4): a thaw record that ends every freeze of it. The root and the
     * admin phones do it; Remove takes the computer out for good instead.
     */
    fun thaw(device: String, caSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isAdmin) throw Failure("this phone is no admin")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (!d.frozen || d.adminKey == null || d.freezes.isEmpty()) throw Failure("not frozen")
        val b = Records.Body.of("thaw", caSigner, now)
        b.records = d.freezes
        return sign(b, caSigner)
    }

    /**
     * Makes a computer an admin (section 10, "A computer as admin"): the
     * root issues an admin CA for the admin key the computer's hello offered
     * (a SubjectPublicKeyInfo) and signs its device record again, naming that
     * CA. It returns the admin CA, for the admin message, and the record to
     * send. Only the root makes admins. keyStore is where the computer's
     * hello says its keys live; one that keeps them in a file becomes an
     * admin only with allowFileKey, else it throws FileKey, and a rootless
     * install never (Rootless).
     */
    fun makeAdmin(
        device: String,
        adminKey: ByteArray,
        rootSigner: CertificateSigner,
        now: Instant,
        keyStore: String? = null,
        allowFileKey: Boolean = false,
    ): Pair<ByteArray, Member.Record> {
        if (!isRoot) throw Failure("only the root makes admins")
        val d = devices.firstOrNull { it.id == device } ?: throw Failure("unknown device")
        if (d.role != "full") throw Failure("not a computer")
        if (d.frozen) throw Failure("frozen: unfreeze it or remove it")
        val proven = d.store == Records.PROVEN
        val store = if (proven) d.store else Records.storeOf(keyStore, d.role)
        if (store == Records.ROOTLESS || d.store == Records.ROOTLESS) throw Rootless()
        if (!Records.levelAllows(keyLevel, store, true)) throw BelowKeyLevel()
        if (store == Records.FILE && !allowFileKey) throw FileKey()
        val ca = GroupCertificates.adminCA(device, adminKey, currentRoot, rootSigner)
        val r = record(
            device, d.name, d.role, d.key, rootSigner, now, Records.keyHashOfCert(ca), d.os, store,
            d.kind.takeIf { proven }, d.proof.takeIf { proven }, seal = d.seal,
        )
        computerAdmins[device] = ca
        return ca to r
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
    fun makeRecovery(rootSigner: CertificateSigner, now: Instant): Recovery {
        if (!isRoot) throw Failure("only the root makes the recovery key")
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
    fun makeRecoveryOnCard(publicKey: ByteArray, rootSigner: CertificateSigner, now: Instant): Pair<ByteArray, Member.Record> {
        if (!isRoot) throw Failure("only the root makes the recovery key")
        return recoveryFor(publicKey, rootSigner, now)
    }

    private fun recoveryFor(publicKey: ByteArray, rootSigner: CertificateSigner, now: Instant): Pair<ByteArray, Member.Record> {
        val ca = GroupCertificates.adminCA(SyncEngine.newID(), publicKey, currentRoot, rootSigner)
        val b = Records.Body.of("recovery", rootSigner, now)
        b.admin = Records.keyHashOfCert(ca)
        b.cert = ca
        return ca to sign(b, rootSigner)
    }

    /** Removes the group's recovery key, as the root: a revocation of its key. It returns the record to send. */
    fun removeRecovery(rootSigner: CertificateSigner, now: Instant): Member.Record {
        if (!isRoot) throw Failure("only the root removes the recovery key")
        val k = records.recovery ?: throw Failure("the group has no recovery key")
        val b = Records.Body.of("revoke", rootSigner, now)
        b.keys = listOf(k)
        return sign(b, rootSigner)
    }

    /**
     * Makes a watch an admin (section 10, "Watches"): the root issues an admin
     * CA for the key the watch made in its Keystore or Secure Enclave
     * (adminKey, a SubjectPublicKeyInfo) and signs the watch's device
     * record, whose key and admin both name that CA, since a watch has no
     * member key. device is the ID the watch picked, os "wearos" or
     * "watchos". It returns the admin CA, for the watch, and the record to
     * send. Only the root does it; the watch checked its lock screen before
     * it made the key.
     */
    fun addWatch(
        device: String,
        name: String,
        os: String,
        adminKey: ByteArray,
        rootSigner: CertificateSigner,
        now: Instant,
    ): Pair<ByteArray, Member.Record> {
        if (!isRoot) throw Failure("only the root makes admins")
        if (device.length != 32 || device.any { it !in "0123456789abcdef" } || os !in setOf("wearos", "watchos") || devices.any { it.id == device }) {
            throw Failure(NOT_A_WATCH)
        }
        val n = name.trim()
        if (n.isEmpty() || validName(n) != n) throw Failure(INVALID_NAME)
        val ca = GroupCertificates.adminCA(device, adminKey, currentRoot, rootSigner)
        val key = Records.keyHashOfCert(ca)
        return ca to record(device, n, "watch", key, rootSigner, now, key, os, Records.HARDWARE)
    }

    /** What a watch of the group may do from its wrist (section 10, "Watches"). */
    enum class WatchAction(val key: String) {
        FREEZE("freeze"), REMOVE("remove"), PASTE_OFF("paste-off"), ACTIONS_OFF("actions-off"), AWAY_OFF("away-off"), ACTION("action");

        companion object {
            fun of(key: String?): WatchAction? = entries.firstOrNull { it.key == key }
        }
    }

    /**
     * What a watch may do to device: freeze it when it is an admin computer,
     * remove it when it is no admin, and send a member the commands that
     * turn things off or run a quick action. Nothing to the root, a phone or
     * a watch.
     */
    fun watchActions(device: String): List<WatchAction> {
        val d = devices.firstOrNull { it.id == device } ?: return emptyList()
        if (device == records.rootDevice || (d.role != "full" && d.role != "lite")) return emptyList()
        val out = mutableListOf<WatchAction>()
        if (d.adminKey != null && d.role == "full" && !d.frozen) out.add(WatchAction.FREEZE)
        if (d.adminKey == null && !d.admin) out.add(WatchAction.REMOVE)
        return out + listOf(WatchAction.PASTE_OFF, WatchAction.ACTIONS_OFF, WatchAction.AWAY_OFF, WatchAction.ACTION)
    }

    /**
     * The body the watch with the device ID watch signs for action on device
     * (name is the quick action's, for ACTION): the phone builds it, the
     * watch shows what it says and signs it with its admin key, and
     * watchRecord puts the two together. Any phone of the group builds it,
     * admin or not: what counts is the watch's signature.
     */
    fun watchBody(action: WatchAction, device: String, watch: String, now: Instant, name: String? = null): ByteArray {
        val w = devices.firstOrNull { it.id == watch && it.role == "watch" }
        val ca = w?.adminKey
        if (w == null || ca == null || !w.admin) throw Failure(NOT_A_WATCH)
        val d = devices.firstOrNull { it.id == device }
        if (d == null || action !in watchActions(device)) throw Failure(NOT_FOR_WATCH)
        val s = BodyOnly
        val r = when (action) {
            WatchAction.FREEZE -> {
                val admin = d.adminKey ?: throw Failure(NOT_FOR_WATCH)
                val b = Records.Body("freeze", ca, now.toEpochMilli())
                b.keys = listOf(admin)
                return records.canonical(b)
            }
            WatchAction.REMOVE -> {
                val b = Records.Body("revoke", ca, now.toEpochMilli())
                b.keys = d.keys
                return records.canonical(b)
            }
            WatchAction.PASTE_OFF -> Commands.pasteOff(device, tag, watch, now, s)
            WatchAction.ACTIONS_OFF -> Commands.actionsOff(device, tag, watch, now, s)
            WatchAction.AWAY_OFF -> Commands.awayOff(device, tag, watch, now, s)
            WatchAction.ACTION -> {
                if (name == null || !Commands.validActionName(name)) throw Failure(NOT_FOR_WATCH)
                Commands.action(device, name, tag, watch, now, s)
            }
        }
        return r.body
    }

    /** Signs nothing: the watch signs the body elsewhere. */
    private object BodyOnly : CertificateSigner {
        override val publicKeyDER = ByteArray(0)

        override fun signature(data: ByteArray) = ByteArray(0)
    }

    /**
     * Checks the attestation a device sent of its member key (section 17,
     * "Evidence") and, on the root, returns a new device record with what
     * it shows when that differs from the device's record; null when there
     * is nothing to record. chain is the certificate chain the device
     * presented, leaf first. Throws AndroidAttestation.Invalid for a proof
     * of nothing.
     */
    fun evidence(
        device: String,
        chain: List<ByteArray>,
        e: Member.Evidence,
        rootSigner: CertificateSigner,
        now: Instant,
        roots: List<ByteArray>? = null,
        revoked: Set<String> = emptySet(),
    ): Member.Record? {
        if (!isRoot || chain.isEmpty() || e.format != Member.Evidence.ANDROID || e.key != Member.Evidence.MEMBER) return null
        val key = Records.keyHashOfCert(chain[0])
        val d = devices.firstOrNull { it.id == device && it.key.contentEquals(key) } ?: return null
        if (e.groupTag != null && e.groupTag != tag) throw AndroidAttestation.Invalid("an attestation made for another group")
        val challenge = try {
            Attestation.challenge(e.groupTag ?: "", ByteArray(0), e.salt)
        } catch (x: IllegalArgumentException) {
            throw AndroidAttestation.Invalid(x.message ?: "a bad salt")
        }
        val r = try {
            AndroidAttestation.check(e.chain, CertificateInfo(chain[0]).publicKey, challenge, AndroidAttestation.Policy(revoked = revoked, roots = roots))
        } catch (x: AndroidAttestation.Invalid) {
            // Revoked: the keys may still be in hardware, as the hello
            // says, but Google no longer vouches for the chain.
            if (!x.revoked) throw x
            if (d.store != Records.PROVEN) return null
            return recordAgain(d, rootSigner, now, store = Records.HARDWARE, proof = null)
        }
        if (d.store == r.store && (d.kind ?: "") == r.kind) return null
        val proof = if (r.store == Records.PROVEN) sha256(e.chain[0]).joinToString("") { "%02x".format(it) } else null
        return recordAgain(d, rootSigner, now, store = r.store, kind = r.kind.ifEmpty { null }, proof = proof)
    }

    /** The admin CA this phone issued for an admin key a computer offers, while that computer is still listed as an admin. */
    fun computerAdminCA(adminKey: ByteArray): ByteArray? {
        val listed = devices.filter { it.admin }.map { it.id }.toSet()
        return computerAdmins.entries.firstOrNull { (id, ca) ->
            id in listed && runCatching { CertificateInfo(ca).publicKey }.getOrNull()?.contentEquals(adminKey) == true
        }?.value
    }

    /**
     * Admits a listening device over a pairing connection whose TLS
     * handshake is done (section 6, "The joiner listens"): joinerCert is the
     * device's certificate, already checked against the QR code's
     * fingerprint, and sessionID the TLS exporter's output. The device gets
     * a member certificate from this phone's CA and the group CA, never a
     * key. A phone that sent an admin key becomes an admin when this phone is
     * the root and makeAdmin is set: it gets an admin CA for that key. On
     * success a computer is in computers, where one admitted again replaces
     * its entry, and every device has its record. A computer keeps those of
     * addrs that are on a home network, where the phone dialed it. With
     * invitation, the device dialed this phone, the hub, with a remote
     * invitation (section 12): code is unused and the device never becomes
     * an admin.
     */
    fun admit(
        t: FrameTransport,
        code: String,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        caSigner: CertificateSigner,
        now: Instant,
        makeAdmin: Boolean = true,
        addrs: List<String> = emptyList(),
        invitation: PairingMember.Invitation? = null,
    ): PairingMember.Admitted {
        if (!isAdmin) throw Failure("this phone is no admin")
        val first = groupCA
        val later = roots
        val root = currentRoot
        val ca = signingCA
        val issuer = adminCA
        val canMakeAdmins = isRoot && invitation == null
        var adminKey: ByteArray? = null
        val taken = { dev: String -> dev == device || records.knows(dev) }
        val pathRecords = records.pathRecords
        val claimTimes = records.claimTimes
        val admitted = PairingMember.admit(t, code, memberCert, joinerCert, sessionID, Pairing.MemberAD(device, tag), taken, invitation) { dev, publicKey, info ->
            val cert = GroupCertificates.member(dev, publicKey, ca, caSigner, now)
            val key = info.adminKey
            val forAdmin = if (Pairing.Info.isPhone(info.os) && key != null && makeAdmin && canMakeAdmins) {
                adminKey = key
                GroupCertificates.adminCA(dev, key, root, caSigner)
            } else {
                null
            }
            // The records let the new device take its peers at once; a group
            // never handed over leaves them out when they do not fit in a
            // frame, and the device gets them from its peers.
            var w = Pairing.Welcome(
                cert, first, issuer, forAdmin, later.ifEmpty { null }, pathRecords.ifEmpty { null }, claimTimes = claimTimes.ifEmpty { null },
            )
            if (later.isEmpty() && Wire.encode(w.toJson()).size > Pairing.MAX_FRAME - Pairing.WELCOME_ROOM) {
                w = Pairing.Welcome(cert, first, issuer, forAdmin)
            }
            w
        }
        val name = validName(admitted.info.name)
        val key = Records.keyHashOfCert(admitted.cert)
        if (Pairing.Info.isPhone(admitted.info.os)) {
            record(admitted.device, name, "phone", key, caSigner, now, adminKey?.let { Records.keyHash(it) }, admitted.info.os, Records.HARDWARE,
                seal = admitted.info.seal)
            return admitted
        }
        computers.removeAll { it.device == admitted.device }
        computers.add(Computer(admitted.device, admitted.info.name, admitted.info.os, admitted.cert, now, addrs.filter(JoinCode::isHome)))
        val role = if (admitted.info.role == Pairing.Info.LITE) "lite" else "full"
        record(admitted.device, name, role, key, caSigner, now, os = admitted.info.os, seal = admitted.info.seal)
        return admitted
    }

    /**
     * Notes a computer the core admitted for this phone (CorePairing):
     * its name, system and those of addrs that are on a home network, the
     * one that answered first, for dialing it where mDNS does not find it.
     * One admitted again replaces its entry. Its record reaches the group
     * from the member.
     */
    fun noteComputer(device: String, name: String, os: String, addrs: List<String>, now: Instant) {
        computers.removeAll { it.device == device }
        computers.add(Computer(device, name, os, ByteArray(0), now, addrs.filter(JoinCode::isHome)))
    }

    /** The group as JSON, to save it. */
    fun toJson(): ByteArray = Wire.encode(
        Wire.obj(
            "device" to Wire.str(device),
            "group_ca" to Wire.bytes(groupCA),
            "roots" to Wire.list(roots),
            "member_cert" to Wire.bytes(memberCert),
            "member_issuer" to Wire.bytes(memberIssuer),
            "is_root" to JsonPrimitive(isRoot),
            "admin_ca" to Wire.bytes(adminCA),
            "computers" to JsonArray(
                computers.map {
                    Wire.obj(
                        "device" to Wire.str(it.device),
                        "name" to Wire.str(it.name),
                        "os" to Wire.str(it.os),
                        "cert" to Wire.bytes(it.cert),
                        "admitted_ms" to Wire.num(it.admitted.toEpochMilli()),
                        "addrs" to JsonArray(it.addrs.map { a -> JsonPrimitive(a) }),
                    )
                },
            ),
            "records" to Wire.parse(records.toJson()),
            "computer_admins" to JsonObject(computerAdmins.mapValues { Wire.bytes(it.value)!! }),
            "claim" to Wire.bytes(claim),
            "claimed_from" to Wire.str(claimedFrom),
        ),
    )

    /** Saves the group in one step, so a crash leaves the old file or the new one. */
    fun save(file: File) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(toJson())
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) throw java.io.IOException("cannot save ${file.path}")
        }
    }

    companion object {
        /**
         * Creates a group: a root CA for caSigner's key, a member certificate
         * for this phone's member key (a SubjectPublicKeyInfo), and the
         * phone's own device record under name, with seal, the phone's public
         * key for sealed messages, when it has one.
         */
        fun create(caSigner: CertificateSigner, memberKey: ByteArray, now: Instant, name: String = "Android", seal: ByteArray? = null): PhoneGroup {
            val ca = GroupCertificates.groupCA(caSigner, now, pathLength = 1)
            val device = SyncEngine.newID()
            val cert = GroupCertificates.member(device, memberKey, ca, caSigner, now)
            val g = PhoneGroup(device, ca, cert)
            g.record(device, validName(name), "phone", Records.keyHash(memberKey), caSigner, now, os = "android", store = Records.HARDWARE, seal = seal)
            return g
        }

        /** The message of the Failure for a name that the records do not accept. */
        const val INVALID_NAME = "a device name has 1 to 64 bytes and no control characters"
        const val NOT_A_WATCH = "the watch's request names a device ID or system that is not a new watch's, or the device is no watch of the group"
        const val NOT_FOR_WATCH = "a watch may not do that to this device"
        const val NO_TAKEOVER = "the root did not give this admin the power to take the group over"
        const val CLAIM_WAITING = "this admin's claim to take the group over waits already"
        const val INVALID_DELAY = "the delay before a claim takes effect is 0 to 7 days"
        const val INVALID_INCOMING = "how long an incoming copy stays live is 5 s to 1 h"
        const val INVALID_KEY_LEVEL = "the key level is proven, hardware or files"

        /** The record or command a watch signed: body, its signature (ECDSA with SHA-256, DER) and the watch's admin CA. */
        fun watchRecord(body: ByteArray, signature: ByteArray, watchCA: ByteArray): Member.Record = Member.Record(body, signature, listOf(watchCA))

        /** A name that the records accept: 1 to 64 bytes without control characters, or "Android". */
        fun validName(s: String): String {
            val out = StringBuilder()
            var i = 0
            while (i < s.length) {
                val cp = s.codePointAt(i)
                i += Character.charCount(cp)
                if (Character.getType(cp) == Character.CONTROL.toInt()) continue
                val ch = String(Character.toChars(cp))
                if ((out.toString() + ch).toByteArray().size > 64) break
                out.append(ch)
            }
            return out.toString().ifEmpty { "Android" }
        }

        /**
         * The group a phone joins, from the welcome the admitting phone sent
         * and PairingJoiner checked: a member of it, and an admin when the
         * welcome carries its admin CA. The records arrive from the computers.
         */
        fun joined(j: PairingJoiner.Joined): PhoneGroup {
            val g = PhoneGroup(j.device, j.welcome.groupCA, j.welcome.cert)
            g.memberIssuer = j.welcome.issuer
            g.isRoot = false
            g.adminCA = j.welcome.adminCA
            // The records that lead to the roots stay with the group, so the roots are those its records name.
            g.records.addAll(j.welcome.records.orEmpty(), j.welcome.groupCA)
            g.records.takeClaimTimes(j.welcome.claimTimes.orEmpty())
            g.roots = g.records.roots
            return g
        }

        /**
         * The group the core made with this phone's root key
         * (CorePairing.newGroup), or the group a phone joined through the
         * core (CorePairing.Joining): a member of it, and an admin when the
         * admitting phone sent its admin CA.
         */
        fun of(c: CorePairing.Group, root: Boolean): PhoneGroup {
            val g = PhoneGroup(c.device, c.groupCA, c.cert)
            g.memberIssuer = c.issuer
            g.isRoot = root
            g.adminCA = if (root) null else c.adminCA
            g.records = RecordSet.fromFile(c.groupCA, c.records)
            // The records that lead to the roots stay with the group, so the roots are those its records name.
            g.roots = g.records.roots.ifEmpty { c.roots }
            return g
        }

        /** A group saved with toJson. */
        fun fromJson(data: ByteArray): PhoneGroup {
            val o = Wire.parse(data) ?: throw Failure("not a saved group")
            try {
                val g = PhoneGroup(
                    o.optString("device") ?: throw Failure("no device"),
                    o.optBytes("group_ca") ?: throw Failure("no group CA"),
                    o.optBytes("member_cert") ?: throw Failure("no member certificate"),
                )
                g.roots = o.optBytesList("roots").orEmpty()
                g.memberIssuer = o.optBytes("member_issuer")
                g.isRoot = (o.opt("is_root") as? JsonPrimitive)?.booleanOrNull ?: true
                g.adminCA = o.optBytes("admin_ca")
                for (c in o.optArray("computers").orEmpty()) {
                    val co = c as? JsonObject ?: continue
                    g.computers.add(
                        Computer(
                            co.optString("device") ?: continue,
                            co.optString("name") ?: "",
                            co.optString("os") ?: "linux",
                            co.optBytes("cert") ?: ByteArray(0),
                            Instant.ofEpochMilli(co.optLong("admitted_ms") ?: 0),
                            co.optArray("addrs").orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.filter(JoinCode::isHome),
                        ),
                    )
                }
                o.optObject("records")?.let { g.records = RecordSet.fromJson(Wire.encode(it)) }
                o.optObject("computer_admins")?.forEach { (k, _) -> o.optObject("computer_admins")!!.optBytes(k)?.let { g.computerAdmins[k] = it } }
                g.claim = o.optBytes("claim")
                g.claimedFrom = o.optString("claimed_from")
                return g
            } catch (e: WireTypeException) {
                throw Failure("not a saved group: ${e.message}")
            }
        }

        /** Reads a saved group; null when there is none. */
        fun load(file: File): PhoneGroup? = if (file.exists()) fromJson(file.readBytes()) else null
    }
}
