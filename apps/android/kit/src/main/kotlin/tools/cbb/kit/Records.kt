// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant

/**
 * The group's signed records of version 2 (docs/records-v2.md): what a
 * phone writes into them. The phone signs a record with the root's own key,
 * without a chain, or with its admin key, and the chain holds the admin CA.
 * What the records say comes from the Rust core ([RecordSet]), never from
 * rules written again here.
 */
object Records {
    const val VERSION = 2

    /** The signature algorithm every record names: ECDSA P-256 with SHA-256. */
    const val ALG = "es256"

    /**
     * A record body before the set fills in its group, seq, prev and seen
     * ([RecordSet.sign]); the fields depend on its type (docs/records-v2.md,
     * "Record types"). signer is the signer's key hash.
     */
    class Body(val type: String, val signer: ByteArray, val timeMS: Long) {
        // device
        var device: String? = null
        var name: String? = null
        var role: String? = null
        var os: String? = null
        var key: ByteArray? = null
        var admin: ByteArray? = null
        var powers: List<String>? = null
        var commands: List<String>? = null

        /** Where the device's keys live: "file", "hardware", "proven" or "rootless" ([storeOf]). */
        var store: String? = null

        /** With a checked attestation: the kind of hardware and the hex SHA-256 of the attestation's leaf. */
        var kind: String? = null
        var proof: String? = null
        var holdsRoot = false

        /** The device's public key for sealed messages (docs/protocol.md, section 15). */
        var seal: ByteArray? = null

        /** A hub that only passes copies on: none is sealed to it (docs/protocol.md, section 4). */
        var forwardOnly = false

        // revoke, freeze
        var keys: List<ByteArray>? = null

        // thaw, resolve
        var records: List<ByteArray>? = null

        // claim
        var root: ByteArray? = null

        // recovery: the recovery key's admin CA, DER
        var cert: ByteArray? = null

        // settings
        var takeoverDelayMS: Long? = null

        /** Which keys may be the group's root, an admin or a hub: one of Records.KEY_LEVELS. */
        var keyLevel: String? = null

        // hubs
        var hubs: List<String>? = null

        /** In a copies record: how long a copy from another device stays live after it arrives. */
        var incomingMS: Long? = null

        /** The body as the core reads it, the empty fields left out, each key and record once. */
        fun toJson(): JsonObject {
            fun s(v: String?) = v?.takeIf { it.isNotEmpty() }?.let { JsonPrimitive(it) }
            fun b(v: ByteArray?) = v?.takeIf { it.isNotEmpty() }?.let { Wire.bytes(it) }
            fun strs(v: List<String>?) = v?.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { JsonPrimitive(it) }) }
            fun once(v: List<ByteArray>?) = v?.distinctBy { it.toHex() }?.takeIf { it.isNotEmpty() }?.let { Wire.list(it) }
            return Wire.obj(
                "v" to Wire.num(VERSION.toLong()),
                "alg" to JsonPrimitive(ALG),
                "type" to JsonPrimitive(type),
                "signer" to Wire.bytes(signer),
                "time_ms" to Wire.num(timeMS),
                "device" to s(device),
                "name" to s(name),
                "role" to s(role),
                "os" to s(os),
                "key" to b(key),
                "admin" to b(admin),
                "powers" to strs(powers),
                "commands" to strs(commands),
                "store" to s(store),
                "kind" to s(kind),
                "proof" to s(proof),
                "holds_root" to if (holdsRoot) JsonPrimitive(true) else null,
                "seal" to b(seal),
                "forward_only" to if (forwardOnly) JsonPrimitive(true) else null,
                "keys" to once(keys),
                "records" to once(records),
                "root" to b(root),
                "cert" to b(cert),
                "takeover_delay_ms" to takeoverDelayMS?.let { Wire.num(it) },
                "key_level" to s(keyLevel),
                "hubs" to strs(hubs),
                "incoming_ms" to incomingMS?.let { Wire.num(it) },
            )
        }

        companion object {
            /** A body of type, signed by signer at now. */
            fun of(type: String, signer: CertificateSigner, now: Instant): Body = Body(type, keyHash(signer.publicKeyDER), now.toEpochMilli())
        }
    }

    /** The powers an admin may have (docs/protocol.md, section 10, "Who signs what"): what the apps give an admin phone. */
    val POWERS = listOf("admit", "freeze", "hub", "remove", "remove-admins", "renew", "takeover", "thaw")

    /** The commands an admin may sign. */
    val COMMANDS = listOf("action", "actions-off", "away-off", "hub", "mode", "mute", "paste", "paste-off", "unmute")

    /** What the apps give an admin computer under a phone's root. */
    val COMPUTER_POWERS = listOf("admit", "freeze", "hub", "remove", "renew")

    /** What the apps give a watch. */
    val WATCH_POWERS = listOf("freeze", "remove")
    val WATCH_COMMANDS = listOf("action", "actions-off", "away-off", "paste-off")

    /** The powers and commands the apps give an admin with role. */
    fun grants(role: String): Pair<List<String>, List<String>> = when (role) {
        "phone" -> POWERS to COMMANDS
        "watch" -> WATCH_POWERS to WATCH_COMMANDS
        else -> COMPUTER_POWERS to COMMANDS
    }

    /** Whether s is a device ID: 32 of 0-9 and a-f. */
    fun isDeviceID(s: String?): Boolean = s != null && s.length == 32 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /** Whether s is a device name: 1 to 64 bytes of UTF-8 without control characters. */
    fun validName(s: String?): Boolean =
        s != null && s.isNotEmpty() && s.toByteArray().size <= 64 && s.codePoints().noneMatch { Character.isISOControl(it) }

    /** The hash that names a key in records: SHA-256 over a SubjectPublicKeyInfo. */
    fun keyHash(spki: ByteArray): ByteArray = sha256(spki)

    /** The hash of the key a certificate certifies. */
    fun keyHashOfCert(cert: ByteArray): ByteArray = keyHash(CertificateInfo(cert).publicKey)

    /** A record's ID: SHA-256 over its body. */
    fun id(r: Member.Record): ByteArray = sha256(r.body)

    const val FILE = "file"
    const val HARDWARE = "hardware"

    /** How long a copy from another device stays live after it arrives without a copies record, and the bounds of one, in milliseconds. */
    const val DEFAULT_INCOMING_MS = 60_000L
    val INCOMING_BOUNDS = 5_000L..3_600_000L

    /** A key in hardware whose attestation a signer checked. */
    const val PROVEN = "proven"

    /**
     * A rootless install's keys: in a file every program of its user may
     * read, so the device is never the root, an admin or a hub (D-79).
     */
    const val ROOTLESS = "rootless"

    /**
     * The group's key levels (docs/guide/keys.md, "The three levels"): which
     * keys may be its root, an admin or a hub. The levels proven and
     * hardware share their names with the stores they let in; files lets in
     * keys in files too, each after a warning.
     */
    const val LEVEL_FILES = "files"
    val KEY_LEVELS = listOf(PROVEN, HARDWARE, LEVEL_FILES)

    /** Whether the key level lets a device whose keys are in store be the group's root, an admin or a hub; a key in a file needs consent too. */
    fun levelAllows(level: String, store: String, consent: Boolean): Boolean = when (store) {
        ROOTLESS -> false
        PROVEN -> true
        FILE -> level == LEVEL_FILES && consent
        else -> level != PROVEN
    }

    /**
     * Where a device's keys live, as a hello's key_store or a record's store
     * says (docs/protocol.md, section 17): FILE, HARDWARE, PROVEN or ROOTLESS.
     * Without one, or with one this version does not know, a phone's and a
     * watch's keys are in hardware and any other device's in a file.
     */
    fun storeOf(store: String?, role: String): String = when (store) {
        FILE, HARDWARE, PROVEN, ROOTLESS -> store
        else -> if (role == "phone" || role == "watch") HARDWARE else FILE
    }
}

/** Bytes compared by content, for sets and maps. */
internal data class Key(val hex: String) {
    constructor(b: ByteArray) : this(b.toHex())

    val bytes: ByteArray get() = ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

private fun List<ByteArray>.sameAs(o: List<ByteArray>): Boolean = size == o.size && zip(o).all { (a, b) -> a.contentEquals(b) }

private fun JsonObject.strings(key: String): List<String> =
    optArray(key)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()

/**
 * The record set a member keeps: the records file of the Rust core
 * (cbb_core::group::Records, docs/core-api.md, "The record set"), which
 * only grows, and what the core says of it. The set asks the core for
 * every answer, so the phones follow the same rules as every member.
 */
class RecordSet {
    /** The records file, as the core writes it; null for an empty set. */
    var file: ByteArray? = null
        private set

    /** The group's first root, which names it; the first add sets it. */
    var groupCA: ByteArray? = null
        internal set

    /** The group's tag where it is not the group CA's own, for the vectors. */
    internal var tag: String? = null

    /** The member's clock: the wall clock, which the claims' delays count in; tests set another. */
    var clock: () -> Instant = { Instant.now() }

    /** The clock in milliseconds when set, in place of clock: a command's or a vector's time, exactly. */
    internal var nowMS: Long? = null

    /** What the core said of the set when it last changed or [refresh] ran. */
    var view = View()
        private set

    /** A device as the list shows it. */
    class Device(
        val id: String,
        val name: String,
        /** "full", "phone", "lite" or "watch". */
        val role: String,
        /** The member key of its newest counting record. */
        val key: ByteArray,
        /** An admin now: it has an admin key and is not frozen. */
        val admin: Boolean = false,
        /** The key hash of its admin CA, whether or not it is frozen. */
        val adminKey: ByteArray? = null,
        /** Its operating system; null when its record does not tell. */
        val os: String? = null,
        /** An admin another admin froze: no admin until the freeze ends, and refused. */
        val frozen: Boolean = false,
        /** Every key that a counting device record names for it and that is not revoked, key among them: what removing it revokes. */
        val keys: List<ByteArray> = listOf(key),
        /** Where its keys live: Records.FILE, Records.HARDWARE, Records.PROVEN or Records.ROOTLESS. */
        val store: String = Records.storeOf(null, role),
        /** The kind of hardware and the hash of the attestation the root checked, if any. */
        val kind: String? = null,
        val proof: String? = null,
        val powers: List<String> = emptyList(),
        val commands: List<String> = emptyList(),
        /** The IDs of the freezes of a frozen admin, which a thaw names. */
        val freezes: List<ByteArray> = emptyList(),
        /** Its public key for sealed messages, which commands for it are sealed to; null when its record has none. */
        val seal: ByteArray? = null,
        /** A hub that only passes copies on, which no copy is sealed to. */
        val forwardOnly: Boolean = false,
    ) {
        /** Whether it is an admin with the power p. */
        fun may(p: String): Boolean = admin && p in powers

        override fun equals(other: Any?): Boolean =
            other is Device && id == other.id && name == other.name && role == other.role && os == other.os && store == other.store &&
                kind == other.kind && proof == other.proof && key.contentEquals(other.key) && admin == other.admin &&
                adminKey.contentEqualsOrNull(other.adminKey) && frozen == other.frozen && keys.sameAs(other.keys) &&
                powers == other.powers && commands == other.commands && freezes.sameAs(other.freezes) &&
                forwardOnly == other.forwardOnly

        override fun hashCode(): Int = id.hashCode()

        override fun toString(): String = "Device($id, $name, $role, admin=$admin, frozen=$frozen)"

        companion object {
            internal fun of(o: JsonObject): Device {
                val role = o.optString("role") ?: ""
                val key = o.optBytes("key") ?: ByteArray(0)
                return Device(
                    id = o.optString("device") ?: "",
                    name = o.optString("name") ?: "",
                    role = role,
                    key = key,
                    admin = o.optBool("admin") ?: false,
                    adminKey = o.optBytes("admin_key"),
                    os = o.optString("os"),
                    frozen = o.optBool("frozen") ?: false,
                    keys = o.optBytesList("keys") ?: listOf(key),
                    store = o.optString("store") ?: Records.storeOf(null, role),
                    kind = o.optString("kind"),
                    proof = o.optString("proof"),
                    powers = o.strings("powers"),
                    commands = o.strings("commands"),
                    freezes = o.optBytesList("freezes").orEmpty(),
                    seal = o.optBytes("seal"),
                    forwardOnly = o.optBool("forward_only") ?: false,
                )
            }
        }
    }

    /** A claim of the state: an admin's handover of the group to its new root (docs/protocol.md, section 10, "Handing the group over"). */
    class Claim(
        val record: ByteArray,
        val claimant: ByteArray,
        val root: ByteArray,
        /** "pending", "effective", "disputed", "cancelled" and the others the state names. */
        val state: String,
        val leftMS: Long?,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Claim && record.contentEquals(other.record) && claimant.contentEquals(other.claimant) && root.contentEquals(other.root) &&
                state == other.state && leftMS == other.leftMS

        override fun hashCode(): Int = record.contentHashCode()
    }

    /** A conflict of the state: kind is admins, claims or two_histories. */
    class Conflict(val kind: String, val records: List<ByteArray>, val signers: List<ByteArray>) {
        override fun equals(other: Any?): Boolean =
            other is Conflict && kind == other.kind && records.sameAs(other.records) && signers.sameAs(other.signers)

        override fun hashCode(): Int = kind.hashCode()
    }

    /** The parts of the group's state (docs/protocol.md, section 10, "The state") the phones show. */
    class State(
        val rootDevice: String? = null,
        val roots: List<ByteArray> = emptyList(),
        /** "none", or why the group stops (docs/protocol.md, section 10, "Stopping the exchange"). */
        val stop: String = "none",
        val claims: List<Claim> = emptyList(),
        /** The keys the records revoke. */
        val revoked: List<ByteArray> = emptyList(),
        /** The devices this member sends no secret, only its mark. */
        val noSecretsTo: List<String> = emptyList(),
        /** The devices this member sends nothing but records. */
        val nothingTo: List<String> = emptyList(),
        /** The conflicts that stop the group until its root decides. */
        val conflicts: List<Conflict> = emptyList(),
        /** How many records of a later version the set keeps. */
        val newer: Int = 0,
        /** The key hash of the group's recovery key, while one counts. */
        val recovery: ByteArray? = null,
        /** The key level of the current root's newest settings; null means hardware. */
        val keyLevel: String? = null,
        /** How long a copy from another device stays live after it arrives, from the copies record that counts; null means a minute. */
        val incomingMS: Long? = null,
    ) {
        override fun equals(other: Any?): Boolean =
            other is State && rootDevice == other.rootDevice && roots.sameAs(other.roots) && stop == other.stop && claims == other.claims &&
                revoked.sameAs(other.revoked) && noSecretsTo == other.noSecretsTo && nothingTo == other.nothingTo &&
                conflicts == other.conflicts && newer == other.newer && recovery.contentEquals(other.recovery) &&
                keyLevel == other.keyLevel && incomingMS == other.incomingMS

        override fun hashCode(): Int = stop.hashCode()

        override fun toString(): String =
            "State(root_device=$rootDevice, roots=${roots.map { it.toHex() }}, stop=$stop, " +
                "claims=${claims.map { "${it.state}:${it.root.toHex()}" }}, revoked=${revoked.map { it.toHex() }})"

        companion object {
            /** The state in o, as the core writes it. */
            fun of(o: JsonObject): State = State(
                rootDevice = o.optString("root_device")?.takeIf { it.isNotEmpty() },
                roots = o.optBytesList("roots").orEmpty(),
                stop = o.optString("stop") ?: "none",
                claims = o.optArray("claims").orEmpty().mapNotNull { e ->
                    val c = e as? JsonObject ?: return@mapNotNull null
                    Claim(
                        c.optBytes("record") ?: ByteArray(0),
                        c.optBytes("claimant") ?: ByteArray(0),
                        c.optBytes("root") ?: ByteArray(0),
                        c.optString("state") ?: "",
                        c.optLong("left_ms"),
                    )
                },
                revoked = o.optBytesList("revoked").orEmpty(),
                noSecretsTo = o.optArray("no_secrets_to").orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content },
                nothingTo = o.optArray("nothing_to").orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content },
                conflicts = o.optArray("conflicts").orEmpty().mapNotNull { e ->
                    val c = e as? JsonObject ?: return@mapNotNull null
                    Conflict(c.optString("kind") ?: "", c.optBytesList("records").orEmpty(), c.optBytesList("signers").orEmpty())
                },
                newer = o.optArray("newer")?.size ?: 0,
                recovery = o.optBytes("recovery"),
                keyLevel = o.optString("key_level")?.takeIf { it.isNotEmpty() },
                incomingMS = o.optLong("incoming_ms")?.takeIf { it > 0 },
            )
        }
    }

    /** When the set first held a claim, which a Welcome passes on. */
    class ClaimTime(val record: ByteArray, val ms: Long) {
        fun toJson(): JsonObject = Wire.obj("record" to Wire.bytes(record), "ms" to Wire.num(ms))

        override fun equals(other: Any?): Boolean = other is ClaimTime && record.contentEquals(other.record) && ms == other.ms

        override fun hashCode(): Int = record.contentHashCode()

        companion object {
            fun of(o: JsonObject): ClaimTime? = try {
                ClaimTime(o.optBytes("record") ?: return null, o.optLong("ms") ?: return null)
            } catch (e: WireTypeException) {
                null
            }

            fun list(a: JsonArray?): List<ClaimTime> = a.orEmpty().mapNotNull { (it as? JsonObject)?.let(::of) }
        }
    }

    /** What the core says of the set (group_view). */
    class View(
        val state: State = State(),
        val devices: List<Device> = emptyList(),
        /** The roots' certificates on the path, the group CA first. */
        val path: List<ByteArray> = emptyList(),
        val rootMember: Pair<String, ByteArray>? = null,
        val hubOrder: List<String> = emptyList(),
        /** The admin key hash the current root handed the group to (docs/protocol.md, section 10, "Handing the group over"). */
        val handedTo: ByteArray? = null,
        val digest: String? = null,
        val claimTimes: List<ClaimTime> = emptyList(),
        val known: List<String> = emptyList(),
    ) {
        companion object {
            fun of(o: JsonObject): View = View(
                state = o.optObject("state")?.let { State.of(it) } ?: State(),
                devices = o.optArray("devices").orEmpty().mapNotNull { (it as? JsonObject)?.let(Device::of) },
                path = o.optBytesList("path").orEmpty(),
                rootMember = o.optObject("root_member")?.let { r ->
                    val d = r.optString("device") ?: return@let null
                    val k = r.optBytes("key") ?: return@let null
                    d to k
                },
                hubOrder = o.strings("hub_order"),
                handedTo = o.optBytes("handed_to"),
                digest = o.optString("digest"),
                claimTimes = ClaimTime.list(o.optArray("claim_times")),
                known = o.strings("known"),
            )
        }
    }

    /** The set's records, as the file holds them. */
    val records: List<Member.Record>
        get() {
            val f = file ?: return emptyList()
            val o = Wire.parse(f) ?: return emptyList()
            return runCatching { o.optArray("records")?.map { Member.Record.fromJson(it as JsonObject) } }.getOrNull().orEmpty()
        }

    /** Asks the core op with the set's arguments and extra; throws Core.Refusal. */
    private fun ask(op: String, vararg extra: Pair<String, JsonElement?>): JsonObject {
        val ca = groupCA ?: throw Core.Mismatch("the set knows no group yet")
        val args = Wire.obj(
            "group_ca" to Wire.bytes(ca),
            "group" to Wire.str(tag),
            "now_ms" to Wire.num(nowMS ?: clock().toEpochMilli()),
            "file" to Wire.bytes(file),
            *extra,
        )
        return Core.run(op, args) as? JsonObject ?: throw Core.Mismatch("the answer to $op is not an object")
    }

    /**
     * Seals a copy this member made to the readers the set names
     * (group_seal_copy, docs/protocol.md, section 4, "Sealing") and signs it
     * with signer, the member key of cert; key sealed the blob of its images
     * or files, if it has one.
     */
    fun sealCopy(e: Member.Event, cert: ByteArray, issuer: ByteArray?, key: ByteArray?, blob: Blob?, signer: CertificateSigner): Sealed {
        val a = ask("group_seal_copy", *e.sealArgs(cert, issuer, key, blob))
        val s = a.optObject("event")?.let { Sealed.fromJson(it) } ?: throw Core.Mismatch("the answer to group_seal_copy has no event")
        val toSign = a.optBytes("to_sign") ?: throw Core.Mismatch("the answer to group_seal_copy has nothing to sign")
        return s.with(sig = signer.signature(toSign))
    }

    /** Checks a copy's origin and signature against the set, as a member does before it keeps or passes the copy on (group_check_copy). */
    fun checkCopy(s: Sealed) {
        ask("group_check_copy", "event" to s.toJson())
    }

    /** Asks the core what the set says again: after the clock moved, as a claim's delay runs out. */
    fun refresh() {
        if (groupCA == null) {
            view = View()
            return
        }
        view = runCatching { View.of(ask("group_view")) }.getOrElse { View() }
    }

    /** Adds a record signed under one of the group's roots, unless it holds it; reports whether it was new. */
    fun add(r: Member.Record, groupCA: ByteArray): Boolean = addAll(listOf(r), groupCA).isNotEmpty()

    /** Adds records and returns those it did not hold; the core leaves out records it refuses (docs/records-v2.md). */
    fun addAll(rs: List<Member.Record>, groupCA: ByteArray): List<Member.Record> {
        if (this.groupCA == null) this.groupCA = groupCA
        if (rs.isEmpty() || !this.groupCA.contentEqualsOrNull(groupCA)) return emptyList()
        val out = runCatching { ask("group_add", "records" to JsonArray(rs.map { it.toJson() })) }.getOrNull() ?: return emptyList()
        file = runCatching { out.optBytes("file") }.getOrNull() ?: return emptyList()
        refresh()
        return out.optArray("fresh").orEmpty().mapNotNull { e -> (e as? JsonObject)?.let { runCatching { Member.Record.fromJson(it) }.getOrNull() } }
    }

    /** Takes the claim times a Welcome brought: those earlier than the set's own and not in the future. */
    fun takeClaimTimes(ts: List<ClaimTime>) {
        if (ts.isEmpty() || groupCA == null) return
        val out = runCatching { ask("group_claim_times", "claim_times" to JsonArray(ts.map { it.toJson() })) }.getOrNull() ?: return
        file = runCatching { out.optBytes("file") }.getOrNull() ?: return
        refresh()
    }

    /**
     * Signs body as the signer's next record: the core sets the group, seq
     * and prev, and seen for a removal, freeze or claim, from the set. The
     * caller adds the record to the set.
     */
    fun sign(body: Records.Body, signer: CertificateSigner, adminCA: ByteArray? = null): Member.Record {
        val data = canonical(body)
        return Member.Record(data, signer.signature(data), adminCA?.let { listOf(it) })
    }

    /** The canonical bytes of body as the signer's next record, to sign. */
    fun canonical(body: Records.Body): ByteArray =
        ask("group_body", "body" to body.toJson()).optBytes("body") ?: throw Core.Mismatch("the answer to group_body has no body")

    /** The devices list, sorted by name. */
    val devices: List<Device> get() = view.devices

    /** The roots that took the group over from the group CA, in order, DER; the last is the current root. */
    val roots: List<ByteArray> get() = view.path.drop(1)

    /** The device of the group's root, when the records name it. */
    val rootDevice: String? get() = view.state.rootDevice

    /** The device that holds the root key and its member key. */
    internal fun rootMember(): Pair<String, Key>? = view.rootMember?.let { (d, k) -> d to Key(k) }

    /** The devices that may be hubs, in the order members try them. */
    val hubOrder: List<String> get() = view.hubOrder

    /** The admin key hash the current root handed the group to, whose claim takes effect at once; null without a handover. */
    val handedTo: ByteArray? get() = view.handedTo

    /** Whether the records let the device be the group's hub. */
    fun mayHost(device: String): Boolean = device in view.hubOrder

    /** The digest a hello carries; null for an empty set. */
    val digest: String? get() = view.digest

    /** When the set first held each claim, which a Welcome passes on. */
    val claimTimes: List<ClaimTime> get() = view.claimTimes

    /** Whether a device record names device, counted or not: an ID a new device must not take. */
    fun knows(device: String): Boolean = device in view.known

    /** Why the group stops exchanging, "none" when it does not. */
    val stop: String get() = view.state.stop

    /** The claims of the state. */
    val claims: List<Claim> get() = view.state.claims

    /** The keys the records revoke, in hex. */
    val revoked: Set<String> get() = view.state.revoked.map { it.toHex() }.toSet()

    /** The key hash of the group's recovery key, while one counts. */
    val recovery: ByteArray? get() = view.state.recovery

    /** The group's key level (Records.KEY_LEVELS): hardware when the root set none. */
    val keyLevel: String get() = view.state.keyLevel ?: Records.HARDWARE

    /** How long a copy from another device stays live after it arrives, in milliseconds (docs/protocol.md, section 10, "The copies setting"). */
    val incomingMS: Long get() = view.state.incomingMS ?: Records.DEFAULT_INCOMING_MS

    /** Whether a key hash is revoked. */
    fun isRevoked(keyHash: ByteArray): Boolean = keyHash.toHex() in revoked

    /**
     * The records a new member gets in the Welcome, to check the Welcome's
     * roots, and a hub shows its forwarder: all of them, since every member
     * evaluates the whole set.
     */
    val pathRecords: List<Member.Record> get() = records
    val authorityRecords: List<Member.Record> get() = records

    /** What the set says of a peer's chain. */
    sealed class Verdict {
        object Ok : Verdict()

        /** No device record that counts names the device yet; its connection carries records only. */
        data class NotListed(val why: String) : Verdict()

        /** The root's own device that a claim took the group over from; its connection carries records only, so that it may cancel the claim. */
        data class TakenOver(val why: String) : Verdict()

        /** The state stops the exchange with the device (docs/protocol.md, section 10, "Stopping the exchange"); its connection carries records only, so that the root's decision reaches every member. */
        data class Stopped(val why: String) : Verdict()

        data class Refused(val why: String) : Verdict()

        /** Why it is not ok, null when it is. */
        val reason: String?
            get() = when (this) {
                Ok -> null
                is NotListed -> why
                is TakenOver -> why
                is Stopped -> why
                is Refused -> why
            }

        /** Whether the connection carries records only. */
        val recordsOnly: Boolean get() = this is NotListed || this is TakenOver || this is Stopped

        companion object {
            internal fun of(o: JsonObject): Verdict {
                val why = o.optString("why") ?: ""
                return when (o.optString("verdict")) {
                    "ok" -> Ok
                    "not_listed" -> NotListed(why)
                    "taken_over" -> TakenOver(why)
                    "stopped" -> Stopped(why)
                    else -> Refused(why.ifEmpty { "refused" })
                }
            }
        }
    }

    /** Whether the set takes a member's chain, leaf first, already verified to a trusted root; an empty set takes any. */
    fun verdict(chain: List<ByteArray>): Verdict {
        if (groupCA == null || file == null) return Verdict.Ok
        return try {
            Verdict.of(ask("group_refused", "chain" to Wire.list(chain)))
        } catch (e: Exception) {
            Verdict.Refused(e.toString())
        }
    }

    /**
     * Why the set refuses a member's chain, null when it takes it; a chain
     * the state only stops the exchange with is taken, for records only
     * (stopped).
     */
    fun refused(chain: List<ByteArray>): String? = verdict(chain).let { if (it is Verdict.Stopped) null else it.reason }

    /**
     * Whether the state stops the exchange with this chain's device: its
     * connection carries records only (docs/protocol.md, section 10,
     * "Stopping the exchange").
     */
    fun stopped(chain: List<ByteArray>): Boolean = verdict(chain) is Verdict.Stopped

    /**
     * Whether this member sends device no secret: while the state stops
     * secrets or everything, or names device among those that get no secrets
     * or nothing. Such a device gets the mark of a secret, never its text. A
     * null device is checked against the stop alone.
     */
    fun noSecrets(device: String?): Boolean {
        val st = view.state
        if (st.stop != "none") return true
        return device != null && (device in st.noSecretsTo || device in st.nothingTo)
    }

    /** Whether the set takes an admin CA. */
    fun verdictAdminCA(adminCA: ByteArray): Verdict {
        if (groupCA == null || file == null) return Verdict.Ok
        return try {
            Verdict.of(ask("group_refused_admin_ca", "ca" to Wire.bytes(adminCA)))
        } catch (e: Exception) {
            Verdict.Refused(e.toString())
        }
    }

    /** Whether the device with the chain is the group's root or an admin, which alone may be a hub. */
    fun mayHost(device: String, chain: List<ByteArray>): Boolean =
        runCatching { ask("group_admin_peer", "device" to JsonPrimitive(device), "chain" to Wire.list(chain)).optBool("admin") }.getOrNull() ?: false

    /** The admin that took the group over from the root whose own device has chain, by a claim that took effect: its device and admin key. */
    fun takenOver(chain: List<ByteArray>): Pair<String, ByteArray>? {
        val c = runCatching { ask("group_taken_over", "chain" to Wire.list(chain)).optObject("claimant") }.getOrNull() ?: return null
        return (c.optString("device") ?: return null) to (c.optBytes("admin") ?: return null)
    }

    /** A command the core checked for this member. */
    class CheckedCommand(
        /** The device that signed it, when the records list it. */
        val signer: Device?,
        /** Whether the current root's own key signed it. */
        val root: Boolean,
        /** The device the limits count it for, or "key " and the signer's key hash in hex. */
        val sender: String,
        /** Whether that device's own key signed it. */
        val verified: Boolean,
        /** The command's body, with the orders of a sealed one opened. */
        val command: JsonObject? = null,
        /** Whether its orders were sealed to this member and opened. */
        val opened: Boolean = false,
    )

    /**
     * Checks command c for the member me (docs/protocol.md, section 15): an
     * admin of the group that may sign its type signed it, its by is the
     * signer's device, it is for me in this group and in its lifetime. A
     * sealed command's orders are opened with secret, this member's secret
     * for sealed messages; a paste in the open is refused when this
     * member's device record has a `seal` key. The caller keeps the replay
     * cache.
     */
    fun check(c: Member.Record, me: String, secret: ByteArray? = null): CheckedCommand {
        if (groupCA == null) throw Commands.Refused("this device has no records of its group yet")
        val o = try {
            ask("group_command", "command" to c.toJson(), "me" to JsonPrimitive(me), "secret" to secret?.let { Wire.bytes(it) })
        } catch (r: Core.Refusal) {
            throw Commands.Refused(r.details?.let { "${r.message}: $it" } ?: r.message)
        }
        return CheckedCommand(
            o.optObject("signer")?.let { Device.of(it) },
            o.optBool("root") ?: false,
            o.optString("sender") ?: "",
            o.optBool("verified") ?: false,
            o.optObject("command"),
            o.optBool("opened") ?: false,
        )
    }

    /**
     * Whom the limits per sender and the logs count command c for, which
     * is for the member me: its signer's device, verified (true), when the
     * records show that the device holds the signing key, and otherwise the
     * signing key itself, as "key " and its hash in hex. A command the set
     * refuses counts for nobody ("", false).
     */
    fun commandSender(c: Member.Record, me: String): Pair<String, Boolean> =
        runCatching { check(c, me) }.getOrNull()?.let { it.sender to it.verified } ?: ("" to false)

    /** The set as JSON, to keep it: the group CA and the records file. */
    fun toJson(): ByteArray = Wire.encode(Wire.obj("group_ca" to Wire.bytes(groupCA), "file" to Wire.bytes(file)))

    companion object {
        /** The set of a records file the core wrote (docs/core-api.md, "The record set") for the group of groupCA. */
        fun fromFile(groupCA: ByteArray, file: ByteArray): RecordSet {
            val s = RecordSet()
            s.groupCA = groupCA
            s.file = file.takeIf { it.isNotEmpty() }
            s.refresh()
            return s
        }

        /** A set kept with toJson; the core reads the file again, so what it says follows the rules of this version. */
        fun fromJson(data: ByteArray): RecordSet {
            val s = RecordSet()
            val o = Wire.parse(data) ?: return s
            s.groupCA = runCatching { o.optBytes("group_ca") }.getOrNull()
            s.file = runCatching { o.optBytes("file") }.getOrNull()
            s.refresh()
            return s
        }
    }
}

/** Compares bytes as unsigned, lexicographically, as Swift's and Go's byte comparisons do. */
internal fun compareBytes(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
        val c = (a[i].toInt() and 0xff).compareTo(b[i].toInt() and 0xff)
        if (c != 0) return c
    }
    return a.size.compareTo(b.size)
}
