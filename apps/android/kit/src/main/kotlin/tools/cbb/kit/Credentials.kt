// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.security.SecureRandom

/**
 * Server credentials (docs/protocol.md, section 18), as internal/group
 * makes and checks them. The group lives in periods of about 30 days. For
 * each, its root signs, inside the group, a period credential: a fresh tag
 * for the servers and a fresh period key. Each device signs with its
 * member key the server key it uses with the servers in that period. The
 * servers see only what the period key signs: the hubs' and the members'
 * credentials, padded lists of server key hashes under the period's tag.
 */
object ServerCredentials {
    const val PERIOD = "period"
    const val SERVER = "server"
    const val HUBS = "hubs"
    const val MEMBERS = "members"

    /** How long a period lasts, and how old it may get before the root starts the next. */
    const val PERIOD_LIFETIME_MS = 35L * 24 * 3600 * 1000
    const val PERIOD_RENEW_MS = 30L * 24 * 3600 * 1000

    const val MAX_HUBS = 16
    const val MAX_MEMBERS = 256
    const val MAX_ADMINS = 64
    private const val MAX_BODY = 16 shl 10

    /** The most credentials a member keeps and sends: the period, the hubs', the members' and one server credential per member. */
    const val MAX_CREDENTIALS = MAX_MEMBERS + 3

    class Refused(message: String) : Exception(message)

    /** A signed credential body: the body's exact bytes, an ECDSA P-256 signature over them, and the signer's SubjectPublicKeyInfo. */
    class Credential(val body: ByteArray, val sig: ByteArray, val key: ByteArray) {
        /** The hash of the key that signed it. */
        val signer: ByteArray get() = sha256(key)

        fun toJson(): JsonObject = Wire.obj("body" to Wire.bytes(body), "sig" to Wire.bytes(sig), "key" to Wire.bytes(key))

        /** Checks the signature and returns the body; it checks neither who signed it nor the group. */
        fun open(): Body {
            val b = Body.parse(body)
            if (p256PublicKey(key) == null) throw Refused("the credential's key is not a P-256 key")
            if (!verifySignature(key, body, sig)) throw Refused("the credential's signature does not verify")
            return b
        }

        override fun equals(other: Any?): Boolean =
            other is Credential && body.contentEquals(other.body) && sig.contentEquals(other.sig) && key.contentEquals(other.key)

        override fun hashCode(): Int = body.contentHashCode()

        companion object {
            fun fromJson(o: JsonObject): Credential =
                Credential(o.optBytes("body") ?: ByteArray(0), o.optBytes("sig") ?: ByteArray(0), o.optBytes("key") ?: ByteArray(0))
        }
    }

    /** What a credential says. */
    class Body(
        val v: Long = 1,
        val type: String,
        /** The group's own tag in a period or a server credential, the period's tag in a hubs' or a members' credential. */
        val group: String,
        val version: Long,
        val expiresMS: Long,
        /** A period's tag, or the period a server credential is for. */
        val tag: String = "",
        /** The period key or the server key (SubjectPublicKeyInfo). */
        val key: ByteArray = ByteArray(0),
        val hubs: List<ByteArray> = emptyList(),
        val admins: List<ByteArray> = emptyList(),
        val members: List<ByteArray> = emptyList(),
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "v" to Wire.num(v), "type" to Wire.str(type), "group" to Wire.str(group), "version" to Wire.num(version),
            "expires_ms" to Wire.num(expiresMS), "tag" to Wire.str(tag.ifEmpty { null }), "key" to Wire.bytes(key.takeIf { it.isNotEmpty() }),
            "hubs" to Wire.list(hubs.ifEmpty { null }), "admins" to Wire.list(admins.ifEmpty { null }), "members" to Wire.list(members.ifEmpty { null }),
        )

        internal fun check() {
            if (v != 1L) throw Refused("unknown credential version $v")
            if (version <= 0 || expiresMS <= 0) throw Refused("a credential without a version or an expiry")
            if (!validTag(group)) throw Refused("a credential's group is not a tag")
            if ((hubs + admins + members).any { it.size != 32 }) throw Refused("a credential lists a key hash that is not 32 bytes")
            when (type) {
                PERIOD, SERVER -> {
                    if (!validTag(tag)) throw Refused("a credential's period tag is not a tag")
                    if (p256PublicKey(key) == null) throw Refused("the credential's key is not a P-256 key")
                    if (hubs.size + admins.size + members.size != 0) throw Refused("a period or server credential lists keys")
                }
                HUBS -> {
                    if (hubs.size > MAX_HUBS || admins.size > MAX_ADMINS) throw Refused("a hubs' credential lists too many keys")
                    if (tag.isNotEmpty() || key.isNotEmpty() || members.isNotEmpty()) throw Refused("a hubs' credential carries more than its lists")
                }
                MEMBERS -> {
                    if (members.size > MAX_MEMBERS) throw Refused("a members' credential lists too many keys")
                    if (tag.isNotEmpty() || key.isNotEmpty() || hubs.size + admins.size != 0) throw Refused("a members' credential carries more than its list")
                }
                else -> throw Refused("unknown credential type \"$type\"")
            }
        }

        companion object {
            /** Reads and checks a credential's body: its size, the strict form of signed bodies, then its fields. */
            internal fun parse(data: ByteArray): Body {
                // The core decides whether the body is taken (parse_body).
                Core.bodyRefusal("credential", data)?.let { throw Refused("the credential is not valid: $it") }
                if (data.size > MAX_BODY) throw Refused("the credential is too large")
                try {
                    Strict.check(data, "v", "type", "group", "version", "expires_ms")
                } catch (e: Strict.Invalid) {
                    throw Refused("the credential is not valid: ${e.message}")
                }
                val o = Wire.parse(data) ?: throw Refused("the credential does not decode")
                return try {
                    fromJson(o).also { it.check() }
                } catch (e: WireTypeException) {
                    throw Refused("the credential does not decode: ${e.message}")
                }
            }

            fun fromJson(o: JsonObject): Body = Body(
                v = o.optLong("v") ?: 0, type = o.optString("type") ?: "", group = o.optString("group") ?: "",
                version = o.optLong("version") ?: 0, expiresMS = o.optLong("expires_ms") ?: 0, tag = o.optString("tag") ?: "",
                key = o.optBytes("key") ?: ByteArray(0), hubs = o.optBytesList("hubs") ?: emptyList(),
                admins = o.optBytesList("admins") ?: emptyList(), members = o.optBytesList("members") ?: emptyList(),
            )
        }
    }

    /** Whether s is a tag: 16 lower-case hex characters. */
    fun validTag(s: String): Boolean = s.length == 16 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /** The name of a server key at the relay: its fingerprint, the hash in standard base64. */
    fun pseudonym(keyHash: ByteArray): String = java.util.Base64.getEncoder().encodeToString(keyHash)

    /** A fresh tag for the servers: 8 random bytes in hex. */
    fun newPeriodTag(): String = ByteArray(8).also { SecureRandom().nextBytes(it) }.toHex()

    /** The next version after prev: one more, or the time in seconds if that is later, so a device that lost its state still goes forward. */
    fun nextVersion(prev: Long, nowMS: Long): Long = maxOf(prev + 1, nowMS / 1000)

    /** What the group's credentials must list, by member key (Go's Records.CredentialLists). */
    class Lists(val hubs: List<ByteArray>, val admins: List<ByteArray>, val members: List<ByteArray>)

    /**
     * The hubs in their order, at most MAX_HUBS; the admins that are not
     * frozen, other than the root's own device, which holds the period
     * key; and every device that is not frozen, at most MAX_MEMBERS.
     */
    fun lists(s: RecordSet): Lists {
        val root = s.rootMember()
        val devs = s.devices
        val hubs = mutableListOf<ByteArray>()
        for (id in s.hubOrder) {
            if (hubs.size == MAX_HUBS) break
            if (root != null && root.first == id) {
                hubs += hexBytes(root.second.hex)
                continue
            }
            devs.filter { it.id == id }.forEach { hubs += it.key }
        }
        val admins = mutableListOf<ByteArray>()
        val members = mutableListOf<ByteArray>()
        for (d in devs) {
            if (d.frozen) continue
            if (d.admin && d.id != root?.first && admins.size < MAX_ADMINS) admins += d.key
            if (members.size < MAX_MEMBERS) members += d.key
        }
        return Lists(hubs, admins, members)
    }

    private fun hexBytes(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    /** The size a list of n entries is padded to: the next of 4, 8, 16 and on. */
    fun padTo(n: Int): Int {
        var size = 4
        while (size < n) size *= 2
        return size
    }

    /** ks with random 32-byte entries up to padTo(ks.size): a key hash looks random, so the padding cannot be told from a real entry. */
    fun pad(ks: List<ByteArray>): List<ByteArray> {
        val r = SecureRandom()
        return ks + List(padTo(ks.size) - ks.size) { ByteArray(32).also(r::nextBytes) }
    }

    /** Signs b with key. */
    fun sign(b: Body, key: CertificateSigner): Credential {
        b.check()
        val data = Wire.encode(b.toJson())
        Body.parse(data)
        return Credential(data, key.signature(data), key.publicKeyDER)
    }

    /** The period credential: the root signs the period's tag and key for the group tagged groupTag. */
    fun signPeriod(groupTag: String, tag: String, periodKey: ByteArray, version: Long, nowMS: Long, root: CertificateSigner): Credential =
        sign(Body(type = PERIOD, group = groupTag, version = version, expiresMS = nowMS + PERIOD_LIFETIME_MS, tag = tag, key = periodKey), root)

    /** A device's server key for the period p, signed by its member key. */
    fun signServer(p: Body, serverKey: ByteArray, version: Long, member: CertificateSigner): Credential =
        sign(Body(type = SERVER, group = p.group, version = version, expiresMS = p.expiresMS, tag = p.tag, key = serverKey), member)

    /** The hubs' credential of the period p, signed by the period key. */
    fun signHubs(p: Body, hubs: List<ByteArray>, admins: List<ByteArray>, version: Long, periodKey: CertificateSigner): Credential {
        if (hubs.size > MAX_HUBS || admins.size > MAX_ADMINS) throw Refused("too many hubs or admins")
        return sign(Body(type = HUBS, group = p.tag, version = version, expiresMS = p.expiresMS, hubs = pad(hubs), admins = pad(admins)), periodKey)
    }

    /** The members' credential of the period p, signed by the period key or a listed admin's server key. */
    fun signMembers(p: Body, members: List<ByteArray>, version: Long, key: CertificateSigner): Credential {
        if (members.size > MAX_MEMBERS) throw Refused("too many members")
        return sign(Body(type = MEMBERS, group = p.tag, version = version, expiresMS = p.expiresMS, members = pad(members)), key)
    }

    /** What a server checked of the credentials a device presented (Go's Presented). */
    class Presented(val tag: String, val signer: ByteArray, val hubs: Body, val members: Body?, val period: Body?, val periodRoot: ByteArray?)

    /**
     * Checks the credentials a device presents a server, as Go's
     * CheckPresented: one hubs' credential, and with it at most one members'
     * credential of the same period, which the period key or an admin that
     * the hubs' credential lists signed, and at most one period credential
     * whose tag and key are those of the hubs' credential. None may have
     * expired at nowMS.
     */
    fun checkPresented(cs: List<Credential>, nowMS: Long): Presented {
        val wrong = Refused("the credentials are not a hubs' credential with at most a members' and a period credential")
        if (cs.isEmpty() || cs.size > 3) throw wrong
        val got = mutableMapOf<String, Pair<Body, Credential>>()
        for (c in cs) {
            val b = c.open()
            if (nowMS >= b.expiresMS) throw Refused("the ${b.type} credential expired")
            if (b.type !in setOf(HUBS, MEMBERS, PERIOD) || b.type in got) throw wrong
            got[b.type] = b to c
        }
        val (hubs, hc) = got[HUBS] ?: throw Refused("no hubs' credential")
        val members = got[MEMBERS]?.let { (b, c) ->
            if (b.group != hubs.group) throw Refused("a members' credential of another period")
            if (!c.key.contentEquals(hc.key) && hubs.admins.none { it.contentEquals(c.signer) }) {
                throw Refused("a members' credential that neither the period key nor a listed admin signed")
            }
            b
        }
        val period = got[PERIOD]?.let { (b, _) ->
            if (b.tag != hubs.group || !b.key.contentEquals(hc.key)) throw Refused("a period credential of another period")
            b
        }
        return Presented(hubs.group, hc.signer, hubs, members, period, got[PERIOD]?.second?.key)
    }
}

/**
 * A member's server credentials (Go's group.Credentials): the newest
 * period that the group's current root signed, and for it each member's
 * newest server credential and the newest hubs' and members' credentials.
 * Not safe for concurrent use; MemberNode keeps it under its lock.
 */
class CredentialStore(private val groupCA: ByteArray) {
    private var period: ServerCredentials.Credential? = null
    private val servers = linkedMapOf<Key, ServerCredentials.Credential>() // by the member key that signed it
    private var hubs: ServerCredentials.Credential? = null
    private var members: ServerCredentials.Credential? = null

    private fun rank(c: ServerCredentials.Credential): Int =
        listOf(ServerCredentials.PERIOD, ServerCredentials.SERVER, ServerCredentials.HUBS, ServerCredentials.MEMBERS)
            .indexOf(Wire.parse(c.body)?.optString("type"))

    private fun periodOf(root: ByteArray): ServerCredentials.Body? {
        val p = period ?: return null
        if (!p.key.contentEquals(root)) return null
        return runCatching { p.open() }.getOrNull()
    }

    private fun newer(old: ServerCredentials.Credential?, b: ServerCredentials.Body): Boolean =
        old == null || runCatching { b.version > old.open().version }.getOrDefault(true)

    /**
     * Takes the credentials that are valid for the group and newer than
     * what it keeps, and returns those it took, with the errors of those it
     * dropped. root is the current root's SubjectPublicKeyInfo; isMember
     * tells whether a key hash is the member key of a device in the group.
     * A newer period with another tag drops the credentials of the one
     * before.
     */
    fun add(root: ByteArray, isMember: (ByteArray) -> Boolean, cs: List<ServerCredentials.Credential>): Pair<List<ServerCredentials.Credential>, List<String>> {
        val tag = GroupCertificates.tag(groupCA)
        val fresh = mutableListOf<ServerCredentials.Credential>()
        val errs = mutableListOf<String>()
        for (c in cs.sortedBy(::rank)) {
            val b = try {
                c.open()
            } catch (e: ServerCredentials.Refused) {
                errs += e.message ?: "refused"
                continue
            }
            val p = periodOf(root)
            when (b.type) {
                ServerCredentials.PERIOD -> {
                    if (b.group != tag) { errs += "a period of another group"; continue }
                    if (!c.key.contentEquals(root)) { errs += "a period that the group's root did not sign"; continue }
                    if (!newer(if (p != null) period else null, b)) continue
                    if (p == null || p.tag != b.tag) {
                        servers.clear()
                        hubs = null
                        members = null
                    }
                    period = c
                }
                ServerCredentials.SERVER -> {
                    if (p == null || b.group != tag || b.tag != p.tag) continue
                    if (!isMember(c.signer)) { errs += "a server credential that no member signed"; continue }
                    val k = Key(c.signer)
                    val old = servers[k]
                    if (old != null && !newer(old, b)) continue
                    if (old == null && servers.size >= ServerCredentials.MAX_MEMBERS) { errs += "too many server credentials"; continue }
                    servers[k] = c
                }
                ServerCredentials.HUBS -> {
                    if (p == null || b.group != p.tag) continue
                    if (!c.key.contentEquals(p.key)) { errs += "a hubs' credential that the period key did not sign"; continue }
                    if (!newer(hubs, b)) continue
                    hubs = c
                }
                ServerCredentials.MEMBERS -> {
                    if (p == null || b.group != p.tag) continue
                    val admin = runCatching { hubs?.open()?.admins?.any { it.contentEquals(c.signer) } }.getOrNull() == true
                    if (!c.key.contentEquals(p.key) && !admin) { errs += "a members' credential that neither the period key nor a listed admin signed"; continue }
                    if (!newer(members, b)) continue
                    members = c
                }
            }
            fresh += c
        }
        return fresh to errs
    }

    /** Every credential it keeps, the period first. */
    val all: List<ServerCredentials.Credential>
        get() = listOfNotNull(period) + servers.values + listOfNotNull(hubs, members)

    /** The period kept, if the current root signed it. */
    fun period(root: ByteArray): Pair<ServerCredentials.Credential, ServerCredentials.Body>? =
        periodOf(root)?.let { period!! to it }

    /** The hash of the server key the member key hash member signed for the period. */
    fun server(member: ByteArray): ByteArray? = servers[Key(member)]?.let { runCatching { sha256(it.open().key) }.getOrNull() }

    /** The member key that signed the server key whose hash is k. */
    fun memberOfServer(k: ByteArray): ByteArray? =
        servers.values.firstOrNull { c -> runCatching { sha256(c.open().key).contentEquals(k) }.getOrDefault(false) }?.signer

    /** The server keys of the member keys ms, in their order, leaving out those without one. */
    fun serverKeys(ms: List<ByteArray>): List<ByteArray> = ms.mapNotNull { server(it) }

    fun hubs(): Pair<ServerCredentials.Credential, ServerCredentials.Body>? = hubs?.let { c -> runCatching { c to c.open() }.getOrNull() }

    fun members(): Pair<ServerCredentials.Credential, ServerCredentials.Body>? = members?.let { c -> runCatching { c to c.open() }.getOrNull() }

    /**
     * Whether the root should start a new period: none kept, one older
     * than PERIOD_RENEW_MS, or one with a server credential that no member
     * of the group signed any more (a removal).
     */
    fun periodStale(root: ByteArray, isMember: (ByteArray) -> Boolean, nowMS: Long): Boolean {
        val p = periodOf(root) ?: return true
        if (nowMS >= p.expiresMS - ServerCredentials.PERIOD_LIFETIME_MS + ServerCredentials.PERIOD_RENEW_MS) return true
        return servers.values.any { !isMember(it.signer) }
    }

    /**
     * Whether a list a credential holds is not the list want: want must be
     * its first entries, in its order when ordered, and the rest padding.
     */
    fun listStale(got: List<ByteArray>, want: List<ByteArray>, ordered: Boolean): Boolean {
        if (got.size != ServerCredentials.padTo(want.size) && !(want.isEmpty() && got.size == 4)) return true
        if (ordered) return want.indices.any { !got[it].contentEquals(want[it]) }
        val head = got.take(want.size).map { Key(it) }.toSet()
        return want.any { Key(it) !in head }
    }

    fun toJson(): JsonArray = JsonArray(all.map { it.toJson() })

    /**
     * What a device registers with at a relay (docs/protocol.md, section
     * 18): the hubs' and the members' credentials, then the period; the
     * group's roots, the group CA first; and the pseudonyms of the group's
     * devices with the IDs they stand for.
     */
    class Registration(val credentials: List<ServerCredentials.Credential>, val roots: List<ByteArray>, val names: Map<String, String>)

    /**
     * The registration with these credentials for the device whose server
     * key hashes to mine, or null until the members' credential lists it;
     * root is the current root's key, records the group's records.
     */
    fun registration(records: RecordSet, root: ByteArray, mine: ByteArray): Registration? {
        val (pc, _) = period(root) ?: return null
        val (hc, _) = hubs() ?: return null
        val (mc, mb) = members() ?: return null
        if (mb.members.none { it.contentEquals(mine) }) return null
        val names = buildMap {
            for (d in records.devices) for (k in d.keys) server(k)?.let { put(ServerCredentials.pseudonym(it), d.id) }
        }
        return Registration(listOf(hc, mc, pc), listOf(groupCA) + records.roots, names)
    }

    companion object {
        /** A store with the credentials of a saved array, those that still count. */
        fun fromJson(a: JsonArray, groupCA: ByteArray, root: ByteArray, isMember: (ByteArray) -> Boolean): CredentialStore =
            CredentialStore(groupCA).apply {
                add(root, isMember, a.mapNotNull { runCatching { ServerCredentials.Credential.fromJson(it.jsonObject) }.getOrNull() })
            }
    }
}

/**
 * A device's keys for the servers, one set per period (Go's
 * group.ServerKeys): its server key, and on the root that started the
 * period, the period key. The app keeps them in the Keystore or the Secure
 * Enclave, without user presence, since they sign in the background.
 */
interface PeriodKeys {
    /** The key of kind (SERVER_KEY or PERIOD_KEY) for the period tag, made when there is none. */
    fun get(kind: String, tag: String): CertificateSigner

    fun has(kind: String, tag: String): Boolean

    /** Drops the keys of every period but tag. */
    fun keep(tag: String)

    companion object {
        const val SERVER_KEY = "server"
        const val PERIOD_KEY = "period"
    }
}

/**
 * Brings a device's server credentials up to date as far as it can, as
 * Go's refreshCredential (docs/protocol.md, section 18), and returns what
 * it signed and the store took, for the peers. On the current root, a new
 * period when the one kept is due or a member that sent its server key
 * left the group; on every member, its server key for the period; on the
 * root, the hubs' and the members' credentials when they list other keys
 * than the records and the server credentials say; on an admin that the
 * hubs' credential lists, the members' credential.
 *
 * root is the current root's certificate; rootSigner, given only on the
 * phone that holds that root, is asked for its key when a period must be
 * signed, about once a month, and returns null while the key cannot sign
 * without asking the user: the period then waits for the next refresh.
 */
object CredentialRefresh {
    fun refresh(
        store: CredentialStore,
        records: RecordSet,
        groupCA: ByteArray,
        root: ByteArray,
        member: CertificateSigner,
        keys: PeriodKeys,
        nowMS: Long,
        rootSigner: (() -> CertificateSigner?)? = null,
    ): List<ServerCredentials.Credential> {
        val rootKey = CertificateInfo(root).publicKey
        val isMember = { k: ByteArray -> isMember(records, k) }
        val signed = mutableListOf<ServerCredentials.Credential>()
        fun add(c: ServerCredentials.Credential) {
            signed += store.add(rootKey, isMember, listOf(c)).first
        }

        val rs = if (rootSigner != null && store.periodStale(rootKey, isMember, nowMS)) rootSigner() else null
        if (rs != null) {
            val tag = ServerCredentials.newPeriodTag()
            val pk = keys.get(PeriodKeys.PERIOD_KEY, tag)
            val prev = store.period(rootKey)?.second?.version ?: 0
            add(ServerCredentials.signPeriod(GroupCertificates.tag(groupCA), tag, pk.publicKeyDER, ServerCredentials.nextVersion(prev, nowMS), nowMS, rs))
        }
        val p = store.period(rootKey)?.second ?: return signed
        keys.keep(p.tag)

        val sk = keys.get(PeriodKeys.SERVER_KEY, p.tag)
        val mine = sha256(sk.publicKeyDER)
        if (store.server(sha256(member.publicKeyDER))?.contentEquals(mine) != true) {
            add(ServerCredentials.signServer(p, sk.publicKeyDER, ServerCredentials.nextVersion(0, nowMS), member))
        }

        val l = ServerCredentials.lists(records)
        val hubs = store.serverKeys(l.hubs)
        val admins = store.serverKeys(l.admins)
        val members = store.serverKeys(l.members)
        val hb = store.hubs()?.second
        val signer = when {
            rootSigner != null && keys.has(PeriodKeys.PERIOD_KEY, p.tag) -> {
                val pk = keys.get(PeriodKeys.PERIOD_KEY, p.tag)
                if (hb == null || store.listStale(hb.hubs, hubs, true) || store.listStale(hb.admins, admins, false)) {
                    add(ServerCredentials.signHubs(p, hubs, admins, ServerCredentials.nextVersion(hb?.version ?: 0, nowMS), pk))
                }
                pk
            }
            hb != null && hb.admins.any { it.contentEquals(mine) } -> sk
            else -> return signed
        }
        val mb = store.members()?.second
        if (mb == null || store.listStale(mb.members, members, false)) {
            add(ServerCredentials.signMembers(p, members, ServerCredentials.nextVersion(mb?.version ?: 0, nowMS), signer))
        }
        return signed
    }

    /** Whether k is the member key of a device of the group that is not frozen (Go's Records.IsMember). */
    fun isMember(records: RecordSet, k: ByteArray): Boolean = records.devices.any { d -> !d.frozen && d.keys.any { it.contentEquals(k) } }
}
