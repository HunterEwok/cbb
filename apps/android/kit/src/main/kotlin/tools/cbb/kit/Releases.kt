// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The signed files that describe a release (docs/protocol.md, section 16):
 * keys.json, in which a root key certifies the release keys; release.json,
 * which lists a release's files with their hashes; and a channel file such
 * as stable.json, which names the current release of its channel until it
 * expires. The same keys.json certifies the status key that signs
 * attest-status.json, the mirror of Google's revocation list for Android
 * attestations (section 17), and the keys of entries.json. The Rust core
 * checks them all (release_check, docs/core-api.md, "Release files"): both
 * signatures of every file, the roots it pins, the expiries and the sequence
 * numbers. The kit only carries the files and reads the answer.
 */
object Releases {
    /** The largest body a file may carry. */
    const val MAX_BODY = 256 shl 10

    /** The largest file, its body and its signatures, a device downloads. */
    const val MAX_FILE = 1 shl 20

    class Refused(message: String) : Exception(message)

    /**
     * A release file as it was fetched: the kit reads nothing of it, the core reads its bytes as
     * every reader does (docs/core-api.md, "Release files").
     */
    class File(val data: ByteArray) {
        /** The file as the core's release calls take it: its bytes in base64. */
        fun toJson(): JsonElement = JsonPrimitive(java.util.Base64.getEncoder().encodeToString(data))
    }

    /** A root key's half, for tests and drills that sign with roots of their own: the core uses the roots it pins when none are given. */
    class Key(val alg: Long, val key: ByteArray, val name: String, val use: String) {
        fun toJson(): JsonObject = Wire.obj("alg" to Wire.num(alg), "key" to Wire.bytes(key), "name" to Wire.str(name), "use" to Wire.str(use))

        companion object {
            fun fromJson(o: JsonObject): Key = Key(o.optLong("alg") ?: 0, o.optBytes("key") ?: ByteArray(0), o.optString("name") ?: "", o.optString("use") ?: "")
        }
    }

    class Asset(val name: String, val size: Long, val sha256: String, val binaries: List<Pair<String, String>>)

    class Release(val version: String, val channel: String, val minFrom: String, val files: List<Asset>, val docker: Pair<String, String>?) {
        /** Whether a device at installed may update to this release in one step, or must first take minFrom. */
        fun direct(installed: String): Boolean = minFrom.isEmpty() || compare(installed, minFrom) >= 0

        /** Checks that data is the release's file name. */
        fun checkFile(name: String, data: ByteArray) {
            val a = files.firstOrNull { it.name == name } ?: throw Refused("$name is not in the release")
            if (a.size != data.size.toLong() || hex(sha256(data)) != a.sha256) throw Refused("$name does not match release.json")
        }
    }

    /**
     * What a device keeps between checks: the highest sequence numbers and version it has taken, as
     * the core gives them back. A channel or status seq holds only under the keys.json that
     * certified its signer ([channelKeysSeq], [statusKeysSeq]): a newer keys.json, which only a
     * root signs, starts them again.
     */
    data class Seen(
        val keysSeq: Long = 0,
        val channelSeq: Long = 0,
        val version: String = "",
        val statusSeq: Long = 0,
        val channelKeysSeq: Long = 0,
        val statusKeysSeq: Long = 0,
        /** The highest entries.json seq taken and the keys.json seq it was taken under, kept apart from the release's. */
        val entriesSeq: Long = 0,
        val entriesKeysSeq: Long = 0,
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "keys_seq" to Wire.num(keysSeq),
            "channel_seq" to Wire.num(channelSeq),
            "version" to Wire.str(version),
            "status_seq" to Wire.num(statusSeq),
            "channel_keys_seq" to Wire.num(channelKeysSeq),
            "status_keys_seq" to Wire.num(statusKeysSeq),
            "entries_seq" to Wire.num(entriesSeq),
            "entries_keys_seq" to Wire.num(entriesKeysSeq),
        )

        companion object {
            fun fromJson(o: JsonObject): Seen = Seen(
                o.optLong("keys_seq") ?: 0,
                o.optLong("channel_seq") ?: 0,
                o.optString("version") ?: "",
                o.optLong("status_seq") ?: 0,
                o.optLong("channel_keys_seq") ?: 0,
                o.optLong("status_keys_seq") ?: 0,
                o.optLong("entries_seq") ?: 0,
                o.optLong("entries_keys_seq") ?: 0,
            )
        }
    }

    /** The body of attest-status.json: the serial numbers Google's list revokes, as AndroidAttestation.Policy takes them. */
    class Status(val seq: Long, val timeMS: Long, val expiresMS: Long, val sourceMS: Long, val androidRevoked: List<String>)

    private val VERSION = Regex("^(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})(-rc\\.([1-9][0-9]{0,5}))?$")

    /** X, Y, Z and the release candidate's number, Int.MAX_VALUE for a release. */
    private fun parseVersion(s: String): List<Int>? {
        val m = VERSION.matchEntire(s) ?: return null
        val g = m.groupValues
        return listOf(g[1].toInt(), g[2].toInt(), g[3].toInt(), if (g[5].isEmpty()) Int.MAX_VALUE else g[5].toInt())
    }

    /** Compares two versions X.Y.Z or X.Y.Z-rc.N, a release candidate before its release; a string that is not a version sorts below every version. */
    fun compare(a: String, b: String): Int {
        val pa = parseVersion(a)
        val pb = parseVersion(b)
        if (pa == null || pb == null) return (if (pa != null) 1 else 0) - (if (pb != null) 1 else 0)
        for (i in 0 until 4) if (pa[i] != pb[i]) return pa[i].compareTo(pb[i]).coerceIn(-1, 1)
        return 0
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /**
     * Asks the core for the release call [op]: the file's fields and the Seen to keep. A file it
     * refuses is [Refused], with its reason; any other refusal is the kit's mistake and stays the
     * core's.
     */
    private fun ask(op: String, roots: List<Key>?, nowMS: Long, seen: Seen, vararg files: Pair<String, JsonElement?>): Pair<JsonObject, Seen> {
        val args = Wire.obj(
            "roots" to roots?.let { r -> JsonArray(r.map { it.toJson() }) },
            "now_ms" to Wire.num(nowMS),
            "seen" to seen.toJson(),
            *files,
        )
        val ok = try {
            Core.run(op, args).jsonObject
        } catch (r: Core.Refusal) {
            if (r.name != "signed") throw r
            throw Refused(r.details?.takeIf { it.isNotEmpty() }?.let { "${r.message}: $it" } ?: r.message)
        }
        val value = ok.optObject("value") ?: throw Core.Mismatch("the answer to $op has no value")
        val next = ok.optObject("seen") ?: throw Core.Mismatch("the answer to $op has no seen")
        return value to Seen.fromJson(next)
    }

    private fun release(o: JsonObject): Release = Release(
        o.optString("version") ?: "",
        o.optString("channel") ?: "",
        o.optString("min_from") ?: "",
        o.optArray("files")?.map { a ->
            val ao = a.jsonObject
            Asset(
                ao.optString("name") ?: "",
                ao.optLong("size") ?: 0,
                ao.optString("sha256") ?: "",
                ao.optArray("binaries")?.map { b -> b.jsonObject.let { (it.optString("name") ?: "") to (it.optString("sha256") ?: "") } } ?: emptyList(),
            )
        } ?: emptyList(),
        o.optObject("docker")?.let { (it.optString("image") ?: "") to (it.optString("digest") ?: "") },
    )

    /**
     * Checks a channel file and the release.json it names: keys.json under the roots (the pinned
     * ones when null), the channel file under its release or channel keys and release.json under
     * its release keys, the channel's name, both expiries, and that nothing is older than seen.
     * Returns the release and the Seen to keep.
     */
    fun check(keys: File, channel: File, release: File, roots: List<Key>? = null, name: String, nowMS: Long, seen: Seen): Pair<Release, Seen> {
        val (v, next) = ask("release_check", roots, nowMS, seen, "keys" to keys.toJson(), "channel" to channel.toJson(), "release" to release.toJson(), "name" to Wire.str(name))
        return release(v) to next
    }

    /**
     * The version a channel file names, read by the core before the file is checked, to know
     * which release.json to fetch; [check] then checks both. Null when the file is not a channel
     * file.
     */
    fun named(channel: File): String? = try {
        Core.run("release_named", Wire.obj("channel" to channel.toJson())).jsonObject.optString("release")?.takeIf { parseVersion(it) != null }
    } catch (r: Core.Refusal) {
        if (r.name != "signed") throw r
        null
    }

    /**
     * Checks attest-status.json: keys.json under the roots (the pinned ones when null), the list
     * under a status key of it, its expiry, and that neither is older than seen. Returns the list
     * and the Seen to keep.
     */
    fun checkStatus(keys: File, status: File, roots: List<Key>? = null, nowMS: Long, seen: Seen): Pair<Status, Seen> {
        val (v, next) = ask("release_check_status", roots, nowMS, seen, "keys" to keys.toJson(), "status" to status.toJson())
        val list = v.optArray("android_revoked")?.map { (it as JsonPrimitive).content } ?: emptyList()
        return Status(v.optLong("seq") ?: 0, v.optLong("time_ms") ?: 0, v.optLong("expires_ms") ?: 0, v.optLong("source_ms") ?: 0, list) to next
    }

    /** A way in over VLESS to a forwarder that entries.json lists. */
    data class EntryVLESS(val transport: String, val serverName: String, val port: Int, val path: String) {
        fun toJson(): JsonObject = JsonObject(
            mapOf("transport" to JsonPrimitive(transport), "server_name" to JsonPrimitive(serverName), "port" to JsonPrimitive(port), "path" to JsonPrimitive(path)),
        )
    }

    /** A forwarder of the project in entries.json: host:port and its ways in. */
    data class EntryForwarder(val name: String, val vless: List<EntryVLESS>)

    /** The body of entries.json, the signed list of the project's entry points (docs/protocol.md, section 16, "Entry points"). */
    class Entries(val seq: Long, val timeMS: Long, val expiresMS: Long, val forwarders: List<EntryForwarder>) {
        /** The entry of the forwarder named [name]. */
        fun forwarder(name: String): EntryForwarder? = forwarders.firstOrNull { it.name == name }
    }

    /**
     * The signed entry points as members pass them, `{"keys": keys.json, "entries": entries.json}`,
     * as they were received or kept: the core reads them.
     */
    class EntriesSet(val data: ByteArray)

    /**
     * Checks entries.json: keys.json under the roots (the pinned ones when null), the list under a
     * release or channel key of it, its expiry, and that neither is older than seen. Returns the
     * list and the Seen to keep.
     */
    fun checkEntries(set: EntriesSet, roots: List<Key>? = null, nowMS: Long, seen: Seen): Pair<Entries, Seen> {
        val (v, next) = ask("release_check_entries", roots, nowMS, seen, "set" to Wire.bytes(set.data))
        val fws = v.optArray("forwarders")?.map { f ->
            val fo = f.jsonObject
            val ways = fo.optArray("vless")?.map { w ->
                val wo = w.jsonObject
                EntryVLESS(wo.optString("transport") ?: "", wo.optString("server_name") ?: "", (wo.optLong("port") ?: 0).toInt(), wo.optString("path") ?: "")
            } ?: emptyList()
            EntryForwarder(fo.optString("name") ?: "", ways)
        } ?: emptyList()
        return Entries(v.optLong("seq") ?: 0, v.optLong("time_ms") ?: 0, v.optLong("expires_ms") ?: 0, fws) to next
    }
}
