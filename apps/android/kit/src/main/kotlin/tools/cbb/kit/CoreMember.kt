// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import java.io.Closeable
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The phone's member in the Rust core (docs/core-api.md, "The member"): the
 * lite member's node on threads of its own inside the app, through the C
 * functions cbb_member_start, cbb_member_call and cbb_member_stop of
 * lite/ffi, loaded by JNA from libcbb_ffi as [Core] loads it. It dials the
 * members the app hands in ([found]), syncs with them and calls the app back
 * with each [Event]; the app finds the members itself (NSD), and the node
 * starts with mDNS off.
 *
 * The device key stays where the app keeps it: the node signs its TLS
 * handshakes and its copies through sign, which gets a SHA-256 digest and
 * returns an ECDSA P-256 signature in DER.
 *
 * [fetch], [command] and [waitConnected] wait for the network: the app calls
 * them off its main thread. The other calls answer at once. Every call
 * throws [Core.Refusal] when the node refuses it.
 */
class CoreMember private constructor(internal val handle: Pointer, private val callbacks: Callbacks) : Closeable {
    /** What the member starts from: the app's data directory and the phone's identity in the group. */
    class Start(
        /** The node's own files (its records, the clock's mark, the entry points, the cached copies). */
        val dir: File,
        val name: String,
        val os: String,
        val osVersion: String = "",
        val version: String = "",
        /** Where the key lives: hardware (the Keystore's TEE or StrongBox) or file. */
        val keyStore: String = "hardware",
        val device: String,
        /** The member key's public key: a SubjectPublicKeyInfo or an uncompressed point. */
        val publicKey: ByteArray,
        /** The secret for sealed messages, 32 bytes. */
        val seal: ByteArray,
        val cert: ByteArray,
        val issuer: ByteArray? = null,
        val groupCA: ByteArray,
        val roots: List<ByteArray> = emptyList(),
        /** Members to dial at these addresses (host:port) from the start. */
        val peers: List<String> = emptyList(),
        /** Whether the node finds the members by mDNS itself; the apps find them and hand them in. */
        val mdns: Boolean = false,
    ) {
        internal fun toJson(): JsonObject = Wire.obj(
            "dir" to Wire.str(dir.path),
            "name" to Wire.str(name),
            "os" to Wire.str(os),
            "os_version" to Wire.str(osVersion),
            "version" to Wire.str(version),
            "key_store" to Wire.str(keyStore),
            "device" to Wire.str(device),
            "public" to Wire.bytes(point(publicKey)),
            "seal" to Wire.bytes(seal),
            "cert" to Wire.bytes(cert),
            "issuer" to Wire.bytes(issuer),
            "group_ca" to Wire.bytes(groupCA),
            "roots" to JsonArray(roots.map { Wire.bytes(it)!! }),
            "peers" to JsonArray(peers.map { JsonPrimitive(it) }),
            "mdns" to JsonPrimitive(mdns),
        )
    }

    /** A copy as the node shows it: its header, its content when this phone opened it, and the key the button compares it by. */
    data class Copy(
        val id: String,
        val origin: String,
        val ageMS: Long,
        val kind: Member.Kind,
        val via: Member.Via,
        val text: String,
        val media: Media.Manifest?,
        val unread: Boolean,
        val key: String,
    ) {
        /** Whether it carries files or folders, which the phone saves rather than putting in its clipboard. */
        val isFiles: Boolean get() = media?.isFiles == true

        companion object {
            internal fun fromJson(o: JsonObject): Copy = Copy(
                o.optString("id") ?: "",
                o.optString("origin") ?: "",
                o.optLong("age_ms") ?: 0,
                o.optString("kind")?.let { Member.Kind.of(it) } ?: Member.Kind.TEXT,
                o.optString("via")?.let { Member.Via.of(it) } ?: Member.Via.COPY,
                o.optString("text") ?: "",
                o.optObject("media")?.let { runCatching { Media.Manifest.fromJson(it) }.getOrNull() },
                o.optBool("unread") ?: false,
                o.optString("key") ?: "",
            )
        }
    }

    /** A connected member as its hello and reach messages present it, with its chain as the handshake checked it, leaf first. */
    data class Peer(
        val device: String,
        val name: String,
        val role: String,
        val os: String,
        val keyStore: String,
        val mode: String,
        val muted: Boolean,
        val mutedForMS: Long,
        val actions: List<String>,
        val info: Member.DeviceInfo?,
        val adminKey: ByteArray?,
        val tunnelKey: ByteArray?,
        val tunnelPSK: ByteArray?,
        val reach: List<String>,
        val recordsOnly: Boolean,
        val features: List<String>,
        val chain: List<ByteArray>,
    ) {
        /** Whether it serves the content of copies with images or files. */
        val media: Boolean get() = Member.FEATURE_MEDIA in features

        /** Until when an admin muted it, in Unix milliseconds, 0 for until it is lifted; null when it is not muted. */
        fun mutedUntil(now: Long = System.currentTimeMillis()): Long? = if (!muted) null else if (mutedForMS <= 0) 0 else now + mutedForMS

        companion object {
            internal fun fromJson(o: JsonObject): Peer = Peer(
                o.optString("device") ?: "",
                o.optString("name") ?: "",
                o.optString("role") ?: "",
                o.optString("os") ?: "",
                o.optString("key_store") ?: "",
                o.optString("mode") ?: "",
                o.optBool("muted") ?: false,
                o.optLong("muted_for_ms") ?: 0,
                o.strings("actions"),
                runCatching { Member.DeviceInfo.fromJson(o.opt("info")) }.getOrNull(),
                o.optBytes("admin_key"),
                o.optBytes("tunnel_key"),
                o.optBytes("tunnel_psk"),
                o.strings("reach"),
                o.optBool("records_only") ?: false,
                o.strings("features"),
                o.optBytesList("chain") ?: emptyList(),
            )
        }
    }

    /** A part of images or files the phone sends: clipboard data of a type, or a file or folder at a path with the file on the phone. */
    class Part private constructor(val type: String?, val path: String?, val dir: Boolean, val data: ByteArray?, val file: File?) {
        internal fun toJson(): JsonObject = Wire.obj(
            "type" to Wire.str(type),
            "path" to Wire.str(path),
            "dir" to JsonPrimitive(dir),
            "data" to Wire.bytes(data),
            "file" to Wire.str(file?.path),
        )

        companion object {
            /** Clipboard data, such as an image/png. */
            fun data(type: String, bytes: ByteArray) = Part(type, null, false, bytes, null)

            /** A file at path in the copy, with its bytes. */
            fun file(path: String, bytes: ByteArray) = Part(null, path, false, bytes, null)

            /** A file at path in the copy, read from the phone's file. */
            fun file(path: String, file: File) = Part(null, path, false, null, file)

            /** A folder at path in the copy. */
            fun folder(path: String) = Part(null, path, true, null, null)
        }
    }

    /** A part [fetch] opened: the manifest's part and where its file is now (none for a folder). */
    class Fetched(val type: String?, val path: String?, val dir: Boolean, val size: Long, val file: File)

    /** What the node tells the app, on the app's executor. */
    sealed class Event {
        /** A text for the phone's clipboard, with how long a secret may stay there. */
        data class Write(val text: String, val kind: Member.Kind, val ttlMS: Long?) : Event()

        data class Log(val line: String) : Event()

        /** A copy that became the group's current one from another member. */
        data class CopyChanged(val copy: Copy) : Event()

        /** An admin, hubs, credentials or evidence message a peer sent, decoded as the member protocol carries it. */
        class Message(val from: String, val message: Member.Message) : Event()

        /** The phone's certificate an admin renewed, or the roots after a takeover; the app keeps them. */
        class Identity(val cert: ByteArray, val issuer: ByteArray?, val roots: List<ByteArray>) : Event()

        /** A peer whose hello the node took. */
        data class PeerConnected(val peer: Peer) : Event()

        /** A tunnel offer of the group's root or an admin. */
        class Tunnel(val from: String, val offer: Member.TunnelOffer) : Event()

        /** A command for this phone itself, which the app checks, carries out and answers with [answer] and the token within ten seconds. */
        class Command(val token: Long, val from: String, val command: Member.Record) : Event()

        /**
         * A call to the relay's port from the loopback port [port], whose certificate names [device]: the app names the caller the
         * relay announced from there with [caller] and the token within five seconds, or the call is closed.
         */
        class Caller(val token: Long, val port: Int, val device: String) : Event()

        /** An admin muted this phone for [forMS] milliseconds (0: until an admin lifts it), or ended its mute; the node carried it out and keeps it. */
        class Mute(val muted: Boolean, val forMS: Long, val by: String) : Event()
    }

    /** What a member port is for. */
    enum class Listen(val wire: String) {
        /** The home network, while the phone is the hub: every address; the app publishes it with r=phone. */
        HOME("home"),

        /** The hub's tunnel, on the loopback address. */
        TUNNEL("tunnel"),

        /** A blind relay's calls, on the loopback address, each served only when the app names its caller ([Event.Caller]). */
        RELAY("relay"),
    }

    private val closed = AtomicBoolean(false)

    // The clipboard and the button (docs/design.md, "The one button").

    /** Sends a text; board says it came from the phone's clipboard, which the button then compares with it. */
    fun copy(text: String, secret: Boolean = false, board: Boolean = true) {
        call("copy", Wire.obj("text" to Wire.str(text), "secret" to JsonPrimitive(secret), "board" to JsonPrimitive(board)))
    }

    /** Sends images or files with their plain-text alternative; board says they came from the phone's clipboard. */
    fun copyMedia(text: String, parts: List<Part>, board: Boolean = false): Copy {
        val ok = call("copy_media", Wire.obj("text" to Wire.str(text), "parts" to JsonArray(parts.map { it.toJson() }), "board" to JsonPrimitive(board)))
        return (ok.optObject("copy") ?: throw Core.Mismatch("copy_media answered no copy")).let(Copy::fromJson)
    }

    /** The group's current copy, or null. */
    fun current(): Copy? = call("current").optObject("copy")?.let(Copy::fromJson)

    /** The copy from another device that waits for the phone (the button's first case), or null. */
    fun waiting(): Copy? = call("waiting").optObject("copy")?.let(Copy::fromJson)

    /** The app took the copy id into the clipboard, or saved its files, so that it waits no more. */
    fun took(id: String) {
        call("took", Wire.obj("id" to Wire.str(id)))
    }

    /** Whether the button sends what the clipboard holds, by its key (the button's second case). */
    fun sends(board: String): Boolean = call("sends", Wire.obj("board" to Wire.str(board))).optBool("sends") ?: false

    /** Fetches the images or files of the group's copy id, unless its sealed blob is larger than max bytes, and opens them into the new folder out. Blocks. */
    fun fetch(id: String, max: Long, out: File): List<Fetched> =
        call("fetch", Wire.obj("id" to Wire.str(id), "max" to Wire.num(max), "out" to Wire.str(out.path))).optArray("parts").orEmpty().map {
            val o = it as? JsonObject ?: throw Core.Mismatch("fetch answered a part that is not an object")
            Fetched(o.optString("type"), o.optString("path"), o.optBool("dir") ?: false, o.optLong("size") ?: 0, File(o.optString("file") ?: ""))
        }

    // Finding the members, listening, the app's life.

    /** How far the peers read the sealed blob of the group's copy [id] this phone made, and its size; zeros for a copy no longer the group's or with no bytes. */
    fun served(id: String): Pair<Long, Long> {
        val ok = call("served", Wire.obj("id" to Wire.str(id)))
        return (ok.optLong("served") ?: 0) to (ok.optLong("size") ?: 0)
    }

    /** Dials the member the app knows as key (an NSD name, the tunnel) at addrs (host:port), again and again until [lost]; device when known. */
    fun found(key: String, addrs: List<String>, device: String? = null) {
        call("found", Wire.obj("key" to Wire.str(key), "addrs" to JsonArray(addrs.map { JsonPrimitive(it) }), "device" to Wire.str(device)))
    }

    /** Stops dialing the member the app lost. */
    fun lost(key: String) {
        call("lost", Wire.obj("key" to Wire.str(key)))
    }

    /** Opens a member port for [what] on port (0: any free one); the port, one open already for [what] staying. */
    fun listen(what: Listen = Listen.HOME, port: Int = 0): Int =
        call("listen", Wire.obj("port" to Wire.num(port.toLong()), "kind" to Wire.str(what.wire))).optLong("port")?.toInt()
            ?: throw Core.Mismatch("listen answered no port")

    /** Closes the port [listen] opened for [what], or every one with null. */
    fun unlisten(what: Listen? = null) {
        call("unlisten", Wire.obj("kind" to (what?.let { Wire.str(it.wire) } ?: JsonNull)))
    }

    /** Answers an [Event.Caller]: the device the relay announced from the call's loopback port, null for a call it did not announce. */
    fun caller(token: Long, device: String?) {
        call("caller", Wire.obj("token" to JsonPrimitive(token), "device" to (device?.let { Wire.str(it) } ?: JsonNull)))
    }

    /** Closes every connection with a goodbye and makes none until [resume]: the app went to the background. */
    fun pause() {
        call("pause")
    }

    fun resume() {
        call("resume")
    }

    /** Waits up to timeoutMS for a member to connect. Blocks. */
    fun waitConnected(timeoutMS: Long): Boolean = call("wait", Wire.obj("timeout_ms" to Wire.num(timeoutMS))).optBool("connected") ?: false

    /** Sets the sync mode the hellos say; the members see it at the next connection, which comes at once. */
    fun setMode(mode: String) {
        call("mode", Wire.obj("mode" to Wire.str(mode)))
    }

    /** Sets until when an admin muted this phone, in Unix milliseconds, 0 for until an admin unmutes it; null unmutes. */
    fun setMute(untilMS: Long?) {
        call("mute", Wire.obj("until_ms" to (untilMS?.let { JsonPrimitive(it) } ?: JsonNull)))
    }

    // What the app shows.

    /** The members connected now, those whose connection carries records only too when all. */
    fun peers(all: Boolean = false): List<Peer> =
        call("peers", Wire.obj("all" to JsonPrimitive(all))).optArray("peers").orEmpty().mapNotNull { (it as? JsonObject)?.let(Peer::fromJson) }

    /** The group's records the node keeps. */
    fun records(): List<Member.Record> =
        call("records").optArray("records").orEmpty().mapNotNull { e -> (e as? JsonObject)?.let { runCatching { Member.Record.fromJson(it) }.getOrNull() } }

    // What an admin's app signed.

    /** Takes records the app's root or admin key signed, keeps them and sends them to every peer. */
    fun addRecords(rs: List<Member.Record>) {
        if (rs.isEmpty()) return
        call("add_records", Wire.obj("records" to JsonArray(rs.map { it.toJson() })))
    }

    /** Sends a command an admin key signed, straight to its receiver or through the group's hubs, and waits for its result. Blocks. */
    fun command(c: Member.Record, timeoutMS: Long = 10_000): Member.CommandResult {
        val r = call("command", Wire.obj("command" to c.toJson(), "timeout_ms" to Wire.num(timeoutMS))).optObject("result")
            ?: throw Core.Mismatch("command answered no result")
        return Member.CommandResult.fromJson(r)
    }

    /** Sends a renewed member certificate to the member to. */
    fun sendCert(to: String, cert: ByteArray, issuer: ByteArray?): Boolean =
        call("send_cert", Wire.obj("to" to Wire.str(to), "cert" to Wire.bytes(cert), "issuer" to Wire.bytes(issuer))).optBool("sent") ?: false

    /** Sends a full member the admin CA for the admin key its hello offered. */
    fun sendAdminCA(to: String, ca: ByteArray): Boolean =
        call("send_admin_ca", Wire.obj("to" to Wire.str(to), "ca" to Wire.bytes(ca))).optBool("sent") ?: false

    /** Sends the member to this hub's offer for its tunnel key. */
    fun sendTunnel(to: String, offer: Member.TunnelOffer): Boolean =
        call("send_tunnel", Wire.obj("to" to Wire.str(to), "offer" to offer.toJson())).optBool("sent") ?: false

    /** Sends what this hub shares to the group's other hubs connected, or to the member [to] only; those it went to. */
    fun sendHubs(share: Member.HubShare, to: String? = null): List<String> =
        call("send_hubs", Wire.obj("share" to share.toJson(), "to" to (to?.let { Wire.str(it) } ?: JsonNull))).strings("to")

    /**
     * Sends the group's server credentials to the member [to] only (a peer that just connected), or to every member but [except]
     * (the one that sent them); those they went to.
     */
    fun sendCredentials(list: List<ServerCredentials.Credential>, to: String? = null, except: String? = null): List<String> =
        call(
            "send_credentials",
            Wire.obj(
                "credentials" to JsonArray(list.map { it.toJson() }),
                "to" to (to?.let { Wire.str(it) } ?: JsonNull),
                "except" to (except?.let { Wire.str(it) } ?: JsonNull),
            ),
        ).strings("to")

    // The phone's own part.

    /** Answers a [Event.Command] with the result its sender gets. */
    fun answer(token: Long, result: Member.CommandResult) {
        call("answer", Wire.obj("token" to JsonPrimitive(token), "status" to Wire.str(result.status), "reason" to Wire.str(result.reason ?: "")))
    }

    /** Sets the tunnel key and preshared key the hellos offer the group's hubs, or none; the phone connects to the full members again. */
    fun setTunnelKey(keys: Pair<ByteArray, ByteArray>?) {
        call("tunnel_key", Wire.obj("key" to Wire.bytes(keys?.first), "psk" to Wire.bytes(keys?.second)))
    }

    /** Sets the attestations of the phone's keys, which every peer gets after its hello. */
    fun setEvidence(list: List<Member.Evidence>) {
        call("evidence", Wire.obj("evidence" to JsonArray(list.map { it.toJson() })))
    }

    /** Ends the connection to device with a goodbye; it is dialed again later. */
    fun disconnect(device: String) {
        call("disconnect", Wire.obj("device" to Wire.str(device)))
    }

    /** Stops the member and closes its connections; calls after it fail. */
    override fun close() {
        if (closed.getAndSet(true)) return
        lib.cbb_member_stop(handle)
    }

    /** Asks the node op with args and returns the answer's ok as an object. */
    private fun call(op: String, args: JsonObject? = null): JsonObject {
        if (closed.get()) throw IllegalStateException("the member is stopped")
        val request = Wire.encode(Wire.obj("op" to Wire.str(op), "args" to args))
        val count = Memory(Native.SIZE_T_SIZE.toLong()).apply { clear() }
        val answer = lib.cbb_member_call(handle, request, Core.SizeT(request.size.toLong()), count) ?: throw Core.Mismatch("the member gave no answer to $op")
        return okOf(op, take(answer, count))
    }

    /** The callbacks the node calls, kept as long as the process runs: a call may still come in a moment after close. */
    private class Callbacks(val sign: SignFn, val event: EventFn)

    @Suppress("FunctionName")
    private interface Lib : Library {
        fun cbb_member_start(request: ByteArray, len: Core.SizeT, sign: SignFn, event: EventFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_member_call(m: Pointer, request: ByteArray, len: Core.SizeT, answerLen: Pointer): Pointer?

        fun cbb_member_stop(m: Pointer)

        fun cbb_free(answer: Pointer?, len: Core.SizeT)
    }

    /** cbb_sign_fn: signs the 32-byte digest, writing the DER signature and its length. */
    fun interface SignFn : Callback {
        fun invoke(ctx: Pointer?, digest: Pointer, sig: Pointer, sigLen: Pointer): Int
    }

    /** cbb_event_fn: an event as JSON bytes. */
    fun interface EventFn : Callback {
        fun invoke(ctx: Pointer?, event: Pointer, len: Core.SizeT)
    }

    companion object {
        /** The longest DER signature of P-256, the room the node gives. */
        internal const val MAX_SIG = 72

        private val lib: Lib by lazy { Native.load("cbb_ffi", Lib::class.java) }

        /** Every member's callbacks, so that the garbage collector never takes one the node may still call. */
        private val kept = mutableListOf<Callbacks>()

        /**
         * Starts the member. sign signs a SHA-256 digest with the member key
         * (ECDSA P-256, DER); events gets each event, run by post on the
         * app's thread of choice (the main thread in the app), in order.
         */
        fun start(start: Start, sign: (ByteArray) -> ByteArray, post: (Runnable) -> Unit = { it.run() }, events: (Event) -> Unit): CoreMember {
            val signFn = signFn(sign)
            val eventFn = EventFn { _, event, len ->
                val e = runCatching { decode(event.getByteArray(0, len.toInt())) }.getOrNull()
                if (e != null) post { events(e) }
            }
            val cbs = Callbacks(signFn, eventFn)
            synchronized(kept) { kept += cbs }
            val request = Wire.encode(start.toJson())
            val answer = PointerByReference()
            val count = Memory(Native.SIZE_T_SIZE.toLong()).apply { clear() }
            val m = lib.cbb_member_start(request, Core.SizeT(request.size.toLong()), signFn, eventFn, null, answer, count)
            val got = answer.value?.let { take(it, count) } ?: throw Core.Mismatch("the member gave no answer to start")
            okOf("start", got)
            return CoreMember(m ?: throw Core.Mismatch("the member did not start"), cbs)
        }

        /** A cbb_sign_fn over sign, which signs a SHA-256 digest (ECDSA P-256, DER); a failure answers 1. */
        internal fun signFn(sign: (ByteArray) -> ByteArray): SignFn = SignFn { _, digest, sig, sigLen ->
            try {
                val s = sign(digest.getByteArray(0, 32))
                if (s.isEmpty() || s.size > MAX_SIG) return@SignFn 1
                sig.write(0, s, 0, s.size)
                if (Native.SIZE_T_SIZE == 8) sigLen.setLong(0, s.size.toLong()) else sigLen.setInt(0, s.size)
                0
            } catch (e: Exception) {
                1
            }
        }

        /** The uncompressed point of a P-256 public key given as a SubjectPublicKeyInfo or as the point itself. */
        internal fun point(key: ByteArray): ByteArray =
            if (key.size == 65 && key[0] == 4.toByte()) key else key.copyOfRange(maxOf(0, key.size - 65), key.size)

        internal fun take(answer: Pointer, count: Memory): ByteArray {
            val n = if (Native.SIZE_T_SIZE == 8) count.getLong(0) else count.getInt(0).toLong() and 0xffffffffL
            try {
                if (n > Int.MAX_VALUE) throw Core.Mismatch("the member's answer is $n bytes long")
                return answer.getByteArray(0, n.toInt())
            } finally {
                lib.cbb_free(answer, Core.SizeT(n))
            }
        }

        internal fun okOf(op: String, bytes: ByteArray): JsonObject {
            val a = runCatching { Json.parseToJsonElement(bytes.decodeToString()) as JsonObject }.getOrNull()
                ?: throw Core.Mismatch("the member's answer to $op does not read")
            (a["error"] as? JsonObject)?.let { e ->
                throw Core.Refusal(
                    (e["code"] as? JsonPrimitive)?.let { runCatching { it.int }.getOrNull() } ?: 0,
                    e.optString("name") ?: "",
                    e.optString("message") ?: "the member refused $op",
                    e.optString("details"),
                )
            }
            return when (val ok = a["ok"]) {
                is JsonObject -> ok
                null, JsonNull -> throw Core.Mismatch("the member's answer to $op has neither ok nor error")
                else -> JsonObject(mapOf("value" to ok))
            }
        }

        /** An event of the node, or null for one this kit does not know. */
        internal fun decode(bytes: ByteArray): Event? {
            val o = Json.parseToJsonElement(bytes.decodeToString()) as? JsonObject ?: return null
            return when (o.optString("type")) {
                "write" -> Event.Write(o.optString("text") ?: "", Member.Kind.of(o.optString("kind") ?: "") ?: Member.Kind.TEXT, o.optLong("ttl_ms"))
                "log" -> Event.Log(o.optString("line") ?: "")
                "copy" -> o.optObject("copy")?.let { Event.CopyChanged(Copy.fromJson(it)) }
                "message" -> o.optObject("message")?.let { m ->
                    val msg = runCatching { Member.decode(Wire.encode(m)) }.getOrNull() ?: return null
                    Event.Message(o.optString("from") ?: "", msg)
                }
                "identity" -> Event.Identity(o.optBytes("cert") ?: return null, o.optBytes("issuer"), o.optBytesList("roots") ?: emptyList())
                "peer" -> o.optObject("peer")?.let { Event.PeerConnected(Peer.fromJson(it)) }
                "tunnel" -> o.optObject("offer")?.let { Event.Tunnel(o.optString("from") ?: "", Member.TunnelOffer.fromJson(it)) }
                "command" -> {
                    val c = o.optObject("command") ?: return null
                    Event.Command(o.optLong("token") ?: return null, o.optString("from") ?: "", Member.Record.fromJson(c))
                }
                "mute" -> Event.Mute(o.optBool("muted") ?: return null, o.optLong("for_ms") ?: 0, o.optString("by") ?: "")
                "caller" -> Event.Caller(o.optLong("token") ?: return null, o.optLong("port")?.toInt() ?: return null, o.optString("device") ?: "")
                else -> null
            }
        }

        private fun JsonObject.strings(key: String): List<String> =
            (get(key) as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()
    }
}
