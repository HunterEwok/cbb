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
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.Closeable
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The phone's member in the Rust core (docs/core-api.md, "The member"): the
 * Rust member's node on threads of its own inside the app, through the C
 * functions cbb_member_start, cbb_member_call and cbb_member_stop of
 * ffi/, loaded by JNA from libcbb_ffi as [Core] loads it. It dials the
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
    /**
     * What the member starts from: the app's folder, where the member keeps
     * the group's set (a group made before 0.6 is refused, D-126), and what
     * the phone says of itself.
     */
    class Start(
        /** The member's own files: the group's set, the entry points, the cached copies. */
        val dir: File,
        val name: String,
        val os: String,
        val osVersion: String = "",
        val version: String = "",
        /** The device ID the app keeps, which the member key must make. */
        val device: String,
        /** The member key's public key: a SubjectPublicKeyInfo or an uncompressed point. */
        val publicKey: ByteArray,
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
            "device" to Wire.str(device),
            "public" to Wire.bytes(point(publicKey)),
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
        /** The devices the copy is sealed to. */
        val readers: List<String> = emptyList(),
        /** How long the copy lives from when it came, in milliseconds, as its sender stamped it (D-129); null when unknown. */
        val ttlMS: Long? = null,
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
                o.optArray("readers").orEmpty().mapNotNull { (it as? JsonPrimitive)?.content },
                o.optLong("ttl_ms"),
            )
        }
    }

    /** A connected member as the records and its hello name it, with the members it says it reaches. */
    data class Peer(
        val device: String,
        val name: String,
        val role: String,
        val os: String,
        val keyStore: String,
        val mode: String,
        val muted: Boolean,
        val reach: List<String>,
    ) {
        companion object {
            internal fun fromJson(o: JsonObject): Peer = Peer(
                o.optString("device") ?: "",
                o.optString("name") ?: "",
                o.optString("role") ?: "",
                o.optString("os") ?: "",
                o.optString("key_store") ?: "",
                o.optString("mode") ?: "",
                o.optBool("muted") ?: false,
                o.strings("reach"),
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

        /** An admin muted this phone for [forMS] milliseconds (0: until an admin lifts it), or ended its mute; the node carried it out and keeps it. */
        class Mute(val muted: Boolean, val forMS: Long, val by: String) : Event()

        /** An admin turned this phone's sync off ([off]) or on again; the member of 0.6 carried it out and keeps it. */
        class Sync(val off: Boolean, val by: String) : Event()

        /** The group's state changed (a record came, a device joined or left). */
        class State(val state: GroupState) : Event()

        /** A new notice about the group. */
        class NoticeAdded(val notice: Notice) : Event()

        /**
         * The group's root changed by its recovery key: every device shows it and cannot turn it off,
         * with "This wasn't me". from and to are the old and new root's devices, seq the change's step.
         */
        class RootChanged(val from: String, val to: String, val seq: Long) : Event()

        /** The member no longer needs the key public: the app may delete it. */
        class KeyDone(val public: ByteArray) : Event()

        /**
         * Something in the member broke (docs/core-api.md, "Panics"): details say what and
         * where. The app logs it, shows it and starts the member again.
         */
        class Panic(val details: String) : Event()
    }

    /** What a member port is for. */
    enum class Listen(val wire: String) {
        /** The home network, while the phone is the hub: every address; the app publishes it with r=phone. */
        HOME("home"),
    }

    private val closed = AtomicBoolean(false)

    // The clipboard and the button (docs/design.md, "The one button").

    /** Sends a text; board says it came from the phone's clipboard, which the button then compares with it. */
    fun copy(text: String, secret: Boolean = false, board: Boolean = true) {
        call("copy", Wire.obj("text" to Wire.str(text), "kind" to Wire.str(if (secret) "secret" else "text"), "board" to JsonPrimitive(board)))
    }

    /** Sends images or files with their plain-text alternative; board says they came from the phone's clipboard. */
    fun copyMedia(text: String, parts: List<Part>, board: Boolean = false): Copy {
        val ok = call("copy_media", Wire.obj("text" to Wire.str(text), "parts" to JsonArray(parts.map { it.toJson() }), "board" to JsonPrimitive(board)))
        return (ok.optObject("copy") ?: throw Core.Mismatch("copy_media answered no copy")).let(Copy::fromJson)
    }

    /** The group's current copy, or null. */
    fun current(): Copy? = call("current").optObject("copy")?.let(Copy::fromJson)

    /**
     * What a gesture or the app's opening does (D-128): whether the
     * clipboard goes out (sends), and the group's copy that comes into it,
     * or null.
     */
    class Swap(val sends: Boolean, val copy: Copy?)

    /** The gesture swaps: board is the clipboard's key (Copy.key's shape), empty for an empty clipboard. */
    fun swap(board: String): Swap = call("swap", Wire.obj("board" to Wire.str(board))).let(::swapOf)

    /** The app opened: a clipboard that changed since the app last saw it goes out, otherwise the group's copy comes in. */
    fun opened(board: String, changed: Boolean): Swap =
        call("opened", Wire.obj("board" to Wire.str(board), "changed" to JsonPrimitive(changed))).let(::swapOf)

    private fun swapOf(o: JsonObject) = Swap(o.optBool("sends") ?: false, o.optObject("copy")?.let(Copy::fromJson))

    /** The app took the copy id into the clipboard, or saved its files: its own write, never a copy of the phone's. */
    fun took(id: String) {
        call("took", Wire.obj("id" to Wire.str(id)))
    }

    /** Fetches the images or files of the group's copy id, unless its sealed blob is larger than max bytes, and opens them into the new folder out. Blocks. */
    fun fetch(id: String, max: Long, out: File): List<Fetched> =
        call("fetch", Wire.obj("id" to Wire.str(id), "max" to Wire.num(max), "out" to Wire.str(out.path))).optArray("parts").orEmpty().map {
            val o = it as? JsonObject ?: throw Core.Mismatch("fetch answered a part that is not an object")
            Fetched(o.optString("type"), o.optString("path"), o.optBool("dir") ?: false, o.optLong("size") ?: 0, File(o.optString("file") ?: ""))
        }

    // Finding the members, listening, the app's life.

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

    /** A hub's registration with its forwarder, as the member's sync away from home shows it. */
    data class ForwarderState(val endpoint: String, val registered: Boolean, val seen: String, val entriesStale: Boolean, val error: String, val detail: String)

    /** This phone's link to the group's blind relay. */
    data class RelayState(val endpoint: String, val connected: Boolean, val online: List<String>, val error: String, val detail: String)

    /**
     * Sync away from home on a group of 0.6, as the member runs it (`away_status`, docs/core-api.md): a hub (standing
     * by while a hub above it serves) with its port, clients, endpoints and forwarder; else the hub it reaches and
     * whether through the tunnel now; the relay link; the last error with its detail.
     */
    data class AwayState(
        val hub: Boolean,
        val standby: Boolean,
        val port: Int,
        val clients: Int,
        val obfuscated: Boolean,
        val vless: Boolean,
        val endpoints: List<String>,
        val hubDevice: String,
        val through: Boolean,
        val keysInFile: Boolean,
        val forwarder: ForwarderState?,
        val relay: RelayState?,
        val error: String,
        val detail: String,
    ) {
        companion object {
            private fun strings(o: JsonObject, key: String): List<String> = o.optArray(key)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } ?: emptyList()

            /** The answer's `away`, null while sync away from home is off and nothing failed. */
            fun of(answer: JsonObject): AwayState? = answer.optObject("away")?.let { a ->
                AwayState(
                    a.optBool("hub") ?: false, a.optBool("standby") ?: false, (a.optLong("port") ?: 0).toInt(), (a.optLong("clients") ?: 0).toInt(),
                    a.optBool("obfuscated") ?: false, a.optBool("vless") ?: false, strings(a, "endpoints"), a.optString("hub_device") ?: "",
                    a.optBool("through") ?: false, a.optBool("keys_in_file") ?: false,
                    a.optObject("forwarder")?.let { f ->
                        ForwarderState(f.optString("endpoint") ?: "", f.optBool("registered") ?: false, f.optString("seen") ?: "",
                            f.optBool("entries_stale") ?: false, f.optString("error") ?: "", f.optString("detail") ?: "")
                    },
                    a.optObject("relay")?.let { r ->
                        RelayState(r.optString("endpoint") ?: "", r.optBool("connected") ?: false, strings(r, "online"),
                            r.optString("error") ?: "", r.optString("detail") ?: "")
                    },
                    a.optString("error") ?: "", a.optString("detail") ?: "",
                )
            }
        }

        /** Sync away from home is on: the member keeps its tunnel keys; a failure while it is off shows only error. */
        val isOn: Boolean get() = keysInFile
    }

    /** On a group of 0.6: sync away from home as the member runs it, null while it is off. */
    fun awayStatus(): AwayState? = AwayState.of(call("away_status"))

    /** The forwarder the group's root set for this phone as a hub: its address and its key's pin. */
    data class RootForwarder(val endpoint: String, val key: String)

    /** On a group of 0.6: the forwarder the group's root set for this phone as a hub, which it serves through; null while the root set none. */
    fun rootForwarder(): RootForwarder? = call("away_status").optObject("root_forwarder")?.let { f ->
        RootForwarder(f.optString("endpoint") ?: "", f.optString("key") ?: "")
    }

    /**
     * On the root phone of a group of 0.6: whether the group's server credentials need its root key ([renewPeriod]) and
     * whether they expired already, so that the group's relay and its hubs' forwarders take nobody; both false elsewhere.
     */
    fun periods(): Pair<Boolean, Boolean> = call("away_status").let { (it.optBool("period_due") ?: false) to (it.optBool("period_overdue") ?: false) }

    /**
     * On a group of 0.6: the group's face toward the push service that the newest keys.json the member
     * holds names (16 bytes), which every registration names; null until one does.
     */
    fun pushFace(): ByteArray? = call("push_face").optBytes("face")?.takeIf { it.size == 16 }

    /**
     * On a group of 0.6: this phone's registration for push, message `push` as [Push] made it, which the
     * member sends to every member connected now and to each one that connects later; null stops it.
     */
    fun setPush(frame: ByteArray?) {
        call("push", Wire.obj("frame" to Wire.bytes(frame)))
    }

    /** On a group of 0.6: the `push-renew` messages members sent since the last call, as slot and ahead, one per slot. */
    fun pushRenewals(): List<Pair<ByteArray, Boolean>> =
        call("push_renewals").optArray("renewals")?.mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            o.optBytes("slot")?.let { it to (o.optBool("ahead") ?: false) }
        } ?: emptyList()

    /** On the root phone of a group of 0.6: renews the group's server credentials with the root key; the periods after. */
    fun renewPeriod(public: ByteArray, sign: (ByteArray) -> ByteArray): Pair<Boolean, Boolean> =
        act(Wire.obj("action" to Wire.str("period")), public, sign).let { (it.optBool("period_due") ?: false) to (it.optBool("period_overdue") ?: false) }

    /** On a group of 0.6: turns sync away from home on, with new tunnel keys, or off. */
    fun setAway(on: Boolean): AwayState? = AwayState.of(call("away", Wire.obj("on" to JsonPrimitive(on))))

    /**
     * On a group of 0.6, serves as a hub of the group (the records must make this phone one: an admin key), with the
     * computers' hub: reached away from home through the forwarder at forwarder (`host:port`, its key's pin key or
     * `default` for the project's; none given: the one the root set, [rootForwarder]), or at addrs ("ip:port") on the
     * UDP port (0: any free one), hidden as obfuscateOff and vlessOff say. Its clients and the guests of invitations come in through its tunnel.
     */
    fun serveAsHub(
        port: Int = 0,
        addrs: List<String> = emptyList(),
        forwarder: String = "",
        key: String = "",
        obfuscateOff: Boolean = false,
        vlessOff: Boolean = false,
    ): AwayState? = AwayState.of(
        call(
            "hub",
            Wire.obj(
                "port" to Wire.num(port.toLong()), "addrs" to JsonArray(addrs.map { JsonPrimitive(it) }),
                "forwarder" to Wire.str(forwarder), "key" to Wire.str(key),
                "obfuscate_off" to JsonPrimitive(obfuscateOff), "vless_off" to JsonPrimitive(vlessOff),
            ),
        ),
    )

    /** On a group of 0.6: stops serving as a hub; its clients go to the next hub in the group's order. */
    fun stopHub(): AwayState? = AwayState.of(call("hub_off"))

    /** On the root of a group of 0.6: the group's relays, each "address pin", or "default" alone; none meets at no relay. */
    fun setRelays(relays: List<String>, public: ByteArray, sign: (ByteArray) -> ByteArray): List<String> =
        act(Wire.obj("action" to Wire.str("relay"), "relays" to JsonArray(relays.map { JsonPrimitive(it) })), public, sign)
            .optArray("relays")?.map { (it as JsonPrimitive).content } ?: emptyList()

    /**
     * On the root of a group of 0.6: names the forwarder of device, an admin phone or a computer that may be a hub, at
     * forwarder (`host:port`, or `default` for the project's) with its key's pin key, which the device takes as its
     * forwarder setting and serves through once its hub is on. The device's answer: done, refused or failed, and why.
     */
    fun nameForwarder(device: String, forwarder: String, key: String, public: ByteArray, sign: (ByteArray) -> ByteArray): Pair<String, String> =
        act(Wire.obj("action" to Wire.str("forwarder"), "device" to Wire.str(device), "forwarder" to Wire.str(forwarder), "key" to Wire.str(key)), public, sign)
            .let { (it.optString("status") ?: "") to (it.optString("reason") ?: "") }

    /** Closes the port [listen] opened for [what], or every one with null. */
    fun unlisten(what: Listen? = null) {
        call("unlisten", Wire.obj("kind" to (what?.let { Wire.str(it.wire) } ?: JsonNull)))
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

    /**
     * Turns the phone's sync on, or off for forMS milliseconds, 0 for until
     * it is turned on (design.md, "Sync on and off"); the members see it at
     * the next connection, which comes at once. A time with sync on is
     * refused.
     */
    fun setSync(on: Boolean, forMS: Long = 0) {
        call("sync", Wire.obj("on" to JsonPrimitive(on), "for_ms" to Wire.num(forMS)))
    }

    /** Sets until when an admin muted this phone, in Unix milliseconds, 0 for until an admin unmutes it; null unmutes. */
    fun setMute(untilMS: Long?) {
        call("set_mute", Wire.obj("until_ms" to (untilMS?.let { JsonPrimitive(it) } ?: JsonNull)))
    }

    // What the app shows.

    /**
     * The device tiles in the user's order, with the user's change op applied
     * and kept first (docs/apps.md, "What the member shows"); a change that
     * does not fit throws and changes nothing.
     */
    fun view(op: Arrangement.Op? = null, away: WhyAway? = null): Arrangement.View {
        val a = away?.toJson() ?: JsonNull
        val answer = if (op == null) call("view", Wire.obj("away" to a)) else call("arrange", Wire.obj("arrange" to Arrangement.json(op), "away" to a))
        return Arrangement.view(answer.getValue("view").jsonObject)
    }

    /** The members connected now, the offline ones too when all. */
    fun peers(all: Boolean = false): List<Peer> =
        call("peers", Wire.obj("all" to JsonPrimitive(all))).optArray("peers").orEmpty().mapNotNull { (it as? JsonObject)?.let(Peer::fromJson) }

    /**
     * Why the phone does not sync, the reason that stops the most first
     * (docs/apps.md, "Why it does not sync"); empty when everything syncs.
     * away is where the app's own tunnel stands, null while it is off.
     */
    fun why(away: WhyAway? = null): List<WhyReason> =
        call("why", Wire.obj("away" to (away?.toJson() ?: JsonNull))).optArray("why").orEmpty().mapNotNull { (it as? JsonObject)?.let(WhyReason::fromJson) }

    /** Sets the attestations of the phone's keys, which every peer gets after its hello. */
    fun setEvidence(list: List<Member.Evidence>) {
        call("evidence", Wire.obj("evidence" to JsonArray(list.map { it.toJson() })))
    }

    // The group in 0.6 (docs/core-api.md, "The member"): the member keeps and evaluates the
    // records; the app reads what it shows and asks for what the person decides.

    /** The group as the member sees it now. */
    fun group(): GroupState = GroupState.fromJson(call("group"))

    /** The member's notices about the group, newest first. */
    fun notices(): List<Notice> = call("notices").objects("notices").map(Notice::fromJson)

    /** Hides the notice id until something about it changes. */
    fun dismiss(id: String) {
        call("dismiss", Wire.obj("id" to Wire.str(id)))
    }

    /** The person saw the change of root [Event.RootChanged] told of: the member no longer tells of it, not even when it starts again. */
    fun rootChangeSeen() {
        call("root_change_seen")
    }

    /**
     * Who stays after a change of root with the recovery key, before anything is signed: the
     * core writes the list; leaveOut are the devices the person unticked. The recovery keys
     * are derived inside the call and dropped at its end.
     */
    fun changePreview(recovery: RecoveryInput, leaveOut: List<String> = emptyList()): ChangePreview = ChangePreview.fromJson(
        manage(
            Wire.obj(
                "action" to Wire.str("change_preview"),
                "recovery" to recovery.toJson(),
                "leave_out" to JsonArray(leaveOut.map { JsonPrimitive(it) }),
            ),
        ) { throw IllegalStateException("a preview signs nothing") },
    )

    /**
     * Changes the group's root to this phone's new root key rootPublic, which sign signs with
     * (Face ID before each use): the recovery key signs the change, the new root its first
     * records, and leaveOut are removed in the same act. overWaiting writes over a change
     * whose records never came; offer it only after a sync failed.
     */
    fun changeRoot(
        recovery: RecoveryInput,
        leaveOut: List<String>,
        rootPublic: ByteArray,
        sign: (ByteArray) -> ByteArray,
        dropHubs: Boolean = false,
        overWaiting: Boolean = false,
    ): Long = manage(
        Wire.obj(
            "action" to Wire.str("change_root"),
            "recovery" to recovery.toJson(),
            "leave_out" to JsonArray(leaveOut.map { JsonPrimitive(it) }),
            "drop_hubs" to JsonPrimitive(dropHubs),
            "over_waiting" to JsonPrimitive(overWaiting),
            "public" to Wire.bytes(point(rootPublic)),
        ),
        sign,
    ).optLong("seq") ?: 0

    /** The callbacks of the manage calls under way. */
    private val signing = mutableListOf<SignFn>()

    // The root's own records (cbb_core::root, docs/protocol.md, section 10,
    // "Handing the group over" and "The recovery key"): the core builds and
    // checks them, signs them with the root key public through sign, adds
    // them and sends them to every member.

    /**
     * Sets the group's key level (proven, hardware or files), keeping the
     * takeover delay; never a level this phone's own keys do not pass. It
     * returns the admins and hubs whose keys the level would not let in, by
     * device ID: they stay until the user removes them.
     */
    fun setKeyLevel(level: String, public: ByteArray, sign: (ByteArray) -> ByteArray): List<String> =
        act(Wire.obj("action" to Wire.str("key_level"), "level" to Wire.str(level)), public, sign)
            .optArray("below")?.map { it.jsonPrimitive.content }.orEmpty()

    /** Sets how long a copy and a secret live, in milliseconds, either left out to keep it: a copies record, which any admin signs (D-129). */
    fun setTtl(ttlMS: Long?, secretTtlMS: Long?, public: ByteArray, sign: (ByteArray) -> ByteArray) {
        act(Wire.obj("action" to Wire.str("ttl"), "ttl_ms" to Wire.num(ttlMS), "secret_ttl_ms" to Wire.num(secretTtlMS)), public, sign)
    }

    /**
     * The action of an admin or the root (cbb_member_manage): request with
     * the point of the key public, the phone's admin key or the root's,
     * signed through sign; the records judge whether the key may.
     */
    fun act(request: JsonObject, public: ByteArray, sign: (ByteArray) -> ByteArray): JsonObject =
        manage(JsonObject(request + ("public" to Wire.bytes(point(public))!!)), sign)

    /** Asks the member for an admin's change or a step of a takeover (cbb_member_manage), signed through sign during this call. */
    fun manage(request: JsonObject, sign: (ByteArray) -> ByteArray): JsonObject {
        if (closed.get()) throw IllegalStateException("the member is stopped")
        val bytes = Wire.encode(request)
        val signFn = signFn(sign)
        val count = Memory(Native.SIZE_T_SIZE.toLong()).apply { clear() }
        // Held where the garbage collector sees it until the call is over: the core calls it during the call.
        synchronized(signing) { signing += signFn }
        try {
            val answer = lib.cbb_member_manage(handle, bytes, Core.SizeT(bytes.size.toLong()), signFn, null, count)
                ?: throw Core.Mismatch("the member gave no answer to manage")
            return okOf("manage", take(answer, count))
        } finally {
            synchronized(signing) { signing -= signFn }
        }
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

        fun cbb_member_manage(m: Pointer, request: ByteArray, len: Core.SizeT, sign: SignFn, ctx: Pointer?, answerLen: Pointer): Pointer?

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
                "mute" -> Event.Mute(o.optBool("muted") ?: return null, o.optLong("for_ms") ?: 0, o.optString("by") ?: "")
                "sync" -> Event.Sync(o.optBool("off") ?: return null, o.optString("by") ?: "")
                "state" -> o.optObject("state")?.let { Event.State(GroupState.fromJson(it)) }
                "notice" -> o.optObject("notice")?.let { Event.NoticeAdded(Notice.fromJson(it)) }
                "root_changed" -> Event.RootChanged(o.optString("from") ?: "", o.optString("to") ?: "", o.optLong("seq") ?: 0)
                "key_done" -> Event.KeyDone(o.optBytes("public") ?: return null)
                "panic" -> Event.Panic(o.optString("details") ?: "")
                else -> null
            }
        }

        private fun JsonObject.strings(key: String): List<String> =
            (get(key) as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()
    }
}
