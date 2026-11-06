// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.SecureRandom
import java.time.Instant

/**
 * Commands (docs/protocol.md, section 15): an admin's order for one member,
 * signed like a record and never stored, as internal/group/command.go makes
 * them: one sets the receiver's sync mode, another makes the receiver, an
 * admin computer, the group's hub in place of this phone; a paste command
 * puts a text where the receiver's focus is, and paste-off turns remote
 * paste off on the receiver (design.md, "Remote paste"); an action command
 * runs one of the receiver's quick actions by its name, and actions-off
 * turns them all off there (design.md, "Quick actions"); away-off turns
 * sync away from home off on the receiver. A watch signs only those that
 * turn things off and action ([WATCH_TYPES]).
 */
object Commands {
    /** The version of command bodies. */
    const val VERSION = 1

    /** How long after signing a command expires; the receivers take at most 30 s. */
    const val LIFETIME_MS = 30_000L

    /** A new command ID: 128 random bits in hex. */
    fun newID(): String = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

    /**
     * A mode command for the device to, signed with the root key (adminCA
     * null) or with an admin CA key, adminCA being that CA's certificate.
     */
    fun mode(
        to: String,
        mode: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record {
        require(mode in Member.MODES) { "unknown sync mode $mode" }
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(VERSION.toLong()),
                "type" to Wire.str("mode"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                "mode" to Wire.str(mode),
            ),
        )
        return finish(body, signer, adminCA, seal)
    }

    /**
     * A hub command for the admin computer to (section 11, "Moving the
     * hub"): it becomes the group's hub, reached through the forwarder
     * (endpoint "ip:port" and the pin of its key) and at endpoints, and
     * takes clients, the old hub's, with the keys they have. Signed as mode.
     */
    fun hub(
        to: String,
        forwarder: Pair<String, String>?,
        endpoints: List<String>,
        clients: List<PhoneHub.Client>,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record {
        require(forwarder != null || endpoints.isNotEmpty()) { "the new hub needs a forwarder or an address" }
        require(endpoints.size <= 8 && clients.size <= MAX_HUB_CLIENTS) { "too many addresses or clients" }
        val ms = now.toEpochMilli()
        val order = Wire.obj(
            "forwarder" to forwarder?.let { (ep, pin) -> Wire.obj("endpoint" to Wire.str(ep), "key" to Wire.str(pin)) },
            "endpoints" to endpoints.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { Wire.str(it)!! }) },
            "clients" to clients.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map<PhoneHub.Client, JsonElement> { it.toJson() }) },
        )
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(VERSION.toLong()),
                "type" to Wire.str("hub"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                "hub" to order,
            ),
        )
        return finish(body, signer, adminCA, seal)
    }

    /** The longest text of a paste command, in bytes of UTF-8, and of one typed key by key. */
    const val MAX_PASTE_TEXT = 1 shl 20
    const val MAX_TYPE_TEXT = 4 shl 10

    /**
     * A paste command for the device to: put text where its focus is, by
     * method "paste" (the clipboard and the paste keys) or "type", then
     * press Enter when enter is set; kind is "text" or "secret". Signed as
     * mode.
     */
    fun paste(
        to: String,
        text: String,
        method: String = "paste",
        enter: Boolean = false,
        kind: String = "text",
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record {
        val limit = when (method) {
            "paste" -> MAX_PASTE_TEXT
            "type" -> MAX_TYPE_TEXT
            else -> throw IllegalArgumentException("a paste is paste or type, not $method")
        }
        require(kind == "text" || kind == "secret") { "a paste is text or secret, not $kind" }
        val n = text.toByteArray().size
        require(n in 1..limit) { "the text is empty or longer than $limit bytes" }
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(VERSION.toLong()),
                "type" to Wire.str("paste"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                "mode" to Wire.str(method),
                "enter" to if (enter) JsonPrimitive(true) else null,
                "kind" to Wire.str(kind),
                "text" to Wire.str(text),
            ),
        )
        return finish(body, signer, adminCA, seal)
    }

    /** A paste-off command for the device to: it turns remote paste off there. Signed as mode. */
    fun pasteOff(
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record {
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(VERSION.toLong()),
                "type" to Wire.str("paste-off"),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
            ),
        )
        return finish(body, signer, adminCA, seal)
    }

    /** The longest name of a quick action. */
    const val MAX_ACTION_NAME = 32

    /** The most quick actions a hello lists. */
    const val MAX_HELLO_ACTIONS = 64

    /** The presets every computer knows, in the order the apps show them. */
    val PRESETS = listOf("lock", "sleep", "reboot", "shutdown", "cancel-shutdown", "restart", "keyboard-layout")

    /** Whether name is a quick action's name: 1 to 32 of a-z, 0-9 and -, starting with a letter. */
    fun validActionName(name: String): Boolean =
        name.length in 1..MAX_ACTION_NAME && name[0] in 'a'..'z' && name.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }

    /** An action command for the device to: run its quick action name, which only the receiver defines. Signed as mode. */
    fun action(
        to: String,
        name: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record {
        require(validActionName(name)) { "$name is not an action's name" }
        return signed("action", to, group, by, now, signer, adminCA, id, seal, "action" to Wire.str(name))
    }

    /** An actions-off command for the device to: it turns every quick action off there. Signed as mode. */
    fun actionsOff(
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record = signed("actions-off", to, group, by, now, signer, adminCA, id, seal)

    /** An away-off command for the device to: it turns sync away from home off there, and its tunnel keys go. Signed as mode. */
    fun awayOff(
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray? = null,
        id: String = newID(),
        seal: ByteArray? = null,
    ): Member.Record = signed("away-off", to, group, by, now, signer, adminCA, id, seal)

    /** The commands a watch's admin key may sign (docs/protocol.md, section 10, "Watches"), as Go's WatchCommand. */
    val WATCH_TYPES = setOf("paste-off", "actions-off", "away-off", "action")

    /**
     * Signs body; with seal, the receiver's key for sealed messages from its
     * device record, its orders are sealed to that key first (docs/protocol.md,
     * section 15, "Sealed commands"), in the Rust core.
     */
    private fun finish(body: ByteArray, signer: CertificateSigner, adminCA: ByteArray?, seal: ByteArray?): Member.Record {
        val b = if (seal != null) Core.sealCommand(body, seal) else body
        return Member.Record(b, signer.signature(b), adminCA?.let { listOf(it) })
    }

    private fun signed(
        type: String,
        to: String,
        group: String,
        by: String,
        now: Instant,
        signer: CertificateSigner,
        adminCA: ByteArray?,
        id: String,
        seal: ByteArray?,
        vararg extra: Pair<String, JsonElement?>,
    ): Member.Record {
        val ms = now.toEpochMilli()
        val body = Wire.encode(
            Wire.obj(
                "v" to Wire.num(VERSION.toLong()),
                "type" to Wire.str(type),
                "group" to Wire.str(group),
                "by" to Wire.str(by),
                "to" to Wire.str(to),
                "id" to Wire.str(id),
                "time_ms" to Wire.num(ms),
                "expires_ms" to Wire.num(ms + LIFETIME_MS),
                *extra,
            ),
        )
        return finish(body, signer, adminCA, seal)
    }

    /** The most clients a hub command hands over, as many as a hub keeps. */
    const val MAX_HUB_CLIENTS = 256

    /** How far ahead of the receiver's clock a command's time may be. */
    const val AHEAD_MS = 60_000L

    /** The most bytes of a command's body, as Go takes: a hub command carries up to 256 clients' keys, a paste up to 1 MiB of text. */
    private const val MAX_BODY = 64 shl 10
    private const val MAX_PASTE_BODY = 2 shl 20

    /** What a command orders, as its receiver checked it. mode is set for a mode or paste command, enter, kind and text for a paste. */
    data class Body(
        val type: String,
        val group: String,
        val by: String,
        val to: String,
        val id: String,
        val timeMS: Long,
        val expiresMS: Long,
        val mode: String?,
        val enter: Boolean = false,
        val kind: String? = null,
        val text: String? = null,
        val action: String? = null,
    )

    /** Why a command was refused, in words for the sender. */
    class Refused(message: String) : Exception(message)

    /**
     * Checks command c for the member self at nowMS (docs/protocol.md,
     * section 15) through the Rust core: an admin of the group that may sign
     * its type signed it, its by is the signer's device, it is for self in
     * this group and in its lifetime. A sealed command opens with secret,
     * this member's secret for sealed messages. The caller
     * keeps the replay cache; a mode command's mode is not checked against
     * [Member.MODES] here.
     */
    fun verify(c: Member.Record, records: RecordSet, self: String, nowMS: Long, secret: ByteArray? = null): Body {
        // A sealed command's orders are read once the core opened them.
        val sealed = runCatching { Wire.parse(c.body)?.optLong("v") }.getOrNull() == SEALED_VERSION
        val b = if (sealed) null else parse(c.body)
        val saved = records.nowMS
        records.nowMS = nowMS
        val checked = try {
            records.check(c, self, secret)
        } finally {
            records.nowMS = saved
        }
        if (b != null) return b
        val o = checked.command?.takeIf { checked.opened } ?: throw Refused("the sealed command did not open")
        return bodyOf(o)
    }

    /** The version of a command whose orders are sealed to its receiver. */
    private const val SEALED_VERSION = 2L

    /** Reads a command's body once the Rust core took it (parse_body), in the strict form of signed bodies, as Go's parseCommandBody. */
    internal fun parse(body: ByteArray): Body =
        try {
            parseBody(body)
        } catch (e: WireTypeException) {
            throw Refused("the command is not valid: ${e.message}")
        }

    /** A command's fields, as its body or the core's opened command gives them. */
    private fun bodyOf(o: JsonObject): Body =
        Body(
            type = o.optString("type") ?: "",
            group = o.optString("group") ?: "",
            by = o.optString("by") ?: "",
            to = o.optString("to") ?: "",
            id = o.optString("id") ?: "",
            timeMS = o.optLong("time_ms") ?: 0,
            expiresMS = o.optLong("expires_ms") ?: 0,
            mode = o.optString("mode"),
            enter = o.optBool("enter") ?: false,
            kind = o.optString("kind"),
            text = o.optString("text"),
            action = o.optString("action"),
        )

    private fun parseBody(body: ByteArray): Body {
        // The core decides whether the body is taken; the checks below only read its fields.
        Core.bodyRefusal("command", body)?.let { throw Refused("the command is not valid: $it") }
        if (body.size > MAX_PASTE_BODY) throw Refused("the command is too large")
        try {
            Strict.check(body, "v", "type", "group", "by", "to", "id", "time_ms", "expires_ms")
        } catch (e: Strict.Invalid) {
            throw Refused("the command is not valid: ${e.message}")
        }
        val o = Wire.parse(body) ?: throw Refused("the command is not valid")
        val type = o.optString("type")
        if (type != "paste" && body.size > MAX_BODY) throw Refused("the command is too large")
        val b = bodyOf(o)
        if (o.optLong("v") != VERSION.toLong()) throw Refused("unknown command version")
        if (b.id.length != 32 || b.id.any { it !in "0123456789abcdef" }) throw Refused("the command has no valid ID")
        // As in Go, an empty string is no paste and no action.
        if (type != "paste" && (b.enter || !b.kind.isNullOrEmpty() || !b.text.isNullOrEmpty())) throw Refused("a $type command carries a paste")
        if (type != "action" && !b.action.isNullOrEmpty()) throw Refused("a $type command names an action")
        when (type) {
            "mode" -> if (b.mode.isNullOrEmpty() || o.opt("hub") != null) throw Refused("a mode command names no mode")
            "hub" -> {
                if (o.opt("hub") == null || !b.mode.isNullOrEmpty()) throw Refused("a hub command has no order")
                checkHub(o.optObject("hub")!!)
            }
            "paste-off", "actions-off", "away-off" -> if (o.opt("hub") != null || !b.mode.isNullOrEmpty()) throw Refused("a $type command carries an order")
            "action" -> {
                if (o.opt("hub") != null || !b.mode.isNullOrEmpty()) throw Refused("an action command carries an order")
                if (!validActionName(b.action ?: "")) throw Refused("an action command names no valid action")
            }
            "paste" -> {
                val limit = when (b.mode) {
                    "paste" -> MAX_PASTE_TEXT
                    "type" -> MAX_TYPE_TEXT
                    else -> throw Refused("a paste command's way is not paste or type")
                }
                if (o.opt("hub") != null) throw Refused("a paste command carries a hub order")
                if (b.kind != "text" && b.kind != "secret") throw Refused("a paste command's kind is not text or secret")
                val n = b.text?.toByteArray()?.size ?: 0
                if (n == 0) throw Refused("a paste command has no text")
                if (n > limit) throw Refused("a paste command's text is longer than $limit bytes")
            }
            else -> throw Refused("unknown command type $type")
        }
        if (b.to.length != 32 || b.to.any { it !in "0123456789abcdef" }) throw Refused("the command names no valid device")
        if (b.by.length != 32 || b.by.any { it !in "0123456789abcdef" }) throw Refused("a command's by is not a device ID")
        // A time before 1970 is no signing time; from it the difference cannot overflow.
        if (b.timeMS < 0 || b.expiresMS <= b.timeMS || b.expiresMS - b.timeMS > LIFETIME_MS) throw Refused("the command's lifetime is not valid")
        return b
    }

    /**
     * Checks a hub command's order as Go's HubOrder.check: a forwarder with an address and a key, or an address at
     * least; at most 8 addresses and [MAX_HUB_CLIENTS] clients, each a device ID once with keys of 32 bytes.
     */
    private fun checkHub(h: JsonObject) {
        val forwarder = h.optObject("forwarder")
        val endpoints = h.optArray("endpoints").orEmpty().map {
            (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw WireTypeException("endpoints: not a string")
        }
        val clients = h.optArray("clients").orEmpty().map { it as? JsonObject ?: throw WireTypeException("clients: not an object") }
        // An order to stop being a hub carries nothing else.
        if (h.optBool("stop") == true) {
            if (forwarder != null || endpoints.isNotEmpty() || clients.isNotEmpty()) {
                throw Refused("a hub command that stops a hub carries a forwarder, addresses or clients")
            }
            return
        }
        if (forwarder == null && endpoints.isEmpty()) throw Refused("a hub command gives no forwarder and no address")
        if (endpoints.size > 8) throw Refused("a hub command gives too many addresses")
        if (clients.size > MAX_HUB_CLIENTS) throw Refused("a hub command hands over too many clients")
        if (forwarder != null && (forwarder.optString("endpoint").isNullOrEmpty() || forwarder.optString("key").isNullOrEmpty())) {
            throw Refused("a hub command's forwarder has no address or key")
        }
        val seen = HashSet<String>()
        for (c in clients) {
            val device = c.optString("device") ?: ""
            if (device.length != 32 || device.any { it !in "0123456789abcdef" }) throw Refused("a hub command's client has no valid device ID")
            if (!seen.add(device)) throw Refused("a hub command hands over $device twice")
            if (c.optBytes("key")?.size != 32 || c.optBytes("psk")?.size != 32) throw Refused("a hub command's keys for $device are not 32 bytes")
        }
    }

    /** The ID in a command's body, or null when it has none. */
    fun idOf(c: Member.Record): String? = Wire.parse(c.body)?.optString("id")
}
