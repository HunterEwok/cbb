// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.CredentialStore
import tools.cbb.kit.Member
import tools.cbb.kit.FrameTransport
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64

/**
 * What the phone keeps to meet its group at a blind relay (docs/design.md,
 * "Blind relay", D-68): its WireGuard private key, made on the phone, and
 * the relay, its endpoint and the pin of its key, as `cbb relay` prints
 * them. The user turned it on after reading what a relay learns, so the
 * settings are the consent too: without them the phone meets nobody there.
 */
data class RelaySettings(val key: ByteArray, val relay: HubState.Forwarder) {
    fun encode(): ByteArray = JsonObject(mapOf(
        "key" to JsonPrimitive(Base64.getEncoder().encodeToString(key)),
        "relay" to JsonObject(mapOf("endpoint" to JsonPrimitive(relay.endpoint), "pin" to JsonPrimitive(relay.pin))),
    )).toString().toByteArray()

    override fun equals(other: Any?): Boolean = other is RelaySettings && key.contentEquals(other.key) && relay == other.relay

    override fun hashCode(): Int = key.contentHashCode() * 31 + relay.hashCode()

    companion object {
        /** The settings in b, or null when they are not ones this version wrote. */
        fun decode(b: ByteArray): RelaySettings? = runCatching {
            val o = Json.parseToJsonElement(b.toString(Charsets.UTF_8)) as JsonObject
            val key = Base64.getDecoder().decode(o.string("key") ?: return null)
            val r = o["relay"] as? JsonObject ?: return null
            val relay = HubState.Forwarder(r.string("endpoint") ?: return null, r.string("pin") ?: return null)
            if (key.size != 32 || !HubState.validPin(relay.pin)) return null
            RelaySettings(key, relay)
        }.getOrNull()
    }
}

/** What mobile/cbbtun's relay link asks of the app (cbbtun's RelayEvents). */
interface RelayLinkEvents {
    /** The relay joined a connection to peer: the app dials 127.0.0.1:port, which takes one connection, as the TLS client expecting peer. */
    fun dial(peer: String, port: Int)
    /** peer called: its connection comes to the member listener from 127.0.0.1:localPort. */
    fun calling(peer: String, localPort: Int)
    /** Whether to connect to peer through the relay now. */
    fun wanted(peer: String): Boolean
    /** The link stands as the JSON state says. */
    fun changed(state: String)
}

/** A running link of mobile/cbbtun to a blind relay. */
interface RelayLink {
    fun setRecords(records: String)
    /** cbbtun's Relay.SetCredentials: an empty creds goes back to the member certificate. */
    fun setCredentials(serverKey: ByteArray, sign: (ByteArray) -> ByteArray, creds: String, roots: String, names: String)
    fun close()
}

/** Starts links to relays; the app's come from mobile/cbbtun, the tests' from a fake. */
interface RelayLinks {
    fun newKey(): ByteArray
    fun start(
        private: ByteArray, device: String, endpoint: String, pin: String, chain: String,
        sign: (ByteArray) -> ByteArray, records: String, memberPort: Int, events: RelayLinkEvents,
    ): RelayLink
}

/** The links of mobile/cbbtun to a blind relay. */
object GoRelayLinks : RelayLinks {
    override fun newKey(): ByteArray = cbbtun.Cbbtun.newKey()
    override fun start(
        private: ByteArray, device: String, endpoint: String, pin: String, chain: String,
        sign: (ByteArray) -> ByteArray, records: String, memberPort: Int, events: RelayLinkEvents,
    ): RelayLink {
        val r = cbbtun.Cbbtun.startRelay(private, device, endpoint, pin, chain, cbbtun.Signer { sign(it) }, records, memberPort.toLong(),
            object : cbbtun.RelayEvents {
                override fun dial(peer: String, port: Long) = events.dial(peer, port.toInt())
                override fun calling(peer: String, localPort: Long) = events.calling(peer, localPort.toInt())
                override fun wanted(peer: String): Boolean = events.wanted(peer)
                override fun changed(state: String) = events.changed(state)
            })
        return object : RelayLink {
            override fun setRecords(records: String) = r.setRecords(records)
            override fun setCredentials(serverKey: ByteArray, sign: (ByteArray) -> ByteArray, creds: String, roots: String, names: String) =
                r.setCredentials(serverKey, cbbtun.Signer { sign(it) }, creds, roots, names)
            override fun close() = r.close()
        }
    }
}

/**
 * The phone at a blind relay while it syncs (docs/protocol.md, section 14):
 * it registers by its member key and the group's authority records, or,
 * once the group's server credentials list its server key, with them under
 * a pseudonym (section 18), and the relay joins its member connections to
 * the other devices of the group there, which the relay cannot read:
 * member TLS runs end to end. The
 * device with the lower ID dials, so the phone both dials and answers. An
 * answered call comes to the loopback member listener, which serves it only
 * when the client certificate names the device the relay said calls
 * (caller), so the relay cannot pose as another device of the group.
 */
class RelayOnPhone(
    private val device: String,
    private val links: RelayLinks,
    load: () -> RelaySettings?,
    private val save: (RelaySettings?) -> Unit,
    /** Reaches peer's member TLS through the port of a dialed connection, checking that the peer is peer. */
    private val dialPeer: (port: Int, peer: String) -> FrameTransport,
    /** Runs a connection until it ends. */
    private val serve: (FrameTransport, peer: String) -> Unit,
    /** Whether the phone reaches a device another way now, as on the home network. */
    private val elsewhere: (String) -> Boolean,
    private val log: (String, Throwable?) -> Unit = { _, _ -> },
) : RelayLinkEvents {
    /** What the screens show. */
    enum class Status { OFF, PAUSED, CONNECTING, CONNECTED, FAILED }

    /** What the phone registers with in place of its member certificate: its server key for the period, SubjectPublicKeyInfo DER, how it signs a SHA-256 digest with it, and the registration the credentials give. */
    class Credentials(val serverKey: ByteArray, val sign: (ByteArray) -> ByteArray, val registration: CredentialStore.Registration) {
        val creds: String get() = JsonArray(registration.credentials.map { it.toJson() }).toString()
        val roots: String get() = JsonArray(registration.roots.map { bytes(it) }).toString()
        val names: String get() = JsonObject(registration.names.mapValues { JsonPrimitive(it.value) }).toString()

        /** What the relay sees of it, to tell whether it changed. */
        val shown: String get() = listOf(Base64.getEncoder().encodeToString(serverKey), creds, roots, names).joinToString("\n")
    }

    /** How the link stands, as cbbtun reports it: registered, the other devices of the group at the relay, the connections through it, why it is not connected. */
    data class Report(val connected: Boolean = false, val online: List<String> = emptyList(), val through: Int = 0, val error: String? = null)

    private val lock = Any()
    private var settings: RelaySettings? = runCatching { load() }.onFailure { log("cannot read the relay's settings", it) }.getOrNull()
    private var link: RelayLink? = null
    private var report = Report()
    private var failure: String? = null
    private var credentials: Credentials? = null
    /** What the running link registers with: Credentials.shown, or null with the member certificate. */
    private var applied: String? = null

    /** The callers by the source port of their loopback connections, oldest first. */
    private val calls = LinkedHashMap<Int, String>()

    val isOn: Boolean get() = synchronized(lock) { settings != null }
    val relay: HubState.Forwarder? get() = synchronized(lock) { settings?.relay }
    val running: Boolean get() = synchronized(lock) { link != null }

    /** Turns it on with the relay at endpoint, "ip:port" (HubState.resolve), whose key pin pins, keeping the phone's key when it had one. */
    fun turnOn(endpoint: String, pin: String) {
        require(HubState.validPin(pin)) { "not a relay's key" }
        val old = synchronized(lock) { settings }
        val s = RelaySettings(old?.key ?: links.newKey(), HubState.Forwarder(endpoint, pin))
        save(s)
        synchronized(lock) { settings = s }
        if (old != s) stop()
    }

    /** Turns it off: forgets the relay and the phone's key there. */
    fun turnOff() {
        save(null)
        synchronized(lock) { settings = null }
        stop()
    }

    /** Starts the link while it is on; nothing when it runs already. g is what a hub takes: the loopback member listener's port, the member chain with the roots after it, the signer, the records. */
    fun start(g: HubOnPhone.Group) {
        val s = synchronized(lock) { if (link != null) return else settings } ?: return
        val l = try {
            links.start(s.key, device, s.relay.endpoint, s.relay.pin, JsonArray(g.chain.map { bytes(it) }).toString(), g.sign,
                recordsJson(g.records), g.memberPort, this)
        } catch (e: Exception) {
            log("the link to the relay could not start", e)
            synchronized(lock) { failure = e.message ?: e.toString() }
            return
        }
        val kept = synchronized(lock) {
            (link == null && settings == s).also {
                if (it) {
                    link = l
                    failure = null
                    report = Report()
                    applied = null
                }
            }
        }
        if (!kept) runCatching { l.close() } else applyCredentials()
    }

    /** Registers with the credentials c from now on, or with the member certificate when null; the link registers again only when they changed. */
    fun setCredentials(c: Credentials?) {
        synchronized(lock) { credentials = c }
        applyCredentials()
    }

    private fun applyCredentials() {
        val (l, c) = synchronized(lock) {
            val l = link ?: return
            val c = credentials
            if (c?.shown == applied) return
            applied = c?.shown
            l to c
        }
        runCatching {
            if (c == null) l.setCredentials(ByteArray(0), { it }, "", "", "") else l.setCredentials(c.serverKey, c.sign, c.creds, c.roots, c.names)
        }.onFailure {
            log("cannot hand the server credentials to the relay", it)
            synchronized(lock) { if (link == l) applied = null }
        }
    }

    /** Leaves the relay; the next start registers again. */
    fun stop() {
        val l = synchronized(lock) {
            link.also {
                link = null
                calls.clear()
                report = Report()
            }
        }
        l?.let { runCatching { it.close() } }
    }

    /** Hands the relay new authority records at the next registration, after a removal or a new admin. */
    fun setRecords(records: List<Member.Record>) {
        val l = synchronized(lock) { link } ?: return
        runCatching { l.setRecords(recordsJson(records)) }.onFailure { log("cannot hand the records to the relay", it) }
    }

    /** The device the relay said calls from the loopback port, once; null for a connection the relay did not announce. */
    fun caller(port: Int): String? = synchronized(lock) { calls.remove(port) }

    /** Where it stands, the report, and why it failed, for the screens; paused tells that the phone does not sync now. */
    fun status(paused: Boolean): Triple<Status, Report, String?> {
        val (on, running, r) = synchronized(lock) { Triple(settings != null, link != null, report) }
        val f = synchronized(lock) { failure }
        return when {
            !on -> Triple(Status.OFF, r, null)
            !running -> if (f != null && !paused) Triple(Status.FAILED, r, f) else Triple(Status.PAUSED, r, null)
            r.connected -> Triple(Status.CONNECTED, r, null)
            r.error != null -> Triple(Status.FAILED, r, r.error)
            else -> Triple(Status.CONNECTING, r, null)
        }
    }

    override fun dial(peer: String, port: Int) {
        Thread({
            try {
                serve(dialPeer(port, peer), peer)
            } catch (e: Exception) {
                log("a connection through the relay to $peer failed", e)
            }
        }, "cbb-relay-dial").apply { isDaemon = true; start() }
    }

    override fun calling(peer: String, localPort: Int) {
        synchronized(lock) {
            calls.remove(localPort)
            calls[localPort] = peer
            while (calls.size > MAX_CALLS) calls.remove(calls.keys.first())
        }
    }

    override fun wanted(peer: String): Boolean = !elsewhere(peer)

    override fun changed(state: String) {
        val r = runCatching {
            val o = Json.parseToJsonElement(state) as JsonObject
            Report(
                connected = o["connected"]?.jsonPrimitive?.booleanOrNull ?: false,
                online = (o["online"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }.orEmpty(),
                through = o["through"]?.jsonPrimitive?.intOrNull ?: 0,
                error = o.string("error"),
            )
        }.getOrNull() ?: return log("the relay's state does not decode: $state", null)
        synchronized(lock) { report = r }
    }

    private fun recordsJson(rs: List<Member.Record>): String = JsonArray(rs.map { it.toJson() }).toString()

    companion object {
        /** The most calls whose callers it keeps before their connections come. */
        const val MAX_CALLS = 64
    }
}

private fun bytes(b: ByteArray) = JsonPrimitive(Base64.getEncoder().encodeToString(b))

private fun JsonObject.string(key: String): String? = (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content
