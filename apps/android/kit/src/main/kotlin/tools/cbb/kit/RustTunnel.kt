// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.Timer
import kotlin.concurrent.fixedRateTimer

/**
 * The phones' tunnel in Rust (lite/ffi/src/tunnel.rs, the library's feature
 * `tunnel`), in place of mobile/cbbtun: the tunnel to the hub, the phone as
 * the group's hub with its remote invitations and its registration with
 * the forwarder, and the link to the blind relay. The app's Tunnels,
 * HubTunnels and RelayLinks wrap it as they wrapped cbbtun.
 */
object RustTunnel {
    /** A request the tunnel refused, or an answer it could not give. */
    class Failure(override val message: String, val details: String = "") : Exception(message) {
        override fun toString(): String = if (details.isEmpty()) "tunnel: $message" else "tunnel: $message: $details"
    }

    @Suppress("FunctionName")
    private interface Lib : Library {
        fun cbb_tunnel(request: ByteArray, len: Core.SizeT, answerLen: Pointer): Pointer?

        fun cbb_tunnel_register(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answerLen: Pointer): Pointer?

        fun cbb_tunnel_relay(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, event: CoreMember.EventFn, ctx: Pointer?, answerLen: Pointer): Pointer?

        fun cbb_tunnel_relay_credentials(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answerLen: Pointer): Pointer?

        fun cbb_free(answer: Pointer?, len: Core.SizeT)
    }

    private val lib: Lib by lazy { Native.load("cbb_ffi", Lib::class.java) }

    /** The longest DER signature of P-256, the room the library gives. */
    private const val MAX_SIG = 72

    /**
     * Every callback handed to the library, so that the garbage collector never takes one it may still call: a
     * registration or a link holds its callbacks until it stops, and a few kilobytes for the process is the price.
     */
    private val kept = mutableListOf<Callback>()

    private fun <T : Callback> keep(c: T): T = c.also { synchronized(kept) { kept += it } }

    private fun signFn(sign: (ByteArray) -> ByteArray): CoreMember.SignFn = keep(
        CoreMember.SignFn { _, digest, sig, sigLen ->
            try {
                val s = sign(digest.getByteArray(0, 32))
                if (s.isEmpty() || s.size > MAX_SIG) return@SignFn 1
                sig.write(0, s, 0, s.size)
                if (Native.SIZE_T_SIZE == 8) sigLen.setLong(0, s.size.toLong()) else sigLen.setInt(0, s.size)
                0
            } catch (e: Exception) {
                1
            }
        },
    )

    /** Sends one request to cbb_tunnel and returns its `ok`. */
    fun call(request: JsonObject): JsonObject = answer(request) { r, n -> lib.cbb_tunnel(r, Core.SizeT(r.size.toLong()), n) }

    private fun answer(request: JsonObject, f: (ByteArray, Pointer) -> Pointer?): JsonObject {
        val body = Wire.encode(request)
        val count = Memory(Native.SIZE_T_SIZE.toLong()).apply { clear() }
        val p = f(body, count) ?: throw Failure("the tunnel gave no answer")
        val n = if (Native.SIZE_T_SIZE == 8) count.getLong(0) else count.getInt(0).toLong() and 0xffffffffL
        val bytes = try {
            if (n > Int.MAX_VALUE) throw Failure("the tunnel's answer is $n bytes long")
            p.getByteArray(0, n.toInt())
        } finally {
            lib.cbb_free(p, Core.SizeT(n))
        }
        val a = runCatching { Json.parseToJsonElement(bytes.decodeToString()) as JsonObject }.getOrNull()
            ?: throw Failure("the tunnel's answer does not read")
        (a["error"] as? JsonObject)?.let { throw Failure(it.optString("message") ?: "unknown", it.optString("details") ?: "") }
        return a["ok"] as? JsonObject ?: JsonObject(emptyMap())
    }

    /** A JSON value from text the app's interfaces carry: "" for none. */
    fun json(s: String): JsonElement? = if (s.isEmpty()) null else Json.parseToJsonElement(s)

    private fun obj(vararg pairs: Pair<String, JsonElement?>): JsonObject = JsonObject(pairs.filter { it.second != null }.associate { it.first to it.second!! })

    private fun b64(b: ByteArray) = JsonPrimitive(Base64.getEncoder().encodeToString(b))

    private fun bytes(o: JsonObject, key: String): ByteArray =
        o.optString(key)?.let { Base64.getDecoder().decode(it) } ?: throw Failure("the tunnel gave no $key")

    private fun long(o: JsonObject, key: String): Long = o.optLong(key) ?: throw Failure("the tunnel gave no $key")

    /** The public point (SEC1, uncompressed) of the key of a certificate, DER. */
    fun point(certificate: ByteArray): ByteArray {
        val c = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certificate))
        return CoreMember.point(c.publicKey.encoded)
    }

    /** The certificates of a JSON array of base64 DER, as cbbtun took a chain. */
    private fun chain(json: String): List<ByteArray> =
        (json(json) as? JsonArray)?.map { Base64.getDecoder().decode(it.jsonPrimitive.content) } ?: throw Failure("the chain is not a JSON array")

    fun newKey(): ByteArray = bytes(call(obj("op" to JsonPrimitive("new_key"))), "key")

    fun publicKey(private: ByteArray): ByteArray = bytes(call(obj("op" to JsonPrimitive("public_key"), "key" to b64(private))), "public")

    /** New AmneziaWG settings for a group, as JSON. */
    fun newObfuscation(): String = (call(obj("op" to JsonPrimitive("new_obfuscation")))["obfuscation"] ?: throw Failure("the tunnel gave no obfuscation")).toString()

    fun newVLESSID(): String = call(obj("op" to JsonPrimitive("new_vless_id"))).optString("id") ?: throw Failure("the tunnel gave no VLESS ID")

    /** A running tunnel to the hub: its loopback port leads to the hub's member port. */
    class Tunnel internal constructor(val id: Long, val port: Int) {
        fun setEndpoint(endpoint: String) {
            call(obj("op" to JsonPrimitive("set_endpoint"), "id" to JsonPrimitive(id), "endpoint" to JsonPrimitive(endpoint)))
        }

        fun close() {
            runCatching { call(obj("op" to JsonPrimitive("stop"), "id" to JsonPrimitive(id))) }
        }
    }

    /** Starts a tunnel to the hub; obfuscation and vless are the offer's as JSON, "" without. */
    fun start(private: ByteArray, psk: ByteArray, hubKey: ByteArray, device: String, hub: String, endpoint: String, obfuscation: String, vless: String): Tunnel {
        val offer = obj(
            "hub_key" to b64(hubKey), "psk" to b64(psk),
            "endpoints" to JsonArray(if (endpoint.isEmpty()) emptyList() else listOf(JsonPrimitive(endpoint))),
            "obfuscation" to json(obfuscation), "vless" to json(vless),
        )
        val ok = call(obj("op" to JsonPrimitive("start"), "key" to b64(private), "device" to JsonPrimitive(device), "hub" to JsonPrimitive(hub), "offer" to offer))
        return Tunnel(long(ok, "id"), long(ok, "port").toInt())
    }

    /** The guest tunnel of a remote invitation. */
    class Guest internal constructor(private val hub: Long, private val guest: Long, val text: String, val secret: ByteArray, val expires: Long) {
        fun admitted() {
            runCatching { call(obj("op" to JsonPrimitive("guest_admitted"), "id" to JsonPrimitive(hub), "guest" to JsonPrimitive(guest))) }
        }

        fun close() {
            runCatching { call(obj("op" to JsonPrimitive("guest_close"), "id" to JsonPrimitive(hub), "guest" to JsonPrimitive(guest))) }
        }
    }

    /** A running hub on the phone. */
    class Hub internal constructor(val id: Long) {
        private fun op(op: String, vararg pairs: Pair<String, JsonElement?>): JsonObject =
            call(obj("op" to JsonPrimitive(op), "id" to JsonPrimitive(id), *pairs))

        fun setClients(json: String) {
            op("hub_set_clients", "clients" to (json(json) ?: JsonArray(emptyList())))
        }

        /** Registers with the forwarder; chain is a JSON array of base64 DER, the member certificate first. */
        fun register(endpoint: String, pin: String, chain: String, sign: (ByteArray) -> ByteArray, records: String, vlessID: String) {
            val certs = chain(chain)
            val leaf = certs.firstOrNull() ?: throw Failure("the member certificate is missing")
            val req = obj(
                "id" to JsonPrimitive(id), "endpoint" to JsonPrimitive(endpoint), "pins" to JsonArray(listOf(JsonPrimitive(pin))),
                "chain" to JsonArray(certs.map { b64(it) }), "public" to b64(point(leaf)),
                "records" to json(records), "vless_id" to vlessID.takeIf { it.isNotEmpty() }?.let { JsonPrimitive(it) },
            )
            val s = signFn(sign)
            answer(req) { r, n -> lib.cbb_tunnel_register(r, Core.SizeT(r.size.toLong()), s, null, n) }
        }

        fun setRecords(records: String) {
            op("hub_set_records", "records" to (json(records) ?: JsonArray(emptyList())))
        }

        fun setProjectWays(ways: String) {
            op("hub_set_project_ways", "ways" to (json(ways) ?: JsonArray(emptyList())))
        }

        /** The forwarder's report as cbbtun's Status gave it: {} before the registration. */
        fun status(): String = runCatching { (op("hub_status")["forwarder"] as? JsonObject)?.toString() }.getOrNull() ?: "{}"

        /** Opens a remote invitation; endpoints is a JSON array of "ip:port". */
        fun invite(group: String, endpoints: String, lifetimeS: Int, guestPort: Int): Guest {
            val ok = op(
                "hub_invite", "group" to JsonPrimitive(group), "endpoints" to (json(endpoints) ?: JsonArray(emptyList())),
                "lifetime" to JsonPrimitive(lifetimeS), "guest_port" to JsonPrimitive(guestPort),
            )
            return Guest(id, long(ok, "guest"), ok.optString("text") ?: throw Failure("the tunnel gave no invitation"), bytes(ok, "secret"), long(ok, "expires"))
        }

        /** The hub's WireGuard port. */
        fun udpPort(): Int = long(op("hub_status"), "udp_port").toInt()

        fun close() {
            runCatching { op("hub_stop") }
        }
    }

    /** Starts the hub; obfuscation is its AmneziaWG settings as JSON, "" for plain WireGuard; clients a JSON array. */
    fun startHub(private: ByteArray, device: String, memberPort: Int, obfuscation: String, clients: String): Hub {
        val ok = call(
            obj(
                "op" to JsonPrimitive("hub_start"), "key" to b64(private), "device" to JsonPrimitive(device),
                "member_port" to JsonPrimitive(memberPort), "clients" to (json(clients) ?: JsonArray(emptyList())),
                "obfuscation" to json(obfuscation),
            ),
        )
        return Hub(long(ok, "id"))
    }

    /** What a relay link asks of the app, as cbbtun's RelayEvents. */
    interface RelayEvents {
        fun dial(peer: String, port: Int)
        fun calling(peer: String, localPort: Int)
        fun wanted(peer: String): Boolean
        /** The link stands as the JSON state says: connected, online, through, error. */
        fun changed(state: String)
    }

    /**
     * A running link to a blind relay. The library asks which devices are connected another way, where cbbtun asked
     * whether each one is wanted: the link asks the app about each device on the relay whenever the relay's list
     * changes and every few seconds, and tells the library.
     */
    class Relay internal constructor(private val events: RelayEvents) {
        private val lock = Any()
        private var id: Long? = null
        private var online: List<String> = emptyList()
        private var connected: Set<String> = emptySet()
        private var closed = false
        private var timer: Timer? = null

        internal fun started(id: Long) {
            synchronized(lock) {
                this.id = id
                timer = fixedRateTimer("relay wanted", daemon = true, initialDelay = WANT_CHECK_MS, period = WANT_CHECK_MS) { askWanted() }
            }
            askWanted()
        }

        internal fun event(e: JsonObject) {
            val peer = e.optString("peer") ?: ""
            val port = e.optLong("port")?.toInt() ?: 0
            when (e.optString("type")) {
                "dial" -> events.dial(peer, port)
                "calling" -> events.calling(peer, port)
                "changed" -> {
                    val state = JsonObject(e - "type")
                    val on = (state["online"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } ?: emptyList()
                    synchronized(lock) { online = on }
                    events.changed(state.toString())
                    askWanted()
                }
            }
        }

        private fun askWanted() {
            val (id, on) = synchronized(lock) { (if (closed) null else id) to online }
            if (id == null) return
            val other = on.filter { !events.wanted(it) }.toSet()
            val changed = synchronized(lock) { (connected != other).also { connected = other } }
            if (changed) {
                runCatching {
                    call(obj("op" to JsonPrimitive("relay_set_connected"), "id" to JsonPrimitive(id), "devices" to JsonArray(other.map { JsonPrimitive(it) })))
                }
            }
        }

        fun setRecords(records: String) {
            val id = synchronized(lock) { id } ?: return
            call(obj("op" to JsonPrimitive("relay_set_records"), "id" to JsonPrimitive(id), "records" to (json(records) ?: JsonArray(emptyList()))))
        }

        /** Registers with the group's server credentials from now on; an empty creds goes back to the member certificate. */
        fun setCredentials(serverKey: ByteArray, sign: (ByteArray) -> ByteArray, creds: String, roots: String, names: String) {
            val id = synchronized(lock) { id } ?: return
            val req = obj(
                "id" to JsonPrimitive(id), "credentials" to (json(creds) ?: JsonArray(emptyList())),
                "roots" to (json(roots) ?: JsonArray(emptyList())), "names" to (json(names) ?: JsonObject(emptyMap())),
                "public" to if (creds.isEmpty()) null else b64(CoreMember.point(serverKey)),
            )
            val s = signFn(sign)
            answer(req) { r, n -> lib.cbb_tunnel_relay_credentials(r, Core.SizeT(r.size.toLong()), s, null, n) }
        }

        fun close() {
            val (id, t) = synchronized(lock) {
                val was = if (closed) null else id
                closed = true
                (was to timer).also { timer = null }
            }
            t?.cancel()
            if (id != null) runCatching { call(obj("op" to JsonPrimitive("relay_stop"), "id" to JsonPrimitive(id))) }
        }

        private companion object {
            const val WANT_CHECK_MS = 2000L
        }
    }

    /** Links the phone to a blind relay; chain is a JSON array of base64 DER, records the authority records as JSON. */
    fun startRelay(
        private: ByteArray, device: String, endpoint: String, pin: String, chain: String,
        sign: (ByteArray) -> ByteArray, records: String, memberPort: Int, events: RelayEvents,
    ): Relay {
        val certs = chain(chain)
        val leaf = certs.firstOrNull() ?: throw Failure("the member certificate is missing")
        val req = obj(
            "key" to b64(private), "device" to JsonPrimitive(device), "endpoint" to JsonPrimitive(endpoint),
            "pins" to JsonArray(listOf(JsonPrimitive(pin))), "chain" to JsonArray(certs.map { b64(it) }),
            "public" to b64(point(leaf)), "member_port" to JsonPrimitive(memberPort), "records" to json(records),
        )
        val link = Relay(events)
        val s = signFn(sign)
        val e = keep(
            CoreMember.EventFn { _, event, len ->
                runCatching { Json.parseToJsonElement(event.getByteArray(0, len.toInt()).decodeToString()) as JsonObject }.getOrNull()?.let(link::event)
            },
        )
        val ok = answer(req) { r, n -> lib.cbb_tunnel_relay(r, Core.SizeT(r.size.toLong()), s, e, null, n) }
        link.started(long(ok, "id"))
        return link
    }
}
