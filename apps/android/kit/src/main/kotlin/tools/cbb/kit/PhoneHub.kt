// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.SecureRandom

/**
 * The phone as the group's hub while its app is open (docs/design.md, "The
 * phone as the hub", D-64): the clients it admits by the tunnel keys their
 * hellos offer, and the offers it answers with (docs/protocol.md, section
 * 11), by the same rules as a computer's hub. The tunnel itself is cbbtun's
 * Hub, which takes clientsJson.
 *
 * publicKey is the hub's WireGuard public key. The methods are thread-safe.
 */
class PhoneHub(val publicKey: ByteArray, clients: List<Client> = emptyList()) {
    /**
     * A client: its device ID, the tunnel key it offered and its preshared
     * key, and whether this hub met it itself (by its hello) rather than
     * only taking it from another hub.
     */
    class Client(val device: String, val key: ByteArray, val psk: ByteArray, val met: Boolean = false) {
        /** As cbbtun and the other hubs take it; met only to keep it. */
        fun toJson(keep: Boolean = false): JsonObject = Wire.obj(
            "device" to Wire.str(device),
            "key" to Wire.bytes(key),
            "psk" to Wire.bytes(psk),
            "met" to if (keep && met) JsonPrimitive(true) else null,
        )

        companion object {
            fun fromJson(o: JsonObject): Client = Client(
                o.optString("device") ?: throw WireTypeException("device: missing"),
                o.optBytes("key") ?: throw WireTypeException("key: missing"),
                o.optBytes("psk") ?: throw WireTypeException("psk: missing"),
                o.optBool("met") ?: false,
            )
        }
    }

    class Refused(message: String) : Exception(message)

    private val lock = Any()
    private val list = clients.toMutableList()

    /**
     * Where the clients reach the hub away from home, "ip:port": the
     * forwarder's endpoint, which the offers carry.
     */
    @Volatile var endpoints: List<String> = emptyList()

    /** The group's obfuscation settings as JSON text, null for plain WireGuard. */
    @Volatile var obfuscation: String? = null

    /**
     * Whether the clients may come over VLESS: the offers then wait for
     * vless, the way to the forwarder that its answer gives (cbbtun's
     * Status).
     */
    @Volatile var vlessOnly: Boolean = false

    /** The way to the forwarder over VLESS as JSON text, null without it. */
    @Volatile var vless: String? = null

    init {
        require(publicKey.size == 32) { "a WireGuard key is 32 bytes" }
    }

    val clients: List<Client> get() = synchronized(lock) { list.toList() }

    /**
     * Admits device with the tunnel key and the preshared key it offered
     * (null from an older member), as Go's State.Admit: the client's own
     * preshared key when it offers one, so every hub of the group uses the
     * same (docs/protocol.md, section 11, "Several hubs"); otherwise a
     * client that keeps its key keeps its preshared key, and a new key gets
     * a new one. changed tells whether the clients must be saved and handed
     * to the tunnel again. It throws Refused for a key that is not 32
     * bytes, the hub's own, or another client's, and for a 257th client.
     */
    fun admit(device: String, key: ByteArray, psk: ByteArray? = null): Pair<Client, Boolean> = synchronized(lock) {
        if (!GroupCertificates.isDeviceID(device)) throw Refused("$device is not a device ID")
        if (key.size != 32 || key.all { it == 0.toByte() } || key.contentEquals(publicKey)) throw Refused("a client offered no key or the hub's own")
        val own = psk?.takeIf { it.size == 32 && !it.all { b -> b == 0.toByte() } }?.copyOf()
        val i = list.indexOfFirst { it.device == device }
        list.withIndex().firstOrNull { (j, o) -> j != i && o.key.contentEquals(key) }?.let { (_, o) ->
            throw Refused("$device offered the key of ${o.device}")
        }
        if (i >= 0) {
            val c = list[i]
            if (c.met && c.key.contentEquals(key) && (own == null || own.contentEquals(c.psk))) return c to false
            val next = own ?: if (c.key.contentEquals(key)) c.psk else newPSK()
            return Client(device, key.copyOf(), next, met = true).also { list[i] = it } to true
        }
        if (list.size >= MAX_CLIENTS) throw Refused("the hub has too many clients")
        Client(device, key.copyOf(), own ?: newPSK(), met = true).also { list += it } to true
    }

    /**
     * Takes a client another hub shared or handed over, with the keys it
     * has, as Go's State.Take: a client this hub met itself stays as it is;
     * one only taken before gets the new keys. It returns whether the
     * clients changed, and throws Refused as admit.
     */
    fun take(c: Client): Boolean = synchronized(lock) {
        if (!GroupCertificates.isDeviceID(c.device)) throw Refused("${c.device} is not a device ID")
        if (c.key.size != 32 || c.psk.size != 32 || c.key.all { it == 0.toByte() } || c.psk.all { it == 0.toByte() }) {
            throw Refused("${c.device} has no key")
        }
        if (c.key.contentEquals(publicKey)) throw Refused("${c.device} has the hub's own key")
        val i = list.indexOfFirst { it.device == c.device }
        list.withIndex().firstOrNull { (j, o) -> j != i && o.key.contentEquals(c.key) }?.let { (_, o) ->
            throw Refused("${c.device} has the key of ${o.device}")
        }
        if (i >= 0) {
            val o = list[i]
            if (o.met || o.key.contentEquals(c.key) && o.psk.contentEquals(c.psk)) return false
            list[i] = Client(c.device, c.key.copyOf(), c.psk.copyOf())
            return true
        }
        if (list.size >= MAX_CLIENTS) throw Refused("the hub has too many clients")
        list += Client(c.device, c.key.copyOf(), c.psk.copyOf())
        true
    }

    /** The other hubs' offers without a preshared key, by device, which this hub passes on to its clients. */
    private val others = mutableMapOf<String, Member.TunnelOffer>()

    /** Keeps the offer of another hub, from what it shared, to pass on; null forgets it. It returns whether it changed. */
    fun setOther(device: String, offer: Member.TunnelOffer?): Boolean = synchronized(lock) {
        if (offer == null || offer.hubKey.contentEquals(publicKey)) return others.remove(device) != null
        val o = offer.with(ByteArray(0), null)
        (others.put(device, o) != o)
    }

    /**
     * The offers the client c gets: this hub's own, then the other hubs'
     * with c's preshared key and the hub named, highest first in order.
     */
    fun offers(c: Client, order: List<String> = emptyList()): List<Member.TunnelOffer> {
        val own = offer(c) ?: return emptyList()
        val rest = synchronized(lock) { others.toList() }
            .filter { (d, _) -> d != c.device }
            .sortedBy { (d, _) -> order.indexOf(d).let { if (it < 0) order.size else it } }
            .map { (d, o) -> o.with(c.psk, d) }
        return listOf(own) + rest
    }

    /**
     * What this hub shares with the group's other hubs: that it serves, its
     * offer without a preshared key and its clients; null while its offers
     * wait for VLESS.
     */
    fun share(): Member.HubShare? {
        val v = vless
        if (vlessOnly && v == null) return null
        return Member.HubShare(true, Member.TunnelOffer(publicKey, ByteArray(0), endpoints.take(8), obfuscation, v), clients)
    }

    /** The offer for a client admitted with admit, or null while the offers wait for VLESS. */
    fun offer(c: Client): Member.TunnelOffer? {
        val v = vless
        if (vlessOnly && v == null) return null
        return Member.TunnelOffer(publicKey, c.psk, endpoints.take(8), obfuscation, v)
    }

    /**
     * Admits a peer and returns its offer, for MemberNode's hub: null when
     * it is refused (refused tells why) or the offers wait. changed gets
     * the clients when they changed.
     */
    fun offer(device: String, key: ByteArray, changed: (List<Client>) -> Unit = {}, refused: (String) -> Unit = {}): Member.TunnelOffer? =
        offers(device, key, null, emptyList(), changed, refused).firstOrNull()

    /**
     * Admits a peer with the keys its hello offers and returns its offers,
     * this hub's own first, for MemberNode's hub: empty when it is refused
     * (refused tells why) or the offers wait. changed gets the clients when
     * they changed.
     */
    fun offers(
        device: String, key: ByteArray, psk: ByteArray?, order: List<String>,
        changed: (List<Client>) -> Unit = {}, refused: (String) -> Unit = {},
    ): List<Member.TunnelOffer> {
        val (c, fresh) = try {
            admit(device, key, psk)
        } catch (e: Refused) {
            refused(e.message ?: "refused")
            return emptyList()
        }
        if (fresh) changed(clients)
        return offers(c, order)
    }

    /**
     * The offer the client device gets when the hub moves to newHub, whose
     * offer without a preshared key is offer (a hub command's result): with
     * the client's own preshared key and newHub named (docs/protocol.md,
     * section 11, "Moving the hub"); null for a device that is no client,
     * or newHub itself.
     */
    fun movedOffer(device: String, newHub: String, offer: Member.TunnelOffer): Member.TunnelOffer? =
        if (device == newHub) null else clients.firstOrNull { it.device == device }?.let { offer.with(it.psk, newHub, moved = true) }

    /** Forgets the clients keep refuses, removed devices for one, and returns their devices. */
    fun prune(keep: (Client) -> Boolean): List<String> = synchronized(lock) {
        val gone = list.filterNot(keep)
        list.removeAll(gone)
        gone.map { it.device }
    }

    /** The clients as cbbtun's StartHub and SetClients take them. */
    val clientsJson: String get() = JsonArray(clients.map { it.toJson() }).toString()

    companion object {
        /** The most clients a hub keeps, as a computer's hub. */
        const val MAX_CLIENTS = 256

        private val random = SecureRandom()

        private fun newPSK(): ByteArray = ByteArray(32).also { random.nextBytes(it) }

        /** The clients clientsJson gave; it throws IllegalArgumentException on anything else. */
        fun clientsFromJson(s: String): List<Client> {
            if (s.isEmpty()) return emptyList()
            try {
                val a = Json.parseToJsonElement(s) as? JsonArray ?: throw IllegalArgumentException("the clients are not an array")
                return a.map { Client.fromJson(it as? JsonObject ?: throw IllegalArgumentException("a client is not an object")) }
            } catch (e: WireTypeException) {
                throw IllegalArgumentException("the clients: ${e.message}", e)
            } catch (e: kotlinx.serialization.SerializationException) {
                throw IllegalArgumentException("the clients: ${e.message}", e)
            }
        }
    }
}
