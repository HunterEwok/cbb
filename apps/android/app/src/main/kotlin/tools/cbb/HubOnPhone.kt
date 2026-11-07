// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.Member
import tools.cbb.kit.PhoneHub
import tools.cbb.kit.Releases
import tools.cbb.kit.RustTunnel
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Base64

/**
 * What the phone keeps as the group's hub (docs/design.md, "The phone as
 * the hub", D-64): whether it is on, its WireGuard private key, the
 * forwarder it registers with, whether Android keeps it running in the
 * background, the home networks where it takes members and publishes
 * itself, and its clients.
 */
data class HubState(
    val key: ByteArray,
    val on: Boolean = false,
    val forwarder: Forwarder? = null,
    val background: Boolean = false,
    val homes: List<String> = emptyList(),
    val clients: List<PhoneHub.Client> = emptyList(),
    /** The group's AmneziaWG settings as JSON while the hub's tunnel speaks it, null for plain WireGuard; kept while it stays on, so the clients' offers stay good. */
    val obfuscation: String? = null,
    /** The group's VLESS user ID while its clients may come over VLESS to the forwarder, null otherwise. */
    val vlessID: String? = null,
) {
    /** The forwarder: its endpoint, "ip:port", and the pin of its key: SHA-256 of its key in standard base64. */
    data class Forwarder(val endpoint: String, val pin: String) {
        /** Whether this is the project's forwarder. */
        val isProject get() = pin == PROJECT_PIN

        companion object {
            /** The project's forwarder, which the hub uses unless the user gives their own: its name with the port, looked up when it is set, and the pin of its key, as cbb has them (internal/forward/project.go). */
            const val PROJECT_HOST = "cbb.tools:8764"
            const val PROJECT_PIN = "efzUG2YzJBqS8FfojZGwqioECt46VzQcFo3oWpPru/g="

            /** The project's forwarder at the address its name has now, IPv4 first; null when it cannot be looked up. On an IO thread. */
            fun project(): Forwarder? = HubState.resolve(PROJECT_HOST)?.let { Forwarder(it, PROJECT_PIN) }
        }
    }

    fun encode(): ByteArray = JsonObject(mapOfValues(
        "key" to bytes(key),
        "on" to JsonPrimitive(on),
        "forwarder" to forwarder?.let { JsonObject(mapOf("endpoint" to JsonPrimitive(it.endpoint), "pin" to JsonPrimitive(it.pin))) },
        "background" to JsonPrimitive(background),
        "homes" to JsonArray(homes.map { JsonPrimitive(it) }),
        "clients" to JsonArray(clients.map { it.toJson(keep = true) }),
        "obfuscation" to obfuscation?.let { Json.parseToJsonElement(it) },
        "vless_id" to vlessID?.let { JsonPrimitive(it) },
    )).toString().toByteArray()

    override fun equals(other: Any?): Boolean = other is HubState && encode().contentEquals(other.encode())

    override fun hashCode(): Int = key.contentHashCode()

    companion object {
        /** The most home networks the phone remembers; the oldest goes first. */
        const val MAX_HOMES = 8

        /** The state in b, or null when it is not one this version wrote. */
        fun decode(b: ByteArray): HubState? = runCatching {
            val o = Json.parseToJsonElement(b.toString(Charsets.UTF_8)) as JsonObject
            val key = Base64.getDecoder().decode(o.string("key") ?: return null)
            if (key.size != 32) return null
            val fw = (o["forwarder"] as? JsonObject)?.let { f -> Forwarder(f.string("endpoint") ?: return null, f.string("pin") ?: return null) }
            HubState(
                key,
                on = o["on"]?.jsonPrimitive?.booleanOrNull ?: false,
                forwarder = fw,
                background = o["background"]?.jsonPrimitive?.booleanOrNull ?: false,
                homes = (o["homes"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }.orEmpty(),
                clients = PhoneHub.clientsFromJson((o["clients"] as? JsonArray)?.toString() ?: ""),
                obfuscation = (o["obfuscation"] as? JsonObject)?.toString(),
                vlessID = o.string("vless_id"),
            )
        }.getOrNull()

        /** Whether pin is the pin of a forwarder's key, as `cbb forward` prints it. */
        fun validPin(pin: String): Boolean = runCatching {
            val b = Base64.getDecoder().decode(pin)
            b.size == 32 && Base64.getEncoder().encodeToString(b) == pin
        }.getOrDefault(false)

        /**
         * The forwarder's address as cbbtun takes it, "ip:port", from what
         * the user typed: an address or a name with its port. A name is
         * looked up now, IPv4 first; on the caller's IO thread.
         */
        fun resolve(s: String): String? {
            val t = s.trim()
            val i = t.lastIndexOf(':')
            if (i <= 0 || i == t.length - 1) return null
            val port = t.substring(i + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            val host = t.substring(0, i).removePrefix("[").removeSuffix("]")
            val addrs = runCatching { InetAddress.getAllByName(host).toList() }.getOrNull() ?: return null
            val a = addrs.firstOrNull { it is Inet4Address } ?: addrs.firstOrNull() ?: return null
            val ip = a.hostAddress ?: return null
            return if (a is Inet6Address) "[${ip.substringBefore('%')}]:$port" else "$ip:$port"
        }
    }
}

/** A running hub of mobile/cbbtun. */
interface HubTunnel {
    fun setClients(json: String)
    /** Registers with the forwarder; vlessID is the group's VLESS user ID, "" without VLESS. */
    fun register(endpoint: String, pin: String, chain: String, sign: (ByteArray) -> ByteArray, records: String, vlessID: String)
    fun setRecords(records: String)
    /** Tells the hub that its forwarder is the project's, with the ways in over VLESS of the signed entry points as JSON, "" for none (cbbtun's Hub.SetProjectWays). */
    fun setProjectWays(ways: String)
    /** cbbtun's Status JSON. */
    fun status(): String
    /** Opens a remote invitation's guest tunnel (cbbtun's Hub.Invite). */
    fun invite(group: String, endpoints: String, lifetimeS: Int, guestPort: Int): HubGuest
    fun close()
}

/** The guest tunnel of a remote invitation, cbbtun's Guest. */
interface HubGuest {
    /** The invitation's text, cbb://invite#…. */
    val text: String
    val secret: ByteArray
    /** When it expires, Unix seconds. */
    val expires: Long
    /** The window admitted the device: its first member connection goes to the member port. */
    fun admitted()
    fun close()
}

/** Starts hubs; the app's come from mobile/cbbtun, the tests' from a fake. */
interface HubTunnels {
    fun newKey(): ByteArray
    fun publicKey(private: ByteArray): ByteArray
    /** Starts the hub; obfuscation is its AmneziaWG settings as JSON, "" for plain WireGuard. */
    fun start(private: ByteArray, device: String, memberPort: Int, obfuscation: String, clients: String): HubTunnel
    /** New AmneziaWG settings for the group as JSON (cbbtun's NewObfuscation). */
    fun newObfuscation(): String
    /** A new VLESS user ID for the group (cbbtun's NewVLESSID). */
    fun newVLESSID(): String
}

/** The phone's hub in the Rust core (the kit's RustTunnel), WireGuard in the app's process. */
object CoreHubTunnels : HubTunnels {
    override fun newKey(): ByteArray = RustTunnel.newKey()
    override fun publicKey(private: ByteArray): ByteArray = RustTunnel.publicKey(private)
    override fun newObfuscation(): String = RustTunnel.newObfuscation()
    override fun newVLESSID(): String = RustTunnel.newVLESSID()
    override fun start(private: ByteArray, device: String, memberPort: Int, obfuscation: String, clients: String): HubTunnel {
        val h = RustTunnel.startHub(private, device, memberPort, obfuscation, clients)
        return object : HubTunnel {
            override fun setClients(json: String) = h.setClients(json)
            override fun register(endpoint: String, pin: String, chain: String, sign: (ByteArray) -> ByteArray, records: String, vlessID: String) =
                h.register(endpoint, pin, chain, sign, records, vlessID)
            override fun setRecords(records: String) = h.setRecords(records)
            override fun setProjectWays(ways: String) = h.setProjectWays(ways)
            override fun status(): String = h.status()
            override fun invite(group: String, endpoints: String, lifetimeS: Int, guestPort: Int): HubGuest {
                val g = h.invite(group, endpoints, lifetimeS, guestPort)
                return object : HubGuest {
                    override val text: String = g.text
                    override val secret: ByteArray = g.secret
                    override val expires: Long = g.expires
                    override fun admitted() = g.admitted()
                    override fun close() = g.close()
                }
            }
            override fun close() {
                h.close()
            }
        }
    }
}

/**
 * The phone as the group's hub while its app is open, or in the foreground
 * service when the user allows it (D-64). At home it takes the members on
 * its member port, which LiveGroup publishes by mDNS; from afar its
 * clients reach it through its forwarder, with which it registers by its
 * member key and the group's authority records (docs/protocol.md, section
 * 13). It admits a client by the tunnel key its hello offers, as a
 * computer's hub (PhoneHub), and answers with its offer, whose endpoint is
 * the forwarder's: without a forwarder it is a hub at home only and offers
 * nothing.
 */
class HubOnPhone(
    private val device: String,
    private val tunnels: HubTunnels,
    private val load: () -> HubState?,
    private val save: (HubState?) -> Unit,
    private val log: (String, Throwable?) -> Unit = { _, _ -> },
) {
    /** What the screens show. */
    enum class Status { OFF, PAUSED, HOME_ONLY, REGISTERING, REGISTERED, FAILED }

    /** How the hub's tunnel hides (docs/design.md, "Blocked networks"): plain WireGuard, AmneziaWG, or AmneziaWG with VLESS to the forwarder. */
    enum class Disguise { PLAIN, OBFUSCATE, VLESS }

    /** What a running hub needs from the group: the member listener's port, the member chain, the member key's signer, the authority records. */
    class Group(
        val memberPort: Int,
        val chain: List<ByteArray>,
        val sign: (ByteArray) -> ByteArray,
        val records: List<Member.Record>,
        /** The ways in over VLESS to the project's forwarder that the signed entry points name (EntriesFile.ways). */
        val ways: List<Releases.EntryVLESS> = emptyList(),
    )

    private val lock = Any()
    private var state: HubState? = runCatching { load() }.onFailure { log("cannot read the hub's state", it) }.getOrNull()
    private var hub: PhoneHub? = state?.let(::phoneHub)
    private var tunnel: HubTunnel? = null
    private var tunnelPort = 0 // the member listener's port the tunnel joins its connections to

    val isOn: Boolean get() = synchronized(lock) { state?.on == true }
    val forwarder: HubState.Forwarder? get() = synchronized(lock) { state?.forwarder }
    val background: Boolean get() = synchronized(lock) { state?.background == true }

    /** How the hub's tunnel hides now. */
    val disguise: Disguise
        get() = synchronized(lock) {
            when {
                state?.vlessID != null -> Disguise.VLESS
                state?.obfuscation != null -> Disguise.OBFUSCATE
                else -> Disguise.PLAIN
            }
        }
    val running: Boolean get() = synchronized(lock) { tunnel != null }

    /** The clients' devices, for the screens. */
    val clients: List<String> get() = synchronized(lock) { hub?.clients.orEmpty().map { it.device } }

    /** The clients with their keys, which a hub command hands to the new hub (docs/protocol.md, section 11, "Moving the hub"). */
    val handover: List<PhoneHub.Client> get() = synchronized(lock) { hub?.clients.orEmpty() }

    /** The offer the client device gets when the hub moves to newHub, as PhoneHub.movedOffer. */
    fun movedOffer(device: String, newHub: String, offer: Member.TunnelOffer): Member.TunnelOffer? =
        synchronized(lock) { hub }?.movedOffer(device, newHub, offer)

    private fun phoneHub(s: HubState): PhoneHub? = runCatching {
        PhoneHub(tunnels.publicKey(s.key), s.clients).also { configure(it, s) }
    }.onFailure { log("cannot make the hub", it) }.getOrNull()

    /** Gives h what the state says it offers: the forwarder's endpoint, the AmneziaWG settings and whether its clients may come over VLESS. */
    private fun configure(h: PhoneHub, s: HubState) {
        h.endpoints = listOfNotNull(s.forwarder?.endpoint)
        h.obfuscation = s.obfuscation
        h.vlessOnly = s.vlessID != null
        if (s.vlessID == null) h.vless = null
    }

    private fun change(f: (HubState) -> HubState) {
        val next = synchronized(lock) {
            val s = state ?: HubState(tunnels.newKey())
            f(s).also {
                state = it
                if (hub == null || !it.key.contentEquals(s.key)) hub = phoneHub(it)
                hub?.let { h -> configure(h, it) }
            }
        }
        save(next)
    }

    /** Turns it on, remembering home, the network the phone is on now, as a home network. */
    fun turnOn(home: String?) = change { s -> s.copy(on = true, homes = withHome(s.homes, home)) }

    /** Turns it off; the key and the clients stay, so turning it on again keeps the clients' tunnels. */
    fun turnOff() {
        change { it.copy(on = false) }
        stop()
    }

    /** Sets the forwarder, or none; endpoint is "ip:port" (HubState.resolve). */
    fun setForwarder(f: HubState.Forwarder?) {
        require(f == null || HubState.validPin(f.pin)) { "not a forwarder's key" }
        change { it.copy(forwarder = f) }
        stop() // the next start registers with it
    }

    /**
     * Sets how the hub's tunnel hides. The AmneziaWG settings and the VLESS
     * ID are made once and kept while that stays on; the clients get the new
     * offer the next time they meet the hub at home. VLESS comes with
     * AmneziaWG: the clients try it over UDP first, and inside VLESS it hides
     * WireGuard's sizes (docs/protocol.md, section 11, "VLESS").
     */
    fun setDisguise(d: Disguise) {
        val current = synchronized(lock) { state }
        val obf = if (d != Disguise.PLAIN) current?.obfuscation ?: tunnels.newObfuscation() else null
        val id = if (d == Disguise.VLESS) current?.vlessID ?: tunnels.newVLESSID() else null
        change { it.copy(obfuscation = obf, vlessID = id) }
        stop() // the next start speaks it
    }

    /** Lets Android keep the hub running in the foreground service while the app is in the background. */
    fun setBackground(on: Boolean) = change { it.copy(background = on) }

    /** Remembers home as a home network. */
    fun addHome(home: String) = change { s -> s.copy(homes = withHome(s.homes, home)) }

    /** Whether the phone takes members and publishes itself on the network home names. */
    fun isHome(home: String?): Boolean = home != null && synchronized(lock) { state?.homes?.contains(home) == true }

    private fun withHome(homes: List<String>, home: String?): List<String> =
        if (home == null || home in homes) homes else (homes + home).takeLast(HubState.MAX_HOMES)

    /** The hub while it is on and has a forwarder, as it offers and shares. */
    private val offering: PhoneHub? get() = synchronized(lock) { if (state?.on == true && state?.forwarder != null) hub else null }

    /**
     * The offers for a member whose hello offered key and psk, for
     * phone as the hub: this hub's own, then the group's other hubs' it
     * passes on, in order (docs/protocol.md, section 11, "Several hubs");
     * none while the hub is off or has no forwarder, or when the key is
     * refused. admitted runs once a new client is kept: the other hubs take
     * this hub's clients from what it shares, so it shares again, as a
     * computer does.
     */
    fun offers(
        device: String, key: ByteArray, psk: ByteArray? = null, order: List<String> = emptyList(), admitted: () -> Unit = {},
    ): List<Member.TunnelOffer> {
        val h = offering ?: return emptyList()
        val changed = { clients: List<PhoneHub.Client> ->
            clientsChanged(clients)
            admitted()
        }
        return h.offers(device, key, psk, order, changed = changed, refused = { why -> log("refused a client: $why", null) })
    }

    /** The offer for a member whose hello offered key, as offers gives it first; null without one. */
    fun offer(device: String, key: ByteArray): Member.TunnelOffer? = offers(device, key).firstOrNull()

    /** The offers a connected client device gets, after another hub's offer changed; empty for a device that is no client. */
    fun offersFor(device: String, order: List<String>): List<Member.TunnelOffer> {
        val h = offering ?: return emptyList()
        return h.clients.firstOrNull { it.device == device }?.let { h.offers(it, order) }.orEmpty()
    }

    /**
     * What this hub shares with another of the group's hubs: that it
     * serves, its offer and its clients; null while it is off or has no
     * forwarder. The phone serves whenever it is on: it does not yet give
     * way to a hub above it.
     */
    fun share(): Member.HubShare? = offering?.share()

    /**
     * Takes what another hub, from, shared: the clients the records know
     * (known), which this hub can then serve too, and the offer it passes
     * on to its clients. It returns whether that offer changed, so the
     * connected clients get it.
     */
    fun shared(from: String, share: Member.HubShare, known: (String) -> Boolean): Boolean {
        val h = offering ?: return false
        var changed = false
        for (c in share.clients) {
            if (c.device == device || !known(c.device)) continue
            try {
                if (h.take(c)) changed = true
            } catch (e: PhoneHub.Refused) {
                log("refused a client $from shared: ${e.message}", null)
            }
        }
        if (changed) clientsChanged(h.clients)
        return h.setOther(from, share.offer?.takeIf { it.hubKey.size == 32 && it.endpoints.size <= 8 })
    }

    private fun clientsChanged(clients: List<PhoneHub.Client>) {
        val (next, t) = synchronized(lock) {
            val s = state ?: return
            s.copy(clients = clients).also { state = it } to tunnel
        }
        runCatching { save(next) }.onFailure { log("cannot keep the hub's clients", it) }
        val json = JsonArray(clients.map { it.toJson() }).toString()
        t?.let { runCatching { it.setClients(json) }.onFailure { e -> log("cannot hand the clients to the tunnel", e) } }
    }

    /** Forgets the clients whose devices keep refuses, removed devices; returns them. */
    fun prune(keep: (String) -> Boolean): List<String> {
        val h = synchronized(lock) { hub } ?: return emptyList()
        val gone = h.prune { keep(it.device) }
        if (gone.isNotEmpty()) clientsChanged(h.clients)
        return gone
    }

    /** Starts the tunnel and the registration when the hub is on and has a forwarder; nothing when it runs already. */
    fun start(g: Group) {
        // A tunnel that joins its connections to another member listener's
        // port, one that stopped, starts again with this one.
        if (synchronized(lock) { tunnel != null && tunnelPort != g.memberPort }) {
            log("the hub's member listener moved to port ${g.memberPort}; the tunnel starts again", null)
            stop()
        }
        val (s, h) = synchronized(lock) {
            if (tunnel != null) return
            val s = state?.takeIf { it.on } ?: return
            s to (hub ?: return)
        }
        val fw = s.forwarder ?: return
        val t = try {
            tunnels.start(s.key, device, g.memberPort, s.obfuscation ?: "", h.clientsJson).also {
                // Away from home the hub may reach the project's forwarder only over VLESS (section 13).
                if (fw.isProject) it.setProjectWays(if (g.ways.isEmpty()) "" else JsonArray(g.ways.map { w -> w.toJson() }).toString())
                it.register(fw.endpoint, fw.pin, JsonArray(g.chain.map { bytes(it) }).toString(), g.sign, recordsJson(g.records), s.vlessID ?: "")
            }
        } catch (e: Exception) {
            log("the hub could not start", e)
            synchronized(lock) { failure = e.message ?: e.toString() }
            return
        }
        val kept = synchronized(lock) {
            (tunnel == null && state?.on == true).also {
                if (it) {
                    tunnel = t
                    tunnelPort = g.memberPort
                    failure = null
                }
            }
        }
        if (!kept) runCatching { t.close() }
    }

    /** Stops the tunnel and the registration; the clients come back at the next start. */
    fun stop() {
        val t = synchronized(lock) { tunnel.also { tunnel = null } }
        t?.let { runCatching { it.close() } }
    }

    /** Hands the forwarder new authority records at the next registration, after a removal or a new admin. */
    fun setRecords(records: List<Member.Record>) {
        val t = synchronized(lock) { tunnel } ?: return
        runCatching { t.setRecords(recordsJson(records)) }.onFailure { log("cannot hand the records to the tunnel", it) }
    }

    /**
     * Opens a remote invitation's guest tunnel to the window on guestPort
     * (docs/protocol.md, section 12), with the forwarder as the hub's
     * address away from home; throws while the hub does not run.
     */
    fun invite(group: String, lifetimeS: Int, guestPort: Int): HubGuest {
        val (t, fw) = synchronized(lock) { tunnel to state?.forwarder }
        if (t == null || fw == null) throw NotRunning()
        return t.invite(group, JsonArray(listOf(JsonPrimitive(fw.endpoint))).toString(), lifetimeS, guestPort)
    }

    /** The hub does not run: an invitation needs its tunnel and forwarder. */
    class NotRunning : Exception("the hub does not run")

    /** Why the hub could not start, until it does. */
    private var failure: String? = null

    /** Where it stands, and why it failed, for the screens; paused tells that the app is in the background. */
    fun status(paused: Boolean): Pair<Status, String?> {
        val (s, t, f) = synchronized(lock) { Triple(state, tunnel, failure) }
        if (s?.on != true) return Status.OFF to null
        if (s.forwarder == null) return Status.HOME_ONLY to null
        if (t == null) return if (f != null && !paused) Status.FAILED to f else Status.PAUSED to null
        val o = runCatching { Json.parseToJsonElement(t.status()) as JsonObject }.getOrNull() ?: return Status.REGISTERING to null
        // The way over VLESS comes with the forwarder's answer; the offers wait for it.
        if (s.vlessID != null) {
            (o["vless"] as? JsonObject)?.toString()?.let { v -> synchronized(lock) { hub }?.let { h -> if (h.vless != v) h.vless = v } }
        }
        if (o["registered"]?.jsonPrimitive?.booleanOrNull == true) return Status.REGISTERED to null
        val e = o.string("error") ?: return Status.REGISTERING to null
        return Status.FAILED to e
    }

    private fun recordsJson(rs: List<Member.Record>): String = JsonArray(rs.map { it.toJson() }).toString()

    companion object {
        /**
         * A network as the hub remembers it: its gateway's address and the
         * network of the phone's address on it, as "192.168.0.1 192.168.0.0/24".
         * Wi-Fi in a café has another, so the phone neither takes members
         * nor publishes itself there (as D-63 on the computers).
         */
        fun networkKey(gateway: InetAddress?, address: InetAddress?, prefixLength: Int): String? {
            val g = gateway?.hostAddress ?: return null
            val a = address?.address ?: return null
            if (prefixLength !in 0..a.size * 8) return null
            val n = a.copyOf()
            for (i in n.indices) {
                val bits = (prefixLength - i * 8).coerceIn(0, 8)
                n[i] = (n[i].toInt() and (0xff shl (8 - bits)).toByte().toInt()).toByte()
            }
            val net = InetAddress.getByAddress(n).hostAddress ?: return null
            return "${g.substringBefore('%')} $net/$prefixLength"
        }
    }
}

private fun bytes(b: ByteArray) = JsonPrimitive(Base64.getEncoder().encodeToString(b))

/** The pairs whose value is not null, as a JSON object's fields. */
private fun mapOfValues(vararg pairs: Pair<String, JsonElement?>): Map<String, JsonElement> =
    pairs.mapNotNull { (k, v) -> v?.let { k to it } }.toMap()

private fun JsonObject.string(key: String): String? = (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content
