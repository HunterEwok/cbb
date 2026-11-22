// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.provider.Settings as SystemSettings
import android.util.Log
import tools.cbb.kit.AndroidAttestation
import tools.cbb.kit.CertificateSigner
import tools.cbb.kit.Core
import tools.cbb.kit.CoreMember
import tools.cbb.kit.CorePairing
import tools.cbb.kit.ChangePreview
import tools.cbb.kit.Notice
import tools.cbb.kit.RecoveryInput
import tools.cbb.kit.Discovery
import tools.cbb.kit.FoundMember
import tools.cbb.kit.LocalAddresses
import tools.cbb.kit.Media
import tools.cbb.kit.Member
import tools.cbb.kit.PhoneGroup
import tools.cbb.kit.Records as KitRecords
import tools.cbb.kit.CardLink
import tools.cbb.kit.RecoveryCard
import tools.cbb.kit.WhyReason
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.File
import java.io.IOException
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.Signature
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * The phone's group (docs/protocol.md, section 9): its root or admin key
 * in the Keystore, signing only after the fingerprint, the face or the
 * screen lock (Keys, Authenticator), its member key there too, the group in
 * the app's files. While there is a group it finds the computers, keeps a
 * connection to each, and syncs with them.
 *
 * The group is read and changed under one lock: the screens' actions run on
 * the main thread and the network work on Dispatchers.IO, the node's
 * connections on threads of their own.
 */
class LiveGroup(private val context: Context, private val file: File = defaultFile(context)) {
    /** The failures the app says something about. */
    /** A computer refused a command this phone sent it, for the reason it gave. */
    class CommandRefused(val reason: String) : Exception(reason)

    /** The device a command or a fetch needs is not connected, nor is a hub that passes it on. */
    class NotConnected(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** The images or files of a copy could not be fetched from the connected devices. */
    class Unavailable(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** An admin muted this phone: its copies do not reach the group. */
    class Muted : Exception("an admin muted this phone: its copies do not reach the group")

    class Failure(val kind: Kind, cause: Throwable? = null) : Exception(kind.name, cause) {
        enum class Kind { UNREACHABLE, NOT_CONFIRMED, NO_NETWORK, TIMED_OUT, TOO_MANY_WRONG_CODES, NOT_ADMIN, NO_COMPUTERS, NO_SCREEN, NO_WINDOW, TWO_WINDOWS, NO_GROUP, ROOT_LEAVES, HUB_UNREACHABLE }
    }

    /** A device of the group, as the screens show it: a computer, or this phone. */
    data class Device(
        val id: String,
        val name: String,
        /** Connected to this phone, or to a computer that is (throughHub). */
        val online: Boolean,
        val role: String = "member",
        /** What a member can do: "admin", "dials" and "hub". */
        val caps: List<String> = emptyList(),
        /** Its system: linux, windows, macos, ios, android or none; null if unknown. */
        val os: String? = null,
        val isSelf: Boolean = false,
        /** An admin: it may add and remove devices. */
        val admin: Boolean = false,
        /** The phone that holds the group's root. */
        val isRoot: Boolean = false,
        /** A computer this phone, the root, can make an admin: it offers an admin key. */
        val canMakeAdmin: Boolean = false,
        /** Its keys sit in a file, as its hello or else its record says: a thief with it can copy them. */
        val keysInFile: Boolean = false,
        /** It is a rootless install, as its hello or else its record says: never an admin or a hub (D-79). */
        val rootless: Boolean = false,
        /** An admin computer another admin froze: the root or an admin phone unfreezes or removes it. */
        val frozen: Boolean = false,
        /** What its hello says about its device, while it is connected; this phone's own for itself. */
        val device: Member.DeviceInfo? = null,
        /** The sync mode its hello reports, while it is connected. */
        val mode: String? = null,
        /** The quick actions its hello says are on, while it is connected. */
        val actions: List<String> = emptyList(),
        /** The records let it be a hub: the root's own device, an admin with the hub power, or a hub that only passes copies on. */
        val mayHub: Boolean = false,
        /** A hub that only passes the copies on: none is sealed to it. */
        val forwardOnly: Boolean = false,
        /** Where it stands among the group's hubs, as this phone knows: null when it is none. */
        val hub: HubMark? = null,
        /**
         * Online only through a connected computer, the hub away from home, which
         * passes commands on to it (docs/protocol.md, section 4, "Reach"); a hub
         * command still needs it connected here.
         */
        val throughHub: Boolean = false,
        /**
         * An admin muted it: its copies stay its own (design.md, "Muting a
         * device"). This phone's own, or what a connected device's hello says.
         */
        val muted: Hold? = null,
        /** This phone takes no copies from the group for now; only on its own entry. */
        val syncOff: Hold? = null,
    ) {
        /** Whether it is a member with the capability c. */
        fun can(c: String): Boolean = role == "member" && c in caps
    }

    /** A mute or a pause that holds: until when in Unix milliseconds, null for until it is lifted. */
    data class Hold(val until: Long?) {
        companion object {
            /** From Unix milliseconds, 0 for until it is lifted; null for none or one that ended. */
            fun of(ms: Long?, now: Long = System.currentTimeMillis()): Hold? = when {
                ms == null -> null
                ms == 0L -> Hold(null)
                ms > now -> Hold(ms)
                else -> null
            }
        }
    }

    /** A device as one of the group's hubs: this phone while it is the hub, or a hub whose offer the phone keeps. */
    enum class HubMark {
        HUB,

        /** The hub the phone reaches now. */
        IN_USE,
    }

    /**
     * What this phone says about itself in its hellos: a phone, a tablet or
     * a TV, its Android version and the app's; Android gives apps no MAC
     * address.
     */
    private val ownDevice: Member.DeviceInfo by lazy {
        Member.DeviceInfo(
            form = when {
                Tv.isTv(context) -> "tv"
                context.resources.configuration.smallestScreenWidthDp >= 600 -> "tablet"
                else -> "phone"
            },
            osVersion = Build.VERSION.RELEASE,
            version = runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull(),
        )
    }

    enum class SyncResult { SENT, FETCHED, SWAPPED, NOTHING_NEW }

    private val lock = Any()
    private var state: PhoneGroup? = runCatching { PhoneGroup.load(file) }.getOrNull()

    /**
     * The app's folder holds a group made before 0.6, which this version
     * no longer runs (D-126): the app says so and offers to leave it; its
     * files stay until the person leaves.
     */
    @Volatile var before06: Boolean = runCatching { PhoneGroup.load(file) }.exceptionOrNull() is PhoneGroup.Before06
        private set
    private var node: CoreMember? = null

    /** How many nodes this process made, and what made the current one, for the tests' messages; guarded by lock. */
    private var nodeCount = 0
    private var nodeMadeBy = ""

    /** The last nodes that were stopped, with their diagnostics as they stopped, for the tests' messages; guarded by lock. */
    private val retiredNodes = ArrayDeque<String>()

    /** The current node's last log lines, for the tests' messages; guarded by itself. */
    private val nodeLog = ArrayDeque<String>()
    private var browser: NsdBrowser? = null
    private var found: Set<FoundMember> = emptySet()

    /**
     * Members' addresses that a debuggable build's instrumented tests hand
     * in (dialInTests), device ID to "host:port": the emulator's network
     * passes no mDNS, so NSD finds no member there; guarded by lock.
     */
    private var testMembers: Map<String, String> = emptyMap()

    /** The members handed to the node to dial, with the addresses handed; guarded by lock. */
    private var dialing: Map<String, List<String>> = emptyMap()

    /** The node's events, one after another, off its threads. */
    private val nodeEvents = Executors.newSingleThreadExecutor { r -> Thread(r, "node events").apply { isDaemon = true } }

    /** Asks the node for the group's records now and then, which peers send without an event. */
    private val recordsPoll = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "records").apply { isDaemon = true } }

    /** The node's files: its records, the clock's mark, the entry points and the copies with images or files. */
    private val nodeDir = File(file.parentFile, "node")

    /** When browsing first found each member, as System.nanoTime. */
    private var foundAt: Map<String, Long> = emptyMap()

    /** The hub's mDNS service while it runs on a home network. */
    private var publisher: NsdPublisher? = null

    /** What the user chose for the hub; the Live member runs away, the hub and the relay (AwayOn06). */
    private val away06 = AwayOn06(SealedFile(File(file.parentFile, "hub06.bin"), "cbb.hub")) { what, e -> Log.w(TAG, what, e) }

    /** Waits out the hub's grace in the background before it stops (updateHub06). */
    private val hubGrace = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "hub grace").apply { isDaemon = true } }

    /** The hub's work, one change at a time, off the main thread. */
    private val hubWork = Executors.newSingleThreadExecutor { r -> Thread(r, "phone hub").apply { isDaemon = true } }

    /** Whether the app is in front: the phone is the hub only then, unless the user lets it run in the background. */
    @Volatile private var foreground = false
    private var started = 0 // under lock: the app's started activities

    /**
     * This phone's sync mode (docs/design.md, "Sync modes"), in the file
     * mode beside the group's, as the computers keep it; own when there is
     * none.
     */
    private val modeFile = File(file.parentFile, "mode")

    /** This phone as a Bluetooth keyboard for a TV, a tablet or a computer near it. */
    val keyboard = BluetoothKeyboard(context, file.parentFile!!)

    /** This phone as a remote paste target: its switches, limits and log. */
    val pastes = PasteReceiver(context, file.parentFile!!, keyboard)

    /**
     * The sync mode: own, shared, receive or send; shared when there is
     * none, as a new device syncs. Sync turned off for a while (own with
     * a time in mute.json's "sync") reads as shared once that time passes.
     */
    val syncMode: String
        get() {
            val m = runCatching { modeFile.readText().trim() }.getOrNull()?.takeIf { it in Member.MODES } ?: "shared"
            if (m != "own") return m
            val until = synchronized(muteLock) { readMute("sync") }
            return if (until != null && until > 0 && until <= System.currentTimeMillis()) "shared" else m
        }

    /**
     * An admin's mute of this phone and until when its user turned sync
     * off, as Go's service keeps them in mute.json: until when in Unix
     * milliseconds, 0 for until it is lifted. Its own lock, as the node
     * reads the mute under its own.
     */
    private val muteFile = File(file.parentFile, "mute.json")
    private val muteLock = Any()

    private fun readMute(key: String): Long? = runCatching {
        (Json.parseToJsonElement(muteFile.readText()) as? JsonObject)?.get(key)?.jsonPrimitive?.longOrNull
    }.getOrNull()

    private fun writeMute(key: String, until: Long?) = synchronized(muteLock) {
        val old = runCatching { Json.parseToJsonElement(muteFile.readText()) as? JsonObject }.getOrNull() ?: JsonObject(emptyMap())
        val m = buildMap {
            putAll(old.filterKeys { it != key })
            until?.let { put(key, JsonPrimitive(it)) }
        }
        muteFile.parentFile?.mkdirs()
        val tmp = File(muteFile.parentFile, "mute.json.tmp")
        tmp.writeText(JsonObject(m).toString())
        if (!tmp.renameTo(muteFile)) throw IOException("cannot save the mute")
    }

    /** Until when an admin muted this phone, 0 for until an admin unmutes it; null while it is not muted. */
    val mutedUntilMS: Long? get() = synchronized(muteLock) { readMute("mute") }?.takeIf { Hold.of(it) != null }

    /** Until when this phone's sync is off, 0 for until its user turns it on; null while it syncs. */
    val syncOffUntilMS: Long?
        get() = if (syncMode != "own") null else (synchronized(muteLock) { readMute("sync") } ?: 0L)

    /** The node, read under the lock; its methods are called outside it. */
    private val currentNode: CoreMember? get() = synchronized(lock) { node }

    /** Asks for the fingerprint, the face or the screen lock before each signature of the root or admin key. */
    private val authenticator = Authenticator()

    /** The activity that shows the authentication prompt; null while the app is in the background. */
    @Volatile var activity: Context? = null

    val hasGroup: Boolean get() = synchronized(lock) { state != null }

    /** The group's tag; null without a group. */
    val groupTag: String? get() = synchronized(lock) { state?.tag }

    /**
     * The device tiles as the member keeps them, with the user's change op
     * applied first (docs/apps.md, "What the member shows"); null while no
     * member runs. A change that does not fit throws and changes nothing.
     */
    fun view(op: tools.cbb.kit.Arrangement.Op? = null): tools.cbb.kit.Arrangement.View? = synchronized(lock) { node }?.view(op)

    /**
     * Whether this phone may add and remove devices: it made the group, or
     * the phone that did made it an admin. A phone without a group makes
     * one when it adds a computer.
     */
    val isAdmin: Boolean get() = synchronized(lock) { state?.isAdmin ?: true }

    /** Whether this phone holds the group's root, which ends conflicts. */
    val isRoot: Boolean get() = synchronized(lock) { state?.isRoot ?: false }

    /** Every device of the group, this phone included. */
    val devices: List<Device>
        get() {
            // The node is asked outside the lock.
            val (g, n) = synchronized(lock) { (state ?: return emptyList()) to node }
            return devices06(g, n)
        }

    val computers: List<Device> get() = devices.filter { !it.isSelf }

    // The group of 0.6

    /**
     * The devices of a group of 0.6, as its member's state names them
     * (CoreMember.group), with what the connected ones' hellos say; it
     * notes whether the state names this phone an admin.
     */
    private fun devices06(g: PhoneGroup, n: CoreMember?): List<Device> {
        val gs = n?.let { runCatching { it.group() }.onFailure { e -> Log.w(TAG, "the member's group", e) }.getOrNull() } ?: return emptyList()
        g.admin = gs.me.admin
        val peers = runCatching { n.peers() }.getOrNull().orEmpty().associateBy { it.device }
        // The hub whose offer this phone keeps: in use while its tunnel
        // runs, or while the phone reaches it at home, as on the iPhone.
        // The members a connected computer reaches for this phone, as the
        // hub away from home does (docs/protocol.md, section 4, "Reach").
        val reached = peers.values.flatMap { it.reach }.toSet()
        val a = awayState06
        val away = a?.takeIf { !it.hub && it.hubDevice.isNotEmpty() }
        return gs.devices.map {
            val p = peers[it.device]
            val self = it.device == g.device
            Device(
                id = it.device, name = it.name, online = self || p != null || it.device in reached, role = if (it.role == "computer") "member" else it.role,
                os = it.os.ifEmpty { null }, isSelf = self, admin = it.admin, isRoot = it.device == gs.rootDevice,
                canMakeAdmin = gs.isRoot && !self && it.offersAdmin,
                keysInFile = p?.keyStore == KitRecords.FILE, frozen = it.frozen,
                device = if (self) ownDevice.cleaned else null, mode = if (self) syncMode else p?.mode?.ifEmpty { null },
                hub = when {
                    self && a?.hub == true -> HubMark.HUB
                    away?.hubDevice == it.device && (away.through || p != null) -> HubMark.IN_USE
                    it.hub || away?.hubDevice == it.device -> HubMark.HUB
                    else -> null
                },
                throughHub = !self && p == null && it.device in reached,
                muted = if (self) Hold.of(mutedUntilMS) else if (p?.muted == true) Hold(null) else null,
                syncOff = if (self) syncOffUntilMS?.let(Hold::of) else null,
            )
        }
    }

    /**
     * Makes a group of 0.6 on this phone (docs/apps.md, "Making a group"):
     * a new root key, the core writes this phone's record under it and keeps
     * the set where the member runs, and the member starts. Answers the
     * recovery sheet, which the app shows once and keeps nowhere.
     */
    suspend fun newGroup06(): Core.RecoverySheet {
        check(!hasGroup) { "this phone is in a group already" }
        if (activity == null) throw Failure(Failure.Kind.NO_SCREEN)
        Log.i(TAG, "making a group of 0.6")
        return withContext(Dispatchers.IO) {
            val root = newRootKey("", R.string.reason_add, Prompts(1))
            val member = memberSigner()
            nodeDir.mkdirs()
            val made = CorePairing.newGroup(
                nodeDir, PhoneGroup.validName(deviceName), "android", KitRecords.HARDWARE, root.publicKeyDER, member.publicKeyDER, root::signDigest,
            )
            adopt(PhoneGroup.of(made.device, made.group, root = true))
            Log.i(TAG, "made the group")
            Core.RecoverySheet(made.recoveryQR, made.recoveryText.flatMap { it.split(" ") }.joinToString("-"), ByteArray(0))
        }
    }

    /**
     * Opens this phone's home window on a group of 0.6 (docs/protocol.md,
     * "Pairing in 0.6"): the member port listens, the window is announced
     * by NSD, and shown gets the QR code and the six digits. A device that
     * dials proves the digits; nobody is asked. Returns the name of the
     * device that joined; the window closes when it does, when its time is
     * up, after three wrong codes, or when the caller is cancelled.
     */
    suspend fun openWindow(shown: (qr: String, digits: String) -> Unit): String {
        val g = synchronized(lock) { state } ?: throw Failure(Failure.Kind.NO_GROUP)
        if (!g.isAdmin) throw Failure(Failure.Kind.NO_GROUP)
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        val signer = caSigner(R.string.reason_add, prompts = Prompts(1))
        val (w, port) = withContext(Dispatchers.IO) {
            val port = listen(n, CoreMember.Listen.HOME) ?: throw Failure(Failure.Kind.UNREACHABLE)
            val hosts = LocalAddresses.current()
            if (hosts.isEmpty()) throw Failure(Failure.Kind.NO_NETWORK)
            CorePairing.Window(n, signer.publicKeyDER, hosts, sign = signer::signDigest) to port
        }
        Log.i(TAG, "the window is open on port $port")
        val announced = NsdPublisher(context, g.device, port, Discovery.windowTXT(g.tag, w.fingerprint, w.id))
        announced.start()
        try {
            shown(w.qr, w.digits)
            var version = 0L
            while (true) {
                val st = withContext(Dispatchers.IO) { w.next(version, 1000) }
                version = st.version
                when (st.state) {
                    "done" -> return st.name
                    "closed" -> throw st.failure ?: Failure(Failure.Kind.TIMED_OUT)
                    "failed" -> st.failure?.let { Log.w(TAG, "a device did not join through the window", it) }
                }
            }
        } finally {
            withContext(NonCancellable + Dispatchers.IO) {
                w.close()
                announced.stop()
            }
        }
    }

    /**
     * Joins a group of 0.6 by a home window's QR code, or by the six digits
     * the person typed (qr empty: the one window NSD finds): this phone
     * dials, proves the digits, and the member starts on the group it keeps.
     */
    suspend fun joinByWindow(qr: String, digits: String = "") {
        if (hasGroup) return
        val code = qr.ifEmpty { findHomeWindow(digits) }
        val j = withContext(Dispatchers.IO) {
            val member = memberSigner()
            nodeDir.mkdirs()
            CorePairing.Joiner(nodeDir.path, code, PhoneGroup.validName(deviceName), "android", member.publicKeyDER, member::signDigest)
        }
        follow(j, invite = false)
    }

    /** Follows a joiner to its end: on done the member starts on the group it keeps; by an invitation, a hub that never answered is HUB_UNREACHABLE. */
    private suspend fun follow(j: CorePairing.Joiner, invite: Boolean) {
        try {
            var version = 0L
            var answered = false
            while (true) {
                val st = withContext(Dispatchers.IO) { j.next(version, 1000) }
                version = st.version
                answered = answered || st.answered
                when (st.state) {
                    "done" -> {
                        withContext(Dispatchers.IO) {
                            synchronized(lock) {
                                newDeviceMode()
                                state = PhoneGroup.of(st.device, st.group, root = false).also { it.save(file) }
                            }
                            startSync()
                        }
                        return
                    }
                    "failed" -> throw if (invite && !answered) Failure(Failure.Kind.HUB_UNREACHABLE, st.failure) else st.failure ?: Failure(Failure.Kind.UNREACHABLE)
                }
            }
        } finally {
            withContext(NonCancellable + Dispatchers.IO) { j.close() }
        }
    }

    /**
     * Sync away from home as the Live member runs it: a hub, a client and
     * its hub, the link to the group's relay; null while the phone does not
     * sync or away was never on.
     */
    val awayState06: CoreMember.AwayState?
        get() = currentNode?.let { n -> runCatching { n.awayStatus() }.onFailure { Log.w(TAG, "reading where sync away from home stands", it) }.getOrNull() }

    /** The forwarder the group's root set for this phone as a hub; null while it set none. */
    val rootForwarder06: CoreMember.RootForwarder?
        get() = currentNode?.let { n -> runCatching { n.rootForwarder() }.onFailure { Log.w(TAG, "reading the root's forwarder", it) }.getOrNull() }

    /** What the user chose for the hub; null on a phone that is no admin, which cannot be a hub. */
    val hub06: AwayOn06.Prefs? get() = if (isAdmin) away06.hub else null

    /** Whether the member reaches device now, at home or by any way. */
    fun reaches(device: String): Boolean = currentNode?.let { n -> runCatching { n.peers() }.getOrNull() }.orEmpty().any { it.device == device }

    /** Whether the app is in front now, so the hub's status says it waits for it. */
    val inForeground: Boolean get() = foreground

    /**
     * Tells the group an activity of the app came to the front (on) or
     * stopped; the hub follows. It counts them: a finished activity may
     * stop after the next one started, and the app is in front while one is.
     */
    fun setForeground(on: Boolean) {
        foreground = synchronized(lock) {
            started = maxOf(0, started + if (on) 1 else -1)
            started > 0
        }
        refreshHub()
    }

    /** Makes this phone a hub of the group, or stops it being one. */
    fun setPhoneHub(on: Boolean) {
        if (!isAdmin) return
        away06.setOn(on, currentNetwork())
        if (!on) unhub06() else updateHub06(throwing = true)
    }

    /** Sets how the hub's tunnel hides, for the member of 0.6 to serve with; on the caller's IO thread. */
    fun setHubDisguise(d: HubOnPhone.Disguise) {
        if (!isAdmin) return
        away06.setDisguise(d)
        updateHub06(throwing = true)
    }

    /** Lets the hub run in the foreground service while the app is in the background. */
    fun setHubInBackground(on: Boolean) {
        if (isAdmin) away06.setBackground(on)
        refreshHub()
    }

    /**
     * Remembers the network the phone is on as a home network of the hub;
     * false when the phone is on no Wi-Fi or Ethernet network with an
     * address now, so there is none to remember.
     */
    fun addHomeNetwork(): Boolean {
        val n = currentNetwork() ?: return false
        if (isAdmin) away06.addHome(n)
        refreshHub()
        return true
    }

    /** Whether the phone is on one of the hub's home networks now. */
    val onHomeNetwork: Boolean get() = away06.isHome(currentNetwork())

    /**
     * The network the phone is on, as the hub remembers home networks
     * (HubOnPhone.networkKey): Wi-Fi or Ethernet with a gateway, never a
     * mobile network.
     */
    private fun currentNetwork(): String? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val net = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(net) ?: return null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return null
        val lp = cm.getLinkProperties(net) ?: return null
        val gw = lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway
            ?: lp.routes.firstOrNull { it.isDefaultRoute && it.hasGateway() }?.gateway
        val la = lp.linkAddresses.firstOrNull { it.address is Inet4Address } ?: lp.linkAddresses.firstOrNull() ?: return null
        return HubOnPhone.networkKey(gw, la.address, la.prefixLength)
    }

    private fun refreshHub() = hubWork.execute {
        runCatching { updateHub06(throwing = false) }
    }

    /**
     * Has the Live member serve as a hub while the user
     * turned it on and the app is in front, or in the background when the
     * user lets it; otherwise the hub stops, and its clients move to the
     * group's next hub. On a home network of the hub it publishes itself
     * there. A change the user made throws its failure, for the screen.
     */
    private fun updateHub06(throwing: Boolean) {
        val (n, g) = synchronized(lock) { (node ?: return) to (state ?: return) }
        val p = away06.hub
        if (!g.isAdmin || !p.on) {
            cancelUnhub06()
            unhub06()
            return
        }
        // The app went to the background on its own, with no leave to run
        // there: the hub stops only once it stayed there a while, so that
        // a short trip away hands no clients over; meanwhile the clients
        // wait out the gap as they do for any hub that goes quiet.
        if (!(foreground || p.background)) {
            synchronized(lock) {
                if (unhubLater == null) unhubLater = hubGrace.schedule({ hubWork.execute { unhubAfterGrace06() } }, HUB_GRACE_MS, TimeUnit.MILLISECONDS)
            }
            return
        }
        cancelUnhub06()
        try {
            away06.serve(n, homeAddrs(), runCatching { n.rootForwarder() }.getOrNull())
        } catch (e: Exception) {
            Log.w(TAG, "the hub did not start", e)
            if (throwing) throw e
            return
        }
        if (!away06.isHome(currentNetwork())) {
            stopHome()
            return
        }
        if (synchronized(lock) { publisher } != null) return
        val home = listen(n, CoreMember.Listen.HOME) ?: return
        val pub = NsdPublisher.hub(context, g.device, g.tag, home)
        synchronized(lock) { publisher = pub }
        pub.start()
    }

    /** The pending stop of the hub while the app is in the background; guarded by lock. */
    private var unhubLater: ScheduledFuture<*>? = null

    /** Stops the hub after its grace in the background, unless the app came back meanwhile. */
    private fun unhubAfterGrace06() {
        synchronized(lock) { unhubLater = null }
        val p = away06.hub
        if (p.on && (foreground || p.background)) return
        Log.i(TAG, "the app stayed in the background: the hub stops and hands its clients to the next hub")
        unhub06()
    }

    private fun cancelUnhub06() {
        synchronized(lock) { unhubLater.also { unhubLater = null } }?.cancel(false)
    }

    /** Stops the Live member serving as a hub, when it does. */
    private fun unhub06() {
        stopHome()
        val n = currentNode ?: return
        if (runCatching { n.awayStatus()?.hub }.getOrNull() == true) {
            runCatching { n.stopHub() }.onFailure { Log.w(TAG, "the hub did not stop", it) }
        }
    }

    /** The phone's addresses on the network it is on, "ip:port" on the hub's UDP port, for a hub at home only. */
    private fun homeAddrs(): List<String> {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val lp = cm.activeNetwork?.let { cm.getLinkProperties(it) } ?: return emptyList()
        return lp.linkAddresses.map { it.address }.filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }.map { "$it:${AwayOn06.HOME_PORT}" }
    }

    /**
     * Why the phone does not sync (docs/apps.md, "Why it does not sync"):
     * the member's reasons. Blocks.
     */
    fun why(): List<WhyReason> {
        val n = synchronized(lock) { node } ?: return listOf(WhyReason("not_in_group", "stop"))
        // The member runs the tunnel itself and says where it stands.
        return runCatching { n.why(null) }.getOrDefault(emptyList())
    }

    /**
     * Opens the node's member port for [what]: on the home network the
     * computers' port when it is free, on the loopback address any; null,
     * with the reason in the log, when the node cannot listen.
     */
    private fun listen(n: CoreMember, what: CoreMember.Listen): Int? {
        val first = if (what == CoreMember.Listen.HOME) MEMBER_PORT else 0
        return runCatching { n.listen(what, first) }.recoverCatching { n.listen(what, 0) }
            .onFailure { Log.w(TAG, "the phone cannot listen for members (${what.wire})", it) }.getOrNull()
    }

    /** Closes the node's member port for [what]. */
    private fun unlisten(what: CoreMember.Listen) {
        synchronized(lock) { node }?.let { runCatching { it.unlisten(what) } }
    }

    private fun stopHome() {
        val p = synchronized(lock) { publisher.also { publisher = null } }
        p?.stop()
        unlisten(CoreMember.Listen.HOME)
    }

    /** Turns sync away from home on or off in the member. */
    fun setAwayFromHome(on: Boolean) {
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        n.setAway(on)
    }

    init {
        startSync()
        // A new network may be a home network of the hub, or no longer be one.
        runCatching {
            context.getSystemService(ConnectivityManager::class.java)?.registerNetworkCallback(
                NetworkRequest.Builder().build(),
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) = refreshHub()
                    override fun onLost(network: Network) = refreshHub()
                },
            )
        }
    }

    /** This phone's name for the other devices: the one in the system's settings, else the model. */
    val deviceName: String
        get() = SystemSettings.Global.getString(context.contentResolver, SystemSettings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() }
            ?: Build.MODEL

    // Keys

    /** Makes this phone's own key, which proves it to the other devices, unless it has one. */
    fun prepare() {
        memberSigner()
    }

    private fun memberSigner(): KeystoreSigner = Keys.loadOrCreate(context, Keys.MEMBER)

    /** The alias of the key this phone signs with: the root key, or the admin key of a phone that joined. */
    private fun signingAlias(g: PhoneGroup?): String = if (g?.isRoot == false) Keys.ADMIN else Keys.ROOT

    /**
     * The signer of this phone's root or admin key for an action the user
     * asked for: each signature asks for the fingerprint, the face or the
     * screen lock with reason, and subtitle when given, so an action asks
     * once for each signature it makes. A phone that is no admin has no
     * such key.
     */
    private suspend fun caSigner(reason: Int, subtitle: String? = null, prompts: Prompts = Prompts()): KeystoreSigner {
        if (!isAdmin) throw Failure(Failure.Kind.NOT_ADMIN)
        return signer(signingAlias(synchronized(lock) { state }), reason, subtitle, prompts)
    }

    private suspend fun signer(alias: String, reason: Int, subtitle: String? = null, prompts: Prompts = Prompts()): KeystoreSigner {
        if (activity == null) throw Failure(Failure.Kind.NO_SCREEN)
        return withContext(Dispatchers.IO) { authorized(alias, reason, subtitle, prompts) }
    }

    /** The key under alias, made now when there is none, whose every signature asks with reason. */
    private fun authorized(alias: String, reason: Int, subtitle: String? = null, prompts: Prompts = Prompts()): KeystoreSigner =
        Keys.loadOrCreateAuthorized(context, alias, authorize = prompter(reason, subtitle, prompts))

    /** A new root key for the group tagged tag, replacing one left from before, whose every signature asks with reason. */
    private fun newRootKey(tag: String, reason: Int, prompts: Prompts = Prompts()): KeystoreSigner {
        Keys.create(context, Keys.ROOT, tag)
        return authorized(Keys.ROOT, reason, prompts = prompts)
    }

    /**
     * The prompts of one action, counted so that each says which it is
     * ("Signature 2 of 5"): total is how many signatures the action makes
     * (PhoneGroupTest's signaturesPerAction keeps the kit to them), null
     * when that is not fixed, and then the second and later say their
     * number alone.
     */
    private class Prompts(val total: Int? = null) {
        val made = AtomicInteger(0)
    }

    /** Asks the user, on the activity open now, for one signature. */
    private fun prompter(reason: Int, subtitle: String?, prompts: Prompts): (Signature?) -> Signature? = { s ->
        val ui = activity ?: throw Failure(Failure.Kind.NO_SCREEN)
        val n = prompts.made.incrementAndGet()
        val total = prompts.total
        // A timed key asks once for all of them (s null): no count then.
        val which = when {
            s == null -> null
            total != null && total > 1 && n <= total -> ui.getString(R.string.signature_of, n, total)
            n > 1 -> ui.getString(R.string.signature_n, n)
            else -> null
        }
        authenticator.authorize(ui, ui.getString(reason), listOfNotNull(subtitle, which).joinToString(" · ").ifEmpty { null }, s)
    }

    // Inviting from afar

    /** An open remote invitation: its text, as a file of one line holds it, when it expires, and how to cancel it. */
    class Invitation(val text: String, val expires: Instant, val cancel: () -> Unit)

    /**
     * Opens a remote invitation through a hub of the group
     * (docs/protocol.md, section 12, "Through the hub"): the core opens the
     * guest tunnel on a connected hub and runs the pairing window here, the
     * hub passing the pairing's bytes, for one device, for lifetimeS
     * seconds. ask asks the user whether to admit a device that proved it
     * knows the secret, showing its name and fingerprint; on yes the user
     * unlocks the group's key. ended gets the admitted device's name, or why
     * the invitation ended without one.
     */
    fun invite(lifetimeS: Int, ask: suspend (CorePairing.Inviting.Request) -> Boolean, ended: (Result<String>) -> Unit): Invitation {
        val g = synchronized(lock) { state }?.takeIf { it.isAdmin } ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        // Each signature asks the user, after they confirmed the device in ask.
        val ca = authorized(signingAlias(g), R.string.reason_add)
        val inviting = CorePairing.Inviting(n, ca.publicKeyDER, lifetimeS, sign = ca::signDigest)
        Thread({
            var version = 0L
            while (true) {
                val st = runCatching { inviting.next(version) }.getOrNull() ?: break
                if (st.version == version) continue
                version = st.version
                when (st.state) {
                    "joining" -> {
                        val r = st.request ?: continue
                        // The window waits for the user, up to the 5 minutes the device waits.
                        inviting.answer(runBlocking { ask(r) && activity != null })
                    }
                    "done" -> {
                        inviting.close()
                        ended(Result.success(st.name))
                        return@Thread
                    }
                    "failed" -> {
                        inviting.close()
                        ended(Result.failure(st.failure ?: CorePairing.Failure("the invitation ended")))
                        return@Thread
                    }
                }
            }
        }, "invitation").apply { isDaemon = true }.start()
        return Invitation(inviting.text, Instant.now().plusSeconds(inviting.expires.toLong())) { Thread { inviting.close() }.start() }
    }

    /**
     * Saves the group and makes it the group; starts syncing when this is
     * the first group, and passes the change to the parts that run with it.
     */
    private fun adopt(g: PhoneGroup) {
        synchronized(lock) {
            if (state == null) newDeviceMode()
            g.save(file)
            state = g
        }
        startSync()
    }

    // Joining

    /**
     * Joins a group of 0.6 from afar by a remote invitation's text
     * (docs/protocol.md, section 12): this phone dials the hub through the
     * invitation's guest tunnel and shows its fingerprint (shown) for the
     * inviting admin to compare; once admitted, the member starts on the
     * group it keeps and reaches the hub through that tunnel until the
     * hub's offer comes. A hub that never answered is HUB_UNREACHABLE.
     */
    suspend fun joinByInvite(text: String, shown: (String) -> Unit) {
        if (hasGroup) return
        val j = withContext(Dispatchers.IO) {
            val member = memberSigner()
            nodeDir.mkdirs()
            CorePairing.Joiner(nodeDir.path, "", PhoneGroup.validName(deviceName), "android", member.publicKeyDER, member::signDigest, invite = text)
        }
        shown(j.fingerprint)
        follow(j, invite = true)
    }

    /**
     * The QR code text of the one home window NSD finds (p=1 with its ID
     * and key hash), with the six digits the person typed from its screen.
     */
    private suspend fun findHomeWindow(digits: String): String {
        val windows = java.util.concurrent.atomic.AtomicReference<Set<FoundMember>>(emptySet())
        val b = NsdBrowser(context) { members -> windows.set(members.filter { it.pairing && it.windowID != null && it.fingerprint != null }.toSet()) }
        try {
            b.start()
            withTimeoutOrNull(BROWSE_MS) {
                while (windows.get().isEmpty()) delay(100)
            } ?: throw Failure(Failure.Kind.NO_WINDOW)
            delay(PAIRING_SETTLE_MS)
            val found = windows.get()
            if (found.size > 1) throw Failure(Failure.Kind.TWO_WINDOWS)
            val w = found.first()
            val a = b.address(w.device) ?: throw Failure(Failure.Kind.NO_WINDOW)
            val host = a.address.hostAddress?.substringBefore('%') ?: throw Failure(Failure.Kind.NO_WINDOW)
            val hostPort = if (host.contains(':')) "[$host]:${a.port}" else "$host:${a.port}"
            return Discovery.windowLink(hostPort, w.fingerprint!!, w.windowID!!, digits.filter { it.isDigit() })
        } finally {
            b.stop()
        }
    }

    // Removing

    /**
     * Removes a device from the group: a revocation signed with this
     * phone's root or admin key, sent to every connected computer, which
     * refuse the device from then on. The phone stops dialing it. Removing
     * the phone that holds the root hands the group to this one.
     */
    suspend fun remove(id: String) {
        act(R.string.reason_remove, "remove", "device" to JsonPrimitive(id))
    }

    /** Whether the group removed this phone: its records, once it has some, no longer list it. The app then offers to leave. */
    val removed: Boolean
        get() {
            val (g, n) = synchronized(lock) { (state ?: return false) to node }
            val gs = n?.let { runCatching { it.group() }.getOrNull() } ?: return false
            return gs.devices.isNotEmpty() && gs.devices.none { it.device == g.device }
        }

    /**
     * Takes this phone out of its group (D-83, docs/design.md, "Leaving the
     * group"): it stops syncing and deletes its keys, the group's files and
     * the tunnel's settings, and turns remote paste off, since it was
     * allowed to the admins of the group it leaves; the sync mode and the
     * other settings stay. The phone can then make a group or join one
     * again. The root leaves only when the group has no other devices than
     * itself and its watch: nobody could add or remove one after it. The
     * group keeps listing the phone until an admin removes it.
     */
    fun leave() {
        val g = synchronized(lock) { state }
        if (g == null && !before06) throw Failure(Failure.Kind.NO_GROUP)
        val others = devices.filter { !it.isSelf }.map { it.role }
        if (g?.isRoot == true && others.any { it != "watch" }) throw Failure(Failure.Kind.ROOT_LEAVES)
        hubWork.submit { stopHome() }.get()
        val (b, n) = synchronized(lock) {
            (browser to node).also {
                browser = null
                node = null
                dialing = emptyMap()
            }
        }
        b?.stop()
        n?.close()
        synchronized(lock) { state = null }
        file.delete()
        before06 = false
        // What a phone of a group from before 0.6 kept beside it goes too (D-126).
        File(file.parentFile, "credentials.json").delete()
        File(file.parentFile, "entries.json").delete()
        SealedFile(File(file.parentFile, "seal-secret"), "cbb.seal").delete()
        nodeDir.deleteRecursively()
        File(context.filesDir, "attest-status").deleteRecursively()
        pastes.turnOff()
        pastes.forgetLog()
        for (alias in listOf(Keys.ROOT, Keys.ADMIN, Keys.MEMBER)) runCatching { Keys.remove(alias) }
        runCatching { Keys.clearPeriodKeys() }
        Log.i(TAG, "this phone left its group: its keys and the group's files are deleted")
    }

    /**
     * Gives a device another name (docs/protocol.md, section 10): its
     * device record again with that name, signed with this phone's root or
     * admin key, which the member sends to every connected device.
     */
    suspend fun rename(id: String, name: String) {
        act(R.string.reason_rename, "rename", "device" to JsonPrimitive(id), "name" to JsonPrimitive(name))
    }

    /**
     * Unfreezes an admin computer that another admin froze
     * (docs/protocol.md, section 10, "Removals and freezes keep what the author saw"): a thaw record signed with this
     * phone's root or admin key.
     */
    suspend fun unfreeze(id: String) {
        act(R.string.reason_unfreeze, "thaw", "device" to JsonPrimitive(id))
    }

    /** Gives a phone that just made or joined a group the sync mode of a new device, shared (receive on a TV), unless it has one from an earlier group. */
    private fun newDeviceMode() {
        // A TV receives the group's copies and sends none of its own (docs/roadmap.md, item 25).
        if (!modeFile.exists()) setOwnMode(if (Tv.isTv(context)) "receive" else "shared")
    }

    /**
     * An action of this phone as an admin or the root (CoreMember.act):
     * the member writes the record or sends the command, signed with this
     * phone's root or admin key after the fingerprint, the face or the
     * screen lock with reason; the records judge whether the key may. A
     * command the device refused or could not carry out is CommandRefused.
     */
    private suspend fun act(reason: Int, action: String, vararg fields: Pair<String, JsonElement>, prompts: Prompts = Prompts()): JsonObject {
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        val ca = caSigner(reason, prompts = prompts)
        val a = withContext(Dispatchers.IO) { n.act(JsonObject(mapOf("action" to JsonPrimitive(action)) + fields), ca.publicKeyDER, ca::signDigest) }
        val status = (a["status"] as? JsonPrimitive)?.content
        if (status != null && status != "done") throw CommandRefused((a["reason"] as? JsonPrimitive)?.content?.ifEmpty { null } ?: status)
        return a
    }

    /** Sets this phone's own sync mode and keeps it; with tell, the hellos say it at once. */
    fun setOwnMode(mode: String, tell: Boolean = true) {
        require(mode in Member.MODES) { "unknown sync mode $mode" }
        // A phone making its first group sets its mode before the group's
        // file, which makes the folder, is written.
        modeFile.parentFile?.mkdirs()
        val tmp = File(modeFile.parentFile, "mode.tmp")
        tmp.writeText(mode + "\n")
        if (!tmp.renameTo(modeFile)) throw IOException("cannot save the sync mode")
        Log.i(TAG, "the sync mode is $mode now")
        // The hellos say it from the next connection, which the node makes at once.
        if (tell) currentNode?.let { n -> runCatching { n.setSync(mode != "own") } }
    }

    /**
     * Turns a connected computer's sync off (mode own) or on (any other
     * mode, shared on 0.6) (docs/protocol.md, section 15): a command signed
     * with this phone's root or admin key, which the computer answers.
     */
    suspend fun setMode(id: String, mode: String) {
        act(R.string.reason_set_mode, if (mode == "own") "sync_off" else "sync_on", "device" to JsonPrimitive(id))
    }

    /**
     * Turns this phone's sync on, or off for forMS milliseconds, 0 for
     * until its user turns it on again (docs/apps.md, the house). Off,
     * nothing goes out or comes in. Needs no rights.
     */
    fun setSync(on: Boolean, forMS: Long = 0) {
        val now = System.currentTimeMillis()
        writeMute("sync", if (on) null else if (forMS > 0) now + forMS else 0)
        setOwnMode(if (on) "shared" else "own", tell = false)
        currentNode?.let { n -> runCatching { n.setSync(on, if (on) 0 else forMS) }.onFailure { Log.w(TAG, "turning sync", it) } }
        onModeChanged?.invoke()
    }

    /**
     * Mutes a device for the whole group for forMS milliseconds, 0 for
     * until an admin unmutes it, or with on false ends its mute: a command
     * signed with this phone's root or admin key, passed on by a hub when
     * this phone is not connected to it. This phone's own mute changes at
     * once.
     */
    suspend fun setMuted(id: String, on: Boolean, forMS: Long = 0) {
        val g = synchronized(lock) { state } ?: return
        if (!g.isAdmin) throw Failure(Failure.Kind.NOT_ADMIN)
        if (id == g.device) {
            withContext(Dispatchers.IO) {
                writeMute("mute", if (!on) null else if (forMS > 0) System.currentTimeMillis() + forMS else 0)
                currentNode?.let { n -> runCatching { n.setMute(mutedUntilMS) } }
            }
            return
        }
        if (on) {
            act(R.string.reason_mute, "mute", "device" to JsonPrimitive(id), "for_ms" to JsonPrimitive(forMS))
        } else {
            act(R.string.reason_unmute, "unmute", "device" to JsonPrimitive(id))
        }
    }

    /**
     * Puts text where a computer's focus is (design.md, "Remote paste"): a
     * paste command signed with this phone's root or admin key, passed on
     * by a hub of the group connected to it when this phone is not; the computer
     * answers once the text is in, or why not.
     */
    suspend fun paste(id: String, text: String, method: String, enter: Boolean, secret: Boolean) {
        act(
            R.string.reason_paste, "paste", "device" to JsonPrimitive(id), "text" to JsonPrimitive(text), "method" to JsonPrimitive(method),
            "enter" to JsonPrimitive(enter), "kind" to JsonPrimitive(if (secret) "secret" else "text"),
        )
    }

    /**
     * Pastes an image or files where a computer's focus is (docs/protocol.md,
     * section 15): they go to the group as a copy, then a paste command of
     * kind media names that copy; the computer fetches it, puts it in its
     * clipboard and presses the paste keys.
     */
    suspend fun pasteShared(id: String, shared: Files.Shared, enter: Boolean) {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        notMuted()
        withContext(Dispatchers.IO) {
            when (shared) {
                is Files.Shared.Image -> n.copyMedia("", listOf(CoreMember.Part.data(shared.image.type, shared.image.bytes)))
                is Files.Shared.Many -> n.copyMedia("", shared.files.map { (path, bytes) -> CoreMember.Part.file(path, bytes) })
            }
        }
        // The paste names the group's copy, which is the one just made.
        act(R.string.reason_paste, "paste", "device" to JsonPrimitive(id), "kind" to JsonPrimitive("media"), "enter" to JsonPrimitive(enter))
    }

    /**
     * Runs a quick action on a computer (docs/protocol.md, section 15): an
     * action command, signed with this phone's root or admin key, names it;
     * the computer defines what it does and runs it only when its user
     * turned it on there.
     */
    suspend fun runAction(id: String, name: String) {
        act(R.string.reason_action, "action", "device" to JsonPrimitive(id), "name" to JsonPrimitive(name))
    }

    /** Turns every quick action off on a computer; only its user turns them on again. */
    suspend fun actionsOff(id: String) {
        act(R.string.reason_action, "actions_off", "device" to JsonPrimitive(id))
    }

    /**
     * Makes a phone or a computer an admin (docs/protocol.md, section 10,
     * "Admins"): the root key certifies the admin key the
     * device offers; the device gets its admin CA and every member the new
     * record. A computer whose keys sit in a file becomes one only with
     * allowFileKey, after the user read the warning; else
     * PhoneGroup.FileKey. A rootless install never (PhoneGroup.Rootless). A
     * phone keeps the store its record names.
     */
    suspend fun makeAdmin(id: String, allowFileKey: Boolean = false) {
        val n = synchronized(lock) { if (state?.isRoot == true) node else null } ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val peer = withContext(Dispatchers.IO) { runCatching { n.peers(all = true) }.getOrNull() }?.firstOrNull { it.device == id }
        val phone = peer?.role == "phone"
        val store = if (phone) null else peer?.keyStore?.ifEmpty { null }
        if (!phone && KitRecords.storeOf(store, "member") == KitRecords.ROOTLESS) throw PhoneGroup.Rootless()
        val inFile = !phone && KitRecords.storeOf(store, "member") == KitRecords.FILE
        if (inFile && !allowFileKey) throw PhoneGroup.FileKey()
        val prompts = Prompts()
        // The user's consent to a key in a file, after the dialog's
        // warning, lets the group take keys in files too.
        if (inFile && keyLevel != KitRecords.LEVEL_FILES) {
            act(R.string.reason_make_admin, "key_level", "level" to JsonPrimitive(KitRecords.LEVEL_FILES), prompts = prompts)
        }
        act(R.string.reason_make_admin, "make_admin", "device" to JsonPrimitive(id), "allow_file_key" to JsonPrimitive(allowFileKey), prompts = prompts)
    }

    /**
     * Adds the group's watch with its key (docs/protocol.md, section 10,
     * "Watches"): the root key, after the fingerprint, the face or the
     * screen lock, signs its device record with the role watch, which the
     * member sends to every member. On 0.6 the watch shows the group and
     * signs nothing (D-124). Returns what the watch keeps.
     */
    suspend fun addWatch(request: WatchState.KeyRequest): WatchState.Admission {
        if (!isRoot) throw PhoneGroup.Failure("only the root adds a watch")
        val a = act(
            R.string.reason_add_watch, "add_watch", "key" to JsonPrimitive(java.util.Base64.getEncoder().encodeToString(request.key)),
            "name" to JsonPrimitive(request.name), "os" to JsonPrimitive("wearos"),
        )
        val device = (a["device"] as? JsonPrimitive)?.content ?: request.device
        return WatchState.Admission(device, ByteArray(0), groupTag ?: "")
    }

    /** The group's key level (KitRecords.KEY_LEVELS) on the root phone; null elsewhere. */
    val keyLevel: String? get() = if (!isRoot) null else currentNode?.let { n -> runCatching { n.group().keyLevel }.getOrNull() }

    /** How long a copy and a secret live, in milliseconds, as the group's records set them (D-129). */
    val ttlMS: Pair<Long, Long>
        get() {
            val g = currentNode?.let { n -> runCatching { n.group() }.getOrNull() }
            return (g?.ttlMS ?: KitRecords.DEFAULT_TTL_MS) to (g?.secretTtlMS ?: KitRecords.DEFAULT_SECRET_TTL_MS)
        }

    /**
     * Sets how long a copy (ttlMS) or a secret (secretTtlMS) lives, the other
     * left as it is: a copies record, signed by the root or an admin after the
     * fingerprint, the face or the screen lock and sent to every member
     * (docs/protocol.md, section 10, "The copies setting").
     */
    suspend fun setTtl(ttlMS: Long?, secretTtlMS: Long?) {
        if (!isAdmin) throw Failure(Failure.Kind.NOT_ADMIN)
        val args = listOfNotNull(ttlMS?.let { "ttl_ms" to JsonPrimitive(it) }, secretTtlMS?.let { "secret_ttl_ms" to JsonPrimitive(it) })
        act(R.string.reason_ttl, "ttl", *args.toTypedArray())
    }

    /**
     * Sets the group's key level (docs/guide/keys.md, "The three levels"): a
     * settings record, signed with the root key after the fingerprint, the
     * face or the screen lock and sent to every member, which keeps the
     * takeover delay.
     */
    suspend fun setKeyLevel(level: String) {
        if (!isRoot) throw PhoneGroup.Failure("only the root sets the key level")
        // The core refuses it too; asked here first, the screen says why
        // before the fingerprint. A phone's keys are in its hardware.
        if (!KitRecords.levelAllows(level, KitRecords.HARDWARE, true)) throw PhoneGroup.BelowKeyLevel()
        val root = caSigner(R.string.reason_key_level)
        rootRecord(root) { m, public, sign -> m.setKeyLevel(level, public, sign) }
    }

    /**
     * Waits for a YubiKey plugged in or held to the phone, with nothing done
     * on it: true when it is on USB, false over NFC.
     */
    suspend fun findCard(): Boolean {
        val ui = activity as? android.app.Activity ?: throw Failure(Failure.Kind.NO_SCREEN)
        return YubiKeys.withCard(ui, {}) { card -> card is CardLink.Ccid }
    }

    /**
     * Seals the recovery key's secret, from sheet (the sheet's QR code or
     * its text), onto a YubiKey held to the phone or plugged in (NFC or
     * USB-C; docs/protocol.md, "The recovery key on a YubiKey (0.6)"): the
     * core speaks PIV, behind the card's PIN and a touch, and puts it in the
     * card's first empty retired slot, named for this group.
     */
    suspend fun sealOnCard(sheet: String, pin: String, plugged: () -> Unit = {}): RecoveryCard.Sealed {
        val ui = activity as? android.app.Activity ?: throw Failure(Failure.Kind.NO_SCREEN)
        val tag = groupTag ?: throw Failure(Failure.Kind.NO_GROUP)
        return YubiKeys.withCard(ui, plugged) { card -> RecoveryCard.seal(card, pin, sheet, tag) }
    }

    /**
     * Opens this group's recovery key secret on a YubiKey held to the phone,
     * after its PIN and a touch, for [changeRoot]; the caller drops it after
     * that.
     */
    suspend fun openCard(pin: String, plugged: () -> Unit = {}): ByteArray {
        val ui = activity as? android.app.Activity ?: throw Failure(Failure.Kind.NO_SCREEN)
        val tag = groupTag ?: throw Failure(Failure.Kind.NO_GROUP)
        return YubiKeys.withCard(ui, plugged) { card -> RecoveryCard.open(card, pin, tag) }
    }

    /**
     * On a group of 0.6, sets the group's relay (docs/design.md, "Blind
     * relay"), where every device meets the others while sync away from
     * home is on: the root writes it into the group's settings, signed with
     * the root key after the fingerprint, the face or the screen lock. Both
     * empty meet at no relay.
     */
    suspend fun setGroupRelay(address: String, pin: String) {
        if (!isRoot) throw PhoneGroup.Failure("only the root sets the group's relay")
        val relays = if (address.isBlank() && pin.isBlank()) {
            emptyList()
        } else {
            val ep = withContext(Dispatchers.IO) { HubState.resolve(address) } ?: throw IllegalArgumentException("not an address")
            listOf("$ep ${pin.trim()}")
        }
        val root = caSigner(R.string.reason_relay)
        rootRecord(root) { m, public, sign -> m.setRelays(relays, public, sign) }
    }

    /**
     * Has the core's member build and sign one of the root's own records
     * (cbb_member_manage) with root, which adds it and sends it to every
     * member, and takes it into the group's file.
     */
    private suspend fun <T> rootRecord(root: KeystoreSigner, act: (CoreMember, ByteArray, (ByteArray) -> ByteArray) -> T): T {
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        return withContext(Dispatchers.IO) { act(n, root.publicKeyDER, root::signDigest) }
    }

    /** What the group's watch may do to a device: nothing on 0.6, where a watch signs nothing from the wrist (D-124). */
    fun watchActions(@Suppress("UNUSED_PARAMETER") id: String): List<String> = emptyList()

    /** The body the watch signs: none on 0.6 (D-124). */
    fun watchBody(@Suppress("UNUSED_PARAMETER") ask: WatchState.Ask): ByteArray = throw PhoneGroup.Failure(NO_WRIST)

    /** Brings what the watch signed into the group: nothing on 0.6 (D-124). */
    suspend fun deliverFromWatch(@Suppress("UNUSED_PARAMETER") signed: WatchState.Signed): Unit = throw PhoneGroup.Failure(NO_WRIST)

    // The group in 0.6 (docs/apps.md, "Notices" and "Changing the main device").

    /** A change of the group's root the member told of: the devices' names, from and to. */
    data class RootChange(val from: String, val to: String, val seq: Long)

    /** The change of root the member told of last, until the person saw it. */
    @Volatile var rootChanged: RootChange? = null
        private set

    /** The member's notices about the group; empty while no member runs. */
    val notices: List<Notice> get() = currentNode?.let { n -> runCatching { n.notices() }.onFailure { Log.w(TAG, "reading the notices", it) }.getOrNull() }.orEmpty()

    /** Hides a notice that may be hidden. */
    fun dismissNotice(id: String) {
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        n.dismiss(id)
    }

    fun rootChangeSeen() {
        rootChanged = null
        currentNode?.let { n -> runCatching { n.rootChangeSeen() }.onFailure { Log.w(TAG, "noting that the change of root was seen", it) } }
    }

    /** A device's name as the group's devices show it, else its ID. */
    private fun nameOf(id: String): String = devices.firstOrNull { it.id == id }?.name ?: id

    /** The "who stays" list the core writes for a change of root with the recovery key, leaveOut unticked. */
    fun changePreview(recovery: RecoveryInput, leaveOut: List<String>): ChangePreview {
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        return n.changePreview(recovery, leaveOut)
    }

    /**
     * Moves the group's root to this phone (docs/design.md, "Changing the root"): a new root
     * key in the Keystore behind the fingerprint or the screen lock, and the member signs the
     * change with the recovery key and the new root's first records with that key; leaveOut
     * are removed in the same act.
     */
    suspend fun changeRoot(recovery: RecoveryInput, leaveOut: List<String>, overWaiting: Boolean) {
        val n = currentNode ?: throw Failure(Failure.Kind.UNREACHABLE)
        val g = synchronized(lock) { state } ?: throw Failure(Failure.Kind.UNREACHABLE)
        withContext(Dispatchers.IO) {
            val root = newRootKey(g.tag, R.string.reason_change_root)
            n.changeRoot(recovery, leaveOut, root.publicKeyDER, root::signDigest, overWaiting = overWaiting)
        }
    }

    // Syncing

    /** Starts finding and dialing the computers, once there is a group. */
    private fun startSync() {
        val b = startBrowsing() ?: return
        b.start()
        relay()
        refreshHub()
    }

    private fun startBrowsing(): NsdBrowser? = synchronized(lock) {
        val g = state ?: return null
        if (node != null) return null
        val member = runCatching { memberSigner() }.getOrNull() ?: return null
        // The Live member runs sync away from home, the hub and the relay
        // itself (AwayOn06).
        val number = nodeCount + 1
        nodeDir.mkdirs()
        synchronized(nodeLog) { nodeLog.clear() }
        val n = try {
            CoreMember.start(
                CoreMember.Start(nodeDir, deviceName, "android", Build.VERSION.RELEASE, ownDevice.version ?: "", g.device, member.publicKeyDER),
                member::signDigest,
                post = nodeEvents::execute,
            ) { e -> nodeEvent(e, g.device) }
        } catch (e: Exception) {
            Log.e(TAG, "the node did not start", e)
            return null
        }
        // Each step on its own, so that one refused leaves the others done.
        runCatching {
            n.setSync(syncMode != "own", syncOffUntilMS?.takeIf { it > 0 }?.let { it - System.currentTimeMillis() }?.coerceAtLeast(1) ?: 0)
            n.setMute(mutedUntilMS)
        }.onFailure { Log.w(TAG, "setting up the node", it) }
        // The attestation of the member key, which every peer gets (t 19 on 0.6), so the root records the keys as proven.
        runCatching { n.setEvidence(ownEvidence()) }.onFailure { Log.w(TAG, "handing the node the attestation", it) }
        val b = NsdBrowser(context) { members ->
            synchronized(lock) {
                found = members
                val now = System.nanoTime()
                foundAt = members.filter { it.group == g.tag }.associate { it.device to (foundAt[it.device] ?: now) }
            }
            relay()
        }
        node = n
        dialing = emptyMap()
        nodeCount = number
        // Where the call came from, a few frames up, for a node made when the tests did not expect it.
        nodeMadeBy = Throwable().stackTrace.drop(1).take(6).joinToString(" < ") { "${it.methodName}:${it.lineNumber}" }
        Log.i(TAG, "node #$nodeCount started by $nodeMadeBy")
        browser = b
        // The member serves as the hub again if the user left it on.
        refreshHub()
        // Push: the member sends the group's registration to every member it connects to.
        PushSetup.sink = { f -> currentNode?.setPush(f) }
        runCatching { n.setPush(PushSetup.frame(context)) }.onFailure { Log.w(TAG, "handing the member the push registration", it) }
        val current = n
        recordsPoll.schedule(object : Runnable {
            override fun run() {
                if (currentNode !== current) return
                takeRenewals(current)
                recordsPoll.schedule(this, RECORDS_POLL_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
        }, RECORDS_POLL_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        b
    }

    /** Handles an event of the node, on the events' thread. */
    private fun nodeEvent(e: CoreMember.Event, me: String) {
        val n = currentNode ?: return
        when (e) {
            is CoreMember.Event.Log -> {
                Log.i(TAG, "node #$nodeCount: ${e.line}")
                synchronized(nodeLog) {
                    nodeLog.addLast(e.line)
                    if (nodeLog.size > NODE_LOG_LINES) nodeLog.removeFirst()
                }
            }
            // The phone writes the copies itself, by its own sync mode and pause (CopyChanged).
            is CoreMember.Event.Write -> {}
            is CoreMember.Event.CopyChanged -> copyArrived(n, e.copy, me)
            // The node carried out an admin's mute or unmute; the phone shows it.
            is CoreMember.Event.Mute -> {
                writeMute("mute", if (!e.muted) null else if (e.forMS > 0) System.currentTimeMillis() + e.forMS else 0)
                Log.i(TAG, "${e.by} ${if (e.muted) "muted" else "unmuted"} this phone")
            }
            // The member of 0.6 carried out an admin's sync mode and keeps it; the phone shows it.
            is CoreMember.Event.Sync -> {
                runCatching { setOwnMode(if (e.off) "own" else "shared", tell = false) }.onFailure { Log.e(TAG, "cannot save the sync mode", it) }
                Log.i(TAG, "${e.by} turned sync ${if (e.off) "off" else "on"} on this phone")
                onModeChanged?.invoke()
            }
            // A member that broke stops and starts again, off its own events' thread.
            is CoreMember.Event.Panic -> {
                Log.e(TAG, "the node broke, starting it again: ${e.details}")
                val lines = synchronized(nodeLog) { nodeLog.toList() }
                onPanic?.invoke(e.details, lines)
                Thread({ restartSync() }, "restart").start()
            }
            is CoreMember.Event.State -> {
                Log.i(TAG, "the group's state changed: stop ${e.state.stop}, ${e.state.devices.size} devices")
                onRecords?.invoke()
            }
            is CoreMember.Event.NoticeAdded -> {
                Log.i(TAG, "a notice about the group: ${e.notice.kind}")
                onRecords?.invoke()
            }
            // Every device shows it until the person saw it, and nobody turns it off.
            is CoreMember.Event.RootChanged -> {
                Log.w(TAG, "the group's root changed from ${e.from} to ${e.to} (step ${e.seq})")
                rootChanged = RootChange(nameOf(e.from), nameOf(e.to), e.seq)
                onRecords?.invoke()
            }
            is CoreMember.Event.KeyDone -> Log.i(TAG, "the node no longer needs a key")
        }
    }

    /**
     * A copy from another device (docs/design.md, "Sync model", D-128):
     * Home shows it as the last received, and while the app is on the
     * screen the phone listens like a computer and writes it to the
     * clipboard, whatever its age. In the background or closed the phone
     * writes nothing. Only in a sync mode that takes the group's copies,
     * and only while its sync is on.
     */
    private fun copyArrived(n: CoreMember, c: CoreMember.Copy, me: String) {
        if (c.unread || c.origin == me || c.isFiles) return
        val image = Images.part(c.media)
        if (image == null && (c.text.isEmpty() || c.kind == Member.Kind.MEDIA)) return
        val ttl = c.ttlMS ?: if (c.kind == Member.Kind.SECRET) KitRecords.DEFAULT_SECRET_TTL_MS else KitRecords.DEFAULT_TTL_MS
        lastReceived = Received(c.id, nameOf(c.origin), if (c.kind == Member.Kind.SECRET) "" else c.text, c.kind, image != null, System.currentTimeMillis() + ttl)
        onReceived?.invoke()
        if (!foreground || !Member.receives(syncMode)) return
        if (image != null) {
            // Fetched off the events' thread, which the next events wait for.
            onImage?.let { f ->
                Thread({
                    fetchImage(n, c, image)?.let {
                        f(it, c.text)
                        runCatching { n.took(c.id) }
                        image.sha256?.let { h -> seen(Images.key(h)) }
                    }
                }, "image").start()
            }
        } else {
            onCopy?.invoke(c.text, c.kind, c.ttlMS)
            runCatching { n.took(c.id) }
            seen(c.text)
        }
    }

    /**
     * The last copy that came from another device, for Home's line (D-128);
     * text is empty for a secret, which Home does not show. The line goes at
     * untilMS, when the copy's own lifetime ends (D-129).
     */
    data class Received(val id: String, val from: String, val text: String, val kind: Member.Kind, val image: Boolean, val untilMS: Long)

    @Volatile var lastReceived: Received? = null
        private set

    /** Hides the last received line, as its Copy did or a newer copy will replace it. */
    fun dismissReceived() {
        lastReceived = null
        onReceived?.invoke()
    }

    /**
     * Copy on the last received line: the group's copy goes into the
     * phone's clipboard (an image fetched first). Null when the group holds
     * a newer copy now, which its own line shows. On the caller's IO thread.
     */
    fun copyReceived(id: String): Got? {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        val c = n.current()?.takeIf { it.id == id } ?: return null
        return take(n, c)
    }

    /** Keeps a stopped node's last log lines, for the tests' messages. */
    private fun retire() {
        val d = synchronized(nodeLog) { nodeLog.takeLast(4).joinToString(" | ") }
        synchronized(lock) {
            retiredNodes.addLast("node #$nodeCount, stopped: $d")
            if (retiredNodes.size > 2) retiredNodes.removeFirst()
        }
    }

    /** The number of the current node, so that a test can tell a node made while it ran. */
    internal val nodeNumber: Int get() = synchronized(lock) { nodeCount }

    /**
     * The current node's peers and last log lines and the last stopped
     * nodes', for a failing test's message.
     */
    internal val nodeDiagnostics: String
        get() {
            val (n, made, retired) = synchronized(lock) { Triple(node, "node #$nodeCount, made by $nodeMadeBy", retiredNodes.toList()) }
            val now = n?.let {
                val peers = runCatching { it.peers(all = true) }.getOrDefault(emptyList()).joinToString { p -> "${p.device.take(8)} ${p.role}" }
                "$made: peers [$peers], dialing ${synchronized(lock) { dialing.keys.map { k -> k.take(8) } }}; log: ${synchronized(nodeLog) { nodeLog.takeLast(TRACE_LINES).joinToString(" | ") }}"
            } ?: "no node; the last was $made"
            return now + retired.joinToString("") { "\nearlier $it" }
        }

    /** Connects again, as after the user allowed the local network. */
    fun reconnect() = restartSync()

    /** Stops syncing and starts again, with a new certificate or new roots. */
    private fun restartSync() {
        Log.i(TAG, "connecting to the group again")
        val (b, n) = synchronized(lock) {
            (browser to node).also {
                browser = null
                node = null
                dialing = emptyMap()
            }
        }
        b?.stop()
        if (n != null) {
            n.close()
            retire()
        }
        startSync()
    }

    /**
     * Hands the node the members of the group the browser finds, never this
     * phone itself: as a hub it announces itself, and its browser finds
     * that announcement too. The member checks each against the group's
     * records when it connects.
     */
    private fun relay() {
        val (n, want, before) = synchronized(lock) {
            val g = state ?: return
            val n = node ?: return
            val b = browser
            val want = found.filter { (it.group == null || it.group == g.tag) && it.device != g.device && !it.pairing }.associate { m ->
                m.device to listOfNotNull(b?.address(m.device)?.let { hostPort(it.hostString, it.port) })
            }.filterValues { it.isNotEmpty() } + testMembers.filterKeys { it != g.device }.mapValues { listOf(it.value) }
            Triple(n, want, dialing).also { dialing = want }
        }
        for ((d, addrs) in want) if (before[d] != addrs) runCatching { n.found(d, addrs, d) }.onFailure { Log.w(TAG, "dialing $d", it) }
        for (d in before.keys - want.keys) runCatching { n.lost(d) }
    }

    /**
     * Has the node dial device at address ("host:port") as if NSD had
     * found it: for the instrumented tests on an emulator, whose network
     * passes no mDNS. Only a debuggable build takes it.
     */
    fun dialInTests(device: String, address: String) {
        check(context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) { "only a debuggable build dials a member the tests name" }
        synchronized(lock) { testMembers = testMembers + (device to address) }
        relay()
    }

    /** The group's face toward the push service, from the member; null until the entry points name the service. */
    val pushFace: ByteArray?
        get() = currentNode?.let { n -> runCatching { n.pushFace() }.onFailure { Log.w(TAG, "reading the push face", it) }.getOrNull() }

    /** The group's face toward the push service and each `push-renew` members sent: the group registers with the face, and again for each renewal. */
    private fun takeRenewals(n: CoreMember) {
        runCatching { n.pushFace() }.getOrNull()?.let { PushSetup.face(context, it) }
        val renewals = runCatching { n.pushRenewals() }.onFailure { Log.w(TAG, "reading the push renewals", it) }.getOrNull() ?: return
        for ((slot, ahead) in renewals) PushSetup.renew(context, slot, ahead)
    }

    /** The attestation of this phone's member key, which every peer gets (docs/protocol.md, section 17, "Evidence"); none for a key made without one. */
    private val memberEvidence: List<Member.Evidence> by lazy {
        Keys.evidence(context, Keys.MEMBER)?.let {
            listOf(Member.Evidence(Member.Evidence.ANDROID, Member.Evidence.MEMBER, it.groupTag.ifEmpty { null }, it.salt, it.chain))
        } ?: emptyList()
    }

    private fun ownEvidence(): List<Member.Evidence> = runCatching { memberEvidence }.getOrDefault(emptyList())

    /**
     * Signs, with the root key, what came due while it could not ask the
     * user: the next period of the group's server credentials (renewPeriod).
     */
    suspend fun signDue() {
        if (activity == null) return
        renewPeriod()
    }

    /**
     * On the root phone, renews the group's server
     * credentials with the root key when they are due, asking first: only
     * when the app opens, and with the next root action (the member renews
     * them with its key then), never at another moment.
     */
    private suspend fun renewPeriod() {
        val n = currentNode ?: return
        if (!isRoot || !withContext(Dispatchers.IO) { runCatching { n.periods().first }.getOrDefault(false) }) return
        try {
            val root = signer(Keys.ROOT, R.string.reason_period)
            withContext(Dispatchers.IO) { n.renewPeriod(root.publicKeyDER, root::signDigest) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "renewing the group's server credentials; the next start asks again", e)
        }
    }

    /** On the root phone of a group of 0.6, whether the group's server credentials expired; false elsewhere. */
    val periodOverdue06: Boolean
        get() = currentNode?.let { n -> runCatching { n.periods().second }.getOrNull() } ?: false

    /**
     * The one button and the app's opening, by the node's rule (docs/design.md,
     * "The one button", D-128). The button swaps: what the phone's clipboard
     * holds goes to the group and the group's copy comes into the clipboard;
     * an empty clipboard, or one holding the group's copy, only takes.
     * Opening (opening = true) swaps nothing: a clipboard changed since the
     * app last saw it goes out, otherwise the phone takes the group's copy.
     * board reads the clipboard. Returns what happened and what to put in
     * the clipboard; the phone sends before it takes, so nothing it held is
     * lost.
     */
    fun sync(opening: Boolean = false, board: () -> Clipboard.Board?): Pair<SyncResult, Got?> {
        val n = synchronized(lock) { node ?: throw Failure(Failure.Kind.NO_COMPUTERS) }
        val b = board()
        val key = b?.key.orEmpty()
        val changed = key.isNotEmpty() && boardSeen != seenOf(key)
        seen(key)
        // The button works in every mode; only what the phone takes by itself follows it.
        val s = if (opening) n.opened(key, changed) else n.swap(key)
        Log.i(TAG, "${if (opening) "opening" else "the button"}: sends ${s.sends}, takes ${s.copy?.id?.take(12)}")
        if (s.sends && b != null) {
            if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
            notMuted()
            when (b) {
                is Clipboard.Board.Text -> n.copy(b.text, board = true)
                is Clipboard.Board.Image -> sendImage(n, b.image, board = true)
            }
        }
        val w = s.copy
        if (w == null) {
            if (s.sends) return SyncResult.SENT to null
            if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
            return SyncResult.NOTHING_NEW to null
        }
        val got = take(n, w)
        return (if (s.sends) SyncResult.SWAPPED else SyncResult.FETCHED) to got
    }

    /** Takes the group's copy w for the phone: its text, its image fetched, or its files saved; the app's own write is no copy. */
    private fun take(n: CoreMember, w: CoreMember.Copy): Got {
        val files = w.media?.takeIf { it.isFiles }
        if (files != null) {
            if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
            val saved = Files.save(context, n, w, files)
            n.took(w.id)
            return Got.Files(saved.count, saved.gallery)
        }
        val image = Images.part(w.media)
        if (image == null) {
            n.took(w.id)
            seen(w.text)
            return Got.Text(w.text, if (w.kind == Member.Kind.MEDIA) Member.Kind.TEXT else w.kind, w.ttlMS)
        }
        if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
        val f = fetchImage(n, w, image, quiet = false) ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        n.took(w.id)
        image.sha256?.let { seen(Images.key(it)) }
        // The image the button fetched goes to the gallery's album too, as the Aurora app keeps it.
        val type = image.type ?: "image/png"
        runCatching { Files.toGallery(context, f, "CBB ${w.id.take(12)}.${f.extension}", type) }
            .onFailure { Log.w(TAG, "putting the image in the gallery", it) }
        return Got.Image(f, w.text)
    }

    /**
     * The clipboard as the app last saw it, as a hash (D-128): Android has
     * no change count, so opening compares the clipboard with it to tell a
     * copy made since. It keeps across starts, so a copy made while the app
     * was closed goes out as it opens.
     */
    private val boardSeen: String? get() = seenPrefs.getString(SEEN, null)

    private val seenPrefs by lazy { context.getSharedPreferences("board", Context.MODE_PRIVATE) }

    private fun seenOf(key: String): String = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray()).joinToString("") { "%02x".format(it) }

    /** Notes that the clipboard holds key, as the app read it or wrote it itself. */
    private fun seen(key: String) {
        if (key.isNotEmpty()) seenPrefs.edit().putString(SEEN, seenOf(key)).apply()
    }

    /** Throws [Muted] while an admin mutes this phone: its copies stay on it. */
    private fun notMuted() {
        val until = mutedUntilMS
        if (until != null && (until == 0L || until > System.currentTimeMillis())) throw Muted()
    }

    /**
     * Whether a computer is connected, waiting up to CONNECT_WAIT_MS for
     * one: a connection the system dropped takes a moment to come back. On
     * the caller's IO thread.
     */
    private fun connected(n: CoreMember): Boolean {
        val deadline = System.currentTimeMillis() + CONNECT_WAIT_MS
        while (runCatching { n.peers() }.getOrDefault(emptyList()).isEmpty()) {
            if (System.currentTimeMillis() >= deadline) return false
            Thread.sleep(250)
        }
        return true
    }

    /** The current copy as this phone holds it and the node's last lines, for the tests' messages. */
    internal val copyState: String
        get() {
            val n = currentNode ?: return "no node"
            val e = runCatching { n.current() }.getOrNull()
            val what = e?.let { "${it.id} from ${it.origin}, ${it.kind}, unread ${it.unread}, media ${it.media?.let { m -> "${m.parts.size} parts, files ${m.isFiles}" }}" }
            return "current copy: $what; the node's last lines: ${synchronized(nodeLog) { nodeLog.takeLast(8).joinToString(" | ") }}"
        }

    /** Whether a computer is connected now. */
    val online: Boolean get() = currentNode?.let { runCatching { it.peers() }.getOrNull() }?.isNotEmpty() == true

    /**
     * The group's latest copy, as the node holds it; null before any. For
     * the tests.
     */
    internal val latestCopy: CoreMember.Copy?
        get() = currentNode?.let { runCatching { it.current() }.getOrNull() }

    /** What the button fetched for the phone's clipboard: a text, or an image in the app's cache with its text. */
    sealed class Got {
        /** ttlMS: the lifetime its sender stamped (D-129), after which a secret leaves the clipboard. */
        data class Text(val text: String, val kind: Member.Kind, val ttlMS: Long? = null) : Got()

        data class Image(val file: File, val alt: String) : Got()

        /** Files saved in Downloads/CBB, or one image or video in the gallery's album "CBB" (gallery). */
        data class Files(val count: Int, val gallery: Boolean = false) : Got()
    }

    /** Sends what the user shared with the app: an image, or files, which the computers fetch from this phone. */
    fun sendShared(shared: Files.Shared): SyncResult {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
        notMuted()
        when (shared) {
            is Files.Shared.Image -> sendImage(n, shared.image, board = false)
            is Files.Shared.Many -> n.copyMedia("", shared.files.map { (path, bytes) -> CoreMember.Part.file(path, bytes) })
        }
        return SyncResult.SENT
    }

    /** Sends an image the phone copied, or one shared with it: the computers fetch it from this phone. */
    private fun sendImage(n: CoreMember, image: Images.Copied, board: Boolean) {
        n.copyMedia("", listOf(CoreMember.Part.data(image.type, image.bytes)), board)
    }

    /**
     * Fetches a received image into the app's cache; null, with the reason
     * in the log, when it cannot, or the error when not quiet.
     */
    private fun fetchImage(n: CoreMember, c: CoreMember.Copy, part: Media.Part, quiet: Boolean = true): File? =
        try {
            Images.fetch(context, n, c, part)
        } catch (x: Exception) {
            Log.w(TAG, "fetching an image", x)
            if (quiet) null else throw x
        }

    /** Sends a text the phone's clipboard holds, unless it is the group's current text already. */
    fun send(text: String): SyncResult {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        if (runCatching { n.peers() }.getOrDefault(emptyList()).isEmpty()) throw Failure(Failure.Kind.NO_COMPUTERS)
        val cur = n.current()
        if (cur != null && !cur.unread && cur.kind != Member.Kind.MEDIA && cur.text == text) return SyncResult.NOTHING_NEW
        notMuted()
        n.copy(text, board = true)
        return SyncResult.SENT
    }

    /**
     * Gets each text a computer copied, as it arrives, to put on the
     * phone's clipboard; on the node's thread.
     */
    @Volatile var onCopy: ((String, Member.Kind, Long?) -> Unit)? = null

    /** Called on the events' thread when the last received copy changes. */
    @Volatile var onReceived: (() -> Unit)? = null

    /** Gets each image a computer copied, fetched into the app's cache, with its text; on a thread of its own. */
    @Volatile var onImage: ((File, String) -> Unit)? = null

    /** Called when an admin changed this phone's sync mode, on the node's thread. */
    @Volatile var onModeChanged: (() -> Unit)? = null

    /** Called on the node's thread when records arrived that change the group, for the notifications. */
    @Volatile var onRecords: (() -> Unit)? = null

    /** Something in the node broke (a `panic` event): what broke and CBB's log lines, oldest first, for the bug report; the node starts again by itself. */
    @Volatile var onPanic: ((details: String, log: List<String>) -> Unit)? = null

    /** This phone's secret for sealed messages (docs/protocol.md, section 15), 32 random bytes under a Keystore key. */
    companion object {
        private const val TAG = "cbb"

        /** The preference that keeps the clipboard's hash as the app last saw it. */
        private const val SEEN = "seen"

        /** How often the phone reads the push face and renewals the member keeps. */
        private const val RECORDS_POLL_MS = 15_000L

        /** How many of the node's log lines the tests' messages keep. */
        private const val NODE_LOG_LINES = 200
        private const val TRACE_LINES = 60

        /** How long joining browses for a home window, and then for a second one. */
        const val BROWSE_MS = 10_000L
        const val PAIRING_SETTLE_MS = 2_000L

        /** How long the button waits for a computer to connect before it says none is. */
        const val CONNECT_WAIT_MS = 5_000L

        /** The member port the hub takes members on at home, as the computers'; another when it is taken. */
        const val MEMBER_PORT = 8764

        /** How long the hub of 0.6 keeps serving after the app went to the background without leave to run there. */
        const val HUB_GRACE_MS = 60_000L

        fun defaultFile(context: Context) = File(context.filesDir, "cbb/group.json")

        /**
         * Whether the root phone adds a Wear OS watch: not on 0.6, whose
         * watch app does not run on the records of 0.6 yet (D-124).
         */
        const val WEAR_JOINS = false

        /** Why a watch does nothing to a device on 0.6. */
        const val NO_WRIST = "on 0.6 a watch shows the group and signs nothing from the wrist"

        /** host:port, with an IPv6 host in brackets. */
        fun hostPort(host: String, port: Int): String {
            val h = host.substringBefore('%')
            return if (h.contains(':')) "[$h]:$port" else "$h:$port"
        }


        /**
         * Runs block on Dispatchers.IO and calls close when the caller is
         * cancelled or times out, which ends the blocking read in block.
         */
        suspend fun <T> closingOnCancel(close: () -> Unit, block: () -> T): T = coroutineScope {
            val done = AtomicBoolean(false)
            val watch = launch {
                try {
                    awaitCancellation()
                } finally {
                    if (!done.get()) close()
                }
            }
            try {
                withContext(Dispatchers.IO) { block() }
            } finally {
                done.set(true)
                watch.cancel()
            }
        }
    }
}
