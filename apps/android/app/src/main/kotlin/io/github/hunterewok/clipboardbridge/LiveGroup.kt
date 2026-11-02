// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.provider.Settings as SystemSettings
import android.util.Log
import io.github.hunterewok.clipboardbridge.kit.alerts
import io.github.hunterewok.clipboardbridge.kit.GroupAlert
import io.github.hunterewok.clipboardbridge.kit.AndroidAttestation
import io.github.hunterewok.clipboardbridge.kit.CertificateInfo
import io.github.hunterewok.clipboardbridge.kit.CredentialKeeper
import io.github.hunterewok.clipboardbridge.kit.Core
import io.github.hunterewok.clipboardbridge.kit.CredentialRefresh
import io.github.hunterewok.clipboardbridge.kit.CredentialStore
import io.github.hunterewok.clipboardbridge.kit.Commands
import io.github.hunterewok.clipboardbridge.kit.Content
import io.github.hunterewok.clipboardbridge.kit.Discovery
import io.github.hunterewok.clipboardbridge.kit.FoundMember
import io.github.hunterewok.clipboardbridge.kit.GroupCertificates
import io.github.hunterewok.clipboardbridge.kit.HybridClock
import io.github.hunterewok.clipboardbridge.kit.InvitationWindow
import io.github.hunterewok.clipboardbridge.kit.JoinCode
import io.github.hunterewok.clipboardbridge.kit.LocalAddresses
import io.github.hunterewok.clipboardbridge.kit.Media
import io.github.hunterewok.clipboardbridge.kit.Member
import io.github.hunterewok.clipboardbridge.kit.MemberDialer
import io.github.hunterewok.clipboardbridge.kit.MemberListener
import io.github.hunterewok.clipboardbridge.kit.MemberNode
import io.github.hunterewok.clipboardbridge.kit.MemoryContent
import io.github.hunterewok.clipboardbridge.kit.Pairing
import io.github.hunterewok.clipboardbridge.kit.PairingJoiner
import io.github.hunterewok.clipboardbridge.kit.PairingMember
import io.github.hunterewok.clipboardbridge.kit.PeriodKeys
import io.github.hunterewok.clipboardbridge.kit.PhoneGroup
import io.github.hunterewok.clipboardbridge.kit.PhoneHub
import io.github.hunterewok.clipboardbridge.kit.RecordStore
import io.github.hunterewok.clipboardbridge.kit.Records as KitRecords
import io.github.hunterewok.clipboardbridge.kit.ServerCredentials
import io.github.hunterewok.clipboardbridge.kit.SyncEngine
import io.github.hunterewok.clipboardbridge.kit.TLSListener
import io.github.hunterewok.clipboardbridge.kit.TLSTransport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
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
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import java.io.File
import java.io.IOException
import java.net.Inet4Address
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
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

    class Failure(val kind: Kind) : Exception(kind.name) {
        enum class Kind { UNREACHABLE, NOT_CONFIRMED, NO_NETWORK, TIMED_OUT, TOO_MANY_WRONG_CODES, NOT_ADMIN, NO_COMPUTERS, NO_SCREEN }
    }

    /** A device of the group, as the screens show it: a computer, or this phone. */
    data class Device(
        val id: String,
        val name: String,
        val online: Boolean,
        val role: String = "full",
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
    )

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

    enum class SyncResult { SENT, FETCHED, NOTHING_NEW }

    private val lock = Any()
    private var state: PhoneGroup? = runCatching { PhoneGroup.load(file) }.getOrNull()
    private var node: MemberNode? = null
    private var browser: NsdBrowser? = null
    private var dialer: MemberDialer? = null
    private var found: Set<FoundMember> = emptySet()

    /** When browsing first found each member, as System.nanoTime. */
    private var foundAt: Map<String, Long> = emptyMap()
    private var away: AwayFromHome? = null
    private val awayFile = AwayFile(File(file.parentFile, "away.bin"))

    /** The phone as the group's hub: its state, and while it runs its two member listeners and its mDNS service. */
    private var hub: HubOnPhone? = null
    private val hubFile = SealedFile(File(file.parentFile, "hub.bin"), "clipboardbridge.hub")
    private var tunnelListener: MemberListener? = null
    private var homeListener: MemberListener? = null
    private var publisher: NsdPublisher? = null

    /** The phone at a blind relay, and while it runs its member listener on the loopback address, which serves the relay's calls. */
    private var relayLink: RelayOnPhone? = null
    private val relayFile = SealedFile(File(file.parentFile, "relay.bin"), "clipboardbridge.relay")
    private var relayListener: MemberListener? = null

    /** The group's server credentials (docs/protocol.md, section 18), beside the group; read when first needed, under the lock. */
    private val credentialsFile = File(file.parentFile, "credentials.json")
    private var credentialStore: CredentialStore? = null

    /** Brings the credentials up to date, one refresh at a time, off the node's threads. */
    private val credentialWork = Executors.newSingleThreadExecutor { r -> Thread(r, "credentials").apply { isDaemon = true } }

    /** The hub's work, one change at a time, off the main thread. */
    private val hubWork = Executors.newSingleThreadExecutor { r -> Thread(r, "phone hub").apply { isDaemon = true } }

    /** Whether the app is in front: the phone is the hub only then, unless the user lets it run in the background. */
    @Volatile private var foreground = false
    private var started = 0 // under lock: the app's started activities

    /**
     * This phone's sync mode (docs/design.md, "Sync modes"), in the file
     * mode beside the group's, as the computers keep it: own for a phone
     * that makes or joins a group from now on, shared for one that joined
     * before 0.5, which has no file.
     */
    private val modeFile = File(file.parentFile, "mode")

    /** This phone as a Bluetooth keyboard for a TV, a tablet or a computer near it. */
    val keyboard = BluetoothKeyboard(context, file.parentFile!!)

    /** This phone as a remote paste target: its switches, limits and log. */
    val pastes = PasteReceiver(context, file.parentFile!!, keyboard)

    /** The sync mode: own, shared, receive or send. */
    val syncMode: String
        get() = runCatching { modeFile.readText().trim() }.getOrNull()?.takeIf { it in Member.MODES } ?: "shared"

    /** The IDs of the commands carried out, until they expire: the replay cache (docs/protocol.md, section 15). */
    private val commands = mutableMapOf<String, Long>()

    /** When the app started: the replay cache starts empty, so a command signed before then may have been carried out already. */
    private val startedMS = System.currentTimeMillis()

    /** The images this phone copied, which the computers fetch from it. */
    private val content = MemoryContent(maxBytes = 2 * Images.MAX_COPY)

    /** The node, read under the lock; its methods are called outside it, as it calls back into the group under its own. */
    private val currentNode: MemberNode? get() = synchronized(lock) { node }

    /** Asks for the fingerprint, the face or the screen lock before the root or admin key signs. */
    val authenticator = Authenticator()

    /** The activity that shows the authentication prompt; null while the app is in the background. */
    @Volatile var activity: Context? = null

    val hasGroup: Boolean get() = synchronized(lock) { state != null }

    /** The group's tag, which the arrangement of the tiles is kept for; null without a group. */
    val groupTag: String? get() = synchronized(lock) { state?.tag }

    /**
     * Whether this phone may add and remove devices: it made the group, or
     * the phone that did made it an admin. A phone without a group makes
     * one when it adds a computer.
     */
    val isAdmin: Boolean get() = synchronized(lock) { state?.isAdmin ?: true }

    /** Whether this phone holds the group's root, which ends conflicts. */
    val isRoot: Boolean get() = synchronized(lock) { state?.isRoot ?: false }

    /** What the group's records stop and what ends it (GroupAlert). */
    val alerts: List<GroupAlert> get() = synchronized(lock) { state?.records?.alerts.orEmpty() }

    /** Every device of the group, this phone included. */
    val devices: List<Device>
        get() {
            // The node calls back into the group under its own lock, so it is asked outside this one.
            val (g, n) = synchronized(lock) { (state ?: return emptyList()) to node }
            val online = n?.connected.orEmpty()
            val offers = n?.offeredAdminKeys.orEmpty()
            val stores = n?.keyStores.orEmpty()
            val infos = n?.devices.orEmpty()
            val modes = n?.modes.orEmpty()
            val acts = n?.actions.orEmpty()
            val root = g.records.rootDevice
            return g.devices.map {
                Device(
                    id = it.id, name = it.name, online = it.id == g.device || it.id in online, role = it.role, os = it.os, isSelf = it.id == g.device,
                    admin = it.admin || it.id == root, isRoot = it.id == root,
                    canMakeAdmin = g.isRoot && !it.admin && !it.frozen && it.role == "full" && offers[it.id] != null,
                    keysInFile = KitRecords.storeOf(stores[it.id] ?: it.store, it.role) == KitRecords.FILE,
                    rootless = KitRecords.storeOf(stores[it.id] ?: it.store, it.role) == KitRecords.ROOTLESS,
                    frozen = it.frozen,
                    device = if (it.id == g.device) ownDevice.cleaned else infos[it.id],
                    mode = if (it.id == g.device) syncMode else modes[it.id],
                    actions = acts[it.id].orEmpty(),
                )
            }
        }

    val computers: List<Device> get() = devices.filter { !it.isSelf }

    /** Sync away from home on this phone: null without a group. */
    val awayFromHome: AwayFromHome? get() = synchronized(lock) { away }

    /** The phone as the group's hub: null without a group, or on a phone that is no admin, which cannot be the hub. */
    val phoneHub: HubOnPhone? get() = synchronized(lock) { hub?.takeIf { state?.isAdmin == true } }

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

    /**
     * Makes this phone the group's hub, or stops it being the hub. A hub
     * is no client of another, so turning it on turns this phone's own
     * sync away from home off; then it connects again, so the hellos it
     * answers get its offers.
     */
    fun setPhoneHub(on: Boolean) {
        val h = phoneHub ?: return
        if (on) {
            awayFromHome?.takeIf { it.isOn }?.turnOff()
            h.turnOn(currentNetwork())
            // Reached from afar through the project's forwarder, unless the user saved their own.
            if (h.forwarder == null) HubState.Forwarder.project()?.let { h.setForwarder(it) }
        } else {
            h.turnOff()
        }
        restartSync()
    }

    /** Sets the hub's forwarder from what the user typed, or the project's when both are empty (none when its name cannot be looked up now); on the caller's IO thread. */
    fun setForwarder(address: String, pin: String) {
        val h = phoneHub ?: return
        if (address.isBlank() && pin.isBlank()) {
            h.setForwarder(HubState.Forwarder.project())
        } else {
            val ep = HubState.resolve(address) ?: throw IllegalArgumentException("not an address")
            h.setForwarder(HubState.Forwarder(ep, pin.trim()))
        }
        refreshHub()
    }

    /** Lets the hub run in the foreground service while the app is in the background. */
    fun setHubInBackground(on: Boolean) {
        phoneHub?.setBackground(on)
        refreshHub()
    }

    /** Remembers the network the phone is on as a home network, where the hub takes members and publishes itself. */
    fun addHomeNetwork() {
        val n = currentNetwork() ?: return
        phoneHub?.addHome(n)
        refreshHub()
    }

    /** Whether the phone is on one of the hub's home networks now. */
    val onHomeNetwork: Boolean get() = phoneHub?.isHome(currentNetwork()) == true

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
        updateHub()
        updateRelay()
    }

    /** The phone at a blind relay: null without a group. */
    val blindRelay: RelayOnPhone? get() = synchronized(lock) { relayLink }

    /**
     * Meets the group at the relay the user typed, after they read what a
     * relay learns, or leaves it when both are empty; on the caller's IO
     * thread, as a name is looked up.
     */
    fun setRelay(address: String, pin: String) {
        val r = blindRelay ?: return
        if (address.isBlank() && pin.isBlank()) {
            r.turnOff()
        } else {
            val ep = HubState.resolve(address) ?: throw IllegalArgumentException("not an address")
            r.turnOn(ep, pin.trim())
        }
        refreshHub()
    }

    /**
     * Runs the link to the blind relay while it is on and the phone syncs,
     * with its member listener on the loopback address, which serves only
     * the calls the relay announced and only when the certificate names the
     * caller; otherwise it stops them.
     */
    private fun updateRelay() {
        val (r, n, g) = synchronized(lock) { Triple(relayLink, node, state) }
        if (r == null || n == null || g == null || !r.isOn) {
            stopRelay()
            return
        }
        val member = runCatching { memberSigner() }.getOrNull() ?: return
        val trusted = { synchronized(lock) { state?.trusted }.orEmpty() }
        val loop = synchronized(lock) { relayListener } ?: runCatching {
            MemberListener(n, member.privateKey, g.memberChain, trusted, onError = { e -> Log.w(TAG, "a call through the relay failed", e) },
                caller = r::caller)
        }.onFailure { Log.w(TAG, "the relay's calls cannot be taken", it) }.getOrNull()?.also { l -> synchronized(lock) { relayListener = l } } ?: return
        // The relay takes the member chain and the group's roots after it, as a forwarder (docs/protocol.md, section 14).
        r.start(HubOnPhone.Group(loop.port, g.memberChain + g.trusted, member::signDigest, g.records.authorityRecords))
        relayCredentials()
    }

    private fun stopRelay() {
        val l = synchronized(lock) { relayListener.also { relayListener = null } }
        l?.stop()
        synchronized(lock) { relayLink }?.stop()
    }

    /**
     * Runs the hub's parts that the moment calls for: with the hub on, the
     * app in front or the background allowed, the member listener on the
     * loopback address and the tunnel with its registration; on a home
     * network besides, the member listener there and the mDNS service.
     * Otherwise it stops them.
     */
    private fun updateHub() {
        val (h, n, g) = synchronized(lock) { Triple(hub, node, state) }
        if (h == null || n == null || g == null || !g.isAdmin || !h.isOn || !(foreground || h.background)) {
            stopHub()
            return
        }
        val member = runCatching { memberSigner() }.getOrNull() ?: return
        val trusted = { synchronized(lock) { state?.trusted }.orEmpty() }
        val onError: (Exception) -> Unit = { e -> Log.w(TAG, "a member connection to the hub failed", e) }
        val loop = synchronized(lock) { tunnelListener } ?: runCatching {
            MemberListener(n, member.privateKey, g.memberChain, trusted, onError = onError,
                onEnded = { id -> Log.i(TAG, "a member connection to the hub through its tunnel ended: $id") })
        }.onFailure { Log.w(TAG, "the hub cannot listen", it) }.getOrNull()?.also { l ->
            synchronized(lock) { tunnelListener = l }
            Log.i(TAG, "the hub's member listener takes connections through the tunnel on port ${l.port}")
        } ?: return
        // The forwarder takes the member chain and the group's roots after it (docs/protocol.md, section 13).
        h.start(HubOnPhone.Group(loop.port, g.memberChain + g.trusted, member::signDigest, g.records.authorityRecords))
        if (!h.isHome(currentNetwork())) {
            stopHome()
            return
        }
        if (synchronized(lock) { homeListener } != null) return
        val home = runCatching { MemberListener(n, member.privateKey, g.memberChain, trusted, MEMBER_PORT, null, onError) }
            .recoverCatching { MemberListener(n, member.privateKey, g.memberChain, trusted, 0, null, onError) }
            .onFailure { Log.w(TAG, "the hub cannot listen on the home network", it) }.getOrNull() ?: return
        val p = NsdPublisher(context, g.device, g.tag, home.port)
        synchronized(lock) {
            homeListener = home
            publisher = p
        }
        p.start()
    }

    private fun stopHome() {
        val (l, p) = synchronized(lock) {
            (homeListener to publisher).also {
                homeListener = null
                publisher = null
            }
        }
        p?.stop()
        l?.stop()
    }

    private fun stopHub() {
        stopHome()
        val (l, h) = synchronized(lock) { tunnelListener.also { tunnelListener = null } to hub }
        if (l != null) Log.i(TAG, "the hub's member listener on port ${l.port} stops${if (h == null) ", with no hub to stop" else ""}")
        l?.stop()
        h?.stop()
    }

    /** Forgets the hub's clients the records removed and hands its forwarder the new authority records. */
    private fun hubRecords() {
        val (h, g) = synchronized(lock) { (hub ?: return) to (state ?: return) }
        val ids = g.devices.map { it.id }.toSet()
        h.prune { it in ids }
        h.setRecords(g.records.authorityRecords)
        synchronized(lock) { relayLink }?.setRecords(g.records.authorityRecords)
    }

    /**
     * Turns sync away from home on or off, then connects again, so the
     * hellos offer the new key and the hub answers it.
     */
    fun setAwayFromHome(on: Boolean) {
        val a = awayFromHome ?: return
        if (on) a.turnOn() else a.turnOff()
        restartSync()
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
     * asked for: after the fingerprint, the face or the screen lock, asked
     * once and good for the signatures of the next few minutes. A phone
     * that is no admin has no such key.
     */
    private suspend fun caSigner(reason: Int): KeystoreSigner {
        if (!isAdmin) throw Failure(Failure.Kind.NOT_ADMIN)
        return signer(signingAlias(synchronized(lock) { state }), reason)
    }

    private suspend fun signer(alias: String, reason: Int): KeystoreSigner {
        val ui = activity ?: throw Failure(Failure.Kind.NO_SCREEN)
        authenticator.authenticate(ui, ui.getString(reason))
        return withContext(Dispatchers.IO) { Keys.loadOrCreate(context, alias) }
    }

    // Admitting

    /** Admits the device whose QR code the user scanned. */
    suspend fun admit(code: JoinCode) {
        val ca = caSigner(R.string.reason_add)
        val member = withContext(Dispatchers.IO) { memberSigner() }
        val name = deviceName
        val existing = withContext(Dispatchers.IO) { copyOfState() }
        val g = existing ?: withContext(Dispatchers.IO) { PhoneGroup.create(ca, member.publicKeyDER, Instant.now(), PhoneGroup.validName(name), sealKey()) }
        var failure: Exception? = null
        for (addr in SyncRule.ordered(code.addrs)) {
            currentCoroutineContext().ensureActive()
            val (host, port) = SyncRule.split(addr) ?: continue
            try {
                val admitted = withTimeoutOrNull(PAIRING_DEADLINE_MS) {
                    val t = withContext(Dispatchers.IO) {
                        TLSTransport.dial(host, port, Pairing.ALPN, member.privateKey, g.memberChain) { chain ->
                            chain.firstOrNull()?.let { Pairing.fingerprint(it) } == code.fingerprint
                        }
                    }
                    // Closing the connection ends a pairing that takes too
                    // long or that the user cancelled: the pending read fails.
                    closingOnCancel({ t.close() }) {
                        try {
                            val leaf = t.peerCertificate ?: throw Failure(Failure.Kind.UNREACHABLE)
                            val sid = t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
                            // The address that answered goes first, for dialing when mDNS does not find the computer.
                            g.admit(t, code.code, leaf, sid, ca, Instant.now(), addrs = listOf(addr) + code.addrs.filter { it != addr })
                        } finally {
                            t.close()
                        }
                    }
                } ?: throw Failure(Failure.Kind.UNREACHABLE)
                withContext(Dispatchers.IO) {
                    adopt(g)
                    // A group made on this phone has it as its hub from the start (D-64).
                    if (existing == null) setPhoneHub(true)
                }
                published(g.records.records)
                if (!admitted.confirmed) throw Failure(Failure.Kind.NOT_CONFIRMED)
                return
            } catch (e: CancellationException) {
                throw e
            } catch (e: PairingMember.Failure) {
                throw e // the computer answered: a wrong code is not worth another address
            } catch (e: Failure) {
                if (e.kind == Failure.Kind.NOT_CONFIRMED) throw e
                failure = telling(failure, e)
            } catch (e: Exception) {
                failure = telling(failure, e)
            }
        }
        throw failure ?: Failure(Failure.Kind.UNREACHABLE)
    }

    // Inviting from afar

    /** An open remote invitation: its text, as a file of one line holds it, when it expires, and how to cancel it. */
    class Invitation(val text: String, val expires: Instant, val cancel: () -> Unit)

    /**
     * Opens a remote invitation on this phone, the group's hub
     * (docs/protocol.md, section 12): a guest tunnel through the hub's
     * forwarder and its pairing window, for one device, for lifetimeS
     * seconds. ask asks the user whether to admit a device that proved it
     * knows the secret, showing its name and fingerprint; on yes the user
     * unlocks the group's key. ended gets the admitted device's name, or why
     * the invitation ended without one.
     */
    fun invite(lifetimeS: Int, ask: suspend (PairingMember.Request) -> Boolean, ended: (Result<String>) -> Unit): Invitation {
        val g = synchronized(lock) { state }?.takeIf { it.isAdmin } ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val h = phoneHub ?: throw HubOnPhone.NotRunning()
        val member = memberSigner()
        val guest = AtomicReference<HubGuest?>()
        val window = InvitationWindow(
            member.privateKey, g.memberCert, Instant.now().plusSeconds(lifetimeS.toLong()),
            admit = { t, joinerCert, sid -> admitInvited(t, joinerCert, sid, guest.get() ?: throw HubOnPhone.NotRunning(), ask) },
            onEnd = { r ->
                if (r.isFailure) guest.get()?.close()
                ended(r.map { it.info.name })
            },
            onError = { Log.w(TAG, "an attempt with the invitation failed", it) },
        )
        val gt = try {
            h.invite(g.tag, lifetimeS, window.port)
        } catch (e: Exception) {
            window.close()
            throw e
        }
        guest.set(gt)
        return Invitation(gt.text, Instant.ofEpochSecond(gt.expires)) { window.close() }
    }

    /** One attempt with an invitation: the device that proves the secret and that the user confirms is admitted. */
    private fun admitInvited(
        t: TLSTransport,
        joinerCert: ByteArray,
        sid: ByteArray,
        guest: HubGuest,
        ask: suspend (PairingMember.Request) -> Boolean,
    ): PairingMember.Admitted {
        val g = copyOfState() ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val alias = signingAlias(g)
        val invitation = PairingMember.Invitation(guest.secret) { req ->
            // The window's thread waits for the user, up to the 5 minutes the device waits.
            runBlocking { ask(req) && runCatching { signer(alias, R.string.reason_add) }.isSuccess }
        }
        // The key signs only once the user unlocked it in ask.
        val admitted = g.admit(t, "", joinerCert, sid, Keys.loadOrCreate(context, alias), Instant.now(), invitation = invitation)
        guest.admitted()
        adopt(g)
        published(g.records.records)
        return admitted
    }

    /** A deep copy of the group, to change it outside the lock and keep it only when the change works. */
    private fun copyOfState(): PhoneGroup? = synchronized(lock) { state?.let { PhoneGroup.fromJson(it.toJson()) } }

    /**
     * Saves a changed copy of the group and makes it the group, keeping the
     * records the node took in meanwhile; starts syncing when this is the
     * first group, and passes the change to the parts that run with it.
     */
    private fun adopt(g: PhoneGroup) {
        synchronized(lock) {
            if (state == null) newDeviceMode()
            state?.let {
                g.add(it.records.records)
                g.records.takeClaimTimes(it.records.claimTimes)
            }
            g.save(file)
            state = g
        }
        startSync()
        relay()
        refreshCredentials()
        hubWork.execute(::hubRecords)
    }

    // Joining

    /**
     * Joins another phone's group (docs/protocol.md, section 6, "The joiner
     * listens"): makes this phone's admin key, listens, hands show the QR
     * code to put on screen, and waits up to five minutes for an admin
     * phone to scan it and admit this one. Three wrong codes end it, as
     * does cancelling. A TV makes no admin key: it has no fingerprint or
     * face to guard one, and joins as a plain member.
     */
    suspend fun join(show: (JoinCode) -> Unit) {
        if (hasGroup) return
        val listening = withContext(Dispatchers.IO) {
            val member = memberSigner()
            // The admin key, behind the screen lock like the root key;
            // reading its public key asks for nothing.
            val admin = if (Tv.isTv(context)) null else Keys.load(Keys.ADMIN) ?: Keys.create(context, Keys.ADMIN)
            val device = SyncEngine.newID()
            val cert = GroupCertificates.selfSigned(device, member)
            val listener = TLSListener(0, Pairing.ALPN, member.privateKey, listOf(cert)) { it.isNotEmpty() }
            val addrs = LocalAddresses.current().map { JoinCode.address(it, listener.port) }
            if (addrs.isEmpty()) {
                listener.stop()
                throw Failure(Failure.Kind.NO_NETWORK)
            }
            Triple(listener, cert, admin) to JoinCode(JoinCode.newCode(), addrs, Pairing.fingerprint(cert))
        }
        val (parts, code) = listening
        val (listener, cert, admin) = parts
        show(code)
        val info = Pairing.Info(PhoneGroup.validName(deviceName), "android", admin?.publicKeyDER, seal = withContext(Dispatchers.IO) { sealKey() })
        val stopped = AtomicBoolean(false)
        val stop = {
            stopped.set(true)
            listener.stop()
        }
        val joined = try {
            withTimeoutOrNull(JOIN_WINDOW_MS) {
                closingOnCancel(stop) { accept(listener, stopped, code, info, cert) }
            }
        } finally {
            stop()
        }
        if (joined == null) throw Failure(Failure.Kind.TIMED_OUT)
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                newDeviceMode()
                state = PhoneGroup.joined(joined)
            }
            startSync()
        }
    }

    /** Takes connections until an admin phone admits this one; blocks. */
    private fun accept(listener: TLSListener, stopped: AtomicBoolean, code: JoinCode, info: Pairing.Info, cert: ByteArray): PairingJoiner.Joined {
        var wrong = 0
        while (true) {
            val t = try {
                listener.accept()
            } catch (e: IOException) {
                if (stopped.get()) throw e
                continue // a handshake that failed: another device, or a dropped connection
            }
            try {
                val leaf = t.peerCertificate ?: continue
                val sid = t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
                return PairingJoiner.accept(t, code.code, info, leaf, cert, sid, Instant.now()) { PhoneGroup.joined(it).save(file) }
            } catch (e: PairingJoiner.Failure) {
                if (e.code == Pairing.ErrorCode.WRONG_CODE) {
                    wrong++
                    if (wrong >= JOIN_ATTEMPTS) throw Failure(Failure.Kind.TOO_MANY_WRONG_CODES)
                }
            } catch (e: Exception) {
                if (stopped.get()) throw e
                // a dropped connection: the code is not spent
            } finally {
                t.close()
            }
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
        val current = synchronized(lock) { state } ?: return
        if (!current.isRoot && id == current.records.rootDevice) {
            takeOver(id)
            return
        }
        val ca = caSigner(R.string.reason_remove)
        val g = copyOfState() ?: return
        val r = withContext(Dispatchers.IO) { g.revoke(id, ca, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
        currentNode?.close(id)
    }

    /**
     * Gives a device another name (docs/protocol.md, section 10): a device
     * record like its newest one with that name, signed with this phone's
     * root or admin key, sent to every connected computer.
     */
    suspend fun rename(id: String, name: String) {
        val ca = caSigner(R.string.reason_rename)
        val g = copyOfState() ?: return
        val r = withContext(Dispatchers.IO) { g.rename(id, name, ca, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
    }

    /**
     * Ends a conflict or cancels a claim (docs/protocol.md, section 10,
     * "Stopping the exchange"): a resolve of the records ids, signed with the
     * root key after the fingerprint or the screen lock, sent to every
     * connected member.
     */
    suspend fun resolve(ids: List<ByteArray>) {
        if (!isRoot) throw Failure(Failure.Kind.NOT_ADMIN)
        val root = caSigner(R.string.reason_resolve)
        val g = copyOfState() ?: return
        val r = withContext(Dispatchers.IO) { g.resolve(ids, root, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
    }

    /**
     * Unfreezes an admin computer that another admin froze
     * (docs/protocol.md, section 10, "Removals and freezes keep what the author saw"): a thaw record signed with this
     * phone's root or admin key, sent to every connected computer.
     */
    suspend fun unfreeze(id: String) {
        val ca = caSigner(R.string.reason_unfreeze)
        val g = copyOfState() ?: return
        val r = withContext(Dispatchers.IO) { g.thaw(id, ca, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
    }

    /** Gives a phone that just made or joined a group the sync mode of a new device, own (receive on a TV), unless it has one from an earlier group. */
    private fun newDeviceMode() {
        // A TV receives the group's copies and sends none of its own (docs/roadmap.md, item 25).
        if (!modeFile.exists()) setOwnMode(if (Tv.isTv(context)) "receive" else "own")
        // The credentials and the keys for the servers of an earlier group are of no use.
        credentialStore = null
        credentialsFile.delete()
        runCatching { Keys.PhoneKeys.clear() }
        relayLink?.setCredentials(null)
    }

    /** The current root's key and whether a key hash is a member of the group, for the credentials. lock is held. */
    private fun credentialRootLocked(g: PhoneGroup): Pair<ByteArray, (ByteArray) -> Boolean> {
        val records = g.records
        return CertificateInfo(g.currentRoot).publicKey to { k: ByteArray -> CredentialRefresh.isMember(records, k) }
    }

    /** The credentials kept for the group g, read from their file the first time. lock is held. */
    private fun credentialsLocked(g: PhoneGroup): CredentialStore = credentialStore ?: run {
        val (root, isMember) = credentialRootLocked(g)
        val saved = runCatching { Json.parseToJsonElement(credentialsFile.readText()).jsonArray }.getOrNull()
        (saved?.let { CredentialStore.fromJson(it, g.groupCA, root, isMember) } ?: CredentialStore(g.groupCA)).also { credentialStore = it }
    }

    private fun saveCredentialsLocked(s: CredentialStore) {
        runCatching {
            val tmp = File(credentialsFile.path + ".tmp")
            tmp.writeText(s.toJson().toString())
            tmp.renameTo(credentialsFile)
        }.onFailure { Log.w(TAG, "saving the server credentials", it) }
    }

    /** The group's server credentials for the node, which keeps them with every member. */
    private inner class Credentials : CredentialKeeper {
        override val all: List<ServerCredentials.Credential>
            get() = synchronized(lock) { state?.let { credentialsLocked(it).all }.orEmpty() }

        override fun add(credentials: List<ServerCredentials.Credential>): List<ServerCredentials.Credential> {
            val fresh = synchronized(lock) {
                val g = state ?: return emptyList()
                val s = credentialsLocked(g)
                val (root, isMember) = credentialRootLocked(g)
                val (fresh, errs) = s.add(root, isMember, credentials)
                for (e in errs) Log.w(TAG, "dropped a server credential: $e")
                if (fresh.isNotEmpty()) saveCredentialsLocked(s)
                fresh
            }
            if (fresh.isNotEmpty()) refreshCredentials()
            return fresh
        }
    }

    /**
     * Brings the group's server credentials up to date as far as this phone
     * can (docs/protocol.md, section 18) and sends what it signed to the
     * computers: its server key for the period; on the root, the period
     * when one is due, while the user's last authentication lasts, and the
     * hubs' and members' credentials; on a listed admin, the members'.
     */
    private fun refreshCredentials() {
        credentialWork.execute {
            val signed = runCatching {
                synchronized(lock) {
                    val g = state ?: return@execute
                    val s = credentialsLocked(g)
                    val root = if (g.isRoot) {
                        { if (authenticator.isFresh) Keys.load(Keys.ROOT) else null }
                    } else {
                        null
                    }
                    CredentialRefresh.refresh(s, g.records, g.groupCA, g.currentRoot, memberSigner(), Keys.PhoneKeys, System.currentTimeMillis(), root)
                        .also { if (it.isNotEmpty()) saveCredentialsLocked(s) }
                }
            }.onFailure { Log.w(TAG, "signing the server credentials", it) }.getOrNull().orEmpty()
            if (signed.isNotEmpty()) currentNode?.sendCredentials(signed)
            relayCredentials()
        }
    }

    /**
     * Hands the blind relay what the phone registers with there: its server
     * key and the group's credentials once the members' credential lists
     * that key, so the relay knows the phone only by a pseudonym.
     */
    private fun relayCredentials() {
        val r = synchronized(lock) { relayLink } ?: return
        val c = runCatching {
            synchronized(lock) {
                val g = state ?: return
                val s = credentialsLocked(g)
                val (root, _) = credentialRootLocked(g)
                val tag = s.period(root)?.second?.tag?.takeIf { Keys.PhoneKeys.has(PeriodKeys.SERVER_KEY, it) }
                val k = tag?.let { Keys.PhoneKeys.get(PeriodKeys.SERVER_KEY, it) } as? KeystoreSigner ?: return@synchronized null
                val reg = s.registration(g.records, root, MessageDigest.getInstance("SHA-256").digest(k.publicKeyDER)) ?: return@synchronized null
                RelayOnPhone.Credentials(k.publicKeyDER, k::signDigest, reg)
            }
        }.onFailure { Log.w(TAG, "the server credentials for the relay", it) }.getOrNull()
        r.setCredentials(c)
    }

    /** Sends records made on this phone to the computers, and brings the credentials up to date with them. */
    private fun published(rs: List<Member.Record>) {
        currentNode?.sendRecords(rs)
        refreshCredentials()
    }

    /** Sets this phone's own sync mode and keeps it. */
    fun setOwnMode(mode: String) {
        require(mode in Member.MODES) { "unknown sync mode $mode" }
        // A phone making its first group sets its mode before the group's
        // file, which makes the folder, is written.
        modeFile.parentFile?.mkdirs()
        val tmp = File(modeFile.parentFile, "mode.tmp")
        tmp.writeText(mode + "\n")
        if (!tmp.renameTo(modeFile)) throw IOException("cannot save the sync mode")
        Log.i(TAG, "the sync mode is $mode now")
    }

    /**
     * Carries out a command a member sent this phone (docs/protocol.md,
     * section 15): a mode, paste, paste-off or away-off command an admin of
     * the group signed for it, not expired and not carried out before. A
     * phone takes no hub command.
     */
    private fun command(peer: String?, c: Member.Record): Member.CommandResult {
        val id = Commands.idOf(c) ?: ""
        fun refused(reason: String): Member.CommandResult {
            Log.w(TAG, "refused a command from $peer: $reason")
            return Member.CommandResult(id, "refused", reason)
        }
        val g = synchronized(lock) { state } ?: return refused("this device is in no group")
        val now = System.currentTimeMillis()
        val body = try {
            val secret = sealSecret()
            synchronized(lock) { Commands.verify(c, g.records, g.device, now, secret) }
        } catch (e: Commands.Refused) {
            return refused(e.message ?: "the command is not valid")
        }
        if (body.timeMS < startedMS) {
            return refused("this device started after the command was signed, so it may have carried it out already; send it again")
        }
        synchronized(lock) {
            commands.entries.removeAll { it.value <= now }
            if (body.id in commands) return refused("this command was carried out already")
            if (commands.size >= MAX_COMMANDS) return refused("too many commands; try again in a minute")
            commands[body.id] = body.expiresMS
        }
        when (body.type) {
            "paste" -> {
                val (sender, verified) = synchronized(lock) { g.records.commandSender(c, g.device) }
                val name = if (verified) g.devices.firstOrNull { it.id == body.by }?.name else null
                return pastes.paste(body, sender, verified, name)
            }
            "paste-off" -> {
                Log.i(TAG, "${body.by} turned remote paste off")
                return pastes.turnOff()?.copy(id = body.id) ?: Member.CommandResult(body.id, "done")
            }
            "away-off" -> {
                val a = awayFromHome ?: return Member.CommandResult(body.id, "done")
                try {
                    a.turnOff()
                } catch (e: Exception) {
                    Log.e(TAG, "cannot turn sync away from home off", e)
                    return Member.CommandResult(body.id, "failed", e.message)
                }
                Log.i(TAG, "${body.by} turned sync away from home off")
                // Connects again once the result has gone back on the
                // connection that brought the command.
                Thread {
                    Thread.sleep(AWAY_OFF_RESTART_MS)
                    restartSync()
                }.apply { isDaemon = true }.start()
                return Member.CommandResult(body.id, "done")
            }
            // A phone has no quick actions, so none of them stays on.
            "actions-off" -> return Member.CommandResult(body.id, "done")
            "action" -> return refused("a phone has no quick actions")
            "hub" -> return refused("a phone does not become the hub by a command; move the hub from the phone that is the hub")
            "mode" -> {}
            else -> return refused("this phone does not know the command ${body.type}")
        }
        val mode = body.mode?.takeIf { it in Member.MODES } ?: return refused("unknown sync mode ${body.mode}")
        return try {
            setOwnMode(mode)
            Log.i(TAG, "${body.by} set the sync mode to $mode")
            onModeChanged?.invoke()
            Member.CommandResult(body.id, "done")
        } catch (e: IOException) {
            Log.e(TAG, "cannot save the sync mode", e)
            Member.CommandResult(body.id, "failed", e.message)
        }
    }

    /**
     * Sets a connected computer's sync mode (docs/protocol.md, section 15):
     * a command signed with this phone's root or admin key, which the
     * computer answers.
     */
    suspend fun setMode(id: String, mode: String) {
        val ca = caSigner(R.string.reason_set_mode)
        val g = copyOfState() ?: return
        val n = currentNode ?: throw MemberNode.ProtocolException("the device is not connected")
        val r = withContext(Dispatchers.IO) { n.command(id, g.modeCommand(id, mode, ca, Instant.now())) }
        if (!r.done) throw CommandRefused(r.reason ?: r.status)
    }

    /**
     * Puts text where a computer's focus is (design.md, "Remote paste"): a
     * paste command signed with this phone's root or admin key, passed on
     * by a hub of the group connected to it when this phone is not; the computer
     * answers once the text is in, or why not.
     */
    suspend fun paste(id: String, text: String, method: String, enter: Boolean, secret: Boolean) {
        val ca = caSigner(R.string.reason_paste)
        val g = copyOfState() ?: return
        val n = currentNode ?: throw MemberNode.ProtocolException("the device is not connected")
        val c = g.pasteCommand(id, text, method, enter, secret, ca, Instant.now())
        // The computer waits 5 s for its target, and 5 ms more for each typed byte.
        val wait = 10_000L + if (method == "type") text.toByteArray().size * 5L else 0L
        val r = withContext(Dispatchers.IO) { n.command(id, c, timeoutMS = wait, via = hubOrder()) }
        if (!r.done) throw CommandRefused(r.reason ?: r.status)
    }

    /**
     * Runs a quick action on a computer (docs/protocol.md, section 15): an
     * action command, signed with this phone's root or admin key, names it;
     * the computer defines what it does and runs it only when its user
     * turned it on there.
     */
    suspend fun runAction(id: String, name: String) {
        val ca = caSigner(R.string.reason_action)
        val g = copyOfState() ?: return
        val n = currentNode ?: throw MemberNode.ProtocolException("the device is not connected")
        // The computer waits up to 20 s for the action to start.
        val r = withContext(Dispatchers.IO) { n.command(id, g.actionCommand(id, name, ca, Instant.now()), timeoutMS = ACTION_TIMEOUT_MS, via = hubOrder()) }
        if (!r.done) throw CommandRefused(r.reason ?: r.status)
    }

    /** Turns every quick action off on a computer; only its user turns them on again. */
    suspend fun actionsOff(id: String) {
        val ca = caSigner(R.string.reason_action)
        val g = copyOfState() ?: return
        val n = currentNode ?: throw MemberNode.ProtocolException("the device is not connected")
        val r = withContext(Dispatchers.IO) { n.command(id, g.actionsOffCommand(id, ca, Instant.now()), via = hubOrder()) }
        if (!r.done) throw CommandRefused(r.reason ?: r.status)
    }

    /**
     * Makes a connected admin computer the group's hub in place of this
     * phone (docs/protocol.md, section 11, "Moving the hub"): a hub command
     * signed with this phone's root or admin key hands it the clients' keys
     * and the forwarder; the clients connected now get its offer from this
     * phone, which then stops being the hub and becomes its client. A
     * computer that is no admin yet becomes one first, on the root.
     */
    suspend fun moveHub(id: String) {
        val h = phoneHub?.takeIf { it.isOn } ?: throw HubOnPhone.NotRunning()
        val fw = h.forwarder ?: throw HubOnPhone.NotRunning()
        val n = currentNode ?: throw MemberNode.ProtocolException("the device is not connected")
        if (copyOfState()?.records?.mayHost(id) != true) makeAdmin(id)
        val ca = caSigner(R.string.reason_move_hub)
        val g = copyOfState() ?: return
        val a = awayFromHome ?: return
        // This phone is the new hub's client from now on, with a key of its own.
        val wasOn = a.isOn
        if (!wasOn) a.turnOn()
        val (key, psk) = a.keys ?: throw HubOnPhone.NotRunning()
        val clients = h.handover + PhoneHub.Client(g.device, key, psk)
        val r = try {
            withContext(Dispatchers.IO) { n.command(id, g.hubCommand(id, fw.endpoint to fw.pin, clients, ca, Instant.now()), MOVE_TIMEOUT_MS) }
        } catch (e: Exception) {
            if (!wasOn) a.turnOff()
            throw e
        }
        val offer = r.tunnel?.takeIf { r.done }
        if (offer == null) {
            if (!wasOn) a.turnOff()
            throw CommandRefused(r.reason ?: r.status)
        }
        val sent = n.sendTunnel { dev -> h.movedOffer(dev, id, offer) }
        // The clients that came through the tunnel get the offer before it
        // closes: each connection ends after the offer and a goodbye, and
        // the last packets get a second more.
        withContext(Dispatchers.IO) { n.sayGoodbye(sent, MOVE_GRACE_MS) }
        delay(MOVE_LINGER_MS)
        h.turnOff()
        a.keep(id, offer.with(psk, null))
        withContext(Dispatchers.IO) { restartSync() }
    }

    /**
     * The connected computer this phone, the hub, suggests as the hub
     * (docs/design.md, "Moving the hub to a computer"): one that is always
     * on by its hello's form (a desktop, a server, a board or a router) and
     * that is an admin or can be made one here; null without one.
     */
    val suggestedHub: Device?
        get() {
            if (phoneHub?.isOn != true) return null
            return computers.firstOrNull { it.online && it.role == "full" && it.device?.form in ALWAYS_ON && (it.admin || it.canMakeAdmin) }
        }

    /**
     * Makes a computer an admin (docs/protocol.md, section 10, "A computer
     * as admin"): the root key certifies the admin key the computer offers;
     * the computer gets its admin CA and every member the new record. A
     * computer whose keys sit in a file becomes one only with allowFileKey,
     * after the user read the warning; else PhoneGroup.FileKey. A rootless
     * install never (PhoneGroup.Rootless).
     */
    suspend fun makeAdmin(id: String, allowFileKey: Boolean = false) {
        val n = synchronized(lock) { if (state?.isRoot == true) node else null }
        val key = n?.offeredAdminKeys?.get(id) ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val store = n.keyStores[id]
        if (KitRecords.storeOf(store, "full") == KitRecords.ROOTLESS) throw PhoneGroup.Rootless()
        if (KitRecords.storeOf(store, "full") == KitRecords.FILE && !allowFileKey) throw PhoneGroup.FileKey()
        val root = caSigner(R.string.reason_make_admin)
        val g = copyOfState() ?: return
        val (ca, r) = withContext(Dispatchers.IO) { g.makeAdmin(id, key, root, Instant.now(), store, allowFileKey) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
        currentNode?.sendAdminCA(ca, id)
    }

    /**
     * Makes the watch's key an admin key with the role watch (docs/protocol.md,
     * section 10, "Watches"): the root key, after the fingerprint, the face or
     * the screen lock, issues its admin CA and signs its device record, which
     * every member gets. Returns what the watch keeps.
     */
    suspend fun addWatch(request: WatchState.KeyRequest): WatchState.Admission {
        if (synchronized(lock) { state?.isRoot } != true) throw PhoneGroup.Failure("only the root makes admins")
        val root = caSigner(R.string.reason_add_watch)
        val g = copyOfState() ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val (ca, r) = withContext(Dispatchers.IO) { g.addWatch(request.device, request.name, "wearos", request.key, root, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
        return WatchState.Admission(request.device, ca, g.tag)
    }

    /** When the group's recovery key was made, while it has one (docs/protocol.md, section 10, "The recovery key"). */
    val recoveryMade: Instant?
        get() = synchronized(lock) {
            val g = state ?: return null
            val key = g.records.recovery ?: return null
            recoveryTime?.takeIf { it.first.contentEquals(key) }?.let { return it.second }
            recoveryMade(key, g.records.records).also { recoveryTime = key to it }
        }

    /** The recovery key's hash and when its record says it was made, so the records are read once per key. lock is held. */
    private var recoveryTime: Pair<ByteArray, Instant?>? = null

    /**
     * Makes the group's recovery key: the root key, after the fingerprint,
     * the face or the screen lock, issues it an admin CA and signs the
     * `recovery` record, which every member gets. The key itself leaves
     * only on its sheet.
     */
    suspend fun makeRecovery(): Core.RecoverySheet {
        if (!isRoot) throw PhoneGroup.Failure("only the root makes the recovery key")
        val root = caSigner(R.string.reason_make_recovery)
        val g = copyOfState() ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val made = withContext(Dispatchers.IO) { g.makeRecovery(root, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(made.record))
        return made.sheet
    }

    /** Removes the group's recovery key: the root revokes it, and a sheet printed for it no longer works. */
    suspend fun removeRecovery() {
        if (!isRoot) throw PhoneGroup.Failure("only the root removes the recovery key")
        val root = caSigner(R.string.reason_remove_recovery)
        val g = copyOfState() ?: throw Failure(Failure.Kind.NOT_ADMIN)
        val r = withContext(Dispatchers.IO) { g.removeRecovery(root, Instant.now()) }
        withContext(Dispatchers.IO) { adopt(g) }
        published(listOf(r))
    }

    /** What the group's watch may do to a device (PhoneGroup.WatchAction keys). */
    fun watchActions(id: String): List<String> = synchronized(lock) { state?.watchActions(id).orEmpty().map { it.key } }

    /**
     * The body the watch signs (docs/protocol.md, section 10, "Watches"): any
     * phone of the group builds it, since what counts is the watch's
     * signature.
     */
    fun watchBody(ask: WatchState.Ask): ByteArray {
        val g = copyOfState() ?: throw PhoneGroup.Failure(PhoneGroup.NOT_A_WATCH)
        val a = PhoneGroup.WatchAction.of(ask.action) ?: throw PhoneGroup.Failure(PhoneGroup.NOT_FOR_WATCH)
        return g.watchBody(a, ask.device, ask.watch, Instant.now(), ask.name)
    }

    /**
     * Brings what the watch signed into the group: a freeze or a removal
     * joins the records and goes to every member now or at the next sync, a
     * command goes to its device, which must be connected.
     */
    suspend fun deliverFromWatch(signed: WatchState.Signed) {
        val r = PhoneGroup.watchRecord(signed.body, signed.signature, signed.adminCA)
        val o = org.json.JSONObject(String(signed.body))
        val type = o.optString("type")
        if (type == "freeze" || type == "revoke") {
            val g = copyOfState() ?: throw PhoneGroup.Failure(PhoneGroup.NOT_A_WATCH)
            if (g.add(listOf(r)).size != 1) throw CommandRefused("the group did not take the watch's record")
            withContext(Dispatchers.IO) { adopt(g) }
            published(listOf(r))
            return
        }
        val to = o.optString("to").takeIf { it.isNotEmpty() } ?: throw PhoneGroup.Failure(PhoneGroup.NOT_FOR_WATCH)
        val n = currentNode ?: throw MemberNode.ProtocolException("the device is not connected")
        val res = withContext(Dispatchers.IO) { n.command(to, r, 25_000, via = hubOrder()) }
        if (!res.done) throw CommandRefused(res.reason ?: res.status)
    }

    /**
     * Removes the phone that holds the group's root, when it is lost: this
     * admin phone makes a new root key and claims the group for it
     * (docs/protocol.md, section 10, "Handing the group over"). The claim waits the
     * group's delay, in which the root, if it is still in use, cancels it;
     * [finishTakeOverIfDue] then makes this phone the root.
     */
    private suspend fun takeOver(id: String) {
        val admin = signer(Keys.ADMIN, R.string.reason_take_over)
        val r = withContext(Dispatchers.IO) {
            val g = copyOfState() ?: return@withContext null
            // A root key left from a group this phone made before goes.
            val root = Keys.create(context, Keys.ROOT, g.tag)
            val newRoot = GroupCertificates.groupCA(root, Instant.now(), pathLength = 1)
            val r = g.takeOver(id, admin, newRoot, Instant.now())
            adopt(g)
            r
        } ?: return
        published(listOf(r))
    }

    /**
     * Makes this phone the group's root once its claim took effect: it
     * signs, with the new root key, what a new root starts with, and becomes
     * the hub when the lost phone was (docs/design.md, "Losing the phone").
     * A claim that was cancelled is dropped.
     */
    suspend fun finishTakeOverIfDue() {
        val g = withContext(Dispatchers.IO) { copyOfState() } ?: return
        if (g.claim == null) return
        g.records.refresh()
        g.adoptRoots()
        val lost = g.claimedFrom
        if (!g.currentRoot.contentEquals(g.claim)) {
            if (!g.dropEndedClaim()) return
            Log.i(TAG, "the claim to take the group over ended; this phone stays an admin")
            withContext(Dispatchers.IO) { adopt(g) }
            return
        }
        try {
            val root = signer(Keys.ROOT, R.string.reason_take_over)
            val rs = withContext(Dispatchers.IO) {
                val rs = g.finishTakeOver(root, Instant.now())
                adopt(g)
                rs
            }
            published(rs)
            if (lost != null) currentNode?.close(lost)
            val wasHub = lost != null && awayFromHome?.hub == lost
            withContext(Dispatchers.IO) { if (wasHub) setPhoneHub(true) else restartSync() }
        } catch (e: Exception) {
            Log.e(TAG, "finishing the takeover: $e")
        }
    }

    // Syncing

    /** Starts finding and dialing the computers, once there is a group. */
    private fun startSync() {
        val b = startBrowsing() ?: return
        b.start()
        refreshCredentials()
        awayFromHome?.start()
        relay()
        refreshHub()
    }

    /**
     * Whether browsing finds the hub on the home network now, and either
     * found it within [NEAR_GRACE_MS] or the dialer is connected to it:
     * anyone on a network can announce a member's name and the group's tag
     * (docs/protocol.md, section 11).
     */
    private fun atHome(hub: String): Boolean {
        val (at, d) = synchronized(lock) { foundAt[hub] to dialer }
        if (at == null) return false
        if ((System.nanoTime() - at) / 1_000_000 < NEAR_GRACE_MS) return true
        return d?.connected?.contains(hub) == true
    }

    private fun startBrowsing(): NsdBrowser? = synchronized(lock) {
        val g = state ?: return null
        if (node != null) return null
        val member = runCatching { memberSigner() }.getOrNull() ?: return null
        // Through the tunnel the phone dials the hub's member port with the
        // same TLS as at home, and only while the hub is not found here.
        val a = AwayFromHome(
            g.device,
            GoTunnels,
            load = awayFile::read,
            save = { s -> if (s == null) awayFile.delete() else awayFile.write(s) },
            atHome = ::atHome,
            dial = { port, hub ->
                TLSTransport.dial("127.0.0.1", port, Member.ALPN, member.privateKey, g.memberChain) { peer ->
                    runCatching { GroupCertificates.verifyMember(peer, g.trusted, Instant.now()) }.getOrNull() == hub
                }
            },
            serve = { t, hub -> currentNode?.serve(t, hub) ?: t.close() },
            mayHost = { hub -> synchronized(lock) { state?.records?.mayHost(hub) == true } },
            order = ::hubOrder,
            log = { what, e -> Log.w(TAG, what, e) },
            isPhone = { hub -> synchronized(lock) { state?.devices?.firstOrNull { it.id == hub }?.role == "phone" } },
        )
        val h = HubOnPhone(
            g.device,
            GoHubTunnels,
            load = { hubFile.read()?.let(HubState::decode) },
            save = { s -> if (s == null) hubFile.delete() else hubFile.write(s.encode()) },
            log = { what, e -> Log.w(TAG, what, e) },
        )
        // At a blind relay the phone dials the device the relay joined, with
        // the same TLS as at home, while browsing does not find it here.
        val rl = RelayOnPhone(
            g.device,
            GoRelayLinks,
            load = { relayFile.read()?.let(RelaySettings::decode) },
            save = { s -> if (s == null) relayFile.delete() else relayFile.write(s.encode()) },
            dialPeer = { port, peer ->
                TLSTransport.dial("127.0.0.1", port, Member.ALPN, member.privateKey, g.memberChain) { c ->
                    runCatching { GroupCertificates.verifyMember(c, g.trusted, Instant.now()) }.getOrNull() == peer
                }
            },
            serve = { t, peer -> currentNode?.serve(t, peer) ?: t.close() },
            elsewhere = { peer -> synchronized(lock) { peer in foundAt } },
            log = { what, e -> Log.w(TAG, what, e) },
        )
        // The hub answers the tunnel keys of the hellos, shares its clients
        // with the group's other hubs and passes their offers on; it is no
        // client itself (docs/protocol.md, section 11, "Several hubs").
        val isHub = g.isAdmin && h.isOn
        var self: MemberNode? = null
        val share = { peer: String, chain: List<ByteArray> ->
            if (synchronized(lock) { state?.records?.mayHost(peer, chain) } == true) h.share() else null
        }
        val n = MemberNode(
            SyncEngine(g.device, HybridClock()),
            deviceName,
            records = Records(),
            os = "android",
            device = ownDevice,
            mode = { syncMode },
            onCommand = ::command,
            renew = ::renew,
            evidence = ::ownEvidence,
            onEvidence = ::evidenceReceived,
            content = content,
            credentials = Credentials(),
            adminCA = { key -> synchronized(lock) { state?.computerAdminCA(key) } },
            // A copy of a moment ago from another device; an older one, as a
            // hello brings it on connecting, would overwrite what the phone
            // copied since.
            // Only in a sync mode that takes the group's copies.
            onChange = { e ->
                if (!e.isMark && e.origin != g.device && e.ageMS < SyncRule.RECENT_COPY_MS && Member.receives(syncMode)) {
                    val image = Images.part(e.media)
                    if (image != null) {
                        // Fetched off the node's thread, which reads the chunks.
                        onImage?.let { f -> Thread({ fetchImage(e, image)?.let { f(it, e.text) } }, "image").start() }
                    } else if (e.text.isNotEmpty()) {
                        onCopy?.invoke(e.text, e.kind)
                    }
                }
            },
            tunnelKey = { if (isHub) null else a.keys },
            onTunnel = a::keep,
            // A client admitted now is shared with the other hubs at once,
            // so that it reaches them when this phone is off.
            hub = if (isHub) { device, key, psk, _ -> h.offers(device, key, psk, hubOrder()) { self?.sendHubs(share) } } else null,
            hubShare = if (isHub) share else null,
            onHubs = { from, _, share ->
                if (isHub) {
                    val known = { d: String -> synchronized(lock) { state?.records?.knows(d) == true } }
                    if (h.shared(from, share, known)) self?.sendTunnels { dev -> h.offersFor(dev, hubOrder()) }
                } else {
                    // A client keeps the sharing hub's offer with its own preshared key, as any hub's.
                    val psk = a.keys?.second
                    val o = share.offer
                    if (psk != null && o != null) a.keep(from, o.with(psk, null))
                }
            },
        )
        self = n
        val b = NsdBrowser(context) { members ->
            synchronized(lock) {
                found = members
                val now = System.nanoTime()
                foundAt = members.filter { it.group == g.tag }.associate { it.device to (foundAt[it.device] ?: now) }
            }
            relay()
        }
        val known = { d: String -> synchronized(lock) { state?.addresses?.get(d).orEmpty() } }
        dialer = MemberDialer(n, g.tag, dial = b.dialer(member, g.memberChain, g.trusted, known))
        node = n
        browser = b
        away = a
        hub = h
        relayLink = rl
        b
    }

    /** The group's hubs, highest first (RecordSet.hubOrder). */
    private fun hubOrder(): List<String> = synchronized(lock) { state?.records?.hubOrder }.orEmpty()

    /** Connects again, as after the user allowed the local network. */
    fun reconnect() = restartSync()

    /** Stops syncing and starts again, with a new certificate or new roots. */
    private fun restartSync() {
        Log.i(TAG, "connecting to the group again")
        val (d, b, n) = synchronized(lock) {
            Triple(dialer, browser, node).also {
                dialer = null
                browser = null
                node = null
            }
        }
        val a = synchronized(lock) { away.also { away = null } }
        a?.stop()
        // After any change of the hub's that is still running.
        hubWork.submit {
            stopHub()
            stopRelay()
            synchronized(lock) {
                hub = null
                relayLink = null
            }
        }.get()
        d?.stop()
        b?.stop()
        n?.closeAll()
        startSync()
    }

    /**
     * Passes what the browser finds to the dialer, with the computers it
     * does not find at the addresses they had when admitted, only the
     * devices that are in the group's list: a removed computer is not
     * dialed. A phone that joined has no records until a computer sends
     * them, so it dials every member of the group until then; TLS still
     * checks each against the group's roots.
     */
    private fun relay() {
        val (d, members) = synchronized(lock) {
            val g = state ?: return
            val all = Discovery.withKnown(found, g.addresses.keys, g.tag)
            val allowed = if (g.records.records.isEmpty()) null else g.devices.map { it.id }.toSet()
            dialer to (allowed?.let { a -> all.filter { it.device in a }.toSet() } ?: all)
        }
        d?.update(members)
    }

    /** The group's records for the node, which exchanges them with the computers. */
    private inner class Records : RecordStore {
        override val digest: String? get() = synchronized(lock) { state?.records?.digest }
        override val all: List<Member.Record> get() = synchronized(lock) { state?.records?.records.orEmpty() }

        /**
         * Takes in records a computer sent, and the roots they lead to: a
         * new root, after another admin phone took the group over, means
         * connecting again with it trusted.
         */
        override fun add(records: List<Member.Record>): List<Member.Record> {
            val (fresh, rooted) = synchronized(lock) {
                val g = state ?: return emptyList()
                val roots = g.roots.size
                val fresh = g.add(records)
                if (fresh.isNotEmpty()) runCatching { g.save(file) }
                fresh to (g.roots.size != roots)
            }
            if (fresh.isNotEmpty()) {
                relay()
                refreshCredentials()
                hubWork.execute(::hubRecords)
                onRecords?.invoke()
            }
            if (rooted) Thread({ restartSync() }, "restart sync").start()
            return fresh
        }

        override fun refused(chain: List<ByteArray>): String? = synchronized(lock) { state?.records?.refused(chain) }
        override fun stopped(chain: List<ByteArray>): Boolean = synchronized(lock) { state?.records?.stopped(chain) ?: false }
        override fun noSecrets(device: String?): Boolean = synchronized(lock) { state?.records?.noSecrets(device) ?: false }

        override fun mayHost(device: String, chain: List<ByteArray>): Boolean =
            synchronized(lock) { state?.records?.mayHost(device, chain) == true }
    }

    /**
     * Issues a renewed member certificate with the root or admin key for a
     * peer that is due, without asking: only while the user's last
     * authentication lasts, so a computer that connects before that gets
     * its renewal on a later connection (docs/protocol.md, section 2).
     */
    private fun renew(chain: List<ByteArray>): MemberNode.Renewal? {
        val g = synchronized(lock) { state } ?: return null
        val cert = chain.firstOrNull() ?: return null
        recordProofs(null)
        if (!g.isAdmin || !authenticator.isFresh || !GroupCertificates.isDue(cert, g.adminCA ?: g.currentRoot, Instant.now())) return null
        val signer = Keys.load(signingAlias(g)) ?: return null
        return synchronized(lock) { state?.renewal(chain, signer, Instant.now()) }
    }

    /** The attestation of this phone's member key, which every peer gets (docs/protocol.md, section 17, "Evidence"); none for a key made without one. */
    private val memberEvidence: List<Member.Evidence> by lazy {
        Keys.evidence(context, Keys.MEMBER)?.let {
            listOf(Member.Evidence(Member.Evidence.ANDROID, Member.Evidence.MEMBER, it.groupTag.ifEmpty { null }, it.salt, it.chain))
        } ?: emptyList()
    }

    private fun ownEvidence(): List<Member.Evidence> = runCatching { memberEvidence }.getOrDefault(emptyList())

    /** The revocation list the root checks evidence against. */
    private val attestStatus by lazy { AttestStatus(File(context.filesDir, "attest-status")) }

    /**
     * On the root, records what the attestation a peer sent shows, and what
     * this phone's own shows, as renew does while the user's authentication
     * lasts: a peer sends it on every connection, so one that comes later
     * is recorded then.
     */
    private fun evidenceReceived(peer: String?, chain: List<ByteArray>, e: Member.Evidence) {
        if (peer != null) recordProofs(Triple(peer, chain, e))
    }

    /** Records what peer's evidence, when given, and this phone's own show, on the root while its authentication lasts. */
    private fun recordProofs(peer: Triple<String, List<ByteArray>, Member.Evidence>?) {
        val g = synchronized(lock) { state } ?: return
        val own = ownEvidence().firstOrNull()
        if (g.isRoot) attestStatus.refreshIfDue()
        if (!g.isRoot || !authenticator.isFresh || peer == null && (own == null || g.devices.any { it.id == g.device && it.proof != null })) return
        val signer = Keys.load(Keys.ROOT) ?: return
        val copy = copyOfState() ?: return
        val now = Instant.now()
        val rs = listOfNotNull(
            peer?.let { (dev, chain, e) -> prove(copy, dev, chain, e, signer, now) },
            own?.let { prove(copy, copy.device, copy.memberChain.take(1), it, signer, now) },
        )
        if (rs.isEmpty()) return
        adopt(copy)
        published(rs)
    }

    private fun prove(g: PhoneGroup, device: String, chain: List<ByteArray>, e: Member.Evidence, signer: KeystoreSigner, now: Instant) = try {
        g.evidence(device, chain, e, signer, now, revoked = attestStatus.revoked)?.also { Log.i(TAG, "recorded what the attestation of $device shows") }
    } catch (x: AndroidAttestation.Invalid) {
        Log.w(TAG, "the attestation of $device proves nothing: ${x.message}")
        null
    }

    /**
     * Renews this phone's own member certificate when it is due, which asks
     * for the screen lock, and then connects again with it.
     */
    suspend fun renewOwnCertificate() {
        val g = copyOfState() ?: return
        if (!GroupCertificates.isDue(g.memberCert, g.adminCA ?: g.currentRoot, Instant.now())) return
        val ca = runCatching { caSigner(R.string.reason_renew) }.getOrNull() ?: return
        val renewed = withContext(Dispatchers.IO) { runCatching { g.renewOwnCertificate(ca, Instant.now()) }.getOrDefault(false) }
        if (!renewed) return
        withContext(Dispatchers.IO) {
            adopt(g)
            restartSync()
        }
    }

    /**
     * The one button, by SyncRule: given what the phone's clipboard holds
     * now, sends it or returns the text to put there.
     */
    fun sync(board: Clipboard.Board?): Pair<SyncResult, Got?> {
        val (n, device) = synchronized(lock) { (node ?: throw Failure(Failure.Kind.NO_COMPUTERS)) to (state?.device ?: "") }
        val current = n.current
        val image = Images.part(current?.media)
        val files = current?.media?.takeIf { it.isFiles }
        // An image compares by its hash, a text by itself; files count
        // until the button saved them once.
        val usable = when {
            image != null -> Images.key(image.sha256!!) to Member.Kind.MEDIA
            files != null -> if (current.id == savedFiles) null else "\u0000files:" + current.id to Member.Kind.MEDIA
            else -> n.usable
        }
        return when (SyncRule.decide(board?.key, current, usable, device)) {
            SyncRule.Action.FETCH -> {
                if (files != null) {
                    if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
                    val saved = Files.save(context, n, current, files)
                    savedFiles = current.id
                    return SyncResult.FETCHED to Got.Files(saved)
                }
                if (image == null) return SyncResult.FETCHED to usable?.let { Got.Text(it.first, it.second) }
                if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
                val f = fetchImage(current!!, image, quiet = false) ?: throw Failure(Failure.Kind.NO_COMPUTERS)
                SyncResult.FETCHED to Got.Image(f, current.text)
            }
            SyncRule.Action.SEND -> {
                if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
                when (board!!) {
                    is Clipboard.Board.Text -> n.send(board.text, Member.Kind.TEXT)
                    is Clipboard.Board.Image -> sendImage(n, board.image)
                }
                SyncResult.SENT to null
            }
            SyncRule.Action.NOTHING -> {
                if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
                SyncResult.NOTHING_NEW to null
            }
        }
    }

    /**
     * Whether a computer is connected, waiting up to CONNECT_WAIT_MS for
     * one: a connection the system dropped takes a moment to come back. On
     * the caller's IO thread.
     */
    private fun connected(n: MemberNode): Boolean {
        val deadline = System.currentTimeMillis() + CONNECT_WAIT_MS
        while (n.connected.isEmpty()) {
            if (System.currentTimeMillis() >= deadline) return false
            Thread.sleep(250)
        }
        return true
    }

    /** Whether a computer is connected now. */
    val online: Boolean get() = currentNode?.connected?.isNotEmpty() == true

    /**
     * The group's latest copy while the button would fetch it first
     * (SyncRule.decide): another device's, younger than RECENT_COPY_MS;
     * null otherwise. The tests wait it out before they send.
     */
    internal val recentCopy: Member.Event?
        get() {
            val (n, device) = synchronized(lock) { node to state?.device }
            val e = n?.current ?: return null
            return e.takeIf { it.origin != device && it.via == Member.Via.COPY && it.ageMS < SyncRule.RECENT_COPY_MS }
        }

    /** What the button fetched for the phone's clipboard: a text, or an image in the app's cache with its text. */
    sealed class Got {
        data class Text(val text: String, val kind: Member.Kind) : Got()

        data class Image(val file: File, val alt: String) : Got()

        /** Files saved in Downloads/Clipboard Bridge. */
        data class Files(val count: Int) : Got()
    }

    /** The files event the button saved last, so it does not save them again. */
    @Volatile private var savedFiles: String? = null

    /** Sends what the user shared with the app: an image, or files, which the computers fetch from this phone. */
    fun sendShared(shared: Files.Shared): SyncResult {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        if (!connected(n)) throw Failure(Failure.Kind.NO_COMPUTERS)
        when (shared) {
            is Files.Shared.Image -> sendImage(n, shared.image)
            is Files.Shared.Many -> n.send("", Member.Kind.TEXT, media = Content.files(content, shared.files))
        }
        return SyncResult.SENT
    }

    /** Sends an image the phone copied: the computers fetch it from this phone. */
    private fun sendImage(n: MemberNode, image: Images.Copied) {
        n.send("", Member.Kind.TEXT, media = Content.manifest(content, listOf(image.type to image.bytes)))
    }

    /**
     * Fetches a received image into the app's cache; null, with the reason
     * in the log, when it cannot, or the error when not quiet.
     */
    private fun fetchImage(e: Member.Event, part: Media.Part, quiet: Boolean = true): File? {
        val n = currentNode ?: return null
        return try {
            Images.fetch(context, n, e, part)
        } catch (x: Exception) {
            Log.w(TAG, "fetching an image", x)
            if (quiet) null else throw x
        }
    }

    /** Sends a text the user shared or selected, unless it is the group's current text already. */
    fun send(text: String): SyncResult {
        val n = currentNode ?: throw Failure(Failure.Kind.NO_COMPUTERS)
        if (n.connected.isEmpty()) throw Failure(Failure.Kind.NO_COMPUTERS)
        if (n.usable?.first == text) return SyncResult.NOTHING_NEW
        n.send(text, Member.Kind.TEXT)
        return SyncResult.SENT
    }

    /**
     * Gets each text a computer copied, as it arrives, to put on the
     * phone's clipboard; on the node's thread.
     */
    @Volatile var onCopy: ((String, Member.Kind) -> Unit)? = null

    /** Gets each image a computer copied, fetched into the app's cache, with its text; on a thread of its own. */
    @Volatile var onImage: ((File, String) -> Unit)? = null

    /** Called when an admin changed this phone's sync mode, on the node's thread. */
    @Volatile var onModeChanged: (() -> Unit)? = null

    /** Called on the node's thread when records arrived that change the group, for the notifications. */
    @Volatile var onRecords: (() -> Unit)? = null

    /** This phone's secret for sealed messages (docs/protocol.md, section 15), 32 random bytes under a Keystore key. */
    private val sealFile = SealedFile(File(file.parentFile, "seal-secret"), "clipboardbridge.seal")

    /** The secret, made and kept on its first use; null, with the reason in the log, when the Keystore refuses it. */
    private fun sealSecret(): ByteArray? =
        try {
            synchronized(sealFile) {
                sealFile.read()?.takeIf { it.size == 32 } ?: ByteArray(32).also {
                    SecureRandom().nextBytes(it)
                    sealFile.write(it)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "no key for sealed messages", e)
            null
        }

    /**
     * This phone's public key for sealed messages, which its pairing and device record carry so that commands for it
     * come sealed; null when there is none, and the commands for it then come in the open.
     */
    private fun sealKey(): ByteArray? =
        sealSecret()?.let {
            try {
                Core.sealPublic(it)
            } catch (e: Exception) {
                Log.e(TAG, "no public key for sealed messages", e)
                null
            }
        }

    companion object {
        /** The time of the newest `recovery` record that names key. */
        internal fun recoveryMade(key: ByteArray, records: List<Member.Record>): Instant? {
            for (r in records.asReversed()) {
                val o = runCatching { Json.parseToJsonElement(String(r.body)).jsonObject }.getOrNull() ?: continue
                fun field(k: String) = (o[k] as? JsonPrimitive)?.takeIf { it.isString }?.content
                if (field("type") != "recovery") continue
                val admin = field("admin")?.let { runCatching { java.util.Base64.getDecoder().decode(it) }.getOrNull() } ?: continue
                val ms = (o["time_ms"] as? JsonPrimitive)?.longOrNull ?: continue
                if (admin.contentEquals(key)) return Instant.ofEpochMilli(ms)
            }
            return null
        }

        private const val TAG = "clipboardbridge"

        /** The most command IDs the replay cache keeps; a command lives at most 30 s, as Go's maxCommandIDs. */
        private const val MAX_COMMANDS = 4096

        /** How long after an away-off command the phone connects again, as Go's restartAfter. */
        private const val AWAY_OFF_RESTART_MS = 500L

        /** The forms of devices that are always on, as their hellos state them. */
        private val ALWAYS_ON = setOf("desktop", "server", "board", "router")

        /** How long a hub command may take: the computer starts its hub before it answers. */
        private const val MOVE_TIMEOUT_MS = 20_000L

        /** How long a quick action may take: an own action runs for up to 15 s before the computer answers. */
        private const val ACTION_TIMEOUT_MS = 25_000L

        /** The longest the old hub waits for its clients' connections to end after it passed the new hub's offer on, as Go's moveGrace. */
        private const val MOVE_GRACE_MS = 10_000L

        /** How long it keeps its tunnel after they ended, for the last packets, as Go's moveLinger. */
        private const val MOVE_LINGER_MS = 1_000L

        /** How long a member that browsing finds counts as at home without a connection to it. */
        private const val NEAR_GRACE_MS = 30_000L

        /** How long admitting a device may take once it is dialed: a computer that stops answering mid-pairing fails then. */
        const val PAIRING_DEADLINE_MS = 30_000L

        /** How long the join QR code is good for, and how many wrong codes it takes, as for cbb pair (docs/protocol.md, section 6). */
        const val JOIN_WINDOW_MS = 300_000L
        const val JOIN_ATTEMPTS = 3

        /** How long the button waits for a computer to connect before it says none is. */
        const val CONNECT_WAIT_MS = 5_000L

        /** The member port the hub takes members on at home, as the computers'; another when it is taken. */
        const val MEMBER_PORT = 8764

        fun defaultFile(context: Context) = File(context.filesDir, "clipboardbridge/group.json")

        /**
         * Of two failures on different addresses, the one that says more: an
         * address that answered, as with a failed handshake, over one that
         * did not.
         */
        fun telling(earlier: Exception?, later: Exception): Exception {
            if (earlier == null) return later
            if (unreachable(earlier) && !unreachable(later)) return later
            return earlier
        }

        private fun unreachable(e: Exception): Boolean =
            (e is Failure && e.kind == Failure.Kind.UNREACHABLE) || e.cause is SocketException || e.cause is SocketTimeoutException

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
