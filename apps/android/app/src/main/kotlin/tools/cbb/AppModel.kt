// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import tools.cbb.kit.GroupAlert
import tools.cbb.kit.Arrangement
import tools.cbb.kit.Core
import tools.cbb.kit.Content
import tools.cbb.kit.CopyKeys
import tools.cbb.kit.InvitationWindow
import tools.cbb.kit.JoinCode
import tools.cbb.kit.MemberNode
import tools.cbb.kit.PairingJoiner
import tools.cbb.kit.PairingMember
import tools.cbb.kit.Pairing
import tools.cbb.kit.PhoneGroup
import tools.cbb.kit.Piv
import tools.cbb.kit.Restore
import tools.cbb.kit.TLSTransport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.time.Instant

/**
 * What the app shows and does; the screens only read it and call it. Its
 * state is Compose state, changed on the main thread.
 */
class AppModel(private val app: Context) {
    enum class Phase { START, JOINING, JOINING_COMPUTER, HOME }

    /** One line about the last action, in plain words, and the error underneath when details are on. */
    data class Note(@StringRes val text: Int, val detail: String? = null, val error: Boolean = false)

    val settings = Settings(app)

    /** On a TV: it joins a phone's group, as a member without an admin key, and takes the D-pad (Tv). */
    val isTv = Tv.isTv(app)
    val notifier = Notifier(app).also { n ->
        // From the thread that saw the event: the watch hears of it on the main thread.
        n.onEvent = { Handler(Looper.getMainLooper()).post { WatchLink.update(app, this) } }
    }
    val group = LiveGroup(app).also { g ->
        g.onCopy = { text, kind -> Clipboard.write(app, text, kind) }
        g.onImage = { file, alt -> Clipboard.writeImage(app, file, alt) }
        // In the background too: the service keeps the connections that bring the records.
        // Off the node's thread, which may hold its own lock while it hands records over.
        g.onRecords = { Thread({ notifier.observe(g.devices) }, "events").start() }
        // The Bluetooth keyboard, when its user turned it on.
        g.keyboard.apply()
    }

    var phase by mutableStateOf(if (group.hasGroup) Phase.HOME else Phase.START)
        private set
    private var listed by mutableStateOf(group.devices)

    /**
     * The user's order of the tiles and their collections (docs/apps.md,
     * "Collections and the order of the tiles"): null until the group's tag
     * is known.
     */
    var arrangement by mutableStateOf<Arrangement?>(null)
        private set

    /** Every device of the group, this phone included, in the group's order. */
    var devices: List<LiveGroup.Device>
        get() = listed
        private set(v) {
            listed = v
            loadArrangement()
        }

    init {
        loadArrangement()
        // A command from an admin changes this phone's mode on the node's thread.
        group.onModeChanged = { Handler(Looper.getMainLooper()).post { devices = group.devices } }
    }
    val computers: List<LiveGroup.Device> get() = devices.filter { !it.isSelf }
    var message by mutableStateOf<Note?>(null)
    var busy by mutableStateOf(false)
        private set

    /** How many times a device being added that has not answered yet was dialed again; 0 before that. */
    var retries by mutableStateOf(0)
        private set

    /** The QR code this phone shows while it waits to join a group. */
    var joinCode by mutableStateOf<JoinCode?>(null)
        private set
    var isAdmin by mutableStateOf(group.isAdmin)
        private set

    /** Whether this phone holds the group's root, which ends conflicts. */
    var isRoot by mutableStateOf(false)
        private set

    /** Whether the group's root handed the group to this phone, which may take it now. */
    var handedOver by mutableStateOf(false)
        private set

    /** The group removed this phone; the app offers to leave. */
    var removed by mutableStateOf(false)
        private set

    /** What the group's records stop and what ends it. */
    var alerts by mutableStateOf<List<GroupAlert>>(emptyList())
        private set

    /** The one-time note on the Start screen that this phone is ready. */
    var welcome by mutableStateOf(false)
        private set

    var color by mutableStateOf(settings.color)
        private set
    var appearance by mutableStateOf(settings.appearance)
        private set

    /** Sync away from home as Settings shows it: null without a group. */
    data class Away(val on: Boolean, val status: AwayFromHome.Status, val error: Note? = null)

    var away by mutableStateOf<Away?>(null)
        private set

    /** What turning it on or off said, when it failed. */
    var awayNote by mutableStateOf<Note?>(null)
        private set

    /** The group's key level, on the root phone; null elsewhere. */
    var keyLevel by mutableStateOf<String?>(null)
        private set

    /** What the last change to the key level said. */
    var keyLevelNote by mutableStateOf<Note?>(null)
        private set

    /** How long a copy from another device stays live, in milliseconds, on an admin phone; null elsewhere. */
    var incomingMS by mutableStateOf<Long?>(null)
        private set

    /** What the last change to how long a copy stays live said. */
    var incomingNote by mutableStateOf<Note?>(null)
        private set

    /** When the group's recovery key was made, on the root phone while the group has one. */
    var recoveryMade by mutableStateOf<java.time.Instant?>(null)
        private set

    /** What the last change to the recovery key said. */
    var recoveryNote by mutableStateOf<Note?>(null)

    /** What the screen asks while the phone waits for a YubiKey over NFC: a string, or null when it does not wait. */
    var cardPrompt by mutableStateOf<Int?>(null)
        private set

    /** What the last try to make the watch an admin said. */
    var watchNote by mutableStateOf<Note?>(null)
        private set

    /**
     * The phone as the group's hub as Settings and Home show it: null on a
     * phone that cannot be the hub. home tells whether the phone is on one
     * of the hub's home networks now.
     */
    data class Hub(
        val on: Boolean,
        val status: HubOnPhone.Status,
        val error: Note? = null,
        val forwarder: HubState.Forwarder? = null,
        val background: Boolean = false,
        val home: Boolean = false,
        val clients: Int = 0,
        /** How its tunnel hides. */
        val disguise: HubOnPhone.Disguise = HubOnPhone.Disguise.PLAIN,
        /** The connected computers the hub can move to: admins, or computers the root can make admins; by ID, with their names. */
        val computers: List<Pair<String, String>> = emptyList(),
        /** The computer that is always on which the app suggests as the hub, unless the user chose to keep the phone. */
        val suggested: Pair<String, String>? = null,
        /** The project's forwarder does not take it and the phone holds no signed entry points that have not expired: a new list may be what it needs. */
        val entriesStale: Boolean = false,
    )

    var hub by mutableStateOf<Hub?>(null)
        private set

    /** What the last change to the hub said, when it failed. */
    var hubNote by mutableStateOf<Note?>(null)
        private set

    /** The registration's last error, logged once. */
    private var hubError: String? = null

    /**
     * The phone at a blind relay as Settings shows it (docs/design.md,
     * "Blind relay"): where it stands, why the relay does not take it, the
     * relay, and the group's devices there and the connections through it.
     */
    data class BlindRelay(
        val status: RelayOnPhone.Status,
        val error: Note? = null,
        val relay: HubState.Forwarder? = null,
        val online: Int = 0,
        val through: Int = 0,
    )

    var blindRelay by mutableStateOf<BlindRelay?>(null)
        private set

    /** What the last change to the relay said, when it failed. */
    var relayNote by mutableStateOf<Note?>(null)
        private set

    /** The relay's last error, logged once. */
    private var relayError: String? = null

    /**
     * A remote invitation as Settings shows it: when it expires, the file to
     * share, and the device waiting for the user's answer.
     */
    data class Invite(val expires: Instant, val file: File, val request: PairingMember.Request? = null)

    var invite by mutableStateOf<Invite?>(null)
        private set

    /** How the last invitation ended, or why it did not open. */
    var inviteNote by mutableStateOf<Note?>(null)
        private set

    /** The update of an APK installed from a release (ApkUpdate), and its state for Settings. */
    val apkUpdate = ApkUpdate(app)
    var apkState by mutableStateOf(apkUpdate.state)
        private set

    init {
        apkUpdate.onChange = { apkState = apkUpdate.state }
    }

    private var invitation: LiveGroup.Invitation? = null
    private var answer: CompletableDeferred<Boolean>? = null
    private val main = Handler(Looper.getMainLooper())

    fun choose(color: String) {
        settings.color = color
        this.color = color
        WatchLink.update(app, this)
    }

    fun choose(appearance: Appearance) {
        settings.appearance = appearance
        this.appearance = appearance
    }

    /** Admits a scanned or pasted device; on success the app goes Home. */
    suspend fun scanned(text: String): Boolean {
        if (text.trim().startsWith(RECOVERY_QR)) return restore(text.trim())
        val jc = read(text)
        if (jc == null) {
            message = Note(R.string.not_a_code, error = true)
            return false
        }
        busy = true
        retries = 0
        try {
            group.admit(jc) { retries++ }
            phase = Phase.HOME
            message = null
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
            return false
        } finally {
            busy = false
            retries = 0
            update()
        }
    }

    /**
     * Restores the group with the recovery key from the sheet's QR code, on
     * a phone without a group: the claim goes out, the app goes Home, and
     * Home shows the time left until this phone becomes the root.
     */
    suspend fun restore(text: String): Boolean {
        if (phase != Phase.START) {
            message = Note(R.string.error_restore_has_group, error = true)
            return false
        }
        busy = true
        try {
            val sheet = when (val r = withContext(Dispatchers.IO) { Core.readRecoverySheet(text) }) {
                is Core.SheetReading.Key -> r.key
                is Core.SheetReading.Refused -> {
                    message = Note(R.string.error_sheet, if (settings.showsErrorDetails) r.message else null, error = true)
                    return false
                }
            }
            group.restore(sheet)
            phase = Phase.HOME
            message = Note(R.string.restore_started)
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
            return false
        } finally {
            busy = false
            update()
        }
    }

    /** At the first launch: makes this phone's own key and says so once, with what to do next. */
    suspend fun prepare() {
        if (phase != Phase.START || settings.welcomed) return
        try {
            withContext(Dispatchers.IO) { group.prepare() }
            welcome = true
        } catch (e: Exception) {
            message = describe(e)
        }
    }

    /** Hides the note for good. */
    fun dismissWelcome() {
        welcome = false
        settings.welcomed = true
    }

    /** Opens the screen that joins another phone's group. */
    fun startJoining() {
        dismissWelcome()
        message = null
        phase = Phase.JOINING
    }

    /**
     * Joins another phone's group: shows this phone's QR code until an
     * admin phone scans it, then goes Home. The join screen runs it as its
     * effect, so leaving the screen cancels it and stops listening.
     */
    suspend fun join() {
        try {
            group.join { code -> joinCode = code }
            update()
            phase = Phase.HOME
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
        } finally {
            joinCode = null
        }
    }

    /** Opens the screen that joins a computer's group with the code cbb pair shows. */
    fun startJoiningComputer() {
        dismissWelcome()
        message = null
        phase = Phase.JOINING_COMPUTER
    }

    /**
     * Joins a computer's group with the code the user typed from cbb pair on
     * the group's root, then goes Home. A wrong code may be typed again: the
     * computer's window takes three attempts.
     */
    suspend fun joinComputer(code: String) {
        busy = true
        message = null
        try {
            group.joinComputer(code)
            update()
            phase = Phase.HOME
        } catch (e: CancellationException) {
            throw e
        } catch (e: PairingJoiner.Failure) {
            message = describe(e, if (e.code == Pairing.ErrorCode.WRONG_CODE) R.string.error_join_wrong_code else R.string.error_join_computer)
        } catch (e: Exception) {
            message = describe(e)
        } finally {
            busy = false
        }
    }

    /** Leaves the join screen without joining. */
    fun cancelJoin() {
        joinCode = null
        message = null
        phase = Phase.START
    }

    /** The one big button. */
    suspend fun sync() {
        busy = true
        try {
            val (result, fetched) = withContext(Dispatchers.IO) { group.sync { Clipboard.readForSync(app) } }
            when (fetched) {
                is LiveGroup.Got.Text -> Clipboard.write(app, fetched.text, fetched.kind)
                is LiveGroup.Got.Image -> Clipboard.writeImage(app, fetched.file, fetched.alt)
                is LiveGroup.Got.Files -> {}
                null -> {}
            }
            message = if (fetched is LiveGroup.Got.Files) Note(R.string.files_saved) else Note(
                when (result) {
                    LiveGroup.SyncResult.SENT -> R.string.sent
                    LiveGroup.SyncResult.FETCHED -> R.string.fetched
                    LiveGroup.SyncResult.NOTHING_NEW -> R.string.nothing_new
                },
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
        } finally {
            busy = false
            update()
        }
    }

    /**
     * The one button without the app: the tile, the notification, Share
     * and the selection menu. With the app perhaps just started for it, it
     * waits up to waitMS for a computer to connect; then it sends text, or
     * syncs by the button's rule. Returns what it says.
     */
    suspend fun syncFromOutside(text: String?, waitMS: Long = 5_000): Note {
        val deadline = System.currentTimeMillis() + waitMS
        while (group.hasGroup && System.currentTimeMillis() < deadline && !withContext(Dispatchers.IO) { group.online }) delay(250)
        if (text == null) {
            sync()
            return message ?: Note(R.string.nothing_new)
        }
        message = try {
            Note(if (withContext(Dispatchers.IO) { group.send(text) } == LiveGroup.SyncResult.SENT) R.string.sent else R.string.nothing_new)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        return message!!
    }

    /**
     * Sends the images or files another app shared, which the computers
     * fetch from this phone; with the app perhaps just started for it, it
     * waits up to waitMS for a computer to connect. Returns what it says.
     */
    suspend fun sendShared(uris: List<android.net.Uri>, waitMS: Long = 5_000): Note {
        val deadline = System.currentTimeMillis() + waitMS
        while (group.hasGroup && System.currentTimeMillis() < deadline && !withContext(Dispatchers.IO) { group.online }) delay(250)
        message = try {
            withContext(Dispatchers.IO) { group.sendShared(Files.read(app, uris)) }
            Note(R.string.files_sent)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        return message!!
    }

    /** Updates the devices and which of them are online. */
    suspend fun refresh() {
        update()
    }

    private suspend fun update() {
        val (d, admin) = withContext(Dispatchers.IO) { group.devices to group.isAdmin }
        devices = d
        isAdmin = admin
        val (root, a) = withContext(Dispatchers.IO) { group.isRoot to group.alerts }
        isRoot = root
        alerts = a
        handedOver = withContext(Dispatchers.IO) { group.handedOver }
        removed = withContext(Dispatchers.IO) { group.removed }
        recoveryMade = if (root) withContext(Dispatchers.IO) { group.recoveryMade } else null
        keyLevel = withContext(Dispatchers.IO) { group.keyLevel }
        incomingMS = if (admin) withContext(Dispatchers.IO) { group.incomingMS } else null
        notifier.observe(d)
        away = group.awayFromHome?.let { a ->
            // The last failure only while it is still trying; once connected or at home it is old news.
            val e = (a.lastError as? Exception)?.takeIf { a.status == AwayFromHome.Status.CONNECTING }
            notifier.away(a.isOn && e != null)
            // AwayFromHome logs each failure itself.
            Away(a.isOn, a.status, e?.let { describe(it, R.string.away_error, log = false) })
        }
        hub = withContext(Dispatchers.IO) {
            group.phoneHub?.let { h ->
                val (status, error) = h.status(paused = !group.inForeground && !h.background)
                if (error != hubError) {
                    hubError = error
                    if (error != null) Log.w(TAG, "the hub: $error")
                }
                Hub(
                    h.isOn, status,
                    error?.let { Note(R.string.hub_failed, if (settings.showsErrorDetails) it else null, error = true) },
                    h.forwarder, h.background, group.onHomeNetwork, h.clients.size,
                    computers = if (h.isOn) {
                        group.computers.filter { it.online && !it.throughHub && it.role == "full" && (it.admin || it.canMakeAdmin) }.map { it.id to it.name }
                    } else {
                        emptyList()
                    },
                    suggested = group.suggestedHub?.takeIf { h.isOn && !settings.keepsPhoneHub }?.let { it.id to it.name },
                    disguise = h.disguise,
                    entriesStale = status == HubOnPhone.Status.FAILED && h.forwarder?.isProject == true && group.entriesStale,
                )
            }
        }
        blindRelay = withContext(Dispatchers.IO) {
            group.blindRelay?.let { r ->
                val (status, report, error) = r.status(paused = false)
                if (error != relayError) {
                    relayError = error
                    if (error != null) Log.w(TAG, "the relay: $error")
                }
                BlindRelay(
                    status,
                    error?.let { Note(R.string.relay_failed, if (settings.showsErrorDetails) it else null, error = true) },
                    r.relay, report.online.size, report.through,
                )
            }
        }
        WatchLink.update(app, this)
    }

    /**
     * Meets the group at the blind relay at address with the key pin, as
     * cbb relay prints them, after the user read what it learns; both
     * empty leave it.
     */
    suspend fun setRelay(address: String, pin: String) {
        relayNote = try {
            if (address.isBlank() != pin.isBlank()) throw IllegalArgumentException("both or neither")
            if (pin.isNotBlank() && !HubState.validPin(pin.trim())) throw IllegalArgumentException("not a pin")
            withContext(Dispatchers.IO) { group.setRelay(address, pin) }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: IllegalArgumentException) {
            describe(e, R.string.relay_bad)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Makes this phone the group's hub, or stops it being the hub. */
    suspend fun setHub(on: Boolean) = hubChange { group.setPhoneHub(on) }

    /**
     * Makes a connected computer the hub in place of this phone
     * (docs/protocol.md, section 11, "Moving the hub"); the reason it
     * refused, if it does, shows under the message.
     */
    suspend fun moveHub(id: String) {
        hubNote = try {
            group.moveHub(id)
            Note(R.string.hub_moved)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(R.string.hub_move_refused), e)
            Note(R.string.hub_move_refused, e.reason, error = true)
        } catch (e: HubOnPhone.NotRunning) {
            describe(e, R.string.hub_move_not_running)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Keeps this phone as the hub: the app no longer suggests a computer. */
    suspend fun keepPhoneHub() {
        settings.keepsPhoneHub = true
        update()
    }

    /** Sets the hub's forwarder; both empty for a hub at home only. */
    suspend fun setForwarder(address: String, pin: String) = hubChange {
        if ((address.isBlank() || pin.isBlank()) && !(address.isBlank() && pin.isBlank())) throw IllegalArgumentException("both or neither")
        if (pin.isNotBlank() && !HubState.validPin(pin.trim())) throw IllegalArgumentException("not a pin")
        group.setForwarder(address, pin)
    }

    /** Sets how the hub's tunnel hides: plain WireGuard, AmneziaWG or VLESS. */
    suspend fun setHubDisguise(d: HubOnPhone.Disguise) = hubChange { group.setHubDisguise(d) }

    /** Lets the hub run in the background, at the battery's cost. */
    suspend fun setHubInBackground(on: Boolean) = hubChange { group.setHubInBackground(on) }

    /** Remembers the network the phone is on as home. */
    suspend fun addHomeNetwork() {
        hubChange { if (!group.addHomeNetwork()) throw NoHomeNetwork() }
    }

    /** The phone is on no Wi-Fi or Ethernet network to call home. */
    private class NoHomeNetwork : Exception("the phone is on no Wi-Fi or Ethernet network with an address")

    private suspend fun hubChange(f: () -> Unit) {
        hubNote = try {
            withContext(Dispatchers.IO) { f() }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: NoHomeNetwork) {
            describe(e, R.string.hub_no_network)
        } catch (e: IllegalArgumentException) {
            describe(e, R.string.hub_bad_forwarder)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /**
     * Opens a remote invitation for a device far away (docs/protocol.md,
     * section 12), valid for an hour: Settings shares its file, and asks
     * the user about the device that uses it.
     */
    suspend fun openInvite() {
        if (invite != null) return
        inviteNote = try {
            val inv = withContext(Dispatchers.IO) { group.invite(INVITE_SECONDS, ::ask) { r -> main.post { inviteEnded(r) } } }
            val file = withContext(Dispatchers.IO) { Invitations.write(app, inv.text) }
            invitation = inv
            invite = Invite(inv.expires, file)
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: HubOnPhone.NotRunning) {
            describe(e, R.string.invite_no_hub)
        } catch (e: Exception) {
            describe(e)
        }
    }

    /** Asks the user about a device that used the invitation, for up to 5 minutes. */
    private suspend fun ask(req: PairingMember.Request): Boolean = withContext(Dispatchers.Main) {
        val d = CompletableDeferred<Boolean>()
        answer = d
        invite = invite?.copy(request = req)
        val yes = withTimeoutOrNull(CONFIRM_MS) { d.await() } ?: false
        invite = invite?.copy(request = null)
        yes
    }

    /** The user's answer about the device that used the invitation. */
    fun answer(yes: Boolean) {
        answer?.complete(yes)
        answer = null
    }

    /** Cancels the open invitation. */
    fun cancelInvite() {
        invitation?.cancel?.invoke()
    }

    private fun inviteEnded(r: Result<String>) {
        invite?.file?.let(Invitations::delete)
        invite = null
        invitation = null
        answer?.complete(false)
        answer = null
        inviteNote = r.fold(
            { Note(R.string.invite_admitted) },
            { e ->
                val code = (e as? InvitationWindow.Ended)?.code
                when (code) {
                    Pairing.ErrorCode.CLOSED -> null
                    Pairing.ErrorCode.EXPIRED -> Note(R.string.invite_expired)
                    Pairing.ErrorCode.TOO_MANY -> Note(R.string.invite_too_many, error = true)
                    else -> describe(e as? Exception ?: Exception(e))
                }
            },
        )
    }

    /** Turns sync away from home on or off; the hub's answer comes on the next connection at home. */
    suspend fun setAway(on: Boolean) {
        awayNote = try {
            withContext(Dispatchers.IO) { group.setAwayFromHome(on) }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Removes a device from the group. */
    suspend fun remove(id: String) {
        message = try {
            group.remove(id)
            Note(R.string.removed)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /**
     * Takes this phone out of its group (D-83) and goes back to the Start
     * screen, with a new key of its own for the next group. True when it
     * left.
     */
    suspend fun leave(): Boolean {
        busy = true
        try {
            withContext(Dispatchers.IO) { group.leave() }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
            return false
        } finally {
            busy = false
        }
        SyncService.stop(app)
        notifier.forget()
        try {
            withContext(Dispatchers.IO) { group.prepare() }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "no new key after leaving", e)
        }
        phase = Phase.START
        message = null
        update()
        WatchLink.update(app, this)
        return true
    }

    /** Gives a device another name. */
    suspend fun rename(id: String, name: String) {
        message = try {
            group.rename(id, name)
            Note(R.string.renamed)
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneGroup.Failure) {
            if (e.message == PhoneGroup.INVALID_NAME) Note(R.string.rename_invalid, error = true) else describe(e)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Runs a quick action on a computer; true when it did, else the reason shows under the message. */
    suspend fun runAction(id: String, name: String): Boolean = command(R.string.action_done, R.string.error_action_refused) { group.runAction(id, name) }

    /** Turns every quick action off on a computer. */
    suspend fun actionsOff(id: String): Boolean = command(R.string.actions_off_done, R.string.error_action_refused) { group.actionsOff(id) }

    private suspend fun command(done: Int, refused: Int, run: suspend () -> Unit): Boolean {
        var ok = false
        message = try {
            run()
            ok = true
            Note(done)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(refused), e)
            Note(refused, e.reason, error = true)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        update()
        return ok
    }

    /** Puts text where a computer's focus is; true when it did, else the reason shows under the message. */
    suspend fun paste(id: String, text: String, method: String, enter: Boolean, secret: Boolean): Boolean {
        var done = false
        message = try {
            group.paste(id, text, method, enter, secret)
            done = true
            Note(R.string.pasted)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(R.string.error_paste_refused), e)
            Note(R.string.error_paste_refused, e.reason, error = true)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        return done
    }

    /** Ends a conflict or cancels a claim as the group's root: voids the alert's records. */
    suspend fun resolve(alert: GroupAlert) {
        message = try {
            group.resolve(alert.records)
            when (alert.kind) {
                GroupAlert.Kind.CLAIMS, GroupAlert.Kind.CLAIM_PENDING, GroupAlert.Kind.CLAIM_STOPPED -> Note(R.string.claim_cancelled)
                else -> Note(R.string.histories_voided)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Takes the group the root handed to this phone (cbb handover), after the fingerprint or the screen lock. */
    suspend fun takeHandedGroup() {
        message = try {
            group.takeHandedGroup()
            Note(R.string.handed_taken)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Unfreezes an admin computer that another admin froze. */
    suspend fun unfreeze(id: String) {
        message = try {
            group.unfreeze(id)
            Note(R.string.unfrozen)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Sets a device's sync mode, this phone's own without a command; the reason a device refused, if it does, shows under the message. */
    /** This phone's pause of the group's copies; null while it takes them. */
    val pause: LiveGroup.Hold? get() = devices.firstOrNull { it.isSelf }?.paused

    /**
     * Keeps the group's copies out of this phone for forMS milliseconds, 0
     * for until the user takes them again; null takes them again now. Its
     * own copies still go out.
     */
    suspend fun pauseReceiving(forMS: Long?) {
        message = try {
            withContext(Dispatchers.IO) { group.pauseReceiving(forMS) }
            Note(if (forMS == null) R.string.pause_off else R.string.pause_on)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Mutes a device for the whole group for forMS milliseconds, 0 for until it is unmuted, or unmutes it. */
    suspend fun setMuted(id: String, on: Boolean, forMS: Long = 0) {
        message = try {
            group.setMuted(id, on, forMS)
            Note(if (on) R.string.mute_done else R.string.unmute_done)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(R.string.error_command_refused), e)
            Note(R.string.error_command_refused, e.reason, error = true)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    suspend fun setMode(id: String, mode: String) {
        message = try {
            if (devices.firstOrNull { it.id == id }?.isSelf == true) withContext(Dispatchers.IO) { group.setOwnMode(mode) } else group.setMode(id, mode)
            Note(R.string.mode_set)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(R.string.error_command_refused), e)
            Note(R.string.error_command_refused, e.reason, error = true)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /**
     * Makes the connected Wear OS watch an admin with a key of its own, for
     * the emergency actions (docs/protocol.md, section 10, "Watches"): the
     * watch makes the key, and the root signs after the user confirms.
     */
    suspend fun addWatch() {
        watchNote = try {
            val request = WatchLink.keyRequest(app)
            WatchLink.admit(app, group.addWatch(request))
            Note(R.string.watch_made_admin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: WatchLink.NotReachable) {
            Note(R.string.watch_not_reachable, error = true)
        } catch (e: WatchLink.NotProtected) {
            Note(R.string.watch_not_protected, error = true)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /**
     * Makes the group's recovery key and returns its sheet, which only the
     * screen that shows it keeps; null when it failed, with recoveryNote
     * saying why.
     */
    suspend fun makeRecovery(): Core.RecoverySheet? {
        val sheet = try {
            group.makeRecovery().also { recoveryNote = null }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            recoveryNote = describe(e)
            null
        }
        update()
        return sheet
    }

    /**
     * Puts the group's recovery key on a YubiKey held to the phone; true
     * when it is there, with recoveryNote saying so, or why not.
     */
    suspend fun makeRecoveryOnCard(pin: String): Boolean {
        val ok = try {
            cardPrompt = R.string.yubikey_hold
            group.makeRecoveryOnCard(pin)
            recoveryNote = Note(R.string.yubikey_made)
            true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            recoveryNote = describe(e)
            false
        } finally {
            cardPrompt = null
        }
        update()
        return ok
    }

    /**
     * Restores the group with the recovery key on a YubiKey, on a phone
     * without a group, as [restore] does with the sheet.
     */
    suspend fun restoreWithCard(pin: String): Boolean {
        if (phase != Phase.START) {
            message = Note(R.string.error_restore_has_group, error = true)
            return false
        }
        busy = true
        try {
            cardPrompt = R.string.yubikey_hold
            group.restoreWithCard(pin) { cardPrompt = R.string.yubikey_hold_again }
            phase = Phase.HOME
            message = Note(R.string.restore_started)
            return true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message = describe(e)
            return false
        } finally {
            cardPrompt = null
            busy = false
            update()
        }
    }

    /** Removes the group's recovery key. */
    suspend fun removeRecovery() {
        recoveryNote = try {
            group.removeRecovery()
            Note(R.string.recovery_removed)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Sets which keys may be the group's admins and hubs. */
    suspend fun setKeyLevel(level: String) {
        keyLevelNote = try {
            group.setKeyLevel(level)
            Note(R.string.key_level_saved)
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneGroup.BelowKeyLevel) {
            Note(R.string.key_level_own_key)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Sets how long a copy from another device stays live after it arrives. */
    suspend fun setIncoming(ms: Long) {
        incomingNote = try {
            group.setIncoming(ms)
            Note(R.string.incoming_saved)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** Makes a computer an admin, after the dialog that warns when its keys sit in a file. */
    suspend fun makeAdmin(id: String) {
        message = try {
            group.makeAdmin(id, allowFileKey = true)
            Note(R.string.made_admin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /**
     * Makes a connected computer a hub of the group as well
     * (docs/protocol.md, section 11, "Several hubs"): one that reads the
     * copies, an admin, or one that only passes them on; the reason it
     * refused, if it does, shows under the message.
     */
    suspend fun makeHub(id: String, forwardOnly: Boolean = false) {
        message = try {
            group.makeHub(id, forwardOnly)
            Note(if (forwardOnly) R.string.made_hub_forward_only else R.string.made_hub)
        } catch (e: CancellationException) {
            throw e
        } catch (e: LiveGroup.CommandRefused) {
            Log.e(TAG, app.getString(R.string.make_hub_refused), e)
            Note(R.string.make_hub_refused, e.reason, error = true)
        } catch (e: MemberNode.ProtocolException) {
            describe(e, R.string.error_no_answer)
        } catch (e: Exception) {
            describe(e)
        }
        update()
    }

    /** A tile below this phone's: a device, or a collection with its devices as the group lists them. */
    sealed interface Arranged {
        val key: String
        val ref: Arrangement.Ref

        data class Device(val device: LiveGroup.Device) : Arranged {
            override val key get() = "d:" + device.id
            override val ref get() = Arrangement.Ref.Device(device.id)
        }

        data class Collection(val collection: Arrangement.Item.Collection, val devices: List<LiveGroup.Device>) : Arranged {
            override val key get() = "c:" + collection.id
            override val ref get() = Arrangement.Ref.Collection(collection.id)
        }
    }

    /** This phone's own ID: first in the arrangement until the user moves it. */
    private val selfId: String? get() = devices.firstOrNull { it.isSelf }?.id

    /** The devices and collections, this phone among them, in the user's order: the group's order, this phone first, until the user changes it. */
    val arranged: List<Arranged>
        get() {
            val a = arrangement ?: return devices.sortedByDescending { it.isSelf }.map { Arranged.Device(it) }
            val byId = devices.associateBy { it.id }
            return a.view(devices.map { it.id }, selfId).mapNotNull { item ->
                when (item) {
                    is Arrangement.Item.Device -> byId[item.id]?.let { Arranged.Device(it) }
                    is Arrangement.Item.Collection -> Arranged.Collection(item, item.devices.mapNotNull { byId[it] })
                }
            }
        }

    /** The collection with the ID, as Home shows it. */
    fun collection(id: String): Arranged.Collection? =
        arranged.firstNotNullOfOrNull { (it as? Arranged.Collection)?.takeIf { c -> c.collection.id == id } }

    /** The collections that a device can go into: every one but its own. */
    fun collections(apartFrom: String): List<Arrangement.Item.Collection> =
        arranged.mapNotNull { (it as? Arranged.Collection)?.collection?.takeIf { c -> apartFrom !in c.devices } }

    /** The collection a device is in, if any. */
    fun collectionHolding(device: String): Arrangement.Item.Collection? =
        arranged.firstNotNullOfOrNull { (it as? Arranged.Collection)?.collection?.takeIf { c -> device in c.devices } }

    /**
     * Reads the group's arrangement once its tag is known, and drops the
     * devices that left once the list is whole: the group loaded, this
     * phone in it. Until the user changes something nothing is stored.
     */
    private fun loadArrangement() {
        val tag = group.groupTag ?: run {
            arrangement = null
            return
        }
        val stored = settings.deviceArrangement
        val current = arrangement?.takeIf { it.group == tag }
        // A copy: the state's own object never changes, so Compose sees each change.
        val a = Arrangement.decode(current?.encode() ?: stored, tag)
        if (selfId != null && stored != null) {
            val before = a.encode()
            a.prune(devices.map { it.id })
            if (a.encode() != before) settings.deviceArrangement = a.encode()
        }
        if (current == null || current.encode() != a.encode()) arrangement = a
    }

    /** Makes a change to the arrangement and keeps it; one that does not fit leaves it as it was and says so. */
    fun arrange(op: Arrangement.Op): Boolean {
        val a = arrangement?.let { Arrangement.decode(it.encode(), it.group) } ?: return false
        try {
            a.apply(op, devices.map { it.id }, selfId)
        } catch (e: Arrangement.Refused) {
            message = describe(e)
            return false
        }
        settings.deviceArrangement = a.encode()
        arrangement = a
        return true
    }

    /** Makes a collection of the devices and returns its ID; null when it does not fit (a name too long, too many collections). */
    fun newCollection(name: String, devices: List<String>): String? {
        val before = collectionIds()
        if (!arrange(Arrangement.Op.New(name, devices))) return null
        return collectionIds().firstOrNull { it !in before }
    }

    private fun collectionIds(): List<String> =
        arrangement?.items.orEmpty().mapNotNull { (it as? Arrangement.Item.Collection)?.id }

    /** The message for an error, with the error itself below it when details are on. The error is logged either way. */
    fun describe(e: Exception, @StringRes text: Int = summary(e), log: Boolean = true): Note {
        if (log) Log.e(TAG, app.getString(text), e)
        return Note(text, if (settings.showsErrorDetails) e.toString() + (e.cause?.let { "\n" + it } ?: "") else null, error = true)
    }

    companion object {
        private const val TAG = "cbb"

        /** How long an invitation from the phone is valid: an hour, as cbb invite's default. */
        const val INVITE_SECONDS = 3600

        /** How long the user may take to confirm a device that used an invitation (docs/protocol.md, section 12). */
        const val CONFIRM_MS = 5 * 60_000L

        /** How the QR code of a recovery sheet starts (docs/protocol.md, section 10, "The recovery key"). */
        const val RECOVERY_QR = "cbb://recover?"

        /** Reads what the camera saw, or what the user pasted: the text of the QR code of cbb pair or of another phone. */
        fun read(text: String): JoinCode? {
            val jc = JoinCode.parse(text) ?: return null
            return if (jc.codeIsValid && jc.addrs.isNotEmpty() && jc.fingerprint.isNotEmpty()) jc else null
        }

        @StringRes
        fun summary(e: Exception): Int = when (e) {
            is LiveGroup.Failure -> when (e.kind) {
                LiveGroup.Failure.Kind.NOT_CONFIRMED -> R.string.error_not_confirmed
                LiveGroup.Failure.Kind.NO_NETWORK -> R.string.error_no_network
                LiveGroup.Failure.Kind.TIMED_OUT -> R.string.error_timed_out
                LiveGroup.Failure.Kind.TOO_MANY_WRONG_CODES -> R.string.error_too_many_codes
                LiveGroup.Failure.Kind.NOT_ADMIN -> R.string.error_not_admin
                LiveGroup.Failure.Kind.NO_COMPUTERS -> R.string.no_computers
                LiveGroup.Failure.Kind.NO_SCREEN, LiveGroup.Failure.Kind.UNREACHABLE -> R.string.error_unreachable
                LiveGroup.Failure.Kind.NO_WINDOW -> R.string.error_no_window
                LiveGroup.Failure.Kind.TWO_WINDOWS -> R.string.error_two_windows
                LiveGroup.Failure.Kind.NEEDS_ROOT -> R.string.error_needs_root
                LiveGroup.Failure.Kind.NO_GROUP_COMPUTER -> R.string.error_no_group_computer
                LiveGroup.Failure.Kind.NO_GROUP -> R.string.error_nothing_to_leave
                LiveGroup.Failure.Kind.ROOT_LEAVES -> R.string.error_root_leaves
            }
            is Restore.Failure -> when (e.kind) {
                Restore.Kind.NEEDS_QR -> R.string.error_restore_needs_qr
                Restore.Kind.OTHER_GROUP -> R.string.error_restore_other_group
                Restore.Kind.NOT_THE_KEY -> R.string.error_restore_not_the_key
                Restore.Kind.NOT_A_MEMBER -> R.string.error_restore_not_a_member
            }
            is Piv.Failure -> when (e.kind) {
                Piv.Kind.NO_PIV -> R.string.error_yubikey_no_piv
                Piv.Kind.WRONG_PIN -> R.string.error_yubikey_wrong_pin
                Piv.Kind.BLOCKED -> R.string.error_yubikey_blocked
                Piv.Kind.MANAGEMENT_KEY -> R.string.error_yubikey_management_key
                Piv.Kind.OLD_FIRMWARE -> R.string.error_yubikey_old
                Piv.Kind.NO_FREE_SLOT -> R.string.error_yubikey_full
                Piv.Kind.NO_KEY -> R.string.error_yubikey_no_key
                Piv.Kind.CARD -> R.string.error_yubikey
            }
            is YubiKeyNfc.Unavailable -> if (e.off) R.string.error_nfc_off else R.string.error_no_nfc
            is YubiKeyNfc.NoCard -> R.string.error_yubikey_none
            is Clipboard.Unreadable -> R.string.error_clipboard_unreadable
            is Content.TooLarge -> R.string.error_image_too_large
            is Arrangement.Refused -> R.string.error_arrangement
            is Content.Unread -> R.string.error_copy_unread
            is CopyKeys.NoRecords -> R.string.error_copy_no_records
            is MemberNode.Muted -> R.string.error_muted
            is MemberNode.MissingException, is MemberNode.ProtocolException, is Content.Mismatch -> R.string.error_image_unavailable
            is PairingMember.Failure ->
                if (e.code == Pairing.ErrorCode.WRONG_CODE) R.string.error_wrong_code else R.string.error_refused
            is PhoneGroup.Failure -> R.string.error_generic
            is PhoneGroup.FileKey -> R.string.error_file_key
            is PhoneGroup.BelowKeyLevel -> R.string.error_below_key_level
            is PhoneGroup.Rootless -> R.string.error_rootless
            is PhoneGroup.ReadsCopies -> R.string.error_reads_copies
            is PairingJoiner.Failure -> R.string.error_join
            is Keys.NoScreenLock -> R.string.error_no_screen_lock
            is Keys.NoBiometric -> R.string.error_no_biometric
            is Keys.OldKey -> R.string.error_old_key
            is Authenticator.Cancelled -> R.string.error_not_authenticated
            is TLSTransport.Failure, is java.io.IOException -> R.string.error_unreachable
            else -> R.string.error_generic
        }
    }
}
