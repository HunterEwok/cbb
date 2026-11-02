// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.StringRes
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.github.hunterewok.clipboardbridge.kit.GroupAlert
import io.github.hunterewok.clipboardbridge.kit.Arrangement
import io.github.hunterewok.clipboardbridge.kit.Content
import io.github.hunterewok.clipboardbridge.kit.InvitationWindow
import io.github.hunterewok.clipboardbridge.kit.JoinCode
import io.github.hunterewok.clipboardbridge.kit.MemberNode
import io.github.hunterewok.clipboardbridge.kit.PairingJoiner
import io.github.hunterewok.clipboardbridge.kit.PairingMember
import io.github.hunterewok.clipboardbridge.kit.Pairing
import io.github.hunterewok.clipboardbridge.kit.PhoneGroup
import io.github.hunterewok.clipboardbridge.kit.TLSTransport
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
    enum class Phase { START, JOINING, HOME }

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

    /** The QR code this phone shows while it waits to join a group. */
    var joinCode by mutableStateOf<JoinCode?>(null)
        private set
    var isAdmin by mutableStateOf(group.isAdmin)
        private set

    /** Whether this phone holds the group's root, which ends conflicts. */
    var isRoot by mutableStateOf(false)
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
        /** The connected computers the hub can move to: admins, or computers the root can make admins; by ID, with their names. */
        val computers: List<Pair<String, String>> = emptyList(),
        /** The computer that is always on which the app suggests as the hub, unless the user chose to keep the phone. */
        val suggested: Pair<String, String>? = null,
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
        val jc = read(text)
        if (jc == null) {
            message = Note(R.string.not_a_code, error = true)
            return false
        }
        busy = true
        try {
            group.admit(jc)
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
            val (result, fetched) = withContext(Dispatchers.IO) { group.sync(Clipboard.readForSync(app)) }
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
                        group.computers.filter { it.online && it.role == "full" && (it.admin || it.canMakeAdmin) }.map { it.id to it.name }
                    } else {
                        emptyList()
                    },
                    suggested = group.suggestedHub?.takeIf { h.isOn && !settings.keepsPhoneHub }?.let { it.id to it.name },
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

    /** Lets the hub run in the background, at the battery's cost. */
    suspend fun setHubInBackground(on: Boolean) = hubChange { group.setHubInBackground(on) }

    /** Remembers the network the phone is on as home. */
    suspend fun addHomeNetwork() = hubChange { group.addHomeNetwork() }

    private suspend fun hubChange(f: () -> Unit) {
        hubNote = try {
            withContext(Dispatchers.IO) { f() }
            null
        } catch (e: CancellationException) {
            throw e
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

    /** This phone's own ID, which the arrangement leaves out. */
    private val selfId: String? get() = devices.firstOrNull { it.isSelf }?.id

    /** The devices and collections below this phone, in the user's order: the group's order until the user changes it. */
    val arranged: List<Arranged>
        get() {
            val others = devices.filter { !it.isSelf }
            val a = arrangement ?: return others.map { Arranged.Device(it) }
            val byId = others.associateBy { it.id }
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
        private const val TAG = "clipboardbridge"

        /** How long an invitation from the phone is valid: an hour, as cbb invite's default. */
        const val INVITE_SECONDS = 3600

        /** How long the user may take to confirm a device that used an invitation (docs/protocol.md, section 12). */
        const val CONFIRM_MS = 5 * 60_000L

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
            }
            is Clipboard.Unreadable -> R.string.error_clipboard_unreadable
            is Content.TooLarge -> R.string.error_image_too_large
            is Arrangement.Refused -> R.string.error_arrangement
            is MemberNode.MissingException, is MemberNode.ProtocolException -> R.string.error_image_unavailable
            is PairingMember.Failure ->
                if (e.code == Pairing.ErrorCode.WRONG_CODE) R.string.error_wrong_code else R.string.error_refused
            is PhoneGroup.Failure -> R.string.error_generic
            is PhoneGroup.FileKey -> R.string.error_file_key
            is PhoneGroup.Rootless -> R.string.error_rootless
            is PairingJoiner.Failure -> R.string.error_join
            is Keys.NoScreenLock -> R.string.error_no_screen_lock
            is Authenticator.Cancelled -> R.string.error_not_authenticated
            is TLSTransport.Failure, is java.io.IOException -> R.string.error_unreachable
            else -> R.string.error_generic
        }
    }
}
