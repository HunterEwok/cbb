// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothHidDeviceAppSdpSettings
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.hunterewok.clipboardbridge.kit.Keyboard
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors

/**
 * This phone as a Bluetooth keyboard (docs/roadmap.md, item 25, way 3):
 * the HID Device profile types a text into a TV, a tablet, a console or a
 * computer the phone is paired with, which needs nothing installed. The
 * user picks the host among the paired devices and the layout active on
 * it; remote pastes may go there instead of this phone's focused field.
 *
 * Only one app at a time can be a HID device, and the Bluetooth stack
 * forgets the registration when it restarts, so it registers again then.
 * A few makers leave the profile out of their builds; the phone then says
 * it cannot act as a keyboard.
 */
class BluetoothKeyboard(private val context: Context, dir: File) {
    /** Where the keyboard stands, for the settings screen. */
    sealed interface State {
        /** Off in the settings. */
        data object Off : State

        /** The phone has no Bluetooth, or its maker left the HID Device profile out. */
        data class Unsupported(val detail: String) : State

        /** The app may not use Bluetooth yet: the user answers the system's question. */
        data object NoPermission : State

        /** Bluetooth is off on the phone. */
        data object BluetoothOff : State

        /** Getting the profile and registering as a keyboard. */
        data object Starting : State

        /** Another app is the phone's keyboard, or the registration failed. */
        data class Refused(val detail: String) : State

        /** Registered; connecting to host, or waiting for the user to pick one. */
        data class Ready(val host: String?) : State

        /** Connected to the host, by its address and name. */
        data class Connected(val host: String, val name: String) : State
    }

    /** Why a text was not typed, in words for the user or the sender; detail is the underlying error. */
    class Failure(val reason: String, val refused: Boolean = true, val detail: String? = null, val chars: List<String> = emptyList())

    private val file = File(dir, "keyboard.json")
    private val main = Handler(Looper.getMainLooper())
    private val typing = Executors.newSingleThreadExecutor { r -> Thread(r, "keyboard").apply { isDaemon = true } }
    private val _state = MutableStateFlow<State>(State.Off)
    val state: StateFlow<State> = _state.asStateFlow()

    // On the main thread.
    private var hid: BluetoothHidDevice? = null
    private var registered = false
    private var connected: BluetoothDevice? = null
    private var retried = false

    var settings: Keyboard.Settings
        get() = runCatching { Keyboard.Settings.decode(file.readBytes()) }.getOrDefault(Keyboard.Settings())
        set(s) {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeBytes(s.encode())
            if (!tmp.renameTo(file)) throw IOException("cannot save ${file.name}")
        }

    private val adapter: BluetoothAdapter? get() = context.getSystemService(BluetoothManager::class.java)?.adapter

    /** Whether the app may use Bluetooth: BLUETOOTH_CONNECT from Android 12, granted at install before. */
    fun permitted(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
        context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED

    /** The devices the phone is paired with, which may be the host, by name. */
    @SuppressLint("MissingPermission")
    fun pairedHosts(): List<Pair<String, String>> {
        if (!permitted()) return emptyList()
        val a = adapter ?: return emptyList()
        return runCatching { a.bondedDevices.orEmpty().map { it.address to (it.name ?: it.address) } }.getOrDefault(emptyList())
            .sortedBy { it.second.lowercase() }
    }

    /** Starts the keyboard when it is on in the settings, or stops it when it is off; again after a permission or Bluetooth changed. */
    fun apply() {
        main.post {
            watchAdapter()
            applyNow()
        }
    }

    private var watching = false

    /** Applies the settings again when Bluetooth is turned on or off. */
    private fun watchAdapter() {
        if (watching) return
        watching = true
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                val st = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                if (st == BluetoothAdapter.STATE_ON || st == BluetoothAdapter.STATE_OFF) {
                    if (st == BluetoothAdapter.STATE_OFF) {
                        hid = null
                        registered = false
                        connected = null
                    }
                    applyNow()
                }
            }
        }
        ContextCompat.registerReceiver(context, r, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED)
    }

    @SuppressLint("MissingPermission")
    private fun applyNow() {
        val s = settings
        if (!s.on) {
            stop()
            _state.value = State.Off
            return
        }
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)) {
            _state.value = State.Unsupported("no Bluetooth (FEATURE_BLUETOOTH)")
            return
        }
        if (!permitted()) {
            _state.value = State.NoPermission
            return
        }
        val a = adapter
        if (a == null) {
            _state.value = State.Unsupported("no Bluetooth adapter")
            return
        }
        if (!a.isEnabled) {
            stop()
            _state.value = State.BluetoothOff
            return
        }
        val h = hid
        if (h == null) {
            _state.value = State.Starting
            val asked = runCatching { a.getProfileProxy(context, listener, BluetoothProfile.HID_DEVICE) }
            if (asked.getOrDefault(false) != true) {
                _state.value = State.Unsupported("getProfileProxy(HID_DEVICE) = ${asked.exceptionOrNull() ?: false}")
                return
            }
            // A build without the profile may take the request and never answer it.
            main.postDelayed({
                if (hid == null && settings.on && _state.value == State.Starting) {
                    _state.value = State.Unsupported("the HID Device profile did not connect within ${PROXY_WAIT_MS / 1000} s")
                }
            }, PROXY_WAIT_MS)
            return
        }
        if (!registered) {
            register(h)
            return
        }
        connectHost(h, s.host)
    }

    private val listener = object : BluetoothProfile.ServiceListener {
        override fun onServiceConnected(profile: Int, proxy: BluetoothProfile) {
            if (profile != BluetoothProfile.HID_DEVICE) return
            main.post {
                hid = proxy as BluetoothHidDevice
                applyNow()
            }
        }

        override fun onServiceDisconnected(profile: Int) {
            main.post {
                hid = null
                registered = false
                connected = null
                if (settings.on) applyNow()
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun register(h: BluetoothHidDevice) {
        _state.value = State.Starting
        val sdp = BluetoothHidDeviceAppSdpSettings(
            context.getString(R.string.keyboard_sdp_name),
            context.getString(R.string.keyboard_sdp_description),
            "CBB",
            BluetoothHidDevice.SUBCLASS1_KEYBOARD,
            Keyboard.DESCRIPTOR,
        )
        val ok = runCatching { h.registerApp(sdp, null, null, { main.post(it) }, callback) }
        if (ok.getOrDefault(false) != true) {
            _state.value = State.Refused("registerApp = ${ok.exceptionOrNull() ?: false}")
        }
    }

    private val callback = object : BluetoothHidDevice.Callback() {
        override fun onAppStatusChanged(pluggedDevice: BluetoothDevice?, registered: Boolean) {
            val was = this@BluetoothKeyboard.registered
            this@BluetoothKeyboard.registered = registered
            if (registered) {
                retried = false
                applyNow()
                return
            }
            connected = null
            if (!settings.on) return
            // Lost: the Bluetooth stack restarted, or another app took the
            // profile. Register again once; after that the user decides.
            if (was && !retried) {
                retried = true
                main.postDelayed({ if (settings.on && !this@BluetoothKeyboard.registered) applyNow() }, RETRY_MS)
            } else {
                _state.value = State.Refused("onAppStatusChanged(registered = false)")
            }
        }

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            when (state) {
                BluetoothProfile.STATE_CONNECTED -> {
                    connected = device
                    // The host connected by itself: it is the one the user wants.
                    if (settings.host != device.address) runCatching { settings = settings.copy(host = device.address) }
                    _state.value = State.Connected(device.address, runCatching { device.name }.getOrNull() ?: device.address)
                }
                BluetoothProfile.STATE_DISCONNECTED -> if (connected?.address == device.address) {
                    connected = null
                    _state.value = State.Ready(settings.host)
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun connectHost(h: BluetoothHidDevice, host: String?) {
        val c = connected
        if (c != null && c.address == host) return
        if (c != null) runCatching { h.disconnect(c) }
        _state.value = State.Ready(host)
        val a = adapter ?: return
        if (host != null) runCatching { h.connect(a.getRemoteDevice(host)) }.onFailure { Log.w(TAG, "connecting the keyboard to $host", it) }
    }

    @SuppressLint("MissingPermission")
    private fun stop() {
        val h = hid ?: return
        if (permitted()) {
            connected?.let { runCatching { h.disconnect(it) } }
            if (registered) runCatching { h.unregisterApp() }
        }
        adapter?.let { a -> runCatching { a.closeProfileProxy(BluetoothProfile.HID_DEVICE, h) } }
        hid = null
        registered = false
        connected = null
        retried = false
    }

    /**
     * Types text on the connected host in the background, at the rate the
     * user set; null when it started, or why not. A text the layout cannot
     * type is refused whole and its characters named, rather than typed as
     * other characters.
     */
    @SuppressLint("MissingPermission")
    fun type(text: String): Failure? {
        val s = settings
        if (!s.on) return Failure("the Bluetooth keyboard is off on this phone; its user turns it on in the app's settings")
        if (text.codePointCount(0, text.length) > MAX_CHARS) return Failure("the text is longer than the $MAX_CHARS characters a keyboard types")
        val reports = s.layout.reports(text) ?: s.layout.untypeable(text).take(8).let {
            return Failure("the host's layout (${s.layout.key}) has no key for " + it.joinToString(" "), chars = it)
        }
        val h = hid
        val host = connected
        if (h == null || host == null || !registered) {
            return Failure("this phone's Bluetooth keyboard is not connected to a device", refused = false, detail = "state ${_state.value}")
        }
        val pause = 1000L / s.rate / 2
        typing.execute {
            for (r in reports) {
                val sent = runCatching { h.sendReport(host, 0, r) }
                if (sent.getOrDefault(false) != true) {
                    Log.w(TAG, "the keyboard stopped typing: sendReport = ${sent.exceptionOrNull() ?: false}")
                    runCatching { h.sendReport(host, 0, Keyboard.RELEASE) }
                    return@execute
                }
                Thread.sleep(pause)
            }
        }
        return null
    }

    companion object {
        private const val TAG = "clipboardbridge"

        /** The longest text it types: at 20 a second, under four minutes. */
        const val MAX_CHARS = 4096

        private const val PROXY_WAIT_MS = 5_000L
        private const val RETRY_MS = 2_000L
    }
}
