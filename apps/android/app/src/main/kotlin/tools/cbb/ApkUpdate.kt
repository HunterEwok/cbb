// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import tools.cbb.kit.Releases
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * The update of an APK installed from a release (docs/apps.md, "Updates"):
 * the signed keys.json, stable.json and release.json from GitHub or
 * dl.cbb.tools, checked as `cbb update` checks them, the release's APK
 * checked against release.json and against this app's signing
 * certificate, then installed by the system's PackageInstaller, without a
 * question once this app installed the one before. A copy from a store is
 * updated by its store, and so is the F-Droid build wherever it came from:
 * it has no installer permission and leaves its updates to F-Droid
 * (docs/apps.md, "F-Droid"). The core checks the release files under the
 * roots it pins; [roots] replaces them in tests, and an empty list leaves
 * the app without updates.
 */
class ApkUpdate(private val context: Context, private val roots: List<Releases.Key>? = null) {
    /** What the user sees in Settings. */
    sealed interface State {
        /** The app came from a store, which updates it; store is its package name. */
        data class Store(val store: String) : State

        /** This build has no root keys to check a release with. */
        data object NoKeys : State

        data object Idle : State

        data object Checking : State

        data class UpToDate(val version: String) : State

        data class Available(val version: String) : State

        data class Installing(val version: String) : State

        /** The release needs minFrom first, which the releases page has. */
        data class TooOld(val version: String, val minFrom: String) : State

        data class Failed(val error: Exception) : State
    }

    private val prefs = context.getSharedPreferences("update", Context.MODE_PRIVATE)
    private val dir = File(context.filesDir, "update")

    @Volatile
    var state: State = initial()
        private set

    /** Called on the main thread whenever [state] changes. */
    var onChange: () -> Unit = {}

    /** Whether the app checks once a day and installs what it finds; off until the user turns it on. */
    var automatic: Boolean
        get() = prefs.getBoolean(AUTO, false)
        set(v) = prefs.edit().putBoolean(AUTO, v).apply()

    private val installed: String get() = versionName(context) ?: ""

    private fun initial(): State {
        if (!BuildConfig.SELF_UPDATE) return State.Store(FDROID)
        installer(context)?.takeIf { it in STORES }?.let { return State.Store(it) }
        if (roots?.isEmpty() == true) return State.NoKeys
        prefs.getString(FAILED, null)?.let { return State.Failed(Exception(it)) }
        return State.Idle
    }

    private fun set(s: State) {
        state = s
        android.os.Handler(context.mainLooper).post { onChange() }
    }

    /** What the last check took, with the highest version seen, which cbb update keeps too: a channel never goes back below it. */
    private fun seen(): Releases.Seen =
        Releases.Seen(
            prefs.getLong(KEYS_SEQ, 0),
            prefs.getLong(CHANNEL_SEQ, 0),
            version = prefs.getString(SEEN_VERSION, "") ?: "",
            channelKeysSeq = prefs.getLong(CHANNEL_KEYS_SEQ, 0),
        )

    /** Checks once a day while [automatic] is on, and installs a newer release it finds. */
    fun runIfDue() {
        if (!automatic || state is State.Store || roots?.isEmpty() == true) return
        val now = System.currentTimeMillis()
        if (now - prefs.getLong(CHECKED, 0) < DAY_MS) return
        start(install = true)
    }

    /** Checks now, on a thread of its own, and with install also installs. */
    fun start(install: Boolean) {
        if (state is State.Store || state is State.NoKeys || state is State.Checking || state is State.Installing) return
        prefs.edit().putLong(CHECKED, System.currentTimeMillis()).remove(FAILED).apply()
        set(State.Checking)
        Thread({
            try {
                val found = check()
                if (found == null) {
                    set(State.UpToDate(installed))
                } else if (install) {
                    install(found)
                }
            } catch (e: NeedsFirst) {
                set(State.TooOld(e.version, e.minFrom))
            } catch (e: Exception) {
                Log.w(TAG, "updating the app: $e", e)
                prefs.edit().putString(FAILED, e.toString()).apply()
                set(State.Failed(e))
            }
        }, "apk update").start()
    }

    /** A release that is newer than this app, checked, with its APK's entry and the server it came from. */
    private class Found(val release: Releases.Release, val apk: Releases.Asset, val base: String)

    @Volatile
    private var found: Found? = null

    private fun check(): Found? {
        var last: Exception? = null
        for (base in SOURCES) {
            try {
                return checkFrom(base)
            } catch (e: Releases.Refused) {
                // A signature that does not check is an answer, not a server down.
                throw e
            } catch (e: NeedsFirst) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "$base: $e")
                last = e
            }
        }
        throw last ?: IllegalStateException("no update server")
    }

    private fun checkFrom(base: String): Found? {
        val keys = Releases.File(get(url(base, KEYS_FILE, null), Releases.MAX_FILE))
        val channel = Releases.File(get(url(base, CHANNEL_FILE, null), Releases.MAX_FILE))
        val named = Releases.named(channel) ?: throw Releases.Refused("$CHANNEL_FILE names no valid release")
        val release = Releases.File(get(url(base, RELEASE_FILE, named), Releases.MAX_FILE))
        val (r, next) = Releases.check(keys, channel, release, roots, CHANNEL, System.currentTimeMillis(), seen())
        prefs.edit().putLong(KEYS_SEQ, next.keysSeq).putLong(CHANNEL_SEQ, next.channelSeq).putLong(CHANNEL_KEYS_SEQ, next.channelKeysSeq)
            .putString(SEEN_VERSION, next.version).apply()
        if (Releases.compare(r.version, installed) <= 0) {
            found = null
            return null
        }
        if (!r.direct(installed)) throw NeedsFirst(r.version, r.minFrom)
        val apk = asset(r) ?: throw Releases.Refused("release ${r.version} has no ${apkName(r.version)}")
        return Found(r, apk, base).also {
            found = it
            set(State.Available(r.version))
        }
    }

    private class NeedsFirst(val version: String, val minFrom: String) : Exception("$version needs $minFrom first")

    /** Installs the release a check found, on a thread of its own. */
    fun install() {
        val f = found ?: return
        if (state is State.Installing) return
        Thread({
            try {
                install(f)
            } catch (e: Exception) {
                Log.w(TAG, "installing ${f.release.version}: $e", e)
                prefs.edit().putString(FAILED, e.toString()).apply()
                set(State.Failed(e))
            }
        }, "apk update").start()
    }

    private fun install(f: Found) {
        set(State.Installing(f.release.version))
        dir.mkdirs()
        dir.listFiles()?.forEach { it.delete() }
        val apk = File(dir, f.apk.name)
        apk.outputStream().use { out -> download(url(f.base, f.apk.name, f.release.version), out, f.apk) }
        checkSigner(apk)
        val pi = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setSize(apk.length())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = pi.createSession(params)
        pi.openSession(id).use { s ->
            s.openWrite("base.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                s.fsync(out)
            }
            val intent = Intent(context, ApkUpdateReceiver::class.java).setPackage(context.packageName)
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
            s.commit(PendingIntent.getBroadcast(context, id, intent, flags).intentSender)
        }
        Log.i(TAG, "installing ${f.release.version}")
    }

    /**
     * Refuses an APK that is not this app, is not newer, or is not signed
     * with this app's certificate. The system refuses such an update too,
     * but only after a question and with a message that names neither.
     */
    private fun checkSigner(apk: File) {
        val pm = context.packageManager
        val got = archiveInfo(pm, apk.path) ?: throw Releases.Refused("${apk.name} is not an APK")
        val own = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        if (got.packageName != context.packageName) throw Releases.Refused("${apk.name} is ${got.packageName}, not this app")
        if (got.longVersionCode <= own.longVersionCode) throw Releases.Refused("${apk.name} is not newer than this app")
        if (!sameSigners(signers(own), signers(got))) throw Releases.Refused("${apk.name} is not signed with this app's certificate")
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(pm: PackageManager, path: String): PackageInfo? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        } else {
            pm.getPackageArchiveInfo(path, PackageManager.GET_SIGNING_CERTIFICATES)
        }

    private fun signers(p: PackageInfo): List<ByteArray> {
        val info = p.signingInfo ?: return emptyList()
        val sigs = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory?.takeLast(1)?.toTypedArray()
        return sigs.orEmpty().map { it.toByteArray() }
    }

    /** The failure the system reported to [ApkUpdateReceiver]. */
    internal fun failed(message: String) {
        prefs.edit().putString(FAILED, message).apply()
        set(State.Failed(Exception(message)))
    }

    companion object {
        private const val TAG = "ApkUpdate"
        private const val GITHUB = "https://github.com/HunterEwok/cbb/releases"
        private const val MIRROR = "https://dl.cbb.tools"

        /**
         * Where GitHub keeps the current keys.json and channel file: the branch
         * channel, since a published release takes no new files and these are
         * signed again while it is current (docs/protocol.md, section 16).
         */
        private const val CHANNEL_FILES = "https://raw.githubusercontent.com/HunterEwok/cbb/channel"

        /** GitHub first, then the mirror, as cbb update. */
        val SOURCES = listOf(GITHUB, MIRROR)
        const val CHANNEL = "stable"
        private const val KEYS_FILE = "keys.json"
        private const val CHANNEL_FILE = "$CHANNEL.json"
        private const val RELEASE_FILE = "release.json"
        private const val DAY_MS = 24L * 3600 * 1000
        private const val AUTO = "automatic"
        private const val CHECKED = "checkedMs"
        private const val FAILED = "failed"
        private const val KEYS_SEQ = "keysSeq"
        private const val CHANNEL_SEQ = "channelSeq"
        private const val CHANNEL_KEYS_SEQ = "channelKeysSeq"
        private const val SEEN_VERSION = "seenVersion"

        /** F-Droid's client, which updates the F-Droid build. */
        const val FDROID = "org.fdroid.fdroid"

        /** The stores that update what they installed: Google Play, F-Droid, Amazon, Samsung, Huawei, Aurora. */
        val STORES = setOf(
            "com.android.vending",
            FDROID,
            "org.fdroid.basic",
            "com.amazon.venezia",
            "com.sec.android.app.samsungapps",
            "com.huawei.appmarket",
            "com.aurora.store",
        )

        /** The release's APK for phones and TVs, as the release workflow names it. */
        fun apkName(version: String) = "cbb-$version.apk"

        fun asset(r: Releases.Release): Releases.Asset? = r.files.firstOrNull { it.name == apkName(r.version) }

        /**
         * Where a server keeps a file: GitHub under download/vX.Y.Z or latest/download, and the
         * current keys.json and channel file in the branch channel; a mirror under vX.Y.Z or its top.
         */
        fun url(base: String, name: String, version: String?): String = when {
            base == GITHUB && version == null && (name == KEYS_FILE || name == CHANNEL_FILE) -> "$CHANNEL_FILES/$name"
            base == GITHUB && version == null -> "$base/latest/download/$name"
            base == GITHUB -> "$base/download/v$version/$name"
            version == null -> "$base/$name"
            else -> "$base/v$version/$name"
        }

        /** Whether two signer lists are the same certificates. */
        fun sameSigners(a: List<ByteArray>, b: List<ByteArray>): Boolean =
            a.isNotEmpty() && a.size == b.size && a.all { x -> b.any { it.contentEquals(x) } }

        /**
         * Copies in to out and refuses it unless it is the asset's size and
         * SHA-256, reading at most one byte past the size.
         */
        fun copyChecked(input: InputStream, out: OutputStream, a: Releases.Asset) {
            val md = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(64 shl 10)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > a.size) throw Releases.Refused("${a.name} is larger than release.json says")
                md.update(buf, 0, n)
                out.write(buf, 0, n)
            }
            val sum = md.digest().joinToString("") { "%02x".format(it) }
            if (total != a.size || sum != a.sha256) throw Releases.Refused("${a.name} does not match release.json")
        }

        fun versionName(context: Context): String? = runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull()

        /** The package that installed this app, null when adb or nothing known did. */
        @Suppress("DEPRECATION")
        fun installer(context: Context): String? = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        }.getOrNull()

        private fun open(url: String): HttpURLConnection {
            var u = URL(url)
            repeat(5) {
                val c = u.openConnection() as HttpURLConnection
                c.instanceFollowRedirects = false
                c.connectTimeout = 30_000
                c.readTimeout = 60_000
                // The same for every device: no version or system.
                c.setRequestProperty("User-Agent", "cbb")
                when (c.responseCode) {
                    200 -> return c
                    301, 302, 303, 307, 308 -> {
                        val next = URL(u, c.getHeaderField("Location") ?: error("$url: a redirect without a place"))
                        c.disconnect()
                        if (next.protocol != "https" || !allowedHost(next.host)) error("$url: redirected to ${next.host}, which is not an update server")
                        u = next
                    }
                    else -> {
                        c.disconnect()
                        error("$u: ${c.responseCode}")
                    }
                }
            }
            error("$url: too many redirects")
        }

        /** The hosts the updater talks to: the update servers and the ones GitHub sends downloads to. */
        fun allowedHost(host: String): Boolean {
            val h = host.lowercase()
            return h == "github.com" || h == "dl.cbb.tools" || h.endsWith(".githubusercontent.com")
        }

        private fun get(url: String, max: Int): ByteArray {
            val c = open(url)
            try {
                val out = ByteArrayOutputStream()
                c.inputStream.use { s ->
                    val buf = ByteArray(8192)
                    while (true) {
                        val n = s.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        if (out.size() > 2 * max) error("$url is too large")
                    }
                }
                return out.toByteArray()
            } finally {
                c.disconnect()
            }
        }

        private fun download(url: String, out: OutputStream, a: Releases.Asset) {
            val c = open(url)
            try {
                c.inputStream.use { copyChecked(it, out, a) }
            } finally {
                c.disconnect()
            }
        }
    }
}

/**
 * The system's answer to an install of [ApkUpdate]: the question when it
 * needs one (the first update after an install from elsewhere), or the
 * failure; on success the system has already replaced the app.
 */
class ApkUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val ask = (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) else intent.getParcelableExtra(Intent.EXTRA_INTENT)) ?: return
                context.startActivity(ask.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            PackageInstaller.STATUS_SUCCESS -> Log.i("ApkUpdate", "installed")
            else -> {
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "status $status"
                Log.w("ApkUpdate", "the install failed: $msg")
                (context.applicationContext as? CBBApp)?.model?.apkUpdate?.failed("the system refused the update ($status): $msg")
            }
        }
    }
}
