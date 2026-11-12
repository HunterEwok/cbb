// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import tools.cbb.kit.Push
import tools.cbb.kit.PushMarks
import tools.cbb.kit.PushVault
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Push to this phone while the app is closed (docs/core-api.md, "Push"):
 * takes the platform's token from [PushPlatform] (FCM in the full build,
 * UnifiedPush in the F-Droid build), keeps each group's registration in a
 * vault sealed with a Keystore key of its own ([SealedStore], apart from the
 * member key), keeps the push service's challenges for this phone's send
 * key, and opens each body that arrives. The vault holds what opens a body
 * and a copy in it and nothing that signs a record. A registration is made
 * again only when what it says changed or a member asks (`push-renew`). The
 * member's sync sends the saved registration to the group's members (the
 * seam in member/src/pusher.rs).
 */
object PushSetup {
    private const val TAG = "cbb"
    const val ON = "push.on"
    private const val CHANNEL = "push"
    private const val SHOWN = "shown"
    private const val SHOWN_MAX = 200
    private const val TOKEN = "push.token"
    const val COPY_ACTION = "tools.cbb.PUSH_COPY"

    /** The token the platform gave: FCM's bytes, or a UnifiedPush endpoint. */
    class Token(val bytes: ByteArray?, val unifiedPush: Push.UnifiedPush?)

    /** The last problem, shown in Settings under the switch. */
    @Volatile
    var problem: String? = null
        private set

    private fun prefs(c: Context) = c.getSharedPreferences("push", Context.MODE_PRIVATE)

    private fun settings(c: Context) = c.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun on(c: Context): Boolean = settings(c).getBoolean(ON, true)

    fun vault(c: Context) = PushVault(SealedStore.of(c))

    private fun marks(c: Context) = PushMarks(SealedStore.of(c))

    /** At launch: the token when on. */
    fun start(c: Context) {
        if (!PushPlatform.available(c)) return
        if (on(c)) PushPlatform.start(c) else refresh(c)
    }

    /** The user turned the switch. */
    fun set(c: Context, on: Boolean) {
        settings(c).edit().putBoolean(ON, on).apply()
        if (on) {
            PushPlatform.start(c)
        } else {
            PushPlatform.stop(c)
            refresh(c)
        }
    }

    /** The platform gave a token (a new one, or the same again). */
    fun got(c: Context, t: Token) {
        val o = JSONObject()
        t.bytes?.let { o.put("token", b64(it)) }
        t.unifiedPush?.let { o.put("url", it.url).put("p256dh", b64(it.p256dh)).put("auth", b64(it.auth)) }
        SealedStore.of(c).put(TOKEN, o.toString().toByteArray())
        problem = null
        refresh(c)
    }

    /** The platform took the token back (UnifiedPush unregistered, its distributor gone). */
    fun lost(c: Context, why: String? = null) {
        SealedStore.of(c).put(TOKEN, null)
        problem = why
        refresh(c)
    }

    /** Push could not be set up: shown under the switch, the cause in the log. */
    fun failed(c: Context, e: Throwable) {
        val s = settings(c)
        // Details under the message in debug mode (Settings.showsErrorDetails); the log gets them always.
        val details = if (s.contains(Settings.ERROR_DETAILS)) s.getBoolean(Settings.ERROR_DETAILS, false) else BuildConfig.DEBUG
        problem = c.getString(R.string.push_problem) + if (details) "\n$e" else ""
        Log.e(TAG, "push: ${c.getString(R.string.push_problem)}", e)
    }

    private fun token(c: Context): Token? {
        val o = SealedStore.of(c).get(TOKEN)?.let { runCatching { JSONObject(it.decodeToString()) }.getOrNull() } ?: return null
        val bytes = o.optString("token").takeIf { it.isNotEmpty() }?.let(::unb64)
        val up = o.optString("url").takeIf { it.isNotEmpty() }?.let {
            Push.UnifiedPush(it, unb64(o.optString("p256dh")), unb64(o.optString("auth")))
        }
        return Token(bytes, up)
    }

    /**
     * The group and its devices as the app applied them (this phone among
     * them, the root's marked); a null tag when it has no group. A device gone
     * or a new root draws a new push key, so a removed member's bodies open
     * nothing here.
     */
    fun group(c: Context, tag: String?, devices: List<LiveGroup.Device>) {
        val me = devices.firstOrNull { it.isSelf }?.id?.let(::hex)
        if (tag == null || me == null || me.size != 16) return
        val list = devices.mapNotNull { hex(it.id) }
        val root = devices.firstOrNull { it.isRoot }?.id?.let(::hex)
        prefs(c).edit().putString("group", tag).apply()
        refresh(c, tag, me, PushVault.Devices(list, root))
    }

    /** The phone left its group: that group's push state goes. */
    fun forget(c: Context) {
        val tag = prefs(c).getString("group", null) ?: return
        runCatching { vault(c).forget(tag) }.onFailure { Log.e(TAG, "push: cannot forget the group", it) }
        prefs(c).edit().remove("group").apply()
    }

    /** A member asked for the registration of the group with this slot (`push-renew`). */
    fun renew(c: Context, slot: ByteArray) {
        val v = vault(c)
        val tag = runCatching { v.group(slot) }.getOrNull() ?: return
        val me = v.load(tag).me ?: return
        refresh(c, tag, me, null, setOf(PushVault.Reason.RENEW))
    }

    /**
     * What opens a copy here, which the app writes on every rotation of its
     * sealing key and whenever the group's devices change: the sealing
     * secrets of the epochs in the group's window (any other is erased), the
     * devices as origins, the window and whether the group is halted.
     */
    fun opening(c: Context, sealing: List<Push.Sealing>, origins: List<Push.Origin>, windowMs: Long?, halted: Boolean) {
        val tag = prefs(c).getString("group", null) ?: return
        runCatching { vault(c).opening(tag, sealing, origins, windowMs, halted) }.onFailure { failed(c, it) }
    }

    /** Every group registers again where something changed (after a new token or challenge). */
    private fun refresh(c: Context) {
        val v = vault(c)
        for (tag in runCatching { v.groups() }.getOrDefault(emptyList())) {
            val me = runCatching { v.load(tag).me }.getOrNull() ?: continue
            refresh(c, tag, me, null)
        }
        prefs(c).getString("group", null)?.let { tag ->
            if (tag !in runCatching { v.groups() }.getOrDefault(emptyList())) Log.i(TAG, "push: the group registers once its devices are known")
        }
    }

    private fun refresh(c: Context, tag: String, me: ByteArray, devices: PushVault.Devices?, reasons: Set<PushVault.Reason> = emptySet()) {
        if (!PushPlatform.available(c)) return
        val v = vault(c)
        try {
            val t = token(c)
            if (on(c) && t != null) {
                v.register(tag, me, t.bytes, t.unifiedPush, PushPlatform.env, Push.Kinds.COPIES or Push.Kinds.EVENTS, reasons, devices)
            } else {
                v.register(tag, me, null, null, null, 0, devices = devices)
            }
            // A hints-only mark whose change is now applied, with its new key in place, is spent.
            marks(c).spend(tag, v.load(tag))
        } catch (e: Exception) {
            failed(c, e)
        }
    }

    /**
     * A push arrived: a challenge is kept when it is for this phone's send
     * key (and the groups register again with it); a body is opened with the
     * first group whose keys open it and shown in the app's own words. Only
     * a copy whose origin's signature holds shows its text, never a secret's.
     */
    fun received(c: Context, d: Push.Delivery) {
        val v = vault(c)
        d.challenge?.let { ch ->
            if (runCatching { v.keep(ch) }.getOrDefault(false)) refresh(c)
        }
        val body = d.body ?: return
        var shown = false
        for (tag in runCatching { v.groups() }.getOrDefault(emptyList())) {
            val g = runCatching { v.load(tag) }.getOrNull() ?: continue
            val ctx = g.context(marks(c).hintsOnly(tag, g)) ?: continue
            val o = try {
                Push.open(body, ctx, System.currentTimeMillis())
            } catch (e: Exception) {
                continue
            }
            show(c, tag, o)
            shown = true
            break
        }
        if (!shown) Log.i(TAG, "push: a body no key here opens")
    }

    private fun show(c: Context, tag: String, o: Push.Opened) {
        val id = o.id
        if (id != null) {
            if (seen(c, id)) return
            remember(c, id)
        }
        var title: String? = null
        var text = c.getString(R.string.push_neutral)
        var copy: String? = null
        when (o.kind) {
            "copy" -> {
                title = c.getString(R.string.push_new_copy)
                val t = o.text
                text = when {
                    o.secret == true -> c.getString(R.string.push_secret)
                    o.type == "text" && !t.isNullOrEmpty() -> t.take(300).also { copy = t }
                    else -> c.getString(R.string.push_copy_waits)
                }
            }
            "waits" -> text = c.getString(R.string.push_copy_waits)
            "event" -> {
                val e = o.event ?: 0
                text = c.getString(
                    when (e) {
                        1L -> R.string.push_event_joined
                        2L -> R.string.push_event_removed
                        3L -> R.string.push_event_waiting
                        4L -> R.string.push_event_root
                        5L -> R.string.push_event_own
                        6L -> R.string.push_event_stopped
                        else -> R.string.push_neutral
                    },
                )
                // A removal, a new root or a stop: hints only until the app has applied it.
                if (e == 2L || e == 4L || e == 6L) marks(c).mark(tag, e, o.device)
            }
        }
        notify(c, title, text, copy, id)
    }

    private fun notify(c: Context, title: String?, text: String, copy: String?, id: ByteArray?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            c.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, c.getString(R.string.channel_push), NotificationManager.IMPORTANCE_DEFAULT))
        val n = next(c)
        val open = PendingIntent.getActivity(c, 0, Intent(c, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE)
        val b = Notification.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title ?: c.getString(R.string.cbb_name))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
        if (copy != null) {
            val i = Intent(c, PushCopyReceiver::class.java).setAction(COPY_ACTION).putExtra("text", copy).putExtra("n", n)
            val p = PendingIntent.getBroadcast(c, n, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            b.addAction(Notification.Action.Builder(null, c.getString(R.string.push_copy), p).build())
        }
        id?.let { b.setGroup(b64(it)) }
        runCatching { nm.notify(n, b.build()) }.onFailure { Log.e(TAG, "push: notification not posted", it) }
    }

    private fun next(c: Context): Int {
        val p = prefs(c)
        val n = p.getInt("next", 1000)
        p.edit().putInt("next", if (n >= 1999) 1000 else n + 1).apply()
        return n
    }

    private fun seen(c: Context, id: ByteArray) = b64(id) in (prefs(c).getString(SHOWN, "") ?: "").split(',')

    private fun remember(c: Context, id: ByteArray) {
        val list = (prefs(c).getString(SHOWN, "") ?: "").split(',').filter { it.isNotEmpty() } + b64(id)
        prefs(c).edit().putString(SHOWN, list.takeLast(SHOWN_MAX).joinToString(",")).apply()
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    /** Bytes from hex; null for anything else. */
    fun hex(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        return runCatching { ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() } }.getOrNull()
    }
}

/** The Copy button of a push notification: its text to the clipboard. */
class PushCopyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != PushSetup.COPY_ACTION) return
        val text = intent.getStringExtra("text") ?: return
        context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("cbb", text))
        context.getSystemService(NotificationManager::class.java).cancel(intent.getIntExtra("n", 0))
    }
}

/**
 * Named blobs sealed on the device with an AES key of their own in the
 * Android Keystore (no user authentication: push arrives with the phone
 * locked), under the app's no-backup folder: the push vault's store. The key
 * opens push's files only; the member key is a Keystore key of its own that
 * never leaves it.
 */
class SealedStore private constructor(private val dir: File) : PushVault.Store {
    private val key: SecretKey by lazy { key() }

    override fun get(name: String): ByteArray? = synchronized(this) {
        val f = File(dir, name)
        if (!f.isFile) return null
        val all = f.readBytes()
        if (all.size < 12 + 16) return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, all, 0, 12))
            c.updateAAD(name.toByteArray())
            c.doFinal(all, 12, all.size - 12)
        } catch (e: Exception) {
            Log.e("cbb", "push: $name does not open", e)
            null
        }
    }

    override fun put(name: String, value: ByteArray?) = synchronized(this) {
        val f = File(dir, name)
        if (value == null) {
            f.delete()
            return
        }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        c.updateAAD(name.toByteArray())
        val sealed = c.doFinal(value)
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(c.iv + sealed)
        if (!tmp.renameTo(f)) throw java.io.IOException("cannot save $name")
    }

    override fun names(): List<String> = dir.list()?.filter { !it.endsWith(".tmp") }?.sorted() ?: emptyList()

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return g.generateKey()
    }

    companion object {
        private const val ALIAS = "cbb.push"

        @Volatile
        private var one: SealedStore? = null

        fun of(c: Context): SealedStore =
            one ?: synchronized(this) {
                one ?: SealedStore(File(c.applicationContext.noBackupFilesDir, "push").apply { mkdirs() }).also { one = it }
            }
    }
}
