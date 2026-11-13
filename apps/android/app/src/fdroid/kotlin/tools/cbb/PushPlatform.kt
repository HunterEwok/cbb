// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage
import tools.cbb.kit.Push

/**
 * The F-Droid build's push platform: UnifiedPush (env 4), through the
 * distributor the user installed (ntfy or another). The endpoint and the
 * app's RFC 8291 keys are the token; the distributor decrypts each message,
 * which is parts told apart by a kind byte (`Push.parts`). Without a
 * distributor Settings says how to get one. The full build's (src/full) is
 * FCM.
 */
object PushPlatform {
    const val env = Push.Env.UNIFIED_PUSH
    private const val INSTANCE = "push.instance"

    fun available(c: Context): Boolean = !Tv.isTv(c)

    private fun prefs(c: Context) = c.getSharedPreferences("push", Context.MODE_PRIVATE)

    /**
     * The distributor's instance this app now uses: a new one with each
     * removal applied (newEndpoint), so the endpoint every member knew dies.
     */
    fun instance(c: Context): String = prefs(c).getString(INSTANCE, null) ?: UnifiedPush.INSTANCE_DEFAULT

    fun start(c: Context) {
        UnifiedPush.tryUseCurrentOrDefaultDistributor(c) { ok ->
            if (ok) {
                UnifiedPush.register(c, instance(c))
            } else {
                PushSetup.lost(c, c.getString(R.string.push_no_distributor))
            }
        }
    }

    /**
     * A removal was applied: a new instance and so a new endpoint, and the
     * old one unregistered, so that a removed device's knowledge of the old
     * address and keys reaches nothing.
     */
    fun newEndpoint(c: Context) {
        val old = instance(c)
        val new = "cbb-" + java.util.UUID.randomUUID().toString()
        prefs(c).edit { putString(INSTANCE, new) }
        UnifiedPush.register(c, new)
        UnifiedPush.unregister(c, old)
    }

    fun stop(c: Context) {
        UnifiedPush.unregister(c, instance(c))
    }
}

/** The distributor's events: a new endpoint, a message, the endpoint gone. */
class PushMessages : PushService() {
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        // An endpoint of an instance this app left is not its address any more.
        if (instance != PushPlatform.instance(applicationContext)) return
        val keys = endpoint.pubKeySet ?: return PushSetup.lost(applicationContext, null)
        val flags = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        val up = Push.UnifiedPush(endpoint.url, Base64.decode(keys.pubKey, flags), Base64.decode(keys.auth, flags))
        PushSetup.got(applicationContext, PushSetup.Token(null, up))
    }

    override fun onMessage(message: PushMessage, instance: String) {
        // A message the distributor could not decrypt is not ours to read.
        if (!message.decrypted) return
        if (instance != PushPlatform.instance(applicationContext)) return
        Push.parts(message.content)?.let { PushSetup.received(applicationContext, it) }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        if (instance != PushPlatform.instance(applicationContext)) return
        PushSetup.lost(applicationContext, applicationContext.getString(R.string.push_problem))
    }

    override fun onUnregistered(instance: String) {
        if (instance != PushPlatform.instance(applicationContext)) return
        PushSetup.lost(applicationContext, null)
    }
}
