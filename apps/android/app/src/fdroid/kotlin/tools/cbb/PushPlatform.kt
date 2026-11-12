// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.util.Base64
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

    fun available(c: Context): Boolean = !Tv.isTv(c)

    fun start(c: Context) {
        UnifiedPush.tryUseCurrentOrDefaultDistributor(c) { ok ->
            if (ok) {
                UnifiedPush.register(c)
            } else {
                PushSetup.lost(c, c.getString(R.string.push_no_distributor))
            }
        }
    }

    fun stop(c: Context) {
        UnifiedPush.unregister(c)
    }
}

/** The distributor's events: a new endpoint, a message, the endpoint gone. */
class PushMessages : PushService() {
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        val keys = endpoint.pubKeySet ?: return PushSetup.lost(applicationContext, null)
        val flags = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        val up = Push.UnifiedPush(endpoint.url, Base64.decode(keys.pubKey, flags), Base64.decode(keys.auth, flags))
        PushSetup.got(applicationContext, PushSetup.Token(null, up))
    }

    override fun onMessage(message: PushMessage, instance: String) {
        // A message the distributor could not decrypt is not ours to read.
        if (!message.decrypted) return
        Push.parts(message.content)?.let { PushSetup.received(applicationContext, it) }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        PushSetup.lost(applicationContext, applicationContext.getString(R.string.push_problem))
    }

    override fun onUnregistered(instance: String) {
        PushSetup.lost(applicationContext, null)
    }
}
