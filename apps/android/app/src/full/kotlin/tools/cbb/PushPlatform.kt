// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.util.Log
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import tools.cbb.kit.Push

/**
 * The full build's push platform: Firebase Cloud Messaging (env 3). The
 * project's Firebase app is named by the build (`cbb.firebase.*` in
 * gradle.properties or -P, never a google-services.json in the repository);
 * a build without one has no push, and Settings offers none. The F-Droid
 * build's (src/fdroid) is UnifiedPush.
 */
object PushPlatform {
    private const val TAG = "cbb"
    const val env = Push.Env.FCM

    private fun options(): FirebaseOptions? {
        if (BuildConfig.FIREBASE_APP_ID.isEmpty() || BuildConfig.FIREBASE_PROJECT_ID.isEmpty()) return null
        return FirebaseOptions.Builder()
            .setApplicationId(BuildConfig.FIREBASE_APP_ID)
            .setProjectId(BuildConfig.FIREBASE_PROJECT_ID)
            .setApiKey(BuildConfig.FIREBASE_API_KEY)
            .setGcmSenderId(BuildConfig.FIREBASE_SENDER_ID)
            .build()
    }

    /** Whether this build can get push: one with the project's Firebase app. */
    fun available(c: Context): Boolean = options() != null && !Tv.isTv(c)

    private fun app(c: Context): FirebaseApp? {
        val o = options() ?: return null
        return FirebaseApp.getApps(c).firstOrNull() ?: FirebaseApp.initializeApp(c.applicationContext, o)
    }

    fun start(c: Context) {
        app(c) ?: return
        val m = FirebaseMessaging.getInstance()
        m.isAutoInitEnabled = true
        m.token.addOnCompleteListener { t ->
            if (t.isSuccessful) {
                t.result?.let { PushSetup.got(c, PushSetup.Token(it.toByteArray(), null)) }
            } else {
                PushSetup.failed(c, t.exception ?: IllegalStateException("FCM gave no token"))
            }
        }
    }

    fun stop(c: Context) {
        app(c) ?: return
        val m = FirebaseMessaging.getInstance()
        m.isAutoInitEnabled = false
        m.deleteToken().addOnFailureListener { Log.e(TAG, "push: the FCM token was not deleted", it) }
    }
}

/** FCM's messages: a new token, and the data messages of the push service (body "c", challenge "k"). */
class PushMessages : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        PushSetup.got(applicationContext, PushSetup.Token(token.toByteArray(), null))
    }

    override fun onMessageReceived(message: RemoteMessage) {
        PushSetup.received(applicationContext, Push.data(message.data))
    }
}
