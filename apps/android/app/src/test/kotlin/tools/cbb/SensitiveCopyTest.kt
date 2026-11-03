// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode

/**
 * Automatic sending leaves a copy marked sensitive on the phone; the button still reads it.
 * The clipboard needs no TLS, so Robolectric's Conscrypt, whose native library a runner may
 * lack, stays off.
 */
@RunWith(AndroidJUnit4::class)
@Config(sdk = [35])
@ConscryptMode(ConscryptMode.Mode.OFF)
class SensitiveCopyTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val cm = context.getSystemService(ClipboardManager::class.java)

    private fun copy(text: String, sensitive: Boolean?) {
        val clip = ClipData.newPlainText("", text)
        if (sensitive != null) clip.description.extras = PersistableBundle().apply { putBoolean(Clipboard.SENSITIVE, sensitive) }
        cm.setPrimaryClip(clip)
    }

    @Test
    fun aPlainCopyIsSent() {
        copy("plain", null)
        assertFalse(Clipboard.sensitive(context))
        assertEquals("plain", Clipboard.readForAutoSend(context))
    }

    @Test
    fun aSensitiveCopyStays() {
        copy("hunter2", true)
        assertTrue(Clipboard.sensitive(context))
        assertNull(Clipboard.readForAutoSend(context))
        // The button and the keyboard still read it, since the user asks for it.
        assertEquals("hunter2", Clipboard.read(context))
        assertEquals(Clipboard.Board.Text("hunter2"), Clipboard.readForSync(context))
    }

    @Test
    fun aCopyMarkedNotSensitiveIsSent() {
        copy("open", false)
        assertFalse(Clipboard.sensitive(context))
        assertEquals("open", Clipboard.readForAutoSend(context))
    }
}
