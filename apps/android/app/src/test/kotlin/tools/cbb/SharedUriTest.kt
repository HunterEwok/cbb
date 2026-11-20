// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode
import java.io.IOException

/**
 * What another app shares, or puts on the clipboard, is read only through
 * that app's own provider: the app reads with its own rights, so nothing
 * else is taken.
 */
@RunWith(AndroidJUnit4::class)
@Config(sdk = [35])
@ConscryptMode(ConscryptMode.Mode.OFF)
class SharedUriTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val own = context.packageName

    @Test
    fun onlyAnotherAppsProviderIsRead() {
        assertTrue(Files.foreign(context, Uri.parse("content://com.example.gallery/images/1")))
        assertTrue(Files.foreign(context, Uri.parse("content://10@com.example.gallery/images/1")))
        assertTrue(Files.foreign(context, Uri.parse("CONTENT://media/external/images/media/7")))
        assertFalse(Files.foreign(context, Uri.parse("file:///data/data/$own/files/group.json")))
        assertFalse(Files.foreign(context, Uri.parse("file:///sdcard/Download/a.txt")))
        assertFalse(Files.foreign(context, Uri.parse("/data/data/$own/files/group.json")))
        assertFalse(Files.foreign(context, Uri.parse("content://$own.files/files/group.json")))
        assertFalse(Files.foreign(context, Uri.parse("content://0@$own.files/files/group.json")))
        assertFalse(Files.foreign(context, Uri.parse("content://$own/x")))
        assertFalse(Files.foreign(context, Uri.parse("content://com.example.gallery;$own.files/x")))
        assertFalse(Files.foreign(context, Uri.parse("content:///x")))
    }

    @Test
    fun aShareOfThisAppsOwnFileIsRefused() {
        val f = context.filesDir.resolve("probe.txt").apply { writeText("inside") }
        assertThrows(IOException::class.java) { Files.read(context, listOf(Uri.fromFile(f))) }
    }
}
