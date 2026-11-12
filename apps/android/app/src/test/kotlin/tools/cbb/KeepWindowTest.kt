// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeepWindowTest {
    /**
     * A timed admin key signs without the app's prompt only within five
     * minutes after that prompt: never before the first one (the screen
     * unlock opens the Keystore, not the app), and never on a clock that
     * went back.
     */
    @Test
    fun opensOnlyAfterTheAppsPrompt() {
        val w = KeepWindow(Keys.KEEP_SECONDS * 1000L)
        assertFalse("closed before the first prompt", w.isOpen(1_000))
        w.opened(1_000)
        assertTrue(w.isOpen(1_000))
        assertTrue(w.isOpen(1_000 + 299_999))
        assertFalse("five minutes at most", w.isOpen(1_000 + 300_000))
        assertFalse("not before the prompt", w.isOpen(999))
        w.opened(400_000)
        assertTrue(w.isOpen(600_000))
    }
}
