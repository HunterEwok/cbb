// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode
import org.robolectric.annotation.GraphicsMode

/**
 * The app for a person who uses TalkBack or large text (docs/testing.md, "The
 * apps' languages, accessibility and screenshots"): every control has a name
 * and is at least 48 dp to touch, and with the system's largest font (twice
 * the size) and in the longest language no text is cut off. The colours'
 * contrast is checked once for every app, in tools/tokens.
 */
@RunWith(AndroidJUnit4::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
@ConscryptMode(ConscryptMode.Mode.OFF)
class AccessibilityTest {
    @get:Rule val compose = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun clean() {
        context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun screens(see: (String) -> Unit) {
        val model = AppModel(context)
        compose.setContent { Root(model) }
        compose.waitForIdle()
        see("the Start screen")
        compose.onNodeWithContentDescription(context.getString(R.string.settings)).performClick()
        compose.waitForIdle()
        see("Settings")
    }

    private fun assertNone(what: String, wrong: List<String>) =
        assertTrue("$what:\n" + wrong.joinToString("\n"), wrong.isEmpty())

    /** U14: TalkBack names every control, and each is large enough to touch. */
    @Test
    fun namedAndLargeEnough() = screens { screen ->
        assertNone("$screen, controls without a name", Readers.unnamed(compose))
        assertNone("$screen, controls too small", Readers.small(compose))
    }

    /** U16: at twice the font size nothing is cut off. */
    @Test
    fun largestFont() {
        RuntimeEnvironment.setFontScale(2f)
        screens { screen -> assertNone("$screen at font scale 2", Readers.clipped(compose)) }
    }

    /** U16: Swahili, among the longest of the eight, at twice the font size. */
    @Test
    @Config(qualifiers = "+sw")
    fun largestFontInSwahili() {
        RuntimeEnvironment.setFontScale(2f)
        screens { screen -> assertNone("$screen in Swahili at font scale 2", Readers.clipped(compose)) }
    }
}
