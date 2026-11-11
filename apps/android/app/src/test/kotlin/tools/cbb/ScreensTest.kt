// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.content.res.Configuration
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsNotSelected
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode

/**
 * The app's screens before a group, driven as a person would on Robolectric
 * (docs/testbench-catalogue.md, A2, A9, A14, A15, U12): the Start screen,
 * Settings with the colours and themes kept in the settings, the error
 * details switch behind seven taps on the version, and Russian. A group needs
 * the Keystore and a computer, which the bench's devices give. The screens
 * need no TLS, so Robolectric's Conscrypt, whose native library a runner may
 * not load, stays off.
 */
@RunWith(AndroidJUnit4::class)
@Config(sdk = [35])
@ConscryptMode(ConscryptMode.Mode.OFF)
class ScreensTest {
    @get:Rule val compose = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private lateinit var model: AppModel

    @Before
    fun clean() {
        context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun show(): AppModel {
        model = AppModel(context)
        compose.setContent { Root(model) }
        compose.waitForIdle()
        return model
    }

    private fun str(id: Int) = context.getString(id)

    /** A14: what the app does, both ways in and the way back with the recovery key; the language and Settings at the top. */
    @Test
    fun startScreen() {
        show()
        compose.onNodeWithText(str(R.string.tagline)).assertExists()
        compose.onNodeWithText(str(R.string.create_group)).assertExists()
        compose.onNodeWithText(str(R.string.join_group)).assertExists()
        compose.onNodeWithText(str(R.string.restore_link)).assertExists()
        compose.onNodeWithContentDescription(str(R.string.language)).assertExists()
        compose.onNodeWithContentDescription(str(R.string.settings)).assertExists()
    }

    /** A15, A14: Settings before a group; each colour and theme chosen is the one kept. */
    @Test
    fun coloursAndThemes() {
        show()
        compose.onNodeWithContentDescription(str(R.string.settings)).performClick()
        for (a in Appearance.entries) {
            // The themes are icons, named for the screen reader.
            compose.onNodeWithContentDescription(str(a.title)).performScrollTo().performClick()
            compose.waitForIdle()
            assertEquals(a, model.settings.appearance)
            compose.onNodeWithContentDescription(str(a.title)).assertIsSelected()
        }
        val names = ThemeChoice.offered
        assertTrue("Settings offers ${names.size} themes", names.size >= 10)
        for (name in names) {
            compose.onNodeWithText(str(ThemeChoice.title(name))).performScrollTo().performClick()
            compose.waitForIdle()
            assertEquals(name, model.settings.theme)
            compose.onNodeWithText(str(ThemeChoice.title(name))).assertIsSelected()
            for (other in names) if (other != name) compose.onNodeWithText(str(ThemeChoice.title(other))).assertIsNotSelected()
        }
        // Kept for the next launch.
        assertEquals(names.last(), Settings(context).theme)
    }

    /** U12: seven taps on the version show the error details switch, which sets the setting. */
    @Test
    fun errorDetailsSwitch() {
        show()
        compose.onNodeWithContentDescription(str(R.string.settings)).performClick()
        val version = compose.onNodeWithText(str(R.string.version)).performScrollTo()
        compose.onNodeWithText(str(R.string.error_details_switch)).assertDoesNotExist()
        repeat(7) { version.performClick() }
        compose.onNodeWithText(str(R.string.error_details_switch)).performScrollTo().assertExists()
        val before = model.settings.showsErrorDetails
        compose.onNodeWithText(str(R.string.error_details_switch)).performClick()
        compose.waitForIdle()
        assertEquals(!before, model.settings.showsErrorDetails)
    }

    /**
     * The mute button in a tile's corner: on this phone's own tile always,
     * on another device's only on an admin; with sync off, it says so.
     */
    @Test
    fun tileCorner() {
        model = AppModel(context)
        val phone = LiveGroup.Device("self", "Pixel", online = true, role = "phone", os = "android", isSelf = true, syncOff = LiveGroup.Hold(null))
        val mac = LiveGroup.Device("mac", "MacBook", online = true, os = "macos")
        compose.setContent {
            CompositionLocalProvider(LocalModel provides model) {
                Column {
                    DeviceTile(phone, Modifier, open = {})
                    DeviceTile(mac, Modifier, open = {})
                }
            }
        }
        compose.onNodeWithContentDescription("${str(R.string.sync_off)}, Pixel").assertExists()
        // This phone is no admin: another device's tile has no button.
        compose.onNodeWithContentDescription("${str(R.string.mute)}, MacBook").assertDoesNotExist()
        assertTrue(!model.mayMute(mac) && model.shownMuted(phone) && !model.shownMuted(mac))
    }

    /** A9: in Russian the Start screen is Russian. */
    @Test
    @Config(qualifiers = "ru")
    fun russian() {
        val english = context.createConfigurationContext(Configuration(context.resources.configuration).apply { setLocale(Locale.ENGLISH) })
        for (id in listOf(R.string.tagline, R.string.create_group, R.string.join_group, R.string.restore_link, R.string.settings)) {
            assertNotEquals("no Russian for ${english.getString(id)}", english.getString(id), str(id))
        }
        show()
        compose.onNodeWithText(str(R.string.create_group)).assertExists()
        compose.onNodeWithText(str(R.string.join_group)).assertExists()
    }
}
