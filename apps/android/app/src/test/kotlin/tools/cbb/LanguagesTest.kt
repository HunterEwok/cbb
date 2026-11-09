// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.content.res.Configuration
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.LayoutDirection
import androidx.test.core.app.ApplicationProvider
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode

/**
 * The app in each of the project's eight languages (docs/testbench-catalogue.md,
 * A9; docs/testing.md, "The apps' languages, accessibility and screenshots"):
 * the Start screen and Settings are translated, no text is cut off, Arabic and
 * Hebrew lay the screen out from right to left, and every control has a name
 * TalkBack reads in that language.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@Config(sdk = [35])
@ConscryptMode(ConscryptMode.Mode.OFF)
class LanguagesTest(private val lang: String) {
    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun languages() = Readers.languages.map { arrayOf(it) }
    }

    @get:Rule val compose = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        RuntimeEnvironment.setQualifiers("+$lang")
        context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun str(id: Int) = context.getString(id)

    /** The texts every person meets first, which must not stay English. */
    private val firstTexts = listOf(R.string.tagline, R.string.create_group, R.string.join_group, R.string.restore_link, R.string.settings, R.string.language)

    @Test
    fun translatedAndWhole() {
        // Every language the app offers is one of the project's, and every one is offered.
        assertEquals(Readers.languages.map { if (it == "iw") "he" else it }.sorted(), LanguageChoice.translations.map { it.key }.sorted())
        if (lang != "en") {
            val english = context.createConfigurationContext(Configuration(context.resources.configuration).apply { setLocale(Locale.ENGLISH) })
            for (id in firstTexts) {
                assertNotEquals("no translation for \"${english.getString(id)}\"", english.getString(id), str(id))
            }
        }

        var direction: LayoutDirection? = null
        val model = AppModel(context)
        compose.setContent {
            direction = LocalLayoutDirection.current
            Root(model)
        }
        compose.waitForIdle()
        assertEquals(if (lang in Readers.rightToLeft) LayoutDirection.Rtl else LayoutDirection.Ltr, direction)
        compose.onNodeWithText(str(R.string.create_group)).assertExists()
        check("the Start screen")

        compose.onNodeWithContentDescription(str(R.string.settings)).performClick()
        compose.waitForIdle()
        check("Settings")
    }

    private fun check(screen: String) {
        val wrong = Readers.clipped(compose) + Readers.unnamed(compose)
        assertTrue("$screen in $lang:\n" + wrong.joinToString("\n"), wrong.isEmpty())
    }
}
