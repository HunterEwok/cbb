// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode
import org.robolectric.annotation.GraphicsMode

/**
 * Screenshot regressions (U18, docs/testing.md, "The apps' languages,
 * accessibility and screenshots"): the Start screen and Settings in English
 * dark and light, Arabic and Chinese, drawn by Robolectric's native graphics,
 * which brings its own fonts, and compared with the pictures in
 * src/test/screenshots. Plain test runs only draw them; the comparison is
 *
 *     ./gradlew :app:verifyRoborazziFullDebug
 *
 * and after a change to a screen the pictures are written again, to be
 * looked at before they are committed, with
 *
 *     ./gradlew :app:recordRoborazziFullDebug
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
@ConscryptMode(ConscryptMode.Mode.OFF)
class ScreenshotTest(private val lang: String, private val look: String) {
    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}-{1}")
        fun cases() = listOf(arrayOf("en", "dark"), arrayOf("en", "light"), arrayOf("ar", "dark"), arrayOf("zh", "light"))
    }

    @get:Rule val compose = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    // A small difference is the smoothing of a text, not a change.
    private val options = RoborazziOptions(compareOptions = RoborazziOptions.CompareOptions(changeThreshold = 0.003f))

    @Before
    fun setUp() {
        RuntimeEnvironment.setQualifiers("+$lang-${if (look == "dark") "night" else "notnight"}")
        context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().clear().commit()
    }

    @Test
    fun screens() {
        val model = AppModel(context)
        compose.setContent { Root(model) }
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("src/test/screenshots/start-$lang-$look.png", roborazziOptions = options)
        compose.onNodeWithContentDescription(context.getString(R.string.settings)).performClick()
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("src/test/screenshots/settings-$lang-$look.png", roborazziOptions = options)
    }
}
