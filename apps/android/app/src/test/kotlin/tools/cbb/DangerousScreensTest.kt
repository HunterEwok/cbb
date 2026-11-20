// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.RoborazziTaskType
import com.github.takahirom.roborazzi.captureScreenRoboImage
import java.io.File
import java.time.Instant
import java.util.Locale
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.ConscryptMode
import org.robolectric.annotation.GraphicsMode
import tools.cbb.kit.Core
import tools.cbb.kit.GroupAlert

/**
 * The phone's part of the sheet of the dangerous screens (docs/testing.md,
 * "The dangerous screens"): each screen where a person decides something the
 * group's safety depends on, in the project's eight languages, drawn by
 * Robolectric's native graphics into $CBB_DANGEROUS_SHEET/android, a picture
 * and its words for each; the tray's test (apps/desktop/dangerous_test.go)
 * puts them on the sheet. Skipped when CBB_DANGEROUS_SHEET is not set. The
 * screens are drawn with made-up devices: a group needs the Keystore, which
 * Robolectric lacks.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w411dp-h891dp-xxhdpi")
@ConscryptMode(ConscryptMode.Mode.OFF)
class DangerousScreensTest(private val lang: String) {
    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun languages() = Readers.languages.map { arrayOf(it) }
    }

    @get:Rule val compose = createComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val out = System.getenv("CBB_DANGEROUS_SHEET")?.takeIf { it.isNotEmpty() }?.let { File(it, "android") }

    /** The language as the sheet names it: Hebrew is he, not Android's iw. */
    private val sheetLang get() = if (lang == "iw") "he" else lang

    @Before
    fun setUp() {
        assumeTrue("CBB_DANGEROUS_SHEET names no directory for the sheet", out != null)
        RuntimeEnvironment.setQualifiers("+$lang-night")
        Locale.setDefault(Locale.forLanguageTag(sheetLang))
    }

    private fun show(content: @Composable () -> Unit) {
        compose.setContent {
            AppTheme("terminal", Appearance.DARK) {
                AppBackground { Box(Modifier.fillMaxSize().padding(16.dp)) { content() } }
            }
        }
        compose.waitForIdle()
    }

    /** The picture of every window, and the words on it. */
    private fun shoot(screen: String) {
        val dir = out!!.also { it.mkdirs() }
        // Written on every run: these pictures are for reading, not compared.
        captureScreenRoboImage(File(dir, "$screen-$sheetLang.png").path, RoborazziOptions(taskType = RoborazziTaskType.Record))
        val words = compose.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.Text), useUnmergedTree = true)
            .fetchSemanticsNodes().flatMap { n -> n.config[SemanticsProperties.Text].map { it.text } }
        File(dir, "$screen-$sheetLang.txt").writeText(words.joinToString("\n"))
    }

    @Test
    fun remove() {
        show { RemoveConfirm("Anna's laptop", isRoot = false, dismiss = {}) {} }
        shoot("remove")
    }

    @Test
    fun removeRoot() {
        show { RemoveConfirm("iPhone", isRoot = true, dismiss = {}) {} }
        shoot("remove-root")
    }

    @Test
    fun invitation() {
        show { InviteAsk("Anna's laptop", "Windows", "3F9A 1C2E 88B0 D45E 7A19") {} }
        shoot("invite-fingerprint")
    }

    @Test
    fun alerts() {
        val alerts = listOf(
            GroupAlert(GroupAlert.Kind.SECRETS_STOPPED),
            GroupAlert(GroupAlert.Kind.CLAIM_PENDING, names = listOf("Pixel"), devices = listOf("pixel"), leftMS = 70L * 3_600_000),
            GroupAlert(GroupAlert.Kind.ADMINS, names = listOf("MacBook", "Windows PC"), devices = listOf("mac", "win")),
            GroupAlert(GroupAlert.Kind.CLAIMS, names = listOf("Pixel", "iPad"), devices = listOf("pixel", "ipad")),
            GroupAlert(GroupAlert.Kind.TWO_HISTORIES, names = listOf("Home server"), devices = listOf("srv")),
        )
        show { AlertList(alerts, isRoot = true, resolve = {}, remove = {}) }
        shoot("alerts")
    }

    @Test
    fun recoverySheet() {
        // Not a key: the sheet's words in its layout, as the phone shows them once.
        val sheet = Core.RecoverySheet("CBB-RECOVERY-EXAMPLE-NOT-A-KEY", "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567", ByteArray(0))
        show { RecoverySheetDialog(sheet, Instant.parse("2026-11-12T09:00:00Z")) {} }
        shoot("recovery-sheet")
        compose.onNodeWithText(context.getString(R.string.recovery_done)).performClick()
        compose.waitForIdle()
        shoot("recovery-kept")
    }
}
