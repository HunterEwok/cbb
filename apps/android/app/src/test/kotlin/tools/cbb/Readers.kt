// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.dp

/**
 * What a reader meets on a screen, for LanguagesTest and AccessibilityTest
 * (docs/testing.md, "The apps' languages, accessibility and screenshots"):
 * each returns what is wrong, empty when all is well.
 */
internal object Readers {
    /** The project's eight languages, as Android's resource qualifiers name them (Hebrew is "iw"). */
    val languages = listOf("en", "es", "ru", "ar", "sw", "iw", "hi", "zh")

    /** Those written from right to left. */
    val rightToLeft = setOf("ar", "iw")

    private fun SemanticsNode.label(): String {
        val text = config.getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text }.orEmpty()
        val description = config.getOrNull(SemanticsProperties.ContentDescription)?.joinToString(" ").orEmpty()
        return listOf(text, description).filter { it.isNotBlank() }.joinToString(" / ")
    }

    /**
     * Whether the node was laid out on the screen: a node of a list that
     * was never scrolled to, or of a part being animated in, has no size.
     */
    private fun SemanticsNode.placed() = layoutInfo.isPlaced && size.width > 0 && size.height > 0

    /** Texts cut off or ended with "…": the text did not fit where the screen put it. */
    fun clipped(compose: ComposeContentTestRule): List<String> {
        val out = mutableListOf<String>()
        val nodes = compose.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.Text), useUnmergedTree = true).fetchSemanticsNodes()
        for (node in nodes.filter { it.placed() }) {
            val action = node.config.getOrNull(SemanticsActions.GetTextLayoutResult) ?: continue
            val results = mutableListOf<TextLayoutResult>()
            action.action?.invoke(results)
            for (r in results) {
                val last = r.lineCount - 1
                // Not hasVisualOverflow: Robolectric reports a one-line text narrower than
                // its room as wider than its own size. A line wider than the text's box is
                // the overflow across.
                val across = (0 until r.lineCount).any { r.multiParagraph.getLineWidth(it) > r.size.width + 1 }
                if (r.didOverflowHeight || across || (last >= 0 && r.isLineEllipsized(last))) out += "cut off: \"${r.layoutInput.text}\""
            }
        }
        return out
    }

    /** Controls with neither text nor a description, which TalkBack could only call "button". */
    fun unnamed(compose: ComposeContentTestRule): List<String> =
        compose.onAllNodes(hasClickAction()).fetchSemanticsNodes()
            .filter { it.placed() && it.label().isBlank() }
            .map { "a control without a name at ${it.boundsInRoot}" }

    /** Controls smaller than 48 by 48 dp to touch, below Android's and WCAG's target size. */
    fun small(compose: ComposeContentTestRule): List<String> =
        compose.onAllNodes(hasClickAction()).fetchSemanticsNodes().filter { it.placed() }.mapNotNull { node ->
            val min = with(node.layoutInfo.density) { 48.dp.toPx() } - 1f
            val b = node.touchBoundsInRoot
            if (b.width < min || b.height < min) {
                val dp = with(node.layoutInfo.density) { "${b.width.toDp().value.toInt()}×${b.height.toDp().value.toInt()} dp" }
                "\"${node.label()}\" is $dp to touch"
            } else null
        }
}
