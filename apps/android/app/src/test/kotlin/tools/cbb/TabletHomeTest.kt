// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import org.junit.Assert.assertEquals
import org.junit.Test

/** The big screen's sections outlive a turn of the screen as strings (TabletHome). */
class TabletHomeTest {
    @Test
    fun sectionsRoundTrip() {
        val all = listOf(TabletSection.All, TabletSection.Attention, TabletSection.Collection("c1:x")) +
            SettingsPart.entries.map { TabletSection.Settings(it) }
        for (s in all) assertEquals(s, TabletSection.of(s.key))
    }

    @Test
    fun unknownSectionsGoToAllDevices() {
        assertEquals(TabletSection.All, TabletSection.of(""))
        assertEquals(TabletSection.All, TabletSection.of("s:NOPE"))
    }
}
