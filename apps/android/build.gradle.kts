// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

plugins {
    id("com.android.application") version "9.5.1" apply false
    id("com.android.library") version "9.5.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
    // The app's screenshot regressions on Robolectric (app/src/test/screenshots).
    id("io.github.takahirom.roborazzi") version "1.77.0" apply false
}
