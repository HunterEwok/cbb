// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Android app, its Wear OS app and its protocol core. The core, kit, is a build of its
// own with no Android dependencies, so it builds and tests on any JDK:
// ./gradlew -p kit test.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "cbb-android"
includeBuild("kit")
include(":app", ":shared")
// F-Droid's recipe removes the Wear OS app, which needs Google Play services.
if (file("wear").isDirectory) include(":wear")
