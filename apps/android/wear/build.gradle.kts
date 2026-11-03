// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Wear OS app: the group as the phone sees it, through the Wearable Data
// Layer (docs/apps.md, Wear OS). It has the phone app's application id and
// release key, which the Data Layer requires of the two. F-Droid's build has no watch, so
// F-Droid builds only the app (docs/apps.md, "F-Droid").
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val release = Properties().apply { rootDir.resolve("version.properties").reader().use { load(it) } }

android {
    namespace = "io.github.hunterewok.clipboardbridge.wear"
    compileSdk = 37

    defaultConfig {
        applicationId = "tools.cbb"
        // Wear OS 3.
        minSdk = 30
        targetSdk = 37
        versionCode = (findProperty("versionCode") as String? ?: release.getProperty("versionCode")).toInt()
        versionName = findProperty("versionName") as String? ?: release.getProperty("versionName")
    }

    val keystore = System.getenv("CBB_ANDROID_KEYSTORE")
    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("CBB_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("CBB_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("CBB_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(project(":shared"))
    implementation("com.google.android.gms:play-services-wearable:20.0.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.11.0")

    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.wear.compose:compose-foundation:1.5.0")
    implementation("androidx.wear.compose:compose-material3:1.5.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
}
