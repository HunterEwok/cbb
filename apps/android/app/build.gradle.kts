// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Android app: Compose screens over the protocol core in ../kit.
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val release = Properties().apply { rootDir.resolve("version.properties").reader().use { load(it) } }
val ndkPinned = property("cbb.ndk") as String
val rustPinned = property("cbb.rust") as String

android {
    namespace = "io.github.hunterewok.clipboardbridge"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.hunterewok.clipboardbridge"
        minSdk = 29
        targetSdk = 37
        // The version of the last release, from ../version.properties, which F-Droid reads
        // too; a build by hand from a branch may pass its own: -PversionName=1.2.3-dev.
        versionCode = (findProperty("versionCode") as String? ?: release.getProperty("versionCode")).toInt()
        versionName = findProperty("versionName") as String? ?: release.getProperty("versionName")
        // The instrumented tests on an emulator in a group with the bench's fleet
        // (src/androidTest, tools/bench's phone suite).
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // The two builds of one source (docs/apps.md, "F-Droid"): full for the GitHub releases and
    // the stores, with the Wear OS watch (Google Play services) and the app's own update;
    // fdroid without either, built by F-Droid from the tag. Both have the same application id
    // and, published reproducibly, the same signature, so one updates the other.
    flavorDimensions += "build"
    productFlavors {
        create("full") {
            dimension = "build"
            buildConfigField("boolean", "SELF_UPDATE", "true")
        }
        create("fdroid") {
            dimension = "build"
            buildConfigField("boolean", "SELF_UPDATE", "false")
        }
    }

    // The tunnel's NDK (see bindTunnel): one version, so that the same tag gives the same APK.
    ndkVersion = ndkPinned

    // A reproducible APK: without Google's encrypted block of the dependencies, which
    // F-Droid refuses, and without the commit's details, which a build from a tarball lacks.
    dependenciesInfo {
        includeInApk = false
    }

    // The release key, when the release workflow has it (CBB_ANDROID_KEYSTORE is the
    // keystore file); without it the release APK is unsigned.
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
            vcsInfo.include = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // The screens' tests (ScreensTest) run on Robolectric with the app's resources.
    testOptions {
        unitTests.isIncludeAndroidResources = true
        // A failing test shows its whole stack in CI's log, as there is no report to open.
        unitTests.all {
            // The kit calls the Rust core through JNA: on the host, the core
            // the kit's tests build and JNA's desktop library (below).
            it.dependsOn(gradle.includedBuild("kit").task(":buildCore"))
            it.systemProperty("jna.library.path", rootDir.resolve("../../lite/target/release").canonicalPath)
            it.testLogging {
                events("failed")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}

// The Android NDK of ndkVersion (cbb.ndk in ../gradle.properties), which a different NDK
// would build into different libraries: ANDROID_NDK_HOME when it is that version (F-Droid's
// buildserver sets it), else the SDK's ndk/<version>. Set for the task's command when it runs.
val ndkHome = providers.environmentVariable("ANDROID_NDK_HOME")
fun Exec.withPinnedNdk() {
    val sdk = androidComponents.sdkComponents.sdkDirectory
    val env = ndkHome
    val pinned = ndkPinned
    inputs.property("ndk", pinned)
    doFirst {
        val sdkDir = sdk.get().asFile
        environment("ANDROID_HOME", sdkDir.path)
        fun revision(dir: File) = dir.resolve("source.properties").takeIf { it.isFile }?.let { f ->
            Properties().apply { f.reader().use { load(it) } }.getProperty("Pkg.Revision")
        }
        val home = listOfNotNull(env.orNull?.let(::File), sdkDir.resolve("ndk/$pinned")).firstOrNull { revision(it) == pinned }
            ?: throw GradleException("no Android NDK $pinned: install it with sdkmanager \"ndk;$pinned\" or set ANDROID_NDK_HOME to it")
        environment("ANDROID_NDK_HOME", home.path)
    }
}

// The tunnel for sync away from home: mobile/cbbtun, bound by gomobile into an AAR. It
// needs Go and the pinned NDK.
val tunnelAar = layout.buildDirectory.file("cbbtun/cbbtun.aar")
val bindTunnel = tasks.register<Exec>("bindTunnel") {
    val repo = rootDir.resolve("../..")
    inputs.files(repo.resolve("go.mod"), repo.resolve("go.sum"))
    inputs.dir(repo.resolve("mobile"))
    inputs.dir(repo.resolve("internal/tunnel"))
    outputs.file(tunnelAar)
    workingDir = repo
    commandLine("sh", "mobile/cbbtun/bind.sh", "android", tunnelAar.get().asFile.path)
    withPinnedNdk()
}

// The group's rules: the Rust core's entry point (lite/ffi, docs/core-api.md), which the
// kit calls through JNA, as libcbb_ffi.so for each ABI. It needs the Rust of cbb.rust in
// ../gradle.properties with the Android targets, cargo-ndk and the pinned NDK (lite/ffi/bind.sh).
val coreLibs = layout.buildDirectory.dir("cbbcore")
val bindCore = tasks.register<Exec>("bindCore") {
    val repo = rootDir.resolve("../..")
    inputs.files(repo.resolve("lite/Cargo.lock"), repo.resolve("lite/Cargo.toml"))
    inputs.files(repo.resolve("lite/core/Cargo.toml"), repo.resolve("lite/ffi/Cargo.toml"), repo.resolve("lite/ffi/bind.sh"))
    inputs.dir(repo.resolve("lite/core/src"))
    inputs.dir(repo.resolve("lite/ffi/src"))
    outputs.dir(coreLibs)
    workingDir = repo
    commandLine("sh", "lite/ffi/bind.sh", "android", coreLibs.get().asFile.path)
    inputs.property("rust", rustPinned)
    environment("RUSTUP_TOOLCHAIN", rustPinned)
    withPinnedNdk()
}
// The source set takes a folder, not a provider; preBuild builds what goes in it.
android.sourceSets.getByName("main").jniLibs.srcDir(coreLibs.get().dir("jniLibs").asFile)
tasks.named("preBuild") { dependsOn(bindCore) }

dependencies {
    implementation(files(tunnelAar).builtBy(bindTunnel))
    implementation("io.github.hunterewok.clipboardbridge:kit:0")
    // JNA with its native parts, through which the kit calls the Rust core.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    // The same JNA as a jar for the unit tests on the host: the aar has only Android's libraries.
    testImplementation("net.java.dev.jna:jna:5.19.1")
    implementation(project(":shared"))
    // The kit's TLS: Conscrypt bundled, for TLS 1.3 with the exporter on every Android version.
    implementation("org.conscrypt:conscrypt-android:2.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    // The Wear OS watch (../wear) through the Wearable Data Layer of Google Play services, the
    // only way to a watch; without Play services there is no watch and the rest works as before.
    // Only the full build has it (src/full/.../WatchLink.kt): F-Droid takes no Play services.
    "fullImplementation"("com.google.android.gms:play-services-wearable:20.0.1")
    "fullImplementation"("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.11.0")
    // The QR scanner: CameraX for the frames, ZXing to read them, without Google Play services.
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.4")
    constraints {
        // Guava comes in through the libraries above at 33.3.1, which GHSA-xxph-c9ww-hj94
        // affects; 33.7.2 fixes it.
        implementation("com.google.guava:guava:33.7.2-android")
    }

    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")

    testImplementation("junit:junit:4.13.2")
    // The screens driven as a person would, on the JVM (ScreensTest).
    testImplementation(platform("androidx.compose:compose-bom:2026.09.00"))
    testImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("org.robolectric:robolectric:4.16")
    testImplementation("androidx.test:core:1.7.0")
    testImplementation("androidx.test.ext:junit:1.3.0")

    // The instrumented tests on an emulator (src/androidTest): the screens with Compose's
    // test rule, the system's own screens (notifications, the share sheet) with UI Automator.
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.09.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
