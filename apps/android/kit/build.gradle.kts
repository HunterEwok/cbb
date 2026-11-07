// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's protocol core in Kotlin, the Android twin of
// apps/ios/CBBKit: pairing, certificates, records and the
// member protocol. It has no Android dependencies; its tests run against
// the Go implementation's vectors in testdata/interop.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
    // Test coverage for CI's summary (docs/testing.md, "Coverage").
    jacoco
}

group = "tools.cbb"
version = "0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    // TLS 1.3 with the exporter and ALPN: the app bundles conscrypt-android,
    // the tests use the JVM build, which has the same API.
    compileOnly("org.conscrypt:conscrypt-openjdk-uber:2.8.0")
    testImplementation("org.conscrypt:conscrypt-openjdk-uber:2.8.0")
    // The Rust core's C functions (Core.kt): the app bundles JNA's AAR with
    // its native parts, the tests use the JVM's jar.
    compileOnly("net.java.dev.jna:jna:5.19.1")
    testImplementation("net.java.dev.jna:jna:5.19.1")
    testImplementation(kotlin("test"))
}

// The Rust core for the tests and InteropMain: the host's libcbb_ffi, built
// in the Rust workspace at the top (needs cargo), which decides itself whether
// it is up to date.
val rust = rootDir.resolve("../../..").canonicalFile
val coreDir = rust.resolve("target/release").path
val buildCore by tasks.registering(Exec::class) {
    workingDir = rust
    commandLine("cargo", "build", "--locked", "--release", "-p", "cbb-ffi", "--features", "member")
}

tasks.test {
    useJUnitPlatform()
    dependsOn(buildCore)
    systemProperty("jna.library.path", coreDir)
    // The interop vectors live at the repository's root.
    systemProperty("interop.dir", rootDir.resolve("../../../testdata/interop").canonicalPath)
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

// build/reports/jacoco/test/jacocoTestReport.xml, which tools/coverage reads.
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports { xml.required.set(true); html.required.set(false) }
}

// A script that runs InteropMain, the Kotlin twin of cbb-interop,
// for Go's interop tests: CBB_SWIFT_INTEROP and CBB_SWIFT_INTEROP_TLS name it.
val interopScript by tasks.registering {
    val classpath = sourceSets.test.get().runtimeClasspath
    val script = layout.buildDirectory.file("interop/cbb-interop")
    dependsOn(tasks.testClasses, buildCore)
    inputs.files(classpath)
    outputs.file(script)
    doLast {
        val f = script.get().asFile
        val java = File(System.getProperty("java.home"), "bin/java").path
        f.writeText("#!/bin/sh\nexec '$java' -Djna.library.path='$coreDir' -cp '${classpath.asPath}' tools.cbb.kit.InteropMainKt \"\$@\"\n")
        f.setExecutable(true)
    }
}
