// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Lists the modules the Android apps are built with, for tools/sbom
// (docs/maintainers/maintaining.md, "What a release is built from"). An init script, so
// the apps' own build files stay as they are:
//
//   ./gradlew --no-configuration-cache --init-script ../../packaging/sbom.init.gradle.kts \
//     -Pcbb.sbom.configs=fullReleaseRuntimeClasspath,releaseRuntimeClasspath :app:cbbSbom :wear:cbbSbom
//
// Each project's task resolves those of the configurations it has and
// writes one group:name:version a line to build/sbom/PROJECT-CONFIGURATION.txt
// under the root project; the build's own projects are left out.

allprojects {
    tasks.register("cbbSbom") {
        description = "Lists the modules of -Pcbb.sbom.configs for tools/sbom."
        doLast {
            val wanted = (project.findProperty("cbb.sbom.configs") as String?)
                ?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?: throw GradleException("cbbSbom needs -Pcbb.sbom.configs")
            val out = project.rootProject.layout.buildDirectory.dir("sbom").get().asFile
            out.mkdirs()
            var written = 0
            for (name in wanted) {
                val cfg = project.configurations.findByName(name) ?: continue
                val modules = cfg.incoming.resolutionResult.allComponents
                    .mapNotNull { it.id as? org.gradle.api.artifacts.component.ModuleComponentIdentifier }
                    .map { "${it.group}:${it.module}:${it.version}" }
                    .toSortedSet()
                File(out, "${project.name}-$name.txt").writeText(modules.joinToString("\n", postfix = "\n"))
                written++
            }
            if (written == 0) {
                throw GradleException("${project.path} has none of the configurations $wanted")
            }
        }
    }
}
