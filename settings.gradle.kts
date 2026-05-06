pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "LSPlant"
include(":lsplant")

val testSubmodulesReady = listOf(
    "test/src/main/jni/external/lsparself/CMakeLists.txt",
).all { file(it).exists() }

if (testSubmodulesReady) {
    include(":test")
} else {
    logger.warn(
        "Skipping :test module because required submodules are missing. " +
            "Run `git submodule update --init --recursive` after restoring access."
    )
}
