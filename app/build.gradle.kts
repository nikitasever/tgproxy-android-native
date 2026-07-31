import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// api_id/api_hash are the same Telegram app credentials already used by the
// server-side bot (/opt/tgproxy-bot/config.json) — kept out of source control
// the same way, via a local, gitignored properties file.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

// Gradle's default debug signing config auto-generates ~/.android/debug.keystore
// fresh on every machine/CI runner, so every CI build was signed with a different
// key - Android refuses to install an "update" signed with a different key than
// the currently-installed one (same failure mode as the applicationId collision
// earlier). This pins a stable keystore (written from a secret in CI) instead.
val stableDebugKeystore = rootProject.file("keystore/debug-native.jks")

android {
    namespace = "org.nikitasever.tgproxycheck.nativeapp"
    compileSdk = 37

    defaultConfig {
        // Deliberately distinct from the Python app's org.nikitasever.tgproxycheck —
        // same applicationId with a different signing key makes Android refuse to
        // install ("app not installed"), since they'd collide as the "same" app.
        // ("native" alone is a reserved Java keyword, hence "nativeapp".)
        applicationId = "org.nikitasever.tgproxycheck.nativeapp"
        minSdk = 24
        targetSdk = 37
        // Bump both on every release build - an unchanged versionCode makes Android
        // silently keep the already-installed APK instead of updating (confirmed:
        // v0.1.2 through v0.3.0 all shipped with this stuck at 2, so several
        // "updated" installs were actually still running old code).
        versionCode = 19
        versionName = "0.9.0-native-poc"
        buildConfigField("int", "TG_API_ID", localProps.getProperty("tg.api_id", "0"))
        buildConfigField("String", "TG_API_HASH", "\"${localProps.getProperty("tg.api_hash", "")}\"")
    }

    if (stableDebugKeystore.exists()) {
        signingConfigs {
            create("stableDebug") {
                storeFile = stableDebugKeystore
                storePassword = "tgproxynative2026"
                keyAlias = "tgproxynativedebug"
                keyPassword = "tgproxynative2026"
            }
        }
    }

    buildTypes {
        getByName("debug") {
            if (stableDebugKeystore.exists()) {
                signingConfig = signingConfigs.getByName("stableDebug")
            }
        }
        release {
            isMinifyEnabled = false
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

    // TDLib's prebuilt .so is only published for these ABIs.
    ndkVersion = "28.2.13676358"
    defaultConfig {
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation(platform("androidx.compose:compose-bom:2026.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Prebuilt TDLib native binaries (arm64-v8a) + Kotlin coroutines client.
    implementation("dev.g000sha256:tdl-coroutines-android:14.0.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
