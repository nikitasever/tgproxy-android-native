import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// api_id/api_hash are the same Telegram app credentials already used by the
// server-side bot (/opt/tgproxy-bot/config.json) — kept out of source control
// the same way, via a local, gitignored properties file.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "org.nikitasever.tgproxycheck"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.nikitasever.tgproxycheck"
        minSdk = 24
        targetSdk = 37
        versionCode = 1
        versionName = "0.1-native-poc"
        buildConfigField("int", "TG_API_ID", localProps.getProperty("tg.api_id", "0"))
        buildConfigField("String", "TG_API_HASH", "\"${localProps.getProperty("tg.api_hash", "")}\"")
    }

    buildTypes {
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
