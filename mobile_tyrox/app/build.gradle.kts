plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.tyrox.mobile"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.tyrox.mobile"
        minSdk = 23
        targetSdk = 35
        versionCode = 4
        versionName = "0.4.0-alpha2"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.webrtc:google-webrtc:1.0.32006")
}
