plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)

    id ("org.jetbrains.kotlin.kapt")
    alias(libs.plugins.hilt.android)

    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.fmm.pocqr"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.fmm.pocqr"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = rootProject.extra["viewBindingEnabled"] as Boolean
    }

}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.navigation.fragment.ktx)
    implementation(libs.androidx.navigation.ui.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)

    // Dagger Hilt
    //DaggerHilt
    implementation(libs.hilt.android)
    kapt(libs.hilt.android.compiler)
    kapt(libs.androidx.hilt.compiler)

    // QR
    implementation (libs.zxing.android.embedded)

    // JSON
    implementation(libs.kotlinx.serialization.json)

    // Biometric
    implementation(libs.androidx.biometric)
    // Jetpack Security
    implementation(libs.androidx.security.crypto.ktx)

    // DataStore
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.datastore.core)
    implementation(libs.androidx.datastore.preferences.core)
}