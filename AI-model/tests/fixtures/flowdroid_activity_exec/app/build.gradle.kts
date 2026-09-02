plugins {
    id("com.android.application")
}

android {
    namespace = "com.toyapk.flowdroid.activityexec"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.toyapk.flowdroid.activityexec"
        minSdk = 23
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}
