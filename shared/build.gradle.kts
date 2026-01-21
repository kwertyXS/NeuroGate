import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

kotlin {
    jvm()
    js {
        browser()
    }
    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
    }

    sourceSets {
        commonMain.dependencies {
            implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.0")
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        
        jvmMain.dependencies {
            implementation("com.microsoft.onnxruntime:onnxruntime:1.18.0")
            // --- Pcap4j (стабильная версия) ---
//            implementation("org.pcap4j:pcap4j-core:1.8.2")
//
            implementation("org.pcap4j:pcap4j-core:1.8.1") // основной
            implementation("org.pcap4j:pcap4j-packetfactory-static:1.8.1") // packet factories


        }
    }
}
