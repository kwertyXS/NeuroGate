import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl


kotlin {
    mingwX64("windows") {
        binaries {
            executable {
                entryPoint = "main"
            }
        }

        compilations.getByName("main") {
            cinterops {
                val pcap by creating {
                    defFile("src/nativeInterop/cinterop/pcap.def")
                    includeDirs("src/nativeInterop/cinterop/includes")
                }
            }
        }
    }


    sourceSets {
        val windowsMain by getting
        val windowsTest by getting
    }
}
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
            // put your Multiplatform dependencies here
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

