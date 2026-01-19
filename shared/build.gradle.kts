import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

kotlin {
    mingwX64("windows") {
        binaries.all {
            linkerOpts.add("-L${project.projectDir}/src/nativeInterop/cinterop/Lib/x64")
        }

        binaries.executable {
            entryPoint = "main"
        }

        compilations.getByName("main") {
            cinterops {
                val pcap by creating {
                    defFile("src/nativeInterop/cinterop/pcap.def")
                    // ВОЗВРАЩАЕМ ЭТУ СТРОКУ: Указываем, где лежат заголовочные файлы.
                    includeDirs("src/nativeInterop/cinterop/Include")
                }
            }
        }
    }

    jvm()

    js {
        browser()
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
    }

    sourceSets {
        val windowsMain by getting
        val windowsTest by getting

        commonMain.dependencies {
            // put your Multiplatform dependencies here
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}
