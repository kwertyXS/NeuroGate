import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

kotlin {
    // --- Конфигурация для Windows ---
    mingwX64("windows") {
        binaries.all {
            // Указываем линковщику путь к 64-битным библиотекам
            linkerOpts.add("-L${project.projectDir}/src/nativeInterop/cinterop/Lib/x64")
        }
        binaries.executable {
            entryPoint = "main"
        }
        compilations.getByName("main") {
            cinterops {
                val pcap by creating {
                    defFile("src/nativeInterop/cinterop/pcap.def")
                    // Указываем cinterop, где искать заголовочные файлы
                    includeDirs("src/nativeInterop/cinterop/Include")
                }
            }
        }
    }

    // --- Остальные платформы ---
    jvm()
    js {
        browser()
    }
    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
    }

    // --- Общие зависимости ---
    sourceSets {
        val windowsMain by getting
        val windowsTest by getting

        commonMain.dependencies {
            // put your Multiplatform dependencies here
            implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.0")
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        
        jvmMain.dependencies {
            implementation("com.microsoft.onnxruntime:onnxruntime:1.18.0")
        }
    }
}
