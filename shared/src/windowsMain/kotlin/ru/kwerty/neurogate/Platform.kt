package ru.kwerty.neurogate

class WindowsPlatform : Platform {
    override val name: String = "Windows"
}

actual fun getPlatform(): Platform = WindowsPlatform()