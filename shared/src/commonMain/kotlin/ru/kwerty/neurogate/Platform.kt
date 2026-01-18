package ru.kwerty.neurogate

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform