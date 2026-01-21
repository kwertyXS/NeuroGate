package sync

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.free
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import platform.windows.CRITICAL_SECTION
import platform.windows.DeleteCriticalSection
import platform.windows.EnterCriticalSection
import platform.windows.InitializeCriticalSection
import platform.windows.LeaveCriticalSection

@OptIn(ExperimentalForeignApi::class)
internal class Mutex {
    // Выделяем память под структуру и получаем на нее "умный" указатель
    private val criticalSection = nativeHeap.alloc<CRITICAL_SECTION>()

    init {
        // Используем .ptr, чтобы передать "сырой" указатель в C-функцию
        InitializeCriticalSection(criticalSection.ptr)
    }

    fun lock() {
        EnterCriticalSection(criticalSection.ptr)
    }

    fun unlock() {
        LeaveCriticalSection(criticalSection.ptr)
    }

    fun close() {
        DeleteCriticalSection(criticalSection.ptr)
        // Освобождаем память, передавая сам объект
        nativeHeap.free(criticalSection)
    }
}

internal inline fun <T> Mutex.withLock(block: () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}
