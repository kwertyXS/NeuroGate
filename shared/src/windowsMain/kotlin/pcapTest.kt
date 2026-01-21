import capture.PcapCapturer
import flow.FlowTracker
import kotlinx.cinterop.*
import parser.PacketParser
import platform.windows.CreateThread
import platform.windows.INFINITE
import platform.windows.LPTHREAD_START_ROUTINE
import platform.windows.WaitForSingleObject
import utils.DatasetProcessor

@OptIn(ExperimentalForeignApi::class)
fun main() = memScoped {
    println("Запуск анализатора трафика...")

    val outputCsvPath = "traffic_log.csv"
    val processedCsvPath = "processed_traffic_log.csv"

    val flowTracker = FlowTracker(
        outputCsvPath = outputCsvPath,
        flowTimeoutSeconds = 15
    )

    val capturer = PcapCapturer { header, packet ->
        val parsedPacket = PacketParser.parse(header, packet)
        if (parsedPacket != null) {
            flowTracker.processPacket(parsedPacket)
        }
    }

    val stableRef = StableRef.create(capturer)
    val threadParam = stableRef.asCPointer()

    val threadProc = staticCFunction<COpaquePointer?, UInt> { arg ->
        arg?.asStableRef<PcapCapturer>()?.get()?.startCapture()
        0u // Возвращаем успешный код завершения
    }

    val threadHandle = CreateThread(
        null, 0u,
        threadProc.reinterpret(),
        threadParam, 0u, null
    )

    if (threadHandle == null) {
        println("Ошибка создания потока.")
        stableRef.dispose()
        return@memScoped
    }

    println("\n>>> Нажмите Enter для остановки захвата... <<<\n")
    readln()

    println("Остановка захвата...")
    capturer.breakLoop()

    println("Ожидание завершения потока захвата...")
    WaitForSingleObject(threadHandle, INFINITE)
    println("Поток захвата завершен.")

    stableRef.dispose()
    capturer.close()

    println("Сохранение оставшихся данных...")
    flowTracker.flushAll()
    flowTracker.close()
    println("Захваченные данные сохранены в $outputCsvPath")

    println("Начинается обработка датасета...")
    try {
        val processor = DatasetProcessor(outputCsvPath, processedCsvPath)
        processor.process()
        println("Обработанные данные сохранены в $processedCsvPath")
    } catch (e: Exception) {
        println("Произошла ошибка во время обработки датасета: ${e.message}")
    }

    println("Программа завершена.")
}
