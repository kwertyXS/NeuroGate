import capture.PcapCapturer
import flow.FlowTracker
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.staticCFunction
import parser.PacketParser
import platform.posix.SIGINT
import platform.posix.signal

private var globalCapturer: PcapCapturer? = null

@OptIn(ExperimentalForeignApi::class)
private fun shutdownHook(signal: Int) {
    println("\nПолучен сигнал $signal (Ctrl+C), прерываем pcap_loop...")
    globalCapturer?.stopCapture()
}

@OptIn(ExperimentalForeignApi::class)
fun main() {
    println("Запуск анализатора трафика...")

    // Создаем трекер, указываем имя файла и таймаут потока в 15 секунд
    val flowTracker = FlowTracker(
        outputCsvPath = "traffic_log.csv",
        flowTimeoutSeconds = 15
    )

    val capturer = PcapCapturer { header, packet ->
        val parsedPacket = PacketParser.parse(header, packet)
        if (parsedPacket != null) {
            flowTracker.processPacket(parsedPacket)
        }
    }
    globalCapturer = capturer

    signal(SIGINT, staticCFunction(::shutdownHook))

    try {
        capturer.startCapture()
    } finally {
        println("Блок finally: сохраняем оставшиеся данные.")
        flowTracker.flushAll()
        println("Программа завершена.")
    }
}
