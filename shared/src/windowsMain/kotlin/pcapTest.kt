import capture.PcapCapturer
import flow.FlowTracker
import kotlinx.cinterop.*
import model.OnnxModel
import parser.PacketParser
import platform.posix.getenv
import platform.windows.CreateThread
import platform.windows.INFINITE
import platform.windows.LPTHREAD_START_ROUTINE
import platform.windows.WaitForSingleObject

@OptIn(ExperimentalForeignApi::class)
fun main() = memScoped {
    println("Запуск анализатора трафика...")

    val onnxModel = OnnxModel()
    val appDataPath = getenv("APPDATA")?.toKString()
    if (appDataPath != null) {
        val modelPath = "$appDataPath/NeuroGate/model.onnx"
        println("Загрузка модели из $modelPath")
        onnxModel.loadModel(modelPath)
    } else {
        println("Переменная окружения APPDATA не найдена. Модель не будет загружена.")
    }

    val flowTracker = FlowTracker(
        outputCsvPath = "processed_traffic_log.csv",
        flowTimeoutSeconds = 15
    ) { flow ->
        val prediction = onnxModel.predict(flow)
        println("Поток ${flow.flowId} завершен. Результат: $prediction")
    }

    val capturer = PcapCapturer(
        onPacket = { header, packet ->
            val parsedPacket = PacketParser.parse(header, packet)
            if (parsedPacket != null) {
                flowTracker.processPacket(parsedPacket)
            }
        },
        onFlowFinished = { flow ->
            flowTracker.onFlowFinished(flow)
        }
    )

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
    onnxModel.close()

    println("Сохранение оставшихся данных...")
    flowTracker.flushAll()
    flowTracker.close()
    println("Обработанные данные сохранены в processed_traffic_log.csv")

    println("Программа завершена.")
}
