import kotlinx.datetime.Clock
import model.Flow
import model.ParsedPacket
import model.TcpFlags
import org.pcap4j.core.*
import org.pcap4j.packet.*
import org.pcap4j.packet.factory.PacketFactories
import org.pcap4j.packet.namednumber.DataLinkType
import org.pcap4j.util.NifSelector
import ru.kwerty.neurogate.OnnxInference
import java.io.File
import java.io.IOException
import java.util.*
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.system.exitProcess

fun main() {
    println("Запуск анализатора трафика в реальном времени (Pcap4j)...")

    // --- Загрузка конфигурации и модели ONNX ---
    val properties = Properties()
    val configFile = File("config.properties")
    if (configFile.exists()) {
        configFile.reader(Charsets.UTF_8).use { reader -> properties.load(reader) }
    }
    val modelPath = properties.getProperty("model_path", "model.onnx")
    println("Загрузка модели из: $modelPath")
    val onnxInference = OnnxInference(modelPath)

    // --- Параметры нормализации (опущены для краткости) ---
    val means = floatArrayOf(31643.18918919f, 20154.29729730f, 17.37837838f, 4619276.81081081f, 128.91891892f, 5.83783784f, 23183.10810811f, 731.81081081f, 163.97297297f, 65.59459459f, 97.98033149f, 33.68246280f, 56.91891892f, 39.32432432f, 48.26119645f, 6.37057311f, 291373.15194465f, 4325.91127894f, 309388.38451885f, 597176.53580065f, 1578018.83783784f, 0.00000000f, 4602296.13513513f, 555137.18099395f, 726035.80592989f, 1575944.18918919f, 0.00000000f, 4470226.40540540f, 1011603.03376031f, 409494.13043553f, 1575005.32432432f, 644849.21621622f, 1.32432432f, 1.05405405f, 0.00000000f, 0.00000000f, 3639.67567568f, 186.16216216f, 3217.60955328f, 1108.30172566f, 62.51351351f, 169.27027027f, 95.94972130f, 33.75244246f, 6132.84095268f, 0.40540541f, 0.00000000f, 0.00000000f, 2.37837838f, 4.81081081f, 0.00000000f, 0.00000000f, 0.00000000f, 0.30403574f, 95.94972130f, 97.98033149f, 48.26119645f, 3639.67567568f, 0.00000000f, 0.00000000f, 0.00000000f, 0.00000000f, 0.00000000f, 0.00000000f, 128.91891892f, 23183.10810811f, 5.83783784f, 731.81081081f, 685.72972973f, 238.45945946f, 128.91891892f, 16.64864865f, 2043193.13352638f, 29431.47028262f, 2098469.97297297f, 2023847.02702703f, 1123438.09266409f, 391094.35057521f, 1483497.48648649f, 821756.51351351f, -0.63943900f, -0.76884183f, 0.35367612f, 0.93536795f, 0.43388374f, -0.90096887f, 138.00000000f, 119.48648649f, 45.40540541f, 97.21621622f, 0.54054054f, 35447.48648649f, 9074601.94594595f, 139.94594595f, 135.45945946f, 61.16216216f, 103.91891892f, 0.37837838f, 35961.62162162f, 9206236.29729730f)
    val scales = floatArrayOf(28013.67920667f, 25412.50058626f, 33.07105483f, 8080809.74337901f, 438.06474768f, 13.82812159f, 89702.97078264f, 1984.43584246f, 251.10237887f, 14.35356526f, 74.80759117f, 79.98561648f, 57.89803637f, 35.67954524f, 46.88677831f, 12.73298206f, 907978.89438495f, 14229.23891686f, 630870.71358821f, 1312734.45365204f, 3460220.89608148f, 1.00000000f, 8083176.97693998f, 1294110.40767958f, 1687740.82689483f, 3469189.94321597f, 1.00000000f, 8048456.88194369f, 2500804.92972135f, 1354732.32172304f, 3480901.97401253f, 2267088.87985708f, 2.38298080f, 3.60889252f, 1.00000000f, 1.00000000f, 12257.83069308f, 401.96231594f, 10276.00133498f, 4447.20242531f, 12.27747140f, 249.90653914f, 71.62999822f, 70.66550489f, 17489.44286108f, 0.71506792f, 1.00000000f, 1.00000000f, 5.86031708f, 8.72968789f, 1.00000000f, 1.00000000f, 1.00000000f, 0.34657407f, 71.62999822f, 74.80759117f, 46.88677831f, 12257.83069308f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 438.06474768f, 89702.97078264f, 13.82812159f, 1984.43584246f, 809.29320677f, 390.64635245f, 438.06474768f, 9.32365842f, 6354453.10058472f, 129634.45596019f, 6346657.02109165f, 6359980.49630631f, 2781049.73798665f, 1323282.10460545f, 3493518.45669455f, 2353040.71164581f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 77.27941581f, 70.21381308f, 70.40403070f, 60.80768761f, 0.49835375f, 19837.78968265f, 5078457.27962661f, 69.91073302f, 64.59880117f, 78.52922111f, 66.58113456f, 0.48498266f, 17908.31188168f,  4584484.25205992f)

    // --- Настройка Pcap4j ---
    val nif: PcapNetworkInterface = try {
        Pcaps.findAllDevs().firstOrNull {
            val description = it.description ?: ""
            !it.isLoopBack && description.contains("Realtek", ignoreCase = true)
        } ?: throw IOException("Сетевой интерфейс Realtek не найден.")
    } catch (e: Exception) {
        println("Не удалось программно найти интерфейс: ${e.message}")
        exitProcess(1)
    }

    println("Выбранный интерфейс: ${nif.name} (${nif.description})")

    val handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)
    
    println("Тип канального уровня (DLT): ${handle.dlt.name()} (${handle.dlt.value()})")

    val executor = Executors.newSingleThreadExecutor()

    // --- Основная логика ---
    val flows = Collections.synchronizedMap(mutableMapOf<String, Flow>())
    val flowTimeout = 10L // seconds
    val parsedPacketCount = AtomicInteger(0)
    val totalPacketCount = AtomicInteger(0)


    val listener = PacketListener { packet ->
        totalPacketCount.incrementAndGet()
        val timestamp = handle.timestamp
        val parsedPacket = parsePcap4jPacket(packet, timestamp)
        if (parsedPacket != null) {
            parsedPacketCount.incrementAndGet()
            val flowId = generateFlowId(parsedPacket)
            val flow = flows.getOrPut(flowId) { Flow(flowId, parsedPacket) }
            flow.addPacket(parsedPacket)
        }
    }

    try {
        val task = executor.submit { handle.loop(-1, listener) }
        println("Начало захвата пакетов...")

        while (task.isDone.not()) {
            Thread.sleep(1000)
            print("\r[.] Захвачено: ${totalPacketCount.get()}, Разобрано: ${parsedPacketCount.get()}, Активных потоков: ${flows.size}...")

            val now = Clock.System.now().epochSeconds
            var processedInLoop = false
            flows.entries.removeIf { (_, flow) ->
                if (now - flow.getLastPacketTimeSeconds() > flowTimeout) {
                    if (!processedInLoop) {
                        println() 
                        processedInLoop = true
                    }
                    processFlow(flow, onnxInference, means, scales)
                    true
                } else {
                    false
                }
            }
        }
    } catch (e: InterruptedException) {
        println("\nЗахват пакетов прерван.")
    } catch (e: PcapNativeException) {
        println("\nОшибка во время захвата пакетов: ${e.message}")
    } finally {
        handle.breakLoop()
        handle.close()
        executor.shutdown()
        onnxInference.close()
        println("Программа завершена.")
    }
}


fun dump(packet: Packet?, indent: String = "") {
    if (packet == null) return
    println("$indent${packet::class.simpleName}")
    dump(packet.payload, "$indent  ")
}


fun parsePcap4jPacket(packet: Packet, timestamp: java.sql.Timestamp): ParsedPacket? {

    val ipPacket = packet.get(IpPacket::class.java) ?: return null
    val ipHeader = ipPacket.header

    val sourceIp: String
    val destIp: String
    val protocolNumber: Int
    val ipHeaderLength: Int

    when (ipHeader) {
        is IpV4Packet.IpV4Header -> {
            sourceIp = ipHeader.srcAddr.hostAddress
            destIp = ipHeader.dstAddr.hostAddress
            protocolNumber = ipHeader.protocol.value().toInt()
            ipHeaderLength = ipHeader.ihl * 4
        }
        is IpV6Packet.IpV6Header -> {
            sourceIp = ipHeader.srcAddr.hostAddress
            destIp = ipHeader.dstAddr.hostAddress
            protocolNumber = ipHeader.nextHeader.value().toInt()
            ipHeaderLength = 40 // IPv6 header is fixed at 40 bytes
        }
        else -> return null
    }

    val transportPacket = ipPacket.payload ?: return null

    val sourcePort: Int
    val destPort: Int
    val tcpFlags: TcpFlags
    val transportHeaderLength: Int
    val tcpWindowSize: Int


    when (transportPacket) {
        is TcpPacket -> {
            val tcpHeader = transportPacket.header
            sourcePort = tcpHeader.srcPort.valueAsInt()
            destPort = tcpHeader.dstPort.valueAsInt()
            tcpFlags = TcpFlags(
                syn = tcpHeader.syn,
                ack = tcpHeader.ack,
                fin = tcpHeader.fin,
                rst = tcpHeader.rst,
                psh = tcpHeader.psh,
                urg = tcpHeader.urg
            )
            transportHeaderLength = tcpHeader.dataOffset.toInt() * 4
            tcpWindowSize = tcpHeader.windowAsInt
        }

        is UdpPacket -> {
            val udpHeader = transportPacket.header
            sourcePort = udpHeader.srcPort.valueAsInt()
            destPort = udpHeader.dstPort.valueAsInt()
            tcpFlags = TcpFlags()
            transportHeaderLength = 8
            tcpWindowSize = 0
        }

        else -> return null
    }

    return ParsedPacket(
        timestampSeconds = timestamp.time / 1000,
        timestampMicros = (timestamp.time % 1000) * 1000 + (timestamp.nanos % 1_000_000) / 1000,
        sourceIp = sourceIp,
        destIp = destIp,
        sourcePort = sourcePort,
        destPort = destPort,
        protocol = protocolNumber,
        packetSize = packet.length(),
        tcpFlags = tcpFlags,
        ipHeaderLength = ipHeaderLength,
        transportHeaderLength = transportHeaderLength,
        tcpWindowSize = tcpWindowSize
    )
}



fun generateFlowId(packet: ParsedPacket): String {
    return if (packet.sourceIp < packet.destIp || (packet.sourceIp == packet.destIp && packet.sourcePort < packet.destPort)) {
        "${packet.sourceIp}:${packet.sourcePort}-${packet.destIp}:${packet.destPort}-${packet.protocol}"
    } else {
        "${packet.destIp}:${packet.destPort}-${packet.sourceIp}:${packet.sourcePort}-${packet.protocol}"
    }
}

fun processFlow(flow: Flow, onnxInference: OnnxInference, means: FloatArray, scales: FloatArray) {
    try {
        // Получаем CSV без метки
        val csvRowWithoutLabel = flow.toCsvRow()
        val columns = csvRowWithoutLabel.split(",")
        
        // Извлекаем признаки (предполагая, что они начинаются с 8-го столбца)
        val extractedFeatures = columns.subList(7, columns.size)
            .mapNotNull { it.trim().toDoubleOrNull()?.toFloat() }
            .toFloatArray()

        if (extractedFeatures.isEmpty()) {
            println("Анализ потока ${flow.flowId}: пропущен (нет признаков)")
            return
        }

        // Масштабируем признаки
        val scaledFeatures = extractedFeatures.mapIndexed { index, value ->
            if (index < means.size && index < scales.size && scales[index] != 0.0f) {
                (value - means[index]) / scales[index]
            } else {
                value
            }
        }.toFloatArray()

        // Дополняем или обрезаем признаки до нужного размера
        val expectedFeatureSize = 100 
        val featureData = if (scaledFeatures.size < expectedFeatureSize) {
            scaledFeatures + FloatArray(expectedFeatureSize - scaledFeatures.size) { 0f }
        } else {
            scaledFeatures.copyOfRange(0, expectedFeatureSize)
        }

        // Получаем предсказание от модели
        val prediction = onnxInference.predict(featureData)

        // Выводим результат
        println("Анализ потока ${flow.flowId}: $prediction")

        // ЕСЛИ ТРАФИК ВРЕДОНОСНЫЙ - записываем в лог
        if (prediction == "Вредоносный") {
            val logFile = File("blocked_ips.log")
            val timestamp = Clock.System.now()
            val logMessage = "$timestamp - Обнаружен вредоносный трафик от IP: ${flow.sourceIp} (Поток: ${flow.flowId})\n"
            logFile.appendText(logMessage, Charsets.UTF_8)
            println("!!! IP-адрес ${flow.sourceIp} записан в ${logFile.absolutePath}")
        }

    } catch (e: Exception) {
        println("Ошибка при обработке потока ${flow.flowId}: ${e.message}")
        e.printStackTrace()
    }
}
