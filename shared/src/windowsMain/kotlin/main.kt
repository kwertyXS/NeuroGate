import kotlinx.cinterop.*
import kotlinx.datetime.Clock
import model.Flow
import model.ParsedPacket
import model.TcpFlags
import pcap.*

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    println("Запуск анализатора трафика (Native)...")

    val flows = mutableMapOf<String, Flow>()
    val flowTimeout = 60L // seconds

    memScoped {
        val errbuf = allocArray<ByteVar>(PCAP_ERRBUF_SIZE)
        val alldevs = alloc<pcap_if_tVar>()

        if (pcap_findalldevs(alldevs.ptr.reinterpret(), errbuf) == -1) {
            println("Ошибка при поиске устройств: ${errbuf.toKString()}")
            return
        }

        var dev = alldevs.value
        if (dev == null) {
            println("Не найдено ни одного сетевого интерфейса.")
            pcap_freealldevs(alldevs.value)
            return
        }

        // Выбираем первое не-loopback устройство
        while (dev?.pointed?.flags?.and(PCAP_IF_LOOPBACK.toUInt()) != 0u) {
            dev = dev?.pointed?.next
            if (dev == null) {
                println("Не найдено ни одного не-loopback сетевого интерфейса.")
                pcap_freealldevs(alldevs.value)
                return
            }
        }
        
        val currentDev = dev!!.pointed
        println("Выбранный интерфейс: ${currentDev.name?.toKString()} (${currentDev.description?.toKString()})")

        val handle = pcap_open_live(currentDev.name, 65536, 1, 1000, errbuf)
        if (handle == null) {
            println("Не удалось открыть интерфейс: ${errbuf.toKString()}")
            pcap_freealldevs(alldevs.value)
            return
        }

        pcap_freealldevs(alldevs.value)

        // Печатаем заголовок CSV
        println(Flow.getCsvHeader())

        println("Начало захвата пакетов...")
        while (true) {
            val header = alloc<pcap_pkthdr>()
            val packetData = pcap_next(handle, header.ptr)

            if (packetData != null) {
                val parsedPacket = parsePacket(header.pointed, packetData)
                if (parsedPacket != null) {
                    val flowId = generateFlowId(parsedPacket)
                    val flow = flows.getOrPut(flowId) { Flow(flowId, parsedPacket) }
                    flow.addPacket(parsedPacket)
                }
            }

            // Проверка и обработка истекших потоков
            val now = Clock.System.now().epochSeconds
            val expiredFlows = mutableListOf<String>()
            flows.filterValues { now - it.getLastPacketTimeSeconds() > flowTimeout }
                 .keys
                 .toCollection(expiredFlows)

            for (flowId in expiredFlows) {
                val flow = flows.remove(flowId)
                if (flow != null) {
                    // Выводим завершенный поток в stdout
                    println(flow.toCsvRow())
                }
            }
        }
        // pcap_close(handle) // Недостижимо в бесконечном цикле
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
fun parsePacket(header: pcap_pkthdr, data: CPointer<u_char>): ParsedPacket? {
    val bytes = data.readBytes(header.caplen.toInt())

    // Ethernet header is 14 bytes
    val ethertype = (bytes[12].toUByte().toInt() shl 8) or bytes[13].toUByte().toInt()
    if (ethertype != 0x0800) { // Not IPv4
        return null
    }

    val ipHeaderOffset = 14
    val ipHeader = parseIpHeader(bytes, ipHeaderOffset) ?: return null

    val transportHeaderOffset = ipHeaderOffset + ipHeader.headerLength
    when (ipHeader.protocol) {
        6 -> { // TCP
            val tcpHeader = parseTcpHeader(bytes, transportHeaderOffset) ?: return null
            return ParsedPacket(
                timestampSeconds = header.ts.tv_sec,
                timestampMicros = header.ts.tv_usec,
                sourceIp = ipHeader.sourceIp,
                destIp = ipHeader.destIp,
                sourcePort = tcpHeader.sourcePort,
                destPort = tcpHeader.destPort,
                protocol = ipHeader.protocol,
                packetSize = header.len.toInt(),
                tcpFlags = tcpHeader.flags,
                ipHeaderLength = ipHeader.headerLength,
                transportHeaderLength = tcpHeader.headerLength,
                tcpWindowSize = tcpHeader.windowSize
            )
        }
        17 -> { // UDP
            val udpHeader = parseUdpHeader(bytes, transportHeaderOffset) ?: return null
            return ParsedPacket(
                timestampSeconds = header.ts.tv_sec,
                timestampMicros = header.ts.tv_usec,
                sourceIp = ipHeader.sourceIp,
                destIp = ipHeader.destIp,
                sourcePort = udpHeader.sourcePort,
                destPort = udpHeader.destPort,
                protocol = ipHeader.protocol,
                packetSize = header.len.toInt(),
                tcpFlags = TcpFlags(), // No flags in UDP
                ipHeaderLength = ipHeader.headerLength,
                transportHeaderLength = 8, // UDP header is always 8 bytes
                tcpWindowSize = 0
            )
        }
        else -> return null
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
fun parseIpHeader(bytes: ByteArray, offset: Int): IpHeader? {
    if (offset + 20 > bytes.size) return null // Min IP header size

    val versionAndIhl = bytes[offset].toUByte().toInt()
    val version = versionAndIhl shr 4
    if (version != 4) return null // Not IPv4

    val headerLength = (versionAndIhl and 0x0F) * 4
    if (offset + headerLength > bytes.size) return null

    val protocol = bytes[offset + 9].toUByte().toInt()
    val sourceIp = "${bytes[offset + 12].toUByte()}.${bytes[offset + 13].toUByte()}.${bytes[offset + 14].toUByte()}.${bytes[offset + 15].toUByte()}"
    val destIp = "${bytes[offset + 16].toUByte()}.${bytes[offset + 17].toUByte()}.${bytes[offset + 18].toUByte()}.${bytes[offset + 19].toUByte()}"

    return IpHeader(version, headerLength, protocol, sourceIp, destIp)
}

@OptIn(ExperimentalUnsignedTypes::class)
fun parseTcpHeader(bytes: ByteArray, offset: Int): TcpHeader? {
    if (offset + 20 > bytes.size) return null // Min TCP header size

    val sourcePort = ((bytes[offset].toUByte().toInt() shl 8) or bytes[offset + 1].toUByte().toInt())
    val destPort = ((bytes[offset + 2].toUByte().toInt() shl 8) or bytes[offset + 3].toUByte().toInt())
    
    val dataOffsetAndReserved = bytes[offset + 12].toUByte().toInt()
    val headerLength = (dataOffsetAndReserved shr 4) * 4
    if (offset + headerLength > bytes.size) return null

    val flagsByte = bytes[offset + 13].toUByte().toInt()
    val flags = TcpFlags(
        fin = (flagsByte and 1) != 0,
        syn = (flagsByte and 2) != 0,
        rst = (flagsByte and 4) != 0,
        psh = (flagsByte and 8) != 0,
        ack = (flagsByte and 16) != 0,
        urg = (flagsByte and 32) != 0,
        ece = (flagsByte and 64) != 0,
        cwe = (flagsByte and 128) != 0
    )
    
    val windowSize = ((bytes[offset + 14].toUByte().toInt() shl 8) or bytes[offset + 15].toUByte().toInt())

    return TcpHeader(sourcePort, destPort, flags, headerLength, windowSize)
}

@OptIn(ExperimentalUnsignedTypes::class)
fun parseUdpHeader(bytes: ByteArray, offset: Int): UdpHeader? {
    if (offset + 8 > bytes.size) return null // UDP header size

    val sourcePort = ((bytes[offset].toUByte().toInt() shl 8) or bytes[offset + 1].toUByte().toInt())
    val destPort = ((bytes[offset + 2].toUByte().toInt() shl 8) or bytes[offset + 3].toUByte().toInt())
    
    return UdpHeader(sourcePort, destPort)
}

fun generateFlowId(packet: ParsedPacket): String {
    // ID потока должен быть одинаковым для обоих направлений
    return if (packet.sourceIp < packet.destIp || (packet.sourceIp == packet.destIp && packet.sourcePort < packet.destPort)) {
        "${packet.sourceIp}:${packet.sourcePort}-${packet.destIp}:${packet.destPort}-${packet.protocol}"
    } else {
        "${packet.destIp}:${packet.destPort}-${packet.sourceIp}:${packet.sourcePort}-${packet.protocol}"
    }
}

// --- Вспомогательные классы ---

data class IpHeader(
    val version: Int,
    val headerLength: Int,
    val protocol: Int,
    val sourceIp: String,
    val destIp: String
)

data class TcpHeader(
    val sourcePort: Int,
    val destPort: Int,
    val flags: TcpFlags,
    val headerLength: Int,
    val windowSize: Int
)

data class UdpHeader(
    val sourcePort: Int,
    val destPort: Int
)
