package parser

import kotlinx.cinterop.*
import model.ParsedPacket
import model.TcpFlags
import pcap.pcap_pkthdr
import platform.posix.*

// --- Копии C-структур для парсинга ---

private const val ETHERNET_HEADER_SIZE = 14

@OptIn(ExperimentalForeignApi::class)
private class ip_header(rawPtr: NativePtr) : CStructVar(rawPtr) {
    var ip_vhl: UByte
        get() = memberAt<UByteVar>(0).value
        set(value) { memberAt<UByteVar>(0).value = value }
    val ip_hl: Int get() = (ip_vhl.toInt() and 0x0F)
    var ip_p: UByte
        get() = memberAt<UByteVar>(9).value
        set(value) { memberAt<UByteVar>(9).value = value }
    val ip_src: in_addr get() = memberAt(12)
    val ip_dst: in_addr get() = memberAt(16)
    companion object : CStructVar.Type(20, 4)
}

@OptIn(ExperimentalForeignApi::class)
private class tcp_header(rawPtr: NativePtr) : CStructVar(rawPtr) {
    var th_sport: UShort
        get() = memberAt<UShortVar>(0).value
        set(value) { memberAt<UShortVar>(0).value = value }
    var th_dport: UShort
        get() = memberAt<UShortVar>(2).value
        set(value) { memberAt<UShortVar>(2).value = value }
    var th_offx2: UByte
        get() = memberAt<UByteVar>(12).value
        set(value) { memberAt<UByteVar>(12).value = value }
    val th_flags: UByte
        get() = memberAt<UByteVar>(13).value
    var th_win: UShort
        get() = memberAt<UShortVar>(14).value
        set(value) { memberAt<UShortVar>(14).value = value }

    val th_off: Int get() = (th_offx2.toInt() shr 4)

    companion object : CStructVar.Type(20, 4)
}

@OptIn(ExperimentalForeignApi::class)
private class udp_header(rawPtr: NativePtr) : CStructVar(rawPtr) {
    var uh_sport: UShort
        get() = memberAt<UShortVar>(0).value
        set(value) { memberAt<UShortVar>(0).value = value }
    var uh_dport: UShort
        get() = memberAt<UShortVar>(2).value
        set(value) { memberAt<UShortVar>(2).value = value }
    companion object : CStructVar.Type(8, 2)
}

// --- Сам парсер ---

@OptIn(ExperimentalForeignApi::class)
object PacketParser {

    fun parse(header: CPointer<pcap_pkthdr>, packet: CPointer<u_charVar>): ParsedPacket? {
        val pktHeader = header.pointed
        val packetSize = pktHeader.len.toInt()

        // Пропускаем Ethernet заголовок
        if (packetSize < ETHERNET_HEADER_SIZE) return null
        val ipPacketPtr = (packet + ETHERNET_HEADER_SIZE)!!

        // Парсим IP
        if (packetSize < ETHERNET_HEADER_SIZE + sizeOf<ip_header>()) return null
        val ipHeader = ipPacketPtr.reinterpret<ip_header>().pointed
        val ipHeaderLength = ipHeader.ip_hl * 4
        if (packetSize < ETHERNET_HEADER_SIZE + ipHeaderLength) return null

        val sourceIp = inet_ntoa(ipHeader.ip_src.readValue())?.toKString() ?: return null
        val destIp = inet_ntoa(ipHeader.ip_dst.readValue())?.toKString() ?: return null
        val protocol = ipHeader.ip_p.toInt()

        val transportPacketPtr = (ipPacketPtr + ipHeaderLength)!!
        var sourcePort = 0
        var destPort = 0
        var transportHeaderLength = 0
        var tcpWindowSize = 0
        var tcpFlags = TcpFlags()

        when (protocol) {
            IPPROTO_TCP -> {
                if (packetSize < ETHERNET_HEADER_SIZE + ipHeaderLength + sizeOf<tcp_header>()) return null
                val tcpHeader = transportPacketPtr.reinterpret<tcp_header>().pointed
                transportHeaderLength = tcpHeader.th_off * 4
                sourcePort = ntohs(tcpHeader.th_sport).toInt()
                destPort = ntohs(tcpHeader.th_dport).toInt()
                tcpWindowSize = ntohs(tcpHeader.th_win).toInt()
                
                val flags = tcpHeader.th_flags
                tcpFlags = TcpFlags(
                    fin = (flags.toInt() and 0x01) != 0,
                    syn = (flags.toInt() and 0x02) != 0,
                    rst = (flags.toInt() and 0x04) != 0,
                    psh = (flags.toInt() and 0x08) != 0,
                    ack = (flags.toInt() and 0x10) != 0,
                    urg = (flags.toInt() and 0x20) != 0,
                    ece = (flags.toInt() and 0x40) != 0,
                    cwe = (flags.toInt() and 0x80) != 0
                )
            }
            IPPROTO_UDP -> {
                if (packetSize < ETHERNET_HEADER_SIZE + ipHeaderLength + sizeOf<udp_header>()) return null
                val udpHeader = transportPacketPtr.reinterpret<udp_header>().pointed
                transportHeaderLength = 8
                sourcePort = ntohs(udpHeader.uh_sport).toInt()
                destPort = ntohs(udpHeader.uh_dport).toInt()
            }
            else -> {
                // Для других протоколов портов нет, оставляем 0
            }
        }

        return ParsedPacket(
            timestampSeconds = pktHeader.ts.tv_sec.toLong(),
            timestampMicros = pktHeader.ts.tv_usec.toLong(),
            sourceIp = sourceIp,
            destIp = destIp,
            sourcePort = sourcePort,
            destPort = destPort,
            protocol = protocol,
            packetSize = packetSize,
            tcpFlags = tcpFlags,
            ipHeaderLength = ipHeaderLength,
            transportHeaderLength = transportHeaderLength,
            tcpWindowSize = tcpWindowSize
        )
    }

    // ntohs - преобразует UShort из сетевого порядка байт в хостовый
    private fun ntohs(value: UShort): UShort {
        // На x86/x64 (little-endian) нужно менять байты местами
        return (((value.toInt() and 0xFF) shl 8) or ((value.toInt() and 0xFF00) shr 8)).toUShort()
    }
}
