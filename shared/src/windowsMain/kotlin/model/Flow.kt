package model

import kotlin.math.max
import kotlin.math.min

class Flow(
    val flowId: String,
    initialPacket: ParsedPacket
) {
    // Основные идентификаторы
    val sourceIp: String = initialPacket.sourceIp
    val sourcePort: Int = initialPacket.sourcePort
    val destIp: String = initialPacket.destIp
    val destPort: Int = initialPacket.destPort
    val protocol: Int = initialPacket.protocol

    // Временные метки (в микросекундах)
    private val startTime: Long = initialPacket.timestampSeconds * 1_000_000L + initialPacket.timestampMicros
    private var lastPacketTime: Long = startTime

    // Статистика пакетов
    var forwardPacketCount: Long = 0
    var backwardPacketCount: Long = 0
    var totalForwardBytes: Long = 0
    var totalBackwardBytes: Long = 0

    // Статистика флагов
    var finFlagCount: Int = 0
    var synFlagCount: Int = 0
    var rstFlagCount: Int = 0
    var pshFlagCount: Int = 0
    var ackFlagCount: Int = 0
    var urgFlagCount: Int = 0

    init {
        addPacket(initialPacket)
    }

    fun addPacket(packet: ParsedPacket) {
        lastPacketTime = max(lastPacketTime, packet.timestampSeconds * 1_000_000L + packet.timestampMicros)

        if (packet.sourceIp == sourceIp && packet.sourcePort == sourcePort) {
            forwardPacketCount++
            totalForwardBytes += packet.packetSize
        } else {
            backwardPacketCount++
            totalBackwardBytes += packet.packetSize
        }

        if (packet.tcpFlags.fin) finFlagCount++
        if (packet.tcpFlags.syn) synFlagCount++
        if (packet.tcpFlags.rst) rstFlagCount++
        if (packet.tcpFlags.psh) pshFlagCount++
        if (packet.tcpFlags.ack) ackFlagCount++
        if (packet.tcpFlags.urg) urgFlagCount++
    }

    fun getFlowDurationMicroseconds(): Long {
        return lastPacketTime - startTime
    }

    // --- НОВЫЙ МЕТОД ---
    fun getLastPacketTimeSeconds(): Long {
        return lastPacketTime / 1_000_000L
    }

    override fun toString(): String {
        return "Flow(id='$flowId', duration=${getFlowDurationMicroseconds() / 1_000_000.0}s, fwdPkts=$forwardPacketCount, bwdPkts=$backwardPacketCount)"
    }

    fun toCsvRow(): String {
        val duration = getFlowDurationMicroseconds()
        return listOf(
            flowId,
            sourceIp,
            sourcePort,
            destIp,
            destPort,
            protocol,
            duration,
            forwardPacketCount,
            backwardPacketCount,
            totalForwardBytes,
            totalBackwardBytes,
            finFlagCount,
            synFlagCount,
            rstFlagCount,
            pshFlagCount,
            ackFlagCount,
            urgFlagCount
        ).joinToString(",")
    }

    companion object {
        fun getCsvHeader(): String {
            return "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol," +
                    "Flow Duration,Total Fwd Packets,Total Backward Packets," +
                    "Total Length of Fwd Packets,Total Length of Bwd Packets," +
                    "FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count"
        }
    }
}
