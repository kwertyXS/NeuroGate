package ru.kwerty.neurogate.model

import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

class Flow(
    val flowId: String,
    initialPacket: ParsedPacket
) {
    // --- Идентификаторы ---
    val sourceIp: String = initialPacket.sourceIp
    val sourcePort: Int = initialPacket.sourcePort
    val destIp: String = initialPacket.destIp
    val destPort: Int = initialPacket.destPort
    val protocol: Int = initialPacket.protocol

    // --- Временные метки (в микросекундах) ---
    private val startTime: Long = initialPacket.timestampSeconds * 1_000_000L + initialPacket.timestampMicros
    private var lastPacketTime: Long = 0L
    private val packetTimestamps = mutableListOf<Long>()

    // --- Списки для расчета статистики ---
    private val fwdPacketLengths = mutableListOf<Int>()
    private val bwdPacketLengths = mutableListOf<Int>()
    private val fwdHeaderLengths = mutableListOf<Int>()
    private val bwdHeaderLengths = mutableListOf<Int>()
    private val flowIATs = mutableListOf<Long>()
    private val fwdIATs = mutableListOf<Long>()
    private val bwdIATs = mutableListOf<Long>()
    private var lastFwdPacketTime: Long = 0L
    private var lastBwdPacketTime: Long = 0L

    // --- Счетчики флагов ---
    var finFlagCount: Int = 0
    var synFlagCount: Int = 0
    var rstFlagCount: Int = 0
    var pshFlagCount: Int = 0
    var ackFlagCount: Int = 0
    var urgFlagCount: Int = 0
    var cweFlagCount: Int = 0
    var eceFlagCount: Int = 0
    private var fwdPshFlags: Int = 0
    private var bwdPshFlags: Int = 0
    private var fwdUrgFlags: Int = 0
    private var bwdUrgFlags: Int = 0

    // --- Другие характеристики ---
    private var initWinBytesForward: Int = -1
    private var initWinBytesBackward: Int = -1
    private var actDataPktFwd: Int = 0
    private var minSegSizeForward: Int = Int.MAX_VALUE

    init {
        addPacket(initialPacket)
    }

    fun addPacket(packet: ParsedPacket) {
        val packetTime = packet.timestampSeconds * 1_000_000L + packet.timestampMicros
        packetTimestamps.add(packetTime)

        if (lastPacketTime > 0) {
            flowIATs.add(packetTime - lastPacketTime)
        }
        lastPacketTime = packetTime

        val isForward = packet.sourceIp == sourceIp && packet.sourcePort == sourcePort
        if (isForward) { // Пакет "туда" (Forward)
            fwdPacketLengths.add(packet.packetSize)
            fwdHeaderLengths.add(packet.ipHeaderLength + packet.transportHeaderLength)
            if (lastFwdPacketTime > 0) {
                fwdIATs.add(packetTime - lastFwdPacketTime)
            }
            lastFwdPacketTime = packetTime

            if (packet.tcpFlags.psh) fwdPshFlags++
            if (packet.tcpFlags.urg) fwdUrgFlags++

            if (initWinBytesForward == -1 && packet.protocol == 6) { // TCP
                initWinBytesForward = packet.tcpWindowSize
            }
            if (packet.packetSize > (packet.ipHeaderLength + packet.transportHeaderLength)) { // has payload
                actDataPktFwd++
            }
            if (packet.protocol == 6) { // min_seg_size_forward
                 minSegSizeForward = min(minSegSizeForward, packet.transportHeaderLength) // Simplified
            }

        } else { // Пакет "обратно" (Backward)
            bwdPacketLengths.add(packet.packetSize)
            bwdHeaderLengths.add(packet.ipHeaderLength + packet.transportHeaderLength)
            if (lastBwdPacketTime > 0) {
                bwdIATs.add(packetTime - lastBwdPacketTime)
            }
            lastBwdPacketTime = packetTime

            if (packet.tcpFlags.psh) bwdPshFlags++
            if (packet.tcpFlags.urg) bwdUrgFlags++

            if (initWinBytesBackward == -1 && packet.protocol == 6) { // TCP
                initWinBytesBackward = packet.tcpWindowSize
            }
        }

        // Общие счетчики флагов
        if (packet.tcpFlags.fin) finFlagCount++
        if (packet.tcpFlags.syn) synFlagCount++
        if (packet.tcpFlags.rst) rstFlagCount++
        if (packet.tcpFlags.psh) pshFlagCount++
        if (packet.tcpFlags.ack) ackFlagCount++
        if (packet.tcpFlags.urg) urgFlagCount++
        if (packet.tcpFlags.cwe) cweFlagCount++
        if (packet.tcpFlags.ece) eceFlagCount++
    }

    fun getLastPacketTimeSeconds(): Long = lastPacketTime / 1_000_000L

    private fun calculateStats(list: List<Number>): Map<String, Double> {
        if (list.isEmpty()) return mapOf("max" to 0.0, "min" to 0.0, "mean" to 0.0, "std" to 0.0, "sum" to 0.0)
        val doubleList = list.map { it.toDouble() }
        val sum = doubleList.sum()
        val max = doubleList.maxOrNull() ?: 0.0
        val min = doubleList.minOrNull() ?: 0.0
        val mean = doubleList.average()
        val std = if (doubleList.size > 1) sqrt(doubleList.map { (it - mean) * (it - mean) }.sum() / (doubleList.size - 1)) else 0.0
        return mapOf("max" to max, "min" to min, "mean" to mean, "std" to std, "sum" to sum)
    }
    
    private fun calculateActiveIdle(timestamps: List<Long>, threshold: Long = 1_000_000L): Map<String, Double> {
        if (timestamps.size < 2) return mapOf(
            "active_mean" to 0.0, "active_std" to 0.0, "active_max" to 0.0, "active_min" to 0.0,
            "idle_mean" to 0.0, "idle_std" to 0.0, "idle_max" to 0.0, "idle_min" to 0.0
        )

        val iats = timestamps.zipWithNext { a, b -> b - a }
        val activePeriods = mutableListOf<Long>()
        val idlePeriods = mutableListOf<Long>()
        var currentActiveTime = 0L

        iats.forEach { iat ->
            if (iat > threshold) {
                idlePeriods.add(iat)
                if (currentActiveTime > 0) {
                    activePeriods.add(currentActiveTime)
                    currentActiveTime = 0
                }
            } else {
                currentActiveTime += iat
            }
        }
        if (currentActiveTime > 0) activePeriods.add(currentActiveTime)

        val activeStats = calculateStats(activePeriods)
        val idleStats = calculateStats(idlePeriods)

        return mapOf(
            "active_mean" to (activeStats["mean"] ?: 0.0),
            "active_std" to (activeStats["std"] ?: 0.0),
            "active_max" to (activeStats["max"] ?: 0.0),
            "active_min" to (activeStats["min"] ?: 0.0),
            "idle_mean" to (idleStats["mean"] ?: 0.0),
            "idle_std" to (idleStats["std"] ?: 0.0),
            "idle_max" to (idleStats["max"] ?: 0.0),
            "idle_min" to (idleStats["min"] ?: 0.0)
        )
    }


    fun toCsvRow(): String {
        val durationMicro = if (lastPacketTime > startTime) lastPacketTime - startTime else 0
        val durationSec = durationMicro / 1_000_000.0

        val fwdLenStats = calculateStats(fwdPacketLengths)
        val bwdLenStats = calculateStats(bwdPacketLengths)
        val allPacketLengths = fwdPacketLengths + bwdPacketLengths
        val pktLenStats = calculateStats(allPacketLengths)

        val flowIatStats = calculateStats(flowIATs)
        val fwdIatStats = calculateStats(fwdIATs)
        val bwdIatStats = calculateStats(bwdIATs)
        
        val activeIdleStats = calculateActiveIdle(packetTimestamps)

        val totalFwdPackets = fwdPacketLengths.size
        val totalBwdPackets = bwdPacketLengths.size
        val totalPackets = totalFwdPackets + totalBwdPackets

        val totalFwdBytes = fwdPacketLengths.sum().toDouble()
        val totalBwdBytes = bwdPacketLengths.sum().toDouble()
        val totalBytes = totalFwdBytes + totalBwdBytes

        val flowBytesPerSec = if (durationSec > 0) totalBytes / durationSec else 0.0
        val flowPacketsPerSec = if (durationSec > 0) totalPackets / durationSec else 0.0
        
        val fwdPacketsPerSec = if (durationSec > 0) totalFwdPackets / durationSec else 0.0
        val bwdPacketsPerSec = if (durationSec > 0) totalBwdPackets / durationSec else 0.0

        val downUpRatio = if (totalFwdPackets > 0) totalBwdPackets.toDouble() / totalFwdPackets.toDouble() else 0.0
        val avgPacketSize = if (totalPackets > 0) totalBytes / totalPackets else 0.0
        val avgFwdSegmentSize = if (totalFwdPackets > 0) totalFwdBytes / totalFwdPackets else 0.0
        val avgBwdSegmentSize = if (totalBwdPackets > 0) totalBwdBytes / totalBwdPackets else 0.0
        
        val fwdHeaderLengthSum = fwdHeaderLengths.sum()
        val bwdHeaderLengthSum = bwdHeaderLengths.sum()
        
        val timestamp = Instant.fromEpochSeconds(startTime / 1_000_000, (startTime % 1_000_000) * 1000).toLocalDateTime(TimeZone.UTC)
        val formattedTimestamp = "${timestamp.date} ${timestamp.time.hour}:${timestamp.time.minute}:${timestamp.time.second}.${timestamp.time.nanosecond / 1000}"


        val values = listOf(
            flowId, sourceIp, sourcePort, destIp, destPort, protocol,
            formattedTimestamp,
            durationMicro, totalFwdPackets, totalBwdPackets,
            totalFwdBytes.toLong(), totalBwdBytes.toLong(),
            fwdLenStats["max"], fwdLenStats["min"], fwdLenStats["mean"], fwdLenStats["std"],
            bwdLenStats["max"], bwdLenStats["min"], bwdLenStats["mean"], bwdLenStats["std"],
            flowBytesPerSec, flowPacketsPerSec,
            flowIatStats["mean"], flowIatStats["std"], flowIatStats["max"], flowIatStats["min"],
            fwdIatStats["sum"], fwdIatStats["mean"], fwdIatStats["std"], fwdIatStats["max"], fwdIatStats["min"],
            bwdIatStats["sum"], bwdIatStats["mean"], bwdIatStats["std"], bwdIatStats["max"], bwdIatStats["min"],
            fwdPshFlags, bwdPshFlags, fwdUrgFlags, bwdUrgFlags,
            fwdHeaderLengthSum, bwdHeaderLengthSum,
            fwdPacketsPerSec, bwdPacketsPerSec,
            pktLenStats["min"], pktLenStats["max"], pktLenStats["mean"], pktLenStats["std"], pktLenStats["std"]?.let { it * it } ?: 0.0, // Variance
            finFlagCount, synFlagCount, rstFlagCount, pshFlagCount, ackFlagCount, urgFlagCount, cweFlagCount, eceFlagCount,
            downUpRatio, avgPacketSize, avgFwdSegmentSize, avgBwdSegmentSize,
            fwdHeaderLengthSum, // Fwd Header Length.1 - duplicate
            0, 0, 0, 0, 0, 0, // Bulk fields (заглушка)
            totalFwdPackets, totalFwdBytes.toLong(), totalBwdPackets, totalBwdBytes.toLong(), // Subflow
            initWinBytesForward, initWinBytesBackward,
            actDataPktFwd, if (minSegSizeForward == Int.MAX_VALUE) 0 else minSegSizeForward,
            activeIdleStats["active_mean"], activeIdleStats["active_std"], activeIdleStats["active_max"], activeIdleStats["active_min"],
            activeIdleStats["idle_mean"], activeIdleStats["idle_std"], activeIdleStats["idle_max"], activeIdleStats["idle_min"],
            "BENIGN" // Label
        )
        return values.joinToString(",")
    }

    companion object {
        fun getCsvHeader(): String {
            return "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp," +
                "Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets," +
                "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std," +
                "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std," +
                "Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min," +
                "Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min," +
                "Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min," +
                "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,Bwd Header Length," +
                "Fwd Packets/s,Bwd Packets/s,Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,Packet Length Variance," +
                "FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWE Flag Count,ECE Flag Count," +
                "Down/Up Ratio,Average Packet Size,Avg Fwd Segment Size,Avg Bwd Segment Size," +
                "Fwd Header Length.1,Fwd Avg Bytes/Bulk,Fwd Avg Packets/Bulk,Fwd Avg Bulk Rate,Bwd Avg Bytes/Bulk,Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate," +
                "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes," +
                "Init_Win_bytes_forward,Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward," +
                "Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label"
        }
    }
}
