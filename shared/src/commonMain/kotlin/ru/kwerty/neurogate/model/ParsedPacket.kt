package ru.kwerty.neurogate.model

data class ParsedPacket(
    val timestampSeconds: Long,
    val timestampMicros: Long,
    val sourceIp: String,
    val destIp: String,
    val sourcePort: Int,
    val destPort: Int,
    val protocol: Int,
    val packetSize: Int,
    val tcpFlags: TcpFlags,
    val ipHeaderLength: Int,
    val transportHeaderLength: Int,
    val tcpWindowSize: Int
)

data class TcpFlags(
    val syn: Boolean = false,
    val ack: Boolean = false,
    val fin: Boolean = false,
    val rst: Boolean = false,
    val psh: Boolean = false,
    val urg: Boolean = false,
    val cwe: Boolean = false,
    val ece: Boolean = false
)
