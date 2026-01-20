package model

data class ParsedPacket(
    val timestampSeconds: Long,
    val timestampMicros: Long,
    val sourceIp: String,
    val destIp: String,
    val sourcePort: Int,
    val destPort: Int,
    val protocol: Int,
    val packetSize: Int,
    val tcpFlags: TcpFlags
)

data class TcpFlags(
    val syn: Boolean = false,
    val ack: Boolean = false,
    val fin: Boolean = false,
    val rst: Boolean = false,
    val psh: Boolean = false,
    val urg: Boolean = false
)
