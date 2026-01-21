package flow

import export.CsvWriter
import model.Flow
import model.ParsedPacket
import sync.Mutex
import sync.withLock

class FlowTracker(
    outputCsvPath: String,
    private val flowTimeoutSeconds: Long = 60,
    private val onFlowFinished: (Flow) -> Unit
) {
    private val activeFlows = mutableMapOf<String, Flow>()
    private val csvWriter = CsvWriter(outputCsvPath)
    private val mutex = Mutex() // Мьютекс для защиты activeFlows

    init {
        csvWriter.writeHeader(Flow.getCsvHeader())
    }

    fun processPacket(packet: ParsedPacket) = mutex.withLock {
        checkForTimedOutFlows(packet.timestampSeconds)

        val flowId = generateFlowId(packet)
        val flow = activeFlows.getOrPut(flowId) {
            println("Новый поток: $flowId")
            Flow(flowId, packet)
        }
        flow.addPacket(packet)

        if (packet.tcpFlags.fin || packet.tcpFlags.rst) {
            exportAndRemoveFlow(flow, "FIN/RST")
        }
    }

    fun flushAll() = mutex.withLock {
        println("Принудительное завершение и сохранение ${activeFlows.size} активных потоков...")
        // Создаем копию, чтобы избежать ConcurrentModificationException
        val flowsToFlush = activeFlows.values.toList()
        flowsToFlush.forEach { exportAndRemoveFlow(it, "FORCE", false) }
        activeFlows.clear()
        println("Сохранение завершено.")
    }

    fun close() {
        mutex.close()
    }

    private fun checkForTimedOutFlows(currentTimeSeconds: Long) {
        val flowsToRemove = mutableListOf<Flow>()
        activeFlows.values.forEach { flow ->
            val timeSinceLastPacket = currentTimeSeconds - flow.getLastPacketTimeSeconds()
            if (timeSinceLastPacket > flowTimeoutSeconds) {
                flowsToRemove.add(flow)
            }
        }

        if (flowsToRemove.isNotEmpty()) {
            println("Найдено ${flowsToRemove.size} устаревших потоков...")
            flowsToRemove.forEach { exportAndRemoveFlow(it, "TIMEOUT") }
        }
    }

    private fun exportAndRemoveFlow(flow: Flow, reason: String, logToConsole: Boolean = true) {
        if (logToConsole) {
            println("Поток завершен ($reason): ${flow.flowId}")
        }
        onFlowFinished(flow)
        csvWriter.appendRow(flow.toCsvRow())
        activeFlows.remove(flow.flowId)
    }
    
    fun onFlowFinished(flow: Flow) {
        onFlowFinished.invoke(flow)
    }

    private fun generateFlowId(packet: ParsedPacket): String {
        return if (packet.sourceIp < packet.destIp || (packet.sourceIp == packet.destIp && packet.sourcePort < packet.destPort)) {
            "${packet.sourceIp}:${packet.sourcePort}-${packet.destIp}:${packet.destPort}-${packet.protocol}"
        } else {
            "${packet.destIp}:${packet.destPort}-${packet.sourceIp}:${packet.sourcePort}-${packet.protocol}"
        }
    }
}
