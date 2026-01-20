package flow

import export.CsvWriter
import model.Flow
import model.ParsedPacket

class FlowTracker(
    outputCsvPath: String,
    // Таймаут в секундах. Если по потоку нет пакетов дольше этого времени, он завершается.
    private val flowTimeoutSeconds: Long = 60
) {
    private val activeFlows = mutableMapOf<String, Flow>()
    private val csvWriter = CsvWriter(outputCsvPath)

    init {
        csvWriter.writeHeader(Flow.getCsvHeader())
    }

    fun processPacket(packet: ParsedPacket) {
        // --- НОВЫЙ КОД: Проверяем старые потоки перед обработкой нового ---
        checkForTimedOutFlows(packet.timestampSeconds)

        val flowId = generateFlowId(packet)
        val flow = activeFlows.getOrPut(flowId) {
            println("Новый поток: $flowId")
            Flow(flowId, packet)
        }
        flow.addPacket(packet)

        // Завершаем по FIN/RST, если они есть
        if (packet.tcpFlags.fin || packet.tcpFlags.rst) {
            exportAndRemoveFlow(flow, "FIN/RST")
        }
    }

    fun flushAll() {
        println("Принудительное завершение и сохранение ${activeFlows.size} активных потоков...")
        activeFlows.values.forEach { exportAndRemoveFlow(it, "FORCE", false) }
        activeFlows.clear()
        println("Сохранение завершено.")
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
            println("  - Итоговая статистика: $flow")
        }
        csvWriter.appendRow(flow.toCsvRow())
        activeFlows.remove(flow.flowId)
    }

    private fun generateFlowId(packet: ParsedPacket): String {
        return if (packet.sourceIp < packet.destIp || (packet.sourceIp == packet.destIp && packet.sourcePort < packet.destPort)) {
            "${packet.sourceIp}:${packet.sourcePort}-${packet.destIp}:${packet.destPort}-${packet.protocol}"
        } else {
            "${packet.destIp}:${packet.destPort}-${packet.sourceIp}:${packet.sourcePort}-${packet.protocol}"
        }
    }
}
