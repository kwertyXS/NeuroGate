package utils

import kotlinx.cinterop.*
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import platform.posix.*
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

@OptIn(ExperimentalForeignApi::class)
class DatasetProcessor(private val inputCsvPath: String, private val outputCsvPath: String) {

    fun process() {
        println("Чтение файла: $inputCsvPath")
        val lines = readFile(inputCsvPath)
        if (lines.isEmpty()) {
            println("Ошибка: Входной файл пуст или не может быть прочитан.")
            return
        }
        println("Прочитано ${lines.size} строк.")

        val header = lines.first().split(',')
        val rows = lines.drop(1).map { line ->
            header.zip(line.split(',')).toMap()
        }

        val processedRows = rows.mapNotNull { row ->
            val processedRow = row.toMutableMap()

            // Process timestamp
            row["Timestamp"]?.let { timestamp ->
                try {
                    // Приводим время к стандарту ISO 8601 (заменяем пробел на 'T' и добавляем 'Z')
                    val isoTimestamp = timestamp.trim().replace(' ', 'T') + "Z"
                    val instant = Instant.parse(isoTimestamp)
                    val dateTime = instant.toLocalDateTime(TimeZone.UTC)

                    val minutes = dateTime.hour * 60 + dateTime.minute
                    processedRow["minute_sin"] = sin(2 * PI * minutes / 1440).toString()
                    processedRow["minute_cos"] = cos(2 * PI * minutes / 1440).toString()

                    val dayOfYear = dateTime.dayOfYear
                    val daysInYear = if (isLeapYear(dateTime.year)) 366 else 365
                    processedRow["day_sin"] = sin(2 * PI * dayOfYear / daysInYear).toString()
                    processedRow["day_cos"] = cos(2 * PI * dayOfYear / daysInYear).toString()

                    val weekday = dateTime.dayOfWeek.ordinal + 1
                    processedRow["weekday_sin"] = sin(2 * PI * weekday / 7).toString()
                    processedRow["weekday_cos"] = cos(2 * PI * weekday / 7).toString()
                } catch (e: Exception) {
                    println("Ошибка парсинга timestamp: '$timestamp', ${e.message}")
                    return@mapNotNull null
                }
            }
            processedRow.remove("Timestamp")

            // Process IP addresses
            processIp(row["Source IP"], "src_").forEach { (key, value) ->
                processedRow[key] = value.toString()
            }
            processedRow.remove("Source IP")

            processIp(row["Destination IP"], "dst_").forEach { (key, value) ->
                processedRow[key] = value.toString()
            }
            processedRow.remove("Destination IP")
            processedRow.remove("Flow ID")

            // Map labels
            processedRow["Label"] = mapLabel(row["Label"]).toString()

            processedRow
        }
        println("Обработано ${processedRows.size} из ${rows.size} строк.")


        if (processedRows.isEmpty()) {
            println("Нет данных для записи после обработки.")
            return
        }

        val finalHeader = processedRows.first().keys.toList()
        val finalRows = processedRows.map { row ->
            finalHeader.map { key -> row[key] ?: "" }.joinToString(",")
        }

        println("Запись в файл: $outputCsvPath")
        writeFile(outputCsvPath, listOf(finalHeader.joinToString(",")) + finalRows)
        println("Запись завершена.")
    }

    private fun isLeapYear(year: Int): Boolean {
        return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    }

    private fun processIp(ip: String?, prefix: String): Map<String, Any> {
        if (ip == null) return emptyMap()
        val parts = ip.trim().split('.').mapNotNull { it.toIntOrNull() }
        if (parts.size != 4) return emptyMap()

        val (a, b, c, d) = parts
        val isInternal = (a == 10) || (a == 172 && b in 16..31) || (a == 192 && b == 168)
        val subnet16 = a * 256 + b
        val subnet24 = a * 256 * 256 + b * 256 + c

        return mapOf(
            "${prefix}ip_a" to a,
            "${prefix}ip_b" to b,
            "${prefix}ip_c" to c,
            "${prefix}ip_d" to d,
            "${prefix}is_internal" to if (isInternal) 1 else 0,
            "${prefix}subnet_16" to subnet16,
            "${prefix}subnet_24" to subnet24
        )
    }

    private fun mapLabel(label: String?): Int {
        return when (label?.trim()) {
            "BENIGN" -> 0
            "Bot" -> 1
            "DDoS" -> 2
            "FTP-Patator" -> 3
            "Infiltration" -> 4
            "PortScan" -> 5
            "SSH-Patator" -> 6
            "Web Attack  Brute Force" -> 7
            "Web Attack  Sql Injection" -> 8
            "Web Attack  XSS" -> 9
            else -> -1 // Unknown label
        }
    }

    private fun readFile(filePath: String): List<String> {
        val file = fopen(filePath, "r")
        if (file == null) {
            println("Не удалось открыть файл для чтения: $filePath")
            return emptyList()
        }
        val lines = mutableListOf<String>()
        try {
            memScoped {
                val bufferLength = 65536
                val buffer = allocArray<ByteVar>(bufferLength)
                while (fgets(buffer, bufferLength, file) != null) {
                    lines.add(buffer.toKString().trim())
                }
            }
        } finally {
            fclose(file)
        }
        return lines
    }

    private fun writeFile(filePath: String, lines: List<String>) {
        val file = fopen(filePath, "w")
        if (file == null) {
            println("Не удалось открыть файл для записи: $filePath")
            return
        }
        try {
            lines.forEach { line ->
                fputs(line + "\n", file)
            }
        } finally {
            fclose(file)
        }
    }
}
