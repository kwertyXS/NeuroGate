package export

import kotlinx.cinterop.ExperimentalForeignApi
import platform.posix.F_OK
import platform.posix.access
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fputs

@OptIn(ExperimentalForeignApi::class)
class CsvWriter(private val filePath: String) {

    fun writeHeader(header: String) {
        // Перезаписываем файл, если он существует, чтобы начать с чистого заголовка
        val file = fopen(filePath, "w")
        if (file != null) {
            try {
                fputs(header + "\n", file)
            } finally {
                fclose(file)
            }
        } else {
            println("Ошибка: не удалось открыть файл для записи: $filePath")
        }
    }

    fun appendRow(row: String) {
        // Открываем файл в режиме добавления ("a")
        val file = fopen(filePath, "a")
        if (file != null) {
            try {
                fputs(row + "\n", file)
            } finally {
                fclose(file)
            }
        } else {
            println("Ошибка: не удалось открыть файл для добавления: $filePath")
        }
    }
}
