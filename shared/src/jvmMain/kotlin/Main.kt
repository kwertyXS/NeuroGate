import java.io.File
import java.util.Properties
import kotlin.text.Charsets

fun main() {
    println("Запуск анализатора трафика...")

    val outputCsvPath = "shared/traffic_log.csv"
    
    val properties = Properties()
    val configFile = File("config.properties")
    if (configFile.exists()) {
        configFile.reader(Charsets.UTF_8).use { reader ->
            properties.load(reader)
        }
    }
    val modelPath = properties.getProperty("model_path", "model.onnx")
    println("Загрузка модели из: $modelPath")

    println("Начинается обработка данных с помощью ONNX модели...")
    try {
        val onnxInference = OnnxInference(modelPath)
        val reader = File(outputCsvPath).bufferedReader()
        
        // Read and ignore the header line
        val header = reader.readLine()
        
        var line: String?
        while (reader.readLine().also { line = it } != null) {
            if (line.isNullOrBlank()) continue

            try {
                val columns = line!!.split(",")
                // Assuming the first 7 columns are identifiers/timestamps and the last is the label.
                // These columns should be skipped.
                val extractedFeatures = columns.subList(7, columns.size - 1)
                                         .map { it.trim().toFloat() }
                                         .toFloatArray()

                // Pad the featureData with zeros to match the expected input size of 100
                val expectedFeatureSize = 100
                val featureData = if (extractedFeatures.size < expectedFeatureSize) {
                    extractedFeatures + FloatArray(expectedFeatureSize - extractedFeatures.size) { 0f }
                } else if (extractedFeatures.size > expectedFeatureSize) {
                    extractedFeatures.copyOfRange(0, expectedFeatureSize)
                } else {
                    extractedFeatures
                }

                val prediction = onnxInference.predict(featureData)
                println("Результат анализа для строки: $prediction")

            } catch (e: NumberFormatException) {
                println("Ошибка формата числа в строке: $line - ${e.message}")
            }
        }
        onnxInference.close()
        reader.close()
    } catch (e: Exception) {
        println("Произошла ошибка во время обработки данных: ${e.message}")
        e.printStackTrace()
    }

    println("Программа завершена.")
}
