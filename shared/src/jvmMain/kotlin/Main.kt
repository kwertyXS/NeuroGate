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

    // Параметры для нормализации (StandardScaler), полученные из Python
    val means = floatArrayOf(31643.18918919f, 20154.29729730f, 17.37837838f, 4619276.81081081f, 128.91891892f, 5.83783784f, 23183.10810811f, 731.81081081f, 163.97297297f, 65.59459459f, 97.98033149f, 33.68246280f, 56.91891892f, 39.32432432f, 48.26119645f, 6.37057311f, 291373.15194465f, 4325.91127894f, 309388.38451885f, 597176.53580065f, 1578018.83783784f, 0.00000000f, 4602296.13513513f, 555137.18099395f, 726035.80592989f, 1575944.18918919f, 0.00000000f, 4470226.40540540f, 1011603.03376031f, 409494.13043553f, 1575005.32432432f, 644849.21621622f, 1.32432432f, 1.05405405f, 0.00000000f, 0.00000000f, 3639.67567568f, 186.16216216f, 3217.60955328f, 1108.30172566f, 62.51351351f, 169.27027027f, 95.94972130f, 33.75244246f, 6132.84095268f, 0.40540541f, 0.00000000f, 0.00000000f, 2.37837838f, 4.81081081f, 0.00000000f, 0.00000000f, 0.00000000f, 0.30403574f, 95.94972130f, 97.98033149f, 48.26119645f, 3639.67567568f, 0.00000000f, 0.00000000f, 0.00000000f, 0.00000000f, 0.00000000f, 0.00000000f, 128.91891892f, 23183.10810811f, 5.83783784f, 731.81081081f, 685.72972973f, 238.45945946f, 128.91891892f, 16.64864865f, 2043193.13352638f, 29431.47028262f, 2098469.97297297f, 2023847.02702703f, 1123438.09266409f, 391094.35057521f, 1483497.48648649f, 821756.51351351f, -0.63943900f, -0.76884183f, 0.35367612f, 0.93536795f, 0.43388374f, -0.90096887f, 138.00000000f, 119.48648649f, 45.40540541f, 97.21621622f, 0.54054054f, 35447.48648649f, 9074601.94594595f, 139.94594595f, 135.45945946f, 61.16216216f, 103.91891892f, 0.37837838f, 35961.62162162f, 9206236.29729730f)
    val scales = floatArrayOf(28013.67920667f, 25412.50058626f, 33.07105483f, 8080809.74337901f, 438.06474768f, 13.82812159f, 89702.97078264f, 1984.43584246f, 251.10237887f, 14.35356526f, 74.80759117f, 79.98561648f, 57.89803637f, 35.67954524f, 46.88677831f, 12.73298206f, 907978.89438495f, 14229.23891686f, 630870.71358821f, 1312734.45365204f, 3460220.89608148f, 1.00000000f, 8083176.97693998f, 1294110.40767958f, 1687740.82689483f, 3469189.94321597f, 1.00000000f, 8048456.88194369f, 2500804.92972135f, 1354732.32172304f, 3480901.97401253f, 2267088.87985708f, 2.38298080f, 3.60889252f, 1.00000000f, 1.00000000f, 12257.83069308f, 401.96231594f, 10276.00133498f, 4447.20242531f, 12.27747140f, 249.90653914f, 71.62999822f, 70.66550489f, 17489.44286108f, 0.71506792f, 1.00000000f, 1.00000000f, 5.86031708f, 8.72968789f, 1.00000000f, 1.00000000f, 1.00000000f, 0.34657407f, 71.62999822f, 74.80759117f, 46.88677831f, 12257.83069308f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 438.06474768f, 89702.97078264f, 13.82812159f, 1984.43584246f, 809.29320677f, 390.64635245f, 438.06474768f, 9.32365842f, 6354453.10058472f, 129634.45596019f, 6346657.02109165f, 6359980.49630631f, 2781049.73798665f, 1323282.10460545f, 3493518.45669455f, 2353040.71164581f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 1.00000000f, 77.27941581f, 70.21381308f, 70.40403070f, 60.80768761f, 0.49835375f, 19837.78968265f, 5078457.27962661f, 69.91073302f, 64.59880117f, 78.52922111f, 66.58113456f, 0.48498266f, 17908.31188168f,  4584484.25205992f)

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
                val extractedFeatures = columns.subList(7, columns.size - 1)
                                         .map { it.trim().toFloat() }
                                         .toFloatArray()

                // Применение нормализации (StandardScaler)
                val scaledFeatures = extractedFeatures.mapIndexed { index, value ->
                    if (index < means.size && index < scales.size && scales[index] != 0.0f) {
                        (value - means[index]) / scales[index]
                    } else {
                        value // Оставляем как есть, если нет параметра для скейлинга или scale равен 0
                    }
                }.toFloatArray()

                // Pad the featureData with zeros to match the expected input size of 100
                val expectedFeatureSize = 100
                val featureData = if (scaledFeatures.size < expectedFeatureSize) {
                    scaledFeatures + FloatArray(expectedFeatureSize - scaledFeatures.size) { 0f }
                } else if (scaledFeatures.size > expectedFeatureSize) {
                    scaledFeatures.copyOfRange(0, expectedFeatureSize)
                } else {
                    scaledFeatures
                }

                val prediction = onnxInference.predict(featureData)
                println("Результат анализа: $prediction")

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
