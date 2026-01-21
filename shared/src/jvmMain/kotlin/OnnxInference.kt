import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import java.nio.FloatBuffer

class OnnxInference(modelPath: String) {
    private val environment = OrtEnvironment.getEnvironment()
    private val session: OrtSession

    init {
        session = environment.createSession(modelPath, OrtSession.SessionOptions())
    }

    fun predict(inputData: FloatArray): String {
        val inputName = session.inputNames.iterator().next()
        val tensor = OnnxTensor.createTensor(environment, FloatBuffer.wrap(inputData), longArrayOf(1, inputData.size.toLong()))
        
        session.run(mapOf(inputName to tensor)).use { results ->
            // The 'results' object is a map. We need to get the value from the first entry.
            val outputValue = results.first().value
            // The value is an OnnxTensor.
            val outputTensor = outputValue as OnnxTensor
            // The content of the tensor is a float array of probabilities.
            val probabilities = (outputTensor.value as Array<FloatArray>)[0]
            
            // Find the index of the highest probability to determine the predicted class
            val predictedClass = probabilities.indices.maxByOrNull { probabilities[it] } ?: -1

            // Assuming class 0 is "Normal" and class 1 is "Malicious"
            return if (predictedClass == 0) "Нормальный" else "Вредоносный"
        }
    }

    fun close() {
        session.close()
        environment.close()
    }
}
