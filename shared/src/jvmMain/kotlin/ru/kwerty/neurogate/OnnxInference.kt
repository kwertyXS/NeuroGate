package ru.kwerty.neurogate

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
            val outputValue = results.first().value
            val outputTensor = outputValue as OnnxTensor
            val probabilities = (outputTensor.value as Array<FloatArray>)[0]
            
            val predictedClass = probabilities.indices.maxByOrNull { probabilities[it] } ?: -1

            return if (predictedClass == 0) "Нормальный" else "Вредоносный"
        }
    }

    fun close() {
        session.close()
        environment.close()
    }
}
