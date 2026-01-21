package model

import kotlinx.cinterop.*
import onnx.* // Исправленный импорт
import onnx.*
import onnx.ORT_
@OptIn(ExperimentalForeignApi::class)
class OnnxModel {

    private val api: OrtApi = OrtGetApiBase()?.pointed?.GetApi?.invoke(ORT_API_VERSION.toUInt())?.pointed
        ?: throw RuntimeException("Failed to get ONNX Runtime API.")

    private var env: CPointer<OrtEnv>? = null
    private var session: CPointer<OrtSession>? = null

    init {
        memScoped {
            val envVar = alloc<CPointerVar<OrtEnv>>()
            checkStatus(api.CreateEnv?.invoke(ORT_LOGGING_LEVEL_WARNING, "NeuroGate".cstr.getPointer(this), envVar.ptr))
            env = envVar.value
        }
    }

    fun loadModel(modelPath: String) {
        val currentEnv = env ?: throw IllegalStateException("ONNX Runtime environment not initialized.")
        memScoped {
            val sessionOptions = alloc<CPointerVar<OrtSessionOptions>>()
            checkStatus(api.CreateSessionOptions?.invoke(sessionOptions.ptr))

            val sessionVar = alloc<CPointerVar<OrtSession>>()
            val wideModelPath = modelPath.wcstr
            checkStatus(api.CreateSession?.invoke(currentEnv, wideModelPath.getPointer(this), sessionOptions.value, sessionVar.ptr))
            session = sessionVar.value

            api.ReleaseSessionOptions?.invoke(sessionOptions.value)
        }
        println("ONNX model loaded successfully from $modelPath")
    }

    fun predict(flow: Flow): String {
        val currentSession = session ?: return "Model not loaded"

        memScoped {
            val allocator = alloc<CPointerVar<OrtAllocator>>()
            checkStatus(api.GetAllocatorWithDefaultOptions?.invoke(allocator.ptr))
            val allocatorPtr = allocator.value!!

            val inputNamePtr = api.SessionGetInputName?.invoke(currentSession, 0.toULong(), allocatorPtr)
            val inputName = inputNamePtr!!.toKString()
            api.AllocatorFree?.invoke(allocatorPtr, inputNamePtr.reinterpret()) // Освобождаем память

            val outputNamePtr = api.SessionGetOutputName?.invoke(currentSession, 0.toULong(), allocatorPtr)
            val outputName = outputNamePtr!!.toKString()
            api.AllocatorFree?.invoke(allocatorPtr, outputNamePtr.reinterpret()) // Освобождаем память

            val featureVector = flow.toFeatureVector()
            val inputTensorValues = allocArray<FloatVar>(featureVector.size)
            featureVector.forEachIndexed { index, value -> inputTensorValues[index] = value }
            
            val inputShape = longArrayOf(1L, featureVector.size.toLong())
            val inputTensor = alloc<CPointerVar<OrtValue>>()

            val memInfo = alloc<CPointerVar<OrtMemoryInfo>>()
            checkStatus(api.CreateCpuMemoryInfo?.invoke(OrtAllocatorType.OrtArenaAllocator, OrtMemType.OrtMemTypeDefault, memInfo.ptr))

            checkStatus(api.CreateTensorWithDataAsOrtValue?.invoke(
                memInfo.value,
                inputTensorValues.reinterpret(), (featureVector.size * Float.SIZE_BYTES).toULong(),
                inputShape.toCValues(), inputShape.size.toULong(),
                ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, // Теперь доступно напрямую
                inputTensor.ptr
            ))

            val inputNamesC = allocArrayOf(inputName.cstr.getPointer(this))
            val outputNamesC = allocArrayOf(outputName.cstr.getPointer(this))
            val outputTensor = alloc<CPointerVar<OrtValue>>()

            checkStatus(api.Run?.invoke(
                currentSession, null,
                inputNamesC, inputTensor.ptr, 1.toULong(),
                outputNamesC, 1.toULong(),
                outputTensor.ptr
            ))

            val outputData = alloc<CPointerVar<FloatVar>>()
            checkStatus(api.GetTensorMutableData?.invoke(outputTensor.value, outputData.ptr.reinterpret()))
            val result = outputData.value!![0]

            api.ReleaseMemoryInfo?.invoke(memInfo.value)
            api.ReleaseValue?.invoke(inputTensor.value)
            api.ReleaseValue?.invoke(outputTensor.value)

            return if (result > 0.5f) "ATTACK" else "BENIGN"
        }
    }

    fun close() {
        session?.let { api.ReleaseSession?.invoke(it) }
        env?.let { api.ReleaseEnv?.invoke(it) }
    }

    private fun checkStatus(status: CPointer<OrtStatus>?) {
        if (status != null) {
            val errorMessage = api.GetErrorMessage?.invoke(status)?.toKString()
            api.ReleaseStatus?.invoke(status)
            if (!errorMessage.isNullOrEmpty()) {
                throw RuntimeException("ONNX Runtime error: $errorMessage")
            }
        }
    }
}
