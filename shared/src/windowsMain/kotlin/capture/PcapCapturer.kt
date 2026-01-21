package capture

import kotlinx.cinterop.*
import model.Flow
import model.OnnxModel
import pcap.*
import platform.posix.getenv
import platform.posix.u_charVar

@OptIn(ExperimentalForeignApi::class)
private fun packetHandler(user: CPointer<u_charVar>?, header: CPointer<pcap_pkthdr>?, packet: CPointer<u_charVar>?) {
    if (user == null || header == null || packet == null) return
    val capturer = user.asStableRef<PcapCapturer>().get()
    capturer.onPacket(header, packet)
}

@OptIn(ExperimentalForeignApi::class)
class PcapCapturer(
    internal val onPacket: (CPointer<pcap_pkthdr>, CPointer<u_charVar>) -> Unit,
    private val onFlowFinished: (Flow) -> Unit
) {

    private var pcapHandle: CPointer<pcap_t>? = null
    private var userStableRef: StableRef<PcapCapturer>? = null
    private val onnxModel = OnnxModel()

    init {
        val appDataPath = getenv("APPDATA")?.toKString()
        if (appDataPath != null) {
            onnxModel.loadModel("$appDataPath/NeuroGate/model.onnx")
        } else {
            println("APPDATA environment variable not found. Model not loaded.")
        }
    }

    fun startCapture() {
        val errbuf = nativeHeap.allocArray<ByteVar>(PCAP_ERRBUF_SIZE)
        val deviceName = findDevice(errbuf)

        println("Открытие устройства: $deviceName")
        pcapHandle = pcap_open_live(deviceName, 65535, 1, 1000, errbuf)
        if (pcapHandle == null) {
            println("Ошибка открытия устройства: ${errbuf.toKString()}")
            return
        }

        println("Захват начат...")
        val callback = staticCFunction(::packetHandler)
        userStableRef = StableRef.create(this)
        val user = userStableRef!!.asCPointer()

        pcap_loop(pcapHandle, -1, callback, user.reinterpret())
        println("pcap_loop завершен.")
    }

    // Прерывает pcap_loop. Безопасно для вызова из другого потока.
    fun breakLoop() {
        pcapHandle?.let { pcap_breakloop(it) }
    }

    // Освобождает ресурсы. Вызывать после завершения потока.
    fun close() {
        pcapHandle?.let { pcap_close(it) }
        userStableRef?.dispose()
        onnxModel.close()
        println("\nЗахват остановлен.")
    }

    private fun findDevice(errbuf: CArrayPointer<ByteVar>): String? {
        val alldevs = nativeHeap.alloc<CPointerVar<pcap_if>>()
        if (pcap_findalldevs(alldevs.ptr, errbuf) != 0) {
            println("Ошибка поиска устройств: ${errbuf.toKString()}")
            return null
        }

        var device: pcap_if_t? = alldevs.value?.pointed
        var targetDeviceName: String? = null
        while (device != null) {
            val description = device.description?.toKString() ?: ""
            if (targetDeviceName == null && (device.flags and PCAP_IF_LOOPBACK.toUInt() == 0u) && description.contains("Realtek", ignoreCase = true)) {
                targetDeviceName = device.name?.toKString()
            }
            device = device.next?.pointed
        }

        pcap_freealldevs(alldevs.value)
        return targetDeviceName
    }

    fun handleFlow(flow: Flow) {
        val prediction = onnxModel.predict(flow)
        println("Flow ${flow.flowId} finished. Prediction: $prediction")
        onFlowFinished(flow)
    }
}
