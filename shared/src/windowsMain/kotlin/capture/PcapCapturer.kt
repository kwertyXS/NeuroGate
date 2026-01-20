package capture

import kotlinx.cinterop.*
import pcap.*
import platform.posix.u_charVar
import kotlin.system.exitProcess

// --- ИСПРАВЛЕНИЕ: Выносим колбэк на верхний уровень файла ---
@OptIn(ExperimentalForeignApi::class)
private fun packetHandler(user: CPointer<u_charVar>?, header: CPointer<pcap_pkthdr>?, packet: CPointer<u_charVar>?) {
    if (user == null || header == null || packet == null) return

    // Преобразуем CPointer обратно в наш класс Capturer
    val capturer = user.asStableRef<PcapCapturer>().get()
    // Вызываем лямбду, которую нам передали в конструкторе
    capturer.onPacket(header, packet)
}


@OptIn(ExperimentalForeignApi::class)
class PcapCapturer(internal val onPacket: (CPointer<pcap_pkthdr>, CPointer<u_charVar>) -> Unit) {

    private var pcapHandle: CPointer<pcap_t>? = null
    private var userStableRef: StableRef<PcapCapturer>? = null

    fun startCapture() {
        val errbuf = nativeHeap.allocArray<ByteVar>(PCAP_ERRBUF_SIZE)
        val deviceName = findDevice(errbuf)

        println("Открытие устройства: $deviceName")
        pcapHandle = pcap_open_live(deviceName, 65535, 1, 1000, errbuf)
        if (pcapHandle == null) {
            println("Ошибка открытия устройства: ${errbuf.toKString()}")
            exitProcess(1)
        }

        println("Захват начат... (Нажмите Ctrl+C для остановки)")

        // Теперь staticCFunction ссылается на настоящую статическую функцию
        val callback = staticCFunction(::packetHandler)
        userStableRef = StableRef.create(this)
        val user = userStableRef!!.asCPointer()

        pcap_loop(pcapHandle, -1, callback, user.reinterpret())
    }

    fun stopCapture() {
        pcapHandle?.let {
            pcap_breakloop(it)
            pcap_close(it)
        }
        userStableRef?.dispose()
        println("\nЗахват остановлен.")
    }

    private fun findDevice(errbuf: CArrayPointer<ByteVar>): String {
        val alldevs = nativeHeap.alloc<CPointerVar<pcap_if>>()
        if (pcap_findalldevs(alldevs.ptr, errbuf) != 0) {
            println("Ошибка поиска устройств: ${errbuf.toKString()}")
            exitProcess(1)
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
        return targetDeviceName ?: run {
            println("Подходящее устройство не найдено.")
            exitProcess(1)
        }
    }
}
