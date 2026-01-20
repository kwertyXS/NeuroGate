import kotlinx.cinterop.*
import pcap.*
import platform.posix.*
import kotlin.system.exitProcess

// Размеры заголовков (в байтах)
const val ETHERNET_HEADER_SIZE = 14

// Структура для IP-заголовка (упрощенная)
@OptIn(ExperimentalForeignApi::class)
class ip_header(rawPtr: NativePtr) : CStructVar(rawPtr) {
    var ip_vhl: UByte /* version and header length */
        get() = memberAt<UByteVar>(0).value
        set(value) { memberAt<UByteVar>(0).value = value }

    // ... другие поля ip заголовка можно добавить здесь

    var ip_p: UByte /* protocol */
        get() = memberAt<UByteVar>(9).value
        set(value) { memberAt<UByteVar>(9).value = value }

    val ip_src: in_addr
        get() = memberAt(12)

    val ip_dst: in_addr
        get() = memberAt(16)

    companion object : CStructVar.Type(20, 4)
}

@OptIn(ExperimentalForeignApi::class)
fun main() {
    memScoped {
        println("Поиск сетевых устройств...")
        val alldevs = alloc<CPointerVar<pcap_if>>()
        val errbuf = allocArray<ByteVar>(PCAP_ERRBUF_SIZE)

        if (pcap_findalldevs(alldevs.ptr, errbuf) != 0) {
            println("Ошибка: не удалось найти устройства. ${errbuf.toKString()}")
            exitProcess(1)
        }

        var device: pcap_if_t? = alldevs.value?.pointed
        var targetDeviceName: String? = null

        while (device != null) {
            val name = device.name?.toKString()
            val description = device.description?.toKString() ?: ""
            if (targetDeviceName == null && !((device.flags and PCAP_IF_LOOPBACK.toUInt()) != 0u) && description.contains("Realtek", ignoreCase = true)) {
                targetDeviceName = name
            }
            device = device.next?.pointed
        }

        if (targetDeviceName == null) {
            println("\nОшибка: не найдено устройство с 'Realtek' в описании.")
            pcap_freealldevs(alldevs.value)
            exitProcess(1)
        }
        println("\nВыбрано устройство: $targetDeviceName. Попытка открыть...")

        val handle = pcap_open_live(targetDeviceName, 65535, 1, 1000, errbuf)
        pcap_freealldevs(alldevs.value)

        if (handle == null) {
            println("Ошибка: не удалось открыть устройство '$targetDeviceName'. ${errbuf.toKString()}")
            exitProcess(1)
        }
        println("Устройство успешно открыто. Ожидание одного пакета...")

        val header = alloc<CPointerVar<pcap_pkthdr>>()
        val packetData = alloc<CPointerVar<u_charVar>>()

        val result = pcap_next_ex(handle, header.ptr, packetData.ptr)

        if (result > 0) {
            val pktHeader = header.value!!.pointed
            val capturedLen = pktHeader.caplen.toInt()
            println("\n--- УСПЕХ! ---")
            println("Пакет пойман! Длина: $capturedLen байт.")

            // ИСПРАВЛЕНИЕ: Мы уверены, что packetData.value не null, если result > 0
            parsePacket(packetData.value!!, capturedLen)
        } else {
            println("Пакетов нет или произошла ошибка.")
        }

        pcap_close(handle)
        println("\nСеанс захвата закрыт.")
    }
}

@OptIn(ExperimentalForeignApi::class)
fun parsePacket(packet: CPointer<u_charVar>, size: Int) {
    println("\n--- Начинаем парсинг ---")

    // Шаг 1: Пропускаем Ethernet заголовок.
    if (size < ETHERNET_HEADER_SIZE) {
        println("Ошибка: пакет слишком мал для Ethernet-заголовка.")
        return
    }
    // ИСПРАВЛЕНИЕ: Мы уверены, что результат сложения не будет null
    val ipPacket = (packet + ETHERNET_HEADER_SIZE)!!

    // Шаг 2: "Накладываем" нашу структуру ip_header на указатель.
    val ipHeader = ipPacket.reinterpret<ip_header>().pointed

    // Шаг 3: Извлекаем IP-адреса.
    val sourceIp = inet_ntoa(ipHeader.ip_src.readValue())?.toKString()
    val destIp = inet_ntoa(ipHeader.ip_dst.readValue())?.toKString()

    println("IP-адрес источника: $sourceIp")
    println("IP-адрес назначения: $destIp")

    // Шаг 4: Определяем протокол.
    val protocol = when (ipHeader.ip_p.toInt()) {
        IPPROTO_TCP -> "TCP"
        IPPROTO_UDP -> "UDP"
        IPPROTO_ICMP -> "ICMP"
        else -> "Другой (${ipHeader.ip_p})"
    }
    println("Протокол: $protocol")
}
