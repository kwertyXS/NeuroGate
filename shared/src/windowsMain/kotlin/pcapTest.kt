import kotlinx.cinterop.*
import pcap.*

@OptIn(ExperimentalForeignApi::class)
fun main() {
    memScoped {
        val alldevs = alloc<CPointerVar<pcap_if>>()
        val errbuf = allocArray<ByteVar>(PCAP_ERRBUF_SIZE)

        if (pcap_findalldevs(alldevs.ptr, errbuf) == -1) {
            println("Error finding devices: ${errbuf.toKString()}")
            return
        }

        var dev = alldevs.value
        while (dev != null) {
            println(dev.pointed.name?.toKString())
            dev = dev.pointed.next
        }

        pcap_freealldevs(alldevs.value)
    }
}