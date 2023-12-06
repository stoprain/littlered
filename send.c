#include <pcap.h>
#include <net/ethernet.h>
#include <unistd.h>

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int result;

    handle = pcap_create("en0", error_buffer);
    if (handle == NULL)
    {
        printf("failed to create a handle: %s\n",
               error_buffer);
        return 2;
    }
    result = pcap_set_rfmon(handle, 1);
    if (result != 0)
    {
        printf("failed to set pcap rfmon: %s (%s)\n",
               pcap_statustostr(result),
               pcap_geterr(handle));
        return 2;
    }
    result = pcap_activate(handle);
    if (result != 0)
    {
        printf("failed to activate handle: %s (%s)\n",
               pcap_statustostr(result),
               pcap_geterr(handle));
        return 2;
    }

    const unsigned char *packet;
    struct pcap_pkthdr header;
    int i;

    /*Header Structs*/
    const struct ethernet_h *ethernet;
    const struct ip_h *ip;
    const struct tcp_h *tcp;

    while (1) {
        uint8_t data[90] = {
                    0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x83, 0x67, 0x61, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x10, 0x02, 0x6c, 0x09, 0x80, 0x04, 0xea, 0xa6, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0x8c, 0x85, 0x90, 0x16, 0x6d, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x10,
                    0x01, 0x7f, 0x18, 0xfe, 0x34, 0xdf, 0x59, 0x4c, 0xc9, 0xdd, 0x1b, 0x18, 0xfe, 0x34, 0x04, 0x01,
                    0x6a, 0x02, 0xb2, 0x4c, 0x01, 0x88, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8c, 0x85,
                    0x90, 0x16, 0x6d, 0x33, 0x61, 0x61, 0x5c, 0x95, 0xde, 0x47};

        result = pcap_sendpacket(handle, data, 90);
        printf("send result %d\n", result);
        sleep(1);
    }

    return 0;
}