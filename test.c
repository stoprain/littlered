#include <pcap.h>
main()
{
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
    {
        printf("failed to activate handle: %s (%s)\n",
               pcap_statustostr(result),
               pcap_geterr(handle));
        return 2;
    }

    // while(1) {

    // }
}