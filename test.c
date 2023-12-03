#include <pcap.h>
#include <net/ethernet.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

struct ethernet_h{

struct in_addr ether_dest_host; //the destination host address
struct in_addr ether_src_host; //the source host address
u_short ether_type; //to check if its ip etc


};

struct tcp_h{
u_short src_port;   /* source port */
u_short dst_port;   /* destination port */


};

struct ip_h{


unsigned char ip_vhl; //assuming its ipv4 and header length more than 2
unsigned char service; //type of service
unsigned short total_len; //total length
unsigned short identification; // identification
u_short ip_off; //offset field
u_char ttl; // time to live value
u_char ip_protocol; // the protocol
u_short sum; //the checksum
struct in_addr ip_src;
struct in_addr ip_dst;

#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)


};

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

    for (i = 0; (packet = pcap_next(handle, &header)) != NULL; i++){

        printf("-------- Packet %d ------------\n",i);
        printf(" Size: %d bytes",header.len);

        /*ethernet map */
        ethernet = (struct ethernet_h*) (packet);

        printf("\n MAC src: %s", inet_ntoa(ethernet->ether_src_host));
        printf("\n MAC dest: %s", inet_ntoa(ethernet->ether_dest_host));

        ip = (struct ip_h*) (packet + sizeof(struct ethernet_h));


        printf("\n IP src: %s", inet_ntoa(ip->ip_src));
        printf("\n IP dest: %s", inet_ntoa(ip->ip_dst));

        tcp = (struct tcp_h*) (packet + sizeof(struct ethernet_h) + sizeof(struct ip_h));



        printf("\n Src port ; %d", ntohs(tcp->src_port));
        printf("\n Dst port ; %d", ntohs(tcp->dst_port));
        printf("\n");

    }

    // const u_char *packet;
    // struct pcap_pkthdr packet_header;
    // packet = pcap_next(handle, &packet_header);
    // if (packet == NULL) {
    //     printf("No packet found.\n");
    //     return 2;
    // }

    // /* Our function to output some info */
    // print_packet_info(packet, packet_header);

    // while(1) {

    // }
    return 0;
}