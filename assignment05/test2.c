#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* includes net/ethernet.h */
#include <netinet/tcp.h> /* includes net/ethernet.h */
#include <netinet/udp.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char u_char;


/* FOR TRACKING RETRANSMITTED PACKETS */
// A simple hash table to track TCP sequence numbers
#define MAX_SEQS 10000 // random size basically
static uint32_t seen_tcp_seqs[MAX_SEQS];
static int seq_idx = 0;

int is_retransmission(uint32_t seq_num) {
    for (int i = 0; i < seq_idx; i++) {
        if (seen_tcp_seqs[i] == seq_num) {
            return 1;  //packet is retransmitted
        }
    }
    if (seq_idx < MAX_SEQS) {
        seen_tcp_seqs[seq_idx++] = seq_num;
    }
    return 0;
}


/* FOR TRACKING STATS ON PROGRAM EXIT*/
static int total_packets = 0;
static int tcp_packets = 0;
static int udp_packets = 0;
static int total_tcp_bytes = 0;
static int total_udp_bytes = 0;
static int tcp_flows = 0;
static int udp_flows = 0;


void print_help() {
   printf("Network traffic monitoring using the Packer Capture library\n\n"
                "Options:\n"
                "-i Select the network interface name (e.g., eth0)\n"
                "-r Packet capture file name (e.g., test.pcap)\n"
                "-f Filter expression in string format (e.g., port 8080)\n"
                "-h Help message, which show the usage of each parameter\n\n");
}

//arxikh mou prospatheia na kano capture packets , alla den katalaba giati den douleve
/*
void capture_packets(const char *network_interface){
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle; //to allaksa

    handle = pcap_open_live(network_interface, BUFSIZ, 1, 1000, errbuff);
    if(handle == NULL){
        fprintf(stderr, "Eroor opening interface %s: %s\n", network_interface, errbuff);
        exit(EXIT_FAILURE);
    }
    printf("Capturing packets on interface: %s\n", network_interface);

    //here we start to capture packets
    struct pcap_pktdr *header;
    const u_char *packet; //sosto
    u_char *ptr; //printing out hardware header info
    int res;

    while ((res=pcap_next_ex(handle,&header,&packet)) >=0 ){
        if (res == 0){
            continue;
        }
        printf("captured a packet with lenglth: %d\n", header.len);

    }
    if (res =-1){
        fprintf(stderr, "error reading packets: %s\n", pcap_geterr(handle));
    }

}
*/

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    //this is for debugging only !
    static int count = 1;
    fprintf(stdout,"%d, ",count);
    if(count == 4)
        fprintf(stdout,"count == 4!!! ");
    if(count == 7)
        fprintf(stdout,"count == 7!! ");
    fflush(stdout);
    count++;
}

void capture_packet_with_filter(const char *dev, const char *filter_expression) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;

    // Open the device for capturing
    descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Capturing packets on %s with filter: %s\n", dev, filter_expression);

    //struct pcap_pkthdr *header;
    struct pcap_pkthdr *header; 
    const u_char *packet;
    int res;
    int packet_count=0;
    int max_packets=50;

    while ((res = pcap_next_ex(descr, &header, &packet)) >= 0) {
        if (res == 0) {
            // Timeout
            continue;
        }

        //printf("Grabbed packet of length %d\n",header->len);

        // Decode Ethernet header
        struct ether_header *eth_header = (struct ether_header *)packet;
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            // Skip non-IP packets
            continue;
        }

        // Decode IP header
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        size_t ip_header_length = ip_header->ip_hl * 4;

        //find the protocol 
        uint8_t protocol = ip_header->ip_p;
        printf("Protocol: ");
        switch (protocol){
            case IPPROTO_TCP:
                printf("TCP\n");
                break;
            case IPPROTO_UDP:
                printf("UDP\n");
                break;
            case IPPROTO_ICMP:
                printf("UDP\n");
                break;
            default:
                printf("Other (protocol number: %d)\n",protocol);
        }

        printf("Packet %d: Source IP: %s, Destination IP: %s \n",
        ++packet_count, inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

        // Check transport layer protocol
        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP packet
            struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);

            if (is_retransmission(ntohl(tcp_header->seq))) {
                printf("Retransmitted TCP Packet: Src Port: %d, Dst Port: %d\n",
                ntohs(tcp_header->source), ntohs(tcp_header->dest));
            }

            int tcp_header_length = tcp_header->doff * 4; // TCP header length in bytes
            int tcp_payload_length = header->len - (sizeof(struct ether_header) + ip_header_length + tcp_header_length);
            printf("TCP Packet: Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
            printf("TCP Header Length: %d bytes, TCP Payload Length: %d bytes\n", tcp_header_length, tcp_payload_length);
    
            const u_char *payload = packet + sizeof(struct ether_header) + ip_header_length + tcp_header_length;
            printf("TCP Payload starts at memory location: %p\n", payload);
            // Apply filter
          
            if (filter_expression) {
                char *filter_port_str = strstr(filter_expression, "port ");
                if (filter_port_str) {
                    int filter_port = atoi(filter_port_str + 5); // Extract port from "port XXXX"
                    if (ntohs(tcp_header->source) != filter_port && ntohs(tcp_header->dest) != filter_port) {
                        continue; // Skip packet if it doesn't match the port
                    }
                }
            }
            
            printf("TCP Packet: Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));

            total_tcp_bytes += header->len;
            tcp_packets++;
            tcp_flows++;

        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP packet
            struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_length);
            
            // can't replicate the same method of udp (doesn't have the seq inside its struct)
            // if (is_retransmission(ntohl(udp_header->seq))) {
            //     printf("Retransmitted UDP Packet: Src Port: %d, Dst Port: %d\n",
            //     ntohs(udp_header->source), ntohs(udp_header->dest));
            // }
            
            int udp_header_length = sizeof(struct udphdr); // UDP header length is fixed
            int udp_payload_length = header->len - (sizeof(struct ether_header) + ip_header_length + udp_header_length);
            
            printf("UDP Packet: Src Port: %d, Dst Port: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest));
            printf("UDP Header Length: %d bytes, UDP Payload Length: %d bytes\n", udp_header_length, udp_payload_length);

            const u_char *payload = packet + sizeof(struct ether_header) + ip_header_length + udp_header_length;
            printf("UDP Payload starts at memory location: %p\n", payload);
            // Apply filter
            if (filter_expression) {
                char *filter_port_str = strstr(filter_expression, "port ");
                //printf("this is the filter port: %s\n", filter_port_str);
                if (filter_port_str) {
                    int filter_port = atoi(filter_port_str + 5); // Extract port from "port XXXX"
                    if (ntohs(udp_header->source) != filter_port && ntohs(udp_header->dest) != filter_port) {
                        printf("\n");
                        printf("Skipped packets with Src Port: %d, Dst Port: %d\n\n",
                        ntohs(udp_header->source), ntohs(udp_header->dest));
                        
                        continue; // Skip packet if it doesn't match the port
                    }
                }
            }

            printf("UDP Packet: Src Port: %d, Dst Port: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest));

            total_udp_bytes += header->len;
            udp_packets++;
            udp_flows++;
        }
        total_packets++;

        if(packet_count>=max_packets){
            printf("Max packets!");
            break;
        }
    }

    if (res == -1) {
        fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(descr));
    }

    pcap_close(descr);
}



void capture_packet(const char *dev){
    int i;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    u_char *ptr; /* printing out hardware header info */

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        printf("NOT SUPPOSED TO BE HERE!");
        exit(1);
    }

    printf("THIS IS THE DEV: %s\n",dev);

    /* open the device for sniffing.

       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
       char *ebuf)

       snaplen - maximum size of packets to capture in bytes
       promisc - set card in promiscuous mode?
       to_ms   - time to wait for packets in miliseconds before read
       times out
       errbuf  - if something happens, place error string here

       Note if you change "prmisc" param to anything other than zero, you will
       get all packets your device sees, whether they are intendeed for you or
       not!! Be sure you know the rules of the network you are running on
       before you set your card in promiscuous mode!!     */

    descr = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    packet = pcap_next(descr,&hdr);

    if(packet == NULL)
    {/* did not work*/
        printf("Didn't grab packet\n");
        exit(1);
    }
    //147.27.113.237 ip sto wlp2s0
    printf("Grabbed packet of length %d\n",hdr.len);
    //auth i entoli xreiazete gia argotera
    pcap_loop(descr,6,my_callback,NULL);

    fprintf(stdout,"\nDone processing packets!\n");

}

int main(int argc, char *argv[]) {
    char *network_interface_name= NULL, *packet_capture_file_name= NULL, *filter_expression= NULL;
    int select_nin = 0, packet_capture = 0, filter_exp_flag = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                network_interface_name = argv[++i];
                select_nin = 1;
            } else {
                fprintf(stderr, "Error: Missing network interface name after -i\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-r") == 0) {
            if (i + 1 < argc) {
                packet_capture_file_name = argv[++i];
                packet_capture=1;
            } else {
                fprintf(stderr, "Error: Missing packet capture file name after -r\n");
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                filter_expression = argv[++i];
                filter_exp_flag=1;
            } else {
                fprintf(stderr, "Error: Missing filter expression after -f\n");
                return 1;
            }
        } 
        else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return 1;
        }
    }

    if (select_nin) {
        printf("Your netowrk interface is %s...\n", network_interface_name);
        //capture_packet(network_interface_name);
        capture_packet_with_filter(network_interface_name, filter_expression);

    } 
    else if (packet_capture) {
        printf("packet capture file name is %s...\n", packet_capture_file_name);

    } 
    else if (filter_exp_flag) {
        printf("Filter expression in string format is %s...\n",filter_expression);

    } 

    printf("\n*** Final Stats ***");
    printf("Total packets: %d", total_packets);
    printf("Total TCP packets: %d\n", tcp_packets);
    printf("Total UDP packets: %d\n", udp_packets);
    printf("Total TCP bytes: %d\n", total_tcp_bytes);
    printf("Total UDP bytes: %d\n", total_udp_bytes);
    printf("Captured %d TCP flows\n", tcp_flows);
    printf("Captured %d UDP flows\n", udp_flows);
    return 0;
}
