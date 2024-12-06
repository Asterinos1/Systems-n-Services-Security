#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <netinet/udp.h> 
#include <net/ethernet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char u_char;

#define MAX_SEQS 10000 // random size basically :/
#define MAX_FLOWS 10000 // random size again
#define MAX_PACKETS 200 

struct flow_comp{       // we use flow_comp to correctly
    struct in_addr src_ip;  // compare packets and count the total flows.
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; 
};

static int total_packets = 0;
static int tcp_packets = 0;
static int udp_packets = 0;
static int total_tcp_bytes = 0;
static int total_udp_bytes = 0;
static int tcp_flows = 0;
static int udp_flows = 0;

// we keep track of the flows here
static struct flow_comp flow_list[MAX_FLOWS];
static int flow_count = 0;

static uint32_t seen_tcp_seqs[MAX_SEQS];  //better to use unsigned int to guarantee space for entries
static int seq_idx = 0;					  //here we save the retrasmissions


void print_help() {
   printf("Network traffic monitoring using the Packer Capture library\n\n"
                "Options:\n"
                "-i Select the network interface name (e.g., eth0)\n"
                "-r Packet capture file name (e.g., test.pcap)\n"
                "-f Filter expression in string format (e.g., port 8080)\n"
                "-h Help message, which show the usage of each parameter\n\n");
}

// for a flow to exist, 2 packets need to share the same 5 attributes
int compare_flows(const struct flow_comp *flow1, const struct flow_comp *flow2) {
    return (flow1->src_ip.s_addr == flow2->src_ip.s_addr &&
            flow1->dst_ip.s_addr == flow2->dst_ip.s_addr &&
            flow1->src_port == flow2->src_port &&
            flow1->dst_port == flow2->dst_port &&
            flow1->protocol == flow2->protocol);
}

// When we analyze a packet we basically added to our list and
// then compare it with previously encountered packets in order
// to determinate a existing flow. 
int add_flow(struct flow_comp *new_flow) {
    for (int i = 0; i < flow_count; i++) {
        if (compare_flows(&flow_list[i], new_flow)) {
            return 0; // this flow already exists.
        }
    }
    // if it doesn't exist and we are below our limit
    // add it to the list
    if (flow_count < MAX_FLOWS) {
        flow_list[flow_count++] = *new_flow;
        return 1; 
    }
    return 0;
}

int check_retransmission(uint32_t seq_num) {
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


/*function to show the packets captured by pcap_open_live*/
void capture_packet_with_filter(const char *dev, const char *filter_op) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    /*start online capture
    the 1 atrtibute is to enable promiscuous mode and capture packets
    that are not destined to our divice only,we capture packets in the network*/
    descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    printf("Capturing packets on network interface %s with filter: %s\n", dev, filter_op);

    
    struct pcap_pkthdr *header; 
    const u_char *packet;
    int res;
    int packet_count=0;

    /*pcap_next_ex returns 1 when was read without problem and 0 when in live packet capturing
    the packet buffer timeout expired
    */
    while ((res = pcap_next_ex(descr, &header, &packet)) >= 0) {
        if (res == 0) { //so basically we skip any packet buffer that times out
            continue;
        }

        // we take the ip header and decode it
        /*IP adresses are 32-bits and the ip_hl is a 4-bit field
        so to take the actual ip header we multiply by 4 (to be in bytes)
        */
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
        size_t ip_header_length = ip_header->ip_hl * 4;

        //find the protocol 
        uint8_t protocol = ip_header->ip_p;

        //if the user wrote a filter port then skip all the packets with other ports 
        if (filter_op && strlen(filter_op) > 0) {
            char *filter_port_str = strstr(filter_op, "port ");
            if (filter_port_str) {
                //skip the 5 first leters to access the port 
                int filter_port = atoi(filter_port_str + 5); 
                if (protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);
                    if (ntohs(tcp_header->source) != filter_port && ntohs(tcp_header->dest) != filter_port) {
                        continue; 
                    }
                } else if (protocol == IPPROTO_UDP) {
                    struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_length);
                    if (ntohs(udp_header->source) != filter_port && ntohs(udp_header->dest) != filter_port) {
                        continue; 
                    }
                } else {
                    continue;
                }
            }
        }

        //new for flows
        struct flow_comp new_flow;
        new_flow.src_ip = ip_header->ip_src;
        new_flow.dst_ip = ip_header->ip_dst;
        new_flow.protocol = protocol;

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

        printf("\nPacket %d:\nSource IP: %s, Destination IP: %s \n",
        ++packet_count, inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);

            new_flow.src_port = ntohs(tcp_header->source);
            new_flow.dst_port = ntohs(tcp_header->dest);

            if (add_flow(&new_flow)) {
                tcp_flows++; // new TCP flow
            }

			//check retransmission
            if (check_retransmission(ntohl(tcp_header->seq))) {
                printf("Retransmitted TCP Packet: Src Port: %d, Dst Port: %d\n",
                ntohs(tcp_header->source), ntohs(tcp_header->dest));
            }

            //calculate header and payload sizes of tcp
            int tcp_header_length = tcp_header->doff * 4;
            int tcp_payload_length = header->len - (sizeof(struct ethhdr) + ip_header_length + tcp_header_length);

            printf("TCP Packet: Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
            printf("TCP Header Length: %d bytes, TCP Payload Length: %d bytes\n", tcp_header_length, tcp_payload_length);
    

            const u_char *payload = packet + sizeof(struct ethhdr) + ip_header_length + tcp_header_length;
            printf("TCP Payload starts at memory location: %p\n", payload);
            
            total_tcp_bytes += header->len;
            tcp_packets++;

        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP packet
            struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_length);

            //udp flow check
            new_flow.src_port = ntohs(udp_header->source);
            new_flow.dst_port = ntohs(udp_header->dest);

            if (add_flow(&new_flow)) {
                udp_flows++; // new UDP flow
            }

            //same as tcp
            int udp_header_length = sizeof(struct udphdr);
            int udp_payload_length = header->len - (sizeof(struct ether_header) + ip_header_length + udp_header_length);
            printf("UDP Packet: Src Port: %d, Dst Port: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest));
            printf("UDP Header Length: %d bytes, UDP Payload Length: %d bytes\n", udp_header_length, udp_payload_length);

            const u_char *payload = packet + sizeof(struct ether_header) + ip_header_length + udp_header_length;
            printf("UDP Payload starts at memory location: %p\n", payload);

            total_udp_bytes += header->len;
            udp_packets++;
        }
        total_packets++;

        if(packet_count>=MAX_PACKETS){
            printf("Max packets!");
            break;
        }
    }

    if (res == -1) {
        fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(descr));
    }

    pcap_close(descr);
}

/*This is for ofline capture! */
void capture_pcap_file(const char *file_name, const char *filter_op) {
    char errbuf[PCAP_ERRBUF_SIZE];
	//start offline capture
    pcap_t *descr = pcap_open_offline(file_name, errbuf);
    if (descr == NULL) {
        fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Processing pcap file: %s with filter: %s\n", file_name, filter_op);

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    int packet_count = 0;

    //same as before with the online capture
    while ((res = pcap_next_ex(descr, &header, &packet)) >= 0) {
        if (res == 0) {
            continue;
        }

        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
        size_t ip_header_length = ip_header->ip_hl * 4;
        uint8_t protocol = ip_header->ip_p;

        //if the user wrote a filter port then skip all the packets with other ports 
        if (filter_op && strlen(filter_op) > 0) {
            char *filter_port_str = strstr(filter_op, "port ");
            if (filter_port_str) {
                int filter_port = atoi(filter_port_str + 5); //skip the 5 first leters to access the port 
                if (protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);
                    if (ntohs(tcp_header->source) != filter_port && ntohs(tcp_header->dest) != filter_port) {
                        continue; 
                    }
                } else if (protocol == IPPROTO_UDP) {
                    struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_length);
                    if (ntohs(udp_header->source) != filter_port && ntohs(udp_header->dest) != filter_port) {
                        continue; 
                    }
                } else {
                    continue;
                }
            }
        }

        //new for flows
        struct flow_comp new_flow;
        new_flow.src_ip = ip_header->ip_src;
        new_flow.dst_ip = ip_header->ip_dst;
        new_flow.protocol = protocol;

        printf("Protocol: ");
        switch (protocol) {
            case IPPROTO_TCP:
                printf("TCP\n");
                break;
            case IPPROTO_UDP:
                printf("UDP\n");
                break;
            case IPPROTO_ICMP:
                printf("ICMP\n");
                break;
            default:
                printf("Other (protocol number: %d)\n", protocol);
        }
        printf("Packet %d: Source IP: %s, Destination IP: %s \n", ++packet_count, inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);

            //flow check 
            new_flow.src_port = ntohs(tcp_header->source);
            new_flow.dst_port = ntohs(tcp_header->dest);

            if (add_flow(&new_flow)) {
                tcp_flows++; // new TCP flow
            }

			//check retransmission
            if (check_retransmission(ntohl(tcp_header->seq))) {
                printf("Retransmitted TCP Packet: Src Port: %d, Dst Port: %d\n",
                ntohs(tcp_header->source), ntohs(tcp_header->dest));
            }

            int tcp_header_length = tcp_header->doff * 4; // this is TCP header length in bytes
            int tcp_payload_length = header->len - (sizeof(struct ethhdr) + ip_header_length + tcp_header_length);
            printf("TCP Packet: Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
            printf("TCP Header Length: %d bytes, TCP Payload Length: %d bytes\n", tcp_header_length, tcp_payload_length);
    
            const u_char *payload = packet + sizeof(struct ethhdr) + ip_header_length + tcp_header_length;
            printf("TCP Payload starts at memory location: %p\n", payload);

            total_tcp_bytes += header->len;
            tcp_packets++;

        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_length);

            new_flow.src_port = ntohs(udp_header->source);
            new_flow.dst_port = ntohs(udp_header->dest);

            if (add_flow(&new_flow)) {
                udp_flows++; 
            }

            int udp_header_length = sizeof(struct udphdr); 
            int udp_payload_length = header->len - (sizeof(struct ethhdr) + ip_header_length + udp_header_length);
            printf("UDP Packet: Src Port: %d, Dst Port: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest));
            printf("UDP Header Length: %d bytes, UDP Payload Length: %d bytes\n", udp_header_length, udp_payload_length);

            const u_char *payload = packet + sizeof(struct ethhdr) + ip_header_length + udp_header_length;
            printf("UDP Payload starts at memory location: %p\n", payload);

            total_udp_bytes += header->len;
            udp_packets++;
        }
        total_packets++;

        if (packet_count >= MAX_PACKETS) {
            printf("Max packets reached!\n");
            break;
        }
    }

    if (res == -1) {
        fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(descr));
    }

    pcap_close(descr);
}

/*ouput file creation*/
void create_output_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file for writing: %s\n", filename);
        return;
    }
    fprintf(file, "*** Final Stats ***\n");
    fprintf(file, "Total packets: %d\n", total_packets);
    fprintf(file, "Total TCP packets: %d\n", tcp_packets);
    fprintf(file, "Total UDP packets: %d\n", udp_packets);
    fprintf(file, "Total TCP bytes: %d\n", total_tcp_bytes);
    fprintf(file, "Total UDP bytes: %d\n", total_udp_bytes);
    fprintf(file, "Captured %d TCP flows\n", tcp_flows);
    fprintf(file, "Captured %d UDP flows\n", udp_flows);
    fclose(file);
}

int main(int argc, char *argv[]) {
    char *dev = NULL, *file_name = NULL, *filter_op = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                dev = optarg;
                break;
            case 'r':
                file_name = optarg;
                break;
            case 'f':
                filter_op = optarg;
                break;
            case 'h':
                print_help();
                return 0;
            default:
                print_help();
                return 1;
        }
    }

	//offline mode
    if (file_name != NULL) {
        capture_pcap_file(file_name, filter_op);
        create_output_file("offline_output.txt");
        printf("\n*** Final Stats ***\n");
        printf("Total packets: %d\n", total_packets);
        printf("Total TCP packets: %d\n", tcp_packets);
        printf("Total UDP packets: %d\n", udp_packets);
        printf("Total TCP bytes: %d\n", total_tcp_bytes);
        printf("Total UDP bytes: %d\n", total_udp_bytes);
        printf("Captured %d TCP flows\n", tcp_flows);
        printf("Captured %d UDP flows\n", udp_flows);
	
	//online mode
    } else if (dev != NULL) {
        capture_packet_with_filter(dev, filter_op);
        create_output_file("online_output.txt");
        printf("\n*** Final Stats ***\n");
        printf("Total packets: %d\n", total_packets);
        printf("Total TCP packets: %d\n", tcp_packets);
        printf("Total UDP packets: %d\n", udp_packets);
        printf("Total TCP bytes: %d\n", total_tcp_bytes);
        printf("Total UDP bytes: %d\n", total_udp_bytes);
        printf("Captured %d TCP flows\n", tcp_flows);
        printf("Captured %d UDP flows\n", udp_flows);
    } else {
        printf("No input source specified. Use -i for device or -r for pcap file.\n");
        return 1;
    }
    return 0;
}
