#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char u_char;

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
        capture_packet(network_interface_name);

    } 
    else if (packet_capture) {
        printf("packet capture file name is %s...\n", packet_capture_file_name);

    } 
    else if (filter_exp_flag) {
        printf("Filter expression in string format is %s...\n",filter_expression);

    } 
    return 0;
}
