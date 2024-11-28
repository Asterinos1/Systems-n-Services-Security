#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void print_help() {
   printf("Network traffic monitoring using the Packer Capture library\n\n"
                "Options:\n"
                "-i Select the network interface name (e.g., eth0)\n"
                "-r Packet capture file name (e.g., test.pcap)\n"
                "-f Filter expression in string format (e.g., port 8080)\n"
                "-h Help message, which show the usage of each parameter\n\n");
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

    } 
    else if (packet_capture) {
        printf("packet capture file name is %s...\n", packet_capture_file_name);

    } 
    else if (filter_exp_flag) {
        printf("Filter expression in string format is %s...\n",filter_expression);

    } 
    return 0;
}