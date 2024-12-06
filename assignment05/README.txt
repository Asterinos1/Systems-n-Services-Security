Security of Systems-n-Services (2024-2025)

Assignment05
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

Steps
if you dont have the library libpcap first dowload it with this command:
sudo apt-get install libpcap-dev. Then run make to setup the tool.

!!! NOTE: If it says you don't have permission use sudo, example: sudo ./test -i eth0 !!!

For  ./pcap_ex -i try first ifconfigure to see the devices and then write a device to show the len
of packets

For easy testing, install the hping3 tool for packet sending.
Intiliaze a scan and then send some packets using hping3 for the tool to capture.
Example:  sudo hping3 -S -p 80 google.com to generate packets (replace google.com with any site).

Example usage of the tool:

While in inside project's directory, run:
1) make (or sudo gcc pcap_ex.c -o pcap_ex -lpcap (linking library just in case))
2) sudo ./pcap_ex -r mirai.pcap (offline mode, make sure mirai.pcap is inside the project's directory)
3) sudo ./pcap_ex -i eth0 -f port "0808" 
4) sudo hping3 -S -p 0808 google.com (ports must match)
5) or instead visit any site.

Depending if we use online/offline mode, the corresponding output txt file will be created.

Bibliography: https://www.tcpdump.org/manpages/pcap.3pcap.txt

Regarding the theoretical questions on retransmissions for TCP/UDP packets:

We can only tell if an incoming packet is a retransmission only for the TCP packets (as shown in the code of the tool).
This is done because of the nature of the protocol (TCP) we can compare the sequence numbers of the packets and when we find an already sent
sequence, we consider it a retransmission. However in UDP protocol we are very limited as there are no sequence numbers or any other information regarding the packet
that can be utilized to check for retransmissions.
