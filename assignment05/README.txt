Security of Systems-n-Services (2024-2025)

Assignment05
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

Steps
if you dont have the library libpcap first dowload it with this command:
sudo apt-get install libpcap-dev
1. gcc pcap_ex.c -o pcap_ex     or gcc pcap_ex.c -o test -lpcap
2. ./pcap_ex -h or ./pcap_ex -i etc..

NOTE: If it says you don't have permission use sudo, example: sudo ./test -i eth0

for  ./pcap_ex -i try first ifconfigure to see the devices and then write a device to show the len
of packets

Example usage of the tool:
For easy testing install hping3 tool for packet sending
intiliaze a scan and then run for example:  sudo hping3 -S -p 80 google.com to generate packets 
for the tool to capture

1) sudo gcc pcap_ex.c -o pcap_ex -lpcap (linking library just in case)
2) sudo ./pcap_ex -r mirai.pcap (offline mode, make sure mirai.pcap is inside the project's directory)
3) sudo ./pcap_ex -i eth0 -f port "0808" 
4) sudp ./pcap_ex -h 

Depending if we use online/offline mode, the corresponding output txt file will be created.
