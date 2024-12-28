from scapy.all import *
from datetime import datetime
import base64

#function to make the student packet
def make_student_packet():
    source_ip = "192.0.2.1" 
    dest_ip = "192.168.1.1"
    dest_port = 54321

    name = "Faye"
    student_id = "0088"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = f"{name}-{student_id} {timestamp}"

    packet = IP(src=source_ip, dst=dest_ip) / TCP(dport=dest_port) / Raw(load=payload)
    print("Student packet created!")
    return packet
    
#function to make 10 packets for port scan
def make_port_scan_packets(protocol_input, random_IP, name, student_ID):
    dest_port = 0
    dest_IP = "192.168.1.2"
    match protocol_input:
        case "HTTP":
            dest_port = 80
        case "HTTPS":
            dest_port = 443
        case "SSH":
            dest_port = 22
        case "TELNET":
            dest_port = 23   
        case "FTP":
            dest_port = 21    
        case "DNS":
            dest_port = 53   
        case "RTSP":
            dest_port = 554  
        case "SQL":
            dest_port = 1433       
        case "RDP":
            dest_port = 3389  
        case "MQTT":
            dest_port = 1883      
        case _:
            dest_port = 0
    
    if dest_port == 0:
        print("Invalid protocol!")
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = f"{name}-{student_ID} {timestamp}"
    packet = IP(src=random_IP, dst=dest_IP) / TCP(dport=dest_port) / Raw(load=payload)
    print(f"Packet for port scan with protocol {protocol_input} created!")
    return packet

#a malicious packet with base64 encoding
def make_base64_packet(random_IP, student_ID):
    dest_ip = "192.168.1.3"
    dest_port = 8080

    encoded_payload=encode_in_base64(student_ID)

    packet = IP(src=random_IP, dst=dest_ip) / TCP(dport=dest_port) / Raw(load=encoded_payload)
    print("Packet with base64 created!")
    return packet

#function to encode in base64 and return the encoded output as a string 
def encode_in_base64(input_string):
    encoded_bytes = base64.b64encode(input_string.encode('utf-8'))
    encoded_str = encoded_bytes.decode('utf-8')
    return encoded_str

def make_dns_packet(random_IP, domain):
    dest_ip = "127.0.0.53" #dns IP of the VM
    dest_port = 53

    packet = IP(src=random_IP, dst=dest_ip) / UDP(dport=dest_port) / \
             DNS(rd=1, qd=DNSQR(qname=domain))
    print(f"DNS packet for {domain} created!")
    return packet

#function for ICMP Packet
def make_icmp_packet(random_IP):
    dest_ip = "192.168.1.4"
    payload = "PingTest-2024"

    packet = IP(src=random_IP, dst=dest_ip) / ICMP() / Raw(load=payload)
    print("ICMP Ping packet created!")
    return packet

source_ip = "192.0.2.2"
packets=[]
protocols=["HTTP", "HTTPS","SSH", "TELNET", "FTP","DNS","RTSP","SQL","RDP","MQTT"]


#make the pcap file
packets.append(make_student_packet())

for protocol in protocols:
    packets.append(make_port_scan_packets(protocol, source_ip, "Asterinos", "00107"))

for i in range(5):
    packets.append(make_base64_packet(f"192.0.3.{i}",f"123456789{i}"))

packets.append(make_dns_packet("192.0.4.1", "malicious.example.com"))
packets.append(make_icmp_packet("192.0.5.1"))

wrpcap("custom_packet.pcap", packets)
