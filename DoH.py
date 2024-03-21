import dns.resolver
import dns.update
import dns.dnssec
import socket
import ssl


def add_record_https():
    update = dns.update.Update("example.com")

    update.add("ns1011", 300, "A", "192.168.2.1")

    print(dns.query.https(update, "127.0.0.1", port=31111, timeout=100.0, path='/', verify=False))


def get_record_https():
    resolver = dns.resolver.Resolver()
    resolver.port = 31111
    resolver.nameservers = ["127.0.0.1"]
    answers = resolver.resolve('ns1.example.com', dns.rdatatype.A, tcp=True, lifetime=100.0)

    for rdata in answers:
        print(rdata)


add_record_https()
