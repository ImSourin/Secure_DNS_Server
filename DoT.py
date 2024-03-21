import dns.resolver
import dns.update
import dns.dnssec
import socket
import ssl


def add_record_tls():
    update = dns.update.Update("example.com")

    update.add("ns1011", 300, "A", "192.168.2.1")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE
    # ssl_context.load_cert_chain('ssl_certs/client.crt', 'ssl_certs/client.key')
    print(dns.query.tls(update, "127.0.0.1", port=31111, timeout=100.0, ssl_context=ssl_context))


def get_record_tls():
    resolver = dns.resolver.Resolver()
    resolver.port = 31111
    resolver.nameservers = ["127.0.0.1"]
    answers = resolver.resolve('ns1.example.com', dns.rdatatype.A, tcp=True, lifetime=100.0)

    for rdata in answers:
        print(rdata)


get_record_tls()
