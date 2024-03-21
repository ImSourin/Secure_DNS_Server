import dns.resolver
import dns.update
import dns.dnssec
import socket

def get_record():
    resolver = dns.resolver.Resolver()
    resolver.port = 31111
    resolver.nameservers = ["127.0.0.1"]
    answers = resolver.resolve('ns1.example.com', dns.rdatatype.A)

    for rdata in answers:
        print(rdata)

    answers = resolver.resolve('www.google.com', dns.rdatatype.A)

    for rdata in answers:
        print(rdata)

def add_record():
    update = dns.update.Update("example.com")

    update.add("ns8", 300, "A", "192.168.2.1")

    print(dns.query.udp(update, "127.0.0.1", port=31110))

def perform_axfr_query(zone_name="example.com", master_ip="127.0.0.1"):
    # Create an AXFR query
    axfr_request = dns.query.xfr(master_ip, zone_name, rdtype=dns.rdatatype.IXFR, port=31111,
                                 use_udp=True, relativize=False)

    # Perform the AXFR query and iterate over response messages
    # for response in axfr_request:
    #     if response.rcode() != dns.rcode.NOERROR:
    #         print(f"AXFR query failed with response code: {dns.rcode.to_text(response.rcode())}")
    #         break
    # #
    # #     # Process the response (you can print or save the data)
    #     print(response.to_text())

    zone = dns.zone.from_xfr(axfr_request, relativize=False)
    print(zone)

def udp_client(host="127.0.0.1", port=31112, message="ZONE_TRANSFER example.com 127.0.0.1 31111"):
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send a message to the server
    client_socket.sendto(message.encode('utf-8'), (host, port))

    # Receive the response from the server
    response, server_address = client_socket.recvfrom(1024)

    # Decode and print the response
    decoded_response = response.decode('utf-8')
    print(f"Response from server {server_address}: {decoded_response}")

    # Close the socket
    client_socket.close()

get_record()