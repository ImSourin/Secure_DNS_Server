import argparse
import copy

import dns
import dns.message
import dns.resolver
import dns.zone
import dns.query
import dns.dnssec
import socket
from dns.zone import Zone
import ssl
import traceback
import re

from dns.exception import ValidationFailure

from cryptography.hazmat.primitives import serialization


class MyDNSHandler:
    def __init__(self, forwarding_server, zone_file_path, private_key_path):
        # Set the forwarding DNS server
        self.forwarding_server = forwarding_server
        self.zone_file_path = zone_file_path
        self.zone = dns.zone.from_file(self.zone_file_path, relativize=False)
        with open(private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

        znode = self.zone.nodes.get(self.zone.origin)
        zrds = znode.find_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY, create=True)

        self.public_key = dns.dnssec.make_dnskey(self.private_key.public_key(), 8)
        zrds.add(self.public_key)

    def resolve(self, request):
        query_name = str(request.question[0].name)
        query_type = dns.rdatatype.to_text(request.question[0].rdtype)

        if hasattr(request, 'update') and len(request.update):
            return self.add_record(request)
        elif query_type == "AXFR" or query_type == "IXFR":
            # Handle zone transfer request
            return self.handle_axfr_request(request)
        else:
            # Handle other query types based on the loaded zone
            return self.handle_standard_query(query_name, query_type)

    def handle_standard_query(self, query_name, query_type):
        # Handle other query types based on the loaded zone
        print(query_name, query_type)
        try:
            return self.zone.find_rrset(
                dns.name.from_text(query_name), dns.rdatatype.from_text(query_type)
            )
        except KeyError:
            print("Forwarding request to 1.1.1.1")
            # Forward unknown requests to the specified DNS server
            return self.forward_query(query_name, query_type)

    def handle_zone_transfer(self, zone_name, host, port):
        # Create a DNS query for a zone transfer (AXFR or IXFR)

        # Perform the query
        axfr_request = dns.query.xfr(host, zone_name, rdtype=dns.rdatatype.IXFR, port=port,
                                     use_udp=True, relativize=False)

        zone = dns.zone.from_xfr(axfr_request, relativize=False)

        self.zone = self.validate_zone(zone)

        # Save the zone to a file
        with open(self.zone_file_path, 'w') as zone_file:
            self.zone.to_file(zone_file, relativize=False, want_origin=True)

        print(f"Zone transfer successful. Zone saved to {self.zone_file_path}")

    def validate_zone(self, zone):
        dns_key = None

        # find public key
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                if rdataset.rdtype == dns.rdatatype.DNSKEY:
                    dns_key = rdataset
                    break

        if not dns_key:
            raise ValidationFailure

        origin = zone.origin
        rrsets = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
                rrset.update(rdataset)
                rrsets.append(rrset)

        validated_rrsets = []
        for i in range(0, len(rrsets), 2):
            dns.dnssec.validate(rrsets[i], rrsets[i + 1], {origin: dns_key}, origin)

            if not rrsets[i].rdtype == dns.rdatatype.DNSKEY:
                validated_rrsets.append(rrsets[i])

        z = Zone(origin, relativize=False)
        for rrset in validated_rrsets:
            znode = z.nodes.get(rrset.name)
            if not znode:
                znode = z.node_factory()
                z.nodes[rrset.name] = znode
            zrds = znode.find_rdataset(rrset.rdclass, rrset.rdtype, rrset.covers, True)
            zrds.update_ttl(rrset.ttl)
            for rd in rrset:
                zrds.add(rd)

        return z

    def handle_axfr_request(self, request):
        try:
            # Create a response
            response = dns.message.make_response(request)

            soa_rrset = None
            # Add other records to the answer section
            for name, node in self.zone.nodes.items():
                for rdataset in node.rdatasets:
                    rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
                    rrset.update(rdataset)
                    sig_rrset = dns.rrset.RRset(name, dns.rdataclass.RdataClass.IN, dns.rdatatype.RdataType.RRSIG)
                    sig_rrset.add(dns.dnssec.sign(rrset, self.private_key, self.zone.origin,
                                                  self.public_key, expiration=2017974464, origin=self.zone.origin))

                    if rrset.rdtype == dns.rdatatype.SOA:
                        soa_rrset = rrset
                    response.answer.append(rrset)
                    response.answer.append(sig_rrset)

            response.answer.append(soa_rrset)

            print(response)

            return response

        except Exception as e:
            print(f"Error handling AXFR request: {e}")

    def add_record(self, request):
        try:
            # Add the new record to the zone
            zone_checkpoint = copy.deepcopy(self.zone)
            node = self.zone.nodes.get(request.update[0].name)
            if not node:
                node = self.zone.node_factory()
                self.zone.nodes[request.update[0].name] = node
            zrds = node.find_rdataset(request.update[0].rdclass, request.update[0].rdtype, request.update[0].covers,
                                      True)
            for rd in request.update[0]:
                zrds.add(rd)

            self.zone.check_origin()

            znode = self.zone.nodes.get(self.zone.origin)
            zrds = znode.find_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)

            zrds.discard(self.public_key)

            try:
                self.zone = self.validate_zone(self.zone)
            except Exception as e:
                print(f"Skipping update: {e}")
                self.zone = zone_checkpoint
                return None

            # Save the modified zone back to the file
            with open(self.zone_file_path, 'w') as zone_file:
                self.zone.to_file(zone_file, relativize=False, want_origin=True)

            print("Add record finished")

            return request.update[0]

        except Exception as e:
            print(f"Error adding A record: {e}")

    def forward_query(self, query_name, query_type):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.forwarding_server]
        return resolver.resolve(query_name, dns.rdatatype.from_text(query_type))
    
    def run(self):
        raise NotImplementedError


class MyUDPDNSHandler(MyDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
                 private_key_path="./keys/primary.pem", listen_address="", port=31111):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))

    def run(self):
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)

                message = ""
                try:
                    message = data.decode('utf-8')
                except Exception:
                    print("dns query received")

                if message.split(' ')[0] == "ZONE_TRANSFER":
                    try:
                        self.handle_zone_transfer(message.split(' ')[1], message.split(' ')[2],
                                                  int(message.split(' ')[3]))
                        print("Zone Transfer successful")
                        self.socket.sendto("SUCCESS".encode(), addr)
                    except Exception:
                        print("Zone Transfer failed")
                        self.socket.sendto("FAILURE".encode(), addr)
                    finally:
                        continue

                # print(request)
                try:
                    request = dns.message.from_wire(data)
                    reply = self.resolve(request)
                except dns.resolver.NXDOMAIN:
                    print("NOT FOUND")
                    continue

                if (dns.rdatatype.to_text(request.question[0].rdtype) == "AXFR" or
                        dns.rdatatype.to_text(request.question[0].rdtype) == "IXFR"):
                    self.socket.sendto(reply.to_wire(), addr)
                    continue

                response = dns.message.make_response(request)

                if reply is not None:
                    if hasattr(reply, 'rrset'):
                        response.answer.append(reply.rrset)
                    else:
                        response.answer.append(reply)
                else:
                    response.set_rcode(dns.rcode.NXRRSET)

                self.socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()


class MySSLDNSHandler(MyDNSHandler):
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
                 private_key_path="./keys/primary.pem", listen_address="", port=31111):
        super().__init__(forwarding_server, zone_file_path, private_key_path)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((listen_address, port))
        self.socket.listen(5)

    def run(self):
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain('ssl_certs/client.crt', 'ssl_certs/client.key')
            connection_socket = ssl_context.wrap_socket(self.socket, server_side=True)
            while True:
                try:
                    connection, addr = connection_socket.accept()
                    request = dns.query.receive_tcp(connection)
                    request = request[0]
                    reply = self.resolve(request)
                except dns.resolver.NXDOMAIN:
                    print("NOT FOUND")
                    continue

                if (dns.rdatatype.to_text(request.question[0].rdtype) == "AXFR" or
                        dns.rdatatype.to_text(request.question[0].rdtype) == "IXFR"):
                    dns.query.send_tcp(connection, reply.to_wire())
                    continue

                response = dns.message.make_response(request)

                if reply is not None:
                    if hasattr(reply, 'rrset'):
                        response.answer.append(reply.rrset)
                    else:
                        response.answer.append(reply)
                else:
                    response.set_rcode(dns.rcode.NXRRSET)

                dns.query.send_tcp(connection, response.to_wire())

        except KeyboardInterrupt:
            pass
        finally:
            connection.close()


class MyHTTPSDNSHandler(MySSLDNSHandler):

    def run(self):
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain('ssl_certs/client.crt', 'ssl_certs/client.key')
            connection_socket = ssl_context.wrap_socket(self.socket, server_side=True)
            while True:
                try:
                    connection, addr = connection_socket.accept()
                    header = connection.recv(4096).decode('utf-8')
                    data = connection.recv(int(re.findall(r'content-length: (\d+)', header)[0]))
                    request = dns.message.from_wire(data)
                    reply = self.resolve(request)
                except dns.resolver.NXDOMAIN:
                    print("NOT FOUND")
                    continue
                except Exception:
                    print(traceback.format_exc())

                if (dns.rdatatype.to_text(request.question[0].rdtype) == "AXFR" or
                        dns.rdatatype.to_text(request.question[0].rdtype) == "IXFR"):
                    response_headers = f'HTTP/1.0\r\nstatus: 200\r\ncontent-type: application/dns-message\r\ncontent-length: {len(reply.to_wire())}\r\n'
                    connection.send(response_headers.encode('utf-8'))
                    connection.send(reply.to_wire())

                    continue

                response = dns.message.make_response(request)

                if reply is not None:
                    if hasattr(reply, 'rrset'):
                        response.answer.append(reply.rrset)
                    else:
                        response.answer.append(reply)
                else:
                    response.set_rcode(dns.rcode.NXRRSET)

                response_headers = f'HTTP/1.1\r\nstatus: 200\r\ncontent-type: application/dns-message\r\ncontent-length: {len(response.to_wire())}\r\n'
                connection.send(response_headers.encode('utf-8'))
                connection.send(response.to_wire())

        except KeyboardInterrupt:
            pass
        except Exception as e:
            response = "Not Found"
            response_headers = f'HTTP/1.1\r\nstatus: 404\r\ncontent-type: application/dns-message\r\ncontent-length: {len(response.encode('utf-8'))}\r\n'
            connection.send(response_headers.encode('utf-8'))
            connection.send(response.encode('utf-8'))
        finally:
            self.socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=31111, help="specify dns port")
    parser.add_argument("--zone_file", default="zones/test_primary.zone", help="specify zone file")
    parser.add_argument("--private_key_path", default="keys/primary.pem", help="specify private key file")
    parser.add_argument("--mode", type=str, default=True, help="https for DoH, ssl for DoT, udp otherwise")

    args = parser.parse_args()
    if args.mode == 'https':
        resolver = MyHTTPSDNSHandler(port=args.port, zone_file_path=args.zone_file,
                                     private_key_path=args.private_key_path)
    elif args.mode == 'ssl':
        resolver = MySSLDNSHandler(port=args.port, zone_file_path=args.zone_file,
                                 private_key_path=args.private_key_path)
    else:
        resolver = MyUDPDNSHandler(port=args.port, zone_file_path=args.zone_file,
                                   private_key_path=args.private_key_path)

    resolver.run()
