import argparse
import dns
import dns.message
import dns.resolver
import dns.zone
import dns.query
import dns.dnssec
import socket
from dns.zone import Zone

from dns.exception import ValidationFailure

from cryptography.hazmat.primitives import serialization


class MyDNSHandler:
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
                 private_key_path="./keys/primary.pem", public_key_path="./zones/public_keys/primary.pem",
                 listen_address="", port=31111):

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
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))

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
            node = self.zone.nodes.get(request.update[0].name)
            if not node:
                node = self.zone.node_factory()
                self.zone.nodes[request.update[0].name] = node
            zrds = node.find_rdataset(request.update[0].rdclass, request.update[0].rdtype, request.update[0].covers,
                                      True)
            for rd in request.update[0]:
                zrds.add(rd)

            self.zone.check_origin()

            # Save the modified zone back to the file
            with open(self.zone_file_path, 'w') as zone_file:
                self.zone.to_file(zone_file, relativize=False, want_origin=True)

            print("Add record successful")

            return request.update[0]

        except Exception as e:
            print(f"Error adding A record: {e}")

    def forward_query(self, query_name, query_type):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.forwarding_server]
        return resolver.resolve(query_name, dns.rdatatype.from_text(query_type))

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

                if hasattr(reply, 'rrset'):
                    response.answer.append(reply.rrset)
                else:
                    response.answer.append(reply)

                self.socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="specify dns port")
    parser.add_argument("--zone_file", help="specify zone file")
    parser.add_argument("--private_key_path", help="specify private key file")
    parser.add_argument("--public_key_path", help="specify public key file")
    args = parser.parse_args()
    resolver = MyDNSHandler(port=int(args.port), zone_file_path=args.zone_file,
                            private_key_path=args.private_key_path, public_key_path=args.public_key_path)

    resolver.run()
