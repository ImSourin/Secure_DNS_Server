import argparse
import dns
import dns.message
import dns.resolver
import dns.zone
import dns.query
import socket
from dns.rdtypes.ANY.SOA import SOA


class MyDNSHandler:
    def __init__(self, forwarding_server="1.1.1.1", zone_file_path="./zones/test_primary.zone",
                 listen_address="", port=31111):
        # super().__init__()

        # Define custom DNS zones and records
        # self.custom_zones = {
        #     "example.com": {
        #         "A": ["192.168.1.1", "192.168.1.2"],
        #         "CNAME": {"www": "example.com"},
        #     
        #     "example.net": {
        #         "A": ["10.0.0.1"],
        #         "MX": [{"preference": 10, "exchange": "mail.example.net"}],
        #     },
        # }

        # Set the forwarding DNS server
        self.forwarding_server = forwarding_server
        self.zone_file_path = zone_file_path
        self.zone = dns.zone.from_file(self.zone_file_path, relativize=False)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))

    def resolve(self, request):
        query_name = str(request.question[0].name)
        query_type = dns.rdatatype.to_text(request.question[0].rdtype)

        if len(request.update):
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

    def handle_zone_transfer(self, zone_name):
        # Create a DNS query for a zone transfer (AXFR or IXFR)

        # Perform the query
        axfr_request = dns.query.xfr("127.0.0.1", zone_name, rdtype=dns.rdatatype.IXFR, port=31112,
                                     use_udp=True, relativize=False)

        zone = dns.zone.from_xfr(axfr_request, relativize=False)

        # Save the zone to a file
        with open(self.zone_file_path, 'w') as zone_file:
            zone.to_file(zone_file, relativize=False, want_origin=True)

        self.zone = zone

        print(f"Zone transfer successful. Zone saved to {self.zone_file_path}")

    def handle_axfr_request(self, request):
        try:
            # Create a response
            response = dns.message.make_response(request)

            soa_rrset = None

            # Add other records to the answer section
            for name, node in self.zone.nodes.items():
                for rdataset in node.rdatasets:
                    rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype,
                                            dns.rdatatype.RdataType.make(dns.rdatatype.NONE))
                    rrset.update(rdataset)
                    response.answer.append(rrset)
                    if rrset.rdtype == dns.rdatatype.SOA:
                        soa = SOA(rdataset.rdclass, rdataset.rdtype, rdataset[0].mname, rdataset[0].rname,
                                  rdataset[0].serial, rdataset[0].refresh, rdataset[0].retry, rdataset[0].expire,
                                  rdataset[0].minimum)
                        soa_rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype,
                                                    dns.rdatatype.RdataType.make(dns.rdatatype.NONE))
                        soa_rrset.add(soa)

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
                        self.handle_zone_transfer(message.split(' ')[1])
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
    args = parser.parse_args()
    resolver = MyDNSHandler(port=int(args.port), zone_file_path=args.zone_file)

    resolver.run()
