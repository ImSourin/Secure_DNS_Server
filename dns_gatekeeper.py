import dns.message
import dns.resolver
import socket
import time
from concurrent.futures import ThreadPoolExecutor
import uuid
import argparse


class MyDNSGatekeeper:
    def __init__(self, primary_ns_host="127.0.0.1", primary_ns_port=31111,
                 secondary_ns_host="127.0.0.1", secondary_ns_port=31112, listen_address="", port=31110):
        super().__init__()
        self.primary_ns_host = primary_ns_host
        self.secondary_ns_host = secondary_ns_host

        self.primary_ns_port = primary_ns_port
        self.secondary_ns_port = secondary_ns_port

        self.history = {}

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((listen_address, port))

    def resolve(self, request):
        query_name = str(request.question[0].name)
        query_type = dns.rdatatype.to_text(request.question[0].rdtype)

        key = uuid.uuid4().int

        if hasattr(request, 'update') and len(request.update):
            return self.add_record(request)

        if key % 2 == 0:
            return self.forward_query(query_name, query_type, self.primary_ns_host, self.primary_ns_port)
        else:
            return self.forward_query(query_name, query_type, self.secondary_ns_host, self.secondary_ns_port)

    def forward_query(self, query_name, query_type, host, port):
        resolver = dns.resolver.Resolver()
        resolver.port = port
        resolver.nameservers = [host]
        return resolver.resolve(query_name, dns.rdatatype.from_text(query_type))

    def zone_transfer(self, host, port):
        # Create a UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Send a message to the server
        msg = "ZONE_TRANSFER example.com " + host + " " + port
        client_socket.sendto(msg.encode('utf-8'), (host, port))

        # Receive the response from the server
        response, server_address = client_socket.recvfrom(1024)

        # Decode and print the response
        decoded_response = response.decode('utf-8')
        print(f"Response from server {server_address}: {decoded_response}")

        # Close the socket
        client_socket.close()

    def add_record(self, request):
        update = dns.update.Update(request.zone[0].name)

        address = [rd for rd in request.update[0].items][0].address

        update.add(request.update[0].name, 300, request.update[0].rdtype, address)

        dns.query.udp(update, self.primary_ns_host, port=self.primary_ns_port)

        print("Added record to Primary nameserver")

        return request.update[0]

    def validate(self, sender_ip):
        if sender_ip in self.history:
            self.history[sender_ip] += 1
            if self.history[sender_ip] > 100:
                return False
            return True
        else:
            self.history[sender_ip] = 1
            return True

    def reset_history(self):
        try:
            while True:
                time.sleep(5)
                self.history = {}
                print("Reset history done")
        except KeyboardInterrupt:
            pass

    def run(self):
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)

                if not self.validate(addr[0]):
                    print("IP banned: ", addr[0])
                    self.socket.sendto("IP banned".encode(), addr)
                    continue

                request = dns.message.from_wire(data)
                # print(request)
                try:
                    reply = self.resolve(request)
                except Exception:
                    print("DNS ERROR")
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

    def perform_zone_transfers(self):
        try:
            while True:
                time.sleep(100)
                print("Performing a zone tranfer")
                self.zone_transfer(self.secondary_ns_host, self.secondary_ns_port)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=31110, help="specify dns gatekeeper port")
    parser.add_argument("--primary_ns_host", default="127.0.0.1", help="specify primary dns host")
    parser.add_argument("--primary_ns_port", type=int, default=31111, help="specify primary dns port")
    parser.add_argument("--secondary_ns_host", default="127.0.0.1", help="specify secondary dns host")
    parser.add_argument("--secondary_ns_port", type=int, default=31112, help="specify secondary dns port")
    args = parser.parse_args()

    resolver = MyDNSGatekeeper(args.primary_ns_host, args.primary_ns_port, args.secondary_ns_host,
                               args.secondary_ns_port, port=args.port)

    executor = ThreadPoolExecutor(3)

    executor.submit(resolver.run)
    executor.submit(resolver.perform_zone_transfers)
    executor.submit(resolver.reset_history)
