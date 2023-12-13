import argparse
import time
from concurrent.futures import ThreadPoolExecutor

import dns.resolver


def dns_query(i, resolver, timer):
    times = []
    while time.time() < timer:
        begin = time.time()
        resolver.resolve('ns1.example.com', dns.rdatatype.A)
        print('Sent A record query. Time taken - ', time.time() - begin)
        times.append(str(time.time() - begin))
    with open("logs/timer_" + str(i), "w") as f:
        f.write('\n'.join(times))


def attack(host="127.0.0.1", port=31110, timeout=100, num_threads=5):
    resolver = dns.resolver.Resolver()
    resolver.port = port
    resolver.nameservers = [host]

    timer = time.time() + timeout

    executor = ThreadPoolExecutor(num_threads)

    for i in range(num_threads):
        executor.submit(dns_query, i, resolver, timer)
    executor.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default="127.0.0.1", help="Host IP address")
    parser.add_argument('--port', type=int, default=31110, help="Host port")
    parser.add_argument('--timeout', type=int, default=100, help='Attack duration')
    parser.add_argument('--num_threads', type=int, default=5, help='Number of threads')

    args = parser.parse_args()

    attack(args.host, args.port, args.timeout, args.num_threads)
