#!/usr/bin/env python

import sys
from scapy.all import *
from scapy.layers.http import *



def process_packet(p):
    if p.haslayer(HTTPRequest):
        http = p[HTTPRequest]
        # print(p[HTTPRequest])

        # Extracting method, destination host, and request URI
        method = http.getfieldval('Method').decode()
        host = http.getfieldval('Host').decode()
        path = http.Path.decode()

        # Printing the results
        print(f"Method 1: {method}\nDestination Host: {host}\nRequest URI: {path}\n")
    if p.haslayer("SSL/TLS"):
        print(p.getlayer("SSL/TLS"))
    # print(p)


def main():
    interface = "eth0"
    trace_file = None
    expression = None
    i = 1

    while i < len(sys.argv):
        if sys.argv[i] == "-r" and i + 1 < len(sys.argv):
            trace_file = sys.argv[i + 1]
            i += 2
            continue
        elif sys.argv[i] == "-i" and i + 1 < len(sys.argv):
            interface = sys.argv[i + 1]
            i += 2
            continue
        elif i > 0 and sys.argv[i][0] != "-":
            expression = sys.argv[i]
            break

    # Choose the appropriate source
    if trace_file:
        packets = sniff(offline=trace_file, filter=expression, prn=process_packet)
    elif interface:
        # sudo ./mysniffer.py -i eth0
        print(expression, interface)
        packets = sniff(iface=interface, filter=expression, prn=process_packet)
    else:
        print("""Usage: mysniffer.py [-i interface] [-r tracefile] expression
               -i  Live capture from the network device <interface> (e.g., eth0). If not
                   specified, the program should automatically select a default interface to
                   listen on. Capture should continue indefinitely until the user terminates
                   the program.

               -r  Read packets from <tracefile> (tcpdump format). Useful for analyzing
                   network traces that have been captured previously.""")
        sys.exit(1)


if __name__ == "__main__":
    main()
