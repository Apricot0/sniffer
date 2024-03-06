#!/usr/bin/env python

import sys
from scapy.all import *
from scapy.layers.http import *
from scapy.layers.tls.all import *
from scapy.layers.ipsec import *
from datetime import datetime

load_layer('tls')
load_layer('http')


# pyopenssl 22.1.0
# cryptography 38.0.4

def process_packet(p):
    try:
        if p.haslayer(IP) and p.haslayer(TCP):
            timestamp = float(p.time)  # Convert EDecimal to float
            formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
            # Extract source and destination information
            src_ip = p[IP].src
            src_port = p[TCP].sport
            dest_ip = p[IP].dst
            dest_port = p[TCP].dport

            # Format source and destination in the desired format
            src_to_dest = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}"

            if p.haslayer(HTTPRequest):
                http = p[HTTPRequest]
                method = http.Method.decode()
                host = http.Host.decode()
                path = http.Path.decode()

                print(f"{formatted_time} HTTP {src_to_dest} {host} {method} {path}\n")
            tls_version_mapping = {
                0x0300: "SSL v3.0",
                0x0301: "TLS v1.0",
                0x0002: "SSL v2.0",
                0x0302: "TLS v1.1",
                0x0303: "TLS v1.2",
                0x0304: "TLS v1.3"
            }
            if p.haslayer(TLS) and p[TLS].type == 22 and p[TLS].msg[0].msgtype == 1:
                print(p[TLS].show())
                tls_version = p[TLS].msg[0].version
                version_name = tls_version_mapping.get(tls_version, "TLS Unknown Version")
                if TLS_Ext_ServerName in p:
                    server_name = p[TLS][TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')
                else:
                    server_name = "Unknown Server Name"
                print(f"{formatted_time} {version_name} {src_to_dest} {server_name}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


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
