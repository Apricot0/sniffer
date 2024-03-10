#!/usr/bin/env python

import sys
from scapy.all import *
from scapy.layers.http import *
from scapy.layers.tls.all import *
from scapy.layers.ipsec import *
from datetime import datetime

load_layer('tls')
load_layer('http')
PACKET_READ_MODE = 1
LIVING_CAPTURE_MODE = 2


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
            des_ip = p[IP].dst
            des_port = p[TCP].dport

            # Format source and destination in the desired format
            src_to_des = f"{src_ip}:{src_port} -> {des_ip}:{des_port}"

            if p.haslayer(HTTPRequest):
                http = p[HTTPRequest]
                method = http.Method.decode()
                host = http.Host.decode()
                path = http.Path.decode()

                print(f"{formatted_time} HTTP {src_to_des} {host} {method} {path}")
            tls_version_mapping = {
                0x0300: "SSL v3.0",
                0x0301: "TLS v1.0",
                0x0002: "SSL v2.0",
                0x0302: "TLS v1.1",
                0x0303: "TLS v1.2",
                0x0304: "TLS v1.3"
            }
            if p.haslayer(TLS) and p[TLS].type == 22 and p[TLS].msg[0].msgtype == 1:
                # print(p[TLS].show())
                tls_version = p[TLS].msg[0].version
                version_name = tls_version_mapping.get(tls_version, "TLS Unknown Version")
                if TLS_Ext_ServerName in p:
                    server_name = p[TLS][TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')
                else:
                    server_name = "Unknown Server Name"
                print(f"{formatted_time} {version_name} {src_to_des} {server_name}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def main():
    mode = 0
    interface = None
    trace_file = None
    expression = ""
    i = 1
    usage = ("""Usage: mysniffer.py [-i interface] [-r tracefile] expression
               -i  Live capture from the network device <interface> (e.g., eth0). If not
                   specified, the program should automatically select a default interface to
                   listen on. Capture should continue indefinitely until the user terminates
                   the program.

               -r  Read packets from <tracefile> (tcpdump format). Useful for analyzing
                   network traces that have been captured previously.
        The optional <expression> argument is a BPF filter that specifies a subset of
        the traffic to be monitored (similar to tcpdump). """)

    while i < len(sys.argv):
        if sys.argv[i] == "-r":
            if i + 1 < len(sys.argv):
                trace_file = sys.argv[i + 1]
                mode |= PACKET_READ_MODE
                i += 2
                continue
            else:
                print("No file specified.\n", usage)
                sys.exit(1)
        elif sys.argv[i] == "-i":
            mode |= LIVING_CAPTURE_MODE
            if i + 1 < len(sys.argv):
                interface = sys.argv[i + 1]
                i += 2
                continue
        elif i > 0 and sys.argv[i][0] != "-" and mode != 0:
            expression += " " + sys.argv[i]
        i += 1

    if mode == LIVING_CAPTURE_MODE | PACKET_READ_MODE:
        print("Please only specify one mode.\n", usage)
        sys.exit(1)
    try:
        print("Sniffing...")
        if mode == PACKET_READ_MODE:
            sniff(offline=trace_file, filter=expression, prn=process_packet)
        elif mode == LIVING_CAPTURE_MODE:
            if interface:
                sniff(iface=interface, filter=expression, prn=process_packet)
            else:
                sniff(filter=expression, prn=process_packet)
        else:
            print(usage)
            sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File not found - {trace_file}")
    except PermissionError:
        print(f"Error: Permission denied. You may not have sufficient permissions to sniff on the specified interface/"
              "file. \nDo you mean sudo?")
    except OSError as e:
        if "No such device" in str(e):
            print(f"{e}. Please check if the specified interface '{interface}' exists.")
        else:
            print(f"Error: {e}")
    except Scapy_Exception as e:
        print(f"Error: Scapy exception - {e}")


if __name__ == "__main__":
    main()
