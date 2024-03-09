#!/usr/bin/env python
from scapy.all import *
from scapy.layers.l2 import *

arp_cache = {}

# pyopenssl 22.1.0
# cryptography 38.0.4


def get_current_arp_cache():
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        current_entries = result.stdout
    except FileNotFoundError:
        print("Error: 'arp' command error.")
        exit(1)

    # Parse ARP cache entries and create a dictionary
    arp_cache_temp = {}
    entry_pattern = re.compile(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+) \[ether\]')

    for line in current_entries.splitlines():
        # print(line)
        match = entry_pattern.search(line)
        if match:
            ip_address = match.group(1)
            mac_address = match.group(2)
            arp_cache_temp[ip_address] = mac_address

    return arp_cache_temp


def process_packet(p):
    if p.haslayer(ARP):
        # if (p[ARP].op == 2):
        #     print(p[ARP].summary)
            ip = p[ARP].psrc
            mac = p[ARP].hwsrc
            # print(arp_cache)
            if ip in arp_cache:
                if arp_cache[ip] != mac:
                    print(f"{ip} changed from {arp_cache[ip]} to {mac}")


def main():
    global arp_cache
    interface = "eth0"
    trace_file = "hw1.pcap"
    expression = None
    i = 1
    usage = """Usage: arpwatch.py [-i interface] 
                -i  Live capture from the network device <interface> (e.g., eth0). If not
                    specified, the program should automatically select a default interface to
                    listen on. Capture should continue indefinitely until the user terminates
                    the program."""

    while i < len(sys.argv):
        if sys.argv[i] == "-r" and i + 1 < len(sys.argv):
            trace_file = sys.argv[i + 1]
            i += 2
            continue
        elif sys.argv[i] == "-i" and i + 1 < len(sys.argv):
            interface = sys.argv[i + 1]
            i += 2
            continue
        else:
            print(usage)
    # print(get_current_arp_cache())
    arp_cache = get_current_arp_cache()
    # arp_cache['192.168.0.1'] = 'c4:3d:c7:17:6f:98'
    # arp_cache['192.168.0.200'] = 'c4:3d:c7:17:6f:98'
    # arp_cache['86.0.33.20'] = 'c4:3d:c7:17:6f:96'
    # print(arp_cache)
    if trace_file:
        sniff(offline=trace_file, filter=expression, prn=process_packet)
    elif interface:
        sniff(iface=interface, filter=expression, prn=process_packet)
    else:
        print(usage)
        sys.exit(1)


if __name__ == "__main__":
    main()
