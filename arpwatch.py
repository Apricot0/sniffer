#!/usr/bin/env python
from scapy.all import *
from scapy.layers.l2 import *

arp_cache = {}
arp_debug = False


# pyopenssl 22.1.0
# cryptography 38.0.4


def get_current_arp_cache():
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        current_entries = result.stdout
    except FileNotFoundError:
        print("Error: 'arp' command error.")
        exit(1)

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
        if debug:
            print(p[ARP].summary())
        ip = p[ARP].psrc
        mac = p[ARP].hwsrc
        # print(arp_cache)
        if ip in arp_cache:
            if arp_cache[ip] != mac:
                print(f"{ip} changed from {arp_cache[ip]} to {mac}")


def main():
    global arp_cache
    global arp_debug
    interface = None
    i = 1
    legal_arg = False
    usage = """Usage: arpwatch.py [-i interface] 
-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, the program will automatically select a default interface to
    listen on. Capture will continue indefinitely until the user terminates
    the program."""
    if len(sys.argv) == 1:
        print(usage)
        sys.exit(1)
    while i < len(sys.argv):
        if sys.argv[i] == "-i":
            legal_arg = True
            if i + 1 < len(sys.argv):
                interface = sys.argv[i + 1]
                i += 2
                continue
        elif sys.argv[i] == "-d":
            arp_debug = True
        i += 1
    if legal_arg:
        arp_cache = get_current_arp_cache()
        print("ARP Cache: ", arp_cache, "\nWatching ARP Traffic...")
        try:
            if interface:
                sniff(iface=interface, prn=process_packet)
            else:
                sniff(prn=process_packet)
        except PermissionError:
            print("PermissionError: You may not have sufficient permissions to sniff on the specified interface."
                  "\nDo you mean sudo?")
        except OSError as e:
            if "No such device" in str(e):
                print(f"Error: {e}. Please check if the specified interface '{interface}' exists.")
            else:
                raise
    else:
        print(usage)
    sys.exit(0)


if __name__ == "__main__":
    main()
