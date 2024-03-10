# Network Monitoring with Scapy

## File Structure:

|--arpwatch.py
|--mysniffer.py
|--README.md
|--http_tls_demo.pcap
|--requirements.txt

## Overview
There are two Python script applications included in this simple suite. One is `mysniffer.py`, used to sniff TLS and HTTP
traffic, and the other is `arpwatch.py`, used to monitor ARP changes to detect any possible ARP spoofing. Both scripts are
based on the Scapy network traffic capture/analysis/generation framework.

## Environment
Run `pip install -r requirements.txt` to install the required dependencies.
Preferable OS is 64-bit Kali Linux.

## mysniffer.py
### Introduction
The tool perform the following operations:

1) For HTTP traffic, it parses GET and POST requests and print the
   method used (GET or POST), the destination host name contained in the "Host:"
   HTTP header (e.g., "www.cs.stonybrook.edu"), and the Request URI.

2) For TLS traffic, it parses the Client Hello message and print the TLS
   version number, and the destination host name (e.g., "www.cs.stonybrook.edu").

For both HTTP and TLS, it also prints a timestamp and the source and
destination IP addresses and ports.

### Usage
Usage: mysniffer.py [-i interface] [-r tracefile] expression
      -i Live capture from the network device <interface> (e.g., eth0). If not
      specified, the program should automatically select a default interface to
      listen on. Capture should continue indefinitely until the user terminates
      the program.

      -r  Read packets from <tracefile> (tcpdump format). Useful for analyzing
      network traces that have been captured previously.

The optional <expression> argument is a BPF filter that specifies a subset of the traffic to be monitored (similar to
tcpdump). The application will ignore all the arguments before it detects the -i or -r options. Furthermore, only one
mode can be chosen at a time.

### Example
The following example reads the http_tls_demo.pcap provided in the folder.

```
┌──(venv)(jasper㉿GalaxyBook)-[~/PycharmProjects/sniffer]
└─$ ./mysniffer.py -r http_tls_demo.pcap
Sniffing...
reading from file http_tls_demo.pcap, link-type EN10MB (Ethernet), snapshot length 262144
2024-03-09 20:25:49.143218 TLS v1.2 172.25.84.186:55854 -> 142.251.163.99:443 www.google.com
2024-03-09 20:25:49.358126 TLS v1.2 172.25.84.186:55855 -> 172.253.122.139:443 encrypted-tbn0.gstatic.com
2024-03-09 20:25:49.561961 TLS v1.2 172.25.84.186:55856 -> 172.253.115.132:443 lh5.googleusercontent.com
2024-03-09 20:25:54.250219 TLS v1.2 172.25.84.186:55859 -> 20.189.173.5:443 self.events.data.microsoft.com
An error occurred: msgtype
2024-03-09 20:25:55.372778 TLS v1.2 172.25.84.186:55860 -> 142.251.16.95:443 optimizationguide-pa.googleapis.com
2024-03-09 20:25:56.693965 TLS v1.2 172.25.84.186:55865 -> 52.113.194.132:443 ecs.office.com
2024-03-09 20:25:56.931967 TLS v1.2 172.25.84.186:55866 -> 23.185.0.4:443 www.cs.stonybrook.edu
2024-03-09 20:25:57.003469 TLS v1.2 172.25.84.186:55867 -> 52.113.194.132:443 ecs.office.com
2024-03-09 20:25:57.533493 TLS v1.2 172.25.84.186:55872 -> 172.253.115.95:443 fonts.googleapis.com
2024-03-09 20:25:57.536437 TLS v1.2 172.25.84.186:55873 -> 23.215.0.137:443 use.typekit.net
2024-03-09 20:25:57.576006 TLS v1.2 172.25.84.186:55874 -> 104.18.6.126:443 www.stonybrook.edu
WARNING: Unknown cipher suite 4816251 from ClientMasterKey
2024-03-09 20:25:57.710882 TLS v1.2 172.25.84.186:55875 -> 104.18.10.207:443 stackpath.bootstrapcdn.com
WARNING: Unknown cipher suite 14522645 from ClientMasterKey
WARNING: more Unknown cipher suite 3223399 from ClientMasterKey
2024-03-09 20:25:57.889604 TLS v1.2 172.25.84.186:55877 -> 52.113.194.132:443 ecs.office.com
2024-03-09 20:25:57.890883 TLS v1.2 172.25.84.186:55876 -> 52.113.194.132:443 ecs.office.com
2024-03-09 20:25:57.891028 TLS v1.2 172.25.84.186:55878 -> 52.113.194.132:443 ecs.office.com
2024-03-09 20:25:57.891405 TLS v1.2 172.25.84.186:55879 -> 52.113.194.132:443 ecs.office.com
2024-03-09 20:25:58.568719 TLS v1.2 172.25.84.186:55880 -> 52.109.12.13:443 mrodevicemgr.officeapps.live.com
2024-03-09 20:26:02.651737 TLS v1.2 172.25.84.186:55887 -> 172.253.122.139:443 encrypted-tbn0.gstatic.com
2024-03-09 20:26:02.656786 TLS v1.2 172.25.84.186:55888 -> 172.253.63.113:443 encrypted-tbn2.gstatic.com
2024-03-09 20:26:06.540762 TLS v1.2 172.25.84.186:55891 -> 142.251.167.113:443 ogs.google.com
2024-03-09 20:26:08.447891 TLS v1.2 172.25.84.186:55899 -> 172.253.115.84:443 accounts.google.com
2024-03-09 20:26:08.885959 TLS v1.2 172.25.84.186:55901 -> 20.189.173.5:443 self.events.data.microsoft.com
An error occurred: msgtype
2024-03-09 20:26:09.107596 TLS v1.2 172.25.84.186:55902 -> 84.38.185.158:443 startrinity.com
2024-03-09 20:26:09.600809 HTTP 172.25.84.186:55904 -> 84.38.185.158:80 startrinity.com GET /HttpTester/HttpRestApiClientTester.aspx
2024-03-09 20:26:09.782074 HTTP 172.25.84.186:55904 -> 84.38.185.158:80 startrinity.com GET /Scripts/jquery-1.11.0.min.js
2024-03-09 20:26:09.902888 HTTP 172.25.84.186:55905 -> 84.38.185.158:80 startrinity.com GET /Scripts/collapsible.js
2024-03-09 20:26:09.913362 HTTP 172.25.84.186:55906 -> 84.38.185.158:80 startrinity.com GET /HttpTester/screenshot_01.png
2024-03-09 20:26:10.096816 HTTP 172.25.84.186:55905 -> 84.38.185.158:80 startrinity.com GET /Images/background.png
2024-03-09 20:26:10.096904 HTTP 172.25.84.186:55904 -> 84.38.185.158:80 startrinity.com GET /Images/Logo_big.jpg
2024-03-09 20:26:10.175528 HTTP 172.25.84.186:55906 -> 84.38.185.158:80 startrinity.com GET /Images/footer.jpg
2024-03-09 20:26:10.598900 HTTP 172.25.84.186:55905 -> 84.38.185.158:80 startrinity.com GET /favicon.ico
2024-03-09 20:26:15.709845 TLS v1.2 172.25.84.186:55912 -> 45.33.7.16:443 www.httpvshttps.com
2024-03-09 20:26:17.452824 TLS v1.2 172.25.84.186:55922 -> 104.244.42.136:443 syndication.twitter.com
```
Filtering use BPF example:
```
┌──(venv)(jasper㉿GalaxyBook)-[~/PycharmProjects/sniffer]
└─$ ./mysniffer.py -r http_tls_demo.pcap host startrinity.com
Sniffing...
reading from file http_tls_demo.pcap, link-type EN10MB (Ethernet), snapshot length 262144
2024-03-09 20:26:09.107596 TLS v1.2 172.25.84.186:55902 -> 84.38.185.158:443 startrinity.com
2024-03-09 20:26:09.600809 HTTP 172.25.84.186:55904 -> 84.38.185.158:80 startrinity.com GET /HttpTester/HttpRestApiClientTester.aspx
2024-03-09 20:26:09.782074 HTTP 172.25.84.186:55904 -> 84.38.185.158:80 startrinity.com GET /Scripts/jquery-1.11.0.min.js
2024-03-09 20:26:09.902888 HTTP 172.25.84.186:55905 -> 84.38.185.158:80 startrinity.com GET /Scripts/collapsible.js
2024-03-09 20:26:09.913362 HTTP 172.25.84.186:55906 -> 84.38.185.158:80 startrinity.com GET /HttpTester/screenshot_01.png
2024-03-09 20:26:10.096816 HTTP 172.25.84.186:55905 -> 84.38.185.158:80 startrinity.com GET /Images/background.png
2024-03-09 20:26:10.096904 HTTP 172.25.84.186:55904 -> 84.38.185.158:80 startrinity.com GET /Images/Logo_big.jpg
2024-03-09 20:26:10.175528 HTTP 172.25.84.186:55906 -> 84.38.185.158:80 startrinity.com GET /Images/footer.jpg
2024-03-09 20:26:10.598900 HTTP 172.25.84.186:55905 -> 84.38.185.158:80 startrinity.com GET /favicon.ico

```
## arpwatch.py
### Introduction
The tool perform the following operations:
At startup, the tool will read the current ARP cache entries of
the host system, and consider them as the ground truth. Then, it will
passively monitor the ARP traffic and print a warning message whenever an
existing MAC-IP binding changes.

## Usage
Usage: arpwatch.py [-i interface] 
-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, the program will automatically select a default interface to
    listen on. Capture will continue indefinitely until the user terminates
    the program.

The application will ignore all arguments until it detects the -i option.

### Example
In order to simulate arpspoof, two kali vms are set up under VMware envriment named kali-1 and kali-2. kali-2 will be
the victim.
Below are the network configuration overview of the two vms:
kali-1: ip-192.168.186.128 mac-00:0c:29:b9:69:31
```
┌──(kali㉿kali)-[~]
└─$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.186.128  netmask 255.255.255.0  broadcast 192.168.186.255
        inet6 fe80::be78:f421:8fe:4ffd  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:b9:69:31  txqueuelen 1000  (Ethernet)
        RX packets 546804  bytes 805363823 (768.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 21981  bytes 1446745 (1.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4  bytes 240 (240.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
kali-2: ip-192.168.186.129 mac-00:0c:29:2e:4b:0f
```
┌──(kali㉿kali)-[~]
└─$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.186.129  netmask 255.255.255.0  broadcast 192.168.186.255
        inet6 fe80::c8d2:42d2:4b7e:9a73  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:2e:4b:0f  txqueuelen 1000  (Ethernet)
        RX packets 564141  bytes 829851131 (791.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 21964  bytes 1628912 (1.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4  bytes 240 (240.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```
Step 1: start arpwatch.py from kali-2
```
┌──(.venv)─(kali㉿kali)-[~/Documents/sniffer]
└─$ sudo ./arpwatch.py -i eth0
[sudo] password for kali: 
ARP Cache:  {'192.168.186.1': '00:50:56:c0:00:08', '192.168.186.254': '00:50:56:e2:78:4c', '192.168.186.128': '00:0c:29:b9:69:31', '192.168.186.2': '00:50:56:fb:09:ee'} 
Watching ARP Traffic...
```
Step 2: Start arpspoof from Kali-1 targeting the victim's IP (192.168.186.129) and pretending to be 192.168.186.1.
```
┌──(kali㉿kali)-[~]
└─$ sudo arpspoof -i eth0 -t 192.168.186.129 192.168.186.1

0:c:29:b9:69:31 0:c:29:2e:4b:f 0806 42: arp reply 192.168.186.1 is-at 0:c:29:b9:69:31
0:c:29:b9:69:31 0:c:29:2e:4b:f 0806 42: arp reply 192.168.186.1 is-at 0:c:29:b9:69:31
0:c:29:b9:69:31 0:c:29:2e:4b:f 0806 42: arp reply 192.168.186.1 is-at 0:c:29:b9:69:31

```
Step 3: Check the output from arpwatch.py on Kali-2; you can observe that it captured the abnormal behavior.
```
┌──(.venv)─(kali㉿kali)-[~/Documents/sniffer]
└─$ sudo ./arpwatch.py -i eth0

ARP Cache:  {'192.168.186.1': '00:50:56:c0:00:08', '192.168.186.254': '00:50:56:e2:78:4c', '192.168.186.128': '00:0c:29:b9:69:31', '192.168.186.2': '00:50:56:fb:09:ee'} 
Watching ARP Traffic...
192.168.186.1 changed from 00:50:56:c0:00:08 to 00:0c:29:b9:69:31
192.168.186.1 changed from 00:50:56:c0:00:08 to 00:0c:29:b9:69:31
192.168.186.1 changed from 00:50:56:c0:00:08 to 00:0c:29:b9:69:31
192.168.186.1 changed from 00:50:56:c0:00:08 to 00:0c:29:b9:69:31
192.168.186.1 changed from 00:50:56:c0:00:08 to 00:0c:29:b9:69:31

```