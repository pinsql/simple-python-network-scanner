#!/usr/bin/env python3

# Simple Network Scanner
# Because who doesn't like peeking at who's on the Wi-Fi?

import argparse
import ipaddress
import os
import sys

from scapy.all import ARP, Ether, srp

def parse_target(target):
    # Accept a single IP or a CIDR range; reject garbage before scapy chokes on it
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{target}' isn't an IP or CIDR range (try 192.168.1.0/24)") from None
    if network.version != 4:
        # ARP is an IPv4 thing. IPv6 uses neighbor discovery, different party
        raise argparse.ArgumentTypeError("ARP only speaks IPv4, give me an IPv4 range")
    return str(network)

def get_arguments():
    # Setting up a command-line interface because hardcoding is soooo 2003
    parser = argparse.ArgumentParser(description="Scan your local network and be nosy")
    parser.add_argument("-t", "--target", dest="target", type=parse_target, help="Target IP / IP range. Example: 192.168.1.1/24")
    args = parser.parse_args()
    if not args.target:
        # You had one job... give me an IP range!
        parser.error("Please specify a target IP range, use --help for more info.")
    return args

def require_root():
    # Raw sockets are root-only. A one-liner beats a PermissionError wall of text
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("[!] need root for raw packets. try: sudo python3 network_scanner.py -t <range>")

def scan(ip):
    # Creating an ARP request packet... basically yelling "Who's there?" on the network
    arp_request = ARP(pdst=ip)
    
    # Ethernet frame for the broadcast... MAC address FF:FF:FF:FF:FF:FF = yell at everyone
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Mix them like peanut butter and jelly
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and get answers back (timeout in case some devices are napping)
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    # Making a list of the cool kids who replied
    clients_list = []
    for element in answered_list:
        client_dict = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("📡 Devices on the network (aka your neighbors?):\n")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}")

# Entry point: because Python needs to know where to start being awesome
if __name__ == "__main__":
    args = get_arguments()
    require_root()
    scan_result = scan(args.target)
    print_result(scan_result)
