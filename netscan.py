#!/usr/bin/env python

import argparse
import scapy.all as scapy


def arguments():
    collect = argparse.ArgumentParser()
    collect.add_argument("-r", "--addr", dest="address", help="IP address to scan or IP range")
    option = collect.parse_args()
    if not option:
        collect.error("[-] Please specify an IP range or single IP address")
    else:
        return option


def scan(ip):
    request = scapy.ARP(pdst=ip)
    # scapy.ls(scapy.ARP())
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    # scapy.ls(scapy.Ether())
    arp_request = broadcast / request
    (result) = scapy.srp(arp_request, broadcast, timeout=1, verbose=False)[0]

    address_list = []

    for packet in result:
        address_dict = {"ip_add": packet[1].psrc, "mac_add": packet[1].hwsrc}
        address_list.append(address_dict)

    return address_list


def print_addresses(addresses):
    print("IP ADDRESS\t\t\tMAC ADDRESS\n-----------------------------------------------------")

    for response in addresses:
        print(response["ip_add"] + "\t\t" + response["mac_add"])


use = arguments()
receive = scan(use.address)
print_addresses(receive)
