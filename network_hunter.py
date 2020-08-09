#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-r", "--iprange", dest="IP", help="Ip range to check for connected client")
	return parser.parse_args()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dist = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dist)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n----------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["MAC"])

options = get_arguments()
scan_result = scan(options.IP)
print_result(scan_result)