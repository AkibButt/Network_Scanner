#!/usr/bin/env python
###############################
# Author : Akib Butt          #
# Project : Network Scanner   #
# Contact : Telegram Group (@python_hacks)   #
# Date : 29-08-2020           #
##############################
import scapy.all as scapy
import argparse


def get_Arguments():
    parser =argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target Ip / Ip Range.")
    options =parser.parse_args()
    if not options.target:
        print("[-] Please Specify Any Target Or Use --help For More Information.")
        print("Exiting..bye")
        exit()
    return options    
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast= broadcast/arp_request #combining two packets
    answered_list,unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)

    clients_list=[]
    for element in answered_list:
        client_dict={"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_Result(result_list):
    print("----------------------------------------")
    print("IP \t\t\t At Mac Adress")
    print("----------------------------------------")
    for client in result_list:
        print(client["ip"]+"\t\t"+client["mac"])
        print("\n")

options=get_Arguments()
scan_result=scan(options.target)
print_Result(scan_result)
