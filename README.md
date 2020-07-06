# ARP-spoofer-python3
ARP spoof local IPs (or specific local IP) using scapy and getmac
Sends spoofed localhost ARP packet (pretending to be the gateway) to LAN hosts and sends spoofed LAN hosts ARP packet to gateway.


## Install requirements:
Requirements for the repo are scapy and getmac libraries and you can easily install them with:

```bash
pip3 install -r requirements.txt
```

## Usage:

Firstly you need to enable IP forwarding with:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
Which will allow us to control the flow of IP packets with our script.

Next, you have to invoke python3 with superuser priviledges and specify interface you want to use:
```bash
sudo python3 arp_poisoning.py -i "wlan0"
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)
