from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.config import conf

for i in conf.ifaces:
    print(f"Name: {conf.ifaces[i].name}, MAC: {get_if_hwaddr(conf.iface)}")
print("After Names ----------------------\n")

frames = sniff(iface="Wi-Fi 4", count=10)

print(frames)
for frame in frames:
    print(frame.summary())
print("End Of Summary ---------\n")

to_me_macs = ""
from_me_macs = ""
random = ""

my_mac = get_if_hwaddr("Wi-Fi 4")

for frame in frames:
    if frame.src == my_mac:
        from_me_macs += frame.dst + "\n"
    elif frame.dst == my_mac:
        to_me_macs += frame.src + "\n"
    else:
        random += frame.src + " => " + frame.dst + "\n"

print("From me MAC addresses:")
print(from_me_macs)

print("To me MAC addresses:")
print(to_me_macs)

print("Random MAC addresses:")
print(random)
