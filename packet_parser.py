"""
packet_parser.py

Manual Ethernet/IP/TCP/UDP Packet Parser

Equivalent to:
    packet_parser.h
    packet_parser.cpp
"""

import socket
import struct

from dataclasses import dataclass
from typing import Optional

from pcap_reader import RawPacket
# ==========================================================
# TCP Flags
# ==========================================================

class TCPFlags:

    FIN = 0x01

    SYN = 0x02

    RST = 0x04

    PSH = 0x08

    ACK = 0x10

    URG = 0x20

    ECE = 0x40

    CWR = 0x80


# ==========================================================
# Ethernet Header
# ==========================================================

@dataclass
class EthernetHeader:

    dest_mac: str
    src_mac: str
    ether_type: int


# ==========================================================
# IPv4 Header
# ==========================================================

@dataclass
class IPv4Header:

    version: int
    ihl: int
    total_length: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str


# ==========================================================
# TCP Header
# ==========================================================

@dataclass
class TCPHeader:

    src_port: int
    dst_port: int
    sequence: int
    acknowledgement: int
    data_offset: int
    flags: int


# ==========================================================
# UDP Header
# ==========================================================

@dataclass
class UDPHeader:

    src_port: int
    dst_port: int
    length: int


# ==========================================================
# Parsed Packet
# ==========================================================

@dataclass
class ParsedPacket:

    # Timestamp
    timestamp_sec: int = 0
    timestamp_usec: int = 0

    # Parsed headers
    ethernet: Optional[EthernetHeader] = None
    ip: Optional[IPv4Header] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None

    # Convenience fields
    src_ip: str = ""
    dst_ip: str = ""        # <-- use dst_ip everywhere

    src_port: int = 0
    dst_port: int = 0         # <-- use dst_port everywhere

    protocol: int = 0

    # Transport flags
    has_tcp: bool = False
    has_udp: bool = False

    tcp_flags: int = 0
    tcp_sequence: int = 0

    sequence: int = 0
    acknowledgement: int = 0

    # Payload
    payload_data: bytes = b""
    payload_length: int = 0


# ==========================================================
# Packet Parser
# ==========================================================

class PacketParser:

    ETH_LEN = 14

    IP_PROTO_TCP = 6

    IP_PROTO_UDP = 17

    ETHERTYPE_IPV4 = 0x0800


    @staticmethod
    def mac_to_string(mac):

        return ":".join(f"{b:02x}" for b in mac)


    @staticmethod
    def ip_to_string(raw):

        return socket.inet_ntoa(raw)


    @staticmethod
    def protocol_to_string(proto):

        if proto == 6:
            return "TCP"

        if proto == 17:
            return "UDP"

        if proto == 1:
            return "ICMP"

        return str(proto)


    @staticmethod
    def tcp_flags_to_string(flags):

        names = []

        if flags & 0x02:
            names.append("SYN")

        if flags & 0x10:
            names.append("ACK")

        if flags & 0x01:
            names.append("FIN")

        if flags & 0x04:
            names.append("RST")

        if flags & 0x08:
            names.append("PSH")

        if flags & 0x20:
            names.append("URG")

        return " ".join(names)


    @staticmethod
    def parse(raw_packet):

        parsed = ParsedPacket()

        import time

        # Timestamp for PCAP packets
        if hasattr(raw_packet, "header"):
            parsed.timestamp_sec = raw_packet.header.ts_sec
            parsed.timestamp_usec = raw_packet.header.ts_usec

        # Timestamp for live packets
        else:
            now = time.time()
            parsed.timestamp_sec = int(now)
            parsed.timestamp_usec = int((now - int(now)) * 1_000_000)

        if hasattr(raw_packet, "data"):
            data = raw_packet.data
        else:
            data = raw_packet

        if len(data) < PacketParser.ETH_LEN:

            return None

        eth = struct.unpack(
            "!6s6sH",
            data[:14]
        )

        parsed.ethernet = EthernetHeader(

            dest_mac=PacketParser.mac_to_string(eth[0]),

            src_mac=PacketParser.mac_to_string(eth[1]),

            ether_type=eth[2]

        )

        if parsed.ethernet.ether_type != PacketParser.ETHERTYPE_IPV4:

            return parsed

        ip_offset = 14
                # -----------------------------
        # IPv4 Header
        # -----------------------------

        version_ihl = data[ip_offset]

        version = version_ihl >> 4

        ihl = version_ihl & 0x0F

        ip_header_length = ihl * 4

        if version != 4:

            return parsed

        if len(data) < ip_offset + ip_header_length:

            return parsed

        ip_header = struct.unpack(

            "!BBHHHBBH4s4s",

            data[ip_offset:ip_offset + 20]

        )

        total_length = ip_header[2]

        ttl = ip_header[5]

        protocol = ip_header[6]

        src_ip = PacketParser.ip_to_string(ip_header[8])

        dst_ip = PacketParser.ip_to_string(ip_header[9])

        parsed.ip = IPv4Header(

            version=version,

            ihl=ihl,

            total_length=total_length,

            ttl=ttl,

            protocol=protocol,

            src_ip=src_ip,

            dst_ip=dst_ip

        )

        parsed.src_ip = src_ip

        parsed.dst_ip = dst_ip

        parsed.protocol = protocol

        transport_offset = ip_offset + ip_header_length

        # ------------------------------------
        # TCP
        # ------------------------------------

        if protocol == PacketParser.IP_PROTO_TCP:

            if len(data) < transport_offset + 20:

                return parsed

            tcp = struct.unpack(

                "!HHLLBBHHH",

                data[transport_offset:transport_offset + 20]

            )

            src_port = tcp[0]

            dst_port = tcp[1]

            seq = tcp[2]

            ack = tcp[3]
            parsed.sequence = seq
            parsed.acknowledgement = ack

            data_offset = (tcp[4] >> 4) * 4

            flags = tcp[5]

            parsed.tcp = TCPHeader(

                src_port=src_port,

                dst_port=dst_port,

                sequence=seq,

                acknowledgement=ack,

                data_offset=data_offset,

                flags=flags

            )
            parsed.has_tcp = True
            parsed.has_udp = False

            parsed.tcp_flags = flags
            parsed.tcp_sequence = seq

            parsed.src_port = src_port
            parsed.dst_port = dst_port

            parsed.src_port = src_port

            parsed.dst_port = dst_port

            payload_offset = transport_offset + data_offset

            if payload_offset < len(data):

                parsed.payload_data = data[payload_offset:]

                parsed.payload_length = len(parsed.payload_data)

            return parsed

        # ------------------------------------
        # UDP
        # ------------------------------------

        elif protocol == PacketParser.IP_PROTO_UDP:

            if len(data) < transport_offset + 8:
                 return parsed

            udp = struct.unpack(
                "!HHHH",
             data[transport_offset:transport_offset + 8]
            )

            src_port = udp[0]
            dst_port = udp[1]
            length = udp[2]

            parsed.udp = UDPHeader(
            src_port=src_port,
            dst_port=dst_port,
            length=length
        )

            parsed.has_udp = True
            parsed.has_tcp = False

            parsed.src_port = src_port
            parsed.dst_port = dst_port

            payload_offset = transport_offset + 8

            if payload_offset < len(data):
                 parsed.payload_data = data[payload_offset:]
                 parsed.payload_length = len(parsed.payload_data)

                 return parsed
        return parsed
    # ==========================================================
    # Pretty Print Packet
    # ==========================================================

    @staticmethod
    def print_packet(packet: ParsedPacket):

        print("=" * 70)

        print(
            f"Time : {packet.timestamp_sec}.{packet.timestamp_usec}"
        )

        if packet.ethernet:

            print(
                f"MAC  : {packet.ethernet.src_mac} -> {packet.ethernet.dest_mac}"
            )

        if packet.ip:

            print(
                f"IP   : {packet.src_ip} -> {packet.dst_ip}"
            )

            print(
                f"Proto: {PacketParser.protocol_to_string(packet.protocol)}"
            )

        if packet.tcp:

            print(
                f"TCP  : {packet.src_port} -> {packet.dst_port}"
            )

            print(
                f"Flags: {PacketParser.tcp_flags_to_string(packet.tcp.flags)}"
            )

            print(
                f"Seq  : {packet.tcp.sequence}"
            )

            print(
                f"Ack  : {packet.tcp.acknowledgement}"
            )

        elif packet.udp:

            print(
                f"UDP  : {packet.src_port} -> {packet.dst_port}"
            )

        print(
            f"Payload Length : {packet.payload_length} bytes"
        )

        print("=" * 70)


    # ==========================================================
    # Packet Summary
    # ==========================================================

    @staticmethod
    def summary(packet: ParsedPacket):

        proto = PacketParser.protocol_to_string(packet.protocol)

        return (

            f"{packet.src_ip}:{packet.src_port}"

            f" -> "

            f"{packet.dst_ip}:{packet.dst_port}"

            f" ({proto})"

        )


    # ==========================================================
    # Is TCP?
    # ==========================================================

    @staticmethod
    def is_tcp(packet):

        return packet.protocol == 6


    # ==========================================================
    # Is UDP?
    # ==========================================================

    @staticmethod
    def is_udp(packet):

        return packet.protocol == 17


    # ==========================================================
    # Has Payload?
    # ==========================================================

    @staticmethod
    def has_payload(packet):

        return packet.payload_length > 0


    # ==========================================================
    # Is TLS?
    # ==========================================================

    @staticmethod
    def is_tls(packet):

        if packet.protocol != 6:
            return False

        if packet.src_port == 443 or packet.dst_port == 443:
            return True

        if packet.payload_length < 5:
            return False

        return packet.payload_data[0] in (20, 21, 22, 23)


    # ==========================================================
    # Is HTTP?
    # ==========================================================

    @staticmethod
    def is_http(packet):

        if packet.protocol != 6:

            return False

        return (

            packet.src_port == 80 or

            packet.dst_port == 80

        )


    # ==========================================================
    # Is DNS?
    # ==========================================================

    @staticmethod
    def is_dns(packet):

        if packet.protocol != 17:

            return False

        return (

            packet.src_port == 53 or

            packet.dst_port == 53

        )


    # ==========================================================
    # Payload Preview
    # ==========================================================

    @staticmethod
    def payload_preview(packet, size=32):

        if packet.payload_length == 0:

            return ""

        return packet.payload_data[:size].hex(" ")


# ==========================================================
# End of packet_parser.py
# ==========================================================