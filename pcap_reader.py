"""
pcap_reader.py

Reads packets from a PCAP/PCAPNG file.

Equivalent to:
    pcap_reader.h
    pcap_reader.cpp
"""

from dataclasses import dataclass
from typing import List, Optional

from scapy.all import rdpcap


# ==========================================================
# PCAP Global Header (Information Only)
# ==========================================================

@dataclass
class PcapGlobalHeader:
    version_major: int = 2
    version_minor: int = 4
    snaplen: int = 65535
    network: int = 1  # Ethernet


# ==========================================================
# Packet Header
# ==========================================================

@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


# ==========================================================
# Raw Packet
# ==========================================================

@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes


# ==========================================================
# PCAP Reader
# ==========================================================

class PcapReader:

    def __init__(self):

        self.filename = None

        self.packets: List = []

        self.current_index = 0

        self.global_header = PcapGlobalHeader()

    # ------------------------------------------------------
    # Open PCAP File
    # ------------------------------------------------------

    def open(self, filename: str) -> bool:

        try:

            self.filename = filename

            self.packets = rdpcap(filename)

            self.current_index = 0

            print("\n======================================")
            print("PCAP FILE OPENED")
            print("======================================")
            print("Filename :", filename)
            print("Packets  :", len(self.packets))
            print(
                "Version  :",
                f"{self.global_header.version_major}.{self.global_header.version_minor}",
            )
            print("Snaplen  :", self.global_header.snaplen)
            print("LinkType : Ethernet")
            print("======================================\n")

            return True

        except Exception as e:

            print("Error opening PCAP:", e)

            return False

    # ------------------------------------------------------
    # Close File
    # ------------------------------------------------------

    def close(self):

        self.filename = None

        self.packets.clear()

        self.current_index = 0

    # ------------------------------------------------------
    # Check File Open
    # ------------------------------------------------------

    def is_open(self):

        return self.filename is not None

    # ------------------------------------------------------
    # Read Next Packet
    # ------------------------------------------------------

    def read_next_packet(self) -> Optional[RawPacket]:

        if self.current_index >= len(self.packets):

            return None

        pkt = self.packets[self.current_index]

        self.current_index += 1

        raw_data = bytes(pkt)

        timestamp = float(pkt.time)

        ts_sec = int(timestamp)

        ts_usec = int((timestamp - ts_sec) * 1_000_000)

        header = PcapPacketHeader(

            ts_sec=ts_sec,

            ts_usec=ts_usec,

            incl_len=len(raw_data),

            orig_len=len(raw_data)

        )

        return RawPacket(

            header=header,

            data=raw_data

        )

    # ------------------------------------------------------
    # Read All Packets
    # ------------------------------------------------------

    def read_all_packets(self):

        packets = []

        while True:

            packet = self.read_next_packet()

            if packet is None:

                break

            packets.append(packet)

        return packets

    # ------------------------------------------------------
    # Total Packet Count
    # ------------------------------------------------------

    def packet_count(self):

        return len(self.packets)

    # ------------------------------------------------------
    # Restart Reading
    # ------------------------------------------------------

    def reset(self):

        self.current_index = 0

    # ------------------------------------------------------
    # Get Global Header
    # ------------------------------------------------------

    def get_global_header(self):

        return self.global_header