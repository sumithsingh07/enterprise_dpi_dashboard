"""
test_tls.py

Tests:
PCAP Reader
Packet Parser
TLS/SNI Extractor
"""

from pcap_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import ApplicationClassifier

reader = PcapReader()

if not reader.open("sample.pcapng"):
    exit()

classifier = ApplicationClassifier()

packet_number = 0

while True:

    raw_packet = reader.read_next_packet()

    if raw_packet is None:
        break

    packet_number += 1

    parsed = PacketParser.parse(raw_packet)

    if parsed is None:
        continue

    if parsed.payload_length == 0:
        continue

    result = classifier.classify(
        parsed.payload_data
    )

    if result is not None:

        print("=" * 60)
        print("Packet :", packet_number)
        print("Source :", parsed.src_ip)
        print("Dest   :", parsed.dest_ip)
        print("SNI    :", result.sni)
        print("App    :", result.app_type)
        print("=" * 60)

reader.close()