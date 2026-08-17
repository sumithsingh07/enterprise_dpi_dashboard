from pcap_reader import PcapReader
from packet_parser import PacketParser

reader = PcapReader()

if reader.open("sample.pcapng"):

    while True:

        raw = reader.read_next_packet()

        if raw is None:
            break

        packet = PacketParser.parse(raw)

        if packet is None:
            continue

        print("=" * 60)

        print("Source MAC :", packet.src_mac)

        print("Destination:", packet.dest_mac)

        if packet.has_ip:

            print("Source IP  :", packet.src_ip)

            print("Destination:", packet.dest_ip)

            print("Protocol   :", PacketParser.protocol_to_string(packet.protocol))

        if packet.has_tcp:

            print("TCP Ports  :", packet.src_port, "->", packet.dest_port)

            print("Flags      :", PacketParser.tcp_flags_to_string(packet.tcp_flags))

        if packet.has_udp:

            print("UDP Ports  :", packet.src_port, "->", packet.dest_port)

        print("Payload    :", packet.payload_length, "Bytes")