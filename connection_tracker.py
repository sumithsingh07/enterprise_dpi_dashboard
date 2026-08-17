"""
connection_tracker.py

Tracks TCP/UDP connections using the FiveTuple.
Supports TCP Stream Reassembly.
"""

from dataclasses import dataclass
from datetime import datetime

from tcp_stream import TCPStream

from dpi_types import (
    FiveTuple,
    AppType,
    ConnectionState,
    PacketAction
)

from packet_parser import TCPFlags


# ==========================================================
# Connection Object
# ==========================================================

@dataclass
class Connection:

    tuple: FiveTuple

    state: ConnectionState = ConnectionState.NEW

    app_type: AppType = AppType.UNKNOWN

    sni: str = ""

    packets_in: int = 0
    packets_out: int = 0

    bytes_in: int = 0
    bytes_out: int = 0

    first_seen: datetime = None
    last_seen: datetime = None

    action: PacketAction = PacketAction.FORWARD

    # TCP Stream Buffer
    stream: TCPStream = None

    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


# ==========================================================
# Connection Tracker
# ==========================================================

class ConnectionTracker:

    def __init__(self):

        self.connections = {}

    # ------------------------------------------------------

    def get_connection(self, five_tuple):

        if five_tuple in self.connections:
            return self.connections[five_tuple]

        reverse = five_tuple.reverse()

        if reverse in self.connections:
            return self.connections[reverse]

        conn = Connection(tuple=five_tuple,stream=TCPStream())
        conn.first_seen = datetime.now()
        conn.last_seen = datetime.now()

        # Create TCP stream
        conn.stream = TCPStream()

        self.connections[five_tuple] = conn

        return conn

    # ------------------------------------------------------

    def update(self, parsed_packet):

        five_tuple = FiveTuple(
            src_ip=parsed_packet.src_ip,
            dst_ip=parsed_packet.dst_ip,
            src_port=parsed_packet.src_port,
            dst_port=parsed_packet.dst_port,
            protocol=parsed_packet.protocol
        )

        conn = self.get_connection(five_tuple)

        conn.last_seen = datetime.now()

        conn.packets_out += 1
        conn.bytes_out += parsed_packet.payload_length

        # ---------------- TCP ----------------

        if parsed_packet.has_tcp:

            # Save payload into stream
            if parsed_packet.payload_length > 0:
                conn.stream.add_packet(
                    parsed_packet.tcp_sequence,
                    parsed_packet.payload_data
                )
            flags = parsed_packet.tcp_flags

            if flags & TCPFlags.SYN:
                conn.syn_seen = True

            if flags & TCPFlags.ACK:
                conn.syn_ack_seen = True

            if flags & TCPFlags.FIN:
                conn.fin_seen = True

            if conn.syn_seen and conn.syn_ack_seen:
                conn.state = ConnectionState.ESTABLISHED

            if conn.fin_seen:
                conn.state = ConnectionState.CLOSED

        return conn

    # ------------------------------------------------------

    def process_packet(self, parsed_packet):

        return self.update(parsed_packet)

    # ------------------------------------------------------

    def get_stream_data(self, connection):

        if connection.stream is None:
            return b""
        return connection.stream.get_stream()
        tls = connection.stream.get_tls_record()

        if tls is not None:
            return tls
        return connection.stream.reassemble()
    # ------------------------------------------------------

    def remove_closed(self):

        remove = []

        for key, conn in self.connections.items():

            if conn.state == ConnectionState.CLOSED:
                remove.append(key)

        for key in remove:
            del self.connections[key]

    # ------------------------------------------------------

    def connection_count(self):

        return len(self.connections)

    # ------------------------------------------------------

    def get_all_connections(self):

        return list(self.connections.values())

    # ------------------------------------------------------

    def print_connections(self):

        print("\n")
        print("=" * 90)
        print("ACTIVE CONNECTIONS")
        print("=" * 90)

        if len(self.connections) == 0:
            print("No active connections.")
            return

        for conn in self.connections.values():

            print("\n------------------------------------------")

            print("Flow:")
            print(conn.tuple)

            print("State :", conn.state.name)

            print("Packets Out :", conn.packets_out)
            print("Packets In  :", conn.packets_in)

            print("Bytes Out :", conn.bytes_out)
            print("Bytes In  :", conn.bytes_in)

            print("Application :", conn.app_type.name)

            print("SNI :", conn.sni if conn.sni else "Not Detected")

            print("Action :", conn.action.name)

            if conn.stream:
                print("TCP Stream Size :", len(conn.stream.reassemble()))

            print("First Seen :", conn.first_seen)
            print("Last Seen  :", conn.last_seen)

            print("------------------------------------------")

    # ------------------------------------------------------

    def clear(self):

        self.connections.clear()