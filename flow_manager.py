"""
flow_manager.py

Enterprise Flow Manager
"""

from dataclasses import dataclass
from datetime import datetime

@dataclass
class Flow:

    flow_id: int

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: str

    app: str = "UNKNOWN"

    domain: str = ""

    sni: str = ""

    ja3: str = ""

    ja4: str = ""

    packets: int = 0

    bytes: int = 0

    first_seen: datetime = None

    last_seen: datetime = None
class FlowManager:

    def __init__(self):

        self.flows = {}

        self.counter = 1

    def update(self, connection, packet):

        key = (
            connection.tuple.src_ip,
            connection.tuple.dst_ip,
            connection.tuple.src_port,
            connection.tuple.dst_port,
            connection.tuple.protocol,
        )

        if key not in self.flows:

            self.flows[key] = Flow(

                flow_id=self.counter,

                src_ip=connection.tuple.src_ip,

                dst_ip=connection.tuple.dst_ip,

                src_port=connection.tuple.src_port,

                dst_port=connection.tuple.dst_port,

                protocol=connection.tuple.protocol,

                first_seen=datetime.now(),

                last_seen=datetime.now(),
            )

            self.counter += 1

        flow = self.flows[key]

        flow.last_seen = datetime.now()

        flow.packets += 1

        flow.bytes += packet.payload_length

        flow.app = connection.app_type.name

        flow.domain = getattr(connection, "domain", "")

        flow.sni = connection.sni

        flow.ja3 = getattr(connection, "ja3", "")

        flow.ja4 = getattr(connection, "ja4", "")

        return flow

    def print_statistics(self):

        print("\n========== FLOW SUMMARY ==========")

        print("Total Flows :", len(self.flows))

        print("==================================")