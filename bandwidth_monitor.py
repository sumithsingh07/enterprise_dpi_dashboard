"""
bandwidth_monitor.py

Enterprise Bandwidth Monitor
"""

from collections import defaultdict
from datetime import datetime


class BandwidthMonitor:

    def __init__(self):
        self.rx_bytes = defaultdict(int)
        self.tx_bytes = defaultdict(int)

    def update(self, packet):

        now = datetime.now().strftime("%H:%M:%S")

        self.rx_bytes[now] += packet.payload_length
        self.tx_bytes[now] += packet.payload_length

    def get_statistics(self):

        return [
            {
                "time": t,
                "rx": self.rx_bytes[t],
                "tx": self.tx_bytes[t]
            }
            for t in sorted(self.rx_bytes.keys())
        ]