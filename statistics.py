"""
statistics.py

Collects statistics for the DPI Engine.
"""

from collections import Counter
from multiprocessing import connection


class DPIStatistics:

    def __init__(self):

        self.total_packets = 0

        self.protocols = Counter()

        self.applications = Counter()

        self.source_ips = Counter()

        self.destination_ips = Counter()

        self.domains = Counter()

    # ------------------------------------
    # Update Statistics
    # ------------------------------------

    def update(self, packet, connection=None, domain=None):

        self.total_packets += 1

        if packet.protocol == 6:
            self.protocols["TCP"] += 1

        elif packet.protocol == 17:
            self.protocols["UDP"] += 1

        else:
            self.protocols["OTHER"] += 1

        self.source_ips[packet.src_ip] += 1
        self.destination_ips[packet.dst_ip] += 1

        if connection:

            if hasattr(connection, "app_type") and connection.app_type:
                self.applications[connection.app_type.name] += 1

            elif hasattr(connection, "application"):

                if hasattr(connection.application, "name"):
                    self.applications[connection.application.name] += 1

                else:
                    self.applications[str(connection.application)] += 1
        if domain:
            self.domains[domain] += 1

    # ------------------------------------
    # Print Report
    # ------------------------------------

    def print_report(self):

        print("\n")
        print("=" * 65)
        print("DPI STATISTICS REPORT")
        print("=" * 65)

        print(f"Total Packets : {self.total_packets}")

        print("\nProtocols")

        for proto, count in self.protocols.items():
            print(f"{proto:10} {count}")

        print("\nTop Applications")

        for app, count in self.applications.most_common(10):
            print(f"{app:20} {count}")

        print("\nTop Source IPs")

        for ip, count in self.source_ips.most_common(10):
            print(f"{ip:20} {count}")

        print("\nTop Destination IPs")

        for ip, count in self.destination_ips.most_common(10):
            print(f"{ip:20} {count}")

        print("\nTop Domains")

        for domain, count in self.domains.most_common(10):
            print(f"{domain:40} {count}")

        print("=" * 65)