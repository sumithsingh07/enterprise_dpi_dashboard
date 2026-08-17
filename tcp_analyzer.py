"""
tcp_analyzer.py

Enterprise TCP Analyzer

Detects:
- Retransmissions
- Duplicate ACKs
- Out-of-order packets

Designed for PCAP analysis without flooding the console.
"""

from dataclasses import dataclass


@dataclass
class TCPStatistics:
    retransmissions: int = 0
    duplicate_acks: int = 0
    out_of_order: int = 0


class TCPAnalyzer:

    def __init__(self, print_alerts=False, alert_limit=20):

        # Highest sequence number observed per TCP flow
        self.highest_seq = {}

        # Last ACK observed per TCP flow
        self.last_ack = {}

        self.stats = TCPStatistics()

        # Console control
        self.print_alerts = print_alerts
        self.alert_limit = alert_limit

        self._retransmission_printed = 0
        self._duplicate_ack_printed = 0

    # ---------------------------------------------------------
    # ANALYZE
    # ---------------------------------------------------------

    def analyze(self, connection, packet):

        if not packet.has_tcp:
            return

        key = connection.tuple

        # -----------------------------------------------------
        # Get sequence number
        # -----------------------------------------------------

        seq = self._get_sequence(packet)

        # -----------------------------------------------------
        # Get acknowledgment number
        # -----------------------------------------------------

        ack = self._get_ack(packet)

        # -----------------------------------------------------
        # RETRANSMISSION
        # -----------------------------------------------------

        if key in self.highest_seq:

            highest = self.highest_seq[key]

            if seq < highest:

                self.stats.retransmissions += 1

                self._print_retransmission()

        # Update highest sequence
        self.highest_seq[key] = max(
            self.highest_seq.get(key, seq),
            seq
        )

        # -----------------------------------------------------
        # DUPLICATE ACK
        # -----------------------------------------------------

        if key in self.last_ack:

            previous_ack = self.last_ack[key]

            if ack == previous_ack:

                self.stats.duplicate_acks += 1

                self._print_duplicate_ack()

        self.last_ack[key] = ack

    # ---------------------------------------------------------
    # SEQUENCE
    # ---------------------------------------------------------

    @staticmethod
    def _get_sequence(packet):

        if hasattr(packet, "tcp_sequence"):

            value = packet.tcp_sequence

            if value is not None:
                return int(value)

        if hasattr(packet, "tcp"):

            tcp = packet.tcp

            if tcp is not None:

                value = getattr(
                    tcp,
                    "sequence",
                    0
                )

                if value is not None:
                    return int(value)

        return 0

    # ---------------------------------------------------------
    # ACK
    # ---------------------------------------------------------

    @staticmethod
    def _get_ack(packet):

        if hasattr(packet, "tcp_ack"):

            value = packet.tcp_ack

            if value is not None:
                return int(value)

        if hasattr(packet, "tcp"):

            tcp = packet.tcp

            if tcp is not None:

                value = getattr(
                    tcp,
                    "acknowledgement",
                    0
                )

                if value is not None:
                    return int(value)

        return 0

    # ---------------------------------------------------------
    # PRINT RETRANSMISSION
    # ---------------------------------------------------------

    def _print_retransmission(self):

        if not self.print_alerts:
            return

        if self._retransmission_printed >= self.alert_limit:
            return

        print("*** TCP RETRANSMISSION ***")

        self._retransmission_printed += 1

    # ---------------------------------------------------------
    # PRINT DUPLICATE ACK
    # ---------------------------------------------------------

    def _print_duplicate_ack(self):

        if not self.print_alerts:
            return

        if self._duplicate_ack_printed >= self.alert_limit:
            return

        print("*** DUPLICATE ACK ***")

        self._duplicate_ack_printed += 1

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    def print_statistics(self):

        print("\n========== TCP ANALYSIS ==========")

        print(
            "Retransmissions :",
            self.stats.retransmissions
        )

        print(
            "Duplicate ACKs  :",
            self.stats.duplicate_acks
        )

        print(
            "Out Of Order    :",
            self.stats.out_of_order
        )

        print("==================================")