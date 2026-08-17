"""
tcp_order.py

TCP ordering analyzer.

Detects:
- Out-of-order packets
- Missing segments
- Sequence gaps

Designed for PCAP analysis without flooding the console.
"""

from dataclasses import dataclass


@dataclass
class TCPOrderStatistics:

    out_of_order: int = 0
    missing_segments: int = 0
    sequence_gaps: int = 0


class TCPOrderAnalyzer:

    def __init__(self, print_alerts=False, alert_limit=20):

        # Expected next sequence number per flow
        self.expected_seq = {}

        self.stats = TCPOrderStatistics()

        # Console control
        self.print_alerts = print_alerts
        self.alert_limit = alert_limit

        self._out_of_order_printed = 0
        self._sequence_gap_printed = 0

    # ---------------------------------------------------------
    # ANALYZE
    # ---------------------------------------------------------

    def analyze(self, connection, packet):

        if not packet.has_tcp:
            return

        key = connection.tuple

        # -----------------------------------------------------
        # Safely obtain TCP object
        # -----------------------------------------------------

        tcp = getattr(packet, "tcp", None)

        if tcp is None:
            return

        # -----------------------------------------------------
        # Sequence number
        # -----------------------------------------------------

        seq = getattr(
            tcp,
            "sequence",
            None
        )

        if seq is None:
            return

        seq = int(seq)

        # -----------------------------------------------------
        # Payload length
        # -----------------------------------------------------

        payload = getattr(
            packet,
            "payload_length",
            0
        )

        if payload is None:
            payload = 0

        payload = int(payload)

        # -----------------------------------------------------
        # TCP flags
        # -----------------------------------------------------

        syn = bool(
            getattr(tcp, "syn", False)
        )

        fin = bool(
            getattr(tcp, "fin", False)
        )

        # SYN and FIN consume one sequence number.
        sequence_consumption = payload

        if syn:
            sequence_consumption += 1

        if fin:
            sequence_consumption += 1

        # -----------------------------------------------------
        # First packet of flow
        # -----------------------------------------------------

        if key not in self.expected_seq:

            self.expected_seq[key] = (
                seq + sequence_consumption
            )

            return

        expected = self.expected_seq[key]

        # -----------------------------------------------------
        # Ignore pure duplicate ACKs
        #
        # A packet with no payload and no SYN/FIN does not
        # advance TCP sequence space.
        # -----------------------------------------------------

        if payload == 0 and not syn and not fin:

            return

        # -----------------------------------------------------
        # OUT OF ORDER / DUPLICATE DATA
        # -----------------------------------------------------

        if seq < expected:

            self.stats.out_of_order += 1

            self._print_out_of_order()

        # -----------------------------------------------------
        # SEQUENCE GAP
        # -----------------------------------------------------

        elif seq > expected:

            self.stats.missing_segments += 1

            gap = seq - expected

            self.stats.sequence_gaps += gap

            self._print_sequence_gap()

        # -----------------------------------------------------
        # Update expected sequence
        # -----------------------------------------------------

        new_expected = seq + sequence_consumption

        if new_expected > expected:

            self.expected_seq[key] = new_expected

    # ---------------------------------------------------------
    # OUT OF ORDER PRINT
    # ---------------------------------------------------------

    def _print_out_of_order(self):

        if not self.print_alerts:
            return

        if self._out_of_order_printed >= self.alert_limit:
            return

        print("*** OUT OF ORDER PACKET ***")

        self._out_of_order_printed += 1

    # ---------------------------------------------------------
    # SEQUENCE GAP PRINT
    # ---------------------------------------------------------

    def _print_sequence_gap(self):

        if not self.print_alerts:
            return

        if self._sequence_gap_printed >= self.alert_limit:
            return

        print("*** SEQUENCE GAP DETECTED ***")

        self._sequence_gap_printed += 1

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    def print_statistics(self):

        print("\n========== TCP ORDER ANALYSIS ==========")

        print(
            "Out Of Order     :",
            self.stats.out_of_order
        )

        print(
            "Missing Segments :",
            self.stats.missing_segments
        )

        print(
            "Sequence Gaps    :",
            self.stats.sequence_gaps
        )

        print("========================================")