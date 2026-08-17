"""
tcp_stream.py

TCP Stream Reassembly

Collects TCP payloads using sequence numbers
and rebuilds the application stream.

Similar to Wireshark TCP Reassembly.
"""

from collections import OrderedDict


class TCPStream:

    def __init__(self):

        self.fragments = OrderedDict()

        self.expected_seq = None

        self.closed = False

    # -----------------------------------------------------

    def add_packet(self, sequence, payload):

        if len(payload) == 0:
            return

        self.fragments[sequence] = payload

        if self.expected_seq is None:
            self.expected_seq = sequence

    # -----------------------------------------------------

    def get_stream(self):

        if self.expected_seq is None:
            return b""

        stream = bytearray()

        seq = self.expected_seq

        while seq in self.fragments:

            data = self.fragments[seq]

            stream.extend(data)

            seq += len(data)

        return bytes(stream)

    # -----------------------------------------------------

    def clear_consumed(self):

        if self.expected_seq is None:
            return

        seq = self.expected_seq

        while seq in self.fragments:

            data = self.fragments.pop(seq)

            seq += len(data)

        self.expected_seq = seq

    # -----------------------------------------------------

    def reset(self):

        self.fragments.clear()

        self.expected_seq = None

        self.closed = False

    # -----------------------------------------------------

    def size(self):

        return len(self.get_stream())

    # -----------------------------------------------------

    def has_data(self):

        return self.size() > 0

    # -----------------------------------------------------

    def close(self):

        self.closed = True