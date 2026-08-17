"""
protocol_detector.py

Payload-based Protocol Detection

Detects protocols without relying on port numbers.
"""

from dpi_types import ProtocolType


class ProtocolDetector:

    @staticmethod
    def detect(payload: bytes) -> ProtocolType:

        if not payload:
            return ProtocolType.UNKNOWN

        # -----------------------------
        # HTTP
        # -----------------------------
        http_methods = (
            b"GET ",
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"TRACE ",
            b"HTTP/"
        )

        for method in http_methods:
            if payload.startswith(method):
                return ProtocolType.HTTP

        # -----------------------------
        # TLS
        # -----------------------------
        if len(payload) >= 5:

            content_type = payload[0]
            version_major = payload[1]
            version_minor = payload[2]

            if (
                content_type in (20, 21, 22, 23)
                and version_major == 3
                and version_minor in (0, 1, 2, 3, 4)
            ):
                return ProtocolType.TLS

        # -----------------------------
        # DNS
        # -----------------------------
        if len(payload) >= 12:

            flags = (payload[2] << 8) | payload[3]

            opcode = (flags >> 11) & 0x0F

            if opcode <= 5:
                return ProtocolType.DNS

        # -----------------------------
        # SSH
        # -----------------------------
        if payload.startswith(b"SSH-"):
            return ProtocolType.SSH

        # -----------------------------
        # FTP
        # -----------------------------
        ftp_keywords = (
            b"USER",
            b"PASS",
            b"220 ",
            b"230 ",
            b"331 "
        )

        for word in ftp_keywords:
            if payload.startswith(word):
                return ProtocolType.FTP

        # -----------------------------
        # SMTP
        # -----------------------------
        smtp_keywords = (
            b"HELO",
            b"EHLO",
            b"MAIL FROM",
            b"RCPT TO",
            b"DATA"
        )

        for word in smtp_keywords:
            if payload.startswith(word):
                return ProtocolType.SMTP

        # -----------------------------
        # POP3
        # -----------------------------
        pop_keywords = (
            b"+OK",
            b"USER",
            b"PASS"
        )

        for word in pop_keywords:
            if payload.startswith(word):
                return ProtocolType.POP3

        # -----------------------------
        # IMAP
        # -----------------------------
        if (
            payload.startswith(b"* OK")
            or payload.startswith(b"A001")
        ):
            return ProtocolType.IMAP

        # -----------------------------
        # MQTT
        # -----------------------------
        if payload[0] == 0x10:
            return ProtocolType.MQTT

        # -----------------------------
        # QUIC
        # -----------------------------
        if len(payload) >= 6:

            first = payload[0]

            if first & 0x80:
                return ProtocolType.QUIC

        return ProtocolType.UNKNOWN