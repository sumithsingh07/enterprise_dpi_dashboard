"""
tls_certificate.py

TLS Certificate Parser

Extracts X509 certificates from TLS Certificate handshake messages.
Used after TCP stream reassembly.

Equivalent to Wireshark TLS Certificate parser.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional

from dpi_types import AppType


# ==========================================================
# TLS Handshake Types
# ==========================================================

CERTIFICATE = 11


# ==========================================================
# ASN.1 Reader
# ==========================================================

class ASN1Reader:

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def remaining(self):
        return len(self.data) - self.offset

    def eof(self):
        return self.offset >= len(self.data)

    def read_byte(self):

        if self.eof():
            raise ValueError("Unexpected EOF")

        value = self.data[self.offset]
        self.offset += 1

        return value

    def read_bytes(self, count):

        if self.offset + count > len(self.data):
            raise ValueError("Unexpected EOF")

        value = self.data[self.offset:self.offset + count]

        self.offset += count

        return value

    def read_length(self):

        first = self.read_byte()

        if first < 0x80:
            return first

        count = first & 0x7F

        length = 0

        for _ in range(count):
            length = (length << 8) | self.read_byte()

        return length

    def read_tlv(self):

        tag = self.read_byte()

        length = self.read_length()

        value = self.read_bytes(length)

        return tag, value


# ==========================================================
# Certificate
# ==========================================================

@dataclass
class X509Certificate:

    raw: bytes

    subject_cn: str = ""

    issuer_cn: str = ""

    dns_names: List[str] = None


# ==========================================================
# TLS Certificate Result
# ==========================================================

@dataclass
class CertificateResult:

    valid: bool = False

    certificates: List[X509Certificate] = None

    application: AppType = AppType.UNKNOWN


# ==========================================================
# TLS Certificate Parser
# ==========================================================

class TLSCertificateParser:

    @staticmethod
    def parse(handshake_payload):

        result = CertificateResult()

        result.certificates = []

        if len(handshake_payload) < 4:
            return result

        if handshake_payload[0] != CERTIFICATE:
            return result

        handshake_length = int.from_bytes(
            handshake_payload[1:4],
            "big"
        )

        if len(handshake_payload) < handshake_length + 4:
            return result

        body = handshake_payload[4:]

        if len(body) < 3:
            return result

        total_length = int.from_bytes(
            body[:3],
            "big"
        )

        offset = 3

        while offset + 3 <= len(body):

            cert_length = int.from_bytes(
                body[offset:offset + 3],
                "big"
            )

            offset += 3

            if offset + cert_length > len(body):
                break

            certificate_bytes = body[
                offset:offset + cert_length
            ]

            offset += cert_length

            cert = X509Certificate(
                raw=certificate_bytes,
                dns_names=[]
            )

            cert = X509Parser.parse_certificate(cert)
            result.certificates.append(cert)

        if len(result.certificates):

            result.valid = True

        return result
    # ==========================================================
# ASN.1 Object Identifiers
# ==========================================================

OID_COMMON_NAME = b"\x55\x04\x03"
OID_ORGANIZATION = b"\x55\x04\x0A"
OID_COUNTRY = b"\x55\x04\x06"


# ==========================================================
# X509 Decoder
# ==========================================================

class X509Parser:

    @staticmethod
    def parse_certificate(cert):

        try:

            X509Parser._extract_names(cert)

            X509Parser._extract_dns_names(cert)

        except Exception:

            pass

        return cert

    # ------------------------------------------------------

    @staticmethod
    def _extract_names(cert):

        data = cert.raw

        cn_list = []

        issuer_list = []

        i = 0

        while i < len(data) - 10:

            # Search for Common Name OID
            if data[i:i+3] == OID_COMMON_NAME:

                pos = i + 3

                if pos >= len(data):
                    break

                tag = data[pos]
                pos += 1

                if pos >= len(data):
                    break

                length = data[pos]
                pos += 1

                if length & 0x80:

                    count = length & 0x7F

                    length = int.from_bytes(
                        data[pos:pos+count],
                        "big"
                    )

                    pos += count

                if pos + length > len(data):
                    break

                try:

                    text = data[
                        pos:pos+length
                    ].decode(
                        "utf-8",
                        errors="ignore"
                    )

                except Exception:

                    text = ""

                if text:

                    cn_list.append(text)

                i = pos + length

            else:

                i += 1

        if len(cn_list):

            cert.subject_cn = cn_list[0]

            if len(cn_list) > 1:

                cert.issuer_cn = cn_list[-1]
    @staticmethod
    def _extract_dns_names(cert):

        data = cert.raw

        cert.dns_names = []

        i = 0

        while i < len(data) - 4:

            # IA5String tag (used for DNS names)
            if data[i] == 0x82:

                length = data[i + 1]

                if length == 0:
                    i += 1
                    continue

                if i + 2 + length > len(data):
                    break

                try:

                    text = data[
                        i + 2:
                        i + 2 + length
                    ].decode(
                        "ascii",
                        errors="ignore"
                    )

                except Exception:

                    text = ""

                if "." in text:

                    cert.dns_names.append(text)

                i += 2 + length

            else:

                i += 1
class CertificateClassifier:

    @staticmethod
    def classify(cert):

        from sni_extractor import ApplicationClassifier

        if cert.subject_cn:

            app = ApplicationClassifier.classify(
                cert.subject_cn
            )

            if app.name != "UNKNOWN":

                return app

        for domain in cert.dns_names:

            app = ApplicationClassifier.classify(domain)

            if app.name != "UNKNOWN":

                return app

        return AppType.UNKNOWN