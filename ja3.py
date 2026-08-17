"""
ja3.py

JA3 TLS Fingerprinting

Part 1
- Parse ClientHello
- Extract TLS Version
- Extract Cipher Suites
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import List


# ==========================================================
# JA3 Result
# ==========================================================

@dataclass
class JA3Result:

    valid: bool = False

    version: int = 0

    cipher_suites: List[int] = None

    extensions: List[int] = None

    curves: List[int] = None

    ec_formats: List[int] = None

    ja3_string: str = ""

    ja3_hash: str = ""


# ==========================================================
# JA3 Parser
# ==========================================================

class JA3Parser:

    @staticmethod
    def parse_client_hello(data):

        result = JA3Result()

        result.cipher_suites = []
        result.extensions = []
        result.curves = []
        result.ec_formats = []

        if len(data) < 9:
            return result

        # TLS Record
        if data[0] != 22:
            return result

        record_length = struct.unpack("!H", data[3:5])[0]

        if len(data) < record_length + 5:
            return result

        offset = 5

        # Handshake Type
        if data[offset] != 1:
            return result

        offset += 4

        # TLS Version
        result.version = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2

        # Random
        offset += 32

        # Session ID
        session_len = data[offset]
        offset += 1 + session_len

        # Cipher Suites
        cipher_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2

        end = offset + cipher_len

        while offset + 2 <= end:
            cipher = struct.unpack("!H", data[offset:offset+2])[0]
            result.cipher_suites.append(cipher)
            offset += 2

        # Compression Methods
        compression_len = data[offset]
        offset += 1 + compression_len

        # Extensions
        if offset + 2 > len(data):
            result.valid = True
            return result

        ext_total = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2

        ext_end = offset + ext_total

        while offset + 4 <= ext_end:

            ext_type = struct.unpack("!H", data[offset:offset+2])[0]
            ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]

            result.extensions.append(ext_type)

            ext_data = data[offset+4:offset+4+ext_len]

            # Supported Groups (Extension 10)
            if ext_type == 10:

                if len(ext_data) >= 2:

                    curve_len = struct.unpack("!H", ext_data[:2])[0]

                    p = 2

                    while p + 2 <= 2 + curve_len:

                        curve = struct.unpack(
                            "!H",
                            ext_data[p:p+2]
                        )[0]

                        result.curves.append(curve)

                        p += 2

            # EC Point Formats (Extension 11)
            elif ext_type == 11:

                if len(ext_data) >= 1:

                    fmt_len = ext_data[0]

                    result.ec_formats = list(
                        ext_data[1:1+fmt_len]
                    )

            offset += 4 + ext_len

        result.valid = True

        return result
    @staticmethod
    def build_ja3_string(result):

        version = str(result.version)

        ciphers = "-".join(
            str(x) for x in result.cipher_suites
        )

        extensions = "-".join(
            str(x) for x in result.extensions
        )

        curves = "-".join(
            str(x) for x in result.curves
        )

        ec_formats = "-".join(
            str(x) for x in result.ec_formats
        )

        return ",".join([
            version,
            ciphers,
            extensions,
            curves,
            ec_formats
        ])
    @staticmethod
    def fingerprint(result):

        if not result.valid:
            return result

        result.ja3_string = JA3Parser.build_ja3_string(result)

        result.ja3_hash = hashlib.md5(
            result.ja3_string.encode()
        ).hexdigest()

        return result