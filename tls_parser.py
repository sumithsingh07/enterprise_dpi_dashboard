"""
tls_parser.py

Manual TLS ClientHello Parser

Equivalent to:
    tls_parser.h
    tls_parser.cpp

This module manually parses:

- TLS Record Header
- TLS Handshake Header
- ClientHello

No Scapy TLS parser is used.
"""

import struct

from dataclasses import dataclass


# ==========================================================
# TLS Constants
# ==========================================================

TLS_CHANGE_CIPHER_SPEC = 20
TLS_ALERT = 21
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23

TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43


# ==========================================================
# TLS Record
# ==========================================================

@dataclass
class TLSRecord:

    content_type: int

    version: int

    length: int

    payload: bytes


# ==========================================================
# TLS Handshake
# ==========================================================

@dataclass
class TLSHandshake:

    handshake_type: int

    length: int

    payload: bytes


# ==========================================================
# ClientHello
# ==========================================================

@dataclass
class ClientHello:

    version: int = 0

    random: bytes = b""

    session_id: bytes = b""

    cipher_suites: list = None

    compression_methods: list = None

    extensions: dict = None

    sni: str = ""

    alpn: list = None


# ==========================================================
# TLS Parser
# ==========================================================

class TLSParser:

    # ------------------------------------------------------
    # Parse TLS Record
    # ------------------------------------------------------

    @staticmethod
    def parse_record(data: bytes):

        if len(data) < 5:
            return None

        content_type = data[0]

        version = struct.unpack("!H", data[1:3])[0]

        length = struct.unpack("!H", data[3:5])[0]

        if len(data) < 5 + length:
            return None

        payload = data[5:5 + length]

        return TLSRecord(

            content_type,

            version,

            length,

            payload

        )

    # ------------------------------------------------------
    # Parse Handshake
    # ------------------------------------------------------

    @staticmethod
    def parse_handshake(record: TLSRecord):

        if record is None:
            return None

        if record.content_type != TLS_HANDSHAKE:
            return None

        if len(record.payload) < 4:
            return None

        handshake_type = record.payload[0]

        length = int.from_bytes(

            record.payload[1:4],

            "big"

        )

        if len(record.payload) < 4 + length:
            return None

        payload = record.payload[4:4 + length]

        return TLSHandshake(

            handshake_type,

            length,

            payload

        )

    # ------------------------------------------------------
    # Check ClientHello
    # ------------------------------------------------------

    @staticmethod
    def is_client_hello(handshake):

        if handshake is None:
            return False

        return handshake.handshake_type == TLS_CLIENT_HELLO

    # ------------------------------------------------------
    # TLS Version String
    # ------------------------------------------------------

    @staticmethod
    def version_to_string(version):

        versions = {

            0x0301: "TLS 1.0",

            0x0302: "TLS 1.1",

            0x0303: "TLS 1.2",

            0x0304: "TLS 1.3",

        }

        return versions.get(

            version,

            hex(version)

        )
        # ------------------------------------------------------
    # Parse ClientHello
    # ------------------------------------------------------

    @staticmethod
    def parse_client_hello(handshake):

        if handshake is None:
            return None

        if handshake.handshake_type != TLS_CLIENT_HELLO:
            return None

        data = handshake.payload
        offset = 0

        hello = ClientHello()

        # -----------------------------------
        # Client Version (2 bytes)
        # -----------------------------------

        if len(data) < offset + 2:
            return None

        hello.version = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        offset += 2

        # -----------------------------------
        # Random (32 bytes)
        # -----------------------------------

        if len(data) < offset + 32:
            return None

        hello.random = data[offset:offset + 32]

        offset += 32

        # -----------------------------------
        # Session ID
        # -----------------------------------

        if len(data) < offset + 1:
            return None

        session_length = data[offset]

        offset += 1

        if len(data) < offset + session_length:
            return None

        hello.session_id = data[offset:offset + session_length]

        offset += session_length

        # -----------------------------------
        # Cipher Suites
        # -----------------------------------

        if len(data) < offset + 2:
            return None

        cipher_length = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        offset += 2

        if len(data) < offset + cipher_length:
            return None

        hello.cipher_suites = []

        end = offset + cipher_length

        while offset + 2 <= end:

            cipher = struct.unpack(
                "!H",
                data[offset:offset + 2]
            )[0]

            hello.cipher_suites.append(cipher)

            offset += 2

        # -----------------------------------
        # Compression Methods
        # -----------------------------------

        if len(data) < offset + 1:
            return hello

        compression_count = data[offset]

        offset += 1

        if len(data) < offset + compression_count:
            return hello

        hello.compression_methods = list(
            data[offset:offset + compression_count]
        )

        offset += compression_count

        # -----------------------------------
        # Save remaining bytes
        # (Extensions start here)
        # -----------------------------------

        hello.extensions = {}

        hello._extension_offset = offset
        hello._raw = data

        return hello
        # ------------------------------------------------------
    # Parse Extensions
    # ------------------------------------------------------

    @staticmethod
    def parse_extensions(hello):

        if hello is None:
            return None

        data = hello._raw
        offset = hello._extension_offset

        # No extensions
        if len(data) < offset + 2:
            return hello

        extensions_length = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        offset += 2

        end = offset + extensions_length

        hello.extensions = {}

        while offset + 4 <= end and offset + 4 <= len(data):

            ext_type = struct.unpack(
                "!H",
                data[offset:offset + 2]
            )[0]

            ext_length = struct.unpack(
                "!H",
                data[offset + 2:offset + 4]
            )[0]

            offset += 4

            if offset + ext_length > len(data):
                break

            ext_data = data[offset:offset + ext_length]

            hello.extensions[ext_type] = ext_data

            # ----------------------------
            # Extension 0 = Server Name
            # ----------------------------

            if ext_type == EXT_SERVER_NAME:

                TLSParser.parse_sni(
                    hello,
                    ext_data
                )

            # ----------------------------
            # Extension 16 = ALPN
            # ----------------------------

            elif ext_type == EXT_ALPN:

                TLSParser.parse_alpn(
                    hello,
                    ext_data
                )

            offset += ext_length

        return hello


    # ------------------------------------------------------
    # Parse Server Name (SNI)
    # ------------------------------------------------------

    @staticmethod
    def parse_sni(hello, data):

        try:

            if len(data) < 5:
                return

            offset = 2

            name_type = data[offset]

            offset += 1

            if name_type != 0:
                return

            name_length = struct.unpack(
                "!H",
                data[offset:offset + 2]
            )[0]

            offset += 2

            if offset + name_length > len(data):
                return

            hello.sni = data[
                offset:offset + name_length
            ].decode(
                "utf-8",
                errors="ignore"
            )

        except Exception:

            pass


    # ------------------------------------------------------
    # Parse ALPN
    # ------------------------------------------------------

    @staticmethod
    def parse_alpn(hello, data):

        hello.alpn = []

        try:

            if len(data) < 2:
                return

            offset = 2

            while offset < len(data):

                proto_len = data[offset]

                offset += 1

                if offset + proto_len > len(data):
                    break

                proto = data[
                    offset:offset + proto_len
                ].decode(
                    "utf-8",
                    errors="ignore"
                )

                hello.alpn.append(proto)

                offset += proto_len

        except Exception:

            pass


    # ------------------------------------------------------
    # Complete TLS Parse
    # ------------------------------------------------------

    @staticmethod
    def parse(data):

        record = TLSParser.parse_record(data)

        if record is None:
            return None

        handshake = TLSParser.parse_handshake(record)

        if handshake is None:
            return None

        if not TLSParser.is_client_hello(handshake):
            return None

        hello = TLSParser.parse_client_hello(handshake)

        if hello is None:
            return None

        TLSParser.parse_extensions(hello)

        return hello