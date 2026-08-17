"""
sni_extractor.py

Manual TLS ClientHello Parser

This module extracts the SNI (Server Name Indication)
from HTTPS traffic without decrypting TLS.

Equivalent to the C++ SNI parser.
"""

import struct

from dpi_types import AppType, sni_to_app_type


# ==========================================================
# TLS Constants
# ==========================================================

TLS_HANDSHAKE = 22
TLS_ALERT = 21
TLS_APPLICATION_DATA = 23
TLS_CHANGE_CIPHER_SPEC = 20

CLIENT_HELLO = 1


# ==========================================================
# TLS Record
# ==========================================================

class TLSRecord:

    def __init__(self):

        self.content_type = 0
        self.version = 0
        self.length = 0
        self.payload = b""


# ==========================================================
# Handshake Message
# ==========================================================

class TLSHandshake:

    def __init__(self):

        self.handshake_type = 0
        self.length = 0
        self.body = b""


# ==========================================================
# SNI Result
# ==========================================================

class SNIResult:

    def __init__(self):

        self.valid = False

        self.sni = ""

        self.application = None

        self.tls_version = ""

        self.handshake_length = 0


# ==========================================================
# TLS Parser
# ==========================================================

class TLSParser:

    @staticmethod
    def parse_record(data):

        if len(data) < 5:

            return None

        record = TLSRecord()

        record.content_type = data[0]

        record.version = struct.unpack(
            "!H",
            data[1:3]
        )[0]

        record.length = struct.unpack(
            "!H",
            data[3:5]
        )[0]

        if len(data) < 5 + record.length:

            return None

        record.payload = data[5:5 + record.length]

        return record


    @staticmethod
    def parse_handshake(record):

        if len(record.payload) < 4:

            return None

        hs = TLSHandshake()

        hs.handshake_type = record.payload[0]

        hs.length = int.from_bytes(
            record.payload[1:4],
            "big"
        )

        if len(record.payload) < 4 + hs.length:

            return None

        hs.body = record.payload[4:4 + hs.length]

        return hs
        # ==========================================================
    # Parse ClientHello
    # ==========================================================

    @staticmethod
    def parse_client_hello(handshake):

        if handshake.handshake_type != CLIENT_HELLO:
            return None

        body = handshake.body

        offset = 0

        # --------------------------------------------
        # Client Version (2 bytes)
        # --------------------------------------------

        if len(body) < 2:
            return None

        version = struct.unpack(
            "!H",
            body[offset:offset + 2]
        )[0]

        offset += 2

        # --------------------------------------------
        # Random (32 bytes)
        # --------------------------------------------

        if len(body) < offset + 32:
            return None

        offset += 32

        # --------------------------------------------
        # Session ID
        # --------------------------------------------

        if len(body) < offset + 1:
            return None

        session_length = body[offset]

        offset += 1

        if len(body) < offset + session_length:
            return None

        offset += session_length

        # --------------------------------------------
        # Cipher Suites
        # --------------------------------------------

        if len(body) < offset + 2:
            return None

        cipher_length = struct.unpack(
            "!H",
            body[offset:offset + 2]
        )[0]

        offset += 2

        if len(body) < offset + cipher_length:
            return None

        offset += cipher_length

        # --------------------------------------------
        # Compression Methods
        # --------------------------------------------

        if len(body) < offset + 1:
            return None

        compression_length = body[offset]

        offset += 1

        if len(body) < offset + compression_length:
            return None

        offset += compression_length

        # --------------------------------------------
        # Extensions Length
        # --------------------------------------------

        if len(body) < offset + 2:
            return None

        extensions_length = struct.unpack(
            "!H",
            body[offset:offset + 2]
        )[0]

        offset += 2

        if len(body) < offset + extensions_length:
            return None

        return {

            "version": version,

            "extensions": body[offset:offset + extensions_length]

        }
        # ==========================================================
    # Parse TLS Extensions
    # ==========================================================

    @staticmethod
    def parse_extensions(client_hello):

        extensions = client_hello["extensions"]

        offset = 0

        while offset + 4 <= len(extensions):

            # Extension Header
            extension_type = struct.unpack(
                "!H",
                extensions[offset:offset + 2]
            )[0]

            extension_length = struct.unpack(
                "!H",
                extensions[offset + 2:offset + 4]
            )[0]

            offset += 4

            if offset + extension_length > len(extensions):
                break

            extension_data = extensions[
                offset:offset + extension_length
            ]

            # --------------------------------------------------
            # Server Name Indication (Extension Type = 0)
            # --------------------------------------------------

            if extension_type == 0:

                sni = TLSParser.parse_sni_extension(
                    extension_data
                )

                if sni:
                    return sni

            offset += extension_length

        return None
        # ==========================================================
    # Parse SNI Extension
    # ==========================================================

    @staticmethod
    def parse_sni_extension(data):

        """
        SNI Extension Format

        2 bytes  Server Name List Length

        1 byte   Name Type

        2 bytes  Hostname Length

        N bytes  Hostname
        """

        if len(data) < 5:
            return None

        offset = 0

        # Server Name List Length
        list_length = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        offset += 2

        if offset >= len(data):
            return None

        # Name Type (0 = hostname)
        name_type = data[offset]

        offset += 1

        if name_type != 0:
            return None

        if offset + 2 > len(data):
            return None

        hostname_length = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        offset += 2

        if offset + hostname_length > len(data):
            return None

        try:

            hostname = data[
                offset:offset + hostname_length
            ].decode("utf-8")

            return hostname

        except Exception:

            return None
        # ==========================================================
# Application Classifier
# ==========================================================

class ApplicationClassifier:

    DOMAIN_MAP = {

        # ==========================
        # Google
        # ==========================
        "google.com": AppType.GOOGLE,
        "google.co.in": AppType.GOOGLE,
        "googleapis.com": AppType.GOOGLE,
        "gstatic.com": AppType.GOOGLE,
        "googleusercontent.com": AppType.GOOGLE,
        "googlevideo.com": AppType.YOUTUBE,
        "clients6.google.com": AppType.GOOGLE,
        "youtube.com": AppType.YOUTUBE,
        "youtu.be": AppType.YOUTUBE,

        # ==========================
        # Microsoft
        # ==========================
        "microsoft.com": AppType.MICROSOFT,
        "windows.net": AppType.MICROSOFT,
        "office.com": AppType.MICROSOFT,
        "office365.com": AppType.MICROSOFT,
        "sharepoint.com": AppType.MICROSOFT,
        "live.com": AppType.MICROSOFT,
        "outlook.com": AppType.MICROSOFT,
        "bing.com": AppType.MICROSOFT,
        "msn.com": AppType.MICROSOFT,
        "azureedge.net": AppType.MICROSOFT,
        "microsoftonline.com": AppType.MICROSOFT,
        "windowsupdate.com": AppType.MICROSOFT,

        # ==========================
        # WhatsApp
        # ==========================
        "whatsapp.com": AppType.WHATSAPP,
        "web.whatsapp.com": AppType.WHATSAPP,
        "mmg.whatsapp.net": AppType.WHATSAPP,
        "static.whatsapp.net": AppType.WHATSAPP,

        # ==========================
        # Telegram
        # ==========================
        "telegram.org": AppType.TELEGRAM,
        "t.me": AppType.TELEGRAM,

        # ==========================
        # GitHub
        # ==========================
        "github.com": AppType.GITHUB,
        "githubusercontent.com": AppType.GITHUB,
        "githubassets.com": AppType.GITHUB,

        # ==========================
        # ChatGPT
        # ==========================
        "chatgpt.com": AppType.CHATGPT,
        "openai.com": AppType.CHATGPT,
        "oaistatic.com": AppType.CHATGPT,
        "oaiusercontent.com": AppType.CHATGPT,

        # ==========================
        # StackOverflow
        # ==========================
        "stackoverflow.com": AppType.STACKOVERFLOW,
        "stackexchange.com": AppType.STACKOVERFLOW,
        "sstatic.net": AppType.STACKOVERFLOW,

        # ==========================
        # Facebook
        # ==========================
        "facebook.com": AppType.FACEBOOK,
        "fbcdn.net": AppType.FACEBOOK,

        # ==========================
        # Instagram
        # ==========================
        "instagram.com": AppType.INSTAGRAM,
        "cdninstagram.com": AppType.INSTAGRAM,

        # ==========================
        # Discord
        # ==========================
        "discord.com": AppType.DISCORD,
        "discord.gg": AppType.DISCORD,
        "discordapp.com": AppType.DISCORD,

        # ==========================
        # Zoom
        # ==========================
        "zoom.us": AppType.ZOOM,
        "zoomgov.com": AppType.ZOOM,

        # ==========================
        # Netflix
        # ==========================
        "netflix.com": AppType.NETFLIX,
        "nflxvideo.net": AppType.NETFLIX,

        # ==========================
        # Amazon
        # ==========================
        "amazon.com": AppType.AMAZON,
        "amazonaws.com": AppType.AMAZON,

        # ==========================
        # AnyDesk
        # ==========================
        "anydesk.com": AppType.ANYDESK,
        "net.anydesk.com": AppType.ANYDESK,

        # ==========================
        # Cloudflare
        # ==========================
        "cloudflare.com": AppType.CLOUDFLARE,
        "cloudflare-dns.com": AppType.CLOUDFLARE,
    }

    @staticmethod
    @staticmethod
    def classify(hostname):

        if not hostname:
            return AppType.UNKNOWN

        hostname = hostname.lower().strip()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        for domain, app in ApplicationClassifier.DOMAIN_MAP.items():

            if hostname == domain:
                return app

            if hostname.endswith("." + domain):
                return app

        return AppType.UNKNOWN

    @staticmethod
    def classify_tls(payload):

        result = SNIResult()

        record = TLSParser.parse_record(payload)
        if record is None:
            return result

        if record.content_type != TLS_HANDSHAKE:
            return result

        handshake = TLSParser.parse_handshake(record)
        if handshake is None:
            return result

        if handshake.handshake_type != CLIENT_HELLO:
            return result

        client = TLSParser.parse_client_hello(handshake)
        if client is None:
            return result

        hostname = TLSParser.parse_extensions(client)
        if hostname is None:
            return result

        result.valid = True
        result.sni = hostname
        app = ApplicationClassifier.classify(hostname)
        if app is None:
            app = AppType.UNKNOWN
        result.application = app
        version = client["version"]

        versions = {
            0x0301: "TLS1.0",
            0x0302: "TLS1.1",
            0x0303: "TLS1.2",
            0x0304: "TLS1.3"
        }

        result.tls_version = versions.get(version, hex(version))

        result.handshake_length = handshake.length

        return result
    # ==========================================================
# Utility Functions
# ==========================================================

class TLSUtils:

    @staticmethod
    def is_tls_packet(payload: bytes) -> bool:
        """
        Check if payload appears to be a TLS record.
        """

        if len(payload) < 5:
            return False

        content_type = payload[0]

        return content_type in (
            TLS_HANDSHAKE,
            TLS_ALERT,
            TLS_APPLICATION_DATA,
            TLS_CHANGE_CIPHER_SPEC
        )

    @staticmethod
    def tls_version_string(version):

        versions = {

            0x0300: "SSL 3.0",

            0x0301: "TLS 1.0",

            0x0302: "TLS 1.1",

            0x0303: "TLS 1.2",

            0x0304: "TLS 1.3"

        }

        return versions.get(version, hex(version))

    @staticmethod
    def hex_dump(data: bytes, width=16):

        for i in range(0, len(data), width):

            chunk = data[i:i + width]

            hex_values = " ".join(f"{b:02X}" for b in chunk)

            ascii_values = "".join(

                chr(b) if 32 <= b <= 126 else "."

                for b in chunk

            )

            print(

                f"{i:04X}   "

                f"{hex_values:<48}"

                f"{ascii_values}"

            )

    @staticmethod
    def print_result(result):

        print("\n========== TLS Classification ==========")

        print("Valid          :", result.valid)

        print("TLS Version    :", result.tls_version)

        print("SNI            :", result.sni)

        print("Application    :", result.application)

        print("Handshake Size :", result.handshake_length)

        print("========================================\n")

    @staticmethod
    def print_record(record):

        print("\nTLS Record")

        print("-----------------------")

        print("Content Type :", record.content_type)

        print("Version      :", TLSUtils.tls_version_string(
            record.version
        ))

        print("Length       :", record.length)

    @staticmethod
    def print_handshake(handshake):

        print("\nHandshake")

        print("-----------------------")

        print("Type   :", handshake.handshake_type)

        print("Length :", handshake.length)
# ==========================================================
# Self Test
# ==========================================================

if __name__ == "__main__":

    from pcap_reader import PcapReader
    from packet_parser import PacketParser

    reader = PcapReader()

    if not reader.open("sample.pcapng"):
        print("Unable to open sample.pcapng")
        exit()

    packet_number = 0
    tls_packets = 0
    detected = 0

    while True:

        raw = reader.read_next_packet()

        if raw is None:
            break

        packet_number += 1

        parsed = PacketParser.parse(raw)

        if parsed is None:
            continue

        # We only care about TCP packets with payload
        if not PacketParser.is_tcp(parsed):
            continue

        if parsed.payload_length == 0:
            continue

        # Is it TLS?
        if not TLSUtils.is_tls_packet(parsed.payload_data):
            continue

        tls_packets += 1

        result = ApplicationClassifier.classify_tls(
            parsed.payload_data
        )

        if result.valid:

            detected += 1

            print("=" * 70)

            print(f"Packet #{packet_number}")

            print(
                f"{parsed.src_ip}:{parsed.src_port}"
            )

            print("   ↓")

            print(
                f"{parsed.dst_ip}:{parsed.dst_port}"
            )

            print()

            TLSUtils.print_result(result)

    print("\n=============================")

    print("Finished scanning PCAP")

    print("=============================")

    print(f"Packets Seen      : {packet_number}")

    print(f"TLS Packets       : {tls_packets}")

    print(f"SNI Detected      : {detected}")

    print("=============================")