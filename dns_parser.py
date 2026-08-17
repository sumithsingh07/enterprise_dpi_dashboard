"""
dns_parser.py

Manual DNS Packet Parser

Equivalent to:
    dns_parser.h
    dns_parser.cpp
"""

import struct
from dataclasses import dataclass


# ==========================================================
# DNS Header
# ==========================================================

@dataclass
class DNSHeader:

    transaction_id: int = 0

    flags: int = 0

    questions: int = 0

    answers: int = 0

    authorities: int = 0

    additionals: int = 0


# ==========================================================
# DNS Question
# ==========================================================

@dataclass
class DNSQuestion:

    name: str = ""

    qtype: int = 0

    qclass: int = 0


# ==========================================================
# DNS Packet
# ==========================================================

@dataclass
class DNSPacket:

    header: DNSHeader = None

    questions: list = None

    answers: list = None
class DNSParser:

    DNS_PORT = 53

    TYPE_A = 1
    TYPE_AAAA = 28
    TYPE_CNAME = 5

    CLASS_IN = 1
    @staticmethod
    def parse_header(data):

        if len(data) < 12:
            return None

        values = struct.unpack(
            "!HHHHHH",
            data[:12]
        )

        return DNSHeader(

            transaction_id=values[0],

            flags=values[1],

            questions=values[2],

            answers=values[3],

            authorities=values[4],

            additionals=values[5]

        )
    @staticmethod
    def read_name(data, offset):

        labels = []

        while True:

            if offset >= len(data):
                break

            length = data[offset]

            offset += 1

            if length == 0:
                break

            label = data[
                offset:offset + length
            ].decode(
                "utf-8",
                errors="ignore"
            )

            labels.append(label)

            offset += length

        return ".".join(labels), offset
        # ------------------------------------------------------
    # Parse Question
    # ------------------------------------------------------

    @staticmethod
    def parse_question(data, offset):

        name, offset = DNSParser.read_name(data, offset)

        if offset + 4 > len(data):
            return None, offset

        qtype, qclass = struct.unpack(
            "!HH",
            data[offset:offset + 4]
        )

        offset += 4

        question = DNSQuestion(
            name=name,
            qtype=qtype,
            qclass=qclass
        )

        return question, offset
        # ------------------------------------------------------
    # Parse DNS Packet
    # ------------------------------------------------------

    @staticmethod
    def parse(data):

        header = DNSParser.parse_header(data)

        if header is None:
            return None

        packet = DNSPacket()

        packet.header = header
        packet.questions = []
        packet.answers = []

        offset = 12

        # -----------------------------
        # Questions
        # -----------------------------

        for _ in range(header.questions):

            question, offset = DNSParser.parse_question(
                data,
                offset
            )

            if question is None:
                break

            packet.questions.append(question)

        return packet
        # ------------------------------------------------------
    # Print DNS Packet
    # ------------------------------------------------------

    @staticmethod
    def print_packet(packet):

        print("\n========== DNS ==========")

        print(
            "Transaction ID :",
            hex(packet.header.transaction_id)
        )

        print(
            "Questions      :",
            packet.header.questions
        )

        print(
            "Answers        :",
            packet.header.answers
        )

        print("-------------------------")

        for q in packet.questions:

            print("Name  :", q.name)

            print("Type  :", q.qtype)

            print("Class :", q.qclass)

            print()

        print("=========================\n")
        # ------------------------------------------------------
    # Is DNS Packet
    # ------------------------------------------------------

    @staticmethod
    def is_dns(packet):

        return (

            packet.protocol == 17 and

            (

                packet.src_port == 53 or

                packet.dst_port == 53

            )

        )
    # ------------------------------------------------------
    # Get First Queried Domain
    # ------------------------------------------------------

    @staticmethod
    def get_domain(packet):

        dns = DNSParser.parse(packet)

        if dns is None:
            return ""

        if len(dns.questions) == 0:
            return ""

        return dns.questions[0].name
from dpi_types import AppType


class DNSClassifier:

    DOMAIN_MAP = {

    # Google
    "google.com": AppType.GOOGLE,
    "gmail.com": AppType.GOOGLE,

    # Microsoft
    "microsoft.com": AppType.MICROSOFT,
    "microsoftonline.com": AppType.MICROSOFT,
    "live.com": AppType.MICROSOFT,
    "office.com": AppType.MICROSOFT,
    "office365.com": AppType.MICROSOFT,
    "outlook.com": AppType.MICROSOFT,
    "teams.microsoft.com": AppType.MICROSOFT,
    "windows.net": AppType.MICROSOFT,
    "sharepoint.com": AppType.MICROSOFT,

    # GitHub
    "github.com": AppType.GITHUB,

    # AnyDesk
    "anydesk.com": AppType.ANYDESK,
    "net.anydesk.com": AppType.ANYDESK,

    # YouTube
    "youtube.com": AppType.YOUTUBE,
    "googlevideo.com": AppType.YOUTUBE,
    "youtu.be": AppType.YOUTUBE,

    # Facebook
    "facebook.com": AppType.FACEBOOK,

    # Instagram
    "instagram.com": AppType.INSTAGRAM,

    # Netflix
    "netflix.com": AppType.NETFLIX,

    # Amazon
    "amazon.com": AppType.AMAZON,

    # Zoom
    "zoom.us": AppType.ZOOM,

    # Discord
    "discord.com": AppType.DISCORD,

    # WhatsApp
    "whatsapp.net": AppType.WHATSAPP,

    # Telegram
    "telegram.org": AppType.TELEGRAM,

    # TikTok
    "tiktok.com": AppType.TIKTOK,
}

    @staticmethod
    def classify(domain):

        domain = domain.lower()

        for suffix, app in DNSClassifier.DOMAIN_MAP.items():

            if domain.endswith(suffix):
                return app

        return AppType.UNKNOWN