from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
from ipaddress import IPv4Address
from enum import Enum, auto


# ============================================================
# FiveTuple
# ============================================================

@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self):
        return FiveTuple(
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
            self.protocol,
        )

    def ip_to_string(self, ip):
        return str(IPv4Address(ip))

    def __str__(self):
        proto = {
            6: "TCP",
            17: "UDP"
        }.get(self.protocol, "UNKNOWN")

        return (
            f"{self.ip_to_string(self.src_ip)}:{self.src_port}"
            f" -> "
            f"{self.ip_to_string(self.dst_ip)}:{self.dst_port}"
            f" ({proto})"
        )


# ============================================================
# Application Types
# ============================================================

class AppType(Enum):

    UNKNOWN = 0

    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5

    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    ANYDESK = 23
    CHATGPT = auto()
    STACKOVERFLOW = auto()
class ProtocolType(Enum):

    UNKNOWN = auto()

    HTTP = auto()

    HTTPS = auto()

    TLS = auto()

    DNS = auto()

    SSH = auto()

    FTP = auto()

    SMTP = auto()

    POP3 = auto()

    IMAP = auto()

    MQTT = auto()

    QUIC = auto()


# ============================================================
# Connection State
# ============================================================

class ConnectionState(Enum):

    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4


# ============================================================
# Packet Action
# ============================================================

class PacketAction(Enum):

    FORWARD = 0
    DROP = 1
    INSPECT = 2
    LOG_ONLY = 3


# ============================================================
# Connection
# ============================================================

@dataclass
class Connection:

    tuple: FiveTuple

    state: ConnectionState = ConnectionState.NEW

    app_type: AppType = AppType.UNKNOWN

    sni: str = ""

    packets_in: int = 0
    packets_out: int = 0

    bytes_in: int = 0
    bytes_out: int = 0

    first_seen: datetime = field(default_factory=datetime.now)

    last_seen: datetime = field(default_factory=datetime.now)

    action: PacketAction = PacketAction.FORWARD

    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


# ============================================================
# Packet Job
# ============================================================

@dataclass
class PacketJob:

    packet_id: int

    tuple: FiveTuple

    data: bytes

    eth_offset: int = 0

    ip_offset: int = 0

    transport_offset: int = 0

    payload_offset: int = 0

    payload_length: int = 0

    tcp_flags: int = 0

    payload_data: bytes = b''

    ts_sec: int = 0

    ts_usec: int = 0


# ============================================================
# Statistics
# ============================================================

@dataclass
class DPIStats:

    total_packets: int = 0
    total_bytes: int = 0

    forwarded_packets: int = 0
    dropped_packets: int = 0

    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0

    active_connections: int = 0


# ============================================================
# Helper Functions
# ============================================================

def app_type_to_string(app_type: AppType) -> str:
    return app_type.name.title()


# ============================================================
# SNI to Application
# ============================================================

def sni_to_app_type(sni: str) -> AppType:

    if not sni:
        return AppType.UNKNOWN

    sni = sni.lower()

    if any(x in sni for x in [
        "youtube",
        "youtu.be",
        "ytimg",
        "yt3.ggpht"
    ]):
        return AppType.YOUTUBE

    if any(x in sni for x in [
        "google",
        "gstatic",
        "googleapis",
        "ggpht",
        "gvt1"
    ]):
        return AppType.GOOGLE

    if any(x in sni for x in [
        "facebook",
        "fbcdn",
        "fb.com",
        "meta.com",
        "fbsbx"
    ]):
        return AppType.FACEBOOK

    if "instagram" in sni or "cdninstagram" in sni:
        return AppType.INSTAGRAM

    if "whatsapp" in sni or "wa.me" in sni:
        return AppType.WHATSAPP

    if any(x in sni for x in [
        "twitter",
        "twimg",
        "x.com",
        "t.co"
    ]):
        return AppType.TWITTER

    if any(x in sni for x in [
        "netflix",
        "nflxvideo",
        "nflximg"
    ]):
        return AppType.NETFLIX

    if any(x in sni for x in [
        "amazon",
        "amazonaws",
        "cloudfront",
        "aws"
    ]):
        return AppType.AMAZON

    if any(x in sni for x in [
        "microsoft",
        "microsoftonline",
        "office",
        "office365",
        "outlook",
        "live.com",
        "teams.microsoft",
        "sharepoint",
        "windows.net",
        "azure",
        "bing"
    ]):
        return AppType.MICROSOFT

    if any(x in sni for x in [
        "apple",
        "icloud",
        "itunes",
        "mzstatic"
    ]):
        return AppType.APPLE

    if "telegram" in sni or "t.me" in sni:
        return AppType.TELEGRAM

    if any(x in sni for x in [
        "tiktok",
        "musical.ly",
        "bytedance",
        "tiktokcdn"
    ]):
        return AppType.TIKTOK

    if "spotify" in sni or "scdn.co" in sni:
        return AppType.SPOTIFY

    if "zoom" in sni:
        return AppType.ZOOM

    if "discord" in sni or "discordapp" in sni:
        return AppType.DISCORD

    if "github" in sni or "githubusercontent" in sni:
        return AppType.GITHUB

    if "cloudflare" in sni or "cf-" in sni:
        return AppType.CLOUDFLARE

    return AppType.UNKNOWN