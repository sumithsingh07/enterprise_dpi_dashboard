"""
dpi_engine.py

Main Deep Packet Inspection Engine

Packet
   ↓
Parser
   ↓
Connection Tracker
   ↓
TLS / DNS / HTTP Detection
   ↓
Application Classification
   ↓
JA3 / JA4
   ↓
IDS / Malware / Reputation
   ↓
GeoIP
   ↓
Rule Manager
   ↓
Database
"""

from django.db import connection

from dpi_types import AppType, ProtocolType
from pcap_reader import PcapReader
from packet_parser import PacketParser
from connection_tracker import ConnectionTracker
from sni_extractor import ApplicationClassifier
from rule_manager import RuleManager, PacketAction
from http_parser import HTTPParser, HTTPRequest, HTTPResponse
from dns_parser import DNSParser, DNSClassifier
from statistics import DPIStatistics
from ja3_database import JA3Database
from ja3 import JA3Parser
from protocol_detector import ProtocolDetector
from tcp_analyzer import TCPAnalyzer
from tcp_order import TCPOrderAnalyzer
from http_extractor import HTTPFileExtractor
from malware_detector import MalwareDetector
from ids_engine import IDSEngine
from flow_manager import FlowManager
from geoip import GeoIP
from ip_reputation import IPReputation
from database_logger import DatabaseLogger
from ja4 import JA4Parser
from bandwidth_monitor import BandwidthMonitor
from ml_engine import MLEngine
from threat_engine import ThreatEngine


class DPIEngine:

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self, socketio=None):

        self.socketio = socketio

        # PCAP
        self.reader = PcapReader()

        # GeoIP
        self.geoip = GeoIP()

        # Database
        self.database = DatabaseLogger()

        # Reputation
        self.reputation = IPReputation()

        # TCP
        self.tcp = TCPAnalyzer()
        self.order = TCPOrderAnalyzer()

        # Bandwidth
        self.bandwidth = BandwidthMonitor()

        # HTTP file extraction
        self.extractor = HTTPFileExtractor()

        # Connections
        self.connections = ConnectionTracker()

        # IDS
        self.ids = IDSEngine(
            socketio=socketio,
            database=self.database
        )

        # Machine Learning
        self.ml = MLEngine(self.database)

        # Threat analysis
        self.threat = ThreatEngine(self.database)

        # Rules
        self.rules = RuleManager()

        # Statistics
        self.stats = DPIStatistics()

        # Flow
        self.flow = FlowManager()

        # Counters
        self.packet_counter = 0
        self.allowed = 0
        self.blocked = 0
        self.logged = 0
        self.unknown = 0

        print("[DPI] Engine initialized.")

    # =====================================================
    # DEFAULT RULES
    # =====================================================

    def install_default_rules(self):

        default_rules = [

            ("YOUTUBE", PacketAction.DROP),
            ("FACEBOOK", PacketAction.DROP),
            ("INSTAGRAM", PacketAction.DROP),
            ("NETFLIX", PacketAction.LOG_ONLY),

            ("GOOGLE", PacketAction.FORWARD),
            ("MICROSOFT", PacketAction.FORWARD),
            ("GITHUB", PacketAction.FORWARD),

            ("ANYDESK", PacketAction.FORWARD),
            ("ZOOM", PacketAction.FORWARD),
            ("TEAMS", PacketAction.FORWARD),

            ("WHATSAPP", PacketAction.FORWARD),
            ("TELEGRAM", PacketAction.LOG_ONLY),

            ("DROPBOX", PacketAction.LOG_ONLY),
            ("ONEDRIVE", PacketAction.LOG_ONLY),

            ("AMAZON", PacketAction.FORWARD),
            ("AWS", PacketAction.FORWARD)
        ]

        for app_name, rule_action in default_rules:

            try:

                self.rules.add_rule(
                    app_name,
                    rule_action
                )

            except Exception as e:

                print(
                    f"[DPI] Rule error for "
                    f"{app_name}: {e}"
                )

        print(
            f"[DPI] Default rules loaded: "
            f"{len(default_rules)}"
        )

    # =====================================================
    # OPEN PCAP
    # =====================================================

    def open(self, filename):

        try:

            result = self.reader.open(filename)

            if result:

                print(
                    f"[DPI] PCAP opened: {filename}"
                )

            else:

                print(
                    f"[DPI] Unable to open: {filename}"
                )

            return result

        except Exception as e:

            print(
                f"[DPI] PCAP open error: {e}"
            )

            return False

    # =====================================================
    # ANALYZE PCAP
    # =====================================================

    def analyze_pcap(self, filename):

        print()
        print("=" * 70)
        print("              PCAP ANALYSIS STARTED")
        print("=" * 70)
        print(f"File: {filename}")
        print()

        try:

            if not self.open(filename):

                print(
                    "[DPI] Failed to open PCAP."
                )

                return False

            # Make sure rules exist
            self.install_default_rules()

            # Process packets
            self.run()

            # Print summary
            self.print_statistics()

            return True

        except Exception as e:

            print(
                f"[DPI] PCAP analysis error: {e}"
            )

            return False

        finally:

            self.close()

    # =====================================================
    # RUN ENGINE
    # =====================================================

    def run(self):

        print()
        print("=" * 70)
        print("              DPI ENGINE STARTED")
        print("=" * 70)

        while True:

            try:

                raw_packet = (
                    self.reader.read_next_packet()
                )

            except Exception as e:

                print(
                    f"[DPI] Packet read error: {e}"
                )

                break

            if raw_packet is None:
                break

            self.packet_counter += 1

            try:

                self.process_packet(raw_packet)

            except Exception as e:

                print(
                    f"[DPI] Packet "
                    f"{self.packet_counter} "
                    f"error: {e}"
                )

        print()
        print("=" * 70)
        print("              DPI ENGINE FINISHED")
        print("=" * 70)

        # -------------------------------------------------
        # Machine Learning
        # -------------------------------------------------

        try:

            trained = self.ml.train()

            if trained:
                self.ml.detect()

        except Exception as e:

            print(
                f"[ML] Analysis error: {e}"
            )

        # -------------------------------------------------
        # Threat Analysis
        # -------------------------------------------------

        print("=" * 70)
        print("              THREAT ANALYSIS STARTED")
        print("=" * 70)

        try:

            self.threat.analyze()

        except Exception as e:

            print(
                f"[Threat] Analysis error: {e}"
            )

        print("=" * 70)

    # =====================================================
    # PROCESS PACKET
    # =====================================================

    def process_packet(self, raw_packet):

        # -------------------------------------------------
        # Parse packet
        # -------------------------------------------------

        packet = PacketParser.parse(raw_packet)

        if packet is None:
            return

        if packet.payload_length == 0:
            return

        # -------------------------------------------------
        # Connection tracking
        # -------------------------------------------------

        connection = (
            self.connections.process_packet(packet)
        )

        # -------------------------------------------------
        # TCP analysis
        #
        # IMPORTANT:
        # These analyzers still calculate statistics.
        # Their individual console messages are disabled
        # inside tcp_analyzer.py and tcp_order.py.
        # -------------------------------------------------

        if packet.has_tcp:

            try:

                self.tcp.analyze(
                    connection,
                    packet
                )

                self.order.analyze(
                    connection,
                    packet
                )

            except Exception as e:

                print(
                    f"[TCP] Analysis error: {e}"
                )

        # -------------------------------------------------
        # Payload
        # -------------------------------------------------

        payload = packet.payload_data

        if packet.has_tcp:

            try:

                stream = (
                    self.connections
                    .get_stream_data(connection)
                )

                if stream:
                    payload = stream

            except Exception:

                payload = packet.payload_data

        if not payload:
            return

        # -------------------------------------------------
        # Protocol detection
        # -------------------------------------------------

        protocol = ProtocolDetector.detect(
            payload
        )

        packet.detected_protocol = protocol

        # -------------------------------------------------
        # IDS
        # -------------------------------------------------

        try:

            self.ids.inspect(
                payload,
                packet.src_ip,
                packet.dst_ip,
                protocol.name
            )

        except TypeError:

            try:

                self.ids.inspect(
                    payload
                )

            except Exception as e:

                print(
                    f"[IDS] Inspection error: {e}"
                )

        except Exception as e:

            print(
                f"[IDS] Inspection error: {e}"
            )

        # -------------------------------------------------
        # Malware Detection
        # -------------------------------------------------

        try:

            alert = MalwareDetector.scan(
                payload
            )

            if alert and alert.detected:

                MalwareDetector.print_alert(
                    alert
                )

                self.database.log_alert(
                    "HIGH",
                    "Malware",
                    packet.src_ip,
                    packet.dst_ip,
                    alert.name
                )

        except Exception as e:

            print(
                f"[Malware] Error: {e}"
            )

        # -------------------------------------------------
        # Initial values
        # -------------------------------------------------

        app = AppType.UNKNOWN

        domain = ""

        ja3 = ""

        ja4 = ""

        # IMPORTANT:
        # Prevent undefined-variable errors if TLS
        # ClientHello parsing fails.
        client_hello = None

        # -------------------------------------------------
        # Existing application
        # -------------------------------------------------

        try:

            if (
                connection.app_type
                != AppType.UNKNOWN
            ):

                app = connection.app_type

        except Exception:

            app = AppType.UNKNOWN

        # =================================================
        # HTTP
        # =================================================

        if protocol == ProtocolType.HTTP:

            try:

                http = HTTPParser.parse(
                    payload
                )

                if http:

                    if isinstance(
                        http,
                        HTTPRequest
                    ):

                        if http.host:

                            domain = http.host

                            app = (
                                ApplicationClassifier
                                .classify(domain)
                            )

                            connection.sni = domain

                            connection.app_type = app

                            connection.application = app

                    elif isinstance(
                        http,
                        HTTPResponse
                    ):

                        self.extractor.save(
                            http
                        )

            except Exception as e:

                print(
                    f"[HTTP] Error: {e}"
                )

        # =================================================
        # TLS
        # =================================================

        elif protocol == ProtocolType.TLS:

            # -------------------------------------------------
            # TLS application classification
            # -------------------------------------------------

            try:

                tls = (
                    ApplicationClassifier
                    .classify_tls(payload)
                )

                if tls.valid:

                    domain = tls.sni

                    app = tls.application

                    connection.sni = domain

                    connection.app_type = app

                    connection.application = app

            except Exception as e:

                print(
                    f"[TLS] Error: {e}"
                )

            # -------------------------------------------------
            # JA3 ClientHello parsing
            # -------------------------------------------------

            try:

                client_hello = (
                    JA3Parser
                    .parse_client_hello(payload)
                )

            except Exception:

                client_hello = None

            # -------------------------------------------------
            # JA3
            # -------------------------------------------------

            if client_hello:

                try:

                    ja3_result = (
                        JA3Parser
                        .fingerprint(
                            client_hello
                        )
                    )

                    if (
                        ja3_result
                        and ja3_result.valid
                    ):

                        ja3 = (
                            ja3_result.ja3_hash
                        )

                        connection.ja3 = ja3

                        detected = (
                            JA3Database.lookup(
                                ja3
                            )
                        )

                        if (
                            detected
                            != AppType.UNKNOWN
                        ):

                            connection.app_type = (
                                detected
                            )

                            connection.application = (
                                detected
                            )

                except Exception as e:

                    print(
                        f"[JA3] Error: {e}"
                    )

                # -------------------------------------------------
                # JA4
                #
                # Calculate only once per connection.
                # -------------------------------------------------

                try:

                    existing_ja4 = getattr(
                        connection,
                        "ja4",
                        ""
                    )

                    if not existing_ja4:

                        ja4_result = (
                            JA4Parser.fingerprint(
                                client_hello
                            )
                        )

                        if (
                            ja4_result
                            and getattr(
                                ja4_result,
                                "valid",
                                False
                            )
                        ):

                            ja4 = (
                                ja4_result.ja4
                            )

                            connection.ja4 = ja4

                            # Keep JA4 output concise.
                            print(
                                "\n========== JA4 =========="
                            )

                            print(
                                "JA4 :",
                                connection.ja4
                            )

                except Exception as e:

                    # Do not stop PCAP processing
                    # because of JA4.
                    print(
                        f"[JA4] Fingerprint error: {e}"
                    )

        # =================================================
        # DNS
        # =================================================

        elif protocol == ProtocolType.DNS:

            try:

                dns = DNSParser.parse(
                    payload
                )

                if dns and dns.questions:

                    domain = (
                        dns.questions[0].name
                    )

                    app = (
                        DNSClassifier
                        .classify(domain)
                    )

                    connection.sni = domain

                    connection.app_type = app

                    connection.application = app

            except Exception as e:

                print(
                    f"[DNS] Error: {e}"
                )

        # =================================================
        # Final Application
        # =================================================

        if (
            connection.app_type
            == AppType.UNKNOWN
        ):

            connection.app_type = app

        # =================================================
        # Rule Manager
        # =================================================

        try:

            action = (
                self.rules
                .get_action(
                    connection.app_type
                )
            )

        except Exception as e:

            print(
                f"[Rules] Error: {e}"
            )

            action = PacketAction.FORWARD

        connection.action = action

        # =================================================
        # Counters
        # =================================================

        if action == PacketAction.FORWARD:

            self.allowed += 1

        elif action == PacketAction.DROP:

            self.blocked += 1

        elif action == PacketAction.LOG_ONLY:

            self.logged += 1

        else:

            self.unknown += 1

        # =================================================
        # Statistics
        # =================================================

        try:

            self.stats.update(
                packet,
                connection,
                domain
            )

        except Exception as e:

            print(
                f"[Statistics] Error: {e}"
            )

        # =================================================
        # Bandwidth
        # =================================================

        try:

            self.bandwidth.update(
                packet
            )

        except Exception:

            pass

        # =================================================
        # Flow
        # =================================================

        try:

            self.flow.update(
                connection,
                packet
            )

        except Exception as e:

            print(
                f"[Flow] Error: {e}"
            )

        # =================================================
        # GeoIP
        # =================================================

        geo = {}

        try:

            geo = self.geoip.lookup(
                packet.src_ip
            )

            if geo is None:
                geo = {}

        except Exception as e:

            print(
                f"[GeoIP] Error: {e}"
            )

            geo = {}

        # =================================================
        # IP Reputation
        # =================================================

        try:

            rep = self.reputation.lookup(
                packet.dst_ip
            )

        except Exception as e:

            print(
                f"[Reputation] Error: {e}"
            )

            rep = None

        # =================================================
        # Database Logging
        # =================================================

        try:

            self.database.log_flow(
                packet,
                connection,
                geo,
                rep
            )

        except Exception as e:

            print(
                f"[Database] Flow error: {e}"
            )

        # =================================================
        # Malicious IP
        # =================================================

        try:

            if rep and rep.malicious:

                self.database.log_alert(
                    "MEDIUM",
                    "Malicious IP",
                    packet.src_ip,
                    packet.dst_ip,
                    rep.category
                )

        except Exception as e:

            print(
                f"[Alert] Error: {e}"
            )

        # =================================================
        # Live Socket.IO Update
        # =================================================

        if self.socketio:

            try:

                self.socketio.emit(
                    "new_packet",
                    {
                        "src_ip":
                            packet.src_ip,

                        "dst_ip":
                            packet.dst_ip,

                        "protocol":
                            protocol.name,

                        "application":
                            connection
                            .app_type
                            .name,

                        "country":
                            geo.get(
                                "country",
                                "Unknown"
                            ),

                        "city":
                            geo.get(
                                "city",
                                "Unknown"
                            ),

                        "action":
                            action.value
                    }
                )

            except Exception as e:

                print(
                    f"[SocketIO] Error: {e}"
                )

        # =================================================
        # Cleanup
        # =================================================

        try:

            self.connections.remove_closed()

        except Exception:

            pass

    # =====================================================
    # PRINT STATISTICS
    # =====================================================

    def print_statistics(self):

        print()

        print("=" * 70)

        print(
            "                 DPI ENGINE SUMMARY"
        )

        print("=" * 70)

        print(
            f"Total Packets       : "
            f"{self.packet_counter}"
        )

        print(
            f"Allowed Packets     : "
            f"{self.allowed}"
        )

        print(
            f"Blocked Packets     : "
            f"{self.blocked}"
        )

        print(
            f"Logged Packets      : "
            f"{self.logged}"
        )

        print(
            f"Unknown Packets     : "
            f"{self.unknown}"
        )

        try:

            print(
                "Active Connections  :",
                self.connections
                .connection_count()
            )

        except Exception:

            pass

        print("=" * 70)

        # -------------------------------------------------
        # General DPI statistics
        # -------------------------------------------------

        try:

            self.stats.print_report()

        except Exception:

            pass

        # -------------------------------------------------
        # TCP statistics
        # -------------------------------------------------

        try:

            self.tcp.print_statistics()

        except Exception:

            pass

        # -------------------------------------------------
        # TCP order statistics
        # -------------------------------------------------

        try:

            self.order.print_statistics()

        except Exception:

            pass

        # -------------------------------------------------
        # HTTP extraction statistics
        # -------------------------------------------------

        try:

            self.extractor.print_statistics()

        except Exception:

            pass

        # -------------------------------------------------
        # IDS statistics
        # -------------------------------------------------

        try:

            self.ids.print_statistics()

        except Exception:

            pass

        # -------------------------------------------------
        # Flow statistics
        # -------------------------------------------------

        try:

            self.flow.print_statistics()

        except Exception:

            pass

        print("=" * 70)

    # =====================================================
    # CLOSE
    # =====================================================

    def close(self):

        try:

            self.reader.close()

        except Exception:

            pass

        try:

            self.geoip.close()

        except Exception:

            pass

        try:

            self.database.close()

        except Exception:

            pass

        print(
            "\n[DPI] Resources closed successfully."
        )


# =========================================================
# TEST MODE
# =========================================================

if __name__ == "__main__":

    engine = DPIEngine()

    engine.install_default_rules()

    engine.analyze_pcap(
        "sample.pcapng"
    )