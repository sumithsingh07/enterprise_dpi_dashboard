"""
ids_engine.py

Rule-based IDS Engine
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Rule:
    signature: bytes
    severity: str
    description: str


class IDSEngine:

    def __init__(self, socketio=None, database=None):

        self.rules = []
        self.alerts = 0

        self.socketio = socketio
        self.database = database

        self.load_rules()

    # =====================================================
    # LOAD RULES
    # =====================================================

    def load_rules(self):

        filename = Path("rules/signatures.rules")

        if not filename.exists():

            print("[IDS] Rule file not found.")
            return

        with open(filename, "r", encoding="utf-8") as f:

            for line in f:

                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                parts = line.split("|")

                if len(parts) != 3:
                    continue

                signature = parts[0].strip()
                severity = parts[1].strip()
                description = parts[2].strip()

                self.rules.append(
                    Rule(
                        signature.encode(),
                        severity,
                        description
                    )
                )

        print(f"[IDS] Loaded {len(self.rules)} rules.")

    # =====================================================
    # INSPECT PACKET
    # =====================================================

    def inspect(
        self,
        payload,
        src_ip="Unknown",
        dst_ip="Unknown",
        protocol="Unknown"
    ):

        if not payload:
            return

        if isinstance(payload, str):
            payload = payload.encode()

        payload_lower = payload.lower()

        for rule in self.rules:

            signature_lower = rule.signature.lower()

            if signature_lower in payload_lower:

                self.alerts += 1

                signature_text = rule.signature.decode(
                    errors="ignore"
                )

                print()
                print("=" * 60)
                print("IDS ALERT")
                print("=" * 60)
                print("Source      :", src_ip)
                print("Destination :", dst_ip)
                print("Protocol    :", protocol)
                print("Severity    :", rule.severity)
                print("Signature   :", signature_text)
                print("Description :", rule.description)
                print("=" * 60)

                # -----------------------------------------
                # DATABASE
                # -----------------------------------------

                if self.database:

                    self.database.log_alert(
                        rule.severity,
                        signature_text,
                        src_ip,
                        dst_ip,
                        rule.description
                    )

                # -----------------------------------------
                # SOCKET.IO
                # -----------------------------------------

                if self.socketio:

                    self.socketio.emit(
                        "new_alert",
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": protocol,
                            "signature": signature_text,
                            "severity": rule.severity,
                            "description": rule.description
                        }
                    )

    # =====================================================
    # STATISTICS
    # =====================================================

    def print_statistics(self):

        print()
        print("========== IDS ==========")
        print("Rules Loaded :", len(self.rules))
        print("Alerts       :", self.alerts)
        print("=========================")