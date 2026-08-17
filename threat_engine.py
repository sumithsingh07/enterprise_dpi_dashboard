"""
threat_engine.py

Threat Risk Analysis Engine
"""


class ThreatEngine:

    def __init__(self, database):

        self.database = database

    # =====================================================
    # ANALYZE FLOWS
    # =====================================================

    def analyze(self):

        try:

            rows = self.database.get_flows(limit=100000)

            if not rows:

                print("[THREAT] No flows available.")

                return 0

            updated = 0

            with self.database.lock:

                for flow in rows:

                    score = 0

                    # -----------------------------------------
                    # Reputation
                    # -----------------------------------------

                    reputation = (
                        flow["reputation"]
                        if "reputation" in flow.keys()
                        else ""
                    )

                    if reputation:

                        if str(reputation).lower() == "malicious":
                            score += 50

                    # -----------------------------------------
                    # Protocol
                    # -----------------------------------------

                    protocol = (
                        flow["protocol"]
                        if "protocol" in flow.keys()
                        else ""
                    )

                    if str(protocol).upper() == "TLS":
                        score += 10

                    # -----------------------------------------
                    # Application
                    # -----------------------------------------

                    application = (
                        flow["application"]
                        if "application" in flow.keys()
                        else ""
                    )

                    if (
                        not application
                        or str(application).upper()
                        in ("UNKNOWN", "UNKN", "NONE")
                    ):
                        score += 10

                    # -----------------------------------------
                    # Destination Port
                    # -----------------------------------------

                    dst_port = (
                        flow["dst_port"]
                        if "dst_port" in flow.keys()
                        else 0
                    )

                    try:
                        dst_port = int(dst_port)
                    except (TypeError, ValueError):
                        dst_port = 0

                    if dst_port in (22, 23, 3389):
                        score += 20

                    # -----------------------------------------
                    # Maximum Risk
                    # -----------------------------------------

                    score = min(score, 100)

                    # -----------------------------------------
                    # Update Database
                    # -----------------------------------------

                    self.database.cursor.execute(
                        """
                        UPDATE flows
                        SET risk_score=?
                        WHERE id=?
                        """,
                        (
                            score,
                            flow["id"]
                        )
                    )

                    updated += 1

                self.database.conn.commit()

            print(
                f"[THREAT] Risk analysis completed for {updated} flows."
            )

            return updated

        except Exception as e:

            print("[THREAT] Analysis error:", e)

            return 0