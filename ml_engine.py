"""
ml_engine.py

Machine Learning Anomaly Detection Engine
"""

import pandas as pd
from sklearn.ensemble import IsolationForest


class MLEngine:

    def __init__(self, database):

        self.database = database

        self.model = IsolationForest(
            contamination=0.05,
            random_state=42
        )

        self.trained = False

    # =====================================================
    # TRAIN MODEL
    # =====================================================

    def train(self):

        try:

            rows = self.database.get_flows(limit=100000)

            if not rows:
                print("[ML] No flow data available.")
                return False

            data = []

            for row in rows:

                data.append({
                    "packet_size": row["packet_size"]
                    if "packet_size" in row.keys() else 0,

                    "src_port": row["src_port"]
                    if "src_port" in row.keys() else 0,

                    "dst_port": row["dst_port"]
                    if "dst_port" in row.keys() else 0
                })

            df = pd.DataFrame(data)

            if len(df) < 20:

                print(
                    f"[ML] Not enough data for training: {len(df)}"
                )

                return False

            df = df.fillna(0)

            self.model.fit(
                df[
                    [
                        "packet_size",
                        "src_port",
                        "dst_port"
                    ]
                ]
            )

            self.trained = True

            print(
                f"[ML] Model trained using {len(df)} flows."
            )

            return True

        except Exception as e:

            print("[ML] Training error:", e)

            return False

    # =====================================================
    # DETECT ANOMALIES
    # =====================================================

    def detect(self):

        if not self.trained:

            print("[ML] Model is not trained.")

            return 0

        try:

            rows = self.database.get_flows(limit=100000)

            if not rows:
                return 0

            data = []

            ids = []

            for row in rows:

                ids.append(row["id"])

                data.append({

                    "packet_size":
                        row["packet_size"]
                        if "packet_size" in row.keys()
                        else 0,

                    "src_port":
                        row["src_port"]
                        if "src_port" in row.keys()
                        else 0,

                    "dst_port":
                        row["dst_port"]
                        if "dst_port" in row.keys()
                        else 0
                })

            df = pd.DataFrame(data)

            if len(df) < 20:
                return 0

            df = df.fillna(0)

            prediction = self.model.predict(
                df[
                    [
                        "packet_size",
                        "src_port",
                        "dst_port"
                    ]
                ]
            )

            anomaly_count = 0

            # -------------------------------------------------
            # IMPORTANT:
            # Use the DatabaseLogger connection instead of
            # sqlite3.connect()
            # -------------------------------------------------

            with self.database.lock:

                for flow_id, result in zip(ids, prediction):

                    anomaly = 1 if result == -1 else 0

                    if anomaly:
                        anomaly_count += 1

                    try:

                        self.database.cursor.execute(
                            """
                            UPDATE flows
                            SET anomaly=?
                            WHERE id=?
                            """,
                            (
                                anomaly,
                                flow_id
                            )
                        )

                    except Exception as e:

                        # If old database does not have
                        # anomaly column, don't crash the DPI.
                        print(
                            "[ML] Could not update anomaly:",
                            e
                        )

                self.database.conn.commit()

            print(
                f"[ML] Anomalies detected: {anomaly_count}"
            )

            return anomaly_count

        except Exception as e:

            print("[ML] Detection error:", e)

            return 0