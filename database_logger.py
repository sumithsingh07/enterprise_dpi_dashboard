"""
database_logger.py

Enterprise SQLite Logger
Safe shared SQLite connection with automatic reconnect.
"""

import sqlite3
import threading
import time
from pathlib import Path


class DatabaseLogger:

    def __init__(self, database_path="dpi_database.db"):

        self.database_path = Path(database_path).resolve()

        self.lock = threading.RLock()

        self.conn = None
        self.cursor = None

        self._ensure_connection()

        self.create_tables()

    # =====================================================
    # CONNECTION
    # =====================================================

    def _ensure_connection(self):

        with self.lock:

            if self.conn is not None and self.cursor is not None:
                return

            self.conn = sqlite3.connect(
                str(self.database_path),
                timeout=60,
                check_same_thread=False
            )

            self.conn.row_factory = sqlite3.Row

            self.cursor = self.conn.cursor()

            self.cursor.execute(
                "PRAGMA busy_timeout=60000"
            )

            self.conn.commit()

    # =====================================================
    # EXECUTE
    # =====================================================

    def execute(self, query, parameters=(), retries=10):

        self._ensure_connection()

        for attempt in range(retries):

            try:

                with self.lock:

                    self.cursor.execute(
                        query,
                        parameters
                    )

                    self.conn.commit()

                    return self.cursor

            except sqlite3.OperationalError as e:

                text = str(e).lower()

                if "locked" not in text and "busy" not in text:
                    raise

                time.sleep(
                    0.2 * (attempt + 1)
                )

                self._ensure_connection()

        raise sqlite3.OperationalError(
            "Database remained locked"
        )

    # Backward compatibility
    def _execute(self, query, parameters=(), retries=10):

        try:

            self.execute(
                query,
                parameters,
                retries
            )

            return True

        except Exception as e:

            print(
                "[Database] SQL error:",
                e
            )

            return False

    # =====================================================
    # CREATE TABLES
    # =====================================================

    def create_tables(self):

        self._ensure_connection()

        with self.lock:

            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    application TEXT,
                    domain TEXT,
                    sni TEXT,
                    ja3 TEXT,
                    ja4 TEXT,
                    country TEXT,
                    city TEXT,
                    organization TEXT,
                    reputation TEXT,
                    action TEXT,
                    packet_size INTEGER DEFAULT 0,
                    anomaly INTEGER DEFAULT 0,
                    risk_score INTEGER DEFAULT 0,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT,
                    severity TEXT,
                    alert_type TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT
                )
            """)

            self.conn.commit()

        # Existing databases may not have these columns
        for sql in [
            "ALTER TABLE flows ADD COLUMN packet_size INTEGER DEFAULT 0",
            "ALTER TABLE flows ADD COLUMN anomaly INTEGER DEFAULT 0",
            "ALTER TABLE flows ADD COLUMN risk_score INTEGER DEFAULT 0"
        ]:

            try:

                self.execute(sql)

            except sqlite3.OperationalError:

                pass

        print("[Database] Tables ready.")

    # =====================================================
    # LOG FLOW
    # =====================================================

    def log_flow(self, packet, connection, geo, rep):

        if geo is None:
            geo = {}

        protocol_obj = getattr(
            packet,
            "detected_protocol",
            None
        )

        protocol = getattr(
            protocol_obj,
            "name",
            getattr(packet, "protocol", "UNKNOWN")
        )

        app_obj = getattr(
            connection,
            "app_type",
            None
        )

        application = getattr(
            app_obj,
            "name",
            "UNKNOWN"
        )

        action_obj = getattr(
            connection,
            "action",
            ""
        )

        action = getattr(
            action_obj,
            "name",
            str(action_obj)
        )

        packet_size = getattr(
            packet,
            "payload_length",
            0
        )

        query = """
            INSERT INTO flows(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                application,
                domain,
                sni,
                ja3,
                ja4,
                country,
                city,
                organization,
                reputation,
                action,
                packet_size
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """

        params = (
            getattr(packet, "src_ip", ""),
            getattr(packet, "dst_ip", ""),
            getattr(packet, "src_port", 0),
            getattr(packet, "dst_port", 0),
            protocol,
            application,
            getattr(connection, "domain", ""),
            getattr(connection, "sni", ""),
            getattr(connection, "ja3", ""),
            getattr(connection, "ja4", ""),
            geo.get("country", "Unknown"),
            geo.get("city", "Unknown"),
            geo.get("organization", "Unknown"),
            getattr(rep, "category", "Unknown") if rep else "Unknown",
            action,
            packet_size
        )

        try:

            self.execute(
                query,
                params
            )

            return True

        except Exception as e:

            print(
                "[Database] Flow error:",
                e
            )

            return False

    # =====================================================
    # LOG ALERT
    # =====================================================

    def log_alert(
        self,
        severity,
        alert_type,
        src_ip,
        dst_ip,
        description
    ):

        query = """
            INSERT INTO alerts(
                time,
                severity,
                alert_type,
                source_ip,
                destination_ip,
                description
            )
            VALUES(datetime('now'),?,?,?,?,?)
        """

        try:

            self.execute(
                query,
                (
                    severity,
                    alert_type,
                    src_ip,
                    dst_ip,
                    description
                )
            )

            return True

        except Exception as e:

            print(
                "[Database] Alert error:",
                e
            )

            return False

    # =====================================================
    # READ FLOWS
    # =====================================================

    def get_flows(self, limit=100):

        try:

            cur = self.execute(
                "SELECT * FROM flows ORDER BY id DESC LIMIT ?",
                (limit,)
            )

            return cur.fetchall()

        except Exception:

            return []

    # =====================================================
    # READ ALERTS
    # =====================================================

    def get_alerts(self, limit=100):

        try:

            cur = self.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)
            )

            return cur.fetchall()

        except Exception:

            return []

    # =====================================================
    # CLOSE
    # =====================================================

    def close(self):

        with self.lock:

            if self.conn is None:
                return

            try:

                self.conn.commit()

            except Exception:

                pass

            try:

                self.conn.close()

            except Exception:

                pass

            # Set to None.
            # _ensure_connection() will reconnect automatically
            # if ML or ThreatEngine needs the database later.

            self.conn = None
            self.cursor = None

            print(
                "[Database] Connection closed."
            )