from flask import Flask, render_template, request, redirect, session, jsonify, send_file
from functools import wraps
from pathlib import Path
import sqlite3
import os
import json
import csv
import traceback

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "dpi_database.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"
EXPORT_FOLDER = BASE_DIR / "exports"
TEMPLATE_FOLDER = BASE_DIR / "dashboard" / "templates"
STATIC_FOLDER = BASE_DIR / "dashboard" / "static"

UPLOAD_FOLDER.mkdir(exist_ok=True)
EXPORT_FOLDER.mkdir(exist_ok=True)
TEMPLATE_FOLDER.mkdir(parents=True, exist_ok=True)
STATIC_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_FOLDER),
    static_folder=str(STATIC_FOLDER),
)
app.secret_key = "enterprise_dpi_dashboard_2026"
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)

try:
    from flask_socketio import SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
except Exception:
    socketio = None


def db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn, table_name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def columns_for(conn, table_name="flows"):
    if not table_exists(conn, table_name):
        return []
    return [
        r["name"]
        for r in conn.execute(
            f'PRAGMA table_info("{table_name}")'
        ).fetchall()
    ]


def count_where(conn, condition, params=()):
    try:
        return int(
            conn.execute(
                f"SELECT COUNT(*) AS c FROM flows WHERE {condition}",
                params,
            ).fetchone()["c"]
        )
    except sqlite3.Error:
        return 0


def text_value(row, key, default=""):
    try:
        value = row[key]
    except (KeyError, IndexError):
        return default
    return default if value is None else value


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        if str(session.get("role", "")).lower() != "admin":
            return "Access Denied", 403
        return func(*args, **kwargs)

    return wrapper


def ensure_users_table():
    conn = db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Admin'
            )
            """
        )

        count = conn.execute(
            "SELECT COUNT(*) AS c FROM users"
        ).fetchone()["c"]

        if count == 0:
            conn.execute(
                "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                ("admin", "admin", "Admin"),
            )

        conn.commit()
    finally:
        conn.close()


ensure_users_table()


COUNTRY_CENTROIDS = {
    "india": (20.5937, 78.9629),
    "united states": (39.8283, -98.5795),
    "usa": (39.8283, -98.5795),
    "us": (39.8283, -98.5795),
    "united kingdom": (55.3781, -3.4360),
    "uk": (55.3781, -3.4360),
    "germany": (51.1657, 10.4515),
    "france": (46.2276, 2.2137),
    "singapore": (1.3521, 103.8198),
    "japan": (36.2048, 138.2529),
    "australia": (-25.2744, 133.7751),
    "canada": (56.1304, -106.3468),
    "brazil": (-14.2350, -51.9253),
    "china": (35.8617, 104.1954),
    "russia": (61.5240, 105.3188),
    "netherlands": (52.1326, 5.2913),
    "ireland": (53.1424, -7.6921),
    "uae": (23.4241, 53.8478),
    "united arab emirates": (23.4241, 53.8478),
}


def normalize_country(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def build_map_locations(rows, columns):
    locations = []
    seen = set()

    for row in rows:
        country = str(text_value(row, "country", "") or "").strip()
        city = str(text_value(row, "city", "") or "").strip()
        ip = str(text_value(row, "src_ip", "") or "").strip()

        lat = text_value(row, "lat", None) if "lat" in columns else None
        lon = text_value(row, "lon", None) if "lon" in columns else None

        try:
            lat = float(lat) if lat not in (None, "") else None
            lon = float(lon) if lon not in (None, "") else None
        except (TypeError, ValueError):
            lat = lon = None

        if lat is None or lon is None:
            coords = COUNTRY_CENTROIDS.get(
                normalize_country(country)
            )
            if coords:
                lat, lon = coords

        if lat is None or lon is None:
            continue

        key = (
            round(lat, 3),
            round(lon, 3),
            country,
            city,
        )

        if key in seen:
            continue

        seen.add(key)

        locations.append(
            {
                "lat": lat,
                "lon": lon,
                "country": country or "Unknown",
                "city": city or "Unknown",
                "ip": ip or "Unknown",
            }
        )

        if len(locations) >= 100:
            break

    # Always show a usable map, even if the database does not contain
    # latitude/longitude or country information.
    if not locations:
        locations.append(
            {
                "lat": 20.5937,
                "lon": 78.9629,
                "country": "India",
                "city": "Dashboard fallback",
                "ip": "No GeoIP coordinates in database",
            }
        )

    return locations


def infer_application(protocol, application):
    app_name = str(application or "").strip()

    if app_name:
        return app_name

    p = str(protocol or "").strip().upper()

    mapping = {
        "TLS": "HTTPS / TLS",
        "DNS": "DNS",
        "HTTP": "HTTP",
        "QUIC": "QUIC / HTTP3",
        "6": "TCP",
        "17": "UDP",
        "TCP": "TCP",
        "UDP": "UDP",
    }

    return mapping.get(p, "Unknown")


def dashboard_data():
    conn = db_connection()

    try:
        if not table_exists(conn, "flows"):
            return {
                "total_packets": 0,
                "total_hosts": 0,
                "tls_packets": 0,
                "dns_packets": 0,
                "blocked_packets": 0,
                "malware_count": 0,
                "protocol_stats": [],
                "top_apps": [],
                "top_countries": [],
                "top_attackers": [],
                "anomalies": [],
                "locations": [],
                "traffic_labels": [],
                "traffic_values": [],
                "rows": [],
                "notification_count": 0,
            }

        cols = columns_for(conn)

        total_packets = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM flows"
            ).fetchone()["c"]
        )

        if "src_ip" in cols:
            total_hosts = int(
                conn.execute(
                    """
                    SELECT COUNT(DISTINCT src_ip) AS c
                    FROM flows
                    WHERE src_ip IS NOT NULL
                    AND TRIM(src_ip) <> ''
                    """
                ).fetchone()["c"]
            )
        else:
            total_hosts = 0

        # Case/space-insensitive protocol counting.
        tls_packets = count_where(
            conn,
            "UPPER(TRIM(COALESCE(protocol,'')))='TLS'",
        )

        dns_packets = count_where(
            conn,
            "UPPER(TRIM(COALESCE(protocol,'')))='DNS'",
        )

        blocked_packets = (
            count_where(
                conn,
                """
                UPPER(TRIM(COALESCE(action,'')))
                IN ('DROP','BLOCK','BLOCKED')
                """,
            )
            if "action" in cols
            else 0
        )

        malware_count = (
            count_where(
                conn,
                """
                UPPER(TRIM(COALESCE(reputation,'')))='MALICIOUS'
                """,
            )
            if "reputation" in cols
            else 0
        )

        select_cols = [
            c
            for c in [
                "id",
                "src_ip",
                "dst_ip",
                "protocol",
                "application",
                "country",
                "city",
                "ja3",
                "ja4",
                "action",
                "reputation",
            ]
            if c in cols
        ]

        if not select_cols:
            select_cols = (
                ["id"] if "id" in cols else ["rowid AS id"]
            )

        order_col = "id" if "id" in cols else "rowid"

        rows = conn.execute(
            f"""
            SELECT {",".join(select_cols)}
            FROM flows
            ORDER BY {order_col} DESC
            LIMIT 100
            """
        ).fetchall()

        # ---------------- Protocol Distribution ----------------

        protocol_stats = []

        if "protocol" in cols:
            protocol_stats = conn.execute(
                """
                SELECT
                    CASE
                        WHEN protocol IS NULL
                        OR TRIM(protocol)=''
                        THEN 'UNKNOWN'
                        ELSE UPPER(TRIM(protocol))
                    END AS protocol,
                    COUNT(*) AS total
                FROM flows
                GROUP BY
                    CASE
                        WHEN protocol IS NULL
                        OR TRIM(protocol)=''
                        THEN 'UNKNOWN'
                        ELSE UPPER(TRIM(protocol))
                    END
                ORDER BY total DESC
                """
            ).fetchall()

        # ---------------- Application Distribution ----------------

        top_apps = []

        if "application" in cols:
            top_apps = conn.execute(
                """
                SELECT
                    CASE
                        WHEN application IS NULL
                        OR TRIM(application)=''
                        THEN 'Unknown'
                        ELSE TRIM(application)
                    END AS application,
                    COUNT(*) AS total
                FROM flows
                GROUP BY
                    CASE
                        WHEN application IS NULL
                        OR TRIM(application)=''
                        THEN 'Unknown'
                        ELSE TRIM(application)
                    END
                ORDER BY total DESC
                LIMIT 10
                """
            ).fetchall()

        # If application is empty/unknown, build the chart from protocols.
        if (
            not top_apps
            or all(
                str(r["application"]).lower() == "unknown"
                for r in top_apps
            )
        ):
            app_counts = {}

            for r in protocol_stats:
                name = infer_application(
                    r["protocol"],
                    "",
                )

                app_counts[name] = (
                    app_counts.get(name, 0)
                    + int(r["total"])
                )

            top_apps = [
                {
                    "application": name,
                    "total": total,
                }
                for name, total in sorted(
                    app_counts.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:10]
            ]

        # ---------------- Country Distribution ----------------

        top_countries = []

        if "country" in cols:
            top_countries = conn.execute(
                """
                SELECT
                    CASE
                        WHEN country IS NULL
                        OR TRIM(country)=''
                        THEN 'Unknown'
                        ELSE TRIM(country)
                    END AS country,
                    COUNT(*) AS total
                FROM flows
                GROUP BY
                    CASE
                        WHEN country IS NULL
                        OR TRIM(country)=''
                        THEN 'Unknown'
                        ELSE TRIM(country)
                    END
                ORDER BY total DESC
                LIMIT 10
                """
            ).fetchall()

        # ---------------- Top Attackers ----------------

        top_attackers = []

        if "src_ip" in cols:
            top_attackers = conn.execute(
                """
                SELECT src_ip, COUNT(*) AS total
                FROM flows
                WHERE src_ip IS NOT NULL
                AND TRIM(src_ip)<>''
                GROUP BY src_ip
                ORDER BY total DESC
                LIMIT 10
                """
            ).fetchall()

        # ---------------- ML / Malicious Rows ----------------

        anomalies = []

        if "reputation" in cols:
            anomaly_select = [
                c
                for c in [
                    "src_ip",
                    "dst_ip",
                    "reputation",
                ]
                if c in cols
            ]

            if anomaly_select:
                anomalies = conn.execute(
                    f"""
                    SELECT {",".join(anomaly_select)}
                    FROM flows
                    WHERE UPPER(
                        TRIM(COALESCE(reputation,''))
                    )='MALICIOUS'
                    ORDER BY {order_col} DESC
                    LIMIT 20
                    """
                ).fetchall()

        # ---------------- Alerts ----------------

        notification_count = 0

        if table_exists(conn, "alerts"):
            notification_count = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM alerts"
                ).fetchone()["c"]
            )

        # ---------------- GeoIP Map ----------------

        map_cols = [
            c
            for c in [
                "country",
                "city",
                "src_ip",
                "lat",
                "lon",
            ]
            if c in cols
        ]

        if map_cols:
            map_rows = conn.execute(
                f"""
                SELECT {",".join(map_cols)}
                FROM flows
                ORDER BY {order_col} DESC
                LIMIT 1000
                """
            ).fetchall()
        else:
            map_rows = []

        locations = build_map_locations(
            map_rows,
            cols,
        )

        # ---------------- Traffic Chart ----------------
        # Use the most recent flows and divide them into up to 12 buckets.
        flow_rows = conn.execute(
            f"""
            SELECT {order_col} AS flow_id
            FROM flows
            ORDER BY {order_col} DESC
            LIMIT 1200
            """
        ).fetchall()

        flow_ids = [
            int(r["flow_id"])
            for r in flow_rows
            if r["flow_id"] is not None
        ]

        flow_ids.reverse()

        traffic_labels = []
        traffic_values = []

        if flow_ids:
            bucket_size = max(
                1,
                len(flow_ids) // 12,
            )

            for i in range(
                0,
                len(flow_ids),
                bucket_size,
            ):
                chunk = flow_ids[
                    i : i + bucket_size
                ]

                traffic_labels.append(
                    f"Flows {chunk[0]}-{chunk[-1]}"
                )

                traffic_values.append(
                    len(chunk)
                )

            traffic_labels = traffic_labels[-12:]
            traffic_values = traffic_values[-12:]

        return {
            "total_packets": total_packets,
            "total_hosts": total_hosts,
            "tls_packets": tls_packets,
            "dns_packets": dns_packets,
            "blocked_packets": blocked_packets,
            "malware_count": malware_count,
            "protocol_stats": [
                dict(r) for r in protocol_stats
            ],
            "top_apps": [
                dict(r) for r in top_apps
            ],
            "top_countries": [
                dict(r) for r in top_countries
            ],
            "top_attackers": [
                dict(r) for r in top_attackers
            ],
            "anomalies": [
                dict(r) for r in anomalies
            ],
            "locations": locations,
            "traffic_labels": traffic_labels,
            "traffic_values": traffic_values,
            "rows": [
                dict(r) for r in rows
            ],
            "notification_count": notification_count,
        }

    finally:
        conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        conn = db_connection()

        try:
            user = conn.execute(
                """
                SELECT username, role
                FROM users
                WHERE username=?
                AND password=?
                """,
                (
                    username,
                    password,
                ),
            ).fetchone()
        finally:
            conn.close()

        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect("/")

        return render_template(
            "login.html",
            error="Invalid username or password",
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@admin_required
def index():
    data = dashboard_data()
    return render_template(
        "index.html",
        **data,
    )


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "database_exists": DB_PATH.exists(),
            "database": str(DB_PATH),
        }
    )


@app.route("/api/dashboard")
@admin_required
def api_dashboard():
    data = dashboard_data()

    return jsonify(
        {
            "total_packets": data["total_packets"],
            "total_hosts": data["total_hosts"],
            "tls_packets": data["tls_packets"],
            "dns_packets": data["dns_packets"],
            "blocked_packets": data["blocked_packets"],
            "malware_count": data["malware_count"],
            "protocol_stats": data["protocol_stats"],
            "top_apps": data["top_apps"],
            "traffic_labels": data["traffic_labels"],
            "traffic_values": data["traffic_values"],
        }
    )


@app.route("/live_data")
@admin_required
def live_data():
    return jsonify(
        dashboard_data()["rows"]
    )


@app.route("/api/flows")
@admin_required
def api_flows():
    return jsonify(
        dashboard_data()["rows"]
    )


@app.route("/api/alerts")
@admin_required
def api_alerts():
    conn = db_connection()

    try:
        if not table_exists(
            conn,
            "alerts",
        ):
            return jsonify([])

        rows = conn.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

        return jsonify(
            [dict(r) for r in rows]
        )

    finally:
        conn.close()


@app.route("/upload", methods=["POST"])
@admin_required
def upload():
    uploaded_file = request.files.get(
        "pcap"
    )

    if (
        uploaded_file is None
        or not uploaded_file.filename
    ):
        return (
            "No PCAP file selected",
            400,
        )

    filename = Path(
        uploaded_file.filename
    ).name

    if Path(filename).suffix.lower() not in {
        ".pcap",
        ".pcapng",
    }:
        return (
            "Only .pcap and .pcapng files are allowed",
            400,
        )

    filepath = (
        UPLOAD_FOLDER / filename
    )

    uploaded_file.save(
        filepath
    )

    try:
        from dpi_engine import DPIEngine

        try:
            analyzer = DPIEngine(
                socketio
            )
        except TypeError:
            analyzer = DPIEngine()

        if not analyzer.open(
            str(filepath)
        ):
            try:
                analyzer.close()
            except Exception:
                pass

            return (
                "Unable to open PCAP file",
                500,
            )

        analyzer.run()

        try:
            analyzer.print_statistics()
        except Exception:
            pass

        try:
            analyzer.close()
        except Exception:
            pass

        return redirect("/")

    except Exception as exc:
        traceback.print_exc()

        return (
            f"PCAP analysis failed: "
            f"{type(exc).__name__}: {exc}",
            500,
        )


def export_file(fmt):
    if fmt == "csv":
        path = (
            EXPORT_FOLDER
            / "flows.csv"
        )

        conn = db_connection()

        try:
            cursor = conn.execute(
                "SELECT * FROM flows"
            )

            rows = cursor.fetchall()
            columns = [
                description[0]
                for description in cursor.description
            ]

            with open(
                path,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.writer(file)
                writer.writerow(columns)

                for row in rows:
                    writer.writerow(
                        [
                            row[column]
                            for column in columns
                        ]
                    )

        finally:
            conn.close()

        return (
            path,
            "text/csv",
        )

    if fmt == "json":
        path = (
            EXPORT_FOLDER
            / "flows.json"
        )

        conn = db_connection()

        try:
            rows = conn.execute(
                "SELECT * FROM flows"
            ).fetchall()

            path.write_text(
                json.dumps(
                    [dict(r) for r in rows],
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )

        finally:
            conn.close()

        return (
            path,
            "application/json",
        )

    if fmt == "excel":
        path = (
            EXPORT_FOLDER
            / "flows.xlsx"
        )

        try:
            import pandas as pd

            conn = db_connection()

            try:
                df = pd.read_sql_query(
                    "SELECT * FROM flows",
                    conn,
                )

                df.to_excel(
                    path,
                    index=False,
                )

            finally:
                conn.close()

            return (
                path,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

        except ImportError:
            return None, None

    if fmt == "pdf":
        path = (
            EXPORT_FOLDER
            / "dpi_report.pdf"
        )

        try:
            from reportlab.platypus import (
                SimpleDocTemplate,
                Table,
                TableStyle,
                Paragraph,
            )
            from reportlab.lib import colors
            from reportlab.lib.styles import (
                getSampleStyleSheet,
            )

            conn = db_connection()

            try:
                rows = conn.execute(
                    """
                    SELECT
                        src_ip,
                        dst_ip,
                        protocol,
                        application
                    FROM flows
                    LIMIT 5000
                    """
                ).fetchall()

            finally:
                conn.close()

            document = SimpleDocTemplate(
                str(path)
            )

            styles = (
                getSampleStyleSheet()
            )

            data = [
                [
                    "Source",
                    "Destination",
                    "Protocol",
                    "Application",
                ]
            ]

            for row in rows:
                data.append(
                    [
                        row["src_ip"],
                        row["dst_ip"],
                        row["protocol"],
                        row["application"],
                    ]
                )

            table = Table(
                data,
                repeatRows=1,
            )

            table.setStyle(
                TableStyle(
                    [
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey,
                        ),
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.blue,
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                    ]
                )
            )

            document.build(
                [
                    Paragraph(
                        "Enterprise DPI Report",
                        styles["Heading1"],
                    ),
                    table,
                ]
            )

            return (
                path,
                "application/pdf",
            )

        except ImportError:
            return None, None

    return None, None


def create_export_route(fmt):
    endpoint = f"export_{fmt}"

    @app.route(
        f"/export/{fmt}",
        endpoint=endpoint,
    )
    @admin_required
    def export_route():
        path, mimetype = export_file(
            fmt
        )

        if path is None:
            return (
                f"{fmt.upper()} export requires "
                f"its Python package to be installed.",
                500,
            )

        return send_file(
            str(path),
            as_attachment=True,
            mimetype=mimetype,
        )


for export_format in (
    "csv",
    "json",
    "excel",
    "pdf",
):
    create_export_route(
        export_format
    )


if __name__ == "__main__":
    print("=" * 60)
    print("       ENTERPRISE DPI DASHBOARD")
    print("=" * 60)
    print("Database:", DB_PATH)
    print(
        "Database exists:",
        DB_PATH.exists(),
    )
    print(
        "Dashboard: http://127.0.0.1:5000/"
    )
    print(
        "Health:    http://127.0.0.1:5000/health"
    )
    print(
        "API:       http://127.0.0.1:5000/api/dashboard"
    )
    print("=" * 60)

    if socketio is not None:
        socketio.run(
            app,
            host="0.0.0.0",
            port=5000,
            debug=True,
            use_reloader=False,
        )
    else:
        app.run(
            host="0.0.0.0",
            port=5000,
            debug=True,
            use_reloader=False,
        )