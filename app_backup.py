from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    send_file,
)
from flask_socketio import SocketIO
from functools import wraps
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import sqlite3
import pandas as pd
import os

from dpi_engine import DPIEngine
from ids_engine import IDSEngine


# ============================================================
# APPLICATION SETUP
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "dpi_database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
EXPORT_FOLDER = os.path.join(BASE_DIR, "exports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXPORT_FOLDER, exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
    static_folder=os.path.join(BASE_DIR, "dashboard", "static"),
)

app.secret_key = "enterprise_dpi_dashboard_2026"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

socketio = SocketIO(app, cors_allowed_origins="*")

# Create the engines only once.
engine = DPIEngine(socketio)
ids = IDSEngine(socketio)

print("[DPI] Database :", DB_PATH)
print("[DPI] Uploads  :", UPLOAD_FOLDER)
print("[DPI] Exports  :", EXPORT_FOLDER)


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_connection():
    """Return a SQLite connection using the project's real DB path."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(cur, table_name):
    cur.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table' AND name=?
        """,
        (table_name,),
    )
    return cur.fetchone() is not None


def column_exists(cur, table_name, column_name):
    cur.execute(f"PRAGMA table_info({table_name})")
    return any(row["name"] == column_name for row in cur.fetchall())


def safe_count(cur, sql, default=0):
    try:
        cur.execute(sql)
        row = cur.fetchone()
        return row[0] if row else default
    except sqlite3.Error:
        return default


# ============================================================
# AUTHORIZATION
# ============================================================

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")

        if session.get("role") != "Admin":
            return "Access Denied", 403

        return func(*args, **kwargs)

    return wrapper


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                """
                SELECT *
                FROM users
                WHERE username=? AND password=?
                """,
                (username, password),
            )
            user = cur.fetchone()
        except sqlite3.Error as exc:
            conn.close()
            return f"Login database error: {exc}", 500

        conn.close()

        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect("/")

        return "Invalid Username or Password", 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ============================================================
# DASHBOARD DATA
# ============================================================

def get_dashboard_data():
    """
    Build all dashboard KPIs and chart data from the same database.

    Important:
    Your PCAP data stores TCP/UDP in the protocol column as
    '6' and '17', not necessarily as the strings 'TCP'/'UDP'.
    Therefore both numeric protocol numbers and text names are handled.
    """

    conn = get_connection()
    cur = conn.cursor()

    data = {
        "rows": [],
        "total_packets": 0,
        "total_hosts": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "tls_packets": 0,
        "dns_packets": 0,
        "blocked_packets": 0,
        "malware_count": 0,
        "protocol_stats": [],
        "protocol_labels": [],
        "protocol_values": [],
        "top_apps": [],
        "app_labels": [],
        "app_values": [],
        "top_countries": [],
        "country_labels": [],
        "country_values": [],
        "top_src": [],
        "top_dst": [],
        "top_ports": [],
        "threat_stats": [],
        "threat_labels": [],
        "threat_values": [],
        "ja3_stats": [],
        "ja4_stats": [],
        "top_attackers": [],
        "anomalies": [],
        "anomaly_count": 0,
        "notification_count": 0,
        "locations": [],
    }

    try:
        # --------------------------------------------------------
        # Basic packet KPIs
        # --------------------------------------------------------

        data["total_packets"] = safe_count(
            cur, "SELECT COUNT(*) FROM flows"
        )

        data["total_hosts"] = safe_count(
            cur,
            """
            SELECT COUNT(DISTINCT src_ip)
            FROM flows
            WHERE src_ip IS NOT NULL AND src_ip != ''
            """,
        )

        # Your database contains protocol values such as:
        # TLS, DNS, UNKNOWN, 6, 17, HTTP, QUIC
        data["tcp_packets"] = safe_count(
            cur,
            """
            SELECT COUNT(*)
            FROM flows
            WHERE LOWER(CAST(protocol AS TEXT)) IN ('6', 'tcp')
            """,
        )

        data["udp_packets"] = safe_count(
            cur,
            """
            SELECT COUNT(*)
            FROM flows
            WHERE LOWER(CAST(protocol AS TEXT)) IN ('17', 'udp')
            """,
        )

        data["tls_packets"] = safe_count(
            cur,
            """
            SELECT COUNT(*)
            FROM flows
            WHERE LOWER(CAST(protocol AS TEXT)) = 'tls'
            """,
        )

        data["dns_packets"] = safe_count(
            cur,
            """
            SELECT COUNT(*)
            FROM flows
            WHERE LOWER(CAST(protocol AS TEXT)) = 'dns'
            """,
        )

        data["blocked_packets"] = safe_count(
            cur,
            """
            SELECT COUNT(*)
            FROM flows
            WHERE UPPER(COALESCE(action, '')) = 'DROP'
            """,
        )

        data["malware_count"] = safe_count(
            cur,
            """
            SELECT COUNT(*)
            FROM flows
            WHERE LOWER(COALESCE(reputation, '')) = 'malicious'
            """,
        )

        # --------------------------------------------------------
        # Recent flows
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT *
            FROM flows
            ORDER BY id DESC
            LIMIT 100
            """
        )
        data["rows"] = cur.fetchall()

        # --------------------------------------------------------
        # Protocol distribution
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT
                COALESCE(NULLIF(CAST(protocol AS TEXT), ''), 'UNKNOWN') AS protocol,
                COUNT(*) AS total
            FROM flows
            GROUP BY protocol
            ORDER BY total DESC
            """
        )
        data["protocol_stats"] = cur.fetchall()

        data["protocol_labels"] = [
            row["protocol"] for row in data["protocol_stats"]
        ]
        data["protocol_values"] = [
            row["total"] for row in data["protocol_stats"]
        ]

        # --------------------------------------------------------
        # Application distribution
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT
                COALESCE(NULLIF(application, ''), 'UNKNOWN') AS application,
                COUNT(*) AS total
            FROM flows
            GROUP BY application
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["top_apps"] = cur.fetchall()

        data["app_labels"] = [
            row["application"] for row in data["top_apps"]
        ]
        data["app_values"] = [
            row["total"] for row in data["top_apps"]
        ]

        # --------------------------------------------------------
        # Country distribution
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT
                COALESCE(NULLIF(country, ''), 'UNKNOWN') AS country,
                COUNT(*) AS total
            FROM flows
            GROUP BY country
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["top_countries"] = cur.fetchall()

        data["country_labels"] = [
            row["country"] for row in data["top_countries"]
        ]
        data["country_values"] = [
            row["total"] for row in data["top_countries"]
        ]

        # --------------------------------------------------------
        # Source IPs
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT src_ip, COUNT(*) AS total
            FROM flows
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["top_src"] = cur.fetchall()

        # --------------------------------------------------------
        # Destination IPs
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT dst_ip, COUNT(*) AS total
            FROM flows
            WHERE dst_ip IS NOT NULL AND dst_ip != ''
            GROUP BY dst_ip
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["top_dst"] = cur.fetchall()

        # --------------------------------------------------------
        # Destination ports
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT dst_port, COUNT(*) AS total
            FROM flows
            WHERE dst_port IS NOT NULL
            GROUP BY dst_port
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["top_ports"] = cur.fetchall()

        # --------------------------------------------------------
        # Threat / reputation
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT
                COALESCE(NULLIF(reputation, ''), 'UNKNOWN') AS reputation,
                COUNT(*) AS total
            FROM flows
            GROUP BY reputation
            ORDER BY total DESC
            """
        )
        data["threat_stats"] = cur.fetchall()

        data["threat_labels"] = [
            row["reputation"] for row in data["threat_stats"]
        ]
        data["threat_values"] = [
            row["total"] for row in data["threat_stats"]
        ]

        # --------------------------------------------------------
        # JA3
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT ja3, COUNT(*) AS total
            FROM flows
            WHERE ja3 IS NOT NULL AND ja3 != ''
            GROUP BY ja3
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["ja3_stats"] = cur.fetchall()

        # --------------------------------------------------------
        # JA4
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT ja4, COUNT(*) AS total
            FROM flows
            WHERE ja4 IS NOT NULL AND ja4 != ''
            GROUP BY ja4
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["ja4_stats"] = cur.fetchall()

        # --------------------------------------------------------
        # Top attackers
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT src_ip, COUNT(*) AS total
            FROM flows
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY total DESC
            LIMIT 10
            """
        )
        data["top_attackers"] = cur.fetchall()

        # --------------------------------------------------------
        # ML / malicious anomalies
        # --------------------------------------------------------

        cur.execute(
            """
            SELECT *
            FROM flows
            WHERE LOWER(COALESCE(reputation, '')) = 'malicious'
            ORDER BY id DESC
            LIMIT 20
            """
        )
        data["anomalies"] = cur.fetchall()

        data["anomaly_count"] = data["malware_count"]

        # --------------------------------------------------------
        # Alerts
        # --------------------------------------------------------

        if table_exists(cur, "alerts"):
            data["notification_count"] = safe_count(
                cur, "SELECT COUNT(*) FROM alerts"
            )

        # --------------------------------------------------------
        # GeoIP locations
        # --------------------------------------------------------

        # Keep this available for the template. The map itself is
        # initialized by the JavaScript in index.html.
        data["locations"] = []

    finally:
        conn.close()

    return data


# ============================================================
# MAIN DASHBOARD
# ============================================================

@app.route("/")
def index():
    if "username" not in session:
        return redirect("/login")

    data = get_dashboard_data()

    return render_template("index.html", **data)


# ============================================================
# ADMIN PANEL
# ============================================================

@app.route("/admin")
@admin_required
def admin():
    conn = get_connection()
    cur = conn.cursor()

    users = []

    try:
        if table_exists(cur, "users"):
            cur.execute("SELECT * FROM users")
            users = cur.fetchall()
    finally:
        conn.close()

    return render_template("admin.html", users=users)


# ============================================================
# ALERTS / NOTIFICATIONS
# ============================================================

@app.route("/alerts")
@admin_required
def alerts():
    conn = get_connection()
    cur = conn.cursor()

    alert_rows = []

    try:
        if table_exists(cur, "alerts"):
            cur.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                """
            )
            alert_rows = cur.fetchall()
    finally:
        conn.close()

    return render_template("alerts.html", alerts=alert_rows)


@app.route("/notifications")
@admin_required
def notifications():
    conn = get_connection()
    cur = conn.cursor()

    alert_rows = []

    try:
        if table_exists(cur, "alerts"):
            cur.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                LIMIT 50
                """
            )
            alert_rows = cur.fetchall()
    finally:
        conn.close()

    return render_template("notifications.html", alerts=alert_rows)


# ============================================================
# PCAP UPLOAD / ANALYSIS
# ============================================================

@app.route("/upload", methods=["POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    uploaded_file = request.files.get("pcap")

    if uploaded_file is None:
        return "No file received", 400

    if not uploaded_file.filename:
        return "No file selected", 400

    filename = os.path.basename(uploaded_file.filename)
    extension = os.path.splitext(filename)[1].lower()

    if extension not in (".pcap", ".pcapng"):
        return "Only PCAP and PCAPNG files are allowed", 400

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(filepath)

    if not os.path.isfile(filepath):
        return "PCAP file could not be saved", 500

    print("=" * 60)
    print("PCAP UPLOAD")
    print("File:", filepath)
    print("Size:", os.path.getsize(filepath), "bytes")
    print("=" * 60)

    try:
        # Reuse the same SocketIO-enabled engine configuration.
        analysis_engine = DPIEngine(socketio)

        if not analysis_engine.open(filepath):
            try:
                analysis_engine.close()
            except Exception:
                pass
            return "Unable to open PCAP file", 500

        analysis_engine.run()

        try:
            analysis_engine.print_statistics()
        except Exception:
            pass

        try:
            analysis_engine.close()
        except Exception:
            pass

    except Exception as exc:
        print("[PCAP ERROR]", type(exc).__name__, str(exc))
        return f"PCAP analysis failed: {exc}", 500

    return redirect("/")


# ============================================================
# LIVE DATA
# ============================================================

@app.route("/live_data")
def live_data():
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT
                id,
                src_ip,
                dst_ip,
                protocol,
                application,
                action
            FROM flows
            ORDER BY id DESC
            LIMIT 100
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    return jsonify([dict(row) for row in rows])


# ============================================================
# DASHBOARD API
# IMPORTANT:
# This endpoint now returns BOTH KPIs AND CHART DATA.
# ============================================================

@app.route("/api/dashboard")
def api_dashboard():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = get_dashboard_data()

    return jsonify(
        {
            # KPIs
            "total_packets": data["total_packets"],
            "total_hosts": data["total_hosts"],
            "tcp_packets": data["tcp_packets"],
            "udp_packets": data["udp_packets"],
            "tls_packets": data["tls_packets"],
            "dns_packets": data["dns_packets"],
            "blocked_packets": data["blocked_packets"],
            "malware_count": data["malware_count"],
            "anomaly_count": data["anomaly_count"],
            "notification_count": data["notification_count"],

            # Protocol chart
            "protocol_labels": data["protocol_labels"],
            "protocol_values": data["protocol_values"],

            # Application chart
            "app_labels": data["app_labels"],
            "app_values": data["app_values"],

            # Country chart
            "country_labels": data["country_labels"],
            "country_values": data["country_values"],

            # Threat chart
            "threat_labels": data["threat_labels"],
            "threat_values": data["threat_values"],
        }
    )


@app.route("/api/flows")
def api_flows():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT *
            FROM flows
            ORDER BY id DESC
            LIMIT 100
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/alerts")
def api_alerts():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cur = conn.cursor()

    alert_rows = []

    try:
        if table_exists(cur, "alerts"):
            cur.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                LIMIT 100
                """
            )
            alert_rows = cur.fetchall()
    finally:
        conn.close()

    return jsonify([dict(row) for row in alert_rows])


# ============================================================
# SOCKET.IO DASHBOARD UPDATE
# ============================================================

def send_dashboard_update():

    conn = sqlite3.connect("dpi_database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # =========================================================
    # TOTAL PACKETS
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
    """)
    total_packets = cur.fetchone()[0]

    # =========================================================
    # TOTAL HOSTS
    # =========================================================

    cur.execute("""
        SELECT COUNT(DISTINCT src_ip)
        FROM flows
    """)
    total_hosts = cur.fetchone()[0]

    # =========================================================
    # TCP
    # Database contains TCP as 6 or TCP
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
        WHERE protocol IN ('6', 'TCP')
    """)
    tcp_packets = cur.fetchone()[0]

    # =========================================================
    # UDP
    # Database contains UDP as 17 or UDP
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
        WHERE protocol IN ('17', 'UDP')
    """)
    udp_packets = cur.fetchone()[0]

    # =========================================================
    # TLS
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
        WHERE protocol = 'TLS'
    """)
    tls_packets = cur.fetchone()[0]

    # =========================================================
    # DNS
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
        WHERE protocol = 'DNS'
    """)
    dns_packets = cur.fetchone()[0]

    # =========================================================
    # BLOCKED
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
        WHERE action = 'DROP'
    """)
    blocked_packets = cur.fetchone()[0]

    # =========================================================
    # MALICIOUS / ANOMALIES
    # =========================================================

    cur.execute("""
        SELECT COUNT(*)
        FROM flows
        WHERE reputation = 'Malicious'
    """)
    anomaly_count = cur.fetchone()[0]

    # =========================================================
    # LATEST FLOW
    # =========================================================

    cur.execute("""
        SELECT *
        FROM flows
        ORDER BY id DESC
        LIMIT 1
    """)

    latest_flow = cur.fetchone()

    # =========================================================
    # PROTOCOL DISTRIBUTION
    # Convert 6 -> TCP and 17 -> UDP
    # =========================================================

    cur.execute("""
        SELECT
            CASE
                WHEN protocol IN ('6', 'TCP') THEN 'TCP'
                WHEN protocol IN ('17', 'UDP') THEN 'UDP'
                ELSE protocol
            END AS protocol_name,
            COUNT(*) AS total
        FROM flows
        GROUP BY protocol_name
        ORDER BY total DESC
    """)

    protocol_rows = cur.fetchall()

    protocol_labels = [
        row["protocol_name"]
        for row in protocol_rows
    ]

    protocol_values = [
        row["total"]
        for row in protocol_rows
    ]

    # =========================================================
    # APPLICATION DISTRIBUTION
    # =========================================================

    cur.execute("""
        SELECT
            COALESCE(NULLIF(application, ''), 'UNKNOWN') AS application,
            COUNT(*) AS total
        FROM flows
        GROUP BY application
        ORDER BY total DESC
        LIMIT 10
    """)

    application_rows = cur.fetchall()

    app_labels = [
        row["application"]
        for row in application_rows
    ]

    app_values = [
        row["total"]
        for row in application_rows
    ]

    # =========================================================
    # COUNTRY DISTRIBUTION
    # =========================================================

    cur.execute("""
        SELECT
            country,
            COUNT(*) AS total
        FROM flows
        WHERE country IS NOT NULL
          AND country != ''
        GROUP BY country
        ORDER BY total DESC
        LIMIT 10
    """)

    country_rows = cur.fetchall()

    country_labels = [
        row["country"]
        for row in country_rows
    ]

    country_values = [
        row["total"]
        for row in country_rows
    ]

    conn.close()

    # =========================================================
    # SEND UPDATE
    # =========================================================

    socketio.emit(
        "dashboard_update",
        {
            "total_packets": total_packets,
            "total_hosts": total_hosts,

            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,

            "tls_packets": tls_packets,
            "dns_packets": dns_packets,

            "blocked_packets": blocked_packets,
            "anomaly_count": anomaly_count,

            "protocol_labels": protocol_labels,
            "protocol_values": protocol_values,

            "app_labels": app_labels,
            "app_values": app_values,

            "country_labels": country_labels,
            "country_values": country_values,

            "latest_flow":
                dict(latest_flow)
                if latest_flow
                else None
        }
    )


# ============================================================
# EXPORTS
# ============================================================

@app.route("/export/csv")
@admin_required
def export_csv():
    conn = get_connection()

    try:
        df = pd.read_sql_query("SELECT * FROM flows", conn)
    finally:
        conn.close()

    filename = os.path.join(EXPORT_FOLDER, "flows.csv")
    df.to_csv(filename, index=False)

    return send_file(filename, as_attachment=True)


@app.route("/export/excel")
@admin_required
def export_excel():
    conn = get_connection()

    try:
        df = pd.read_sql_query("SELECT * FROM flows", conn)
    finally:
        conn.close()

    filename = os.path.join(EXPORT_FOLDER, "flows.xlsx")
    df.to_excel(filename, index=False)

    return send_file(filename, as_attachment=True)


@app.route("/export/json")
@admin_required
def export_json():
    conn = get_connection()

    try:
        df = pd.read_sql_query("SELECT * FROM flows", conn)
    finally:
        conn.close()

    filename = os.path.join(EXPORT_FOLDER, "flows.json")
    df.to_json(
        filename,
        orient="records",
        indent=4,
    )

    return send_file(filename, as_attachment=True)


@app.route("/export/pdf")
def export_pdf():
    if "username" not in session:
        return redirect("/login")

    conn = get_connection()

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM flows")
        rows = cur.fetchall()
    finally:
        conn.close()

    filename = os.path.join(EXPORT_FOLDER, "dpi_report.pdf")

    pdf = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("Enterprise DPI Report", styles["Heading1"])
    ]

    data = [["Source", "Destination", "Protocol", "Application"]]

    for row in rows:
        data.append(
            [
                row["src_ip"],
                row["dst_ip"],
                row["protocol"],
                row["application"],
            ]
        )

    table = Table(data)

    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ]
        )
    )

    elements.append(table)
    pdf.build(elements)

    return send_file(filename, as_attachment=True)


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found", 404


@app.errorhandler(500)
def internal_server_error(error):
    return "Internal server error", 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("ENTERPRISE DPI DASHBOARD")
    print("URL: http://127.0.0.1:5000")
    print("Database:", DB_PATH)
    print("=" * 60)

    socketio.run(
        app,
        debug=True,
        host="0.0.0.0",
        port=5000,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )