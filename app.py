
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from db import get_db_connection
from mitigation import find_user_by_username
from auth import auth, login_required
from pdf_report import generate_pdf_report

app = Flask(__name__)

from dotenv import load_dotenv
import os

load_dotenv()

app.secret_key = os.getenv("SECRET_KEY")
app.register_blueprint(auth)

@app.route("/")
@login_required
def home():
    connection = None

    try:
        connection = get_db_connection()
        return render_template("index.html")

    except Exception:
        app.logger.exception("Dashboard database connection failed")
        return "Database connection failed.", 500

    finally:
        if connection and connection.is_connected():
            connection.close()


@app.route("/api/dashboard")
@login_required
def dashboard_api():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Total completed scans
        cursor.execute("""
            SELECT COUNT(*) AS total_scans
            FROM scans
        """)
        total_scans = cursor.fetchone()["total_scans"]

        # Total vulnerabilities
        cursor.execute("""
            SELECT COUNT(*) AS total_vulnerabilities
            FROM vulnerabilities
        """)
        total_vulnerabilities = cursor.fetchone()["total_vulnerabilities"]

        # Blocked test inputs
        cursor.execute("""
            SELECT COUNT(*) AS blocked_inputs
            FROM security_events
            WHERE event_type = 'blocked_input'
        """)
        blocked_inputs = cursor.fetchone()["blocked_inputs"]

        # Vulnerability severity counts
        cursor.execute("""
            SELECT
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) AS low
            FROM vulnerabilities
        """)

        severity = cursor.fetchone()

        severity = {
            key: severity[key] or 0
            for key in ("critical", "high", "medium", "low")
        } 

        # Risk-based security score
        risk_deduction = (
            severity["critical"] * 25 +
            severity["high"] * 15 +
            severity["medium"] * 8 +
            severity["low"] * 3
        )

        security_score = max(0, 100 - risk_deduction)

        # Daily scan activity for the last 7 days
        cursor.execute("""
            SELECT
                DATE(created_at) AS scan_date,
                COUNT(*) AS total
            FROM scans
            WHERE created_at >= CURDATE() - INTERVAL 6 DAY
            GROUP BY DATE(created_at)
            ORDER BY scan_date ASC
        """)

        activity = cursor.fetchall()

        # Latest security events
        cursor.execute("""
            SELECT
                event_type AS title,
                description,
                DATE_FORMAT(created_at, '%d %b %H:%i') AS time
            FROM security_events
            ORDER BY created_at DESC
            LIMIT 10
        """)

        events = cursor.fetchall()

        return jsonify({
            "stats": {
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulnerabilities,
                "blocked_inputs": blocked_inputs,
                "security_score": security_score,
            },
            "severity": severity,
            "events": events,
            "activity": activity
        })

    except Exception:
        app.logger.exception("Dashboard API error")
        return jsonify({
            "error": "Unable to retrieve dashboard data."
        }), 500

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


@app.route("/api/detect", methods=["POST"])
@login_required
def detect_sql_injection():
    data = request.get_json(silent=True) or {}
    user_input = data.get("input", "")

    if not isinstance(user_input, str) or not user_input.strip():
        return jsonify({
            "success": False,
            "message": "Please enter some text to analyze."
        }), 400

    if len(user_input) > 1000:
        return jsonify({
            "success": False,
            "message": "Input must not exceed 1000 characters."
        }), 400

    import re

    patterns = [
        r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b",
        r"(?i)\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
        r"(?i)\bAND\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
        r"(?i)(?:--|#)\s*$",
        r"/\*.*?\*/",
        r"(?i)\bSLEEP\s*\(",
        r"(?i)\bBENCHMARK\s*\("
    ]

    detected = any(
        re.search(pattern, user_input)
        for pattern in patterns
    )

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO scans (scan_type, target, status)
            VALUES (%s, %s, %s)
        """, (
            "SQL Injection Detection",
            "SQL Shield Local Application",
            "completed"
        ))

        scan_id = cursor.lastrowid
        connection.commit()
        if detected:
            cursor.execute("""
                INSERT INTO vulnerabilities
                (scan_id, vulnerability_type, severity, description)
                VALUES (%s, %s, %s, %s)
            """, (
                scan_id,
                "SQL Injection Pattern",
                "High",
                "Suspicious SQL injection pattern detected in submitted input."
            ))
            cursor.execute("""
                INSERT INTO security_events
                (event_type, description)
                VALUES (%s, %s)
            """, (
                "blocked_input",
                "Suspicious SQL injection pattern detected."
            ))

            connection.commit()

            return jsonify({
                "success": True,
                "detected": True,
                "message": "Suspicious SQL injection pattern detected.",
                "action": "Input rejected and event recorded."
            })

        return jsonify({
            "success": True,
            "detected": False,
            "message": "No recognized SQL injection pattern detected.",
            "action": "Input passed this basic pattern check."
        })

    except Exception:
        app.logger.exception("SQL detection error")
        return jsonify({
            "success": False,
            "message": "Detection service temporarily unavailable."
        }), 500

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()

@app.route("/api/mitigation-test", methods=["POST"])
@login_required
def mitigation_test():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")

    if not isinstance(username, str) or not username.strip():
        return jsonify({
            "success": False,
            "message": "Please enter a username."
        }), 400

    if len(username) > 50:
        return jsonify({
            "success": False,
            "message": "Username must not exceed 50 characters."
        }), 400

    try:
        user = find_user_by_username(username)

        if user:
            return jsonify({
                "success": True,
                "protected": True,
                "found": True,
                "message": "User found using a parameterized SQL query."
            })

        return jsonify({
            "success": True,
            "protected": True,
            "found": False,
            "message": "No matching user found. Input was treated as data, not SQL."
        })

    except Exception:
        app.logger.exception("Secure query test failed")
        return jsonify({
            "success": False,
            "message": "Secure database test failed."
        }), 500

@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html")


@app.route("/detection")
@login_required
def detection():
    return render_template("detection.html")


@app.route("/testing")
@login_required
def testing():
    return render_template("testing.html")


@app.route("/mitigation")
@login_required
def mitigation():
    return render_template("mitigation.html")


@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html")

@app.route("/download-report")
@login_required
def download_report():
    try:
        pdf_data = generate_pdf_report()

        from io import BytesIO

        return send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="SQL_Shield_Security_Report.pdf"
        )

    except Exception:
        app.logger.exception("PDF report generation failed")
        return "Unable to generate security report.", 500

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
