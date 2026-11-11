
from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)

from db import get_db_connection


def generate_pdf_report():
    buffer = BytesIO()
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Fetch scan statistics
        cursor.execute("""
            SELECT COUNT(*) AS total_scans
            FROM scans
        """)
        total_scans = cursor.fetchone()["total_scans"]

        # Fetch vulnerability statistics
        cursor.execute("""
            SELECT COUNT(*) AS total_vulnerabilities
            FROM vulnerabilities
        """)
        total_vulnerabilities = cursor.fetchone()["total_vulnerabilities"]

        # Fetch blocked inputs
        cursor.execute("""
            SELECT COUNT(*) AS blocked_inputs
            FROM security_events
            WHERE event_type = 'blocked_input'
        """)
        blocked_inputs = cursor.fetchone()["blocked_inputs"]

        # Fetch vulnerability severity
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

        # Calculate educational risk-based score
        risk_deduction = (
            severity["critical"] * 25
            + severity["high"] * 15
            + severity["medium"] * 8
            + severity["low"] * 3
        )
        security_score = max(0, 100 - risk_deduction)

        # Fetch recent security events
        cursor.execute("""
            SELECT
                event_type,
                description,
                created_at
            FROM security_events
            ORDER BY created_at DESC
            LIMIT 10
        """)
        events = cursor.fetchall()

        # Create PDF document
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=25,
            textColor=colors.HexColor("#102a43"),
            alignment=TA_CENTER,
            spaceAfter=6
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#526779"),
            alignment=TA_CENTER,
            spaceAfter=15
        )

        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#087e9b"),
            spaceBefore=14,
            spaceAfter=8
        )

        normal_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontSize=9,
            leading=13
        )

        story = []

        # Report heading
        story.append(Paragraph("SQL SHIELD", title_style))
        story.append(
            Paragraph("SECURITY ASSESSMENT REPORT", subtitle_style)
        )

        story.append(HRFlowable(
            width="100%",
            color=colors.HexColor("#22b8cf"),
            thickness=2
        ))
        story.append(Spacer(1, 10))

        story.append(Paragraph(
            "Report generated: " + datetime.now().strftime(
                "%d %B %Y, %I:%M %p"
            ),
            normal_style
        ))

        story.append(Paragraph(
            "Assessment environment: Authorized local security lab",
            normal_style
        ))

        # Assessment summary
        story.append(Paragraph("1. Assessment Summary", heading_style))

        summary_data = [
            ["Metric", "Result"],
            ["Total Scans", str(total_scans)],
            ["Vulnerabilities Found", str(total_vulnerabilities)],
            ["Blocked Test Inputs", str(blocked_inputs)],
            ["Risk-Based Security Score", str(security_score) + "%"]
        ]

        summary_table = Table(
            summary_data,
            colWidths=[95 * mm, 65 * mm]
        )

        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#102a43")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5,
             colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#edf5fa")]),
            ("PADDING", (0, 0), (-1, -1), 8)
        ]))

        story.append(summary_table)

        # Vulnerability severity
        story.append(Paragraph(
            "2. Vulnerability Severity Distribution",
            heading_style
        ))

        severity_data = [
            ["Severity", "Findings"],
            ["Critical", str(severity["critical"])],
            ["High", str(severity["high"])],
            ["Medium", str(severity["medium"])],
            ["Low", str(severity["low"])]
        ]

        severity_table = Table(
            severity_data,
            colWidths=[95 * mm, 65 * mm]
        )

        severity_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#102a43")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5,
             colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#edf5fa")]),
            ("PADDING", (0, 0), (-1, -1), 8)
        ]))

        story.append(severity_table)

        # Recent events
        story.append(Paragraph(
            "3. Recent Security Events",
            heading_style
        ))

        if events:
            event_data = [["Event Type", "Description", "Date"]]

            for event in events:
                description = Paragraph(
                    str(event["description"] or "No description"),
                    normal_style
                )

                event_date = event["created_at"]
                if event_date:
                    event_date = event_date.strftime("%d-%m-%Y %H:%M")
                else:
                    event_date = "Unknown"

                event_data.append([
                    str(event["event_type"]),
                    description,
                    event_date
                ])

            event_table = Table(
                event_data,
                colWidths=[38 * mm, 82 * mm, 40 * mm],
                repeatRows=1
            )

            event_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0),
                 colors.HexColor("#102a43")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5,
                 colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#edf5fa")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6)
            ]))

            story.append(event_table)
        else:
            story.append(Paragraph(
                "No security events have been recorded.",
                normal_style
            ))

        # Recommendations
        story.append(Paragraph(
            "4. Security Recommendations",
            heading_style
        ))

        recommendations = [
            "Use parameterized SQL queries for database operations.",
            "Validate and normalize user input.",
            "Apply least-privilege database permissions.",
            "Use safe error handling and avoid exposing database details.",
            "Perform regular security testing on authorized systems."
        ]

        for recommendation in recommendations:
            story.append(Paragraph(
                "• " + recommendation,
                normal_style
            ))
            story.append(Spacer(1, 4))

        story.append(Spacer(1, 15))
        story.append(HRFlowable(
            width="100%",
            color=colors.HexColor("#22b8cf"),
            thickness=1
        ))

        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "Generated by SQL Shield | Academic Security Project",
            subtitle_style
        ))

        story.append(Paragraph(
            "Educational assessment only. The score is an internal "
            "risk-based indicator, not a certified security rating. "
            "Pattern-based detection does not identify every SQL "
            "Injection vulnerability.",
            normal_style
        ))

        document.build(story)

        buffer.seek(0)
        return buffer.getvalue()

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()
