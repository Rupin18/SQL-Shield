# 🛡️ SQL Shield
### Detection, Exploitation, and Mitigation of SQL Injection Vulnerabilities in Web Applications

SQL Shield is an educational cybersecurity application developed to demonstrate how SQL Injection vulnerabilities can be identified, tested, understood, and mitigated in web applications.

The project combines a Flask-based web dashboard, MariaDB database integration, pattern-based SQL injection detection, parameterized SQL queries, security event logging, and downloadable PDF security reports.

> **Project Type:** Cyber Security Course — Minor Project  
> **Development Environment:** Kali Linux  
> **Testing Environment:** Authorized Local Security Lab

---

## 1. Project Objectives

- Understand SQL Injection vulnerabilities and their impact.
- Demonstrate SQL injection testing in an authorized local environment.
- Detect common SQL injection patterns in submitted inputs.
- Demonstrate secure database access using parameterized queries.
- Record security scans, findings, and security events.
- Generate downloadable security assessment reports.

## 2. Key Features

| Feature | Description |
|---|---|
| Authentication | User registration, login, and logout |
| Security Dashboard | Displays scan statistics and security indicators |
| SQL Injection Detection | Identifies common suspicious SQL patterns |
| Vulnerability Testing | Documents authorized local testing tools and environment |
| SQL Injection Mitigation | Demonstrates parameterized SQL queries |
| Security Event Logging | Records suspicious input events |
| Analytics | Displays scan activity and vulnerability statistics |
| PDF Reports | Generates downloadable security assessment reports |

## 3. Technology Stack

**Backend**
- Python
- Flask
- MySQL Connector
- MariaDB

**Frontend**
- HTML5
- CSS3
- JavaScript
- Jinja2 Templates

**Cybersecurity Testing Tools**
- Kali Linux
- Metasploitable 2
- DVWA (Damn Vulnerable Web Application)
- Burp Suite Community Edition
- SQLMap

**Reporting**
- ReportLab (PDF generation)

## 4. System Architecture

The application follows a modular architecture:

1. **Frontend Layer:** Provides the dashboard, authentication pages, detection interface, analytics, and reports.
2. **Application Layer:** Flask handles routing, authentication, detection requests, and report generation.
3. **Security Layer:** Pattern-based detection and parameterized-query mitigation.
4. **Database Layer:** MariaDB stores users, scans, vulnerabilities, and security events.
5. **Reporting Layer:** ReportLab generates PDF security assessment reports.

## 5. Database Structure

The project uses a MariaDB database named `sql_injection_lab`.

| Table | Purpose |
|---|---|
| `users` | Stores user account information and password hashes |
| `scans` | Stores scan records and target information |
| `vulnerabilities` | Stores detected vulnerability findings and severity |
| `security_events` | Records security-related events |

## 6. SQL Injection Detection

SQL Shield uses pattern-based detection to identify common suspicious SQL input patterns, including:

- UNION SELECT patterns
- OR/AND comparison patterns
- SQL comment indicators
- SLEEP-based expressions
- BENCHMARK-based expressions

Suspicious inputs are recorded as security events and associated with vulnerability findings.

**Important:** This is an educational pattern-based detector. It does not identify every possible SQL injection vulnerability and is not a replacement for a professional security testing solution.

## 7. Exploitation and Testing Methodology

The project includes an authorized local testing environment using:

- Metasploitable 2
- DVWA
- Burp Suite Community Edition
- SQLMap

The testing workflow demonstrates how SQL injection vulnerabilities can be investigated in intentionally vulnerable applications.

All exploitation exercises are restricted to systems owned by the user or explicitly authorized for testing.

## 8. SQL Injection Mitigation

The application demonstrates parameterized SQL queries to separate SQL instructions from user-supplied data.

Instead of directly inserting user input into SQL statements, the application uses parameter binding.

This reduces the risk of SQL injection caused by unsafe query construction.

## 9. Security Assessment Reports

SQL Shield provides a PDF reporting feature containing:

- Total scan count
- Vulnerability statistics
- Blocked test inputs
- Severity distribution
- Risk-based security score
- Recent security events
- Security recommendations

The risk-based score is an internal educational indicator and is not a certified security rating.

## 10. Installation and Setup

### Prerequisites

- Python 3
- MariaDB
- Kali Linux or another compatible Linux environment
- Git

### Clone the repository

```bash
git clone https://github.com/Rupin18/SQL-Shield.git
cd SQL-Shield
```

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install Flask mysql-connector-python python-dotenv reportlab
```

### Configure environment variables

Create a `.env` file in the project root:

```env
DB_HOST=localhost
DB_USER=sqlapp
DB_PASSWORD=your_database_password
DB_NAME=sql_injection_lab
SECRET_KEY=your_secret_key
```

Replace the example values with your own local configuration.

### Database setup

Create the MariaDB database and configure the required tables:

- users
- scans
- vulnerabilities
- security_events

Ensure the database credentials match your `.env` configuration.

### Run the application

```bash
python app.py
```

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

## 11. Project Structure

```text
SQL-Shield/
│
├── app.py
├── auth.py
├── db.py
├── mitigation.py
├── pdf_report.py
├── test_db.py
│
├── static/
│   ├── css/
│   │   ├── auth.css
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── analytics.html
│   ├── detection.html
│   ├── testing.html
│   ├── mitigation.html
│   ├── reports.html
│   ├── login.html
│   └── signup.html
│
├── evidence/
├── .gitignore
└── README.md
```

## 12. Security Considerations

- Never commit `.env` files or database credentials.
- Use parameterized queries for database operations.
- Restrict vulnerability testing to authorized environments.
- Do not expose intentionally vulnerable testing applications publicly.
- Disable Flask debug mode outside local development.
- Use strong passwords and secure session configuration.

## 13. Limitations

- Detection relies on predefined suspicious-pattern checks.
- Pattern-based detection may produce false positives and false negatives.
- The application is intended for educational demonstration, not production security monitoring.
- The risk-based score is an illustrative project metric.
- Local lab testing does not establish that arbitrary external applications are secure.

## 14. Future Enhancements

- Advanced SQL injection detection techniques.
- Improved input validation and security controls.
- More detailed vulnerability classification.
- Expanded security analytics.
- Automated test result integration.
- Improved reporting and audit functionality.

## 15. Disclaimer

SQL Shield is developed strictly for educational and cybersecurity learning purposes.

All vulnerability testing and exploitation must be conducted only on systems owned by the user or for which explicit authorization has been granted.

---

**Developed as a Cyber Security Course Minor Project.**

GitHub Repository: https://github.com/Rupin18/SQL-Shield
