import re
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection


from functools import wraps


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))

        return view(*args, **kwargs)

    return wrapped_view


auth = Blueprint("auth", __name__)


@auth.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth.signup"))
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.signup"))

        if len(username) < 3 or len(username) > 50:
            flash("Username must contain 3–50 characters.", "error")
            return redirect(url_for("auth.signup"))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("auth.signup"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("auth.signup"))

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute("""
                SELECT id FROM users
                WHERE username = %s OR email = %s
                LIMIT 1
            """, (username, email))

            if cursor.fetchone():
                flash("Username or email already registered.", "error")
                return redirect(url_for("auth.signup"))

            password_hash = generate_password_hash(password)

            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
            """, (username, email, password_hash, "user"))

            connection.commit()

            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("auth.login"))

        except Exception:
            if connection:
                connection.rollback()

            auth.logger.exception("Signup failed")
            flash("Registration failed. Please try again.", "error")

        finally:
            if cursor:
                cursor.close()

            if connection and connection.is_connected():
                connection.close()

    return render_template("signup.html")


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, username, email, password_hash, role
                FROM users
                WHERE username = %s OR email = %s
                LIMIT 1
            """, (identity, identity.lower()))

            user = cursor.fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]

                return redirect(url_for("home"))

            flash("Invalid username/email or password.", "error")

        except Exception:
            auth.logger.exception("Login failed")
            flash("Login service temporarily unavailable.", "error")

        finally:
            if cursor:
                cursor.close()

            if connection and connection.is_connected():
                connection.close()

    return render_template("login.html")


@auth.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
