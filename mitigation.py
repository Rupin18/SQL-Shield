
from db import get_db_connection


def find_user_by_username(username):
    """
    Securely retrieve a user using a parameterized SQL query.
    User input is never concatenated into the SQL statement.
    """

    if not isinstance(username, str) or not username.strip():
        return None

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Secure parameterized query
        query = """
            SELECT id, username, role, created_at
            FROM users
            WHERE username = %s
            LIMIT 1
        """

        cursor.execute(query, (username.strip(),))

        return cursor.fetchone()

    except Exception:
        raise

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()
