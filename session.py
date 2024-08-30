from uuid import uuid4

from db import get_db_connection

def create_session(username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO sessions (username, id) VALUES (?, ?)",
            (username, uuid4().hex)
        )
    conn.close()

def delete_session(username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM sessions WHERE username = ?", (username,)
        )
    conn.close()

def get_session_id(username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM sessions WHERE username = ?", (username,)
        )
        row = cursor.fetchone()
    conn.close()
    return row["id"] if row else None

def get_csrf(session_id, username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT token FROM sessions WHERE username = ? AND id = ?", (username, session_id)
        )
        row = cursor.fetchone()
    conn.close()
    return row["token"] if row else None

def save_csrf(session_id, username, token):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO csrf (username, id, token) VALUES (?, ?, ?)",
            (username, session_id, token)
        )
    conn.close()