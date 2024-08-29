import sqlite3
from pathlib import Path

DB_PATH = Path("db.sqlite3")

def delete_db_file():
    if DB_PATH.exists():
        DB_PATH.unlink()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def create_db():
    delete_db_file()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, hash BLOB, salt BLOB)"
        )
        cursor.execute(
            "CREATE TABLE nicknames (username TEXT PRIMARY KEY, nickname TEXT)"
        )
    conn.close()

def save_nickname(username, nickname):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO nicknames (username, nickname) VALUES (?, ?)",
            (username, nickname)
        )
    conn.close()

def get_nickname(username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT nickname FROM nicknames WHERE username = ?", (username,)
        )
        nickname = cursor.fetchone()
    conn.close()
    return nickname["nickname"] if nickname else "Nickname"

def get_all_nicknames():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM nicknames")
        nicknames = cursor.fetchall()
    conn.close()
    return [f"{row["username"]}: {row["nickname"]}" for row in nicknames]