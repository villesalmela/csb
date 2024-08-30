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
            "CREATE TABLE users (name TEXT PRIMARY KEY, hash BLOB, salt BLOB)"
        )
        cursor.execute(
            "CREATE TABLE nicknames (username TEXT PRIMARY KEY, nickname TEXT)"
        )
        cursor.execute(
            "CREATE TABLE sessions (username TEXT PRIMARY KEY, id UUID, token TEXT)"
        )
    conn.close()



