import sqlite3
from pathlib import Path
from contextlib import closing

DB_PATH = Path("db.sqlite3")

def delete_db_file():
    if DB_PATH.exists():
        DB_PATH.unlink()

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def create_db():
    delete_db_file()
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")