from db import get_db_connection

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
        row = cursor.fetchone()
    conn.close()
    return row["nickname"] if row else "Nickname"

def get_all_nicknames():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM nicknames")
        nicknames = cursor.fetchall()
    conn.close()
    return [f"{row["username"]}: {row["nickname"]}" for row in nicknames]