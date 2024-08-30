from hmac import compare_digest
from hashlib import pbkdf2_hmac
from secrets import token_bytes
from db import get_db_connection
from sqlite3 import Row

## security flaw: CWE-327: Use of a Broken or Risky Cryptographic Algorithm
## md5 is considered broken and should not be used
HASH_ALGORITHM = "md5"
# HASH_ALGORITHM = "sha256"

def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = token_bytes(16)
    hash = pbkdf2_hmac(HASH_ALGORITHM, password.encode("utf-8"), salt, 100000)
    return salt, hash

def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    input_hash = pbkdf2_hmac(HASH_ALGORITHM, password.encode("utf-8"), salt, 100000)
    return compare_digest(stored_hash, input_hash)

def create_user(name: str, password: str) -> None:
    salt, hash = hash_password(password)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, hash, salt) VALUES (?, ?, ?)", (name, hash, salt))
    conn.close()

def get_user(name: str) -> Row:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
        user = cursor.fetchone()
    conn.close()
    return user
    
def check_user(name: str, password: str) -> bool:
    user = get_user(name)
    if not user:
        return False
    return verify_password(password, user["salt"], user["hash"])