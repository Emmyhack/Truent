"""A small, correctly written service: parameterised SQL, argument-list
subprocess, safe YAML, secrets from the environment, secure randomness."""
import os
import secrets
import subprocess
import hashlib
import yaml
import requests
import sqlite3

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.getenv("API_KEY", "")
password_field = "password"
token_type = "Bearer"


def run(path: str) -> str:
    # Argument list, no shell: metacharacters in `path` are inert.
    return subprocess.run(["ls", "-la", path], capture_output=True, text=True).stdout


def load(cfg_file):
    with open(cfg_file) as f:
        return yaml.safe_load(f)


def user(conn: sqlite3.Connection, uid: int):
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = ?", (uid,))
    return cur.fetchone()


def fetch(url: str):
    return requests.get(url, timeout=10)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def etag(body: bytes) -> str:
    # Non-security use of MD5: a cache key.
    return hashlib.md5(body).hexdigest()


def compute():
    return eval("1 + 1")
