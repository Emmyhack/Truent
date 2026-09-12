# EXPECT: gen_sql_injection
# EXPECT: gen_command_injection
"""Injection reached across several lines — no sink line contains a source."""
from flask import request


def lookup():
    uid = request.args["id"]
    query = "SELECT * FROM users WHERE id = " + uid
    cur.execute(query)


def ping():
    host = request.form["host"]
    cmd = "ping -c 1 " + host
    os.system(cmd)
