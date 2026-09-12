# EXPECT: gen_command_injection
# EXPECT: gen_sql_injection
# EXPECT: gen_unsafe_deserialization
# EXPECT: gen_tls_verification_disabled
import subprocess, pickle, requests

def ping(request, conn):
    host = request.args["host"]
    subprocess.run(f"ping -c 1 {host}", shell=True)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])
    state = pickle.loads(request.data)
    return requests.get(request.args["url"], verify=False)
