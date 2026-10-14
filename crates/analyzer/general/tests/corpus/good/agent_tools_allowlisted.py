# An agent that is NOT autonomous command execution: the model's output only
# selects a tool by name from a fixed allow-list, and each tool runs a fixed
# command with validated, structured arguments. Model text never reaches a shell.
import subprocess
from openai import OpenAI

client = OpenAI()

ALLOWED = {"list_files", "read_metric"}


def run_tool(name: str, path: str) -> str:
    if name == "list_files":
        return subprocess.run(["ls", "-la", _safe(path)], capture_output=True, text=True).stdout
    if name == "read_metric":
        return subprocess.run(["cat", _safe(path)], capture_output=True, text=True).stdout
    raise ValueError("unknown tool")


def _safe(path: str) -> str:
    if not path.isalnum():
        raise ValueError("bad path")
    return path


def step(goal):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": goal}])
    choice = resp.choices[0].message.content
    if choice in ALLOWED:
        return run_tool(choice, "metrics")
    return "no tool"
