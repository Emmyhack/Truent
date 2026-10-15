# EXPECT: gen_agent_command_execution
import os
from openai import OpenAI

client = OpenAI()


def autonomous_step(goal):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": goal}],
    )
    command = resp.choices[0].message.content
    # The model decides the command and we run it — an attacker who steers
    # the model steers this host.
    os.system(command)
