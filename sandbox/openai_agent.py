"""A small coding agent on OpenAI's Responses API, with two tools: bash and write_file."""

import json
import subprocess
from pathlib import Path

from common import SYSTEM, WORKSPACE, build_prompt, early_deny, emit, settings
from openai import APIError, OpenAI

OUTPUT_LIMIT = 20_000
COMMAND_TIMEOUT = 300

TOOLS = [
    {
        "type": "function",
        "name": "bash",
        "description": "Run a shell command in the repository root and return its output.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "write_file",
        "description": "Create or overwrite a file. The path is relative to the repository root.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]

INSTRUCTIONS = (
    SYSTEM
    + """
Use the bash tool to explore, run tests and read files, and write_file to change files.
Work until the task is done and the tests pass, then reply with a short summary.
"""
)


def bash(command: str) -> str:
    if reason := early_deny(command):
        emit("tool_denied", tool="bash", reason=reason)
        return f"Denied: {reason}"
    try:
        proc = subprocess.run(  # noqa: S602 - running the agent's shell is the point
            command, shell=True, cwd=WORKSPACE, capture_output=True, text=True,
            timeout=COMMAND_TIMEOUT,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return f"Timed out after {COMMAND_TIMEOUT}s"
    return f"exit code {proc.returncode}\n{proc.stdout}{proc.stderr}"[-OUTPUT_LIMIT:]


def write_file(path: str, content: str) -> str:
    target = (Path(WORKSPACE) / path).resolve()
    if not target.is_relative_to(WORKSPACE):
        return "Denied: path is outside the repository"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return f"Wrote {len(content)} characters to {path}"


HANDLERS = {"bash": bash, "write_file": write_file}


def call_tool(name: str, arguments: str) -> str:
    try:
        args = json.loads(arguments)
        emit("tool_call", tool=name, input=args)
        return HANDLERS[name](**args)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return f"Tool error: {exc}"


async def run() -> None:
    s = settings()
    client = OpenAI()  # the key is a placeholder; the proxy adds the real one
    history: list = [{"role": "user", "content": build_prompt()}]
    usage = {"input_tokens": 0, "output_tokens": 0}

    for turn in range(1, s["max_turns"] + 1):
        try:
            response = client.responses.create(
                model=s["model"],
                instructions=INSTRUCTIONS,
                input=history,
                tools=TOOLS,
                store=False,
                include=["reasoning.encrypted_content"],
            )
        except APIError as exc:  # blocked by the proxy, bad key, rate limit, ...
            emit("result", subtype="error_api", turns=turn, error=str(exc)[:500], **usage)
            raise SystemExit(1) from None
        usage["input_tokens"] += response.usage.input_tokens
        usage["output_tokens"] += response.usage.output_tokens
        history += [item.model_dump(exclude_none=True) for item in response.output]

        calls = [item for item in response.output if item.type == "function_call"]
        if not calls:
            emit("assistant_text", text=response.output_text[:2000])
            emit("result", subtype="success", turns=turn, **usage)
            return
        for call in calls:
            output = call_tool(call.name, call.arguments)
            history.append(
                {"type": "function_call_output", "call_id": call.call_id, "output": output}
            )

    emit("result", subtype="error_max_turns", turns=s["max_turns"], **usage)
