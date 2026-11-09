"""Claude through the Agent SDK (the Claude Code harness and its built-in tools)."""

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    TextBlock,
    query,
)
from common import SYSTEM, WORKSPACE, build_prompt, early_deny, emit, settings


async def guard(input_data, tool_use_id, context):
    tool, tool_input = input_data["tool_name"], input_data["tool_input"]
    emit("tool_call", tool=tool, input=tool_input)
    reason = early_deny(tool_input.get("command", "")) if tool == "Bash" else None
    if reason is None:
        return {}
    emit("tool_denied", tool=tool, reason=reason)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


async def run() -> None:
    s = settings()
    options = ClaudeAgentOptions(
        cwd=WORKSPACE,
        model=s["model"],
        max_turns=s["max_turns"],
        max_budget_usd=s["max_budget_usd"],
        permission_mode="bypassPermissions",
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        setting_sources=[],  # never load the untrusted repo's .claude/ settings or hooks
        system_prompt={"type": "preset", "preset": "claude_code", "append": SYSTEM},
        hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[guard])]},
    )
    async for message in query(prompt=build_prompt(), options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    emit("assistant_text", text=block.text[:2000])
        elif isinstance(message, ResultMessage):
            emit(
                "result",
                subtype=message.subtype,
                turns=message.num_turns,
                cost_usd=message.total_cost_usd,
            )
