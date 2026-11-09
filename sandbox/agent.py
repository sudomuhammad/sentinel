"""Entry point inside the sandbox: run the agent for the configured provider."""

import asyncio
import importlib
import os

RUNNERS = {"anthropic": "claude_agent", "openai": "openai_agent"}

if __name__ == "__main__":
    runner = importlib.import_module(RUNNERS[os.environ["SENTINEL_PROVIDER"]])
    asyncio.run(runner.run())
