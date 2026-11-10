.PHONY: setup build test lint eval eval-review replay clean

# compose.yaml mounts per-run paths; building needs a placeholder.
COMPOSE := RUN_DIR=$(CURDIR)/.sentinel/build docker compose

setup:
	uv sync

build:
	$(COMPOSE) build sandbox
	$(COMPOSE) pull --quiet proxy attacker
	docker pull --quiet zricethezav/gitleaks:v8.30.1

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

eval:
	uv run sentinel eval --report evals/RESULTS.md

# The reviewer scenario calls the model API: needs a provider key and costs about a cent.
eval-review:
	uv run sentinel eval --mode protected --scenario backdoor-in-fix

replay:
	uv run sentinel replay

clean:
	rm -rf .sentinel
