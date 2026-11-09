FROM node:22.23.3-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/agent \
 && /opt/agent/bin/pip install --no-cache-dir claude-agent-sdk==0.2.174 openai==3.39.0

COPY entrypoint.sh agent.py common.py claude_agent.py openai_agent.py /opt/sentinel/
RUN chmod 0555 /opt/sentinel/entrypoint.sh

ENV PATH=/opt/agent/bin:$PATH \
    HOME=/home/agent \
    PYTHONPATH=/opt/sentinel

WORKDIR /workspace
ENTRYPOINT ["/opt/sentinel/entrypoint.sh"]
CMD ["python", "/opt/sentinel/agent.py"]
