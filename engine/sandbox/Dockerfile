# CageWatch sandbox image: small, non-root, no extra tools for the agent to abuse.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Fixed non-root user (uid/gid 1000) so run_agent.sh can pass --user 1000:1000.
RUN groupadd --gid 1000 cagent \
 && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin cagent \
 && mkdir -p /work /data/authorized /secrets /agent \
 && chown cagent:cagent /work

USER 1000:1000
WORKDIR /work

# Agent code is mounted read-only at /agent at run time (see run_agent.sh).
ENTRYPOINT ["python", "/agent/agent.py"]
CMD ["--mode", "benign"]
