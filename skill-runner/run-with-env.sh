#!/bin/bash

# 设置 skill-runner 配置
export SKILL_RUNNER_DOCKER_IMAGE="ghcr.io/tensorchord/watchu-claude-code-agent:latest"
export SKILL_RUNNER_DOCKER_COMMAND="claude --dangerously-skip-permissions --output-format stream-json --verbose -p"
export SKILL_RUNNER_LLM_BASE_URL=http://127.0.0.1:4000
export SKILL_RUNNER_LLM_API_KEY=dummy

# 设置要传递给 Docker 容器的环境变量（用逗号分隔的 KEY=value 对）
export SKILL_RUNNER_PASS_ENV_VARS="ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic,ANTHROPIC_AUTH_TOKEN=xxx.or85XlLKm9vBFFTC,API_TIMEOUT_MS=3000000,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1,ANTHROPIC_DEFAULT_OPUS_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_SONNET_MODEL=GLM-4.7,ANTHROPIC_DEFAULT_HAIKU_MODEL=GLM-4.5-Air"

echo "=== Starting skill-runner with direct env vars ==="
echo "SKILL_RUNNER_PASS_ENV_VARS=$SKILL_RUNNER_PASS_ENV_VARS"
echo ""

cd /home/xieyuandong/llm-observability/watchu/.worktrees/skill-security-plan/skill-runner
./skill-runner
