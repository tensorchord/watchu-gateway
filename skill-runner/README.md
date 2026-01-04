# Skill Runner

HTTP service that executes claude-code skills in local, Docker, or Kubernetes modes.

## Endpoints

- `POST /run` — start a run
- `GET /runs/{id}` — get run status
- `GET /health`

## Environment Variables

- `SKILL_RUNNER_ADDR` (default `:8091`)
- `SKILL_RUNNER_LOCAL_CMD` (default `claude-code`)
- `SKILL_RUNNER_LOCAL_ARGS`
- `SKILL_RUNNER_DOCKER_CMD` (default `docker`)
- `SKILL_RUNNER_DOCKER_IMAGE`
- `SKILL_RUNNER_DOCKER_ARGS`
- `SKILL_RUNNER_DOCKER_ENTRYPOINT`
- `SKILL_RUNNER_DOCKER_COMMAND`
- `SKILL_RUNNER_K8S_CMD` (default `kubectl`)
- `SKILL_RUNNER_K8S_NAMESPACE` (default `default`)
- `SKILL_RUNNER_K8S_IMAGE`
- `SKILL_RUNNER_K8S_TTL_SECONDS` (default `600`)
- `SKILL_RUNNER_K8S_CPU`
- `SKILL_RUNNER_K8S_MEMORY`
- `SKILL_RUNNER_K8S_COMMAND`
- `SKILL_RUNNER_EXEC_TIMEOUT` (default `30m`)

## Notes

- Runner injects skill metadata into environment variables (e.g. `SKILL_SOURCE_REF`, `SKILL_PROMPT`).
- For Docker/K8s, mount or bake in the skill artifact; `SKILL_ARTIFACT_PATH` is passed through.
