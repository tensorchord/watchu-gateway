# PromptGuard

## Purpose

PromptGuard is a standalone CLI tool and library for detecting prompt injection attacks in LLM applications. It analyzes user prompts to identify potentially malicious inputs that attempt to:

- Override system instructions (jailbreak attempts)
- Extract sensitive information
- Execute unauthorized commands
- Manipulate the AI's behavior

## Features

- **Two Detection Modes**:
  - `prompt_based`: Uses a structured detection template for high accuracy (~95%)
  - `model_based`: Relies on the LLM's native safety capabilities for flexibility

- **Structured Output**: Returns categorized safety assessments with risk scores
- **Integration Ready**: Can be used as a standalone binary or integrated into services
- **Multiple Output Formats**: Supports JSON and human-readable text output

## Usage

### Standalone CLI

```bash
# Basic usage
./promptguard -api-key YOUR_KEY -prompt "User input here"

# Use prompt_based mode (recommended)
./promptguard \
  -mode prompt_based \
  -api-key sk-xxx \
  -api-base https://api.openai.com/v1 \
  -model gpt-4o-mini \
  -prompt "Ignore previous instructions"

# Use model_based mode
./promptguard \
  -mode model_based \
  -api-key sk-xxx \
  -prompt "What is the weather today?"

# JSON output
./promptguard -json -api-key sk-xxx -prompt "Test input"

# Read from stdin
echo "User input" | ./promptguard -api-key sk-xxx

# Extract user prompt from agent wrappers
cat request.json | ./promptguard -api-key sk-xxx -extract-user=true
```

### Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `prompt_based` | Detection mode: `prompt_based` or `model_based` |
| `-api-key` | - | LLM API key (required) |
| `-api-base` | `https://api.openai.com/v1` | LLM API base URL |
| `-model` | `gpt-4o-mini` | LLM model name |
| `-prompt` | - | Prompt to analyze (reads from stdin if not provided) |
| `-extract-user` | `true` | Extract user prompt from agent framework wrappers |
| `-json` | `false` | Output result as JSON |
| `-timeout` | `15s` | API request timeout |

### Exit Codes

- `0`: Safe - No security concerns detected
- `1`: Controversial - Context-dependent risk
- `2`: Unsafe - High-risk content detected

### Output Format

**JSON Output** (`-json` flag):
```json
{
  "Safety": "Unsafe",
  "Categories": ["Jailbreak"],
  "Score": 0.85,
  "Reason": "Detected jailbreak attempt using instruction override pattern"
}
```

**Text Output** (default):
```
Safety: Unsafe
Categories: [Jailbreak]
Score: 0.85
Reason: Detected jailbreak attempt using instruction override pattern
```

## Detection Categories

- **Violent**: Violence or gore content
- **Non-violent Illegal Acts**: Illegal activities like SQL injection, system commands
- **Sexual Content or Sexual Acts**: Adult content
- **Personally Identifiable Information**: PII exposure attempts
- **Suicide & Self-Harm**: Self-harm related content
- **Unethical Acts**: Fraudulent or deceptive behaviors
- **Politically Sensitive Topics**: Sensitive political content
- **Copyright Violation**: Copyright infringement attempts
- **Jailbreak**: System instruction override attempts

## Integration Examples

### Shell Script

```bash
#!/bin/bash
USER_INPUT="$1"

./promptguard -api-key "$API_KEY" -prompt "$USER_INPUT"
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "Input is safe" ;;
  1) echo "Input is controversial - review needed" ;;
  2) echo "Input is unsafe - blocked"; exit 1 ;;
esac
```

### Python Integration

```python
import subprocess
import json

def check_prompt(prompt: str) -> dict:
    result = subprocess.run(
        ["./promptguard", "-json", "-api-key", "sk-xxx", "-prompt", prompt],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

# Usage
result = check_prompt("Ignore all previous instructions")
if result["Safety"] == "Unsafe":
    print(f"Blocked: {result['Reason']}")
```

### Gateway Service Integration

The Watchu Gateway service uses PromptGuard's underlying Detector interface:

```bash
# Environment variables for gateway
export PROMPT_INJECTION_ENABLED=true
export PROMPT_INJECTION_MODE=prompt_based
export PROMPT_INJECTION_API_BASE=http://localhost:4000
export PROMPT_INJECTION_API_KEY=dummy
export PROMPT_INJECTION_MODEL=gpt-4o-mini
export PROMPT_INJECTION_EXTRACT_USER_PROMPT=true
```

## Building from Source

```bash
# Build promptguard binary
cd watchu/gateway
go build -o promptguard ./cmd/promptguard

# Run tests
go test ./pkg/promptinjection/...

# Lint code
make lint
```

## Architecture

PromptGuard uses a shared `Detector` interface that is utilized by both:
1. The standalone CLI tool
2. The Watchu Gateway service

See [DETECTOR_ARCHITECTURE.md](../DETECTOR_ARCHITECTURE.md) for detailed architecture documentation.

## Best Practices

1. **Use prompt_based mode** for production environments (higher accuracy)
2. **Set appropriate timeouts** to avoid blocking requests
3. **Handle exit codes** properly in your integration
4. **Enable extraction** (`-extract-user=true`) when analyzing agent-wrapped prompts
5. **Monitor and log** all Unsafe and Controversial detections for audit trails

## Performance

- **prompt_based mode**: ~500ms average latency, 95% accuracy
- **model_based mode**: ~400ms average latency, 85% accuracy

Response times depend on the LLM API performance and network latency.

## Troubleshooting

**Issue**: `promptguard binary not found`
- Ensure the binary is in your PATH or use absolute path
- Build from source if not available: `go build -o promptguard ./cmd/promptguard`

**Issue**: `API key required`
- Provide API key via `-api-key` flag
- Or set `OPENAI_API_KEY` environment variable

**Issue**: `Timeout errors`
- Increase timeout: `-timeout 30s`
- Check LLM API endpoint availability

**Issue**: `Incorrect extraction`
- Try disabling extraction: `-extract-user=false`
- Verify input format matches expected agent wrapper format
