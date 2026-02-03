package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/securityinsight"
	"github.com/tensorchord/watchu/gateway/pkg/threatinsight"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "prompt":
		runPromptCommand(os.Args[2:])
	case "threat":
		runThreatCommand(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand '%s'\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Security Insight CLI - Unified security analysis tool

Usage:
  securityinsight <command> [options]

Commands:
  prompt      Run prompt injection detection
  threat      Run threat insight analysis
  help        Show this help message

Global Options:
  --pg-dsn string       PostgreSQL DSN (required)
  --base-url string     LLM API base URL (default: OPENAI_BASE_URL env or https://api.openai.com/v1)
  --api-key string      LLM API key (default: OPENAI_API_KEY env)
  --model string        LLM model name (default: gpt-4o)
  --timeout duration    LLM API timeout (default: 120s)
  --verbose             Verbose output

Prompt Injection Detection Options:
  --host string         Host to analyze (required)
  --since string        Start time in RFC3339 format (required)
  --until string        End time in RFC3339 format (required)
  --mode string         Detection mode: prompt_based or model_based (default: prompt_based)

Threat Insight Analysis Options:
  --root-exec-id string Root execution ID to analyze (required)
  --save                Save analysis result to database (default: true)

Examples:
  # Prompt injection detection
  securityinsight prompt --pg-dsn="postgres://..." --host="api-server-1" \
    --since="2024-01-01T00:00:00Z" --until="2024-01-02T00:00:00Z"

  # Threat insight analysis
  securityinsight threat --pg-dsn="postgres://..." \
    --root-exec-id="c9a8f5c7-4d3e-11ef-a1b2-0242ac120002"
`)
}

func runPromptCommand(args []string) {
	fs := flag.NewFlagSet("prompt", flag.ExitOnError)

	pgDSN := fs.String("pg-dsn", "", "PostgreSQL DSN (required)")
	host := fs.String("host", "", "Host to analyze (required)")
	since := fs.String("since", "", "Start time in RFC3339 format (required)")
	until := fs.String("until", "", "End time in RFC3339 format (required)")
	mode := fs.String("mode", "prompt_based", "Detection mode: prompt_based or model_based")
	baseURL := fs.String("base-url", "", "LLM API base URL (default: OPENAI_BASE_URL env)")
	apiKey := fs.String("api-key", "", "LLM API key (default: OPENAI_API_KEY env)")
	model := fs.String("model", "gpt-4o", "LLM model name")
	timeout := fs.Duration("timeout", 120*time.Second, "LLM API timeout")
	verbose := fs.Bool("verbose", false, "Verbose output")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, queries := connectDatabase(ctx, *pgDSN)
	defer pool.Close()

	runPromptMode(ctx, queries, *host, *since, *until, *mode,
		getBaseURL(*baseURL), getAPIKey(*apiKey), *model, *timeout, *verbose)
}

func runThreatCommand(args []string) {
	fs := flag.NewFlagSet("threat", flag.ExitOnError)

	pgDSN := fs.String("pg-dsn", "", "PostgreSQL DSN (required)")
	rootExecID := fs.String("root-exec-id", "", "Root execution ID to analyze (required)")
	saveResult := fs.Bool("save", true, "Save analysis result to database")
	baseURL := fs.String("base-url", "", "LLM API base URL (default: OPENAI_BASE_URL env)")
	apiKey := fs.String("api-key", "", "LLM API key (default: OPENAI_API_KEY env)")
	model := fs.String("model", "gpt-4o", "LLM model name")
	timeout := fs.Duration("timeout", 120*time.Second, "LLM API timeout")
	verbose := fs.Bool("verbose", false, "Verbose output")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, queries := connectDatabase(ctx, *pgDSN)
	defer pool.Close()

	runThreatMode(ctx, queries, *rootExecID, *saveResult,
		getBaseURL(*baseURL), getAPIKey(*apiKey), *model, *timeout, *verbose)
}

func connectDatabase(ctx context.Context, dsn string) (*pgxpool.Pool, *sqlc.Queries) {
	if dsn == "" {
		fmt.Fprintf(os.Stderr, "Error: --pg-dsn is required\n")
		os.Exit(1)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to PostgreSQL: %v\n", err)
		os.Exit(1)
	}

	return pool, sqlc.New(pool)
}

func getBaseURL(baseURL string) string {
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
	}
	return baseURL
}

func getAPIKey(apiKey string) string {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	return apiKey
}

func runPromptMode(ctx context.Context, queries *sqlc.Queries, host, sinceStr, untilStr, mode, baseURL, apiKey, model string, timeout time.Duration, verbose bool) {
	if host == "" {
		fmt.Fprintf(os.Stderr, "Error: --host is required for prompt mode\n")
		os.Exit(1)
	}

	if sinceStr == "" || untilStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --since and --until are required for prompt mode\n")
		os.Exit(1)
	}

	if mode != "prompt_based" && mode != "model_based" {
		fmt.Fprintf(os.Stderr, "Error: --mode must be either 'prompt_based' or 'model_based'\n")
		os.Exit(1)
	}

	since, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing --since: %v\n", err)
		os.Exit(1)
	}

	until, err := time.Parse(time.RFC3339, untilStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing --until: %v\n", err)
		os.Exit(1)
	}

	// Create security insight service
	svc, err := securityinsight.NewService(queries, securityinsight.Options{
		PromptInjectionEnabled:    true,
		PromptInjectionAPIBase:    baseURL,
		PromptInjectionAPIKey:     apiKey,
		PromptInjectionModel:      model,
		PromptInjectionMode:       mode,
		PromptInjectionTimeout:    timeout,
		PromptInjectionBatchSize:  10,
		PromptInjectionMaxRetries: 3,
		PromptInjectionSampleRate: 1.0,
	}, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create security insight service: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Running prompt injection detection for host '%s' from %s to %s\n", host, since.Format(time.RFC3339), until.Format(time.RFC3339))
	}

	err = svc.DetectPromptInjection(ctx, host, since, until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Prompt injection detection failed: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Println("Prompt injection detection completed successfully")
	}
}

func runThreatMode(ctx context.Context, queries *sqlc.Queries, rootExecID string, save bool, baseURL, apiKey, model string, timeout time.Duration, verbose bool) {
	if rootExecID == "" {
		fmt.Fprintf(os.Stderr, "Error: --root-exec-id is required for threat mode\n")
		os.Exit(1)
	}

	// Create security insight service
	svc, err := securityinsight.NewService(queries, securityinsight.Options{
		ThreatInsightEnabled: true,
		ThreatInsightBaseURL: baseURL,
		ThreatInsightAPIKey:  apiKey,
		ThreatInsightModel:   model,
		ThreatInsightTimeout: timeout,
	}, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create security insight service: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Analyzing threat for root_exec_id: %s\n", rootExecID)
	}

	result, err := svc.AnalyzeThreatByRootExecID(ctx, rootExecID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Threat analysis failed: %v\n", err)
		os.Exit(1)
	}

	// Output result as JSON
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal result: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))

	// Save to database if requested
	if save {
		if verbose {
			fmt.Printf("\nSaving analysis result to database...\n")
		}

		err = threatinsight.SaveAnalysisResult(ctx, queries, rootExecID, pgtype.UUID{}, result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to save result: %v\n", err)
		} else if verbose {
			fmt.Println("Result saved successfully")
		}
	}

	// Exit with appropriate code based on threat level
	switch result.ThreatLevel {
	case 0:
		os.Exit(0) // Safe
	case 1:
		os.Exit(1) // Low/Medium threat
	case 2:
		os.Exit(2) // Critical threat
	default:
		os.Exit(0)
	}
}
