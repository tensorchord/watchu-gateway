package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/tensorchord/watchu/gateway/pkg/promptinjection"
)

func main() {
	// Command line flags
	var (
		mode        = flag.String("mode", "prompt_based", "Detection mode: prompt_based (use template) or model_based (direct prompt)")
		apiBase     = flag.String("api-base", "https://api.openai.com/v1", "LLM API base URL")
		apiKey      = flag.String("api-key", "", "LLM API key")
		model       = flag.String("model", "gpt-4o-mini", "LLM model name")
		prompt      = flag.String("prompt", "", "Prompt to analyze (if not provided, reads from stdin)")
		extractUser = flag.Bool("extract-user", true, "Extract user prompt from agent wrappers")
		jsonOutput  = flag.Bool("json", false, "Output result as JSON")
		timeout     = flag.Duration("timeout", 15*time.Second, "API request timeout")
	)

	flag.Parse()

	// Get prompt from stdin if not provided
	promptText := *prompt
	if promptText == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Failed to read from stdin: %v", err)
		}
		promptText = string(data)
	}

	if promptText == "" {
		log.Fatal("No prompt provided. Use -prompt flag or pipe input to stdin.")
	}

	// Extract user prompt if enabled
	if *extractUser {
		if extracted := promptinjection.ExtractPromptFromHTTPBody(promptText, true); extracted != "" {
			promptText = extracted
		}
	}

	// Check API key
	if *apiKey == "" {
		log.Fatal("API key required. Use -api-key flag or set OPENAI_API_KEY env var")
	}

	// Normalize mode
	normalizedMode := strings.ToLower(*mode)
	if normalizedMode != "prompt_based" && normalizedMode != "model_based" {
		log.Fatalf("Invalid mode: %s. Use prompt_based or model_based", *mode)
	}

	// Create detector using shared interface
	client := promptinjection.NewClient(*apiBase, *apiKey, *timeout)
	detector := promptinjection.NewDetector(client, *model, normalizedMode)

	// Run detection
	ctx := context.Background()
	result, err := detector.Detect(ctx, promptText)
	if err != nil {
		log.Fatalf("Detection failed: %v", err)
	}

	// Output result
	if *jsonOutput {
		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		fmt.Println(string(output))
	} else {
		fmt.Printf("Safety: %s\n", result.Safety)
		fmt.Printf("Categories: %v\n", result.Categories)
		fmt.Printf("Score: %.2f\n", result.Score)
		fmt.Printf("Reason: %s\n", result.Reason)
	}

	// Exit with appropriate code
	switch result.Safety {
	case "Unsafe":
		os.Exit(2)
	case "Controversial":
		os.Exit(1)
	default:
		os.Exit(0)
	}
}
