package parser

import (
	"bufio"
	"strings"
)

// AgentType defines different Agent types
type AgentType string

const (
	AgentTypeClaudeCode AgentType = "claude-code"
	AgentTypeCodex      AgentType = "codex"
	AgentTypeGemini     AgentType = "gemini"
)

// Event represents an event during execution
type Event interface {
	Type() string
	Timestamp() string
	ToJSON() ([]byte, error)
}

// RunnerOutputParser is the abstract interface for parsing runner output
// Different agent types have different implementations
type RunnerOutputParser interface {
	// Parse parses runner output into a list of events
	Parse(runnerOutput string) ([]Event, error)

	// ParseEvent parses a single event
	ParseEvent(line string) (Event, error)

	// GetAgentType returns the agent type supported by this parser
	GetAgentType() AgentType
}

// BaseParser provides common parsing functionality
type BaseParser struct {
	agentType AgentType
}

// ParseLines provides common line-by-line parsing logic (NDJSON)
func ParseLines(runnerOutput string, parseFunc func(string) (Event, error)) ([]Event, error) {
	events := make([]Event, 0)
	scanner := bufio.NewScanner(strings.NewReader(runnerOutput))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		event, err := parseFunc(line)
		if err != nil {
			// Log error but continue parsing
			continue
		}

		if event != nil {
			events = append(events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}
