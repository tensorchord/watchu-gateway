package claudecode

import (
	"encoding/json"
	"fmt"
	"time"
)

// Parser implements Claude Code Agent output parser
type Parser struct {
	agentType string
}

// NewParser creates a Claude Code parser
func NewParser() *Parser {
	return &Parser{
		agentType: "claude-code",
	}
}

// GetAgentType returns the agent type
func (p *Parser) GetAgentType() string {
	return p.agentType
}

// Parse parses runner output into a list of events
func (p *Parser) Parse(runnerOutput string) ([]*Event, error) {
	events := make([]*Event, 0)
	lines := splitLines(runnerOutput)

	for _, line := range lines {
		line = trimSpace(line)
		if line == "" {
			continue
		}

		event, err := p.ParseEvent(line)
		if err != nil {
			continue
		}

		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

// ParseEvent parses a single event
func (p *Parser) ParseEvent(line string) (*Event, error) {
	var rawEvent map[string]interface{}
	if err := json.Unmarshal([]byte(line), &rawEvent); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	eventType, ok := rawEvent["type"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid event type")
	}

	switch eventType {
	case "system":
		return p.parseSystemEvent(rawEvent)
	case "assistant":
		return p.parseAssistantEvent(rawEvent)
	case "user":
		return p.parseUserEvent(rawEvent)
	case "result":
		return p.parseResultEvent(rawEvent)
	default:
		return p.parseUnknownEvent(rawEvent)
	}
}

func (p *Parser) parseSystemEvent(raw map[string]interface{}) (*Event, error) {
	data, _ := json.Marshal(raw)
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	event.Timestamp = time.Now()
	return &event, nil
}

func (p *Parser) parseAssistantEvent(raw map[string]interface{}) (*Event, error) {
	data, _ := json.Marshal(raw)
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	event.Timestamp = time.Now()
	return &event, nil
}

func (p *Parser) parseUserEvent(raw map[string]interface{}) (*Event, error) {
	data, _ := json.Marshal(raw)
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	event.Timestamp = time.Now()
	return &event, nil
}

func (p *Parser) parseResultEvent(raw map[string]interface{}) (*Event, error) {
	data, _ := json.Marshal(raw)
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	event.Timestamp = time.Now()
	return &event, nil
}

func (p *Parser) parseUnknownEvent(raw map[string]interface{}) (*Event, error) {
	data, _ := json.Marshal(raw)
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	event.Timestamp = time.Now()
	return &event, nil
}

// splitLines splits string into lines
func splitLines(s string) []string {
	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// trimSpace trims whitespace from a string
func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
