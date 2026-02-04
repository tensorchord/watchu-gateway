package parser

import (
	"fmt"

	"github.com/tensorchord/watchu/gateway/pkg/parser/claudecode"
)

// ParserFactory is the parser factory
type ParserFactory struct {
	parsers map[AgentType]RunnerOutputParser
}

// NewParserFactory creates a parser factory
func NewParserFactory() *ParserFactory {
	factory := &ParserFactory{
		parsers: make(map[AgentType]RunnerOutputParser),
	}

	// Register known parsers
	factory.Register(NewClaudeCodeParser())
	// Future parsers can be added here
	// factory.Register(NewCodexParser())
	// factory.Register(NewGeminiParser())

	return factory
}

// Register registers a parser
func (f *ParserFactory) Register(parser RunnerOutputParser) {
	f.parsers[parser.GetAgentType()] = parser
}

// GetParser gets the parser for the specified agent type
func (f *ParserFactory) GetParser(agentType AgentType) (RunnerOutputParser, error) {
	parser, ok := f.parsers[agentType]
	if !ok {
		return nil, fmt.Errorf("unsupported agent type: %s", agentType)
	}
	return parser, nil
}

// GetSupportedAgentTypes returns the list of supported agent types
func (f *ParserFactory) GetSupportedAgentTypes() []AgentType {
	types := make([]AgentType, 0, len(f.parsers))
	for agentType := range f.parsers {
		types = append(types, agentType)
	}
	return types
}

// claudeCodeAdapter adapts claudecode.Parser to parser.RunnerOutputParser
type claudeCodeAdapter struct {
	parser *claudecode.Parser
}

// NewClaudeCodeParser creates a new Claude Code parser adapter
func NewClaudeCodeParser() RunnerOutputParser {
	return &claudeCodeAdapter{
		parser: claudecode.NewParser(),
	}
}

func (a *claudeCodeAdapter) Parse(runnerOutput string) ([]Event, error) {
	events, err := a.parser.Parse(runnerOutput)
	if err != nil {
		return nil, err
	}

	// Convert claudecode.Event to parser.Event
	result := make([]Event, len(events))
	for i, e := range events {
		result[i] = &claudeCodeEventAdapter{Event: e}
	}
	return result, nil
}

func (a *claudeCodeAdapter) ParseEvent(line string) (Event, error) {
	event, err := a.parser.ParseEvent(line)
	if err != nil {
		return nil, err
	}
	return &claudeCodeEventAdapter{Event: event}, nil
}

func (a *claudeCodeAdapter) GetAgentType() AgentType {
	return AgentTypeClaudeCode
}

// claudeCodeEventAdapter adapts claudecode.Event to parser.Event
type claudeCodeEventAdapter struct {
	Event *claudecode.Event
}

func (a *claudeCodeEventAdapter) Type() string {
	return a.Event.Type()
}

func (a *claudeCodeEventAdapter) Timestamp() string {
	return a.Event.TimestampString()
}

func (a *claudeCodeEventAdapter) ToJSON() ([]byte, error) {
	return a.Event.ToJSON()
}
