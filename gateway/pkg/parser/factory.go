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

	// Convert claudecode.Event to parser.Event concrete types
	result := make([]Event, 0, len(events))
	for _, e := range events {
		converted := convertClaudeCodeEvent(e)
		if converted != nil {
			result = append(result, converted)
		}
	}
	return result, nil
}

func (a *claudeCodeAdapter) ParseEvent(line string) (Event, error) {
	event, err := a.parser.ParseEvent(line)
	if err != nil {
		return nil, err
	}
	converted := convertClaudeCodeEvent(event)
	if converted == nil {
		return nil, fmt.Errorf("failed to convert event")
	}
	return converted, nil
}

func (a *claudeCodeAdapter) GetAgentType() AgentType {
	return AgentTypeClaudeCode
}

// convertClaudeCodeEvent converts claudecode.Event to parser.Event concrete type
func convertClaudeCodeEvent(e *claudecode.Event) Event {
	if e == nil {
		return nil
	}

	switch e.EventType {
	case "system":
		return &SystemEvent{
			EventType:  e.EventType,
			Subtype:    e.Subtype,
			SessionID:  e.SessionID,
			CWD:        e.CWD,
			Tools:      e.Tools,
			MCPServers: e.MCPServers,
			Model:      e.Model,
			UUID:       e.UUID,
			timestamp:  e.Timestamp,
		}
	case "assistant":
		msg := e.Message
		content := make([]MessageContent, 0)
		var msgID, msgRole, msgModel string
		if msg != nil {
			msgID = msg.ID
			msgRole = msg.Role
			msgModel = msg.Model
			for _, c := range msg.Content {
				content = append(content, MessageContent{
					Type:      c.Type,
					Text:      c.Text,
					ID:        c.ID,
					Name:      c.Name,
					Input:     c.Input,
					Content:   c.Content,
					IsError:   c.IsError,
					ToolUseID: c.ToolUseID,
				})
			}
		}
		return &AssistantEvent{
			EventType:       e.EventType,
			Message: Message{
				ID:      msgID,
				Role:    msgRole,
				Model:   msgModel,
				Content: content,
			},
			ParentToolUseID: e.ParentToolUseID,
			SessionID:       e.SessionID,
			UUID:            e.UUID,
			timestamp:       e.Timestamp,
		}
	case "user":
		msg := e.Message
		content := make([]MessageContent, 0)
		var msgID, msgRole, msgModel string
		if msg != nil {
			msgID = msg.ID
			msgRole = msg.Role
			msgModel = msg.Model
			for _, c := range msg.Content {
				content = append(content, MessageContent{
					Type:      c.Type,
					Text:      c.Text,
					ID:        c.ID,
					Name:      c.Name,
					Input:     c.Input,
					Content:   c.Content,
					IsError:   c.IsError,
					ToolUseID: c.ToolUseID,
				})
			}
		}
		return &UserEvent{
			EventType: e.EventType,
			Message: Message{
				ID:      msgID,
				Role:    msgRole,
				Model:   msgModel,
				Content: content,
			},
			SessionID:     e.SessionID,
			UUID:          e.UUID,
			ToolUseResult: e.ToolUseResult,
			timestamp:     e.Timestamp,
		}
	case "result":
		return &ResultEvent{
			EventType:      e.EventType,
			Subtype:        e.Subtype,
			IsError:        e.IsError,
			DurationMS:     e.DurationMS,
			DurationAPIMS:  e.DurationAPIMS,
			NumTurns:       e.NumTurns,
			Result:         e.Result,
			SessionID:      e.SessionID,
			TotalCostUSD:   e.TotalCostUSD,
			Usage:          e.Usage,
			ModelUsage:     e.ModelUsage,
			UUID:           e.UUID,
			timestamp:      e.Timestamp,
		}
	default:
		return &UnknownEvent{
			EventType: e.EventType,
			RawData:   e.RawData,
			timestamp: e.Timestamp,
		}
	}
}
