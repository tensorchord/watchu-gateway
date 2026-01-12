import { Card, Collapse, Tag, Typography, Space } from "antd";
import { useState, useMemo } from "react";

const { Text } = Typography;

interface StreamMessage {
    type?: string;
    subtype?: string;
    level?: string;
    message?: {
        content?: Array<{ type: string; text?: string; tool_use_id?: string; name?: string; input?: Record<string, unknown> }>;
        model?: string;
        permissionMode?: string;
        tools?: string[];
        skills?: string[];
        [key: string]: unknown;
    };
    content?: Array<{ type: string; text?: string; tool_use_id?: string; name?: string; input?: Record<string, unknown> }>;
    session_id?: string;
    uuid?: string;
    result?: string;
    stop_reason?: string;
    is_error?: boolean;
    duration_ms?: number;
    model?: string;
    permissionMode?: string;
    tools?: string[];
    skills?: string[];
    [key: string]: unknown;
}

interface RunnerOutputViewerProps {
    output: string;
}

interface JsonTreeNodeProps {
    data: unknown;
    depth?: number;
}

function JsonTreeNode({ data, depth = 0 }: JsonTreeNodeProps) {
    const [isExpanded, setIsExpanded] = useState(depth < 2);

    if (data === null) {
        return <span style={{ color: "#999" }}>null</span>;
    }

    if (data === undefined) {
        return <span style={{ color: "#999" }}>undefined</span>;
    }

    if (typeof data === "boolean") {
        return <span style={{ color: "#2196f3" }}>{String(data)}</span>;
    }

    if (typeof data === "number") {
        return <span style={{ color: "#f57c00" }}>{String(data)}</span>;
    }

    if (typeof data === "string") {
        return <span style={{ color: "#4caf50" }}>"{data}"</span>;
    }

    if (Array.isArray(data)) {
        if (data.length === 0) {
            return <span>[]</span>;
        }

        return (
            <span>
                <span
                    style={{ cursor: "pointer", userSelect: "none" }}
                    onClick={() => setIsExpanded(!isExpanded)}
                >
                    {isExpanded ? "[-]" : "[+]"}
                </span>
                {isExpanded && (
                    <span style={{ marginLeft: 4 }}>
                        {data.map((item, index) => (
                            <div key={index} style={{ marginLeft: 16 }}>
                                <span style={{ color: "#999" }}>{index}:</span> <JsonTreeNode data={item} depth={depth + 1} />
                            </div>
                        ))}
                    </span>
                )}
            </span>
        );
    }

    if (typeof data === "object") {
        const keys = Object.keys(data);
        if (keys.length === 0) {
            return <span>{"{}"}</span>;
        }

        return (
            <span>
                <span
                    style={{ cursor: "pointer", userSelect: "none" }}
                    onClick={() => setIsExpanded(!isExpanded)}
                >
                    {isExpanded ? "{{-}}" : "{+}"}
                </span>
                {isExpanded && (
                    <span style={{ marginLeft: 4 }}>
                        {keys.map((key) => (
                            <div key={key} style={{ marginLeft: 16 }}>
                                <span style={{ color: "#9c27b0" }}>"{key}"</span>: <JsonTreeNode data={(data as Record<string, unknown>)[key]} depth={depth + 1} />
                            </div>
                        ))}
                    </span>
                )}
            </span>
        );
    }

    return <span>{String(data)}</span>;
}

function getLevelColor(level: string): string {
    switch (level.toLowerCase()) {
        case "error": return "#f5222d";
        case "warn": return "#faad14";
        case "info": return "#1890ff";
        case "debug": return "#8c8c8c";
        default: return "#52c41a";
    }
}

function getTypeColor(type: string): string {
    switch (type?.toLowerCase()) {
        case "system": return "blue";
        case "assistant": return "green";
        case "user": return "orange";
        case "result": return type === "error" ? "red" : "default";
        default: return "default";
    }
}

function getTypeIcon(type: string): string {
    switch (type?.toLowerCase()) {
        case "system": return "⚙️";
        case "assistant": return "🤖";
        case "user": return "👤";
        case "result": return "📊";
        default: return "📝";
    }
}

export default function RunnerOutputViewer({ output }: RunnerOutputViewerProps) {
    const [expandedKeys, setExpandedKeys] = useState<string[]>([]);

    const messages = useMemo(() => {
        if (!output) return [];

        const lines = output.trim().split("\n");
        const parsed: Array<{ raw: string; parsed?: StreamMessage; error?: boolean }> = [];

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;

            try {
                parsed.push({ raw: trimmed, parsed: JSON.parse(trimmed) as StreamMessage });
            } catch {
                parsed.push({ raw: trimmed, error: true });
            }
        }

        return parsed;
    }, [output]);

    const groupedMessages = useMemo(() => {
        const groups: Record<string, typeof messages> = {};

        for (const msg of messages) {
            const type = msg.parsed?.type ?? "other";
            if (!groups[type]) groups[type] = [];
            groups[type].push(msg);
        }

        return groups;
    }, [messages]);

    const renderMessage = (msg: { raw: string; parsed?: StreamMessage; error?: boolean }, index: number) => {
        if (msg.error) {
            return (
                <Card key={index} size="small" style={{ marginBottom: 8, background: "#fff7e6" }}>
                    <pre style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: 12, color: "#8c8c8c" }}>
                        {msg.raw}
                    </pre>
                </Card>
            );
        }

        const p = msg.parsed!;

        // Special handling for result messages
        if (p.type === "result" && p.subtype === "success" && p.result) {
            return (
                <Card key={index} size="small" style={{ marginBottom: 8 }}>
                    <Space direction="vertical" style={{ width: "100%" }}>
                        <Space>
                            <Tag color="green">Success</Tag>
                            {p.duration_ms && <Text type="secondary">{p.duration_ms}ms</Text>}
                            {p.stop_reason && <Tag>{p.stop_reason}</Tag>}
                        </Space>
                        {p.result && (
                            <Text style={{ whiteSpace: "pre-wrap" }}>{p.result}</Text>
                        )}
                    </Space>
                </Card>
            );
        }

        // System init message
        if (p.type === "system" && p.subtype === "init") {
            return (
                <Card key={index} size="small" style={{ marginBottom: 8, background: "#f0f5ff" }}>
                    <Space direction="vertical" style={{ width: "100%" }} size="small">
                        <Space wrap>
                            <Tag color="blue">System Init</Tag>
                            {p.model && <Tag>Model: {p.model}</Tag>}
                            {p.permissionMode && <Tag>Permission: {p.permissionMode}</Tag>}
                        </Space>
                        {p.tools && (
                            <Text type="secondary" style={{ fontSize: 12 }}>
                                Tools: {p.tools.length} available
                            </Text>
                        )}
                        {p.skills && (
                            <Text type="secondary" style={{ fontSize: 12 }}>
                                Skills: {p.skills.join(", ")}
                            </Text>
                        )}
                    </Space>
                </Card>
            );
        }

        // Assistant message with tool use
        if (p.type === "assistant" && p.message?.content) {
            const content = p.message.content as Array<{ type: string; text?: string; name?: string; input?: Record<string, unknown> }>;
            return (
                <Card key={index} size="small" style={{ marginBottom: 8, background: "#f6ffed" }}>
                    <Space direction="vertical" style={{ width: "100%" }} size="small">
                        <Tag color="green">🤖 Assistant</Tag>
                        {content.map((item, i) => (
                            <div key={i}>
                                {item.type === "text" && (
                                    <Text style={{ fontSize: 12 }}>{item.text}</Text>
                                )}
                                {item.type === "tool_use" && (
                                    <Space direction="vertical" style={{ width: "100%" }}>
                                        <Tag color="blue">Tool: {item.name}</Tag>
                                        {item.input && (
                                            <div style={{ marginTop: 4, padding: 8, background: "#f5f5f5", borderRadius: 4, fontSize: 11 }}>
                                                <JsonTreeNode data={item.input} />
                                            </div>
                                        )}
                                    </Space>
                                )}
                            </div>
                        ))}
                    </Space>
                </Card>
            );
        }

        // User message with tool result
        if (p.type === "user" && p.message?.content) {
            const content = p.message.content as Array<{ type: string; tool_use_id?: string; content?: string | unknown }>;
            return (
                <Card key={index} size="small" style={{ marginBottom: 8, background: "#fff7e6" }}>
                    <Space direction="vertical" style={{ width: "100%" }} size="small">
                        <Tag color="orange">👤 User</Tag>
                        {content.map((item, i) => (
                            <div key={i}>
                                {item.type === "tool_result" && (
                                    <Space direction="vertical" style={{ width: "100%" }}>
                                        <Text type="secondary" style={{ fontSize: 12 }}>
                                            Tool Result: {item.tool_use_id?.slice(0, 8)}...
                                        </Text>
                                        {typeof item.content === "string" && item.content.length > 0 && (
                                            <Text
                                                style={{
                                                    fontSize: 11,
                                                    display: "block",
                                                    maxHeight: 100,
                                                    overflow: "auto",
                                                    background: item.content.includes("Error") ? "#fff1f0" : "#f5f5f5",
                                                    padding: 8,
                                                    borderRadius: 4
                                                }}
                                            >
                                                {item.content.slice(0, 500)}
                                                {item.content.length > 500 && "..."}
                                            </Text>
                                        )}
                                    </Space>
                                )}
                                {item.type === "text" && typeof item.content === "string" && (
                                    <Text style={{ fontSize: 12 }}>{item.content}</Text>
                                )}
                            </div>
                        ))}
                    </Space>
                </Card>
            );
        }

        // Default JSON view
        return (
            <Card
                key={index}
                size="small"
                style={{ marginBottom: 8 }}
                title={
                    <Space>
                        <Tag color={getTypeColor(p.type ?? "")}>{getTypeIcon(p.type ?? "")} {p.type ?? "Unknown"}</Tag>
                        {p.subtype && <Tag>{p.subtype}</Tag>}
                        {p.level && <Tag color={getLevelColor(p.level)}>{p.level}</Tag>}
                    </Space>
                }
            >
                <div style={{ fontSize: 11 }}>
                    <JsonTreeNode data={p} />
                </div>
            </Card>
        );
    };

    return (
        <div>
            {Object.keys(groupedMessages).length > 1 ? (
                <Collapse
                    activeKey={expandedKeys}
                    onChange={(keys) => setExpandedKeys(keys as string[])}
                    size="small"
                >
                    {Object.entries(groupedMessages).map(([type, msgs]) => (
                        <Collapse.Panel
                            key={type}
                            header={
                                <Space>
                                    <Tag color={getTypeColor(type)}>{getTypeIcon(type)} {type}</Tag>
                                    <Text type="secondary">({msgs.length})</Text>
                                </Space>
                            }
                        >
                            {msgs.map((msg, i) => renderMessage(msg, i))}
                        </Collapse.Panel>
                    ))}
                </Collapse>
            ) : (
                <div>
                    {messages.map((msg, i) => renderMessage(msg, i))}
                </div>
            )}
        </div>
    );
}
