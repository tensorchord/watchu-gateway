import { ReloadOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Col, Collapse, Descriptions, Empty, List, Row, Space, Spin, Statistic, Tag, Typography } from "antd";
import { useMemo, useState } from "react";
import { useLocation } from "react-router-dom";

import { useAgentRuns, useTraceGraph } from "../hooks/useAnalytics";
import { useSettings } from "../context/SettingsContext";
import type { AgentRunResponse, ResourceUsageEntry, TraceNodeResponse } from "../types/api";
import { formatTimestamp } from "../utils/time";

const { Title, Text } = Typography;
const MAX_AGENT_RUNS = 200;

const TRACE_LABELS: Record<string, { label: string; color: string }> = {
    llm_call: { label: "LLM Call", color: "blue" },
    tool_use: { label: "Tool Use", color: "gold" },
    mcp_call: { label: "MCP Call", color: "purple" },
    command_exec: { label: "Command", color: "cyan" }
};

const TOKEN_KEYS: Array<{ key: string; label: string }> = [
    { key: "input_tokens", label: "Input Tokens" },
    { key: "output_tokens", label: "Output Tokens" },
    { key: "total_tokens", label: "Total Tokens" },
    { key: "cached_input_tokens", label: "Cached Tokens" }
];

function hasStableId(value: unknown): value is { id: string } {
    return typeof value === "object" && value !== null && "id" in value && typeof (value as { id: unknown }).id === "string";
}

function isAgentRunArray(value: unknown): value is AgentRunResponse[] {
    return Array.isArray(value) && value.every(hasStableId);
}

function isTraceNodeArray(value: unknown): value is TraceNodeResponse[] {
    return Array.isArray(value) && value.every(hasStableId);
}

function describeValue(value: unknown): string {
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
        return value.toString();
    }
    if (typeof value === "symbol" || typeof value === "function") {
        return value.toString();
    }
    if (typeof value === "string") {
        return value;
    }
    return Object.prototype.toString.call(value);
}

function formatJson(value: unknown): string | null {
    if (value == null) {
        return null;
    }
    if (typeof value === "string") {
        try {
            const parsed: unknown = JSON.parse(value);
            return JSON.stringify(parsed, null, 2);
        } catch {
            return value;
        }
    }
    if (typeof value === "object") {
        try {
            return JSON.stringify(value, null, 2);
        } catch {
            return describeValue(value);
        }
    }
    return describeValue(value);
}

function truncate(value: string, max = 140): string {
    if (value.length <= max) {
        return value;
    }
    return `${value.slice(0, max).trimEnd()}…`;
}

function summarizePreview(value: unknown, max = 140): string | null {
    const formatted = formatJson(value);
    if (!formatted) {
        return null;
    }
    return truncate(formatted.replace(/\s+/g, " ").trim(), max);
}

function phaseRank(trace: TraceNodeResponse): number {
    const phase = trace.phase?.toLowerCase() ?? "";
    if (trace.trace_type === "tool_use") {
        if (phase.includes("start")) return 0;
        if (phase.includes("request")) return 1;
        if (phase.includes("response")) return 2;
        if (phase.includes("end")) return 3;
    }
    if (trace.trace_type === "llm_call") {
        if (phase.includes("request")) return 0;
        if (phase.includes("response")) return 1;
    }
    if (trace.trace_type === "mcp_call") {
        if (phase.includes("request")) return 0;
        if (phase.includes("response")) return 1;
    }
    return 10;
}

function mergeUsage(
    left?: Record<string, ResourceUsageEntry | null> | null,
    right?: Record<string, ResourceUsageEntry | null> | null
): Record<string, ResourceUsageEntry> | undefined {
    if (!left && !right) {
        return undefined;
    }
    const merged: Record<string, ResourceUsageEntry> = {};
    const add = (source?: Record<string, ResourceUsageEntry | null> | null) => {
        if (!source) return;
        Object.entries(source).forEach(([key, entry]) => {
            if (!entry || entry.value == null) return;
            merged[key] = { value: (merged[key]?.value ?? 0) + entry.value, unit: entry.unit };
        });
    };
    add(left);
    add(right);
    return merged;
}

function isResponsePhase(phase?: string | null): boolean {
    if (!phase) return false;
    const normalized = phase.toLowerCase();
    return normalized.includes("response") || normalized.includes("reply") || normalized.includes("output");
}

function mergeLlmCallPairs(traces: TraceNodeResponse[]): TraceNodeResponse[] {
    const grouped = new Map<string, { request?: TraceNodeResponse; response?: TraceNodeResponse }>();
    const passthrough: TraceNodeResponse[] = [];

    traces.forEach((trace) => {
        if (trace.trace_type !== "llm_call") {
            passthrough.push(trace);
            return;
        }
        const key = trace.external_id ?? trace.parent_trace_id ?? trace.id;
        const bucket = grouped.get(key) ?? {};
        if (isResponsePhase(trace.phase)) {
            bucket.response = bucket.response ?? trace;
        } else {
            bucket.request = bucket.request ?? trace;
        }
        grouped.set(key, bucket);
    });

    const merged: TraceNodeResponse[] = [];
    grouped.forEach(({ request, response }, key) => {
        const base = request ?? response;
        if (!base) {
            return;
        }
        const combinedUsage = mergeUsage(request?.resource_usage, response?.resource_usage);
        const mergedLlm = request?.llm ?? response?.llm ?? base.llm;
        const llm = mergedLlm
            ? {
                ...mergedLlm,
                prompt: request?.llm?.prompt ?? response?.llm?.prompt ?? mergedLlm.prompt,
                response: response?.llm?.response ?? request?.llm?.response ?? mergedLlm.response,
                usage: response?.llm?.usage ?? request?.llm?.usage ?? mergedLlm.usage
            }
            : null;
        merged.push({
            ...base,
            id: base.id ?? key,
            phase: base.phase ?? "llm_call",
            started_at: request?.started_at ?? response?.started_at ?? base.started_at,
            ended_at: response?.ended_at ?? request?.ended_at ?? base.ended_at,
            prompt_preview: request?.prompt_preview ?? base.prompt_preview,
            response_preview: response?.response_preview ?? base.response_preview,
            llm,
            resource_usage: combinedUsage ?? base.resource_usage
        });
    });

    return [...passthrough, ...merged];
}

function getDuration(start: string, end: string): string | null {
    const delta = new Date(end).getTime() - new Date(start).getTime();
    if (Number.isNaN(delta)) {
        return null;
    }
    if (delta < 1000) {
        return `${delta} ms`;
    }
    if (delta < 60_000) {
        return `${(delta / 1000).toFixed(1)} s`;
    }
    return `${(delta / 60_000).toFixed(1)} min`;
}

function buildPreviewPair(trace: TraceNodeResponse): { request: string | null; response: string | null } {
    if (trace.trace_type === "llm_call") {
        return {
            request: trace.prompt_preview ?? summarizePreview(trace.llm?.prompt, 120),
            response: trace.response_preview ?? summarizePreview(trace.llm?.response, 120)
        };
    }
    if (trace.trace_type === "mcp_call") {
        const entries = trace.mcp?.entries ?? [];
        const requestEntry = entries.find((entry) => entry.params != null) ?? entries[0];
        const responseEntry =
            [...entries].reverse().find((entry) => entry.result != null || entry.error != null) ?? entries[entries.length - 1];
        return {
            request: summarizePreview(requestEntry?.params ?? trace.mcp?.method ?? trace.prompt_preview, 120),
            response:
                summarizePreview(responseEntry?.result, 120) ??
                summarizePreview(responseEntry?.error, 120) ??
                summarizePreview(trace.response_preview, 120)
        };
    }
    if (trace.trace_type === "tool_use") {
        return {
            request: trace.prompt_preview ?? summarizePreview(trace.tool?.arguments, 120),
            response: trace.response_preview ?? summarizePreview(trace.tool?.response_key, 120)
        };
    }
    return {
        request: trace.prompt_preview ?? summarizePreview(trace.external_id ?? trace.phase, 120),
        response: trace.response_preview ?? summarizePreview(trace.model ?? trace.source_table, 120)
    };
}

export default function TraceExplorer() {
    const { host, since, until } = useSettings();
    const location = useLocation();
    const initialRunId = useMemo(() => {
        const params = new URLSearchParams(location.search);
        const value = params.get("agent_run_id");
        return value ? value.trim() : null;
    }, [location.search]);
    const [selectedRunId, setSelectedRunId] = useState<string | null>(initialRunId);
    const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);

    const agentRunsQuery = useAgentRuns(host, since, until, MAX_AGENT_RUNS);
    const runs = useMemo<AgentRunResponse[]>(() => {
        return isAgentRunArray(agentRunsQuery.data) ? agentRunsQuery.data : [];
    }, [agentRunsQuery.data]);

    const activeRunId = useMemo(() => {
        if (!runs.length) {
            return null;
        }
        if (selectedRunId && runs.some((run) => run.id === selectedRunId)) {
            return selectedRunId;
        }
        return runs[0].id;
    }, [runs, selectedRunId]);

    const traceGraphQuery = useTraceGraph(host, activeRunId ?? undefined);
    const traces = useMemo<TraceNodeResponse[]>(() => {
        const data = traceGraphQuery.data?.traces;
        return isTraceNodeArray(data) ? data : [];
    }, [traceGraphQuery.data]);

    const mergedTraces = useMemo<TraceNodeResponse[]>(() => mergeLlmCallPairs(traces), [traces]);

    const activeTraceId = useMemo(() => {
        if (selectedTraceId && mergedTraces.some((trace) => trace.id === selectedTraceId)) {
            return selectedTraceId;
        }
        return null;
    }, [mergedTraces, selectedTraceId]);

    const sortedTraces = useMemo(() => {
        return [...mergedTraces].sort((a, b) => {
            const aTime = new Date(a.started_at ?? a.ended_at ?? 0).getTime();
            const bTime = new Date(b.started_at ?? b.ended_at ?? 0).getTime();
            if (aTime !== bTime) {
                return aTime - bTime;
            }
            const phaseDelta = phaseRank(a) - phaseRank(b);
            if (phaseDelta !== 0) {
                return phaseDelta;
            }
            return a.id.localeCompare(b.id);
        });
    }, [mergedTraces]);

    const aggregatedUsage = useMemo(() => {
        const totals: Record<string, number> = {};
        mergedTraces.forEach((trace) => {
            const usageEntries = trace.resource_usage ?? {};
            Object.entries(usageEntries).forEach(([metric, entry]) => {
                if (!entry || entry.value == null) {
                    return;
                }
                totals[metric] = (totals[metric] ?? 0) + entry.value;
            });
        });
        return totals;
    }, [mergedTraces]);

    const handleSelectRun = (id: string) => {
        setSelectedRunId(id);
        setSelectedTraceId(null);
    };

    const handleSelectTrace = (key: string | string[]) => {
        const nextKey = Array.isArray(key) ? key[0] : key;
        setSelectedTraceId(typeof nextKey === "string" ? nextKey : null);
    };

    if (!host) {
        return <Alert type="info" message="Select a host to explore traces." showIcon />;
    }

    return (
        <Space direction="vertical" size="large" style={{ width: "100%" }}>
            <Space align="center" style={{ width: "100%" }} wrap>
                <Text type="secondary">Active host: {host}</Text>
                <Button icon={<ReloadOutlined />} onClick={() => void agentRunsQuery.refetch()} loading={agentRunsQuery.isFetching}>
                    Refresh Runs
                </Button>
                {activeRunId && (
                    <Button
                        icon={<ReloadOutlined />}
                        onClick={() => void traceGraphQuery.refetch()}
                        loading={traceGraphQuery.isFetching}
                    >
                        Refresh Traces
                    </Button>
                )}
            </Space>
            <Row gutter={[24, 24]}>
                <Col xs={24} md={8}>
                    <Card title="Agent Runs" extra={`Total ${runs.length}`} bordered={false} bodyStyle={{ padding: 0, minHeight: 360 }}>
                        {agentRunsQuery.isLoading ? (
                            <Spin style={{ margin: 24 }} />
                        ) : runs.length === 0 ? (
                            <Empty description="No runs in range" style={{ margin: "32px 0" }} />
                        ) : (
                            <List
                                dataSource={runs}
                                renderItem={(run) => (
                                    <AgentRunListItem run={run} selected={run.id === activeRunId} onSelect={handleSelectRun} />
                                )}
                            />
                        )}
                    </Card>
                </Col>
                <Col xs={24} md={16}>
                    <Space direction="vertical" size="large" style={{ width: "100%" }}>
                        <Card
                            title="Trace Timeline"
                            bordered={false}
                            extra={traceGraphQuery.isFetching ? <Spin size="small" /> : null}
                            bodyStyle={{ minHeight: 260 }}
                        >
                            {!activeRunId ? (
                                <Empty description="Select an agent run" />
                            ) : traceGraphQuery.isLoading ? (
                                <Spin />
                            ) : traces.length === 0 ? (
                                <Empty description="No traces recorded" />
                            ) : (
                                <Collapse
                                    accordion
                                    activeKey={activeTraceId ? [activeTraceId] : []}
                                    onChange={handleSelectTrace}
                                    expandIconPosition="end"
                                    items={sortedTraces.map((trace) => ({
                                        key: trace.id,
                                        label: <TraceSummary trace={trace} />,
                                        children: <TraceDetails trace={trace} />
                                    }))}
                                />
                            )}
                        </Card>
                        <Card title="Resource Usage" bordered={false}>
                            {Object.keys(aggregatedUsage).length === 0 ? (
                                <Empty description="No usage metrics" />
                            ) : (
                                <Row gutter={[16, 16]}>
                                    {TOKEN_KEYS.map(({ key, label }) => (
                                        <Col xs={12} key={key}>
                                            <Statistic title={label} value={aggregatedUsage[key] ?? 0} precision={0} />
                                        </Col>
                                    ))}
                                </Row>
                            )}
                        </Card>
                    </Space>
                </Col>
            </Row>
        </Space>
    );
}

function AgentRunListItem({ run, selected, onSelect }: { run: AgentRunResponse; selected: boolean; onSelect: (id: string) => void }) {
    const started = formatTimestamp(run.started_at) ?? "Unknown";
    const ended = formatTimestamp(run.ended_at);
    return (
        <List.Item
            onClick={() => onSelect(run.id)}
            style={{
                cursor: "pointer",
                background: selected ? "#e6f4ff" : undefined,
                borderLeft: selected ? "3px solid #1677ff" : "3px solid transparent",
                paddingInline: 16
            }}
        >
            <Space direction="vertical" size={2} style={{ width: "100%" }}>
                <Space align="center" size="small" wrap>
                    <Text strong>{run.root_exec_id ?? run.id}</Text>
                    {run.provider && <Tag color="processing">{run.provider}</Tag>}
                    {typeof run.root_pid === "number" && <Tag color="default">PID {run.root_pid}</Tag>}
                </Space>
                <Text type="secondary" style={{ fontSize: 12 }}>
                    {started}
                    {ended ? ` → ${ended}` : " (running)"}
                </Text>
            </Space>
        </List.Item>
    );
}

function TraceSummary({ trace }: { trace: TraceNodeResponse }) {
    const meta = TRACE_LABELS[trace.trace_type] ?? { label: trace.trace_type, color: "default" };
    const started = formatTimestamp(trace.started_at) ?? "Unknown";
    const ended = formatTimestamp(trace.ended_at);
    const duration = trace.started_at && trace.ended_at ? getDuration(trace.started_at, trace.ended_at) : null;
    const pair = buildPreviewPair(trace);
    const showPhaseTag = trace.trace_type !== "llm_call";

    return (
        <div
            style={{
                width: "100%",
                padding: 12,
                borderRadius: 10,
                background: "#f7f9fc",
                border: "1px solid #e5e7eb",
                boxShadow: "0 1px 2px rgba(15, 23, 42, 0.06)"
            }}
        >
            <Space direction="vertical" size={6} style={{ width: "100%" }}>
                <Space size="small" wrap>
                    <Tag color={meta.color}>{meta.label}</Tag>
                    {showPhaseTag && <Tag bordered={false}>{trace.phase}</Tag>}
                    {trace.model && <Tag>{trace.model}</Tag>}
                    <Text type="secondary" style={{ fontSize: 12 }}>
                        {started}
                        {ended ? ` → ${ended}` : ""}
                    </Text>
                    {duration && (
                        <Text type="secondary" style={{ fontSize: 12 }}>
                            · {duration}
                        </Text>
                    )}
                </Space>
                {(pair.request || pair.response) && (
                    <Space direction="vertical" size={4} style={{ width: "100%" }}>
                        {pair.request && (
                            <div>
                                <Text strong style={{ fontSize: 12, marginRight: 6 }}>Req:</Text>
                                <Text type="secondary" style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                                    {pair.request}
                                </Text>
                            </div>
                        )}
                        {pair.response && (
                            <div>
                                <Text strong style={{ fontSize: 12, marginRight: 6 }}>Resp:</Text>
                                <Text type="secondary" style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                                    {pair.response}
                                </Text>
                            </div>
                        )}
                    </Space>
                )}
            </Space>
        </div>
    );
}

function TraceDetails({ trace }: { trace: TraceNodeResponse }) {
    const meta = TRACE_LABELS[trace.trace_type] ?? { label: trace.trace_type, color: "default" };
    return (
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <Space size="small" wrap>
                <Tag color={meta.color}>{meta.label}</Tag>
                <Tag bordered={false}>{trace.phase}</Tag>
                {trace.model && <Tag>{trace.model}</Tag>}
            </Space>
            <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label="Started">{formatTimestamp(trace.started_at) ?? "Unknown"}</Descriptions.Item>
                <Descriptions.Item label="Ended">{formatTimestamp(trace.ended_at) ?? "Unknown"}</Descriptions.Item>
                {trace.external_id && <Descriptions.Item label="External ID">{trace.external_id}</Descriptions.Item>}
            </Descriptions>
            {trace.llm && (
                <PayloadBlock title="LLM Payload" prompt={trace.llm.prompt} response={trace.llm.response} usage={trace.llm.usage} />
            )}
            {trace.tool && (
                <Space direction="vertical" size={4} style={{ width: "100%" }}>
                    <Title level={5} style={{ margin: 0 }}>
                        Tool Call
                    </Title>
                    <Descriptions size="small" column={1} bordered>
                        <Descriptions.Item label="Name">{trace.tool.name ?? "Unknown"}</Descriptions.Item>
                        <Descriptions.Item label="Response Key">{trace.tool.response_key}</Descriptions.Item>
                    </Descriptions>
                    {formatJson(trace.tool.arguments) && <CodeBlock value={formatJson(trace.tool.arguments)} />}
                </Space>
            )}
            {trace.mcp && trace.mcp.entries.length > 0 && (
                <Space direction="vertical" size={4} style={{ width: "100%" }}>
                    <Title level={5} style={{ margin: 0 }}>
                        MCP Exchange
                    </Title>
                    {trace.mcp.entries.map((entry, index) => (
                        <Card key={`${trace.mcp?.corr_id}-${index}`} size="small" bodyStyle={{ background: "#f7f9fc" }}>
                            <Space direction="vertical" size={4} style={{ width: "100%" }}>
                                <Space size="small" wrap>
                                    <Tag color="purple">{entry.message_type}</Tag>
                                    <Text type="secondary">{formatTimestamp(entry.timestamp) ?? "Unknown"}</Text>
                                </Space>
                                {formatJson(entry.params) && (
                                    <Space direction="vertical" size={2} style={{ width: "100%" }}>
                                        <Text strong>Params</Text>
                                        <CodeBlock value={formatJson(entry.params)} />
                                    </Space>
                                )}
                                {formatJson(entry.result) && (
                                    <Space direction="vertical" size={2} style={{ width: "100%" }}>
                                        <Text strong>Result</Text>
                                        <CodeBlock value={formatJson(entry.result)} />
                                    </Space>
                                )}
                                {formatJson(entry.error) && (
                                    <Alert type="error" message="Error" description={<CodeBlock value={formatJson(entry.error)} />} />
                                )}
                            </Space>
                        </Card>
                    ))}
                </Space>
            )}
        </Space>
    );
}

function PayloadBlock({
    title,
    prompt,
    response,
    usage
}: {
    title: string;
    prompt?: unknown;
    response?: unknown;
    usage?: unknown;
}) {
    const promptText = formatJson(prompt);
    const responseText = formatJson(response);
    const usageText = formatJson(usage);
    if (!promptText && !responseText && !usageText) {
        return null;
    }
    return (
        <Space direction="vertical" size={4} style={{ width: "100%" }}>
            <Title level={5} style={{ margin: 0 }}>
                {title}
            </Title>
            {promptText && (
                <Space direction="vertical" size={2} style={{ width: "100%" }}>
                    <Text strong>Prompt</Text>
                    <CodeBlock value={promptText} />
                </Space>
            )}
            {responseText && (
                <Space direction="vertical" size={2} style={{ width: "100%" }}>
                    <Text strong>Response</Text>
                    <CodeBlock value={responseText} />
                </Space>
            )}
            {usageText && (
                <Space direction="vertical" size={2} style={{ width: "100%" }}>
                    <Text strong>Usage</Text>
                    <CodeBlock value={usageText} />
                </Space>
            )}
        </Space>
    );
}

function CodeBlock({ value }: { value: string | null }) {
    if (!value) {
        return null;
    }
    return (
        <pre
            style={{
                background: "#0f172a",
                color: "#e2e8f0",
                padding: 12,
                borderRadius: 8,
                maxHeight: 260,
                overflow: "auto",
                fontSize: 12,
                margin: 0
            }}
        >
            {value}
        </pre>
    );
}
