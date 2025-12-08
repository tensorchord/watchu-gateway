import { Column, Line } from "@ant-design/charts";
import { Card, Col, Empty, Row, Skeleton, Space, Statistic, Table, Tag, Typography } from "antd";
import dayjs from "dayjs";
import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { fetchTraceGraph } from "../api/analytics";
import { useSettings } from "../context/SettingsContext";
import { useAgentRuns } from "../hooks/useAnalytics";
import type { AgentRunResponse, ResourceUsageEntry, TraceGraphResponse, TraceNodeResponse } from "../types/api";

const TRACE_GRAPH_LIMIT = 10;

function numericValue(entry?: ResourceUsageEntry | null): number {
    if (!entry || typeof entry.value !== "number" || Number.isNaN(entry.value)) {
        return 0;
    }
    return entry.value;
}

function safeTime(value?: string | null) {
    if (!value) return null;
    const parsed = dayjs(value);
    return parsed.isValid() ? parsed : null;
}

function durationMs(trace: TraceNodeResponse): number | null {
    const start = safeTime(trace.started_at);
    const end = safeTime(trace.ended_at);
    if (!start || !end) return null;
    return end.diff(start, "millisecond");
}

interface AgentRunStats {
    run: AgentRunResponse;
    callCount: number;
    avgDurationMs: number | null;
}

interface MCPAggregate {
    server: string;
    requests: number;
    failures: number;
    durations: number[];
    toolCounts: Record<string, number>;
}

interface MCPCatalogEntry {
    server: string;
    tools: string[];
}

interface ModelAggregate {
    model: string;
    callCount: number;
    avgDurationMs: number | null;
    errorCount: number;
    recent: TraceNodeResponse[];
    inputTokens: number;
    outputTokens: number;
}

function extractMcpNames(trace: TraceNodeResponse): { server: string; tool: string } {
    const serverFromApi = (trace.mcp?.server ?? "").trim();
    const toolFromApi = (trace.mcp?.tool ?? "").trim();

    const entryTool = trace.mcp?.entries?.reduce<string | null>((acc, entry) => {
        if (acc) return acc;
        const params = entry.params as { name?: unknown; tool_name?: unknown } | undefined;
        const fromParams = [params?.name, params?.tool_name]
            .map((v) => (typeof v === "string" ? v.trim() : ""))
            .find((v) => v);
        if (fromParams) return fromParams;
        const result = entry.result as { tool?: { name?: unknown }; name?: unknown } | undefined;
        const fromResult = [result?.tool?.name, result?.name]
            .map((v) => (typeof v === "string" ? v.trim() : ""))
            .find((v) => v);
        return fromResult || null;
    }, null);

    const server = serverFromApi || "unknown";
    const tool = toolFromApi || entryTool || "unknown";
    return { server, tool };
}

export default function AgentDashboard() {
    const navigate = useNavigate();
    const { host, since, until, limit } = useSettings();
    const agentRunsQuery = useAgentRuns(host, since, until, limit);

    const runs = useMemo(() => agentRunsQuery.data ?? [], [agentRunsQuery.data]);
    const traceQueries = useQueries({
        queries: runs.slice(0, TRACE_GRAPH_LIMIT).map((run) => ({
            queryKey: ["trace-graph", host, run.id],
            queryFn: () => fetchTraceGraph(host, run.id),
            enabled: Boolean(host) && Boolean(run.id)
        }))
    });

    const traceGraphs = useMemo(() => {
        return traceQueries.map((q) => q.data).filter((g): g is TraceGraphResponse => Boolean(g));
    }, [traceQueries]);

    const traces = useMemo(() => traceGraphs.flatMap((g) => g.traces ?? []), [traceGraphs]);

    const totalCalls = traces.length;
    const totalTokens = traces.reduce((acc, trace) => {
        const usage = trace.resource_usage ?? {};
        return acc + numericValue(usage.total_tokens) + numericValue(usage.input_tokens) + numericValue(usage.output_tokens);
    }, 0);

    const llmTraces = traces.filter((t) => t.trace_type === "llm_call");
    const errorCount = llmTraces.filter((t) => (t.llm?.status ?? "").toLowerCase() === "error").length;
    const errorRate = llmTraces.length ? (errorCount / llmTraces.length) * 100 : 0;

    const providerDistribution = useMemo(() => {
        const normalize = (p?: string | null) => {
            const cleaned = (p ?? "").trim();
            return cleaned ? cleaned.toLowerCase() : "unknown";
        };
        const counts: Record<string, number> = {};
        runs.forEach((run) => {
            const provider = normalize(run.provider as string | null);
            counts[provider] = (counts[provider] ?? 0) + 1;
        });
        // Ensure the data always carries a visible label
        return Object.entries(counts).map(([provider, value]) => ({ provider: provider || "unknown", value }));
    }, [runs]);

    const topAgentRuns: AgentRunStats[] = useMemo(() => {
        return traceGraphs.map((graph) => {
            const durations = graph.traces.map(durationMs).filter((v): v is number => v !== null && Number.isFinite(v));
            const avgDuration = durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : null;
            return {
                run: graph.agent_run,
                callCount: graph.traces.length,
                avgDurationMs: avgDuration
            };
        })
            .sort((a, b) => b.callCount - a.callCount)
            .slice(0, 8);
    }, [traceGraphs]);

    const mcpAggregates: MCPAggregate[] = useMemo(() => {
        const map = new Map<string, MCPAggregate>();

        traces.filter((t) => t.trace_type === "mcp_call").forEach((trace) => {
            const dur = durationMs(trace);

            // Process each entry individually to get accurate server-tool mapping
            trace.mcp?.entries?.forEach((entry) => {
                // Extract server from entry-level (more accurate)
                const server = (entry.server ?? trace.mcp?.server ?? "").trim() || "unknown";

                // Extract tool name from entry params or result
                const params = entry.params as { name?: unknown; tool_name?: unknown } | undefined;
                const tool = (
                    (typeof params?.name === "string" ? params.name.trim() : "") ||
                    (typeof params?.tool_name === "string" ? params.tool_name.trim() : "") ||
                    ""
                );

                // Only count entries that actually invoke a tool (skip initialize/notifications)
                if (!tool) return;

                const aggregate = map.get(server) ?? {
                    server,
                    requests: 0,
                    failures: 0,
                    durations: [],
                    toolCounts: {}
                };

                aggregate.requests += 1;
                aggregate.toolCounts[tool] = (aggregate.toolCounts[tool] ?? 0) + 1;

                if (dur !== null) {
                    aggregate.durations.push(dur);
                }

                if (entry.error) {
                    aggregate.failures += 1;
                }

                map.set(server, aggregate);
            });
        });

        return Array.from(map.values()).filter((item) => item.requests > 0 || Object.keys(item.toolCounts).length > 0);
    }, [traces]);

    const mcpCatalog: MCPCatalogEntry[] = useMemo(() => {
        const map = new Map<string, Set<string>>();

        const pushTool = (set: Set<string>, value?: unknown) => {
            if (typeof value !== "string") return;
            const trimmed = value.trim();
            if (trimmed) set.add(trimmed);
        };

        traces
            .filter((t) => t.trace_type === "mcp_call")
            .forEach((trace) => {
                // Extract tools from each entry, using entry-level server
                trace.mcp?.entries?.forEach((entry) => {
                    const result = entry.result as { tools?: unknown } | undefined;
                    const maybeTools = Array.isArray(result?.tools) ? result?.tools : [];
                    if (maybeTools.length === 0) return;

                    // Use entry-level server (more accurate) or fall back to trace-level
                    const server = (entry.server ?? trace.mcp?.server ?? "").trim() || "unknown";
                    const toolList = map.get(server) ?? new Set<string>();

                    maybeTools.forEach((tool) => {
                        if (tool && typeof tool === "object" && "name" in tool) {
                            pushTool(toolList, (tool as { name?: unknown }).name);
                        }
                    });

                    if (toolList.size) {
                        map.set(server, toolList);
                    }
                });
            });

        return Array.from(map.entries()).map(([server, tools]) => ({ server, tools: Array.from(tools).sort() }));
    }, [traces]);

    const mcpLeaderboard = useMemo(() => {
        return mcpAggregates
            .map((item) => {
                const sorted = [...item.durations].sort((a, b) => a - b);
                const idx = Math.floor(0.95 * (sorted.length - 1));
                const p95 = sorted[idx] ?? null;
                const toolList = Object.entries(item.toolCounts)
                    .sort((a, b) => b[1] - a[1])
                    .map(([name, count]) => `${name} (${count})`);
                return {
                    server: item.server || "unknown",
                    requests: item.requests,
                    tools: toolList.length ? toolList.join(", ") : "-",
                    failures: item.failures,
                    errorRate: item.requests ? item.failures / item.requests : 0,
                    p95LatencyMs: p95
                };
            })
            .sort((a, b) => (b.requests ?? 0) - (a.requests ?? 0));
    }, [mcpAggregates]);

    const modelAggregates = useMemo(() => {
        const map = new Map<string, ModelAggregate>();
        llmTraces.forEach((trace) => {
            const key = (trace.model ?? trace.llm?.model ?? trace.llm?.model_version ?? "unknown").toLowerCase();
            const entry = map.get(key) ?? {
                model: key || "unknown",
                callCount: 0,
                avgDurationMs: null,
                errorCount: 0,
                recent: [],
                inputTokens: 0,
                outputTokens: 0
            };
            entry.callCount += 1;
            const dur = durationMs(trace);
            if (dur !== null) {
                const existing = entry.avgDurationMs ?? dur;
                entry.avgDurationMs = (existing * (entry.callCount - 1) + dur) / entry.callCount;
            }
            if ((trace.llm?.status ?? "").toLowerCase() === "error") {
                entry.errorCount += 1;
            }
            const usage = trace.resource_usage ?? {};
            entry.inputTokens += numericValue(usage.input_tokens);
            entry.outputTokens += numericValue(usage.output_tokens);
            entry.recent.push(trace);
            map.set(key, entry);
        });
        return Array.from(map.values());
    }, [llmTraces]);

    const modelTrendData = useMemo(() => {
        const bucketMap = new Map<string, { timestamp: string; model: string; inputTokens: number; outputTokens: number }>();
        llmTraces.forEach((trace) => {
            const ts = safeTime(trace.started_at ?? trace.ended_at);
            const bucket = ts ? ts.startOf("hour").toISOString() : "unknown";
            const model = (trace.model ?? trace.llm?.model ?? trace.llm?.model_version ?? "unknown").toLowerCase();
            const key = `${bucket}::${model}`;
            const entry = bucketMap.get(key) ?? {
                timestamp: bucket,
                model: model,
                inputTokens: 0,
                outputTokens: 0
            };
            const usage = trace.resource_usage ?? {};
            entry.inputTokens += numericValue(usage.input_tokens);
            entry.outputTokens += numericValue(usage.output_tokens);
            bucketMap.set(key, entry);
        });
        return Array.from(bucketMap.values()).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    }, [llmTraces]);

    const loading = agentRunsQuery.isLoading || traceQueries.some((q) => q.isLoading);

    const topAgentColumns = [
        { title: "Provider", dataIndex: ["run", "provider"], key: "provider", render: (value: string | null) => value ?? "unknown" },
        {
            title: "Calls",
            dataIndex: "callCount",
            key: "calls",
            sorter: (a: AgentRunStats, b: AgentRunStats) => b.callCount - a.callCount,
            defaultSortOrder: "descend" as const
        },
        {
            title: "Root Exec",
            dataIndex: ["run", "root_exec_id"],
            key: "root_exec",
            render: (rootExecId: string) => (
                <Typography.Link
                    onClick={() => navigate(`/trace?rootExecId=${encodeURIComponent(rootExecId)}`)}
                    style={{ fontFamily: "monospace", fontSize: 12 }}
                >
                    {rootExecId}
                </Typography.Link>
            )
        }
    ];

    const mcpColumns = [
        { title: "Server", dataIndex: "server", key: "server" },
        { title: "Requests", dataIndex: "requests", key: "requests" }
    ];

    const mcpToolColumns = [
        { title: "Server", dataIndex: "server", key: "server" },
        { title: "Tool", dataIndex: "tool", key: "tool" },
        { title: "Requests", dataIndex: "requests", key: "requests" }
    ];

    const mcpToolRows = useMemo(() => {
        return mcpAggregates
            .flatMap((item) =>
                Object.entries(item.toolCounts).map(([tool, count]) => ({
                    server: item.server || "unknown",
                    tool,
                    requests: count
                }))
            )
            .sort((a, b) => b.requests - a.requests || a.tool.localeCompare(b.tool));
    }, [mcpAggregates]);

    const modelColumns = [
        { title: "Model", dataIndex: "model", key: "model" },
        { title: "Calls", dataIndex: "callCount", key: "calls" },
        {
            title: "Error Rate",
            dataIndex: "errorCount",
            key: "error",
            render: (value: number, record: ModelAggregate) => {
                const rate = record.callCount ? (value / record.callCount) * 100 : 0;
                return `${rate.toFixed(1)}%`;
            }
        },
        {
            title: "Avg Duration",
            dataIndex: "avgDurationMs",
            key: "avg",
            render: (v: number | null) => (v ? `${Math.round(v)} ms` : "-")
        }
    ];

    const modelTableData = [...modelAggregates].sort((a, b) => b.callCount - a.callCount).slice(0, 8);

    const lineConfig = {
        data: modelTrendData,
        xField: "timestamp",
        yField: "inputTokens",
        seriesField: "model",
        smooth: true,
        tooltip: {
            formatter: (datum: { timestamp: string; model: string; inputTokens: number; outputTokens: number }) => ({
                name: `${datum.model} tokens`,
                value: `${Math.round(datum.inputTokens)} in / ${Math.round(datum.outputTokens)} out`
            })
        }
    } as const;

    const mcpColumnConfig = {
        data: mcpAggregates.map((item) => ({ server: item.server, requests: item.requests })),
        xField: "server",
        yField: "requests",
        seriesField: "server",
        legend: false
    } as const;

    return (
        <Card bordered={false} bodyStyle={{ paddingTop: 12 }}>
            <Typography.Title level={4} style={{ marginBottom: 4 }}>
                Agent Dashboard
            </Typography.Title>
            <Typography.Paragraph type="secondary" style={{ marginBottom: 24 }}>
                Provider split, MCP usage, and model consumption across agent runs within the selected window.
            </Typography.Paragraph>

            {loading ? (
                <Skeleton active />
            ) : (
                <Space direction="vertical" size={24} style={{ width: "100%" }}>
                    <Row gutter={16}>
                        <Col xs={24} md={8}>
                            <Card>
                                <Statistic title="Total Calls" value={totalCalls} />
                            </Card>
                        </Col>
                        <Col xs={24} md={8}>
                            <Card>
                                <Statistic title="Error Rate" value={errorRate} precision={1} suffix="%" />
                            </Card>
                        </Col>
                        <Col xs={24} md={8}>
                            <Card>
                                <Statistic title="Total Tokens" value={Math.round(totalTokens)} />
                            </Card>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col xs={24} md={12}>
                            <Card title="Agent Provider Distribution" extra={<Tag>{runs.length} runs</Tag>}>
                                {providerDistribution.length ? (
                                    <Space direction="vertical" style={{ width: "100%" }} size="large">
                                        {providerDistribution.map((item) => (
                                            <div key={item.provider} style={{ width: "100%" }}>
                                                <Space style={{ width: "100%", justifyContent: "space-between", marginBottom: 8 }}>
                                                    <Space>
                                                        <Tag color="blue" style={{ fontSize: 14, padding: "4px 12px" }}>
                                                            {item.provider || "unknown"}
                                                        </Tag>
                                                    </Space>
                                                    <Typography.Text strong style={{ fontSize: 18, color: "#1890ff" }}>
                                                        {item.value}
                                                    </Typography.Text>
                                                </Space>
                                            </div>
                                        ))}
                                    </Space>
                                ) : (
                                    <Empty description="No runs" />
                                )}
                            </Card>
                        </Col>
                        <Col xs={24} md={12}>
                            <Card
                                title="Top Agent Runs"
                                extra={<Tag>Top {topAgentRuns.length} by Calls</Tag>}
                            >
                                <Table
                                    size="small"
                                    pagination={false}
                                    columns={topAgentColumns}
                                    dataSource={topAgentRuns.map((item) => ({ ...item, key: item.run.id }))}
                                />
                            </Card>
                        </Col>
                    </Row>

                    <Row gutter={16}>
                        <Col xs={24} md={12}>
                            <Card title="MCP Usage" extra={<Tag>{mcpAggregates.length} servers</Tag>}>
                                {mcpAggregates.length ? (
                                    <>
                                        <Column {...mcpColumnConfig} />
                                        <Table
                                            size="small"
                                            style={{ marginTop: 12 }}
                                            pagination={false}
                                            columns={mcpColumns}
                                            dataSource={mcpLeaderboard.map((item) => ({ ...item, key: item.server }))}
                                            title={() => "Server Usage"}
                                        />
                                        <Table
                                            size="small"
                                            style={{ marginTop: 12 }}
                                            pagination={false}
                                            columns={mcpToolColumns}
                                            dataSource={mcpToolRows.map((item, idx) => ({ ...item, key: `${item.server}-${item.tool}-${idx}` }))}
                                            title={() => "Tool Usage"}
                                        />
                                    </>
                                ) : (
                                    <Empty description="No MCP calls" />
                                )}
                            </Card>
                        </Col>
                        <Col xs={24} md={12}>
                            <Card title="Model Usage" extra={<Tag>{modelTableData.length} models</Tag>}>
                                {modelTrendData.length ? <Line {...lineConfig} /> : <Empty description="No LLM calls" />}
                                <Table
                                    size="small"
                                    style={{ marginTop: 12 }}
                                    pagination={false}
                                    columns={modelColumns}
                                    dataSource={modelTableData.map((item) => ({ ...item, key: item.model }))}
                                />
                            </Card>
                        </Col>
                        <Col xs={24} md={12}>
                            <Card title="MCP Catalog (available tools)" extra={<Tag>{mcpCatalog.length} servers</Tag>}>
                                {mcpCatalog.length ? (
                                    <Table
                                        size="small"
                                        pagination={false}
                                        columns={[
                                            { title: "Server", dataIndex: "server", key: "server" },
                                            {
                                                title: "Tools",
                                                dataIndex: "tools",
                                                key: "tools",
                                                render: (tools: string[]) => (tools.length ? tools.join(", ") : "-")
                                            }
                                        ]}
                                        dataSource={mcpCatalog.map((item) => ({ ...item, key: item.server }))}
                                    />
                                ) : (
                                    <Empty description="No MCP tool catalogs" />
                                )}
                            </Card>
                        </Col>
                    </Row>

                    {/* Recent LLM Calls section removed per request */}
                </Space>
            )}
        </Card>
    );
}
