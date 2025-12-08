import { ArrowRightOutlined } from "@ant-design/icons";
import {
    Alert,
    Button,
    Card,
    Col,
    Empty,
    List,
    Modal,
    Row,
    Skeleton,
    Space,
    Table,
    Tabs,
    Tag,
    Typography
} from "antd";
import type { TabsProps } from "antd";
import type { ColumnsType } from "antd/es/table";
import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useCallback, useMemo, useState } from "react";

import { fetchPromptInjectionDetails } from "../api/analytics";
import { useSettings } from "../context/SettingsContext";
import type { HTTPRequestDetailResponse, SecurityLLMAnalysisResponse } from "../types";
import { formatTimestamp } from "../utils/time";
import { getSeverityColor, getSeverityLabel } from "../utils/severity";
import CommandBlock from "./CommandBlock";
import { decodePayload, preparePayloadContent } from "./processTimeline/helpers";

const { Text, Title, Paragraph, Link } = Typography;

interface SemanticAnalysisItem {
    id: string;
    analyzedAtRaw: string | null;
    analyzedAtDisplay: string | null;
    rootExecId: string | null;
    threatLevel: number | null;
    threatType: string | null;
    confidence: number | null;
    summary: string | null;
    details: string | null;
    recommendations: string[];
    evidence: EvidenceItem[];
}

interface EvidenceItem {
    type: string | null;
    description: string | null;
    severity: string | null;
}

interface PromptTableRow {
    key: string;
    requestId: string;
    severity: string;
    severityKey: string;
    categories: string[];
    observedAtRaw: string | null;
    observedAtDisplay: string;
    reason: string | null;
}

interface SecurityLLMAnalysisProps {
    data?: SecurityLLMAnalysisResponse;
    loading?: boolean;
    onNavigateToRootExec?: (rootExecId: string) => void;
}

const THREAT_LEVEL_META: Record<number, { label: string; color: string }> = {
    5: { label: "Critical", color: "magenta" },
    4: { label: "High", color: "volcano" },
    3: { label: "Elevated", color: "orange" },
    2: { label: "Guarded", color: "gold" },
    1: { label: "Low", color: "green" }
};

function parseRecommendations(value: unknown): string[] {
    const decoded = decodePayload(value);
    if (!decoded) {
        return [];
    }
    try {
        const parsed: unknown = JSON.parse(decoded);
        if (Array.isArray(parsed)) {
            return parsed
                .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
                .filter((entry): entry is string => Boolean(entry));
        }
    } catch {
        // fall through to delimiter parsing
    }
    return decoded
        .split(/\r?\n|•|\u2022/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
}

function parseEvidence(value: unknown): EvidenceItem[] {
    const decoded = decodePayload(value);
    if (!decoded) {
        return [];
    }
    try {
        const parsed: unknown = JSON.parse(decoded);
        if (Array.isArray(parsed)) {
            return parsed
                .map((entry) => {
                    if (entry && typeof entry === "object") {
                        const obj = entry as Record<string, unknown>;
                        return {
                            type: typeof obj.type === "string" ? obj.type : null,
                            description: typeof obj.description === "string" ? obj.description : null,
                            severity: typeof obj.severity === "string" ? obj.severity : null
                        } satisfies EvidenceItem;
                    }
                    if (typeof entry === "string") {
                        return {
                            type: null,
                            description: entry,
                            severity: null
                        } satisfies EvidenceItem;
                    }
                    return null;
                })
                .filter((entry): entry is EvidenceItem => Boolean(entry));
        }
    } catch {
        // fall through
    }
    return decoded
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .map((line) => ({ type: null, description: line, severity: null }));
}

function normalizeSeverityLabel(value: string): string {
    const lower = value.trim().toLowerCase();
    if (!lower) {
        return "Unknown";
    }
    return lower.replace(/(^|\s)([a-z])/g, (_match: string, space: string, char: string) => `${space}${char.toUpperCase()}`);
}

function toMillis(value: string | null): number {
    if (!value) {
        return Number.NEGATIVE_INFINITY;
    }
    const timestamp = new Date(value).getTime();
    return Number.isNaN(timestamp) ? Number.NEGATIVE_INFINITY : timestamp;
}

export default function SecurityLLMAnalysis({ data, loading = false, onNavigateToRootExec }: SecurityLLMAnalysisProps) {
    const { host } = useSettings();
    const [activeRequestId, setActiveRequestId] = useState<string | null>(null);
    const [requestDetails, setRequestDetails] = useState<HTTPRequestDetailResponse | null>(null);
    const [detailsOpen, setDetailsOpen] = useState(false);
    const [detailsLoading, setDetailsLoading] = useState(false);
    const [detailsError, setDetailsError] = useState<string | null>(null);

    const semanticRecords = useMemo<SemanticAnalysisItem[]>(() => {
        if (!data?.semantic?.length) {
            return [];
        }
        return data.semantic.map((record, index) => {
            const id = record.id ?? `semantic-${index}`;
            const analyzedAtDisplay = formatTimestamp(record.analyzed_at);
            return {
                id,
                analyzedAtRaw: record.analyzed_at ?? null,
                analyzedAtDisplay,
                rootExecId: record.root_exec_id ?? null,
                threatLevel: typeof record.threat_level === "number" ? record.threat_level : null,
                threatType: record.threat_type ?? null,
                confidence: typeof record.confidence === "number" ? record.confidence : null,
                summary: record.summary ?? null,
                details: record.details ?? null,
                recommendations: parseRecommendations(record.recommendations),
                evidence: parseEvidence(record.evidence)
            } satisfies SemanticAnalysisItem;
        });
    }, [data?.semantic]);

    const promptRows = useMemo(() => {
        if (!data?.prompt_injections?.length) {
            return [] as PromptTableRow[];
        }
        return data.prompt_injections.map((record, index) => {
            const requestId = record.request_id ?? `request-${index}`;
            const severity = record.severity ?? "Unknown";
            const severityKey = severity.trim().toLowerCase();
            const observedAtRaw = record.observed_at ?? null;
            const observedAtDisplay = formatTimestamp(observedAtRaw) ?? "—";
            const categories = Array.isArray(record.categories) ? record.categories.filter(Boolean) : [];
            const reason = record.reason ?? null;
            return {
                key: requestId,
                requestId,
                severity: normalizeSeverityLabel(severity),
                severityKey,
                categories,
                observedAtRaw,
                observedAtDisplay,
                reason
            } satisfies PromptTableRow;
        });
    }, [data?.prompt_injections]);

    const unsafePromptRows = useMemo(() => promptRows.filter((row) => row.severityKey !== "safe"), [promptRows]);

    const severityDistribution = useMemo(() => {
        const counts = new Map<string, number>();
        promptRows.forEach((row) => {
            const label = normalizeSeverityLabel(row.severity);
            counts.set(label, (counts.get(label) ?? 0) + 1);
        });
        return Array.from(counts.entries()).map(([name, value]) => ({ name, value }));
    }, [promptRows]);

    const categoryDistribution = useMemo(() => {
        const counts = new Map<string, number>();
        promptRows.forEach((row) => {
            row.categories.forEach((category) => {
                const key = category.trim();
                if (!key) {
                    return;
                }
                counts.set(key, (counts.get(key) ?? 0) + 1);
            });
        });
        return Array.from(counts.entries()).map(([name, value]) => ({ name, value }));
    }, [promptRows]);

    const severityChartOption = useMemo<EChartsOption | null>(() => {
        if (!severityDistribution.length) {
            return null;
        }
        return {
            tooltip: { trigger: "item" },
            legend: { orient: "vertical", left: "left" },
            series: [
                {
                    name: "Prompt Severity",
                    type: "pie",
                    radius: ["45%", "72%"],
                    padAngle: 3,
                    itemStyle: {
                        borderRadius: 10,
                        borderColor: "#fff",
                        borderWidth: 2
                    },
                    label: { formatter: "{b}: {c}" },
                    data: severityDistribution
                }
            ]
        } satisfies EChartsOption;
    }, [severityDistribution]);

    const categoryChartOption = useMemo<EChartsOption | null>(() => {
        if (!categoryDistribution.length) {
            return null;
        }
        return {
            tooltip: { trigger: "item" },
            legend: { orient: "vertical", left: "left" },
            series: [
                {
                    name: "Prompt Categories",
                    type: "pie",
                    radius: ["45%", "72%"],
                    padAngle: 3,
                    itemStyle: {
                        borderRadius: 10,
                        borderColor: "#fff",
                        borderWidth: 2
                    },
                    label: { formatter: "{b}: {c}" },
                    data: categoryDistribution
                }
            ]
        } satisfies EChartsOption;
    }, [categoryDistribution]);

    const handleOpenRequestDetails = useCallback(
        async (requestId: string) => {
            setActiveRequestId(requestId);
            setDetailsOpen(true);
            setDetailsLoading(true);
            setDetailsError(null);
            setRequestDetails(null);
            try {
                if (!host) {
                    throw new Error("Select a host before viewing request details");
                }
                const details = await fetchPromptInjectionDetails(host, requestId);
                setRequestDetails(details);
            } catch (error) {
                const message = error instanceof Error ? error.message : "Failed to load request details";
                setDetailsError(message);
            } finally {
                setDetailsLoading(false);
            }
        },
        [host]
    );

    const handleCloseDetails = useCallback(() => {
        setDetailsOpen(false);
        setActiveRequestId(null);
        setRequestDetails(null);
        setDetailsError(null);
    }, []);

    const promptColumns = useMemo<ColumnsType<PromptTableRow>>(
        () => [
            {
                title: "Observed At",
                dataIndex: "observedAtDisplay",
                sorter: (a, b) => toMillis(a.observedAtRaw) - toMillis(b.observedAtRaw),
                defaultSortOrder: "descend",
                sortDirections: ["descend", "ascend"]
            },
            {
                title: "Request ID",
                dataIndex: "requestId",
                render: (value: string) => (
                    <Button
                        type="link"
                        onClick={() => {
                            void handleOpenRequestDetails(value);
                        }}
                        style={{ padding: 0 }}
                    >
                        {value}
                    </Button>
                )
            },
            {
                title: "Severity",
                dataIndex: "severity",
                render: (_: string, row) => (
                    <Tag color={getSeverityColor(row.severity)}>{getSeverityLabel(row.severity)}</Tag>
                )
            },
            {
                title: "Categories",
                dataIndex: "categories",
                render: (value: string[], row) => (
                    <Space size={4} wrap>
                        {value.length ? (
                            value.map((category, index) => (
                                <Tag key={`${row.requestId}-${category}-${index}`} color="processing">
                                    {category}
                                </Tag>
                            ))
                        ) : (
                            <Tag color="default">Uncategorized</Tag>
                        )}
                    </Space>
                )
            },
            {
                title: "Reason",
                dataIndex: "reason",
                render: (value: string | null) => {
                    if (!value) {
                        return <Text type="secondary">—</Text>;
                    }
                    return (
                        <Text style={{ fontSize: "13px", lineHeight: "1.5" }} ellipsis={{ tooltip: value }}>
                            {value}
                        </Text>
                    );
                },
                width: "30%"
            }
        ],
        [handleOpenRequestDetails]
    );

    const semanticContent = useMemo(() => {
        if (!semanticRecords.length) {
            return <Empty description="No semantic analysis yet" image={Empty.PRESENTED_IMAGE_SIMPLE} />;
        }
        return (
            <List
                split={false}
                dataSource={semanticRecords}
                itemLayout="vertical"
                renderItem={(item) => {
                    const threatMeta = item.threatLevel ? THREAT_LEVEL_META[Math.round(item.threatLevel)] : undefined;
                    const confidencePercent = item.confidence != null ? `${Math.round(item.confidence * 100)}%` : null;
                    return (
                        <List.Item
                            key={item.id}
                            style={{
                                border: "1px solid #e2e8f0",
                                borderRadius: 20,
                                padding: 24,
                                marginBottom: 16,
                                background: "linear-gradient(180deg, #ffffff 0%, #f8fafc 100%)",
                                boxShadow: "0 24px 48px -40px rgba(15, 23, 42, 0.35)"
                            }}
                        >
                            <Space direction="vertical" size={16} style={{ width: "100%" }}>
                                <Space align="start" size={16} wrap style={{ justifyContent: "space-between", width: "100%" }}>
                                    <Space size={8} wrap>
                                        {threatMeta ? <Tag color={threatMeta.color}>{threatMeta.label}</Tag> : <Tag color="default">Threat Level N/A</Tag>}
                                        {item.threatType ? <Tag>{item.threatType}</Tag> : null}
                                        {confidencePercent ? <Tag color="blue">Confidence {confidencePercent}</Tag> : null}
                                    </Space>
                                    <Space direction="vertical" size={6} align="end">
                                        {item.rootExecId ? (
                                            <Space size={6} align="center" wrap>
                                                <Text
                                                    type="secondary"
                                                    style={{
                                                        fontSize: 11,
                                                        textTransform: "uppercase",
                                                        letterSpacing: "0.08em",
                                                        color: "#64748b"
                                                    }}
                                                >
                                                    Root Exec
                                                </Text>
                                                <Link
                                                    onClick={() => onNavigateToRootExec?.(item.rootExecId!)}
                                                    style={{
                                                        fontFamily: "JetBrains Mono, Fira Code, Menlo, monospace",
                                                        fontSize: 12,
                                                        display: "inline-flex",
                                                        alignItems: "center",
                                                        gap: 6
                                                    }}
                                                >
                                                    {item.rootExecId}
                                                    <ArrowRightOutlined style={{ fontSize: 12 }} />
                                                </Link>
                                            </Space>
                                        ) : null}
                                        <Text type="secondary" style={{ fontSize: 12 }}>
                                            {item.analyzedAtDisplay ?? "Unknown time"}
                                        </Text>
                                    </Space>
                                </Space>
                                {item.summary ? (
                                    <Title level={5} style={{ margin: 0 }}>
                                        {item.summary}
                                    </Title>
                                ) : null}
                                {item.details ? <Paragraph style={{ marginBottom: 0, color: "#1f2937" }}>{item.details}</Paragraph> : null}
                                <Space direction="vertical" size={14} style={{ width: "100%" }}>
                                    {item.recommendations.length ? (
                                        <div>
                                            <Text
                                                strong
                                                style={{
                                                    display: "block",
                                                    textTransform: "uppercase",
                                                    letterSpacing: "0.06em",
                                                    fontSize: 12,
                                                    color: "#64748b"
                                                }}
                                            >
                                                Recommendations
                                            </Text>
                                            <Space direction="vertical" size={6} style={{ marginTop: 6, width: "100%" }}>
                                                {item.recommendations.map((rec, index) => (
                                                    <Text key={`${item.id}-rec-${index}`} style={{ display: "block", color: "#0f172a" }}>
                                                        • {rec}
                                                    </Text>
                                                ))}
                                            </Space>
                                        </div>
                                    ) : null}
                                    {item.evidence.length ? (
                                        <div>
                                            <Text
                                                strong
                                                style={{
                                                    display: "block",
                                                    textTransform: "uppercase",
                                                    letterSpacing: "0.06em",
                                                    fontSize: 12,
                                                    color: "#64748b"
                                                }}
                                            >
                                                Evidence
                                            </Text>
                                            <Space direction="vertical" size={6} style={{ marginTop: 6, width: "100%" }}>
                                                {item.evidence.map((evidenceItem, index) => (
                                                    <Space key={`${item.id}-evidence-${index}`} align="start" size={8} wrap>
                                                        {evidenceItem.type ? <Tag color="geekblue">{evidenceItem.type}</Tag> : null}
                                                        {evidenceItem.severity ? <Tag color="purple">{evidenceItem.severity}</Tag> : null}
                                                        {evidenceItem.description ? <Text>{evidenceItem.description}</Text> : null}
                                                    </Space>
                                                ))}
                                            </Space>
                                        </div>
                                    ) : null}
                                </Space>
                            </Space>
                        </List.Item>
                    );
                }}
            />
        );
    }, [onNavigateToRootExec, semanticRecords]);

    const promptContent = useMemo(() => {
        if (!promptRows.length) {
            return <Empty description="No prompt inspections yet" image={Empty.PRESENTED_IMAGE_SIMPLE} />;
        }
        return (
            <Space direction="vertical" size={20} style={{ width: "100%" }}>
                <Row gutter={[16, 16]}>
                    <Col xs={24} md={12}>
                        {severityChartOption ? (
                            <Card title="Severity Distribution" bordered={false}>
                                <ReactECharts option={severityChartOption} style={{ height: 280 }} notMerge lazyUpdate />
                            </Card>
                        ) : (
                            <Card bordered={false}>
                                <Empty description="No severity data" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                            </Card>
                        )}
                    </Col>
                    <Col xs={24} md={12}>
                        {categoryChartOption ? (
                            <Card title="Category Breakdown" bordered={false}>
                                <ReactECharts option={categoryChartOption} style={{ height: 280 }} notMerge lazyUpdate />
                            </Card>
                        ) : (
                            <Card bordered={false}>
                                <Empty description="No category data" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                            </Card>
                        )}
                    </Col>
                </Row>
                <Card bordered={false} title="Prompt Injection Events">
                    <Table
                        columns={promptColumns}
                        dataSource={unsafePromptRows}
                        pagination={{ pageSize: 10, showSizeChanger: false }}
                        scroll={{ x: true }}
                        locale={{ emptyText: "No unsafe prompts detected" }}
                    />
                </Card>
            </Space>
        );
    }, [categoryChartOption, promptColumns, promptRows.length, severityChartOption, unsafePromptRows]);

    const tabs: TabsProps["items"] = useMemo(
        () => [
            { key: "prompts", label: "Prompt Analysis", children: promptContent },
            { key: "semantic", label: "Semantic Threats", children: semanticContent }
        ],
        [promptContent, semanticContent]
    );

    const decodedHeaders = decodePayload(requestDetails?.headers);
    const decodedBody = decodePayload(requestDetails?.body);
    const headersContent = useMemo(() => preparePayloadContent(decodedHeaders), [decodedHeaders]);
    const bodyContent = useMemo(() => preparePayloadContent(decodedBody), [decodedBody]);

    return (
        <Card
            title="Security LLM Analysis"
            bordered={false}
            bodyStyle={{ paddingTop: 16 }}
            headStyle={{
                borderBottom: "none",
                fontWeight: 600,
                fontSize: 20,
                letterSpacing: "-0.01em",
                color: "#0f172a"
            }}
        >
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
                <Text type="secondary">
                    Insights generated by secondary LLM analysis pipelines. Monitor high-risk behaviors, review remediation guidance, and track prompt injection
                    scans.
                </Text>
                {loading ? (
                    <Skeleton active paragraph={{ rows: 6 }} />
                ) : (
                    <Tabs defaultActiveKey="prompts" destroyInactiveTabPane items={tabs} />
                )}
            </Space>
            <Modal
                title={activeRequestId ? `Request Details · ${activeRequestId}` : "Request Details"}
                open={detailsOpen}
                onCancel={handleCloseDetails}
                footer={null}
                width={720}
                destroyOnClose
            >
                <Space direction="vertical" size={16} style={{ width: "100%" }}>
                    {detailsLoading ? <Skeleton active paragraph={{ rows: 6 }} /> : null}
                    {detailsError ? <Alert type="error" message={detailsError} /> : null}
                    {!detailsLoading && !detailsError && requestDetails ? (
                        <Space direction="vertical" size={12} style={{ width: "100%" }}>
                            <Row gutter={[12, 12]}>
                                <Col span={12}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">Observed</Text>
                                        <Text strong>{formatTimestamp(requestDetails.timestamp) ?? "—"}</Text>
                                    </Space>
                                </Col>
                                <Col span={12}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">Method</Text>
                                        <Text strong>{requestDetails.method ?? "—"}</Text>
                                    </Space>
                                </Col>
                                <Col span={24}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">URL</Text>
                                        <Text strong style={{ wordBreak: "break-all" }}>{requestDetails.url ?? "—"}</Text>
                                    </Space>
                                </Col>
                                <Col span={12}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">Command</Text>
                                        <Text strong>{requestDetails.comm ?? "—"}</Text>
                                    </Space>
                                </Col>
                                <Col span={12}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">PID / TID</Text>
                                        <Text strong>{[requestDetails.pid, requestDetails.tid].filter((value) => value != null).join(" / ") || "—"}</Text>
                                    </Space>
                                </Col>
                                <Col span={12}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">UID / GID</Text>
                                        <Text strong>{[requestDetails.uid, requestDetails.gid].filter((value) => value != null).join(" / ") || "—"}</Text>
                                    </Space>
                                </Col>
                                <Col span={12}>
                                    <Space direction="vertical" size={4}>
                                        <Text type="secondary">Content Length</Text>
                                        <Text strong>{requestDetails.content_length ?? "—"}</Text>
                                    </Space>
                                </Col>
                            </Row>
                            {decodedHeaders ? (
                                <Space direction="vertical" size={6} style={{ width: "100%" }}>
                                    <Text strong>Headers</Text>
                                    {headersContent ? (
                                        <div dangerouslySetInnerHTML={{ __html: headersContent }} />
                                    ) : (
                                        <CommandBlock text={decodedHeaders} size="small" />
                                    )}
                                </Space>
                            ) : null}
                            {decodedBody ? (
                                <Space direction="vertical" size={6} style={{ width: "100%" }}>
                                    <Text strong>Body</Text>
                                    {bodyContent ? (
                                        <div dangerouslySetInnerHTML={{ __html: bodyContent }} />
                                    ) : (
                                        <CommandBlock text={decodedBody} size="small" />
                                    )}
                                </Space>
                            ) : null}
                            {requestDetails.truncated ? <Alert type="warning" message="Body truncated for transmission" showIcon /> : null}
                        </Space>
                    ) : null}
                </Space>
            </Modal>
        </Card>
    );
}
