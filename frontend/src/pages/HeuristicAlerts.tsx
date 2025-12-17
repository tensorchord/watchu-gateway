import { Button, Card, Descriptions, List, Modal, Result, Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";
import { useState } from "react";

import { useSettings } from "../context/SettingsContext";
import { useHeuristicAlerts } from "../hooks/useAnalytics";
import { HeuristicAlertResponse } from "../types/api";
import { getSeverityColor, getSeverityLabel } from "../utils/severity";
import CommandBlock from "../components/CommandBlock";

const { Text, Paragraph } = Typography;

interface PromptEvidenceItem {
    id: string | null;
    type: string | null;
    source: string | null;
    severity: string | null;
    quote: string | null;
    interpretation: string | null;
}

function parsePromptEvidence(value: unknown): PromptEvidenceItem[] {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value
            .map((entry): PromptEvidenceItem | null => {
                if (!entry || typeof entry !== "object") {
                    return null;
                }
                const obj = entry as Record<string, unknown>;
                return {
                    id: typeof obj.id === "string" ? obj.id : null,
                    type: typeof obj.type === "string" ? obj.type : null,
                    source: typeof obj.source === "string" ? obj.source : null,
                    severity: typeof obj.severity === "string" ? obj.severity : null,
                    quote: typeof obj.quote === "string" ? obj.quote : null,
                    interpretation: typeof obj.interpretation === "string" ? obj.interpretation : null
                } satisfies PromptEvidenceItem;
            })
            .filter((entry): entry is PromptEvidenceItem => entry !== null);
    }
    return [];
}

function decodeBinaryDetails(value: unknown): string | null {
    if (!Array.isArray(value)) {
        return null;
    }
    try {
        const array = new Uint8Array(value.map((entry) => Number(entry) & 0xff));
        return new TextDecoder().decode(array);
    } catch {
        return null;
    }
}

function parseAlertDetails(value: unknown): Record<string, unknown> | null {
    if (!value) {
        return null;
    }
    if (typeof value === "string") {
        try {
            return JSON.parse(value) as Record<string, unknown>;
        } catch {
            return null;
        }
    }
    const decoded = decodeBinaryDetails(value);
    if (decoded) {
        try {
            return JSON.parse(decoded) as Record<string, unknown>;
        } catch {
            return null;
        }
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
        return value as Record<string, unknown>;
    }
    return null;
}

export default function HeuristicAlerts() {
    const { host, since, until, limit } = useSettings();
    const alertsQuery = useHeuristicAlerts(host, since, until, limit);
    const [selectedAlert, setSelectedAlert] = useState<HeuristicAlertResponse | null>(null);
    const [detailsOpen, setDetailsOpen] = useState(false);

    const handleViewDetails = (alert: HeuristicAlertResponse) => {
        setSelectedAlert(alert);
        setDetailsOpen(true);
    };

    const handleCloseDetails = () => {
        setDetailsOpen(false);
        setSelectedAlert(null);
    };

    const columns: ColumnsType<HeuristicAlertResponse> = [
        {
            title: "Alert ID",
            dataIndex: "alert_id",
            key: "alert_id",
            render: (value: string | undefined, record: HeuristicAlertResponse) => (
                <Button
                    type="link"
                    onClick={() => handleViewDetails(record)}
                    style={{ padding: 0, height: "auto", fontFamily: "monospace", fontSize: "13px" }}
                >
                    {value ?? "--"}
                </Button>
            )
        },
        {
            title: "Type",
            dataIndex: "alert_type",
            key: "alert_type"
        },
        {
            title: "Severity",
            dataIndex: "severity",
            key: "severity",
            render: (value: string | undefined) => {
                const label = getSeverityLabel(value ?? "--");
                return <Tag color={getSeverityColor(value)}>{label}</Tag>;
            }
        },
        {
            title: "Score",
            dataIndex: "score",
            key: "score",
            render: (value: number | undefined) => (value != null ? value.toFixed(2) : "--")
        },
        {
            title: "Start",
            dataIndex: "start_ts",
            key: "start_ts",
            render: (value: string | undefined) => (value ? dayjs(value).format("YYYY-MM-DD HH:mm:ss") : "--")
        },
        {
            title: "End",
            dataIndex: "end_ts",
            key: "end_ts",
            render: (value: string | undefined) => (value ? dayjs(value).format("YYYY-MM-DD HH:mm:ss") : "--")
        }
    ];

    if (alertsQuery.error) {
        const message = alertsQuery.error instanceof Error ? alertsQuery.error.message : "Unknown error";
        return <Result status="error" title="Unable to load heuristic alerts" subTitle={message} />;
    }

    const dataSource = Array.isArray(alertsQuery.data) ? alertsQuery.data : [];

    const renderDetails = () => {
        if (!selectedAlert?.details) {
            return <Text type="secondary">No details available</Text>;
        }
        const detailsObj = parseAlertDetails(selectedAlert.details);
        if (!detailsObj) {
            return <Text type="secondary">Invalid details format</Text>;
        }
        return <pre style={{ background: "#f5f5f5", padding: 12, borderRadius: 4, fontSize: "13px", maxHeight: 400, overflow: "auto" }}>
            {JSON.stringify(detailsObj, null, 2)}
        </pre>;
    };

    const renderEvidence = () => {
        if (!selectedAlert?.details) {
            return null;
        }
        const detailsObj = parseAlertDetails(selectedAlert.details);
        if (!detailsObj) {
            return null;
        }
        const evidence = parsePromptEvidence(detailsObj.evidence);
        if (!evidence.length) {
            return null;
        }
        return (
            <div style={{ marginTop: 16 }}>
                <Text strong style={{ fontSize: "14px" }}>Evidence:</Text>
                <div style={{ marginTop: 8 }}>
                    <List
                        size="small"
                        split={false}
                        dataSource={evidence}
                        renderItem={(item, index) => {
                            const quote = item.quote?.trim() ?? "";
                            const interpretation = item.interpretation?.trim() ?? "";
                            const title = item.type ? `${item.type}${item.source ? ` · ${item.source}` : ""}` : `Evidence ${index + 1}`;
                            return (
                                <List.Item style={{ paddingLeft: 0, paddingRight: 0 }}>
                                    <Space direction="vertical" size={8} style={{ width: "100%" }}>
                                        <Space size={8} wrap>
                                            <Text strong style={{ fontSize: 12, color: "#0f172a" }}>
                                                {title}
                                            </Text>
                                            {item.severity ? <Tag>{item.severity}</Tag> : null}
                                            {item.id ? (
                                                <Text type="secondary" style={{ fontFamily: "JetBrains Mono, Fira Code, Menlo, monospace", fontSize: 11 }}>
                                                    {item.id}
                                                </Text>
                                            ) : null}
                                        </Space>
                                        {quote ? <CommandBlock text={quote} size="small" /> : <Text type="secondary">—</Text>}
                                        {interpretation ? <Text style={{ fontSize: 13, color: "#1f2937" }}>{interpretation}</Text> : null}
                                    </Space>
                                </List.Item>
                            );
                        }}
                    />
                </div>
            </div>
        );
    };

    return (
        <>
            <Card bordered={false}>
                <Table
                    rowKey={(record: HeuristicAlertResponse) =>
                        record.alert_id ?? `${record.alert_type ?? "type"}-${record.start_ts ?? "start"}-${record.end_ts ?? "end"}-${record.score ?? "score"}`
                    }
                    columns={columns}
                    dataSource={dataSource}
                    loading={alertsQuery.isLoading}
                    pagination={{ pageSize: 10 }}
                />
            </Card>

            <Modal
                title="Alert Details"
                open={detailsOpen}
                onCancel={handleCloseDetails}
                footer={[
                    <Button key="close" onClick={handleCloseDetails}>
                        Close
                    </Button>
                ]}
                width={800}
            >
                {selectedAlert && (
                    <>
                        <Descriptions bordered column={1} size="small">
                            <Descriptions.Item label="Alert ID">
                                <Text code style={{ fontSize: "13px" }}>{selectedAlert.alert_id}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="Type">
                                <Text strong>{selectedAlert.alert_type}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="Severity">
                                <Tag color={getSeverityColor(selectedAlert.severity)}>
                                    {getSeverityLabel(selectedAlert.severity ?? "--")}
                                </Tag>
                            </Descriptions.Item>
                            <Descriptions.Item label="Score">
                                {selectedAlert.score != null ? selectedAlert.score.toFixed(2) : "--"}
                            </Descriptions.Item>
                            <Descriptions.Item label="Host">
                                <Text code style={{ fontSize: "13px" }}>{selectedAlert.host}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="Root Exec ID">
                                <Text code style={{ fontSize: "13px" }}>{selectedAlert.root_exec_id ?? "--"}</Text>
                            </Descriptions.Item>
                            <Descriptions.Item label="Root PID">
                                {selectedAlert.root_pid ?? "--"}
                            </Descriptions.Item>
                            <Descriptions.Item label="Start Time">
                                {selectedAlert.start_ts ? dayjs(selectedAlert.start_ts).format("YYYY-MM-DD HH:mm:ss") : "--"}
                            </Descriptions.Item>
                            <Descriptions.Item label="End Time">
                                {selectedAlert.end_ts ? dayjs(selectedAlert.end_ts).format("YYYY-MM-DD HH:mm:ss") : "--"}
                            </Descriptions.Item>
                        </Descriptions>

                        {selectedAlert.reason && (
                            <div style={{ marginTop: 16 }}>
                                <Text strong style={{ fontSize: "14px" }}>Reason:</Text>
                                <Paragraph
                                    style={{
                                        marginTop: 8,
                                        padding: 12,
                                        background: "#fff2e8",
                                        border: "1px solid #ffbb96",
                                        borderRadius: 4,
                                        fontSize: "13px",
                                        color: "#d32f2f"
                                    }}
                                >
                                    {selectedAlert.reason}
                                </Paragraph>
                            </div>
                        )}

                        {renderEvidence()}

                        <div style={{ marginTop: 16 }}>
                            <Text strong style={{ fontSize: "14px" }}>Details:</Text>
                            <div style={{ marginTop: 8 }}>
                                {renderDetails()}
                            </div>
                        </div>
                    </>
                )}
            </Modal>
        </>
    );
}
