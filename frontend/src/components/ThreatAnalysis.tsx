import { ExclamationCircleOutlined, InfoCircleOutlined, SyncOutlined, WarningOutlined } from "@ant-design/icons";
import { Button, Card, Col, List, Modal, Progress, Row, Space, Tag, Typography, message } from "antd";
import { useCallback, useEffect, useState } from "react";

import { analyzeThreat, fetchThreatAnalysis } from "../api/analytics";
import type { ThreatAnalysisResponse } from "../types/api";

const { Text, Paragraph } = Typography;

interface ThreatAnalysisProps {
    rootExecId: string;
}

function getThreatLevelColor(level: number): string {
    if (level >= 5) return "#f5222d"; // critical - red
    if (level >= 4) return "#fa8c16"; // high - orange
    if (level >= 3) return "#faad14"; // medium - yellow
    return "#52c41a"; // low - green
}

function getThreatLevelLabel(level: number): string {
    if (level >= 5) return "Critical";
    if (level >= 4) return "High";
    if (level >= 3) return "Medium";
    return "Low";
}

function getThreatLevelIcon(level: number) {
    if (level >= 4) return <ExclamationCircleOutlined />;
    if (level >= 3) return <WarningOutlined />;
    return <InfoCircleOutlined />;
}

export default function ThreatAnalysis({ rootExecId }: ThreatAnalysisProps) {
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<ThreatAnalysisResponse | null>(null);
    const [modalVisible, setModalVisible] = useState(false);

    useEffect(() => {
        let cancelled = false;
        async function loadHistorical() {
            if (!rootExecId) {
                setResult(null);
                return;
            }

            try {
                const data = await fetchThreatAnalysis(rootExecId);
                if (!cancelled) {
                    setResult(data);
                }
            } catch {
                if (!cancelled) {
                    setResult(null);
                }
            }
        }

        void loadHistorical();
        return () => {
            cancelled = true;
        };
    }, [rootExecId]);

    const runAnalysis = useCallback(async () => {
        if (!rootExecId) {
            void message.error("No root execution ID provided");
            return;
        }

        setLoading(true);

        try {
            const data = await analyzeThreat(rootExecId);
            setResult(data);
            setModalVisible(true);
            void message.success("Threat analysis completed");
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : "Failed to analyze threat";
            void message.error(errorMessage);
        } finally {
            setLoading(false);
        }
    }, [rootExecId]);

    const handleViewResult = useCallback(() => {
        setModalVisible(true);
    }, []);

    const handleCloseModal = useCallback(() => {
        setModalVisible(false);
    }, []);

    const threatLevel = result?.threat_level ?? 0;
    const threatColor = getThreatLevelColor(threatLevel);
    const threatLabel = getThreatLevelLabel(threatLevel);
    const confidencePercent = result ? Math.round(result.confidence * 100) : 0;

    return (
        <>
            <Space size={8}>
                <Button
                    type="default"
                    size="middle"
                    loading={loading}
                    onClick={result ? handleViewResult : runAnalysis}
                    icon={result ? <ExclamationCircleOutlined /> : <SyncOutlined />}
                    style={{
                        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                        fontSize: 13,
                        fontWeight: 600,
                        padding: "6px 16px",
                        height: "auto",
                        border: "1.5px solid #d9d9d9",
                        color: result && threatLevel >= 4 ? threatColor : "#262626",
                        background: result && threatLevel >= 4 ? `${threatColor}15` : "#ffffff",
                        borderRadius: 6,
                        boxShadow: "0 2px 4px rgba(0, 0, 0, 0.05)",
                        transition: "all 0.3s ease"
                    }}
                    onMouseEnter={(e) => {
                        e.currentTarget.style.transform = "translateY(-1px)";
                        e.currentTarget.style.boxShadow = "0 4px 8px rgba(0, 0, 0, 0.1)";
                    }}
                    onMouseLeave={(e) => {
                        e.currentTarget.style.transform = "translateY(0)";
                        e.currentTarget.style.boxShadow = "0 2px 4px rgba(0, 0, 0, 0.05)";
                    }}
                >
                    {loading ? "Analyzing..." : result ? "Threat Analysis" : "Run Threat Analysis"}
                </Button>
                {result && (
                    <Tag
                        color={threatColor}
                        style={{
                            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                            fontSize: 12,
                            fontWeight: 600,
                            padding: "4px 10px",
                            margin: 0,
                            borderRadius: 4
                        }}
                    >
                        {threatLabel} • Level {threatLevel}
                    </Tag>
                )}
            </Space>

            <Modal
                title={
                    <Space>
                        {getThreatLevelIcon(threatLevel)}
                        <span>Threat Analysis Result</span>
                    </Space>
                }
                open={modalVisible}
                onCancel={handleCloseModal}
                width={800}
                footer={[
                    <Button
                        key="reanalyze"
                        icon={<SyncOutlined />}
                        onClick={() => {
                            void runAnalysis();
                        }}
                        loading={loading}
                    >
                        Re-analyze
                    </Button>,
                    <Button key="close" type="primary" onClick={handleCloseModal}>
                        Close
                    </Button>
                ]}
            >
                {result && (
                    <Space direction="vertical" size={24} style={{ width: "100%" }}>
                        {/* Threat Level Overview */}
                        <Row gutter={16}>
                            <Col span={12}>
                                <Card size="small" bordered={false} style={{ background: "#fafafa" }}>
                                    <Space direction="vertical" align="center" style={{ width: "100%" }}>
                                        <Text type="secondary" strong>Threat Level</Text>
                                        <Progress
                                            type="circle"
                                            percent={threatLevel * 20}
                                            strokeColor={threatColor}
                                            strokeWidth={6}
                                            width={100}
                                            format={() => (
                                                <Space direction="vertical" align="center" size={0}>
                                                    <Text strong style={{ fontSize: 24, color: threatColor }}>
                                                        {threatLevel}
                                                    </Text>
                                                    <Text style={{ fontSize: 12, fontWeight: 600 }}>{threatLabel}</Text>
                                                </Space>
                                            )}
                                        />
                                    </Space>
                                </Card>
                            </Col>
                            <Col span={12}>
                                <Card size="small" bordered={false} style={{ background: "#fafafa" }}>
                                    <Space direction="vertical" align="center" style={{ width: "100%" }}>
                                        <Text type="secondary" strong>Confidence</Text>
                                        <Progress
                                            type="circle"
                                            percent={confidencePercent}
                                            strokeColor="#1890ff"
                                            strokeWidth={6}
                                            width={100}
                                            format={() => (
                                                <Space direction="vertical" align="center" size={0}>
                                                    <Text strong style={{ fontSize: 24, color: "#1890ff" }}>
                                                        {confidencePercent}%
                                                    </Text>
                                                </Space>
                                            )}
                                        />
                                    </Space>
                                </Card>
                            </Col>
                        </Row>

                        {/* Summary */}
                        <Card size="small" bordered={false} style={{ background: "#fafafa" }}>
                            <Space direction="vertical" size={8} style={{ width: "100%" }}>
                                <Space>
                                    <Tag color={threatColor} style={{ fontSize: 13, padding: "3px 10px" }}>
                                        {result.threat_type}
                                    </Tag>
                                    <Text type="secondary" style={{ fontSize: 12 }}>
                                        Root Exec ID: {result.root_exec_id}
                                    </Text>
                                </Space>
                                <Paragraph style={{ marginBottom: 0 }}>{result.summary}</Paragraph>
                            </Space>
                        </Card>

                        {/* Detailed Analysis */}
                        {result.details && (
                            <Card size="small" title="Detailed Analysis" bordered={false} style={{ background: "#fafafa" }}>
                                <Paragraph style={{ whiteSpace: "pre-wrap", marginBottom: 0 }}>
                                    {result.details}
                                </Paragraph>
                            </Card>
                        )}

                        {/* Evidence */}
                        {result.evidence && result.evidence.length > 0 && (
                            <Card size="small" title="Evidence" bordered={false} style={{ background: "#fafafa" }}>
                                <List
                                    size="small"
                                    dataSource={result.evidence}
                                    renderItem={(item, index) => {
                                        const evidenceType = (item as { type?: string }).type;
                                        const evidenceDescription = (item as { description?: string }).description;
                                        return (
                                            <List.Item>
                                                <Space direction="vertical" style={{ width: "100%" }}>
                                                    <Text strong>
                                                        {index + 1}. {evidenceType || "Evidence"}
                                                    </Text>
                                                    <Text>{evidenceDescription || JSON.stringify(item)}</Text>
                                                </Space>
                                            </List.Item>
                                        );
                                    }}
                                />
                            </Card>
                        )}

                        {/* Recommendations */}
                        {result.recommendations && result.recommendations.length > 0 && (
                            <Card size="small" title="Recommendations" bordered={false} style={{ background: "#fafafa" }}>
                                <List
                                    size="small"
                                    dataSource={result.recommendations}
                                    renderItem={(item) => (
                                        <List.Item>
                                            <Space>
                                                <InfoCircleOutlined style={{ color: "#1890ff" }} />
                                                <Text>{item}</Text>
                                            </Space>
                                        </List.Item>
                                    )}
                                />
                            </Card>
                        )}
                    </Space>
                )}
            </Modal>
        </>
    );
}
