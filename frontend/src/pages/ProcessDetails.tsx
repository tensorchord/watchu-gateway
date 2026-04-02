import { ArrowLeftOutlined } from "@ant-design/icons";
import { Card, Col, Descriptions, Empty, Flex, Result, Row, Skeleton, Space, Tabs, Tag, Typography } from "antd";
import dayjs from "dayjs";
import { useMemo, type CSSProperties } from "react";
import { useNavigate, useParams } from "react-router-dom";

import ProcessEventsTable from "../components/ProcessEventsTable";
import ProcessTimeline from "../components/ProcessTimeline";
import ProcessTreePanel from "../components/ProcessTreePanel";
import { useSettings } from "../context/SettingsContext";
import { useProcessEvents, useProcessHttpEvents, useProcessSummary, useProcessTree } from "../hooks/useAnalytics";
import { HeuristicAlertResponse, ProcessEventResponse, ProcessHTTPEventResponse, ProcessSummaryMeta } from "../types/api";

const { Title, Text } = Typography;

const CARD_STYLE: CSSProperties = {
    borderRadius: 18,
    border: "1px solid #e2e8f0",
    boxShadow: "0 30px 80px -48px rgba(15,23,42,0.55)",
    background: "#ffffff"
};

const CARD_HEAD_STYLE: CSSProperties = {
    borderBottom: "1px solid rgba(15,23,42,0.06)",
    padding: "16px 24px",
    fontWeight: 600,
    fontSize: 18,
    background: "linear-gradient(135deg, rgba(248,250,252,1) 0%, rgba(255,255,255,1) 100%)"
};

const COLUMN_STACK_STYLE: CSSProperties = {
    display: "flex",
    flexDirection: "column",
    gap: 24
};

function renderSeverityTag(severity?: string) {
    if (!severity) {
        return <Tag>Unknown</Tag>;
    }
    const tone = severity.toLowerCase();
    if (tone === "critical" || tone === "high") {
        return <Tag color="red">{severity}</Tag>;
    }
    if (tone === "medium") {
        return <Tag color="orange">{severity}</Tag>;
    }
    return <Tag color="blue">{severity}</Tag>;
}

function renderProcessMetadata(meta?: ProcessSummaryMeta, loading?: boolean) {
    if (loading) {
        return <Skeleton active paragraph={{ rows: 4 }} />;
    }
    if (!meta) {
        return <Empty description="No metadata for this process" image={Empty.PRESENTED_IMAGE_SIMPLE} />;
    }

    return (
        <Descriptions bordered column={1} size="small">
            <Descriptions.Item label="Exec ID">{meta.exec_id ?? "--"}</Descriptions.Item>
            <Descriptions.Item label="Command">{meta.comm ?? "--"}</Descriptions.Item>
            <Descriptions.Item label="Arguments">{meta.args ?? "--"}</Descriptions.Item>
            <Descriptions.Item label="First Seen">
                {meta.first_seen ? dayjs(meta.first_seen).format("YYYY-MM-DD HH:mm:ss") : "--"}
            </Descriptions.Item>
            <Descriptions.Item label="Last Seen">
                {meta.last_seen ? dayjs(meta.last_seen).format("YYYY-MM-DD HH:mm:ss") : "--"}
            </Descriptions.Item>
            <Descriptions.Item label="Event Count">{meta.event_count ?? 0}</Descriptions.Item>
        </Descriptions>
    );
}

function renderHeuristicAlerts(alerts?: HeuristicAlertResponse[], loading?: boolean) {
    if (loading) {
        return <Skeleton active paragraph={{ rows: 4 }} />;
    }
    if (!alerts || alerts.length === 0) {
        return <Empty description="No alerts for this process" image={Empty.PRESENTED_IMAGE_SIMPLE} />;
    }

    return (
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
            {alerts.map((alert) => (
                <Card key={alert.alert_id ?? `${alert.alert_type}-${alert.start_ts ?? ""}`} size="small" bordered={false} style={{ background: "#f8fafc" }}>
                    <Space direction="vertical" size={4} style={{ width: "100%" }}>
                        <Space>
                            {renderSeverityTag(alert.severity)}
                            {alert.alert_type && <Tag color="geekblue">{alert.alert_type}</Tag>}
                            {alert.score != null && <Tag color="purple">Score: {alert.score.toFixed(2)}</Tag>}
                        </Space>
                        <Text type="secondary">
                            {alert.start_ts ? dayjs(alert.start_ts).format("YYYY-MM-DD HH:mm:ss") : "--"} → {" "}
                            {alert.end_ts ? dayjs(alert.end_ts).format("YYYY-MM-DD HH:mm:ss") : "--"}
                        </Text>
                    </Space>
                </Card>
            ))}
        </Space>
    );
}

export default function ProcessDetails() {
    const navigate = useNavigate();
    const params = useParams<{ rootPid: string }>();
    const { host, since, until, limit, nodeLimit, rootLimit } = useSettings();

    const parsedPid = params.rootPid ? Number(params.rootPid) : undefined;
    const isValidRootPid = parsedPid !== undefined && Number.isFinite(parsedPid);
    const rootPid = isValidRootPid ? parsedPid : undefined;

    const summaryQuery = useProcessSummary(host, rootPid);
    const treeQuery = useProcessTree({ host, rootPid, rootLimit, nodeLimit, since, until });
    const eventsQuery = useProcessEvents(host, since, until, limit);
    const httpEventsQuery = useProcessHttpEvents(host, since, until, limit);

    const httpEventsForRoot = useMemo(() => {
        if (!isValidRootPid || rootPid === undefined) {
            return [] as ProcessHTTPEventResponse[];
        }
        return (httpEventsQuery.data ?? []).filter((item: ProcessHTTPEventResponse) => item.root_pid === rootPid);
    }, [httpEventsQuery.data, isValidRootPid, rootPid]);

    const lifecycleEventsForRoot = useMemo(() => {
        if (!isValidRootPid || rootPid === undefined) {
            return [] as ProcessEventResponse[];
        }
        return (eventsQuery.data ?? []).filter((item: ProcessEventResponse) => item.root_pid === rootPid);
    }, [eventsQuery.data, isValidRootPid, rootPid]);

    const tabs = useMemo(() => {
        if (!isValidRootPid) {
            return [];
        }
        return [
            {
                key: "timeline",
                label: "HTTP Timeline",
                children: (
                    <ProcessTimeline
                        httpEvents={httpEventsForRoot}
                        processEvents={lifecycleEventsForRoot}
                        loading={httpEventsQuery.isFetching || eventsQuery.isFetching}
                    />
                )
            },
            {
                key: "events",
                label: "Lifecycle Events",
                children: <ProcessEventsTable events={lifecycleEventsForRoot} loading={eventsQuery.isFetching} />
            }
        ];
    }, [eventsQuery.isFetching, httpEventsForRoot, httpEventsQuery.isFetching, isValidRootPid, lifecycleEventsForRoot]);

    const alertsInRange = useMemo(() => {
        const alerts = summaryQuery.data?.alerts ?? [];
        return alerts.filter((alert) => {
            const reference = alert.end_ts ?? alert.start_ts;
            if (!reference) {
                return true;
            }
            const timestamp = dayjs(reference);
            if (!timestamp.isValid()) {
                return true;
            }
            const startsAfter = timestamp.isAfter(since) || timestamp.isSame(since);
            const endsBefore = timestamp.isBefore(until) || timestamp.isSame(until);
            return startsAfter && endsBefore;
        });
    }, [since, summaryQuery.data?.alerts, until]);

    const metaForDisplay = useMemo<ProcessSummaryMeta | undefined>(() => {
        const base = summaryQuery.data?.meta;
        const events = lifecycleEventsForRoot;
        if (!base && events.length === 0) {
            return undefined;
        }

        let firstSeen: string | undefined;
        let lastSeen: string | undefined;

        events.forEach((event) => {
            const candidates = [event.start_ts, event.end_ts].filter(Boolean) as string[];
            candidates.forEach((value) => {
                const instant = dayjs(value);
                if (!instant.isValid()) {
                    return;
                }
                if (!firstSeen || instant.isBefore(dayjs(firstSeen))) {
                    firstSeen = instant.toISOString();
                }
                if (!lastSeen || instant.isAfter(dayjs(lastSeen))) {
                    lastSeen = instant.toISOString();
                }
            });
        });

        return {
            exec_id: base?.exec_id,
            comm: base?.comm,
            args: base?.args,
            first_seen: firstSeen ?? base?.first_seen,
            last_seen: lastSeen ?? base?.last_seen,
            event_count: events.length > 0 ? events.length : base?.event_count
        };
    }, [lifecycleEventsForRoot, summaryQuery.data?.meta]);

    if (!isValidRootPid) {
        return <Result status="info" title="Invalid process identifier" />;
    }

    const firstError = summaryQuery.error ?? treeQuery.error ?? eventsQuery.error ?? httpEventsQuery.error;
    if (firstError) {
        const message = firstError instanceof Error ? firstError.message : "Unknown error";
        return <Result status="error" title="Failed to load process details" subTitle={message} />;
    }

    return (
        <Flex vertical gap={24}>
            <Flex align="center" justify="space-between">
                <Space>
                    <ArrowLeftOutlined onClick={() => { void navigate(-1); }} style={{ cursor: "pointer" }} />
                    <Text type="secondary">Back</Text>
                </Space>
            </Flex>
            <Card style={CARD_STYLE} bodyStyle={{ padding: 24 }}>
                <Flex vertical gap={8}>
                    <Title level={3} style={{ margin: 0 }}>
                        {`Process PID ${rootPid}`}
                    </Title>
                    <Text type="secondary">
                        Detailed telemetry snapshot for a single process. Metrics and alerts are scoped to the selected root PID.
                    </Text>
                </Flex>
            </Card>
            <Row gutter={[24, 24]} align="stretch">
                <Col xs={24} lg={15} style={COLUMN_STACK_STYLE}>
                    <Card title="Heuristic Alerts" style={CARD_STYLE} headStyle={CARD_HEAD_STYLE} bodyStyle={{ padding: 24, minHeight: 200 }}>
                        {renderHeuristicAlerts(alertsInRange, summaryQuery.isLoading)}
                    </Card>
                    <Card style={CARD_STYLE} headStyle={CARD_HEAD_STYLE} bodyStyle={{ padding: 0 }}>
                        <div style={{ padding: 24 }}>
                            <Tabs defaultActiveKey="timeline" items={tabs} destroyInactiveTabPane />
                        </div>
                    </Card>
                </Col>
                <Col xs={24} lg={9} style={COLUMN_STACK_STYLE}>
                    <ProcessTreePanel
                        title="Process Tree"
                        tree={treeQuery.data}
                        loading={treeQuery.isLoading}
                        fetching={treeQuery.isFetching}
                        since={since}
                        until={until}
                        onRefresh={() => {
                            void treeQuery.refetch();
                        }}
                        height={360}
                    />
                    <Card title="Process Metadata" style={CARD_STYLE} headStyle={CARD_HEAD_STYLE} bodyStyle={{ padding: 24 }}>
                        {renderProcessMetadata(metaForDisplay, summaryQuery.isLoading)}
                    </Card>
                </Col>
            </Row>
        </Flex>
    );
}
