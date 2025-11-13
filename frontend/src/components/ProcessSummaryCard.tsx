import { Card, Descriptions, Space, Tag, Typography } from "antd";
import dayjs from "dayjs";

import { ProcessSummaryResponse } from "../types/api";

interface ProcessSummaryCardProps {
    summary?: ProcessSummaryResponse;
    loading?: boolean;
}

const { Text } = Typography;

function renderAlertSeverity(severity?: string) {
    if (!severity) {
        return <Tag>Unknown</Tag>;
    }
    return <Tag color={severity.toLowerCase() === "critical" ? "red" : "orange"}>{severity}</Tag>;
}

export default function ProcessSummaryCard({ summary, loading = false }: ProcessSummaryCardProps) {
    const alerts = summary?.alerts ?? [];
    const meta = summary?.meta;

    return (
        <Card loading={loading} title="Process Summary" bordered={false}>
            {summary && meta ? (
                <Space direction="vertical" size={16} style={{ width: "100%" }}>
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
                        <Descriptions.Item label="Event Count">{meta.event_count}</Descriptions.Item>
                    </Descriptions>
                    <Space direction="vertical" size={8} style={{ width: "100%" }}>
                        <Text strong>Associated Alerts</Text>
                        {alerts.length === 0 ? (
                            <Text type="secondary">No heuristic alerts recorded for this process.</Text>
                        ) : (
                            alerts.map((alert) => (
                                <Card key={alert.alert_id} size="small">
                                    <Space direction="vertical" size={4} style={{ width: "100%" }}>
                                        <Space>
                                            {renderAlertSeverity(alert.severity)}
                                            <Tag color="geekblue">{alert.alert_type}</Tag>
                                            {alert.score != null && <Tag color="purple">Score: {alert.score.toFixed(2)}</Tag>}
                                        </Space>
                                        <Text type="secondary">
                                            {alert.start_ts ? dayjs(alert.start_ts).format("YYYY-MM-DD HH:mm:ss") : "--"} → {" "}
                                            {alert.end_ts ? dayjs(alert.end_ts).format("YYYY-MM-DD HH:mm:ss") : "--"}
                                        </Text>
                                    </Space>
                                </Card>
                            ))
                        )}
                    </Space>
                </Space>
            ) : (
                <Text type="secondary">Select a process to view summary.</Text>
            )}
        </Card>
    );
}
