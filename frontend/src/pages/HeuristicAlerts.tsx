import { Card, Result, Table, Tag } from "antd";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";

import { useSettings } from "../context/SettingsContext";
import { useHeuristicAlerts } from "../hooks/useAnalytics";
import { HeuristicAlertResponse } from "../types/api";

const columns: ColumnsType<HeuristicAlertResponse> = [
    {
        title: "Alert ID",
        dataIndex: "alert_id",
        key: "alert_id"
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
        render: (value: string | undefined) => <Tag color={(value ?? "").toLowerCase() === "critical" ? "red" : "orange"}>{value ?? "--"}</Tag>
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

export default function HeuristicAlerts() {
    const { host, since, until, limit } = useSettings();
    const alertsQuery = useHeuristicAlerts(host, since, until, limit);

    if (alertsQuery.error) {
        const message = alertsQuery.error instanceof Error ? alertsQuery.error.message : "Unknown error";
        return <Result status="error" title="Unable to load heuristic alerts" subTitle={message} />;
    }

    const dataSource = Array.isArray(alertsQuery.data) ? alertsQuery.data : [];

    return (
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
    );
}
