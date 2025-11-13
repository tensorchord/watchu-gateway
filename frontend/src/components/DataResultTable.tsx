import { Table, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";

import { ProcessHTTPEventResponse } from "../types/api";

interface DataResultTableProps {
    events: ProcessHTTPEventResponse[];
    loading?: boolean;
}

const columns: ColumnsType<ProcessHTTPEventResponse> = [
    {
        title: "Timestamp",
        dataIndex: "timestamp",
        key: "timestamp",
        render: (value: string | undefined) => (value ? dayjs(value).format("YYYY-MM-DD HH:mm:ss") : "--")
    },
    {
        title: "Type",
        dataIndex: "http_type",
        key: "http_type",
        render: (value: string | undefined) => value?.toUpperCase() ?? "--"
    },
    {
        title: "Method",
        dataIndex: "method",
        key: "method"
    },
    {
        title: "URL",
        dataIndex: "url",
        key: "url",
        render: (value: string | undefined) => (value ? <Typography.Text code>{value}</Typography.Text> : "--")
    },
    {
        title: "Status",
        dataIndex: "status_code",
        key: "status_code"
    },
    {
        title: "Process",
        dataIndex: "exec_id",
        key: "exec_id"
    }
];

export default function DataResultTable({ events, loading = false }: DataResultTableProps) {
    const dataSource = Array.isArray(events) ? events : [];
    return (
        <Table
            rowKey={(record: ProcessHTTPEventResponse) => record.http_id ?? `${record.method}-${record.timestamp}`}
            dataSource={dataSource}
            columns={columns}
            loading={loading}
            pagination={{ pageSize: 10, showSizeChanger: false }}
        />
    );
}
