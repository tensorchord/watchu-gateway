import { Table } from "antd";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";

import { ProcessEventResponse } from "../types/api";

interface ProcessEventsTableProps {
    events: ProcessEventResponse[];
    loading?: boolean;
}

const columns: ColumnsType<ProcessEventResponse> = [
    {
        title: "Exec ID",
        dataIndex: "exec_id",
        key: "exec_id"
    },
    {
        title: "PID",
        dataIndex: "pid",
        key: "pid"
    },
    {
        title: "PPID",
        dataIndex: "ppid",
        key: "ppid"
    },
    {
        title: "Command",
        dataIndex: "comm",
        key: "comm"
    },
    {
        title: "Arguments",
        dataIndex: "args",
        key: "args"
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

function getRowKey(record: ProcessEventResponse): string {
    if (record.exec_id) {
        return record.exec_id;
    }
    const pidPart = record.pid != null ? `pid-${record.pid}` : "pid-unknown";
    const startPart = record.start_ts ? `start-${record.start_ts}` : "start-unknown";
    const endPart = record.end_ts ? `end-${record.end_ts}` : "end-unknown";
    return `${pidPart}-${startPart}-${endPart}`;
}

export default function ProcessEventsTable({ events, loading = false }: ProcessEventsTableProps) {
    return <Table rowKey={getRowKey} dataSource={events} columns={columns} loading={loading} pagination={false} />;
}
