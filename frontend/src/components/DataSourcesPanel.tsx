import { Button, Card, Col, Empty, Flex, Input, message, Modal, Row, Select, Skeleton, Space, Table, Tabs, Tag, Tooltip, Typography } from "antd";
import { CopyOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import dayjs from "dayjs";
import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useSettings } from "../context/SettingsContext";
import {
    useAgentRuns,
    useDataSourceByRoot,
    useDataSourceSummary,
    usePostgresEvents,
    usePostgresQueries,
    useS3Buckets,
    useS3Events,
    useS3Operations
} from "../hooks/useAnalytics";
import type { PostgresEventResponse, PostgresQueryTopResponse, S3EventResponse } from "../api/analytics";

const { Text } = Typography;

interface DataSourcesPanelProps {
    rootExecId?: string | null;
    hideRootSelector?: boolean;
}

const MSG_TYPE_COLORS: Record<string, string> = {
    Q: "blue",
    P: "geekblue",
    B: "purple",
    E: "magenta",
    C: "default",
    X: "default"
};

type EChartsClickEvent = {
    name?: string;
};

function formatTimestamp(value?: string): string {
    if (!value) {
        return "--";
    }
    const ts = dayjs(value);
    return ts.isValid() ? ts.format("YYYY-MM-DD HH:mm:ss") : value;
}

function extractS3KeyFromURL(url?: string): string | null {
    if (!url) {
        return null;
    }
    if (url.startsWith("/")) {
        const trimmed = url.substring(1);
        return trimmed.length > 0 ? trimmed : null;
    }
    const vhostMatch = url.match(/\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/(.+)/);
    if (vhostMatch?.[1]) {
        return vhostMatch[1];
    }
    const pathMatch = url.match(/^s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/[^/]+\/(.+)/);
    if (pathMatch?.[1]) {
        return pathMatch[1];
    }
    return null;
}

export default function DataSourcesPanel({ rootExecId, hideRootSelector = false }: DataSourcesPanelProps) {
    const { host, since, until, limit } = useSettings();
    const navigate = useNavigate();
    const [activeTab, setActiveTab] = useState<"overview" | "s3" | "postgres">("overview");
    const [selectedRootExecId, setSelectedRootExecId] = useState<string | null>(rootExecId ?? null);
    const effectiveRootExecId = hideRootSelector ? rootExecId ?? null : selectedRootExecId;
    const [rootExecModalVisible, setRootExecModalVisible] = useState(false);
    const [modalRootExecId, setModalRootExecId] = useState<string | null>(null);
    const [modalRootPid, setModalRootPid] = useState<number | null>(null);

    const agentRunsQuery = useAgentRuns(host, since, until, 200);
    const byRootQuery = useDataSourceByRoot(host, since, until, 100);
    const summaryQuery = useDataSourceSummary(host, since, until, 10, effectiveRootExecId);
    const s3BucketsQuery = useS3Buckets(host, since, until, 20, effectiveRootExecId);
    const s3OperationsQuery = useS3Operations(host, since, until, 20, effectiveRootExecId);
    const [bucketFilter, setBucketFilter] = useState<string | null>(null);
    const [operationFilter, setOperationFilter] = useState<string | null>(null);
    const [s3StatusFilter, setS3StatusFilter] = useState<string | null>(null);
    const [s3MethodFilter, setS3MethodFilter] = useState<string | null>(null);
    const [s3RegionFilter, setS3RegionFilter] = useState<string | null>(null);
    const [s3KeyFilter, setS3KeyFilter] = useState<string | null>(null);
    const [s3PidFilter, setS3PidFilter] = useState<number | null>(null);
    const [s3CommFilter, setS3CommFilter] = useState<string | null>(null);
    const [s3RootExecFilter, setS3RootExecFilter] = useState<string | null>(null);
    const s3EventsQuery = useS3Events(host, since, until, Math.min(500, limit), {
        rootExecId: effectiveRootExecId,
        bucket: bucketFilter,
        operation: operationFilter
    });

    const pgQueriesQuery = usePostgresQueries(host, since, until, 20, effectiveRootExecId);
    const [msgTypeFilter, setMsgTypeFilter] = useState<string | null>(null);
    const [sqlHashFilter, setSqlHashFilter] = useState<string | null>(null);
    const [pgCommFilter, setPgCommFilter] = useState<string | null>(null);
    const [pgPidFilter, setPgPidFilter] = useState<number | null>(null);
    const pgEventsQuery = usePostgresEvents(host, since, until, Math.min(500, limit), {
        rootExecId: effectiveRootExecId,
        msgType: msgTypeFilter,
        sqlHash: sqlHashFilter
    });

    const s3Operations = useMemo(() => {
        if ((s3OperationsQuery.data?.length ?? 0) > 0) {
            return s3OperationsQuery.data ?? [];
        }
        return summaryQuery.data?.s3?.operations ?? [];
    }, [s3OperationsQuery.data, summaryQuery.data?.s3?.operations]);

    const s3BucketOptions = useMemo(() => {
        const buckets = s3BucketsQuery.data ?? [];
        return buckets.map((row) => ({ value: row.bucket, label: row.bucket }));
    }, [s3BucketsQuery.data]);

    const s3OperationOptions = useMemo(() => {
        return s3Operations
            .map((row) => row.operation ?? "Unknown")
            .filter((value, idx, arr) => arr.indexOf(value) === idx)
            .map((value) => ({ value, label: value }));
    }, [s3Operations]);

    const s3RegionOptions = useMemo(() => {
        const set = new Set<string>();
        (s3EventsQuery.data ?? []).forEach((event) => {
            const region = (event.bucket_region ?? "").trim();
            if (region) {
                set.add(region);
            }
        });
        return Array.from(set)
            .sort((a, b) => a.localeCompare(b))
            .map((value) => ({ value, label: value }));
    }, [s3EventsQuery.data]);

    const s3CommOptions = useMemo(() => {
        const set = new Set<string>();
        (s3EventsQuery.data ?? []).forEach((event) => {
            const comm = (event.comm ?? "").trim();
            if (comm) {
                set.add(comm);
            }
        });
        return Array.from(set)
            .sort((a, b) => a.localeCompare(b))
            .map((value) => ({ value, label: value }));
    }, [s3EventsQuery.data]);

    const s3PidOptions = useMemo(() => {
        const set = new Set<number>();
        (s3EventsQuery.data ?? []).forEach((event) => {
            if (typeof event.pid === "number") {
                set.add(event.pid);
            }
        });
        return Array.from(set)
            .sort((a, b) => a - b)
            .map((value) => ({ value, label: String(value) }));
    }, [s3EventsQuery.data]);

    const effectiveS3RootExecFilter = effectiveRootExecId ?? s3RootExecFilter;

    const filteredS3Events = useMemo(() => {
        const events = s3EventsQuery.data ?? [];
        return events.filter((event) => {
            if (effectiveS3RootExecFilter && event.root_exec_id !== effectiveS3RootExecFilter) {
                return false;
            }
            if (bucketFilter) {
                if (bucketFilter === "(unknown)") {
                    const bucketValue = event.bucket ?? "";
                    if (bucketValue !== "" && bucketValue !== "(unknown)") {
                        return false;
                    }
                } else if (event.bucket !== bucketFilter) {
                    return false;
                }
            }
            if (operationFilter) {
                const opValue = event.operation ?? "Unknown";
                if (opValue !== operationFilter) {
                    return false;
                }
            }
            if (s3StatusFilter) {
                if (String(event.status_code ?? "") !== s3StatusFilter) {
                    return false;
                }
            }
            if (s3MethodFilter) {
                if ((event.method ?? "--") !== s3MethodFilter) {
                    return false;
                }
            }
            if (s3RegionFilter) {
                if ((event.bucket_region ?? "") !== s3RegionFilter) {
                    return false;
                }
            }
            if (s3PidFilter !== null) {
                if (event.pid !== s3PidFilter) {
                    return false;
                }
            }
            if (s3CommFilter) {
                if ((event.comm ?? "") !== s3CommFilter) {
                    return false;
                }
            }
            if (s3KeyFilter) {
                const keyCandidate = event.object_key ?? extractS3KeyFromURL(event.url) ?? "";
                if (!keyCandidate.toLowerCase().includes(s3KeyFilter.toLowerCase())) {
                    return false;
                }
            }
            return true;
        });
    }, [
        bucketFilter,
        effectiveS3RootExecFilter,
        operationFilter,
        s3CommFilter,
        s3EventsQuery.data,
        s3KeyFilter,
        s3MethodFilter,
        s3PidFilter,
        s3RegionFilter,
        s3StatusFilter
    ]);

    const s3StatusOptions = useMemo(() => {
        const set = new Set<string>();
        (s3EventsQuery.data ?? []).forEach((event) => {
            if (typeof event.status_code === "number") {
                set.add(String(event.status_code));
            }
        });
        return Array.from(set)
            .sort((a, b) => Number(a) - Number(b))
            .map((value) => ({ value, label: value }));
    }, [s3EventsQuery.data]);

    const s3MethodOptions = useMemo(() => {
        const set = new Set<string>();
        (s3EventsQuery.data ?? []).forEach((event) => {
            const method = (event.method ?? "").trim();
            if (method) {
                set.add(method);
            }
        });
        return Array.from(set)
            .sort((a, b) => a.localeCompare(b))
            .map((value) => ({ value, label: value }));
    }, [s3EventsQuery.data]);

    const s3Aggregations = useMemo(() => {
        const byStatus = new Map<string, number>();
        const byOperation = new Map<string, number>();
        const byBucket = new Map<string, number>();
        filteredS3Events.forEach((event) => {
            const statusKey = typeof event.status_code === "number" ? String(event.status_code) : "unknown";
            byStatus.set(statusKey, (byStatus.get(statusKey) ?? 0) + 1);
            const opKey = event.operation ?? "Unknown";
            byOperation.set(opKey, (byOperation.get(opKey) ?? 0) + 1);
            const bucketKey = event.bucket ?? "(unknown)";
            byBucket.set(bucketKey, (byBucket.get(bucketKey) ?? 0) + 1);
        });
        const toSortedList = (map: Map<string, number>) =>
            Array.from(map.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([key, count]) => ({ key, count }));
        return {
            total: filteredS3Events.length,
            status: toSortedList(byStatus),
            operation: toSortedList(byOperation),
            bucket: toSortedList(byBucket)
        };
    }, [filteredS3Events]);

    const s3OperationsPieData = useMemo(
        () =>
            s3Operations
                .map((item) => ({
                    type: item.operation ?? "Unknown",
                    value: item.hits
                }))
                .filter((item) => Number.isFinite(item.value) && item.value > 0),
        [s3Operations]
    );

    const s3OperationsChartOption = useMemo<EChartsOption>(() => {
        return {
            tooltip: {
                trigger: "item",
                formatter: "{b}: {c} ({d}%)"
            },
            legend: {
                bottom: 0,
                left: "center",
                type: "scroll"
            },
            series: [
                {
                    name: "S3 Operations",
                    type: "pie",
                    radius: ["45%", "70%"],
                    itemStyle: {
                        borderRadius: 6,
                        borderColor: "#fff",
                        borderWidth: 2
                    },
                    label: {
                        show: true,
                        formatter: "{b}: {d}%"
                    },
                    data: s3OperationsPieData.map((item) => ({ name: item.type, value: item.value }))
                }
            ]
        } satisfies EChartsOption;
    }, [s3OperationsPieData]);

    const sourceCounts = useMemo(() => {
        const sources = summaryQuery.data?.sources ?? [];
        const countMap: Record<string, number> = {};

        sources.forEach((item) => {
            countMap[item.source] = (countMap[item.source] ?? 0) + item.hits;
        });

        const s3 = countMap["s3"] ?? 0;
        const postgres = countMap["postgres"] ?? 0;

        return { s3, postgres, total: s3 + postgres };
    }, [summaryQuery.data?.sources]);

    const sourceDistributionOption = useMemo<EChartsOption>(() => {
        const data = [
            { name: "S3", value: sourceCounts.s3 },
            { name: "Postgres", value: sourceCounts.postgres }
        ].filter((item) => item.value > 0);

        const totalText = String(sourceCounts.total);
        return {
            tooltip: {
                trigger: "item",
                formatter: "{b}: {c} ({d}%)"
            },
            legend: {
                bottom: 0,
                left: "center"
            },
            graphic: [
                {
                    type: "text",
                    left: "center",
                    top: "43%",
                    style: {
                        text: "Total",
                        fill: "#8c8c8c",
                        fontSize: 14
                    }
                },
                {
                    type: "text",
                    left: "center",
                    top: "50%",
                    style: {
                        text: totalText,
                        fill: "#262626",
                        fontSize: 26,
                        fontWeight: 700
                    }
                }
            ],
            series: [
                {
                    name: "Sources",
                    type: "pie",
                    radius: ["50%", "78%"],
                    avoidLabelOverlap: true,
                    label: {
                        show: false
                    },
                    emphasis: {
                        label: {
                            show: true,
                            formatter: "{b}: {c}",
                            fontSize: 14,
                            fontWeight: 600
                        }
                    },
                    data
                }
            ]
        } satisfies EChartsOption;
    }, [sourceCounts.postgres, sourceCounts.s3, sourceCounts.total]);

    const rootOptions = useMemo(() => {
        const rows = byRootQuery.data ?? [];
        const set = new Set<string>();
        rows.forEach((row) => {
            if (row.root_exec_id) {
                set.add(row.root_exec_id);
            }
        });
        return Array.from(set)
            .sort((a, b) => a.localeCompare(b))
            .map((value) => ({ value, label: value }));
    }, [byRootQuery.data]);

    const agentRunIdByRootExecId = useMemo(() => {
        const runs = agentRunsQuery.data ?? [];
        const map = new Map<string, string>();
        runs.forEach((run) => {
            if (run.root_exec_id && run.id) {
                map.set(run.root_exec_id, run.id);
            }
        });
        return map;
    }, [agentRunsQuery.data]);

    const copyToClipboard = (text: string, description = "Text") => {
        navigator.clipboard
            .writeText(text)
            .then(() => {
                message.success(`${description} copied to clipboard`);
            })
            .catch(() => {
                message.error("Failed to copy");
            });
    };

    const formatSqlHash = (hash: string) => {
        if (hash.length <= 16) {
            return hash;
        }
        return `${hash.slice(0, 8)}${'*'.repeat(Math.min(hash.length - 16, 10))}${hash.slice(-8)}`;
    };

    const showRootExecModal = (params: { rootExecId?: string | null; rootPid?: number | null }) => {
        setModalRootExecId(params.rootExecId ?? null);
        setModalRootPid(params.rootPid ?? null);
        setRootExecModalVisible(true);
    };

    const navigateToRoot = (params: { rootExecId?: string | null; rootPid?: number | null }) => {
        const normalizedRootExecId = (params.rootExecId ?? "").trim();
        const normalizedRootPid = params.rootPid ?? null;

        if (normalizedRootExecId) {
            const agentRunId = agentRunIdByRootExecId.get(normalizedRootExecId);
            if (agentRunId) {
                navigate(`/trace?agent_run_id=${encodeURIComponent(agentRunId)}`);
                return;
            }
        }
        if (typeof normalizedRootPid === "number" && Number.isFinite(normalizedRootPid) && normalizedRootPid > 0) {
            navigate(`/processes/${normalizedRootPid}`);
        }
    };

    const s3BucketColumns: ColumnsType<{ bucket: string; hits: number }> = [
        { title: "Bucket", dataIndex: "bucket", key: "bucket" },
        { title: "Hits", dataIndex: "hits", key: "hits", width: 120 }
    ];

    const s3EventColumns: ColumnsType<S3EventResponse> = [
        { title: "Time", dataIndex: "timestamp", key: "timestamp", width: 180, render: (value?: string) => formatTimestamp(value) },
        { title: "Method", dataIndex: "method", key: "method", width: 90, render: (v?: string) => v ?? "--" },
        {
            title: "Operation",
            dataIndex: "operation",
            key: "operation",
            width: 150,
            render: (v?: string) => v ? <Tag color="cyan">{v}</Tag> : "--"
        },
        {
            title: "Status",
            dataIndex: "status_code",
            key: "status_code",
            width: 90,
            render: (value?: number) => (typeof value === "number" ? <Tag color={value >= 500 ? "red" : value >= 400 ? "orange" : "green"}>{value}</Tag> : "--")
        },
        { title: "Bucket", dataIndex: "bucket", key: "bucket", width: 220, render: (v?: string) => v ?? "--" },
        { title: "Region", dataIndex: "bucket_region", key: "bucket_region", width: 140, render: (v?: string) => v ?? "--" },
        {
            title: "Key",
            dataIndex: "object_key",
            key: "object_key",
            ellipsis: true,
            render: (v?: string, record?: S3EventResponse) => {
                // If object_key is empty, try to extract from URL
                if (v) return v;
                if (!record?.url) return "--";

                // If URL starts with /, it's already a path - just remove leading slash
                if (record.url.startsWith('/')) {
                    return record.url.substring(1) || "--";
                }

                // Virtual-hosted style: bucket.s3.region.amazonaws.com/path/to/key
                const vhostMatch = record.url.match(/\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/(.+)/);
                if (vhostMatch && vhostMatch[1]) {
                    return vhostMatch[1];
                }

                // Path style: s3.region.amazonaws.com/bucket/path/to/key
                const pathMatch = record.url.match(/^s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/[^/]+\/(.+)/);
                if (pathMatch && pathMatch[1]) {
                    return pathMatch[1];
                }

                return "--";
            }
        },
        { title: "PID", dataIndex: "pid", key: "pid", width: 90, render: (v?: number) => (typeof v === "number" ? v : "--") },
        { title: "Comm", dataIndex: "comm", key: "comm", width: 180, ellipsis: true, render: (v?: string) => v ?? "--" },
        {
            title: "Root Exec",
            dataIndex: "root_exec_id",
            key: "root_exec_id",
            width: 220,
            ellipsis: true,
            render: (v?: string, record?: S3EventResponse) =>
                v ? (
                    <a
                        onClick={(e) => {
                            e.preventDefault();
                            showRootExecModal({ rootExecId: v, rootPid: record?.root_pid ?? null });
                        }}
                    >
                        {v}
                    </a>
                ) : (
                    "--"
                )
        }
    ];

    const pgQueryColumns: ColumnsType<PostgresQueryTopResponse> = [
        { title: "Hits", dataIndex: "hits", key: "hits", width: 110 },
        {
            title: "SQL (sample)",
            dataIndex: "sample",
            key: "sample",
            ellipsis: true,
            render: (v?: string) => v ? (
                <Flex align="center" gap={8}>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{v}</span>
                    <Button
                        type="text"
                        size="small"
                        icon={<CopyOutlined />}
                        onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(v, "SQL");
                        }}
                    />
                </Flex>
            ) : "--"
        },
        {
            title: "SQL Hash",
            dataIndex: "sql_hash",
            key: "sql_hash",
            width: 260,
            render: (v?: string) => v ? (
                <Tooltip title={v}>
                    <Flex align="center" gap={8}>
                        <code style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{formatSqlHash(v)}</code>
                        <Button
                            type="text"
                            size="small"
                            icon={<CopyOutlined />}
                            onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(v, "SQL Hash");
                            }}
                        />
                    </Flex>
                </Tooltip>
            ) : "--"
        }
    ];

    const pgEventColumns: ColumnsType<PostgresEventResponse> = [
        { title: "Time", dataIndex: "timestamp", key: "timestamp", width: 180, render: (value?: string) => formatTimestamp(value) },
        {
            title: "Type",
            dataIndex: "msg_type",
            key: "msg_type",
            width: 80,
            render: (value?: string) => {
                if (!value) {
                    return "--";
                }
                const color = MSG_TYPE_COLORS[value] ?? "default";
                return <Tag color={color}>{value}</Tag>;
            }
        },
        {
            title: "SQL",
            dataIndex: "sql_text",
            key: "sql_text",
            ellipsis: true,
            render: (v?: string) => v ? (
                <Flex align="center" gap={8}>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{v}</span>
                    <Button
                        type="text"
                        size="small"
                        icon={<CopyOutlined />}
                        onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(v, "SQL");
                        }}
                    />
                </Flex>
            ) : "--"
        },
        { title: "PID", dataIndex: "pid", key: "pid", width: 90, render: (v?: number) => (typeof v === "number" ? v : "--") },
        { title: "Comm", dataIndex: "comm", key: "comm", width: 180, ellipsis: true, render: (v?: string) => v ?? "--" }
    ];

    const byRootColumns: ColumnsType<{ root_exec_id?: string; root_pid?: number; source: string; hits: number }> = [
        {
            title: "Root Exec ID",
            dataIndex: "root_exec_id",
            key: "root_exec_id",
            ellipsis: true,
            render: (v?: string, record?: { root_exec_id?: string; root_pid?: number }) =>
                v ? (
                    <Typography.Link
                        onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            navigateToRoot({ rootExecId: v, rootPid: record?.root_pid ?? null });
                        }}
                    >
                        {v}
                    </Typography.Link>
                ) : (
                    "--"
                )
        },
        { title: "Root PID", dataIndex: "root_pid", key: "root_pid", width: 120, render: (v?: number) => (typeof v === "number" && v > 0 ? v : "--") },
        { title: "Source", dataIndex: "source", key: "source", width: 120 },
        { title: "Hits", dataIndex: "hits", key: "hits", width: 120 }
    ];

    const byRootRows = byRootQuery.data ?? [];

    const pgCommOptions = useMemo(() => {
        const set = new Set<string>();
        (pgEventsQuery.data ?? []).forEach((event) => {
            const comm = (event.comm ?? "").trim();
            if (comm) {
                set.add(comm);
            }
        });
        return Array.from(set)
            .sort((a, b) => a.localeCompare(b))
            .map((value) => ({ value, label: value }));
    }, [pgEventsQuery.data]);

    const pgPidOptions = useMemo(() => {
        const set = new Set<number>();
        (pgEventsQuery.data ?? []).forEach((event) => {
            if (typeof event.pid === "number") {
                set.add(event.pid);
            }
        });
        return Array.from(set)
            .sort((a, b) => a - b)
            .map((value) => ({ value, label: String(value) }));
    }, [pgEventsQuery.data]);

    const filteredPgEvents = useMemo(() => {
        const events = pgEventsQuery.data ?? [];
        return events.filter((event) => {
            if (msgTypeFilter && event.msg_type !== msgTypeFilter) {
                return false;
            }
            if (sqlHashFilter && event.sql_hash !== sqlHashFilter) {
                return false;
            }
            if (pgCommFilter && event.comm !== pgCommFilter) {
                return false;
            }
            if (pgPidFilter !== null && event.pid !== pgPidFilter) {
                return false;
            }
            return true;
        });
    }, [msgTypeFilter, pgCommFilter, pgEventsQuery.data, pgPidFilter, sqlHashFilter]);

    const pgAggregations = useMemo(() => {
        const byMsgType = new Map<string, number>();
        const byComm = new Map<string, number>();
        filteredPgEvents.forEach((event) => {
            const msgKey = event.msg_type ?? "unknown";
            byMsgType.set(msgKey, (byMsgType.get(msgKey) ?? 0) + 1);
            if (event.comm) {
                byComm.set(event.comm, (byComm.get(event.comm) ?? 0) + 1);
            }
        });
        const toSortedList = (map: Map<string, number>) =>
            Array.from(map.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([key, count]) => ({ key, count }));
        return {
            total: filteredPgEvents.length,
            msgType: toSortedList(byMsgType),
            comm: toSortedList(byComm)
        };
    }, [filteredPgEvents]);

    return (
        <Flex vertical gap={16}>
            {!hideRootSelector && (
                <Flex align="center" justify="flex-end" wrap="wrap" gap={12}>
                    <Space wrap>
                        <Text type="secondary">Root Exec</Text>
                        <Select
                            allowClear
                            showSearch
                            placeholder="All roots"
                            style={{ width: 360 }}
                            value={selectedRootExecId ?? undefined}
                            options={rootOptions}
                            loading={byRootQuery.isLoading}
                            onChange={(value) => {
                                setSelectedRootExecId(value ?? null);
                                setBucketFilter(null);
                                setOperationFilter(null);
                                setS3StatusFilter(null);
                                setS3MethodFilter(null);
                                setS3RegionFilter(null);
                                setS3KeyFilter(null);
                                setS3PidFilter(null);
                                setS3CommFilter(null);
                                setS3RootExecFilter(null);
                                setMsgTypeFilter(null);
                                setSqlHashFilter(null);
                                setPgCommFilter(null);
                                setPgPidFilter(null);
                            }}
                        />
                    </Space>
                </Flex>
            )}

            <Tabs
                activeKey={activeTab}
                onChange={(key) => setActiveTab(key as typeof activeTab)}
                destroyInactiveTabPane
                items={[
                    {
                        key: "overview",
                        label: "Overview",
                        children: (
                            <Row gutter={[16, 16]}>
                                <Col xs={24} lg={12}>
                                    <Card size="small" title="Source Distribution" bordered={false} style={{ background: "#fafafa" }}>
                                        {summaryQuery.isLoading ? (
                                            <Skeleton active paragraph={{ rows: 2 }} />
                                        ) : summaryQuery.isError ? (
                                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Failed to load data source distribution" />
                                        ) : sourceCounts.total === 0 ? (
                                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No data sources in selected time range" />
                                        ) : (
                                            <div style={{ padding: "20px 0" }}>
                                                <ReactECharts
                                                    option={sourceDistributionOption}
                                                    style={{ height: 320 }}
                                                    notMerge
                                                    lazyUpdate
                                                />
                                            </div>
                                        )}
                                    </Card>
                                </Col>
                                <Col xs={24} lg={12}>
                                    <Card size="small" title="By Root Exec ID" bordered={false} style={{ background: "#fafafa" }}>
                                        {byRootQuery.isLoading ? (
                                            <Skeleton active />
                                        ) : (byRootRows.length === 0) ? (
                                            <Empty
                                                image={Empty.PRESENTED_IMAGE_SIMPLE}
                                                description={
                                                    <Space direction="vertical" size={4}>
                                                        <Text type="secondary">No data sources found with root execution context</Text>
                                                        <Text type="secondary" style={{ fontSize: 12 }}>
                                                            This section shows data sources grouped by their root process execution.
                                                        </Text>
                                                    </Space>
                                                }
                                            />
                                        ) : (
                                            <Table
                                                size="small"
                                                rowKey={(row, idx) => `${row.root_exec_id ?? "null"}-${row.source}-${idx}`}
                                                columns={byRootColumns}
                                                dataSource={byRootRows}
                                                loading={byRootQuery.isLoading}
                                                pagination={false}
                                                onRow={(record) => ({
                                                    onClick: () => {
                                                        navigateToRoot({
                                                            rootExecId: record.root_exec_id ?? null,
                                                            rootPid: record.root_pid ?? null
                                                        });
                                                    },
                                                    style: { cursor: "pointer" }
                                                })}
                                            />
                                        )}
                                    </Card>
                                </Col>
                            </Row>
                        )
                    },
                    {
                        key: "s3",
                        label: "S3",
                        children: (
                            <Row gutter={[16, 16]}>
                                <Col span={24}>
                                    <Card size="small" title="Buckets TopN" bordered={false} style={{ background: "#fafafa" }}>
                                        <Table
                                            size="small"
                                            rowKey={(row) => row.bucket}
                                            columns={s3BucketColumns}
                                            dataSource={s3BucketsQuery.data ?? []}
                                            loading={s3BucketsQuery.isLoading}
                                            pagination={false}
                                            onRow={(record) => ({
                                                onClick: () => {
                                                    setBucketFilter((prev) => (prev === record.bucket ? null : record.bucket));
                                                }
                                            })}
                                        />
                                    </Card>
                                </Col>
                                <Col span={24}>
                                    <Card size="small" title="Operations Distribution" bordered={false} style={{ background: "#fafafa" }}>
                                        <Space wrap size={12} style={{ marginBottom: 12 }}>
                                            <Text type="secondary">Operation filter:</Text>
                                            <Select
                                                allowClear
                                                showSearch
                                                placeholder="All"
                                                style={{ width: 200 }}
                                                value={operationFilter ?? undefined}
                                                options={s3OperationOptions}
                                                onChange={(value) => setOperationFilter(value ?? null)}
                                                loading={s3OperationsQuery.isLoading}
                                            />
                                        </Space>
                                        {s3OperationsQuery.isLoading || s3OperationsQuery.isFetching ? (
                                            <Skeleton active />
                                        ) : s3OperationsQuery.isError ? (
                                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Failed to load operation data" />
                                        ) : s3OperationsPieData.length === 0 ? (
                                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No operation data" />
                                        ) : (
                                            <>
                                                <div style={{ padding: "20px 0" }}>
                                                    <ReactECharts
                                                        option={s3OperationsChartOption}
                                                        style={{ height: 320 }}
                                                        notMerge
                                                        lazyUpdate
                                                        onEvents={{
                                                            click: (evt) => {
                                                                const selectedType = (evt as EChartsClickEvent | null)?.name;
                                                                if (selectedType) {
                                                                    setOperationFilter((prev) => (prev === selectedType ? null : selectedType));
                                                                }
                                                            }
                                                        }}
                                                    />
                                                </div>
                                            </>
                                        )}
                                    </Card>
                                </Col>
                                <Col span={24}>
                                    <Card size="small" title="Access Events" bordered={false} style={{ background: "#fafafa" }}>
                                        <Space wrap size={12} style={{ marginBottom: 12 }}>
                                            <Space>
                                                <Text type="secondary">Bucket:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 180 }}
                                                    value={bucketFilter ?? undefined}
                                                    options={s3BucketOptions}
                                                    onChange={(value) => setBucketFilter(value ?? null)}
                                                    loading={s3BucketsQuery.isLoading}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Operation:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 180 }}
                                                    value={operationFilter ?? undefined}
                                                    options={s3OperationOptions}
                                                    onChange={(value) => setOperationFilter(value ?? null)}
                                                    loading={s3OperationsQuery.isLoading}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Region:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 160 }}
                                                    value={s3RegionFilter ?? undefined}
                                                    options={s3RegionOptions}
                                                    onChange={(value) => setS3RegionFilter(value ?? null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Status:</Text>
                                                <Select
                                                    allowClear
                                                    placeholder="All"
                                                    style={{ width: 120 }}
                                                    value={s3StatusFilter ?? undefined}
                                                    options={s3StatusOptions}
                                                    onChange={(value) => setS3StatusFilter(value ?? null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Method:</Text>
                                                <Select
                                                    allowClear
                                                    placeholder="All"
                                                    style={{ width: 120 }}
                                                    value={s3MethodFilter ?? undefined}
                                                    options={s3MethodOptions}
                                                    onChange={(value) => setS3MethodFilter(value ?? null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">PID:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 120 }}
                                                    value={s3PidFilter ?? undefined}
                                                    options={s3PidOptions}
                                                    onChange={(value) => setS3PidFilter(typeof value === "number" ? value : null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Comm:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 180 }}
                                                    value={s3CommFilter ?? undefined}
                                                    options={s3CommOptions}
                                                    onChange={(value) => setS3CommFilter(value ?? null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Root Exec:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 200 }}
                                                    value={effectiveS3RootExecFilter ?? undefined}
                                                    options={rootOptions}
                                                    onChange={(value) => setS3RootExecFilter(value ?? null)}
                                                    disabled={Boolean(effectiveRootExecId)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">Key:</Text>
                                                <Input
                                                    allowClear
                                                    placeholder="contains..."
                                                    style={{ width: 200 }}
                                                    value={s3KeyFilter ?? ""}
                                                    onChange={(event) => {
                                                        const next = event.target.value.trim();
                                                        setS3KeyFilter(next === "" ? null : next);
                                                    }}
                                                />
                                            </Space>
                                        </Space>
                                        <Space wrap size={[8, 8]} style={{ marginBottom: 12 }}>
                                            <Text type="secondary">Aggregations:</Text>
                                            <Tag color="geekblue">Total {s3Aggregations.total}</Tag>
                                            {s3Aggregations.operation.map((item) => (
                                                <Tag key={`op-${item.key}`} color="cyan">
                                                    {item.key}: {item.count}
                                                </Tag>
                                            ))}
                                            {s3Aggregations.status.map((item) => (
                                                <Tag key={`status-${item.key}`} color="green">
                                                    {item.key}: {item.count}
                                                </Tag>
                                            ))}
                                            {s3Aggregations.bucket.map((item) => (
                                                <Tag key={`bucket-${item.key}`} color="blue">
                                                    {item.key}: {item.count}
                                                </Tag>
                                            ))}
                                        </Space>
                                        {s3EventsQuery.isLoading ? (
                                            <Skeleton active />
                                        ) : filteredS3Events.length === 0 ? (
                                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No S3 events in range" />
                                        ) : (
                                            <Table
                                                size="small"
                                                rowKey={(row, idx) => row.response_id ?? `${row.host}-${idx}`}
                                                columns={s3EventColumns}
                                                dataSource={filteredS3Events}
                                                loading={s3EventsQuery.isFetching}
                                                pagination={{ pageSize: 10 }}
                                            />
                                        )}
                                    </Card>
                                </Col>
                            </Row>
                        )
                    },
                    {
                        key: "postgres",
                        label: "Postgres",
                        children: (
                            <Row gutter={[16, 16]}>
                                <Col span={24}>
                                    <Card size="small" title="Top Queries" bordered={false} style={{ background: "#fafafa" }}>
                                        <Table
                                            size="small"
                                            rowKey={(row) => row.sql_hash}
                                            columns={pgQueryColumns}
                                            dataSource={pgQueriesQuery.data ?? []}
                                            loading={pgQueriesQuery.isLoading}
                                            pagination={false}
                                            onRow={(record) => ({
                                                onClick: () => setSqlHashFilter(record.sql_hash)
                                            })}
                                        />
                                        <div style={{ marginTop: 12 }}>
                                            <Space wrap size={12}>
                                                <Space>
                                                    <Text type="secondary">msg_type:</Text>
                                                    <Select
                                                        allowClear
                                                        placeholder="All"
                                                        style={{ width: 120 }}
                                                        value={msgTypeFilter ?? undefined}
                                                        options={["Q", "P", "B", "E", "C", "X"].map((value) => ({
                                                            value,
                                                            label: value
                                                        }))}
                                                        onChange={(value) => setMsgTypeFilter(value ?? null)}
                                                    />
                                                </Space>
                                                <Space>
                                                    <Text type="secondary">sql_hash:</Text>
                                                    <Select
                                                        allowClear
                                                        showSearch
                                                        placeholder="All"
                                                        style={{ width: 200 }}
                                                        value={sqlHashFilter ?? undefined}
                                                        options={(pgQueriesQuery.data ?? []).map((query) => ({
                                                            value: query.sql_hash,
                                                            label: query.sql_hash.substring(0, 16) + "..."
                                                        }))}
                                                        onChange={(value) => setSqlHashFilter(value ?? null)}
                                                        loading={pgQueriesQuery.isLoading}
                                                    />
                                                </Space>
                                            </Space>
                                        </div>
                                    </Card>
                                </Col>
                                <Col span={24}>
                                    <Card size="small" title="Client Events" bordered={false} style={{ background: "#fafafa" }}>
                                        <Space wrap size={12} style={{ marginBottom: 12 }}>
                                            <Space>
                                                <Text type="secondary">msg_type:</Text>
                                                <Select
                                                    allowClear
                                                    placeholder="All"
                                                    style={{ width: 120 }}
                                                    value={msgTypeFilter ?? undefined}
                                                    options={["Q", "P", "B", "E", "C", "X"].map((value) => ({
                                                        value,
                                                        label: value
                                                    }))}
                                                    onChange={(value) => setMsgTypeFilter(value ?? null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">sql_hash:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 200 }}
                                                    value={sqlHashFilter ?? undefined}
                                                    options={(pgQueriesQuery.data ?? []).map((query) => ({
                                                        value: query.sql_hash,
                                                        label: query.sql_hash.substring(0, 16) + "..."
                                                    }))}
                                                    onChange={(value) => setSqlHashFilter(value ?? null)}
                                                    loading={pgQueriesQuery.isLoading}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">comm:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 180 }}
                                                    value={pgCommFilter ?? undefined}
                                                    options={pgCommOptions}
                                                    onChange={(value) => setPgCommFilter(value ?? null)}
                                                />
                                            </Space>
                                            <Space>
                                                <Text type="secondary">PID:</Text>
                                                <Select
                                                    allowClear
                                                    showSearch
                                                    placeholder="All"
                                                    style={{ width: 120 }}
                                                    value={pgPidFilter ?? undefined}
                                                    options={pgPidOptions}
                                                    onChange={(value) => setPgPidFilter(typeof value === "number" ? value : null)}
                                                />
                                            </Space>
                                        </Space>
                                        <Space wrap size={[8, 8]} style={{ marginBottom: 12 }}>
                                            <Text type="secondary">Aggregations:</Text>
                                            <Tag color="geekblue">Total {pgAggregations.total}</Tag>
                                            {pgAggregations.msgType.map((item) => (
                                                <Tag key={`msg-${item.key}`} color="purple">
                                                    {item.key}: {item.count}
                                                </Tag>
                                            ))}
                                            {pgAggregations.comm.map((item) => (
                                                <Tag key={`comm-${item.key}`} color="volcano">
                                                    {item.key}: {item.count}
                                                </Tag>
                                            ))}
                                        </Space>
                                        {pgEventsQuery.isLoading ? (
                                            <Skeleton active />
                                        ) : filteredPgEvents.length === 0 ? (
                                            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No Postgres events in range" />
                                        ) : (
                                            <Table
                                                size="small"
                                                rowKey={(row, idx) => row.pg_event_id ?? `${row.host}-${idx}`}
                                                columns={pgEventColumns}
                                                dataSource={filteredPgEvents}
                                                loading={pgEventsQuery.isFetching}
                                                pagination={{ pageSize: 10 }}
                                            />
                                        )}
                                    </Card>
                                </Col>
                            </Row>
                        )
                    }
                ]}
            />

            <Modal
                title="Root Execution Details"
                open={rootExecModalVisible}
                onCancel={() => setRootExecModalVisible(false)}
                footer={[
                    <Button key="cancel" onClick={() => setRootExecModalVisible(false)}>
                        Close
                    </Button>,
                    <Button
                        key="navigate"
                        type="primary"
                        onClick={() => {
                            navigateToRoot({ rootExecId: modalRootExecId, rootPid: modalRootPid });
                            setRootExecModalVisible(false);
                        }}
                    >
                        View Details
                    </Button>
                ]}
            >
                <Space direction="vertical" size={16} style={{ width: "100%" }}>
                    <div>
                        <Text type="secondary">Root Exec ID:</Text>
                        <Flex align="center" gap={8} style={{ marginTop: 8 }}>
                            <code style={{ flex: 1, wordBreak: "break-all", background: "#f5f5f5", padding: "4px 8px", borderRadius: 4 }}>
                                {modalRootExecId ?? "--"}
                            </code>
                            {modalRootExecId && (
                                <Button
                                    type="text"
                                    size="small"
                                    icon={<CopyOutlined />}
                                    onClick={() => copyToClipboard(modalRootExecId, "Root Exec ID")}
                                />
                            )}
                        </Flex>
                    </div>
                    <div>
                        <Text type="secondary">Root PID:</Text>
                        <div style={{ marginTop: 8 }}>
                            <Text strong>{modalRootPid ?? "--"}</Text>
                        </div>
                    </div>
                </Space>
            </Modal>
        </Flex>
    );
}
