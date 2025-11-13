import { Empty, Spin } from "antd";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import dayjs from "dayjs";

import { ProcessHTTPEventResponse } from "../types/api";

const defaultColors: Record<string, string> = {
    request: "#1677ff",
    response: "#52c41a",
    suspicious: "#ff4d4f"
};

interface TimelinePoint {
    name: string;
    value: [number, string];
    http: ProcessHTTPEventResponse;
    itemStyle: {
        color: string;
    };
}

interface TimelineChartProps {
    events: ProcessHTTPEventResponse[] | undefined;
    loading?: boolean;
    onSelect?: (event: ProcessHTTPEventResponse) => void;
}

export default function TimelineChart({ events, loading = false, onSelect }: TimelineChartProps) {
    const safeEvents = useMemo(() => (Array.isArray(events) ? events : []), [events]);

    const fallbackTimestamp = useMemo(() => {
        if (safeEvents.length === 0) {
            return 0;
        }
        const reference = safeEvents.find((event) => event.timestamp);
        return reference ? dayjs(reference.timestamp).valueOf() : 0;
    }, [safeEvents]);

    const chartData = useMemo<TimelinePoint[]>(() => {
        if (safeEvents.length === 0) {
            return [];
        }
        return safeEvents.map((event) => {
            const timestamp = event.timestamp ? dayjs(event.timestamp).valueOf() : fallbackTimestamp;
            const type = event.http_type?.toLowerCase();
            const isError = (event.status_code ?? 200) >= 400;
            const color = isError ? defaultColors.suspicious : defaultColors[type ?? "request"];
            return {
                name: `${event.method ?? ""} ${event.url ?? ""}`.trim(),
                value: [timestamp, event.http_type ?? "request"],
                http: event,
                itemStyle: {
                    color: color ?? defaultColors.request
                }
            } satisfies TimelinePoint;
        });
    }, [fallbackTimestamp, safeEvents]);

    const options = useMemo(() => ({
        darkMode: false,
        animation: false,
        grid: { left: 48, right: 24, top: 24, bottom: 40 },
        tooltip: {
            trigger: "item",
            formatter: (params: unknown) => {
                const datum = params as { data?: TimelinePoint };
                const http = datum.data?.http;
                if (!http) {
                    return "";
                }
                return [
                    `<strong>${http.http_type ?? "HTTP"}</strong>`,
                    http.timestamp ? dayjs(http.timestamp).format("YYYY-MM-DD HH:mm:ss") : "",
                    http.method && http.url ? `${http.method} ${http.url}` : http.url ?? "",
                    http.status_code ? `Status: ${http.status_code}` : "",
                    http.is_mcp_http ? "MCP traffic" : ""
                ]
                    .filter(Boolean)
                    .join("<br />");
            }
        },
        dataZoom: [
            { type: "slider", height: 24, bottom: 0 },
            { type: "inside" }
        ],
        xAxis: {
            type: "time",
            boundaryGap: false
        },
        yAxis: {
            type: "category",
            data: ["request", "response", "other"],
            axisLabel: {
                formatter: (value: string) => value.toUpperCase()
            }
        },
        series: [
            {
                type: "scatter",
                symbolSize: 18,
                data: chartData
            }
        ]
    }), [chartData]);

    if (loading) {
        return (
            <div style={{ display: "grid", placeItems: "center", minHeight: 280 }}>
                <Spin />
            </div>
        );
    }

    if (safeEvents.length === 0) {
        return <Empty description="No HTTP activity" image={Empty.PRESENTED_IMAGE_SIMPLE} />;
    }

    return (
        <ReactECharts
            style={{ width: "100%", height: 360 }}
            option={options}
            notMerge
            onEvents={{
                click: (params: unknown) => {
                    const datum = params as { data?: TimelinePoint };
                    const http = datum.data?.http;
                    if (http && onSelect) {
                        onSelect(http);
                    }
                }
            }}
        />
    );
}
