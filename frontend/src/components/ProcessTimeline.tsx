import { DownloadOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Card, Empty, Flex, Input, Select, Space, Spin, Tag, Typography, message } from "antd";
import type { SelectProps } from "antd";
import type { ECharts, EChartsOption } from "echarts";
import ReactECharts, { type ReactEChartsInstance } from "echarts-for-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, KeyboardEvent } from "react";

import type { ProcessEventResponse, ProcessHTTPEventResponse } from "../types/api";
import { exportChartAsImage, exportRowsToCSV } from "../utils/export";
import { CARD_HEAD_STYLE, CARD_TITLE_TEXT_STYLE } from "./cardStyles";
import { buildAxisLabelFormatter, buildZoomLabelFormatter } from "./processTimeline/chart";
import {
    GROUP_OPTIONS,
    HTTP_CATEGORY_ORDER,
    PROCESS_LABEL,
    SEVERITY_FILTERS
} from "./processTimeline/constants";
import {
    buildSeries,
    buildSeverityBadge,
    decodePayload,
    extractProcessEventFromTooltip,
    getHttpCategoryLabel,
    getGroupLabel,
    getSeverityFilterColor,
    getSeverityFilterTextColor,
    isHttpEvent,
    mapHttpEvents,
    mapProcessEvents,
    matchesSelectedRootPid,
    preparePayloadContent,
    renderTooltipContent,
    toExportRows,
    toSeverityFilterKey
} from "./processTimeline/helpers";
import type {
    CombinedEvent,
    GroupByKey,
    ProcessEvent,
    SeverityFilterKey,
    TimelineEvent,
    TimelineTooltipParam,
    TimeRange
} from "./processTimeline/types";

const { CheckableTag } = Tag;
const MAX_TIMELINE_POINTS = 5000;

function downsampleByTime<T extends { timestampMs: number }>(items: T[], limit: number): T[] {
    if (items.length <= limit) {
        return items;
    }
    if (limit <= 1) {
        return [items[Math.floor(items.length / 2)]];
    }
    const sorted = [...items].sort((a, b) => a.timestampMs - b.timestampMs);
    const step = (sorted.length - 1) / (limit - 1);
    const result: T[] = [];
    for (let i = 0; i < limit; i += 1) {
        const index = i === limit - 1 ? sorted.length - 1 : Math.floor(i * step);
        const next = sorted[index];
        if (!result.length || result[result.length - 1] !== next) {
            result.push(next);
        }
    }
    return result;
}

interface ProcessTimelineProps {
    httpEvents?: ProcessHTTPEventResponse[];
    events?: ProcessHTTPEventResponse[];
    processEvents?: ProcessEventResponse[];
    loading?: boolean;
    focusRootExecId?: string | null;
    onRefresh?: () => void;
    onFocusRootExecApplied?: (payload: { rootExecId: string; found: boolean }) => void;
    onFocusRootExecCleared?: () => void;
}

export default function ProcessTimeline({
    httpEvents,
    events,
    processEvents,
    loading = false,
    focusRootExecId,
    onRefresh,
    onFocusRootExecApplied,
    onFocusRootExecCleared
}: ProcessTimelineProps) {
    const timelineEvents = useMemo(() => mapHttpEvents(httpEvents ?? events), [events, httpEvents]);
    const timelineProcessEvents = useMemo(() => mapProcessEvents(processEvents), [processEvents]);

    const [groupBy, setGroupBy] = useState<GroupByKey>("httpType");
    const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
    const [selectedRootPids, setSelectedRootPids] = useState<number[]>([]);
    const [selectedSeverities, setSelectedSeverities] = useState<SeverityFilterKey[]>(() =>
        SEVERITY_FILTERS.map((filter) => filter.value)
    );
    const [search, setSearch] = useState("");
    const [internalRootExecFilter, setInternalRootExecFilter] = useState<string | null>(null);
    const [rootExecDraftState, setRootExecDraftState] = useState("");
    const chartRef = useRef<ReactEChartsInstance | null>(null);
    const lastReportedFocusRef = useRef<string | null>(null);
    const previousRootExecRef = useRef<string | null>(null);

    const isControlled = focusRootExecId !== undefined;

    const controlledRootExecFilter = useMemo(() => {
        if (!isControlled) {
            return null;
        }
        if (focusRootExecId == null || typeof focusRootExecId !== "string") {
            return null;
        }
        const trimmed = focusRootExecId.trim();
        return trimmed.length ? trimmed : null;
    }, [focusRootExecId, isControlled]);

    const rootExecFilter = isControlled ? controlledRootExecFilter : internalRootExecFilter;
    const rootExecDraft = isControlled ? controlledRootExecFilter ?? "" : rootExecDraftState;

    const handleRootExecClear = useCallback(() => {
        if (isControlled) {
            onFocusRootExecCleared?.();
        } else {
            setInternalRootExecFilter(null);
            setRootExecDraftState("");
        }
        lastReportedFocusRef.current = null;
    }, [isControlled, onFocusRootExecCleared]);

    const handleRootExecApply = useCallback(() => {
        if (isControlled) {
            return;
        }
        const trimmed = rootExecDraftState.trim();
        setInternalRootExecFilter(trimmed.length ? trimmed : null);
    }, [isControlled, rootExecDraftState]);

    const handleRootExecDraftChange = useCallback(
        (event: ChangeEvent<HTMLInputElement>) => {
            if (isControlled) {
                return;
            }
            const value = event.target.value;
            setRootExecDraftState(value);
            if (value.trim().length === 0) {
                setInternalRootExecFilter(null);
            }
        },
        [isControlled]
    );

    const handleRootExecPressEnter = useCallback(
        (event: KeyboardEvent<HTMLInputElement>) => {
            event.preventDefault();
            handleRootExecApply();
        },
        [handleRootExecApply]
    );

    useEffect(() => {
        lastReportedFocusRef.current = null;
    }, [rootExecFilter]);

    useEffect(() => {
        if (!isControlled && previousRootExecRef.current && !rootExecFilter) {
            onFocusRootExecCleared?.();
        }
        previousRootExecRef.current = rootExecFilter;
    }, [isControlled, onFocusRootExecCleared, rootExecFilter]);

    useEffect(() => {
        if (!rootExecFilter || !onFocusRootExecApplied) {
            return;
        }
        if (timelineEvents.length === 0 && timelineProcessEvents.length === 0) {
            return;
        }
        const foundInHttp = timelineEvents.some(
            (event) => event.rootExecId === rootExecFilter || event.execId === rootExecFilter
        );
        const foundInProcess = timelineProcessEvents.some(
            (event) => event.rootExecId === rootExecFilter || event.execId === rootExecFilter
        );
        const found = foundInHttp || foundInProcess;
        const key = `${rootExecFilter}:${found ? "1" : "0"}`;
        if (lastReportedFocusRef.current === key) {
            return;
        }
        lastReportedFocusRef.current = key;
        onFocusRootExecApplied({ rootExecId: rootExecFilter, found });
    }, [onFocusRootExecApplied, rootExecFilter, timelineEvents, timelineProcessEvents]);

    const typeOptions = useMemo(() => {
        const labels = new Set<string>();
        timelineEvents.forEach((event) => {
            labels.add(event.httpType);
            labels.add(getHttpCategoryLabel(event));
        });
        return Array.from(labels).sort();
    }, [timelineEvents]);

    const rootPidOptions = useMemo(() => {
        const unique = new Set<number>();
        timelineEvents.forEach((event) => {
            if (event.rootPid != null) {
                unique.add(event.rootPid);
            }
        });
        timelineProcessEvents.forEach((event) => {
            if (event.rootPid != null) {
                unique.add(event.rootPid);
            }
        });
        return Array.from(unique).sort((a, b) => a - b);
    }, [timelineEvents, timelineProcessEvents]);

    const filteredEvents = useMemo(() => {
        const searchLower = search.trim().toLowerCase();
        const severitySet = new Set(selectedSeverities);
        return timelineEvents.filter((event) => {
            if (selectedTypes.length) {
                const categoryLabel = getHttpCategoryLabel(event);
                const matchesType = selectedTypes.some(
                    (selected) => selected === event.httpType || selected === categoryLabel
                );
                if (!matchesType) {
                    return false;
                }
            }
            if (!matchesSelectedRootPid(selectedRootPids, event.rootPid, event.pid)) {
                return false;
            }
            if (rootExecFilter) {
                const matchesExec = event.rootExecId === rootExecFilter || event.execId === rootExecFilter;
                if (!matchesExec) {
                    return false;
                }
            }
            if (event.httpType === "REQUEST") {
                const key = toSeverityFilterKey(event.severityLevel);
                if (!severitySet.has(key)) {
                    return false;
                }
            }
            if (searchLower) {
                const haystack = [event.method, event.url, event.execId, event.rootExecId]
                    .map((value) => (typeof value === "string" ? value.toLowerCase() : ""))
                    .join(" ");
                if (!haystack.includes(searchLower)) {
                    return false;
                }
            }
            return true;
        });
    }, [timelineEvents, rootExecFilter, search, selectedRootPids, selectedSeverities, selectedTypes]);

    const filteredProcessEvents = useMemo(() => {
        const searchLower = search.trim().toLowerCase();
        return timelineProcessEvents.filter((event) => {
            if (event.rootPid == null || event.pid == null) {
                return false;
            }
            if (!matchesSelectedRootPid(selectedRootPids, event.rootPid, event.pid)) {
                return false;
            }
            if (rootExecFilter) {
                const matchesExec = event.rootExecId === rootExecFilter || event.execId === rootExecFilter;
                if (!matchesExec) {
                    return false;
                }
            }
            if (searchLower) {
                const haystack = [event.execId, event.rootExecId, event.comm, event.args]
                    .map((value) => (typeof value === "string" ? value.toLowerCase() : ""))
                    .join(" ");
                if (!haystack.includes(searchLower)) {
                    return false;
                }
            }
            return true;
        });
    }, [timelineProcessEvents, rootExecFilter, search, selectedRootPids]);

    const hasRequestEvents = useMemo(() => timelineEvents.some((event) => event.httpType === "REQUEST"), [timelineEvents]);

    const activeProcessEvents = useMemo(
        () => (groupBy === "httpType" ? filteredProcessEvents : []),
        [filteredProcessEvents, groupBy]
    );
    const totalEvents = filteredEvents.length + activeProcessEvents.length;

    const { displayEvents, displayProcessEvents, sampledTotal } = useMemo(() => {
        if (totalEvents <= MAX_TIMELINE_POINTS) {
            return {
                displayEvents: filteredEvents,
                displayProcessEvents: activeProcessEvents,
                sampledTotal: totalEvents
            };
        }
        const ratio = MAX_TIMELINE_POINTS / totalEvents;
        const httpBudget = Math.max(1, Math.floor(filteredEvents.length * ratio));
        const procBudget = Math.max(1, Math.floor(activeProcessEvents.length * ratio));
        const sampledHttp = downsampleByTime(filteredEvents, httpBudget);
        const sampledProc = downsampleByTime(activeProcessEvents, procBudget);
        return {
            displayEvents: sampledHttp,
            displayProcessEvents: sampledProc,
            sampledTotal: sampledHttp.length + sampledProc.length
        };
    }, [activeProcessEvents, filteredEvents, totalEvents]);

    const grouped = useMemo(() => {
        const map = new Map<string, CombinedEvent[]>();

        if (groupBy === "httpType") {
            HTTP_CATEGORY_ORDER.forEach((label) => {
                map.set(label, []);
            });
            displayEvents.forEach((event) => {
                const categoryLabel = getHttpCategoryLabel(event);
                const bucket = map.get(categoryLabel);
                if (bucket) {
                    bucket.push(event);
                } else {
                    map.set(categoryLabel, [event]);
                }
            });

            const processBucket = map.get(PROCESS_LABEL);
            if (processBucket) {
                displayProcessEvents.forEach((event) => {
                    processBucket.push(event);
                });
            }
        } else {
            displayEvents.forEach((event) => {
                const label = getGroupLabel(event, groupBy);
                if (!map.has(label)) {
                    map.set(label, []);
                }
                map.get(label)?.push(event);
            });
        }

        map.forEach((value) => value.sort((a, b) => a.timestampMs - b.timestampMs));
        return map;
    }, [displayEvents, displayProcessEvents, groupBy]);

    const categories = useMemo(() => {
        if (groupBy === "httpType") {
            const base = HTTP_CATEGORY_ORDER.filter((label) => (grouped.get(label)?.length ?? 0) > 0);
            const rest = Array.from(grouped.keys()).filter(
                (label) => !HTTP_CATEGORY_ORDER.includes(label as (typeof HTTP_CATEGORY_ORDER)[number])
            );
            rest.sort(
                (a, b) => (grouped.get(a)?.[0]?.timestampMs ?? Number.POSITIVE_INFINITY) - (grouped.get(b)?.[0]?.timestampMs ?? Number.POSITIVE_INFINITY)
            );
            return [...base, ...rest.filter((label) => (grouped.get(label)?.length ?? 0) > 0)];
        }
        const entries = Array.from(grouped.entries());
        entries.sort((a, b) => (a[1][0]?.timestampMs ?? 0) - (b[1][0]?.timestampMs ?? 0));
        return entries.map(([label]) => label);
    }, [groupBy, grouped]);

    const timeRange = useMemo<TimeRange>(() => {
        const combined: Array<TimelineEvent | ProcessEvent> = [...displayEvents, ...displayProcessEvents];
        if (!combined.length) {
            return null;
        }
        let min = Number.POSITIVE_INFINITY;
        let max = Number.NEGATIVE_INFINITY;
        combined.forEach((event) => {
            min = Math.min(min, event.timestampMs);
            max = Math.max(max, event.timestampMs);
        });
        if (!Number.isFinite(min) || !Number.isFinite(max)) {
            return null;
        }
        return { min, max };
    }, [displayEvents, displayProcessEvents]);

    const axisLabelFormatter = useMemo(() => buildAxisLabelFormatter(timeRange), [timeRange]);
    const zoomLabelFormatter = useMemo(() => buildZoomLabelFormatter(timeRange), [timeRange]);

    const option = useMemo<EChartsOption>(
        () => ({
            animation: false,
            lazyUpdate: true,
            legend: {
                type: "scroll",
                top: 0
            },
            tooltip: {
                trigger: "item",
                triggerOn: "click",
                confine: false,
                enterable: true,
                hideDelay: 80,
                appendToBody: true,
                formatter: (params: unknown) => {
                    const data = extractProcessEventFromTooltip(params as TimelineTooltipParam | TimelineTooltipParam[]);
                    if (!data) {
                        return "";
                    }
                    const timeLabel = data.timestamp ?? "n/a";
                    if (isHttpEvent(data)) {
                        const isRequest = data.httpType === "REQUEST";
                        const headers = decodePayload(data.headers);
                        const headersEscaped = preparePayloadContent(headers);
                        const body = decodePayload(data.body);
                        const bodyEscaped = preparePayloadContent(body);
                        const rows = [
                            { label: "Type", value: data.httpType },
                            { label: "Method", value: data.method ? data.method.toUpperCase() : null },
                            { label: "Status", value: data.statusCode != null ? `${data.statusCode}` : null },
                            { label: "Safety", value: isRequest ? buildSeverityBadge(data.severityLevel) : null, isHtml: true },
                            { label: "Categories", value: isRequest ? data.severityCategories : null },
                            { label: "URL", value: data.url },
                            { label: "PID", value: data.pid != null ? `${data.pid}` : null },
                            { label: "Root PID", value: data.rootPid != null ? `${data.rootPid}` : null },
                            { label: "Exec ID", value: data.execId, monospace: true },
                            { label: "Root Exec", value: data.rootExecId, monospace: true }
                        ];
                        return renderTooltipContent(timeLabel, rows, [
                            { label: "Headers", content: headersEscaped },
                            { label: "Body", content: bodyEscaped }
                        ]);
                    }

                    const rows = [
                        { label: "Type", value: PROCESS_LABEL },
                        { label: "PID", value: data.pid != null ? `${data.pid}` : null },
                        { label: "Root PID", value: data.rootPid != null ? `${data.rootPid}` : null },
                        { label: "Exec ID", value: data.execId, monospace: true },
                        { label: "Root Exec", value: data.rootExecId, monospace: true },
                        { label: "Command", value: data.comm, monospace: true, preformatted: true },
                        { label: "Args", value: data.args, monospace: true, preformatted: true }
                    ];
                    return renderTooltipContent(timeLabel, rows);
                }
            },
            grid: {
                left: 140,
                right: 32,
                top: 48,
                bottom: 100
            },
            xAxis: {
                type: "time",
                axisLabel: {
                    formatter: axisLabelFormatter
                }
            },
            yAxis: {
                type: "category",
                data: categories,
                axisLabel: {
                    fontWeight: 600,
                    formatter: (value: string) => value.toUpperCase()
                }
            },
            dataZoom: [
                {
                    type: "slider",
                    height: 24,
                    bottom: 40,
                    labelFormatter: zoomLabelFormatter
                },
                { type: "inside" }
            ],
            series: buildSeries(categories, grouped)
        }),
        [axisLabelFormatter, categories, grouped, zoomLabelFormatter]
    );

    const handleExportChart = useCallback(async () => {
        const instance: ECharts | undefined = chartRef.current?.getEchartsInstance?.();
        if (!instance) {
            message.warning("Chart is not ready yet");
            return;
        }
        await exportChartAsImage(instance, "process-timeline");
    }, []);

    const handleExportData = useCallback(() => {
        const total = filteredEvents.length + filteredProcessEvents.length;
        if (!total) {
            message.info("No timeline events to export");
            return;
        }
        const result = toExportRows(filteredEvents, filteredProcessEvents);
        exportRowsToCSV(result.columns, result.rows, "process-timeline");
    }, [filteredEvents, filteredProcessEvents]);

    const typeSelectOptions: SelectProps["options"] = typeOptions.map((value) => ({ label: value, value }));
    const rootPidSelectOptions: SelectProps["options"] = rootPidOptions.map((value) => ({ label: `Root PID ${value}`, value }));

    const isDisabled = loading;

    return (
        <Card
            title={
                <Flex align="center" justify="space-between">
                    <Typography.Text style={CARD_TITLE_TEXT_STYLE}>Timeline View</Typography.Text>
                    <Tag color="blue" style={{ borderRadius: 999, fontWeight: 600 }}>
                        {totalEvents} events
                    </Tag>
                    {sampledTotal < totalEvents ? (
                        <Tag color="gold" style={{ borderRadius: 999, fontWeight: 600 }}>
                            Sampled to {sampledTotal}
                        </Tag>
                    ) : null}
                </Flex>
            }
            extra={
                <Space>
                    {onRefresh ? (
                        <Button icon={<ReloadOutlined />} size="small" onClick={() => onRefresh()} disabled={isDisabled}>
                            Refresh
                        </Button>
                    ) : null}
                    <Button icon={<DownloadOutlined />} size="small" onClick={handleExportData} disabled={!totalEvents}>
                        Export CSV
                    </Button>
                    <Button icon={<DownloadOutlined />} size="small" onClick={() => void handleExportChart()} disabled={!totalEvents}>
                        Export Image
                    </Button>
                </Space>
            }
            style={{ borderRadius: 18, border: "1px solid #e2e8f0", boxShadow: "0 30px 80px -48px rgba(15, 23, 42, 0.45)", background: "#f8fafc" }}
            headStyle={CARD_HEAD_STYLE}
            bodyStyle={{ paddingTop: 16, paddingBottom: 24 }}
        >
            <Flex vertical gap={16}>
                {rootExecFilter ? (
                    <Tag
                        color="geekblue"
                        closable
                        onClose={(event) => {
                            event.preventDefault();
                            handleRootExecClear();
                        }}
                        style={{
                            borderRadius: 999,
                            alignSelf: "flex-start",
                            fontWeight: 600,
                            cursor: "pointer",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 6
                        }}
                    >
                        Root Exec Filter · {rootExecFilter}
                    </Tag>
                ) : null}
                <Flex wrap gap={12} align="center">
                    <Select
                        mode="multiple"
                        allowClear
                        placeholder="Filter HTTP type"
                        style={{ minWidth: 220 }}
                        options={typeSelectOptions}
                        value={selectedTypes}
                        onChange={(values: string[]) => setSelectedTypes(values)}
                        disabled={isDisabled}
                    />
                    <Select
                        mode="multiple"
                        allowClear
                        placeholder="Filter root PID"
                        style={{ minWidth: 180 }}
                        options={rootPidSelectOptions}
                        value={selectedRootPids}
                        onChange={(values: number[]) =>
                            setSelectedRootPids(values.filter((value) => Number.isFinite(value)))
                        }
                        disabled={isDisabled}
                    />
                    <Select
                        value={groupBy}
                        onChange={(value) => setGroupBy(value as GroupByKey)}
                        options={GROUP_OPTIONS}
                        style={{ minWidth: 160 }}
                        disabled={isDisabled}
                    />
                    <Input
                        allowClear
                        style={{ minWidth: 220, maxWidth: 280 }}
                        placeholder="Focus root exec"
                        value={rootExecDraft}
                        onChange={handleRootExecDraftChange}
                        onPressEnter={handleRootExecPressEnter}
                        disabled={isDisabled || isControlled}
                    />
                    <Button
                        type="primary"
                        onClick={handleRootExecApply}
                        disabled={isDisabled || isControlled || !rootExecDraft.trim()}
                    >
                        Focus
                    </Button>
                    <Input
                        allowClear
                        style={{ minWidth: 200, maxWidth: 280 }}
                        placeholder="Search method, URL, exec ID"
                        prefix={<SearchOutlined />}
                        value={search}
                        onChange={(event: ChangeEvent<HTMLInputElement>) => setSearch(event.target.value)}
                        disabled={isDisabled}
                    />
                </Flex>
                {hasRequestEvents ? (
                    <Flex align="center" gap={8} wrap style={{ padding: "4px 0" }}>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            Request safety
                        </Typography.Text>
                        {SEVERITY_FILTERS.map(({ value, label }) => {
                            const checked = selectedSeverities.includes(value);
                            const background = getSeverityFilterColor(value);
                            const textColor = getSeverityFilterTextColor(value);
                            return (
                                <CheckableTag
                                    key={value}
                                    checked={checked}
                                    onChange={(nextChecked) => {
                                        setSelectedSeverities((prev) => {
                                            if (nextChecked) {
                                                if (prev.includes(value)) {
                                                    return prev;
                                                }
                                                return [...prev, value];
                                            }
                                            return prev.filter((item) => item !== value);
                                        });
                                    }}
                                    style={{
                                        background: checked ? background : "transparent",
                                        color: checked ? textColor : background,
                                        borderColor: background,
                                        borderRadius: 999,
                                        padding: "0 12px",
                                        fontWeight: 600,
                                        marginInlineEnd: 0,
                                        userSelect: "none"
                                    }}
                                >
                                    {label}
                                </CheckableTag>
                            );
                        })}
                    </Flex>
                ) : null}
                {loading ? (
                    <div style={{ display: "flex", justifyContent: "center", padding: "48px 0" }}>
                        <Spin size="large" />
                    </div>
                ) : totalEvents > 0 ? (
                    <ReactECharts
                        ref={chartRef}
                        option={option}
                        style={{ height: 380 }}
                        notMerge={true}
                        lazyUpdate={true}
                    />
                ) : (
                    <Empty description="No timeline events" />
                )}
            </Flex>
        </Card>
    );
}
