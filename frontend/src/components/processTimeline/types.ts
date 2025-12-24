import type { ScatterSeriesOption, TooltipComponentFormatterCallbackParams } from "echarts";

export type SeverityLevel = "Unsafe" | "Controversial" | "Safe";

export type GroupByKey = "httpType" | "method" | "rootPid";

export type SeverityFilterKey = SeverityLevel | "Unknown";

export interface TimelineEvent {
    timestamp: string;
    timestampMs: number;
    kind: "http";
    httpType: string;
    isMcpHttp: boolean;
    method: string | null;
    statusCode: number | null;
    url: string | null;
    pid: number | null;
    rootPid: number | null;
    execId: string | null;
    rootExecId: string | null;
    headers: unknown | null;
    body: unknown | null;
    severityLevel: SeverityLevel | null;
    severityCategories: string | null;
}

export interface ProcessEvent {
    timestamp: string;
    timestampMs: number;
    kind: "process";
    pid: number | null;
    rootPid: number | null;
    execId: string | null;
    rootExecId: string | null;
    comm: string | null;
    args: string | null;
}

export type CombinedEvent = TimelineEvent | ProcessEvent;

export type TimelinePoint = {
    value: [number, string];
    processEvent: CombinedEvent;
    itemStyle?: ScatterSeriesOption["itemStyle"];
    symbol?: string;
    symbolSize?: number;
};

export type TimelineTooltipParam = TooltipComponentFormatterCallbackParams & {
    data?: TimelinePoint;
};

export type TimeRange = { min: number; max: number } | null;
