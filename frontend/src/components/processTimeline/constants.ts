import type { GroupByKey, SeverityFilterKey, SeverityLevel } from "./types";

export const PROCESS_LABEL = "PROCESS";
export const MCP_REQUEST_LABEL = "MCP REQUEST";
export const MCP_RESPONSE_LABEL = "MCP RESPONSE";

export const GROUP_OPTIONS: Array<{ label: string; value: GroupByKey }> = [
    { label: "HTTP Direction", value: "httpType" },
    { label: "HTTP Method", value: "method" },
    { label: "Root PID", value: "rootPid" }
];

export const HTTP_CATEGORY_ORDER = [PROCESS_LABEL, "REQUEST", "RESPONSE", MCP_REQUEST_LABEL, MCP_RESPONSE_LABEL] as const;

export const CATEGORY_COLORS: Record<string, string> = {
    REQUEST: "#1d4ed8",
    RESPONSE: "#16a34a",
    [PROCESS_LABEL]: "#f97316",
    [MCP_REQUEST_LABEL]: "#7c3aed",
    [MCP_RESPONSE_LABEL]: "#0ea5e9"
};

export const SEVERITY_COLORS: Record<SeverityLevel, string> = {
    Unsafe: "#ef4444",
    Controversial: "#fbbf24",
    Safe: "#0ea5e9"
};

export const SEVERITY_TEXT_COLORS: Record<SeverityLevel, string> = {
    Unsafe: "#ffffff",
    Controversial: "#1f2937",
    Safe: "#ffffff"
};

export const SEVERITY_SYMBOLS: Record<SeverityLevel, string> = {
    Unsafe: "triangle",
    Controversial: "diamond",
    Safe: "circle"
};

export const SEVERITY_FILTERS: Array<{ value: SeverityFilterKey; label: string }> = [
    { value: "Unsafe", label: "Unsafe" },
    { value: "Controversial", label: "Controversial" },
    { value: "Safe", label: "Safe" },
    { value: "Unknown", label: "Unknown" }
];

export const UNKNOWN_SEVERITY_COLOR = "#94a3b8";

export const TIME_FORMATTERS = {
    timeWithSeconds: new Intl.DateTimeFormat("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    }),
    timeWithoutSeconds: new Intl.DateTimeFormat("en-US", {
        hour: "2-digit",
        minute: "2-digit"
    }),
    dateWithTime: new Intl.DateTimeFormat("en-US", {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
    })
} as const;
