import type { ScatterSeriesOption, TooltipComponentFormatterCallbackParams } from "echarts";

import type { ProcessEventResponse, ProcessHTTPEventResponse } from "../../types/api";
import { formatTimestamp, toTimestampMillis } from "../../utils/time";
import {
    CATEGORY_COLORS,
    MCP_REQUEST_LABEL,
    MCP_RESPONSE_LABEL,
    PROCESS_LABEL,
    SEVERITY_COLORS,
    SEVERITY_SYMBOLS,
    SEVERITY_TEXT_COLORS,
    UNKNOWN_SEVERITY_COLOR
} from "./constants";
import type {
    CombinedEvent,
    GroupByKey,
    ProcessEvent,
    SeverityFilterKey,
    SeverityLevel,
    TimelineEvent,
    TimelinePoint
} from "./types";

const utf8Decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8") : null;
const BASE64_ALLOWED_CHARS = /^[A-Za-z0-9+/=_-]+$/;
const HEX_ALLOWED_CHARS = /^[0-9a-fA-F]+$/;

type BufferLike = {
    from(input: string, encoding: string): { toString(encoding: string): string };
};

type TooltipRowDefinition = {
    label: string;
    value: string | null;
    isHtml?: boolean;
    monospace?: boolean;
    preformatted?: boolean;
};

const JSON_INDENT_UNIT = "  ";
const PRE_BLOCK_STYLE =
    "margin:0; font-family:'JetBrains Mono','Fira Code','Menlo',monospace; font-size:11px; line-height:1.6; background:#f1f5f9; border-radius:12px; padding:12px 14px; max-height:400px; overflow:auto; white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere; scrollbar-width:thin; scrollbar-color:#cbd5e1 #f1f5f9;";

interface SseMetaEntry {
    key: string;
    value: string;
}

export function toPrimitiveString(value: unknown): string | null {
    if (typeof value === "string") {
        return value;
    }
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
        return String(value);
    }
    return null;
}

export function toDisplayString(value: unknown): string | null {
    const primitive = toPrimitiveString(value);
    if (primitive != null) {
        return primitive;
    }
    try {
        return JSON.stringify(value);
    } catch {
        return null;
    }
}

export function normalizeSeverityLevel(value: unknown): SeverityLevel | null {
    const text = toPrimitiveString(value)?.trim().toLowerCase();
    if (!text) {
        return null;
    }
    if (text === "unsafe") {
        return "Unsafe";
    }
    if (text === "controversial") {
        return "Controversial";
    }
    if (text === "safe") {
        return "Safe";
    }
    return null;
}

export function isHttpEvent(event: CombinedEvent): event is TimelineEvent {
    return event.kind === "http";
}

export function getSeverityColor(level: SeverityLevel | null): string | undefined {
    return level ? SEVERITY_COLORS[level] : undefined;
}

export function getSeveritySymbol(level: SeverityLevel | null): string | undefined {
    return level ? SEVERITY_SYMBOLS[level] : undefined;
}

export function getSeverityTextColor(level: SeverityLevel | null): string {
    if (!level) {
        return "#1f2937";
    }
    return SEVERITY_TEXT_COLORS[level];
}

export function decodePayload(value: unknown): string | null {
    if (value == null) {
        return null;
    }
    const primitive = toPrimitiveString(value);
    if (primitive != null) {
        return maybeDecodeHex(primitive) ?? primitive;
    }
    if (value instanceof ArrayBuffer) {
        return utf8Decoder?.decode(new Uint8Array(value)) ?? null;
    }
    if (ArrayBuffer.isView(value)) {
        const view: ArrayBufferView = value;
        const buffer = value instanceof Uint8Array ? value : new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
        return utf8Decoder?.decode(buffer) ?? null;
    }
    if (Array.isArray(value) && value.every((entry) => typeof entry === "number")) {
        return utf8Decoder?.decode(Uint8Array.from(value)) ?? null;
    }
    if (typeof value === "object") {
        try {
            return JSON.stringify(value);
        } catch {
            return null;
        }
    }
    return null;
}

export function escapeHtml(value: string): string {
    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function isLikelyPrintable(value: string): boolean {
    if (!value) {
        return false;
    }
    let printable = 0;
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code === 0) {
            return false;
        }
        if (code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126)) {
            printable += 1;
        }
    }
    return printable / value.length >= 0.85;
}

export function maybeDecodeBase64(value: string): string | null {
    const trimmed = value.trim();
    if (trimmed.length < 8) {
        return null;
    }
    const sanitized = trimmed.replace(/\s+/g, "");
    if (!sanitized || !BASE64_ALLOWED_CHARS.test(sanitized)) {
        return null;
    }
    const normalized = sanitized.replace(/-/g, "+").replace(/_/g, "/");
    const remainder = normalized.length % 4;
    const padded = remainder ? `${normalized}${"=".repeat(4 - remainder)}` : normalized;
    try {
        if (typeof globalThis.atob === "function") {
            const decoded = globalThis.atob(padded);
            return isLikelyPrintable(decoded) ? decoded : null;
        }
        const bufferFactory = (globalThis as unknown as { Buffer?: BufferLike }).Buffer;
        if (bufferFactory) {
            const decoded = bufferFactory.from(padded, "base64").toString("utf-8");
            return isLikelyPrintable(decoded) ? decoded : null;
        }
    } catch {
        return null;
    }
    return null;
}

function maybeDecodeHex(value: string): string | null {
    const trimmed = value.trim();
    if (trimmed.length < 4) {
        return null;
    }
    const sanitized = trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
    if (!sanitized || sanitized.length % 2 !== 0 || !HEX_ALLOWED_CHARS.test(sanitized)) {
        return null;
    }
    try {
        const bytes = new Uint8Array(sanitized.length / 2);
        for (let index = 0; index < sanitized.length; index += 2) {
            const segment = sanitized.slice(index, index + 2);
            const parsed = Number.parseInt(segment, 16);
            if (Number.isNaN(parsed)) {
                return null;
            }
            bytes[index / 2] = parsed;
        }
        let decoded = utf8Decoder?.decode(bytes) ?? null;
        if (!decoded) {
            const bufferFactory = (globalThis as unknown as { Buffer?: BufferLike }).Buffer;
            if (bufferFactory) {
                decoded = bufferFactory.from(sanitized, "hex").toString("utf-8");
            }
        }
        if (!decoded) {
            let manual = "";
            for (let index = 0; index < bytes.length; index += 1) {
                manual += String.fromCharCode(bytes[index]);
            }
            decoded = manual;
        }
        return decoded && isLikelyPrintable(decoded) ? decoded : null;
    } catch {
        return null;
    }
}

function renderPreBlock(content: string): string {
    return `<pre style="${PRE_BLOCK_STYLE}">${content}</pre>`;
}

function formatJsonLines(value: unknown, depth: number): string[] {
    const indent = JSON_INDENT_UNIT.repeat(depth);
    if (value === null) {
        return [`${indent}<span style="color:#d97706;">null</span>`];
    }
    if (typeof value === "string") {
        return [`${indent}<span style="color:#059669;">&quot;${escapeHtml(value)}&quot;</span>`];
    }
    if (typeof value === "number") {
        return [`${indent}<span style="color:#7c3aed;">${String(value)}</span>`];
    }
    if (typeof value === "boolean") {
        return [`${indent}<span style="color:#d97706;">${value}</span>`];
    }
    if (Array.isArray(value)) {
        if (value.length === 0) {
            return [`${indent}[]`];
        }
        const lines = [`${indent}[`];
        value.forEach((item, index) => {
            const childIndent = JSON_INDENT_UNIT.repeat(depth + 1);
            const childLines = formatJsonLines(item, depth + 1).map((line) => {
                const trimmed = line.startsWith(childIndent) ? line.slice(childIndent.length) : line.trimStart();
                return `${childIndent}${trimmed}`;
            });
            const lastIdx = childLines.length - 1;
            childLines[lastIdx] = `${childLines[lastIdx]}${index < value.length - 1 ? "," : ""}`;
            lines.push(...childLines);
        });
        lines.push(`${indent}]`);
        return lines;
    }
    if (typeof value === "object") {
        const entries = Object.entries(value as Record<string, unknown>);
        if (!entries.length) {
            return [`${indent}{}`];
        }
        const lines = [`${indent}{`];
        entries.forEach(([key, entryValue], entryIndex) => {
            const childIndent = JSON_INDENT_UNIT.repeat(depth + 1);
            const childLines = formatJsonLines(entryValue, depth + 1);
            const keyHtml = `<span style="color:#2563eb;">&quot;${escapeHtml(key)}&quot;</span>`;
            const adjusted = childLines.map((line, lineIndex) => {
                const trimmed = line.startsWith(childIndent) ? line.slice(childIndent.length) : line.trimStart();
                if (lineIndex === 0) {
                    return `${childIndent}${keyHtml}: ${trimmed}`;
                }
                return `${childIndent}${trimmed}`;
            });
            const lastIdx = adjusted.length - 1;
            adjusted[lastIdx] = `${adjusted[lastIdx]}${entryIndex < entries.length - 1 ? "," : ""}`;
            lines.push(...adjusted);
        });
        lines.push(`${indent}}`);
        return lines;
    }
    const fallback = toDisplayString(value);
    if (fallback == null) {
        return [`${indent}<span style="color:#94a3b8;">[unserializable]</span>`];
    }
    return [`${indent}<span style="color:#94a3b8;">&quot;${escapeHtml(fallback)}&quot;</span>`];
}

export function formatJsonAsHtml(value: string): string | null {
    try {
        const parsed: unknown = JSON.parse(value);
        const lines = formatJsonLines(parsed, 0);
        const content = lines.join("\n");
        return renderPreBlock(content);
    } catch {
        return null;
    }
}

function formatSsePayload(value: string): string | null {
    const lines = value.split(/\r?\n/);
    const dataSegments: string[] = [];
    const metaEntries: SseMetaEntry[] = [];
    let markerCount = 0;

    for (const rawLine of lines) {
        const trimmed = rawLine.trim();
        if (!trimmed) {
            continue;
        }
        const colonIndex = trimmed.indexOf(":");
        if (colonIndex <= 0) {
            continue;
        }
        const key = trimmed.slice(0, colonIndex).trim();
        if (!key) {
            continue;
        }
        const rest = trimmed.slice(colonIndex + 1).trim();
        if (key === "data") {
            markerCount += 1;
            if (rest) {
                dataSegments.push(rest);
            }
            continue;
        }
        if (key === "event" || key === "id" || key === "retry" || key === "comment" || key === "type") {
            markerCount += 1;
        }
        metaEntries.push({ key, value: rest });
    }

    if (!markerCount) {
        return null;
    }

    let dataSectionHtml: string | null = null;
    if (dataSegments.length) {
        const joined = dataSegments.join("\n");
        dataSectionHtml = formatJsonAsHtml(joined);
        if (!dataSectionHtml) {
            const escaped = escapeHtml(joined).replace(/\r?\n/g, "\n").replace(/\\n/g, "\n");
            if (escaped.trim()) {
                dataSectionHtml = renderPreBlock(escaped);
            }
        }
    }

    const metaHtml = metaEntries.length
        ? `<div style="display:flex; flex-direction:column; gap:6px;">${metaEntries
            .map(
                ({ key: metaKey, value }) =>
                    `<div style="display:grid; grid-template-columns:max-content minmax(0,1fr); gap:4px 12px; align-items:flex-start; font-size:12px; line-height:1.55;">
                            <span style="text-transform:uppercase; letter-spacing:0.06em; color:#94a3b8; font-size:11px;">${escapeHtml(metaKey)}</span>
                            <span style="color:#0f172a; font-weight:600; overflow-wrap:anywhere;">${escapeHtml(value)}</span>
                        </div>`
            )
            .join("")}</div>`
        : "";

    const sections: string[] = [];
    if (metaHtml) {
        sections.push(metaHtml);
    }
    if (dataSectionHtml) {
        sections.push(dataSectionHtml);
    }
    if (!sections.length) {
        return null;
    }
    return `<div style="display:flex; flex-direction:column; gap:12px;">${sections.join("")}</div>`;
}

export function preparePayloadContent(payload: string | null): string | null {
    if (!payload) {
        return null;
    }
    const trimmed = payload.trim();
    if (!trimmed) {
        return null;
    }
    const decoded = maybeDecodeBase64(trimmed);
    const candidates = decoded ? [decoded, trimmed] : [trimmed];
    for (const candidate of candidates) {
        const jsonHtml = formatJsonAsHtml(candidate);
        if (jsonHtml) {
            return jsonHtml;
        }
        const sseHtml = formatSsePayload(candidate);
        if (sseHtml) {
            return sseHtml;
        }
    }
    const displayText = candidates[0];
    const escaped = escapeHtml(displayText);
    if (!escaped.trim()) {
        return null;
    }
    const normalized = escaped.replace(/\r?\n/g, "\n").replace(/\\n/g, "\n");
    return renderPreBlock(normalized);
}

export function buildSeverityBadge(level: SeverityLevel | null): string {
    const baseStyle =
        "display:inline-flex; align-items:center; justify-content:flex-start; padding:2px 8px; border-radius:999px; font-weight:600; font-size:11px; line-height:1.3; min-height:20px;";
    if (!level) {
        return `<span style="${baseStyle} background:${UNKNOWN_SEVERITY_COLOR}; color:#1f2937;">Unknown</span>`;
    }
    const background = getSeverityColor(level) ?? UNKNOWN_SEVERITY_COLOR;
    const textColor = getSeverityTextColor(level);
    return `<span style="${baseStyle} background:${background}; color:${textColor};">${level}</span>`;
}

export function matchesSelectedRootPid(selectedRootPids: number[], rootPid: number | null, pid: number | null): boolean {
    if (!selectedRootPids.length) {
        return true;
    }
    const rootMatches = rootPid != null && selectedRootPids.includes(rootPid);
    const pidMatches = pid != null && selectedRootPids.includes(pid);
    return rootMatches || pidMatches;
}

export function toSeverityFilterKey(level: SeverityLevel | null): SeverityFilterKey {
    return level ?? "Unknown";
}

export function getSeverityFilterColor(value: SeverityFilterKey): string {
    if (value === "Unknown") {
        return UNKNOWN_SEVERITY_COLOR;
    }
    return getSeverityColor(value) ?? UNKNOWN_SEVERITY_COLOR;
}

export function getSeverityFilterTextColor(value: SeverityFilterKey): string {
    if (value === "Unknown") {
        return "#1f2937";
    }
    return getSeverityTextColor(value);
}

export function getHttpCategoryLabel(event: TimelineEvent): string {
    if (event.isMcpHttp) {
        if (event.httpType === "REQUEST") {
            return MCP_REQUEST_LABEL;
        }
        if (event.httpType === "RESPONSE") {
            return MCP_RESPONSE_LABEL;
        }
    }
    return event.httpType;
}

export function getGroupLabel(event: TimelineEvent, groupBy: GroupByKey): string {
    if (groupBy === "httpType") {
        return getHttpCategoryLabel(event);
    }
    if (groupBy === "method") {
        return event.method ?? "UNKNOWN";
    }
    return event.rootPid != null ? `Root PID ${event.rootPid}` : "Root PID unknown";
}

export function extractProcessEventFromTooltip(
    params: TooltipComponentFormatterCallbackParams | TooltipComponentFormatterCallbackParams[]
): CombinedEvent | null {
    const firstParam = Array.isArray(params) ? params[0] : params;
    if (!firstParam) {
        return null;
    }
    const point = (firstParam as { data?: TimelinePoint }).data;
    if (!point) {
        return null;
    }
    if (!point || typeof point !== "object" || !("processEvent" in point)) {
        return null;
    }
    const candidate = (point as { processEvent?: CombinedEvent }).processEvent;
    return candidate ?? null;
}

export function renderTooltipContent(
    title: string,
    rows: TooltipRowDefinition[],
    sections?: Array<{ label: string; content: string | null }>
): string {
    const header = `<div style="font-weight:600; color:#0f172a; font-size:13px; margin-bottom:6px;">${escapeHtml(title)}</div>`;
    const rowsHtml = rows
        .filter((row) => {
            if (row.value == null) {
                return false;
            }
            const trimmed = row.value.trim();
            return trimmed.length > 0;
        })
        .map((row) => {
            const valueText = row.value ?? "";
            const escapedValue = row.isHtml ? valueText : escapeHtml(valueText);
            const valueBase =
                "color:#0f172a; font-weight:600; overflow-wrap:anywhere; word-break:normal; display:block; width:auto;";
            const whiteSpaceStyle = row.preformatted ? "white-space:normal;" : "white-space:nowrap;";
            const valueStyle = row.monospace
                ? `${valueBase} font-family:'JetBrains Mono','Fira Code','Menlo',monospace; font-size:12px; ${whiteSpaceStyle}`
                : `${valueBase} font-size:12px; ${whiteSpaceStyle}`;

            const valueContent = row.preformatted
                ? `<pre style="margin:0; font-family:inherit; font-size:inherit; line-height:1.55; background:#f1f5f9; border-radius:10px; padding:8px 10px; border:1px solid #e2e8f0; white-space:pre-wrap; overflow:auto;">${escapedValue}</pre>`
                : escapedValue;
            return `
                <div style="display:grid; grid-template-columns:max-content minmax(0,1fr); gap:4px 12px; align-items:flex-start; font-size:12px; line-height:1.6; margin-bottom:6px;">
                    <span style="text-transform:uppercase; letter-spacing:0.06em; color:#94a3b8; font-size:11px; word-break:break-word;">${escapeHtml(row.label)}</span>
                    <span style="${valueStyle}">${valueContent}</span>
                </div>
            `;
        })
        .join("");

    const sectionsHtml = (sections ?? [])
        .filter((section) => Boolean(section.content))
        .map(
            (section) => `
        <div style="margin-top:14px; border-top:1px solid #e2e8f0; padding-top:12px; display:flex; flex-direction:column; gap:8px;">
            <span style="text-transform:uppercase; letter-spacing:0.06em; font-size:11px; color:#94a3b8;">${escapeHtml(section.label)}</span>
            ${section.content ?? ""}
        </div>
    `
        )
        .join("");

    return `<div style="width:auto; min-width:520px; max-width:80vw; max-height:70vh; overflow-y:auto; overflow-x:hidden; padding:10px 12px; scrollbar-width:thin; scrollbar-color:#cbd5e1 #f1f5f9;">${header}${rowsHtml}${sectionsHtml}</div>`;
}

export function toExportRows(httpEvents: TimelineEvent[], processEvents: ProcessEvent[]) {
    const columns = [
        "timestamp",
        "kind",
        "http_type",
        "method",
        "status_code",
        "url",
        "pid",
        "root_pid",
        "exec_id",
        "root_exec_id",
        "severity_level",
        "severity_categories",
        "headers",
        "body",
        "comm",
        "args"
    ];

    const httpRows = httpEvents.map((event) => ({
        timestamp: event.timestamp,
        kind: event.kind,
        http_type: event.httpType,
        method: event.method,
        status_code: event.statusCode,
        url: event.url,
        pid: event.pid,
        root_pid: event.rootPid,
        exec_id: event.execId,
        root_exec_id: event.rootExecId,
        severity_level: event.severityLevel ?? "",
        severity_categories: event.severityCategories ?? "",
        headers: decodePayload(event.headers) ?? toDisplayString(event.headers) ?? "",
        body: decodePayload(event.body) ?? toDisplayString(event.body) ?? "",
        comm: "",
        args: ""
    }));

    const processRows = processEvents.map((event) => ({
        timestamp: event.timestamp,
        kind: event.kind,
        http_type: "",
        method: "",
        status_code: "",
        url: "",
        pid: event.pid,
        root_pid: event.rootPid,
        exec_id: event.execId,
        root_exec_id: event.rootExecId,
        severity_level: "",
        severity_categories: "",
        headers: "",
        body: "",
        comm: event.comm ?? "",
        args: event.args ?? ""
    }));

    return { columns, rows: [...httpRows, ...processRows] };
}

export function buildSeries(categories: string[], grouped: Map<string, CombinedEvent[]>) {
    return categories.map((category) => {
        const items = grouped.get(category) ?? [];
        const data: TimelinePoint[] = items.map((item) => {
            const point: TimelinePoint = {
                value: [item.timestampMs, category],
                processEvent: item
            };
            if (item.kind === "http" && item.httpType === "REQUEST") {
                if (item.isMcpHttp) {
                    point.itemStyle = {
                        color: CATEGORY_COLORS[MCP_REQUEST_LABEL],
                        borderColor: "#4338ca",
                        borderWidth: 1
                    };
                    point.symbol = "circle";
                    point.symbolSize = 14;
                    return point;
                }
                const severity = item.severityLevel;
                const color = getSeverityColor(severity) ?? UNKNOWN_SEVERITY_COLOR;
                const symbol = getSeveritySymbol(severity);
                point.itemStyle = {
                    color,
                    borderColor: severity === "Unsafe" ? "#7f1d1d" : "#1f2937",
                    borderWidth: severity === "Unsafe" ? 2 : 1,
                    shadowBlur: severity === "Unsafe" ? 8 : 0,
                    shadowColor: severity === "Unsafe" ? "rgba(239,68,68,0.5)" : undefined
                };
                if (symbol) {
                    point.symbol = symbol;
                }
                if (severity === "Unsafe") {
                    point.symbolSize = 16;
                } else if (severity === "Controversial") {
                    point.symbolSize = 14;
                }
            }
            return point;
        });
        const color = CATEGORY_COLORS[category];
        let symbol = "circle";
        if (category === PROCESS_LABEL) {
            symbol = "diamond";
        }
        return {
            name: category,
            type: "scatter",
            symbolSize: 12,
            symbol,
            emphasis: { focus: "series" },
            data,
            ...(color ? { itemStyle: { color } } : {})
        } satisfies ScatterSeriesOption;
    });
}

export function mapHttpEvents(events: ProcessHTTPEventResponse[] | undefined): TimelineEvent[] {
    if (!Array.isArray(events)) {
        return [];
    }
    return events
        .map((event) => {
            const timestampMs = toTimestampMillis(event.timestamp);
            if (timestampMs == null) {
                return null;
            }
            const httpTypeRaw = toPrimitiveString(event.http_type);
            const httpType = httpTypeRaw ? httpTypeRaw.toUpperCase() : "UNKNOWN";
            const method = toPrimitiveString(event.method);
            const statusCode = event.status_code != null ? Number(event.status_code) : null;
            const url = toPrimitiveString(event.url);
            const pid = event.pid != null ? Number(event.pid) : null;
            const rootPid = event.root_pid != null ? Number(event.root_pid) : null;
            const execId = toPrimitiveString(event.exec_id);
            const rootExecId = toPrimitiveString(event.root_exec_id);
            const severityLevel = normalizeSeverityLevel((event as Record<string, unknown>).severity_level);
            const severityCategories = (event as Record<string, unknown>).severity_categories;
            const categoriesText = typeof severityCategories === "string" ? severityCategories : toPrimitiveString(severityCategories);
            return {
                timestamp:
                    formatTimestamp(timestampMs) ?? (typeof event.timestamp === "string" ? event.timestamp : `${timestampMs}`),
                timestampMs,
                kind: "http" as const,
                httpType,
                isMcpHttp: Boolean(event.is_mcp_http),
                method,
                statusCode,
                url,
                pid,
                rootPid,
                execId,
                rootExecId,
                headers: event.headers ?? null,
                body: event.body ?? null,
                severityLevel,
                severityCategories: categoriesText
            } satisfies TimelineEvent;
        })
        .filter((value): value is TimelineEvent => Boolean(value));
}

export function mapProcessEvents(events: ProcessEventResponse[] | undefined): ProcessEvent[] {
    if (!Array.isArray(events)) {
        return [];
    }
    return events
        .map((event) => {
            const timestampCandidate = event.start_ts ?? event.end_ts;
            const timestampMs = toTimestampMillis(timestampCandidate);
            if (timestampMs == null) {
                return null;
            }
            const pid = event.pid != null ? Number(event.pid) : null;
            const rootPid = event.root_pid != null ? Number(event.root_pid) : null;
            const execId = toPrimitiveString(event.exec_id);
            const rootExecId = toPrimitiveString(event.root_exec_id);
            const comm = toPrimitiveString(event.comm);
            const args = toPrimitiveString(event.args);
            return {
                timestamp:
                    formatTimestamp(timestampMs) ?? (typeof timestampCandidate === "string" ? timestampCandidate : `${timestampMs}`),
                timestampMs,
                kind: "process" as const,
                pid,
                rootPid,
                execId,
                rootExecId,
                comm,
                args
            } satisfies ProcessEvent;
        })
        .filter((value): value is ProcessEvent => Boolean(value));
}
