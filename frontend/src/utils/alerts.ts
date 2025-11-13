import { formatTimestamp } from "./time";

const numberFormatter = new Intl.NumberFormat("en-US");

function formatNumber(value: number): string {
    return numberFormatter.format(value);
}

interface ParsedAlertDetails {
    command?: string | null;
    url?: string | null;
    sensitiveArgs?: string | null;
    message?: string | null;
    endpoint?: string | null;
    gapMs?: number | null;
    score?: number | null;
    primaryPid?: string | null;
    occurrences?: number | null;
    status_code?: string | number | null;
    [key: string]: unknown;
}

function decodeBinaryDetails(value: unknown): string | null {
    if (!Array.isArray(value)) {
        return null;
    }
    try {
        const array = new Uint8Array(value.map((entry) => Number(entry) & 0xff));
        return new TextDecoder().decode(array);
    } catch {
        return null;
    }
}

function parseDetails(raw: string | null): ParsedAlertDetails {
    if (!raw) {
        return {};
    }
    try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        return {
            command: typeof parsed.command === "string" ? parsed.command : null,
            url: typeof parsed.url === "string" ? parsed.url : null,
            sensitiveArgs: typeof parsed.sensitive_args === "string" ? parsed.sensitive_args : null,
            message: typeof parsed.message === "string" ? parsed.message : null,
            endpoint: typeof parsed.endpoint === "string" ? parsed.endpoint : null,
            gapMs: typeof parsed.gap_ms === "number" ? parsed.gap_ms : null,
            score: typeof parsed.score === "number" ? parsed.score : null,
            primaryPid:
                typeof parsed.primary_pid === "string"
                    ? parsed.primary_pid
                    : typeof parsed.primary_pid === "number"
                        ? String(parsed.primary_pid)
                        : null,
            occurrences: typeof parsed.occurrences === "number" ? parsed.occurrences : null,
            status_code:
                typeof parsed.status_code === "string" || typeof parsed.status_code === "number"
                    ? parsed.status_code
                    : null
        } satisfies ParsedAlertDetails;
    } catch {
        return {};
    }
}

function normalizeGenericDetails(raw: string | null): {
    description: string;
    lines: string[];
    raw: string | null;
} {
    if (!raw) {
        const fallback = "No additional details available.";
        return { description: fallback, lines: [fallback], raw: null };
    }

    const normalized = raw.replace(/\r\n/g, "\n");
    const trimmed = normalized.trim();
    const looksJSON = trimmed.startsWith("{") || trimmed.startsWith("[");
    const looksCurl = /^(curl|\s*-x\s+post)\b/i.test(trimmed);
    const containsStructuredKeys = /\b(arguments?|model|messages|payload|request|response|headers?)\b/i.test(normalized);

    let pretty = normalized;
    let treatAsRaw = looksJSON || looksCurl;

    if (looksJSON) {
        try {
            pretty = JSON.stringify(JSON.parse(trimmed), null, 2);
        } catch {
            pretty = normalized;
        }
    }

    if (!treatAsRaw) {
        const newlineCount = (normalized.match(/\n/g) ?? []).length;
        if (newlineCount > 0 && containsStructuredKeys) {
            treatAsRaw = true;
        }
    }

    if (treatAsRaw) {
        const preferred = pretty.replace(/\r\n/g, "\n");
        return { description: preferred, lines: [preferred], raw: preferred };
    }

    const lines = normalized
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);

    if (!lines.length) {
        const fallback = trimmed.length ? trimmed : "No additional details available.";
        return { description: fallback, lines: [fallback], raw: trimmed.length ? normalized : null };
    }

    return { description: lines.join("\n"), lines, raw: normalized };
}

function normalizeString(value: unknown, fallback: string): string {
    if (typeof value === "string") {
        return value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
        return String(value);
    }
    return fallback;
}

function normalizeOptionalString(value: unknown): string | null {
    if (typeof value === "string") {
        return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
        return String(value);
    }
    return null;
}

function normalizeScore(value: unknown): number | null {
    if (typeof value === "number" && Number.isFinite(value)) {
        return value;
    }
    if (typeof value === "string") {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
    }
    return null;
}

export function formatExecId(value: string | null): string {
    if (!value) {
        return "unknown";
    }
    if (value.length <= 16) {
        return value;
    }
    return `${value.slice(0, 8)}…${value.slice(-8)}`;
}

export type AlertSeverityTag = "error" | "warning" | "info";

export interface AlertInfo {
    key: string;
    type: string;
    severity: string;
    severityTag: AlertSeverityTag;
    description: string;
    descriptionLines: string[];
    primaryPid: string | null;
    rootPid: string | null;
    rootExecId: string | null;
    score: number | null;
    startTimestamp: string | null;
    endTimestamp: string | null;
    rawDetails: string | null;
}

export function buildAlertInfo(row: Record<string, unknown>, index: number): AlertInfo {
    const type = normalizeString(row.alert_type, "alert");
    const severity = normalizeString(row.severity, "info");
    const score = normalizeScore(row.score);
    const rootPid = normalizeOptionalString(row.root_pid);
    const rootExecId = normalizeOptionalString(row.root_exec_id);
    const startTimestamp = formatTimestamp(row.start_ts);
    const endTimestamp = formatTimestamp(row.end_ts);

    const originalRawDetails = (() => {
        const detailsValue = row.details;
        if (typeof detailsValue === "string") {
            return detailsValue;
        }
        const decoded = decodeBinaryDetails(detailsValue);
        if (decoded != null) {
            return decoded;
        }
        if (detailsValue && typeof detailsValue === "object") {
            try {
                return JSON.stringify(detailsValue);
            } catch {
                return null;
            }
        }
        return null;
    })();

    const details = parseDetails(originalRawDetails);
    const primaryPid = details.primaryPid ?? null;
    const severityTag: AlertSeverityTag = severity === "high" ? "error" : severity === "medium" ? "warning" : "info";

    let rawDetails = originalRawDetails;
    let description: string;
    let descriptionLines: string[];

    if (type === "data_exfiltration") {
        const gapMs = details.gapMs ?? (typeof score === "number" ? Math.max(0, Math.round((1 - score) * 5000)) : null);
        const clauseEntries: Array<[string, string | null]> = [
            [primaryPid ? `PID ${primaryPid}` : "Sensitive data access", details.message ?? null],
            ["Command", details.command ?? null],
            ["Endpoint", details.url ?? details.endpoint ?? null],
            ["Arguments", details.sensitiveArgs ?? null],
            ["Read at", startTimestamp],
            ["Network activity", endTimestamp],
            ["Gap between events", gapMs != null ? `${formatNumber(gapMs)} ms` : null]
        ];

        const lines = clauseEntries
            .map(([label, value]) => {
                if (value == null) {
                    return label;
                }
                const stringValue = typeof value === "string" ? value.trim() : String(value).trim();
                if (!stringValue.length) {
                    return label;
                }
                return `${label}: ${stringValue}`;
            })
            .filter((line): line is string => Boolean(line && line.trim()))
            .map((line) => line.trim());

        if (!lines.length) {
            lines.push("Sensitive data access detected.");
        }

        descriptionLines = lines;
        description = lines.join("\n");
    } else if (type === "reasoning_loop") {
        const occurrencesRaw = details.occurrences ?? score ?? 0;
        const numericOccurrences = Number(occurrencesRaw);
        const cycles = Number.isFinite(numericOccurrences) ? Math.max(2, Math.round(numericOccurrences)) : 2;
        const statusCode = details.status_code;
        const parts = [
            primaryPid ? `PID ${primaryPid} produced repeated responses.` : "Repeated responses detected.",
            statusCode != null ? `Status code: ${statusCode}.` : null,
            `Occurrences: ${formatNumber(cycles)}.`,
            startTimestamp ? `First seen: ${startTimestamp}.` : null,
            endTimestamp ? `Latest occurrence: ${endTimestamp}.` : null
        ].filter((value): value is string => Boolean(value));
        description = parts.join(" ");
        descriptionLines = parts.length ? parts : ["Repeated responses detected."];
    } else {
        const normalized = normalizeGenericDetails(rawDetails);
        description = normalized.description;
        descriptionLines = normalized.lines;
        rawDetails = normalized.raw;
    }

    return {
        key: `${type}-${index}`,
        type,
        severity,
        severityTag,
        description,
        descriptionLines,
        primaryPid,
        rootPid,
        rootExecId,
        score,
        startTimestamp,
        endTimestamp,
        rawDetails
    };
}

