const formatters = {
    timestamp: new Intl.DateTimeFormat("en-US", {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    }),
    relative: new Intl.RelativeTimeFormat("en", { numeric: "auto" })
};

function normalizeTimestampText(text: string): string[] {
    const candidates = new Set<string>();
    const trimmed = text.trim();
    if (!trimmed) {
        return [];
    }
    candidates.add(trimmed);
    if (!trimmed.includes("T") && trimmed.includes(" ")) {
        candidates.add(trimmed.replace(" ", "T"));
    }
    for (const value of Array.from(candidates)) {
        if (!value.toUpperCase().endsWith("Z")) {
            candidates.add(`${value}Z`);
        }
    }
    return Array.from(candidates);
}

export function toTimestampMillis(value: unknown): number | null {
    if (value == null) {
        return null;
    }

    if (typeof value === "number") {
        const ms = value > 1_000_000_000_000 ? value : value * 1000;
        return Number.isFinite(ms) ? ms : null;
    }

    if (value instanceof Date) {
        const ms = value.getTime();
        return Number.isNaN(ms) ? null : ms;
    }

    const text =
        typeof value === "string"
            ? value
            : typeof value === "number" || typeof value === "boolean" || typeof value === "bigint"
                ? String(value)
                : null;
    if (text == null) {
        return null;
    }
    const numeric = Number(text);
    if (!Number.isNaN(numeric) && text.trim().length >= 10) {
        const ms = numeric > 1_000_000_000_000 ? numeric : numeric * 1000;
        return Number.isFinite(ms) ? ms : null;
    }

    const candidates = normalizeTimestampText(text);
    for (const candidate of candidates) {
        const parsed = Date.parse(candidate);
        if (!Number.isNaN(parsed)) {
            return parsed;
        }
    }

    return null;
}

export function formatTimestamp(value: unknown): string | null {
    const ms = toTimestampMillis(value);
    if (ms == null) {
        return typeof value === "string" ? value : null;
    }
    return formatters.timestamp.format(new Date(ms));
}

export function formatRelativeTime(value: Date | string | number | null | undefined): string | null {
    if (value == null) {
        return null;
    }
    const ms = toTimestampMillis(value);
    if (ms == null) {
        return null;
    }
    const date = new Date(ms);
    const now = Date.now();
    const delta = date.getTime() - now;
    const absDelta = Math.abs(delta);
    if (!Number.isFinite(absDelta)) {
        return null;
    }

    const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
        ["day", 86400000],
        ["hour", 3600000],
        ["minute", 60000],
        ["second", 1000]
    ];

    for (const [unit, ms] of units) {
        if (absDelta >= ms || unit === "second") {
            const valueInUnit = Math.round(delta / ms);
            return formatters.relative.format(valueInUnit, unit);
        }
    }

    return null;
}

