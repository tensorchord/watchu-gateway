const SEVERITY_COLOR_MAP: Record<string, { color: string; label: string }> = {
    // Widely separated hues to make severity tiers easier to distinguish at a glance
    critical: { color: "#991b1b", label: "Critical" }, // deep red
    high: { color: "#ef4444", label: "High" }, // vivid red
    medium: { color: "#f59e0b", label: "Medium" }, // amber
    low: { color: "#22c55e", label: "Low" }, // bright green
    info: { color: "#0ea5e9", label: "Info" }
};

export function normalizeSeverityKey(value?: string | null): string {
    const normalized = value?.trim().toLowerCase() ?? "";
    if (!normalized) {
        return "";
    }
    if (normalized === "unsafe") {
        return "high";
    }
    if (normalized === "suspicious" || normalized === "controversial" || normalized === "warning") {
        return "medium";
    }
    if (normalized === "safe") {
        return "low";
    }
    return normalized;
}

export function getSeverityColor(value?: string | null): string {
    const key = normalizeSeverityKey(value);
    if (key in SEVERITY_COLOR_MAP) {
        return SEVERITY_COLOR_MAP[key].color;
    }
    return "#94a3b8";
}

export function getSeverityLabel(value?: string | null): string {
    const key = normalizeSeverityKey(value);
    if (key in SEVERITY_COLOR_MAP) {
        return SEVERITY_COLOR_MAP[key].label;
    }
    if (!value) {
        return "Unknown";
    }
    return value.charAt(0).toUpperCase() + value.slice(1);
}
