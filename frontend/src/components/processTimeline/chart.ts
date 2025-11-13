import { formatTimestamp } from "../../utils/time";
import { TIME_FORMATTERS } from "./constants";
import type { TimeRange } from "./types";

export function buildAxisLabelFormatter(range: TimeRange): (value: number) => string {
    if (!range) {
        return (value: number) => formatTimestamp(value) ?? "";
    }
    const span = range.max - range.min;
    const sameDay = new Date(range.min).toDateString() === new Date(range.max).toDateString();
    return (value: number) => {
        if (!Number.isFinite(value)) {
            return "";
        }
        const date = new Date(value);
        if (span <= 3 * 60 * 60 * 1000) {
            return TIME_FORMATTERS.timeWithSeconds.format(date);
        }
        if (span <= 24 * 60 * 60 * 1000 && sameDay) {
            return TIME_FORMATTERS.timeWithoutSeconds.format(date);
        }
        return TIME_FORMATTERS.dateWithTime.format(date);
    };
}

export function buildZoomLabelFormatter(range: TimeRange): (value: number) => string {
    if (!range) {
        return (value: number) => formatTimestamp(value) ?? "";
    }
    return (value: number) => {
        if (!Number.isFinite(value)) {
            return "";
        }
        const date = new Date(value);
        return TIME_FORMATTERS.dateWithTime.format(date);
    };
}
