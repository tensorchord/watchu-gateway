import { DatePicker, Select, Space, Tooltip, type SelectProps } from "antd";
import { useEffect, useMemo } from "react";
import dayjs, { Dayjs } from "dayjs";

import { TimeRangePreset, useSettings } from "../context/SettingsContext";
import { useHosts } from "../hooks/useAnalytics";

const presetOptions: Array<{ label: string; value: TimeRangePreset; minutes?: number }> = [
    { label: "Last 15m", value: "15m", minutes: 15 },
    { label: "Last 1h", value: "1h", minutes: 60 },
    { label: "Last 6h", value: "6h", minutes: 360 },
    { label: "Last 24h", value: "24h", minutes: 1440 },
    { label: "Custom", value: "custom" }
];

const { RangePicker } = DatePicker;

function calculateRange(preset: TimeRangePreset): [Dayjs, Dayjs] {
    const until = dayjs();
    const option = presetOptions.find((item) => item.value === preset);
    if (option?.minutes) {
        return [until.subtract(option.minutes, "minute"), until];
    }
    return [until.subtract(1, "hour"), until];
}

export default function GlobalFilters() {
    const { host, setHost, since, setSince, until, setUntil, timePreset, setTimePreset } = useSettings();
    const { data: hosts = [], isLoading: hostsLoading } = useHosts();

    const hostOptions = useMemo<SelectProps<string>["options"]>(
        () => hosts.map((value) => ({ label: value, value })),
        [hosts]
    );

    useEffect(() => {
        if (!hostOptions || hostOptions.length === 0) {
            return;
        }
        const exists = hostOptions.some((option) => option?.value === host);
        if (!exists) {
            const nextHost = hostOptions[0]?.value;
            if (typeof nextHost === "string") {
                setHost(nextHost);
            }
        }
    }, [host, hostOptions, setHost]);

    return (
        <Space size="middle" wrap align="center">
            <Select<string>
                placeholder="Host"
                value={host || undefined}
                loading={hostsLoading}
                style={{ width: 220 }}
                options={hostOptions}
                showSearch
                onChange={(value) => setHost(value?.trim() ?? "")}
                filterOption={(input, option) => {
                    const optionValue = (option?.value as string | undefined) ?? "";
                    return optionValue.toLowerCase().includes(input.toLowerCase());
                }}
                notFoundContent={hostsLoading ? null : "No hosts"}
            />
            <Select<TimeRangePreset>
                value={timePreset}
                style={{ width: 140 }}
                onChange={(preset: TimeRangePreset) => {
                    setTimePreset(preset);
                    if (preset !== "custom") {
                        const [nextSince, nextUntil] = calculateRange(preset);
                        setSince(nextSince);
                        setUntil(nextUntil);
                    }
                }}
                options={presetOptions}
            />
            <Tooltip title="Select a custom time range">
                <RangePicker
                    showTime={{
                        format: "HH:mm:ss",
                        defaultValue: [dayjs().subtract(1, "hour"), dayjs()]
                    }}
                    value={[since, until]}
                    allowClear={false}
                    onChange={(dates) => {
                        if (!dates || dates.length !== 2) {
                            return;
                        }
                        const [start, end] = dates;
                        if (!start || !end) {
                            return;
                        }
                        if (end.isBefore(start)) {
                            return;
                        }
                        setTimePreset("custom");
                        setSince(start);
                        setUntil(end);
                    }}
                    disabledDate={(current) => !!current && current.endOf("minute").isAfter(dayjs())}
                />
            </Tooltip>
        </Space>
    );
}
