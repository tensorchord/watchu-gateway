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
                    disabledDate={(current) => {
                        // 只禁用未来的日期（从明天开始）
                        return !!current && current.startOf('day').isAfter(dayjs().startOf('day'));
                    }}
                    disabledTime={(current, type) => {
                        // 如果是当天，禁用未来的时间
                        if (!current || !current.isSame(dayjs(), 'day')) {
                            return {};
                        }

                        const now = dayjs();
                        const currentHour = now.hour();
                        const currentMinute = now.minute();
                        const currentSecond = now.second();

                        if (type === 'start') {
                            // start 时间可以选择任何过去的时间
                            return {};
                        }

                        // end 时间：禁用未来的小时、分钟、秒
                        return {
                            disabledHours: () => {
                                const hours = [];
                                for (let i = currentHour + 1; i < 24; i++) {
                                    hours.push(i);
                                }
                                return hours;
                            },
                            disabledMinutes: (selectedHour: number) => {
                                if (selectedHour < currentHour) {
                                    return [];
                                }
                                if (selectedHour === currentHour) {
                                    const minutes = [];
                                    for (let i = currentMinute + 1; i < 60; i++) {
                                        minutes.push(i);
                                    }
                                    return minutes;
                                }
                                return [];
                            },
                            disabledSeconds: (selectedHour: number, selectedMinute: number) => {
                                if (selectedHour < currentHour ||
                                    (selectedHour === currentHour && selectedMinute < currentMinute)) {
                                    return [];
                                }
                                if (selectedHour === currentHour && selectedMinute === currentMinute) {
                                    const seconds = [];
                                    for (let i = currentSecond + 1; i < 60; i++) {
                                        seconds.push(i);
                                    }
                                    return seconds;
                                }
                                return [];
                            }
                        };
                    }}
                />
            </Tooltip>
        </Space>
    );
}
