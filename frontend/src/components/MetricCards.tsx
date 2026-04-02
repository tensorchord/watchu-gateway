import { ExclamationCircleFilled, InfoCircleFilled, WarningFilled } from "@ant-design/icons";
import { Button, Card, Collapse, Empty, Flex, Select, Skeleton, Space, Tag, Typography } from "antd";
import type { CollapseProps } from "antd";
import { useMemo, useState } from "react";
import type React from "react";

import type { HeuristicAlertResponse } from "../types";
import { buildAlertInfo, type AlertInfo, type AlertSeverityTag, formatExecId } from "../utils/alerts";
import { CARD_HEAD_STYLE, CARD_TITLE_TEXT_STYLE } from "./cardStyles";
import CommandBlock from "./CommandBlock";

interface MetricCardsProps {
    title?: string;
    alerts?: HeuristicAlertResponse[];
    loading?: boolean;
}

const { Text } = Typography;

const DEFAULT_VISIBLE_GROUPS = 3;

const SEVERITY_ORDER: AlertSeverityTag[] = ["error", "warning", "info"];

const SEVERITY_RANK: Record<AlertSeverityTag, number> = {
    error: 0,
    warning: 1,
    info: 2
};

type CollapsePanelItem = NonNullable<CollapseProps["items"]>[number];

const SEVERITY_META: Record<AlertSeverityTag, {
    label: string;
    surface: string;
    border: string;
    accent: string;
    iconBackground: string;
    text: string;
    icon: React.JSX.Element;
}> = {
    error: {
        label: "High Risk",
        surface: "#fef2f2",
        border: "#fecaca",
        accent: "#ef4444",
        iconBackground: "#fee2e2",
        text: "#7f1d1d",
        icon: <ExclamationCircleFilled style={{ color: "#b91c1c" }} />
    },
    warning: {
        label: "Medium Risk",
        surface: "#fffbeb",
        border: "#fde68a",
        accent: "#f59e0b",
        iconBackground: "#fef3c7",
        text: "#78350f",
        icon: <WarningFilled style={{ color: "#b45309" }} />
    },
    info: {
        label: "Low Risk",
        surface: "#eff6ff",
        border: "#bfdbfe",
        accent: "#3b82f6",
        iconBackground: "#dbeafe",
        text: "#1e3a8a",
        icon: <InfoCircleFilled style={{ color: "#1d4ed8" }} />
    }
};

function formatAlertTypeLabel(value: string): string {
    if (!value) {
        return "Alert";
    }
    const spaced = value.replace(/[_-]+/g, " ");
    return spaced.replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatSeverityLabel(value: string): string {
    if (!value) {
        return "Unknown";
    }
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function decodeAlertRow(alert: HeuristicAlertResponse): Record<string, unknown> {
    return {
        alert_type: alert.alert_type,
        severity: alert.severity,
        score: alert.score,
        details: alert.details,
        root_pid: alert.root_pid,
        root_exec_id: alert.root_exec_id,
        start_ts: alert.start_ts,
        end_ts: alert.end_ts
    } satisfies Record<string, unknown>;
}

export default function MetricCards({ title = "Heuristic Alerts", alerts = [], loading = false }: MetricCardsProps = {}) {
    const [showAll, setShowAll] = useState(false);
    const [activeKeys, setActiveKeys] = useState<string[]>([]);
    const [selectedAlertByGroup, setSelectedAlertByGroup] = useState<Record<string, string>>({});

    const alertInfos = useMemo(() => {
        if (!Array.isArray(alerts)) {
            return [] as AlertInfo[];
        }
        return alerts.map((alert, index) => buildAlertInfo(decodeAlertRow(alert), index));
    }, [alerts]);

    const severityBuckets = useMemo(() => {
        const buckets: Record<AlertSeverityTag, AlertInfo[]> = {
            error: [],
            warning: [],
            info: []
        };
        alertInfos.forEach((alert) => {
            buckets[alert.severityTag].push(alert);
        });
        return buckets;
    }, [alertInfos]);

    const alertGroups = useMemo(() => {
        const map = new Map<
            string,
            {
                key: string;
                rootPid: string | null;
                rootExecId: string | null;
                alerts: AlertInfo[];
                highestSeverity: AlertSeverityTag;
            }
        >();

        alertInfos.forEach((alert) => {
            const groupKey = `${alert.rootPid ?? "unknown"}::${alert.rootExecId ?? "unknown"}`;
            const existing = map.get(groupKey);
            if (existing) {
                existing.alerts.push(alert);
                if (SEVERITY_RANK[alert.severityTag] < SEVERITY_RANK[existing.highestSeverity]) {
                    existing.highestSeverity = alert.severityTag;
                }
            } else {
                map.set(groupKey, {
                    key: groupKey,
                    rootPid: alert.rootPid ?? null,
                    rootExecId: alert.rootExecId ?? null,
                    alerts: [alert],
                    highestSeverity: alert.severityTag
                });
            }
        });

        const groups = Array.from(map.values());
        groups.forEach((group) => {
            group.alerts.sort((a, b) => {
                const rankDelta = SEVERITY_RANK[a.severityTag] - SEVERITY_RANK[b.severityTag];
                if (rankDelta !== 0) {
                    return rankDelta;
                }
                const scoreA = typeof a.score === "number" && Number.isFinite(a.score) ? a.score : -Infinity;
                const scoreB = typeof b.score === "number" && Number.isFinite(b.score) ? b.score : -Infinity;
                return scoreB - scoreA;
            });
        });

        groups.sort((a, b) => {
            const rankDelta = SEVERITY_RANK[a.highestSeverity] - SEVERITY_RANK[b.highestSeverity];
            if (rankDelta !== 0) {
                return rankDelta;
            }
            const topA = a.alerts[0];
            const topB = b.alerts[0];
            const scoreA = typeof topA?.score === "number" && Number.isFinite(topA.score) ? topA.score : -Infinity;
            const scoreB = typeof topB?.score === "number" && Number.isFinite(topB.score) ? topB.score : -Infinity;
            return scoreB - scoreA;
        });

        return groups;
    }, [alertInfos]);

    const visibleGroups = useMemo(() => {
        if (showAll) {
            return alertGroups;
        }
        return alertGroups.slice(0, DEFAULT_VISIBLE_GROUPS);
    }, [alertGroups, showAll]);

    const hasMoreGroups = alertGroups.length > DEFAULT_VISIBLE_GROUPS;

    const effectiveActiveKeys = useMemo(() => {
        const allowed = new Set(visibleGroups.map((group) => group.key));
        const filtered = activeKeys.filter((key) => allowed.has(key));
        if (filtered.length) {
            return filtered;
        }
        const first = visibleGroups[0];
        return first ? [first.key] : [];
    }, [activeKeys, visibleGroups]);

    const collapseItems = useMemo(() => {
        const panelStyle: CollapsePanelItem["style"] = {
            marginBottom: 12,
            borderRadius: 16,
            border: "1px solid #e2e8f0",
            overflow: "hidden"
        };

        const items: CollapsePanelItem[] = [];

        visibleGroups.forEach((group) => {
            const storedKey = selectedAlertByGroup[group.key];
            const fallbackKey = group.alerts[0]?.key;
            const selectedKey = storedKey && group.alerts.some((candidate) => candidate.key === storedKey) ? storedKey : fallbackKey;
            const selectedAlert = group.alerts.find((candidate) => candidate.key === selectedKey) ?? group.alerts[0];
            if (!selectedAlert) {
                return;
            }

            const palette = SEVERITY_META[selectedAlert.severityTag];
            const severityLabel = formatSeverityLabel(selectedAlert.severity);
            const identityEntries = (
                [
                    group.rootPid ? { key: "rootPid", label: "Root PID", value: group.rootPid } : null,
                    group.rootExecId ? { key: "rootExec", label: "Exec", value: formatExecId(group.rootExecId) } : null
                ].filter((entry): entry is { key: string; label: string; value: string } => Boolean(entry))
            );
            const scoreTag =
                typeof selectedAlert.score === "number" && Number.isFinite(selectedAlert.score)
                    ? selectedAlert.score > 1
                        ? `Score ${selectedAlert.score.toFixed(0)}`
                        : `Confidence ${(selectedAlert.score * 100).toFixed(0)}%`
                    : null;

            const timeMeta = [
                { label: "First Seen", value: selectedAlert.startTimestamp },
                { label: "Last Seen", value: selectedAlert.endTimestamp }
            ].filter((entry) => entry.value);

            const hasMultipleAlerts = group.alerts.length > 1;
            const selectOptions = group.alerts.map((candidate) => ({
                value: candidate.key,
                label: `${formatAlertTypeLabel(candidate.type)} · ${candidate.startTimestamp ?? candidate.endTimestamp ?? "Unknown time"}`
            }));

            items.push({
                key: group.key,
                style: panelStyle,
                label: (
                    <Flex align="center" justify="space-between" wrap gap={12}>
                        <Flex align="center" gap={12} style={{ minWidth: 0 }}>
                            <div
                                style={{
                                    width: 36,
                                    height: 36,
                                    borderRadius: "50%",
                                    background: palette.iconBackground,
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center"
                                }}
                            >
                                {palette.icon}
                            </div>
                            <Flex vertical gap={2} style={{ minWidth: 0 }}>
                                <Text strong style={{ color: palette.text }}>
                                    {formatAlertTypeLabel(selectedAlert.type)}
                                </Text>
                                {identityEntries.length ? (
                                    <Space size={8} wrap>
                                        {identityEntries.map((entry) => (
                                            <Tag
                                                key={`${group.key}-identity-${entry.key}`}
                                                style={{
                                                    borderRadius: 999,
                                                    borderColor: palette.border,
                                                    background: "#ffffff",
                                                    color: palette.text,
                                                    fontWeight: 500
                                                }}
                                            >
                                                <Text
                                                    copyable={{ text: entry.value }}
                                                    style={{ color: "inherit", fontWeight: 500, display: "inline-flex", alignItems: "center", gap: 4 }}
                                                >
                                                    {entry.label} {entry.value}
                                                </Text>
                                            </Tag>
                                        ))}
                                    </Space>
                                ) : (
                                    <Text style={{ color: "#64748b", fontSize: 12 }}>Applies to current workspace</Text>
                                )}
                            </Flex>
                        </Flex>
                        <Space size={[8, 8]} wrap>
                            <Tag
                                style={{
                                    borderRadius: 999,
                                    borderColor: palette.accent,
                                    background: palette.surface,
                                    color: palette.text,
                                    fontWeight: 600
                                }}
                            >
                                {severityLabel}
                            </Tag>
                            {scoreTag ? (
                                <Tag
                                    style={{
                                        borderRadius: 999,
                                        borderColor: "#cbd5f5",
                                        color: "#1e293b",
                                        background: "#e2e8f0"
                                    }}
                                >
                                    {scoreTag}
                                </Tag>
                            ) : null}
                            {hasMultipleAlerts ? (
                                <Tag
                                    style={{
                                        borderRadius: 999,
                                        borderColor: "#cbd5f5",
                                        color: "#1e293b",
                                        background: "#f8fafc",
                                        fontWeight: 500
                                    }}
                                >
                                    {group.alerts.length} alerts
                                </Tag>
                            ) : null}
                        </Space>
                    </Flex>
                ),
                children: (
                    <Flex vertical gap={12} style={{ padding: "12px 4px 4px" }}>
                        {hasMultipleAlerts ? (
                            <Flex
                                align="center"
                                gap={12}
                                wrap
                                style={{
                                    padding: "6px 12px",
                                    background: "#eff6ff",
                                    borderRadius: 14,
                                    border: "1px solid #bfdbfe",
                                    boxShadow: "inset 0 0 0 1px rgba(59,130,246,0.08)"
                                }}
                            >
                                <Text
                                    style={{
                                        fontSize: 12,
                                        color: "#1d4ed8",
                                        fontWeight: 600
                                    }}
                                >
                                    Select alert instance
                                </Text>
                                <Select
                                    size="small"
                                    style={{ minWidth: 260 }}
                                    options={selectOptions}
                                    value={selectedKey}
                                    onChange={(value) => setSelectedAlertByGroup((previous) => ({ ...previous, [group.key]: value }))}
                                />
                            </Flex>
                        ) : null}
                        <Flex vertical gap={8}>
                            {selectedAlert.descriptionLines.map((line, index) => (
                                <Text key={`${selectedAlert.key}-line-${index}`} style={{ color: "#0f172a", fontSize: 14 }}>
                                    {line}
                                </Text>
                            ))}
                        </Flex>
                        {timeMeta.length ? (
                            <Space size={12} wrap>
                                {timeMeta.map((entry) => (
                                    <Tag
                                        key={`${selectedAlert.key}-time-${entry.label}`}
                                        style={{
                                            borderRadius: 999,
                                            borderColor: "#cbd5f5",
                                            color: "#1d4ed8",
                                            background: "#e2e8f0",
                                            fontWeight: 500
                                        }}
                                    >
                                        {entry.label}: {entry.value}
                                    </Tag>
                                ))}
                            </Space>
                        ) : null}
                        <CommandBlock text={selectedAlert.rawDetails} size="small" />
                    </Flex>
                )
            });
        });

        return items;
    }, [selectedAlertByGroup, visibleGroups]);

    const hasAlerts = alertInfos.length > 0;

    const headerExtra = hasAlerts && hasMoreGroups ? (
        <Button size="small" type="link" onClick={() => setShowAll((value) => !value)}>
            {showAll ? "Show fewer groups" : "Show more groups"}
        </Button>
    ) : null;

    return (
        <Card
            bordered={false}
            bodyStyle={{ padding: 24, borderRadius: 18 }}
            headStyle={CARD_HEAD_STYLE}
            title={<span style={CARD_TITLE_TEXT_STYLE}>{title}</span>}
            extra={headerExtra}
        >
            {loading ? (
                <Skeleton active paragraph={{ rows: 6 }} />
            ) : hasAlerts ? (
                <Flex vertical gap={24}>
                    <Flex gap={12} wrap>
                        {SEVERITY_ORDER.map((severity) => {
                            const bucket = severityBuckets[severity];
                            if (!bucket.length) {
                                return null;
                            }
                            const palette = SEVERITY_META[severity];
                            return (
                                <Flex
                                    key={severity}
                                    align="center"
                                    justify="space-between"
                                    style={{
                                        background: palette.surface,
                                        border: `1px solid ${palette.border}`,
                                        borderRadius: 16,
                                        padding: "12px 16px",
                                        minWidth: 220
                                    }}
                                >
                                    <Flex align="center" gap={12}>
                                        <div
                                            style={{
                                                width: 32,
                                                height: 32,
                                                borderRadius: "50%",
                                                background: palette.iconBackground,
                                                display: "flex",
                                                alignItems: "center",
                                                justifyContent: "center"
                                            }}
                                        >
                                            {palette.icon}
                                        </div>
                                        <Flex vertical gap={2}>
                                            <Text style={{ color: palette.text, fontWeight: 600 }}>{palette.label}</Text>
                                            <Text style={{ color: palette.text, fontSize: 12 }}>{bucket.length} alerts</Text>
                                        </Flex>
                                    </Flex>
                                </Flex>
                            );
                        })}
                    </Flex>
                    <Collapse
                        bordered={false}
                        ghost
                        items={collapseItems}
                        activeKey={effectiveActiveKeys}
                        onChange={(keys) => {
                            if (Array.isArray(keys)) {
                                setActiveKeys(keys.filter((key): key is string => typeof key === "string"));
                            } else if (typeof keys === "string") {
                                setActiveKeys([keys]);
                            } else {
                                setActiveKeys([]);
                            }
                        }}
                    />
                </Flex>
            ) : (
                <Empty description="No alerts detected in the selected window." />
            )}
        </Card>
    );
}
