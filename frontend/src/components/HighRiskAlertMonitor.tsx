import { AlertOutlined } from "@ant-design/icons";
import { Badge, Button, Space, Tooltip, Typography, notification } from "antd";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useSettings } from "../context/SettingsContext";
import { useHeuristicAlerts } from "../hooks/useAnalytics";
import type { HeuristicAlertResponse } from "../types";
import { getSeverityColor, getSeverityLabel, normalizeSeverityKey } from "../utils/severity";

const SNOOZE_MS = 10 * 60 * 1000;

function getAlertKey(alert: HeuristicAlertResponse, index: number): string {
    if (alert.alert_id) {
        return alert.alert_id;
    }
    const parts = [alert.alert_type ?? "alert", alert.start_ts ?? "", alert.end_ts ?? "", index.toString()];
    return parts.join(":");
}

function isHighSeverity(alert: HeuristicAlertResponse): boolean {
    const key = normalizeSeverityKey(alert.severity ?? undefined);
    return key === "high" || key === "critical";
}

export default function HighRiskAlertMonitor() {
    const navigate = useNavigate();
    const { host, since, until, limit } = useSettings();
    const alertsQuery = useHeuristicAlerts(host, since, until, limit === -1 ? 999999 : Math.max(50, limit));
    const [api, contextHolder] = notification.useNotification();
    const seenRef = useRef<Set<string>>(new Set());
    const [snoozedUntil, setSnoozedUntil] = useState<number | null>(null);

    useEffect(() => {
        seenRef.current.clear();
    }, [host, since, until]);

    const highSeverityAlerts = useMemo(() => {
        if (!Array.isArray(alertsQuery.data)) {
            return [] as HeuristicAlertResponse[];
        }
        return alertsQuery.data.filter(isHighSeverity);
    }, [alertsQuery.data]);

    useEffect(() => {
        if (!highSeverityAlerts.length || alertsQuery.isFetching || !host) {
            return;
        }
        const now = Date.now();
        if (snoozedUntil && now < snoozedUntil) {
            return;
        }
        const unseen = highSeverityAlerts.filter((alert, index) => {
            const key = getAlertKey(alert, index);
            return !seenRef.current.has(key);
        });
        if (!unseen.length) {
            return;
        }
        unseen.forEach((alert, index) => {
            const key = getAlertKey(alert, index);
            seenRef.current.add(key);
        });
        const primary = unseen[0];
        const additional = unseen.length - 1;
        const severityColor = getSeverityColor(primary.severity ?? undefined);
        const severityLabel = getSeverityLabel(primary.severity ?? undefined);

        const handleViewDetails = () => {
            navigate("/alerts");
            api.destroy();
        };
        const handleSnooze = () => {
            setSnoozedUntil(Date.now() + SNOOZE_MS);
            api.destroy();
        };

        api.open({
            message: `${severityLabel} heuristic alert detected`,
            description: (
                <Space direction="vertical" size={8} style={{ width: "100%" }}>
                    <Typography.Text strong>
                        {primary.alert_type ?? "Heuristic alert"} near root PID {primary.root_pid ?? "unknown"} at {primary.start_ts ?? "recent"}.
                    </Typography.Text>
                    {primary.reason ? (
                        <Typography.Text style={{ fontSize: "13px", color: "#d32f2f" }}>
                            {primary.reason}
                        </Typography.Text>
                    ) : null}
                    {additional > 0 ? (
                        <Typography.Text type="secondary">+{additional} additional high severity alerts in this window</Typography.Text>
                    ) : null}
                    <Space size={8}>
                        <Button type="primary" size="small" onClick={handleViewDetails}>
                            View alerts
                        </Button>
                        <Button size="small" onClick={handleSnooze}>
                            Snooze 10 min
                        </Button>
                    </Space>
                </Space>
            ),
            placement: "topRight",
            duration: 0,
            icon: <AlertOutlined style={{ color: severityColor }} />,
            style: {
                borderLeft: `4px solid ${severityColor}`
            }
        });
    }, [api, alertsQuery.isFetching, highSeverityAlerts, host, navigate, snoozedUntil]);

    const badgeCount = highSeverityAlerts.length;

    return (
        <>
            {contextHolder}
            <Tooltip title={badgeCount ? `${badgeCount} high severity alerts` : "No high severity alerts"}>
                <Badge count={badgeCount} size="small" color="#dc2626">
                    <Button
                        icon={<AlertOutlined />}
                        shape="circle"
                        aria-label="Open heuristic alerts"
                        onClick={() => navigate("/alerts")}
                    />
                </Badge>
            </Tooltip>
        </>
    );
}
