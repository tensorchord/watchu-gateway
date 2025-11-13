import { Card, Col, Result, Row, Skeleton, Tabs, message } from "antd";
import { useCallback, useMemo, useRef, useState } from "react";

import ProcessTimeline from "../components/ProcessTimeline";
import SecurityLLMAnalysis from "../components/SecurityLLMAnalysis";
import { useSettings } from "../context/SettingsContext";
import { useProcessEvents, useProcessHttpEvents, useSecurityAnalysis } from "../hooks/useAnalytics";

const TAB_ITEMS = [
    { key: "timeline", label: "HTTP Timeline" },
    { key: "security", label: "Security Analysis" }
];

export default function Dashboard() {
    const { host, since, until, limit } = useSettings();
    const httpEventsQuery = useProcessHttpEvents(host, since, until, limit);
    const processEventsQuery = useProcessEvents(host, since, until, limit);
    const securityQuery = useSecurityAnalysis(host, 20, 20);

    const [activeTab, setActiveTab] = useState<string>("timeline");
    const [focusRootExecId, setFocusRootExecId] = useState<string | null>(null);
    const lastWarningRef = useRef<string | null>(null);

    const hasError =
        httpEventsQuery.error || securityQuery.error || processEventsQuery.error;

    const timelineLoading = httpEventsQuery.isFetching || processEventsQuery.isFetching;

    const handleRefreshTimeline = useCallback(() => {
        void httpEventsQuery.refetch();
        void processEventsQuery.refetch();
    }, [httpEventsQuery, processEventsQuery]);

    const handleFocusApplied = useCallback(
        ({ found, rootExecId }: { found: boolean; rootExecId: string }) => {
            if (!found) {
                if (lastWarningRef.current !== rootExecId) {
                    lastWarningRef.current = rootExecId;
                    void message.warning(`Root Exec ${rootExecId} not found in the timeline.`);
                }
                return;
            }
            lastWarningRef.current = null;
        },
        []
    );

    const handleFocusCleared = useCallback(() => {
        setFocusRootExecId(null);
    }, []);

    const handleNavigateToRootExec = useCallback((rootExecId: string) => {
        setFocusRootExecId(rootExecId);
        setActiveTab("timeline");
    }, []);

    const timelineContent = useMemo(() => {
        if (httpEventsQuery.isLoading || processEventsQuery.isLoading) {
            return <Skeleton active />;
        }
        return (
            <ProcessTimeline
                httpEvents={httpEventsQuery.data ?? []}
                processEvents={processEventsQuery.data ?? []}
                loading={timelineLoading}
                focusRootExecId={focusRootExecId}
                onRefresh={handleRefreshTimeline}
                onFocusRootExecApplied={handleFocusApplied}
                onFocusRootExecCleared={handleFocusCleared}
            />
        );
    }, [
        focusRootExecId,
        handleFocusApplied,
        handleFocusCleared,
        handleRefreshTimeline,
        httpEventsQuery.data,
        httpEventsQuery.isLoading,
        processEventsQuery.data,
        processEventsQuery.isLoading,
        timelineLoading
    ]);

    const securityContent = useMemo(() => {
        if (securityQuery.isLoading) {
            return <Skeleton active />;
        }
        return (
            <SecurityLLMAnalysis
                data={securityQuery.data}
                loading={securityQuery.isFetching}
                onNavigateToRootExec={handleNavigateToRootExec}
            />
        );
    }, [handleNavigateToRootExec, securityQuery.data, securityQuery.isFetching, securityQuery.isLoading]);

    if (hasError) {
        return (
            <Result
                status="error"
                title="Unable to fetch dashboard data"
                subTitle={
                    (httpEventsQuery.error as Error)?.message ??
                    (processEventsQuery.error as Error)?.message ??
                    (securityQuery.error as Error)?.message ??
                    "Unknown error"
                }
            />
        );
    }

    return (
        <Row gutter={[24, 24]}>
            <Col span={24}>
                <Card bordered={false}>
                    <Tabs
                        activeKey={activeTab}
                        onChange={(key) => setActiveTab(key)}
                        items={TAB_ITEMS.map((tab) => ({
                            key: tab.key,
                            label: tab.label,
                            children: tab.key === "timeline" ? timelineContent : securityContent
                        }))}
                    />
                </Card>
            </Col>
        </Row>
    );
}
