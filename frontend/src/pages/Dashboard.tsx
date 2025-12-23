import { Card, Col, Result, Row, Skeleton, Tabs, Typography, message } from "antd";
import { useCallback, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import DataSourcesPanel from "../components/DataSourcesPanel";
import ProcessTimeline from "../components/ProcessTimeline";
import SecurityLLMAnalysis from "../components/SecurityLLMAnalysis";
import TraceExplorer from "../components/TraceExplorer";
import { useSettings } from "../context/SettingsContext";
import { useProcessEvents, useProcessHttpEvents, useSecurityAnalysis } from "../hooks/useAnalytics";

type DashboardView = "timeline" | "trace" | "security";

const VIEW_METADATA: Record<DashboardView, { title: string; description: string }> = {
    timeline: {
        title: "Timeline",
        description: "Correlate HTTP, MCP, and process activity for the selected host."
    },
    trace: {
        title: "Agent Trace Explorer",
        description: "Inspect normalized agent runs and nested traces."
    },
    security: {
        title: "Security Analysis",
        description: "Review heuristic and LLM-based security insights."
    }
};

interface DashboardProps {
    view?: DashboardView;
}

export default function Dashboard({ view = "timeline" }: DashboardProps) {
    const { host, since, until, limit } = useSettings();
    const location = useLocation();
    const httpEventsQuery = useProcessHttpEvents(host, since, until, limit);
    const processEventsQuery = useProcessEvents(host, since, until, limit);
    const securityQuery = useSecurityAnalysis(host, 20, 20);

    const [focusRootExecId, setFocusRootExecId] = useState<string | null>(null);
    const lastWarningRef = useRef<string | null>(null);
    const navigate = useNavigate();
    const activeView: DashboardView = view;

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

    const handleNavigateToRootExec = useCallback(
        (rootExecId: string) => {
            setFocusRootExecId(rootExecId);
            navigate("/timeline");
        },
        [navigate]
    );

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

    const renderContent = useMemo(() => {
        switch (activeView) {
            case "trace":
                return <TraceExplorer key={location.key} />;
            case "security":
                return securityContent;
            case "timeline":
            default:
                return timelineContent;
        }
    }, [activeView, location.key, securityContent, timelineContent]);

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

    const meta = VIEW_METADATA[activeView];

    const showAuxTabs = activeView === "timeline" || activeView === "security";

    return (
        <Row gutter={[24, 24]}>
            <Col span={24}>
                <Card bordered={false} bodyStyle={{ paddingTop: 16 }}>
                    <Typography.Title level={4} style={{ marginBottom: 4 }}>
                        {meta.title}
                    </Typography.Title>
                    <Typography.Paragraph type="secondary" style={{ marginBottom: 24 }}>
                        {meta.description}
                    </Typography.Paragraph>
                    {showAuxTabs ? (
                        <Tabs
                            key={activeView}
                            defaultActiveKey="main"
                            items={[
                                { key: "main", label: meta.title, children: renderContent },
                                { key: "data-sources", label: "Data Sources", children: <DataSourcesPanel /> }
                            ]}
                        />
                    ) : (
                        renderContent
                    )}
                </Card>
            </Col>
        </Row>
    );
}
