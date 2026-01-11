import { Button, Card, Flex, InputNumber, Result, Space, Tooltip, Typography } from "antd";
import { useEffect, useMemo, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import ProcessTreePanel from "../components/ProcessTreePanel";
import { useSettings } from "../context/SettingsContext";
import { useProcessTree } from "../hooks/useAnalytics";
import type { ProcessTreeNodeResponse } from "../types/api";

const { Title, Paragraph, Text } = Typography;

export default function ProcessIndex() {
    const navigate = useNavigate();
    const location = useLocation();
    const { host, since, until, rootLimit, nodeLimit, setRootLimit, setNodeLimit } = useSettings();
    const rootExecQuery = useMemo(() => {
        const params = new URLSearchParams(location.search);
        const raw = params.get("root_exec_id");
        return raw ? raw.trim() : "";
    }, [location.search]);
    const treeQuery = useProcessTree({ host, rootLimit, nodeLimit, since, until, rootExecId: rootExecQuery || undefined });
    const autoNavRef = useRef(false);

    useEffect(() => {
        if (autoNavRef.current) return;
        if (!rootExecQuery || treeQuery.isLoading || treeQuery.isFetching) return;
        const rootPid = findRootPidByExec(treeQuery.data ?? [], rootExecQuery);
        if (typeof rootPid === "number") {
            autoNavRef.current = true;
            navigate(`/processes/${rootPid}?root_exec_id=${encodeURIComponent(rootExecQuery)}`, { replace: true });
        }
    }, [rootExecQuery, treeQuery.data, treeQuery.isLoading, treeQuery.isFetching, navigate]);

    if (treeQuery.error) {
        const message = treeQuery.error instanceof Error ? treeQuery.error.message : "Unknown error";
        return <Result status="error" title="Failed to load process tree" subTitle={message} />;
    }

    return (
        <Flex vertical gap={24}>
            <Card bordered={false} style={{ borderRadius: 16 }}>
                <Flex wrap gap={16} justify="space-between" align="flex-end">
                    <Flex vertical gap={8} style={{ minWidth: 260, flex: 1 }}>
                        <Title level={3} style={{ margin: 0 }}>
                            Process Explorer
                        </Title>
                        <Paragraph style={{ marginBottom: 0 }}>
                            Select a root process to inspect its telemetry, metrics, and alerts in detail.
                        </Paragraph>
                        <Text type="secondary">Choose a node below to jump straight into the process detail page.</Text>
                    </Flex>
                    <Flex wrap gap={12} align="flex-end">
                        <Button onClick={() => navigate("/data-sources")}>Data Sources</Button>
                        <Space direction="vertical" size={2}>
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                Root limit
                            </Typography.Text>
                            <Tooltip title="Maximum root processes displayed in the tree">
                                <InputNumber
                                    min={1}
                                    max={200}
                                    step={1}
                                    value={rootLimit}
                                    style={{ width: 112 }}
                                    onChange={(value: number | null) => {
                                        if (typeof value === "number" && !Number.isNaN(value)) {
                                            setRootLimit(value);
                                        }
                                    }}
                                />
                            </Tooltip>
                        </Space>
                        <Space direction="vertical" size={2}>
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                Node limit
                            </Typography.Text>
                            <Tooltip title="Maximum total nodes fetched for the process tree">
                                <InputNumber
                                    min={50}
                                    max={2000}
                                    step={50}
                                    value={nodeLimit}
                                    style={{ width: 112 }}
                                    onChange={(value: number | null) => {
                                        if (typeof value === "number" && !Number.isNaN(value)) {
                                            setNodeLimit(value);
                                        }
                                    }}
                                />
                            </Tooltip>
                        </Space>
                    </Flex>
                </Flex>
            </Card>
            <ProcessTreePanel
                title="Process Overview"
                tree={treeQuery.data}
                loading={treeQuery.isLoading}
                fetching={treeQuery.isFetching}
                since={since}
                until={until}
                onRefresh={() => {
                    void treeQuery.refetch();
                }}
                onSelectRoot={(root) => {
                    const pidCandidate = root.root_pid ?? root.pid;
                    if (pidCandidate != null) {
                        navigate(`/processes/${pidCandidate}`);
                    }
                }}
            />
        </Flex>
    );
}

function findRootPidByExec(nodes: ProcessTreeNodeResponse[], rootExecId: string): number | null {
    for (const node of nodes) {
        if (node.root_exec_id === rootExecId || node.exec_id === rootExecId) {
            return node.root_pid ?? node.pid ?? null;
        }
        if (node.children && node.children.length > 0) {
            const childPid = findRootPidByExec(node.children, rootExecId);
            if (childPid != null) {
                return childPid;
            }
        }
    }
    return null;
}
