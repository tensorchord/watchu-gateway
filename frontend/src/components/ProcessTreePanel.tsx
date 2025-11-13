import { MinusSquareOutlined, PlusSquareOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Card, Empty, Flex, Input, Skeleton, Space, Tag, Tree, Typography } from "antd";
import type { DataNode, TreeProps } from "antd/es/tree";
import dayjs, { Dayjs } from "dayjs";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { ProcessTreeNodeResponse } from "../types/api";

const { Text } = Typography;

interface ProcessTreePanelProps {
    tree?: ProcessTreeNodeResponse[];
    loading?: boolean;
    fetching?: boolean;
    title?: string;
    showControls?: boolean;
    height?: number;
    onRefresh?: () => void;
    onSelectRoot?: (root: ProcessTreeNodeResponse) => void;
    since?: Dayjs;
    until?: Dayjs;
}

interface NormalizedProcessTreeNode extends ProcessTreeNodeResponse {
    key: string;
    depth: number;
    children: NormalizedProcessTreeNode[];
}

interface TreeDataNode extends Omit<DataNode, "key" | "children" | "title"> {
    key: string;
    title: ReactNode;
    children?: TreeDataNode[];
    dataRef: NormalizedProcessTreeNode;
}

function sanitizeKey(source: ProcessTreeNodeResponse, fallback: string): string {
    if (source.exec_id) {
        return source.exec_id;
    }
    if (source.pid != null) {
        return `pid-${source.pid}`;
    }
    return fallback;
}

function normalizeTree(
    nodes: ProcessTreeNodeResponse[] | undefined,
    depth = 0,
    parentKey = "root"
): NormalizedProcessTreeNode[] {
    if (!nodes) {
        return [];
    }
    return nodes.map((node, index) => {
        const key = sanitizeKey(node, `${parentKey}-${index}`);
        const children = normalizeTree(node.children, depth + 1, key);
        return {
            ...node,
            key,
            depth: node.depth ?? depth,
            children
        };
    });
}

function isNodeWithinRange(node: ProcessTreeNodeResponse, since?: Dayjs, until?: Dayjs): boolean {
    if (!since && !until) {
        return true;
    }
    const timestamps = [node.start_ts, node.end_ts].filter(Boolean) as string[];
    if (timestamps.length === 0) {
        return true;
    }
    return timestamps.some((value) => {
        const instant = dayjs(value);
        if (!instant.isValid()) {
            return false;
        }
        const afterSince = !since || instant.isAfter(since) || instant.isSame(since);
        const beforeUntil = !until || instant.isBefore(until) || instant.isSame(until);
        return afterSince && beforeUntil;
    });
}

function filterTreeByRange(nodes: NormalizedProcessTreeNode[], since?: Dayjs, until?: Dayjs): NormalizedProcessTreeNode[] {
    if (!since && !until) {
        return nodes;
    }
    const results: NormalizedProcessTreeNode[] = [];
    nodes.forEach((node) => {
        const filteredChildren = filterTreeByRange(node.children, since, until);
        if (!isNodeWithinRange(node, since, until) && filteredChildren.length === 0) {
            return;
        }
        results.push({
            ...node,
            children: filteredChildren
        });
    });
    return results;
}

function renderNodeTitle(node: NormalizedProcessTreeNode): ReactNode {
    const argsLabel = node.args?.trim() ? node.args.trim() : null;
    const cwdLabel = node.cwd?.trim() ? node.cwd.trim() : null;
    return (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
                <Text strong style={{ whiteSpace: "nowrap" }}>
                    {node.comm ?? "Unknown process"}
                </Text>
                {node.exec_id && (
                    <Tag color="default" style={{ borderRadius: 12 }}>
                        exec {node.exec_id}
                    </Tag>
                )}
                {Number.isFinite(node.depth) && (
                    <Tag color="geekblue" style={{ borderRadius: 12 }}>
                        depth {node.depth}
                    </Tag>
                )}
            </div>
            <Text type="secondary" style={{ fontSize: 12 }}>
                {node.pid != null ? `PID ${node.pid}` : "PID n/a"}
                {node.ppid != null ? ` • Parent ${node.ppid}` : ""}
                {node.root_pid != null && node.root_pid !== node.pid ? ` • Root ${node.root_pid}` : ""}
                {cwdLabel ? ` • ${cwdLabel}` : ""}
                {argsLabel ? ` • Args: ${argsLabel}` : ""}
            </Text>
        </div>
    );
}

function buildFilteredTreeData(
    nodes: NormalizedProcessTreeNode[],
    predicate: (node: NormalizedProcessTreeNode) => boolean
): TreeDataNode[] {
    const results: TreeDataNode[] = [];
    nodes.forEach((node) => {
        const children = buildFilteredTreeData(node.children, predicate);
        if (!predicate(node) && children.length === 0) {
            return;
        }
        results.push({
            key: node.key,
            title: renderNodeTitle(node),
            children: children.length > 0 ? children : undefined,
            dataRef: node
        });
    });
    return results;
}

function collectExpandedKeys(nodes: NormalizedProcessTreeNode[]): string[] {
    const result: string[] = [];
    const visit = (node: NormalizedProcessTreeNode) => {
        result.push(node.key);
        node.children.forEach(visit);
    };
    nodes.forEach(visit);
    return result;
}

function collectTreeDataKeys(nodes: TreeDataNode[]): string[] {
    const result: string[] = [];
    const visit = (node: TreeDataNode) => {
        result.push(String(node.key));
        (node.children ?? []).forEach((child) => visit(child));
    };
    nodes.forEach(visit);
    return result;
}

function arraysHaveSameMembers(a: string[], b: string[]): boolean {
    if (a.length !== b.length) {
        return false;
    }
    const sortedA = [...a].sort();
    const sortedB = [...b].sort();
    return sortedA.every((value, index) => value === sortedB[index]);
}

function countNodes(nodes: NormalizedProcessTreeNode[]): number {
    return nodes.reduce((total, node) => total + 1 + countNodes(node.children), 0);
}

function computeMaxDepth(nodes: NormalizedProcessTreeNode[]): number {
    let depth = 0;
    const visit = (node: NormalizedProcessTreeNode, current: number) => {
        depth = Math.max(depth, current);
        node.children.forEach((child) => visit(child, current + 1));
    };
    nodes.forEach((node) => visit(node, node.depth ?? 0));
    return depth;
}

function findRootForKey(nodes: NormalizedProcessTreeNode[], key: string): NormalizedProcessTreeNode | null {
    for (const root of nodes) {
        if (root.key === key) {
            return root;
        }
        const stack = [...root.children];
        while (stack.length) {
            const current = stack.pop()!;
            if (current.key === key) {
                return root;
            }
            stack.push(...current.children);
        }
    }
    return null;
}

export default function ProcessTreePanel({
    tree,
    loading = false,
    fetching = false,
    title = "Process Overview",
    showControls = true,
    height = 360,
    onRefresh,
    onSelectRoot,
    since,
    until
}: ProcessTreePanelProps) {
    const normalizedTree = useMemo(() => {
        const base = normalizeTree(tree);
        return filterTreeByRange(base, since, until);
    }, [since, tree, until]);
    
    const [search, setSearch] = useState("");
    
    // Derive initial expanded keys from normalized tree
    const initialExpandedKeys = useMemo(() => normalizedTree.map((node) => node.key), [normalizedTree]);
    
    const [expandedKeys, setExpandedKeys] = useState<string[]>(() => initialExpandedKeys);
    const [autoExpandParent, setAutoExpandParent] = useState(true);
    const previousNormalizedTreeKeysRef = useRef<string[]>([]);

    // Update expanded keys when normalized tree changes (new tree data loaded)
    const currentNormalizedTreeKeys = useMemo(() => normalizedTree.map((node) => node.key), [normalizedTree]);
    
    useEffect(() => {
        if (!arraysHaveSameMembers(previousNormalizedTreeKeysRef.current, currentNormalizedTreeKeys)) {
            previousNormalizedTreeKeysRef.current = currentNormalizedTreeKeys;
            // Use requestAnimationFrame to defer state updates and avoid synchronous setState in effect
            requestAnimationFrame(() => {
                setExpandedKeys(currentNormalizedTreeKeys);
                setAutoExpandParent(false);
            });
        }
    }, [currentNormalizedTreeKeys]);

    const totalNodes = useMemo(() => countNodes(normalizedTree), [normalizedTree]);
    const maxDepth = useMemo(() => computeMaxDepth(normalizedTree), [normalizedTree]);

    const treeData = useMemo(() => {
        const query = search.trim().toLowerCase();
        const predicate = (node: NormalizedProcessTreeNode) => {
            if (!query) {
                return true;
            }
            const haystack = [
                node.comm,
                node.exec_id,
                node.pid != null ? `pid:${node.pid}` : null,
                node.ppid != null ? `ppid:${node.ppid}` : null,
                node.root_pid != null ? `root:${node.root_pid}` : null,
                node.args,
                node.cwd
            ]
                .filter(Boolean)
                .map((value) => String(value).toLowerCase())
                .join(" ");
            return haystack.includes(query);
        };
        return buildFilteredTreeData(normalizedTree, predicate);
    }, [normalizedTree, search]);

    const filteredKeys = useMemo(() => collectTreeDataKeys(treeData), [treeData]);
    const visibleCount = filteredKeys.length;
    const previousFilteredKeysRef = useRef<string[]>([]);
    const previousSearchRef = useRef<string>("");

    // Update expanded keys when search filter changes
    useEffect(() => {
        const hasFilters = Boolean(search.trim());
        const targetKeys = hasFilters ? filteredKeys : currentNormalizedTreeKeys;
        const previousTargetKeys = hasFilters ? previousFilteredKeysRef.current : previousNormalizedTreeKeysRef.current;
        
        const keysChanged = !arraysHaveSameMembers(previousTargetKeys, targetKeys);
        const searchChanged = previousSearchRef.current !== search;
        
        if (keysChanged || searchChanged) {
            previousFilteredKeysRef.current = filteredKeys;
            previousSearchRef.current = search;
            
            // Use requestAnimationFrame to defer state updates and avoid synchronous setState in effect
            requestAnimationFrame(() => {
                if (keysChanged) {
                    setExpandedKeys(targetKeys);
                }
                setAutoExpandParent(hasFilters);
            });
        }
    }, [filteredKeys, currentNormalizedTreeKeys, search]);

    const handleSelect = useCallback<NonNullable<TreeProps<TreeDataNode>["onSelect"]>>(
        (keys, info) => {
            if (!onSelectRoot) {
                return;
            }
            const key = String(info.node.key);
            const root = findRootForKey(normalizedTree, key);
            if (root) {
                onSelectRoot(root);
            }
        },
        [normalizedTree, onSelectRoot]
    );

    const handleExpandAll = useCallback(() => {
        setExpandedKeys(collectExpandedKeys(normalizedTree));
        setAutoExpandParent(false);
    }, [normalizedTree]);

    const handleCollapseAll = useCallback(() => {
        setExpandedKeys(normalizedTree.map((node) => node.key));
        setAutoExpandParent(false);
    }, [normalizedTree]);

    const summaryItems = useMemo(
        () =>
            [
                { label: "Roots", value: normalizedTree.length, color: "geekblue" },
                { label: "Processes", value: totalNodes, color: "green" },
                { label: "Max depth", value: Number.isFinite(maxDepth) ? maxDepth : 0, color: "volcano" },
                { label: "Visible", value: visibleCount, color: "purple" }
            ],
        [maxDepth, normalizedTree.length, totalNodes, visibleCount]
    );

    const summaryTagStyle = useMemo(
        () => ({
            borderRadius: 999,
            padding: "4px 16px",
            fontWeight: 600,
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            border: "none",
            boxShadow: "inset 0 0 0 1px rgba(15,23,42,0.08)"
        }),
        []
    );

    const summaryLabelStyle = useMemo(
        () => ({
            textTransform: "uppercase" as const,
            fontSize: 11,
            letterSpacing: 0.6,
            opacity: 0.75
        }),
        []
    );

    const summaryValueStyle = useMemo(
        () => ({
            fontSize: 16,
            fontVariantNumeric: "tabular-nums" as const,
            color: "#0f172a"
        }),
        []
    );

    const cardBodyStyle = useMemo(
        () => ({
            paddingTop: showControls ? 16 : 8
        }),
        [showControls]
    );

    return (
        <Card
            title={<span style={{ fontWeight: 600, fontSize: 16 }}>{title}</span>}
            extra={
                onRefresh ? (
                    <Button icon={<ReloadOutlined />} size="small" onClick={() => onRefresh()} disabled={fetching}>
                        Refresh
                    </Button>
                ) : null
            }
            style={{
                borderRadius: 18,
                border: "1px solid #e2e8f0",
                boxShadow: "0 30px 80px -48px rgba(15, 23, 42, 0.55)",
                background: "#ffffff"
            }}
            headStyle={{
                borderBottom: "1px solid rgba(15,23,42,0.06)",
                padding: "16px 24px",
                background: "linear-gradient(135deg, rgba(248,250,252,1) 0%, rgba(255,255,255,1) 100%)"
            }}
            bodyStyle={cardBodyStyle}
        >
            {loading ? (
                <Skeleton active paragraph={{ rows: 4 }} />
            ) : normalizedTree.length === 0 ? (
                <Empty description="No process data" />
            ) : (
                <Flex vertical gap={16} style={{ width: "100%" }}>
                    {showControls && (
                        <>
                            <Flex wrap gap={8} align="center">
                                {summaryItems.map((item) => (
                                    <Tag key={item.label} color={item.color} style={summaryTagStyle}>
                                        <span style={summaryLabelStyle}>{item.label}</span>
                                        <span style={summaryValueStyle}>{item.value}</span>
                                    </Tag>
                                ))}
                            </Flex>
                            <Flex wrap gap={12} align="center">
                                <Input
                                    allowClear
                                    style={{ minWidth: 220, maxWidth: 280 }}
                                    placeholder="Search command, exec, PID"
                                    prefix={<SearchOutlined />}
                                    value={search}
                                    onChange={(event) => setSearch(event.target.value)}
                                />
                                <Space>
                                    <Button icon={<PlusSquareOutlined />} size="small" onClick={handleExpandAll}>
                                        Expand all
                                    </Button>
                                    <Button icon={<MinusSquareOutlined />} size="small" onClick={handleCollapseAll}>
                                        Collapse roots
                                    </Button>
                                </Space>
                            </Flex>
                        </>
                    )}
                    <div style={{ maxHeight: height, overflow: "auto", paddingRight: 8 }}>
                        <Tree<TreeDataNode>
                            treeData={treeData}
                            expandedKeys={expandedKeys}
                            autoExpandParent={autoExpandParent}
                            onExpand={(keys) => {
                                setExpandedKeys(keys as string[]);
                                setAutoExpandParent(false);
                            }}
                            onSelect={handleSelect}
                        />
                    </div>
                </Flex>
            )}
        </Card>
    );
}
