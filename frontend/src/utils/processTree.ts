import type { ProcessTreeNode } from "../types";

interface RawProcessTreeNode {
    root_exec_id?: string | null;
    root_pid?: string | number | null;
    parent_exec_id?: string | null;
    parent_pid?: string | number | null;
    exec_id?: string | null;
    pid?: string | number | null;
    command?: string | null;
    start_time?: string | null;
    created_at?: string | null;
    ended_at?: string | null;
    depth?: number | null;
    alerts_count?: number | null;
}

export function buildProcessTree(rawNodes: RawProcessTreeNode[]): ProcessTreeNode[] {
    const nodes: ProcessTreeNode[] = rawNodes.map((node) => ({
        rootExecId: node.root_exec_id ?? null,
        rootPid: normalizePid(node.root_pid),
        parentExecId: node.parent_exec_id ?? null,
        parentPid: normalizePid(node.parent_pid),
        execId: node.exec_id ?? null,
        pid: normalizePid(node.pid),
        command: node.command ?? null,
        startTime: node.start_time ?? node.created_at ?? null,
        endTime: node.ended_at ?? null,
        depth: typeof node.depth === "number" ? node.depth : null,
        alertsCount: typeof node.alerts_count === "number" ? node.alerts_count : null
    }));

    return nodes;
}

function normalizePid(value: string | number | null | undefined): string | null {
    if (value == null) {
        return null;
    }
    if (typeof value === "number") {
        return Number.isFinite(value) ? String(value) : null;
    }
    if (typeof value === "string") {
        const trimmed = value.trim();
        if (!trimmed) {
            return null;
        }
        return trimmed;
    }
    return null;
}
