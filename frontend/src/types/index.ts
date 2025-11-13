export * from "./api";

export interface ProcessTreeNode {
    rootExecId: string | null;
    rootPid: string | null;
    parentExecId: string | null;
    parentPid: string | null;
    execId: string | null;
    pid: string | null;
    command: string | null;
    startTime: string | null;
    endTime: string | null;
    depth: number | null;
    alertsCount: number | null;
}

