import { Dayjs } from "dayjs";

import { apiClient } from "./client";
import {
    CorrelationSummaryResponse,
    HTTPRequestDetailResponse,
    HeuristicAlertResponse,
    ProcessEventResponse,
    ProcessHTTPEventResponse,
    ProcessSummaryResponse,
    ProcessTreeNodeResponse,
    SecurityLLMAnalysisResponse,
    AgentRunResponse,
    TraceGraphResponse
} from "../types/api";

function toQueryTimestamp(value: Dayjs): string {
    return value.toISOString();
}

export async function fetchSecurityLLMAnalysis(host: string, semanticLimit: number, promptLimit: number) {
    const { data } = await apiClient.get<SecurityLLMAnalysisResponse>("/analysis/security_llm_analysis", {
        params: {
            host,
            semantic_limit: semanticLimit,
            prompt_limit: promptLimit
        }
    });
    return data;
}

export async function fetchProcessHttpEvents(host: string, since: Dayjs, until: Dayjs, limit: number) {
    const { data } = await apiClient.get<ProcessHTTPEventResponse[]>("/analysis/process_http_events", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit
        }
    });
    return data;
}

function ensureHeuristicAlertsArray(data: unknown): HeuristicAlertResponse[] {
    if (Array.isArray(data)) {
        return data as HeuristicAlertResponse[];
    }
    if (data && typeof data === "object") {
        const candidate = data as {
            alerts?: unknown;
            data?: unknown;
            items?: unknown;
        };
        if (Array.isArray(candidate.alerts)) {
            return candidate.alerts as HeuristicAlertResponse[];
        }
        if (Array.isArray(candidate.data)) {
            return candidate.data as HeuristicAlertResponse[];
        }
        if (Array.isArray(candidate.items)) {
            return candidate.items as HeuristicAlertResponse[];
        }
    }
    return [];
}

export async function fetchHeuristicAlerts(host: string, since: Dayjs, until: Dayjs, limit: number) {
    const { data } = await apiClient.get<
        HeuristicAlertResponse[] | { alerts?: HeuristicAlertResponse[]; data?: HeuristicAlertResponse[]; items?: HeuristicAlertResponse[] }
    >("/analysis/heuristic_alerts", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit
        }
    });
    return ensureHeuristicAlertsArray(data);
}

export async function fetchProcessEvents(host: string, since: Dayjs, until: Dayjs, limit: number) {
    const { data } = await apiClient.get<ProcessEventResponse[]>("/analysis/process_events", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit
        }
    });
    return data;
}

export interface ProcessTreeParams {
    host: string;
    rootPid?: number;
    rootExecId?: string;
    rootLimit?: number;
    nodeLimit?: number;
    since?: Dayjs;
    until?: Dayjs;
}

function ensureProcessTreeArray(data: unknown): ProcessTreeNodeResponse[] {
    if (Array.isArray(data)) {
        return data as ProcessTreeNodeResponse[];
    }
    if (data && typeof data === "object") {
        const candidate = data as {
            roots?: unknown;
            nodes?: unknown;
            tree?: unknown;
        };
        if (Array.isArray(candidate.roots)) {
            return candidate.roots as ProcessTreeNodeResponse[];
        }
        if (Array.isArray(candidate.tree)) {
            return candidate.tree as ProcessTreeNodeResponse[];
        }
        if (Array.isArray(candidate.nodes)) {
            return candidate.nodes as ProcessTreeNodeResponse[];
        }
    }
    return [];
}

export async function fetchProcessTree(params: ProcessTreeParams) {
    const { host, rootPid, rootExecId, rootLimit = 50, nodeLimit = 500, since, until } = params;
    const requestParams: Record<string, unknown> = {
        host,
        root_limit: rootLimit,
        node_limit: nodeLimit
    };
    if (typeof rootPid === "number") {
        requestParams.root_pid = rootPid;
    }
    if (rootExecId) {
        requestParams.root_exec_id = rootExecId;
    }
    if (since) {
        requestParams.since = toQueryTimestamp(since);
    }
    if (until) {
        requestParams.until = toQueryTimestamp(until);
    }

    const response = await apiClient.get<ProcessTreeNodeResponse[] | { roots?: ProcessTreeNodeResponse[]; nodes?: ProcessTreeNodeResponse[]; tree?: ProcessTreeNodeResponse[] }>("/analysis/process_tree", {
        params: requestParams
    });
    return ensureProcessTreeArray(response.data);
}

export async function fetchProcessSummary(host: string, rootPid: number) {
    const response = await apiClient.get<ProcessSummaryResponse>(`/analysis/process_summary/${rootPid}`, {
        params: { host }
    });
    return response.data;
}

export async function fetchCorrelationSummaries(host: string, since: Dayjs, until: Dayjs, limit: number) {
    const response = await apiClient.get<CorrelationSummaryResponse[]>("/analysis/correlation_summaries", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit
        }
    });
    return response.data;
}

export async function fetchPromptInjectionDetails(host: string, requestId: string): Promise<HTTPRequestDetailResponse> {
    const { data } = await apiClient.get<HTTPRequestDetailResponse>(`/analysis/prompt_injections/${requestId}`, {
        params: { host }
    });
    return data;
}

function ensureStringArray(data: unknown): string[] {
    if (!Array.isArray(data)) {
        return [];
    }
    return data
        .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
        .filter((entry): entry is string => entry.length > 0);
}

export async function fetchHosts(limit = 200) {
    const { data } = await apiClient.get<string[]>("/analysis/hosts", {
        params: { limit }
    });
    return ensureStringArray(data);
}

export async function fetchAgentRuns(host: string, since: Dayjs, until: Dayjs, limit: number) {
    const { data } = await apiClient.get<AgentRunResponse[]>("/analysis/agent_runs", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit
        }
    });
    return data;
}

export async function fetchTraceGraph(host: string, agentRunId: string) {
    const { data } = await apiClient.get<TraceGraphResponse>(`/analysis/agent_runs/${agentRunId}/traces`, {
        params: { host }
    });
    return data;
}
