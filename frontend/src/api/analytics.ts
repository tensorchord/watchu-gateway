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
    TraceGraphResponse,
    ThreatAnalysisResponse,
    SkillSecurityRunCreateRequest,
    SkillSecurityRunResponse
} from "../types/api";

function toQueryTimestamp(value: Dayjs): string {
    return value.toISOString();
}

export interface DataSourceCount {
    source: string;
    hits: number;
}

export interface DataSourceSummaryResponse {
    sources: DataSourceCount[];
    s3: {
        buckets_top: Array<{ bucket: string; hits: number }>;
        status_codes: Array<{ status_code?: number; hits: number }>;
        operations: Array<{ operation?: string; hits: number }>;
    };
    postgres: {
        queries_top: Array<{ sql_hash: string; sample?: string; hits: number }>;
    };
}

export interface DataSourceByRootResponse {
    root_exec_id?: string;
    root_pid?: number;
    source: string;
    hits: number;
}

export interface S3EventResponse {
    host: string;
    response_id?: string;
    request_id?: string;
    timestamp?: string;
    pid?: number;
    tid?: number;
    comm?: string;
    method?: string;
    url?: string;
    status_code?: number;
    bucket?: string;
    bucket_region?: string;
    object_key?: string;
    request_bytes?: number;
    response_bytes?: number;
    container_id?: string;
    exec_id?: string;
    root_exec_id?: string;
    root_pid?: number;
    depth?: number;
    operation?: string;
}

export interface PostgresQueryTopResponse {
    sql_hash: string;
    sample?: string;
    hits: number;
}

export interface PostgresEventResponse {
    host: string;
    pg_event_id?: string;
    timestamp?: string;
    pid?: number;
    tid?: number;
    uid?: number;
    gid?: number;
    comm?: string;
    msg_type?: string;
    container_id?: string;
    exec_id?: string;
    root_exec_id?: string;
    root_pid?: number;
    depth?: number;
    sql_text?: string;
    sql_hash?: string;
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

export async function fetchDataSourceSummary(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string) {
    const { data } = await apiClient.get<DataSourceSummaryResponse>("/analysis/data_sources/summary", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit,
            root_exec_id: rootExecId
        }
    });
    return data;
}

export async function fetchDataSourceByRoot(host: string, since: Dayjs, until: Dayjs, limit: number) {
    const { data } = await apiClient.get<DataSourceByRootResponse[]>("/analysis/data_sources/by_root", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit
        }
    });
    return data;
}

export async function fetchS3Buckets(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string) {
    const { data } = await apiClient.get<Array<{ bucket: string; hits: number }>>("/analysis/data_sources/s3/buckets", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit,
            root_exec_id: rootExecId
        }
    });
    return data;
}

export async function fetchS3Events(host: string, since: Dayjs, until: Dayjs, limit: number, params?: { rootExecId?: string; bucket?: string; operation?: string }) {
    const { data } = await apiClient.get<S3EventResponse[]>("/analysis/data_sources/s3/events", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit,
            root_exec_id: params?.rootExecId,
            bucket: params?.bucket,
            operation: params?.operation
        }
    });
    return data;
}

export async function fetchS3Operations(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string) {
    const { data } = await apiClient.get<Array<{ operation?: string; hits: number }>>("/analysis/data_sources/s3/operations", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit,
            root_exec_id: rootExecId
        }
    });
    return data;
}

export async function fetchPostgresQueries(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string) {
    const { data } = await apiClient.get<PostgresQueryTopResponse[]>("/analysis/data_sources/postgres/queries", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit,
            root_exec_id: rootExecId
        }
    });
    return data;
}

export async function fetchPostgresEvents(
    host: string,
    since: Dayjs,
    until: Dayjs,
    limit: number,
    params?: { rootExecId?: string; msgType?: string; sqlHash?: string }
) {
    const { data } = await apiClient.get<PostgresEventResponse[]>("/analysis/data_sources/postgres/events", {
        params: {
            host,
            since: toQueryTimestamp(since),
            until: toQueryTimestamp(until),
            limit,
            root_exec_id: params?.rootExecId,
            msg_type: params?.msgType,
            sql_hash: params?.sqlHash
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

export async function analyzeThreat(rootExecId: string): Promise<ThreatAnalysisResponse> {
    const { data } = await apiClient.post<ThreatAnalysisResponse>("/security-insight/analyze-threat", {
        root_exec_id: rootExecId
    });
    return data;
}

export async function fetchThreatAnalysis(rootExecId: string): Promise<ThreatAnalysisResponse> {
    const { data } = await apiClient.get<ThreatAnalysisResponse>(`/security-insight/analyze-threat/${encodeURIComponent(rootExecId)}`);
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

export async function createSkillSecurityRun(payload: SkillSecurityRunCreateRequest) {
    const { data } = await apiClient.post<SkillSecurityRunResponse>("/skill-security/runs", payload);
    return data;
}

export async function fetchSkillSecurityRuns(params?: { status?: string; sourceType?: string; limit?: number; offset?: number }) {
    const { data } = await apiClient.get<SkillSecurityRunResponse[]>("/skill-security/runs", {
        params: {
            status: params?.status,
            source_type: params?.sourceType,
            limit: params?.limit,
            offset: params?.offset
        }
    });
    return data;
}

export async function fetchSkillSecurityRun(id: string) {
    const { data } = await apiClient.get<SkillSecurityRunResponse>(`/skill-security/runs/${encodeURIComponent(id)}`);
    return data;
}
