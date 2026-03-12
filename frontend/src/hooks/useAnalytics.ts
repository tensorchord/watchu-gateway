import { useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";
import { Dayjs } from "dayjs";

import type { AgentRunResponse, TraceGraphResponse } from "../types/api";

import {
    fetchCorrelationSummaries,
    fetchHeuristicAlerts,
    fetchHosts,
    fetchProcessEvents,
    fetchProcessHttpEvents,
    fetchProcessSummary,
    fetchProcessTree,
    fetchSecurityLLMAnalysis,
    fetchAgentRuns,
    fetchTraceGraph,
    fetchDataSourceSummary,
    fetchDataSourceByRoot,
    fetchS3Buckets,
    fetchS3Events,
    fetchS3Operations,
    fetchPostgresQueries,
    fetchPostgresEvents,
    ProcessTreeParams
} from "../api/analytics";
import type {
    DataSourceByRootResponse,
    DataSourceSummaryResponse,
    PostgresEventResponse,
    PostgresQueryTopResponse,
    S3EventResponse
} from "../api/analytics";

export function useSecurityAnalysis(host: string, semanticLimit: number, promptLimit: number) {
    return useQuery({
        queryKey: ["security", host, semanticLimit, promptLimit],
        queryFn: () => fetchSecurityLLMAnalysis(host, semanticLimit, promptLimit),
        enabled: Boolean(host)
    });
}

export function useProcessHttpEvents(
    host: string,
    since: Dayjs,
    until: Dayjs,
    limit: number,
    options?: {
        rootExecId?: string;
        urlExcludeContains?: string[];
        httpType?: "request" | "response";
        before?: Dayjs | string;
    }
) {
    return useQuery({
        queryKey: [
            "http-events",
            host,
            since.toISOString(),
            until.toISOString(),
            limit,
            options?.rootExecId ?? "",
            (options?.urlExcludeContains ?? []).join(','),
            options?.httpType ?? '',
            options?.before == null
                ? ''
                : typeof options.before === 'string'
                    ? options.before
                    : options.before.toISOString()
        ],
        queryFn: () => fetchProcessHttpEvents(host, since, until, limit, options),
        enabled: Boolean(host)
    });
}

export function useHeuristicAlerts(host: string, since: Dayjs, until: Dayjs, limit: number) {
    return useQuery({
        queryKey: ["heuristic-alerts", host, since.toISOString(), until.toISOString(), limit],
        queryFn: () => fetchHeuristicAlerts(host, since, until, limit),
        enabled: Boolean(host)
    });
}

export function useProcessEvents(
    host: string,
    since: Dayjs,
    until: Dayjs,
    limit: number,
    options?: { rootExecId?: string; argsExcludeContains?: string[] }
) {
    return useQuery({
        queryKey: [
            "process-events",
            host,
            since.toISOString(),
            until.toISOString(),
            limit,
            options?.rootExecId ?? "",
            (options?.argsExcludeContains ?? []).join(',')
        ],
        queryFn: () => fetchProcessEvents(host, since, until, limit, options),
        enabled: Boolean(host)
    });
}

export function useProcessTree(params: ProcessTreeParams) {
    return useQuery({
        queryKey: [
            "process-tree",
            params.host,
            params.rootPid,
            params.rootExecId,
            params.rootLimit,
            params.nodeLimit,
            params.since ? params.since.toISOString() : null,
            params.until ? params.until.toISOString() : null
        ],
        queryFn: () => fetchProcessTree(params),
        enabled: Boolean(params.host)
    });
}

export function useProcessSummary(host: string, rootPid?: number) {
    return useQuery({
        queryKey: ["process-summary", host, rootPid],
        queryFn: () => {
            if (typeof rootPid !== "number") {
                throw new Error("rootPid is required to fetch process summary");
            }
            return fetchProcessSummary(host, rootPid);
        },
        enabled: Boolean(host) && typeof rootPid === "number"
    });
}

export function useCorrelationSummaries(host: string, since: Dayjs, until: Dayjs, limit: number) {
    return useQuery({
        queryKey: ["correlations", host, since.toISOString(), until.toISOString(), limit],
        queryFn: () => fetchCorrelationSummaries(host, since, until, limit),
        enabled: Boolean(host)
    });
}

export function useHosts(limit = 200) {
    return useQuery({
        queryKey: ["hosts", limit],
        queryFn: () => fetchHosts(limit)
    });
}

export function useAgentRuns(host: string, since: Dayjs, until: Dayjs, limit: number): UseQueryResult<AgentRunResponse[]> {
    return useQuery<AgentRunResponse[]>({
        queryKey: ["agent-runs", host, since.toISOString(), until.toISOString(), limit],
        queryFn: () => fetchAgentRuns(host, since, until, limit),
        enabled: Boolean(host)
    });
}

export function useTraceGraph(host: string, agentRunId?: string): UseQueryResult<TraceGraphResponse> {
    return useQuery<TraceGraphResponse>({
        queryKey: ["trace-graph", host, agentRunId],
        queryFn: () => {
            if (!agentRunId) {
                throw new Error("agentRunId is required");
            }
            return fetchTraceGraph(host, agentRunId);
        },
        enabled: Boolean(host) && Boolean(agentRunId)
    });
}

export function useDataSourceSummary(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string | null) {
    return useQuery<DataSourceSummaryResponse>({
        queryKey: ["data-sources-summary", host, since.toISOString(), until.toISOString(), limit, rootExecId ?? ""],
        queryFn: () => fetchDataSourceSummary(host, since, until, limit, rootExecId ?? undefined),
        enabled: Boolean(host)
    });
}

export function useDataSourceByRoot(host: string, since: Dayjs, until: Dayjs, limit: number) {
    return useQuery<DataSourceByRootResponse[]>({
        queryKey: ["data-sources-by-root", host, since.toISOString(), until.toISOString(), limit],
        queryFn: () => fetchDataSourceByRoot(host, since, until, limit),
        enabled: Boolean(host)
    });
}

export function useS3Buckets(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string | null) {
    return useQuery<Array<{ bucket: string; hits: number }>>({
        queryKey: ["s3-buckets", host, since.toISOString(), until.toISOString(), limit, rootExecId ?? ""],
        queryFn: () => fetchS3Buckets(host, since, until, limit, rootExecId ?? undefined),
        enabled: Boolean(host)
    });
}

export function useS3Events(host: string, since: Dayjs, until: Dayjs, limit: number, params?: { rootExecId?: string | null; bucket?: string | null; operation?: string | null }) {
    return useQuery<S3EventResponse[]>({
        queryKey: ["s3-events", host, since.toISOString(), until.toISOString(), limit, params?.rootExecId ?? "", params?.bucket ?? "", params?.operation ?? ""],
        queryFn: () => fetchS3Events(host, since, until, limit, { rootExecId: params?.rootExecId ?? undefined, bucket: params?.bucket ?? undefined, operation: params?.operation ?? undefined }),
        enabled: Boolean(host)
    });
}

export function useS3Operations(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string | null) {
    return useQuery<Array<{ operation?: string; hits: number }>>({
        queryKey: ["s3-operations", host, since.toISOString(), until.toISOString(), limit, rootExecId ?? ""],
        queryFn: () => fetchS3Operations(host, since, until, limit, rootExecId ?? undefined),
        enabled: Boolean(host)
    });
}

export function usePostgresQueries(host: string, since: Dayjs, until: Dayjs, limit: number, rootExecId?: string | null) {
    return useQuery<PostgresQueryTopResponse[]>({
        queryKey: ["pg-queries", host, since.toISOString(), until.toISOString(), limit, rootExecId ?? ""],
        queryFn: () => fetchPostgresQueries(host, since, until, limit, rootExecId ?? undefined),
        enabled: Boolean(host)
    });
}

export function usePostgresEvents(
    host: string,
    since: Dayjs,
    until: Dayjs,
    limit: number,
    params?: { rootExecId?: string | null; msgType?: string | null; sqlHash?: string | null }
) {
    return useQuery<PostgresEventResponse[]>({
        queryKey: [
            "pg-events",
            host,
            since.toISOString(),
            until.toISOString(),
            limit,
            params?.rootExecId ?? "",
            params?.msgType ?? "",
            params?.sqlHash ?? ""
        ],
        queryFn: () =>
            fetchPostgresEvents(host, since, until, limit, {
                rootExecId: params?.rootExecId ?? undefined,
                msgType: params?.msgType ?? undefined,
                sqlHash: params?.sqlHash ?? undefined
            }),
        enabled: Boolean(host)
    });
}
