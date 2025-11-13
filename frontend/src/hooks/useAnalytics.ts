import { useQuery } from "@tanstack/react-query";
import { Dayjs } from "dayjs";

import {
    fetchCorrelationSummaries,
    fetchHeuristicAlerts,
    fetchHosts,
    fetchProcessEvents,
    fetchProcessHttpEvents,
    fetchProcessSummary,
    fetchProcessTree,
    fetchSecurityLLMAnalysis,
    ProcessTreeParams
} from "../api/analytics";

export function useSecurityAnalysis(host: string, semanticLimit: number, promptLimit: number) {
    return useQuery({
        queryKey: ["security", host, semanticLimit, promptLimit],
        queryFn: () => fetchSecurityLLMAnalysis(host, semanticLimit, promptLimit),
        enabled: Boolean(host)
    });
}

export function useProcessHttpEvents(host: string, since: Dayjs, until: Dayjs, limit: number) {
    return useQuery({
        queryKey: ["http-events", host, since.toISOString(), until.toISOString(), limit],
        queryFn: () => fetchProcessHttpEvents(host, since, until, limit),
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

export function useProcessEvents(host: string, since: Dayjs, until: Dayjs, limit: number) {
    return useQuery({
        queryKey: ["process-events", host, since.toISOString(), until.toISOString(), limit],
        queryFn: () => fetchProcessEvents(host, since, until, limit),
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
