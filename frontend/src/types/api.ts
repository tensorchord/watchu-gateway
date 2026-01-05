import type {
    PkgHttpapiCorrelationSummaryResponse,
    PkgHttpapiHeuristicAlertResponse,
    PkgHttpapiProcessEventResponse,
    PkgHttpapiProcessHTTPEventResponse,
    PkgHttpapiProcessSummaryMeta,
    PkgHttpapiProcessSummaryResponse,
    PkgHttpapiProcessTreeNodeResponse,
    PkgHttpapiPromptInjectionRecord,
    PkgHttpapiHTTPRequestDetailResponse,
    PkgHttpapiSecurityLLMAnalysisResponse,
    PkgHttpapiSecuritySemanticRecord
} from "./api.generated";

export type CorrelationSummaryResponse = PkgHttpapiCorrelationSummaryResponse;
export type HeuristicAlertResponse = PkgHttpapiHeuristicAlertResponse;
export type ProcessHTTPEventResponse = PkgHttpapiProcessHTTPEventResponse;
export type SecuritySemanticRecord = PkgHttpapiSecuritySemanticRecord;
export type PromptInjectionRecord = PkgHttpapiPromptInjectionRecord & {
    reason?: string | null;
    evidence?: unknown;
};
export type SecurityLLMAnalysisResponse = Omit<PkgHttpapiSecurityLLMAnalysisResponse, "prompt_injections"> & {
    prompt_injections?: PromptInjectionRecord[];
};
export type HTTPRequestDetailResponse = PkgHttpapiHTTPRequestDetailResponse;
export type ProcessEventResponse = PkgHttpapiProcessEventResponse;
export type ProcessTreeNodeResponse = PkgHttpapiProcessTreeNodeResponse;
export type ProcessSummaryMeta = PkgHttpapiProcessSummaryMeta;
export type ProcessSummaryResponse = PkgHttpapiProcessSummaryResponse;

export interface AgentRunResponse {
    id: string;
    host: string;
    root_exec_id?: string | null;
    root_pid?: number | null;
    provider?: string | null;
    started_at?: string | null;
    ended_at?: string | null;
}

export interface ResourceUsageEntry {
    value?: number | null;
    unit?: string | null;
}

export interface LLMTraceDetails {
    response_key: string;
    provider?: string | null;
    model?: string | null;
    model_version?: string | null;
    prompt?: unknown;
    response?: unknown;
    usage?: unknown;
    status?: string | null;
    raw_request?: string | null;
    raw_response?: string | null;
    exec_id?: string | null;
    root_exec_id?: string | null;
}

export interface ToolTraceDetails {
    tool_call_id: string;
    response_key: string;
    name?: string | null;
    arguments?: unknown;
}

export interface MCPMessage {
    message_type: string;
    timestamp?: string | null;
    server?: string | null;
    params?: unknown;
    result?: unknown;
    error?: unknown;
}

export interface MCPTraceDetails {
    corr_id: string;
    method?: string | null;
    server?: string | null;
    tool?: string | null;
    entries: MCPMessage[];
}

export interface TraceNodeResponse {
    id: string;
    agent_run_id: string;
    parent_trace_id?: string | null;
    trace_type: string;
    phase: string;
    source_table?: string | null;
    source_id?: string | null;
    external_id?: string | null;
    model?: string | null;
    model_version?: string | null;
    started_at?: string | null;
    ended_at?: string | null;
    prompt_preview?: string | null;
    response_preview?: string | null;
    resource_usage?: Record<string, ResourceUsageEntry | null> | null;
    llm?: LLMTraceDetails | null;
    tool?: ToolTraceDetails | null;
    mcp?: MCPTraceDetails | null;
}

export interface TraceGraphResponse {
    agent_run: AgentRunResponse;
    traces: TraceNodeResponse[];
}

export interface ThreatAnalysisRequest {
    root_exec_id: string;
}

export interface ThreatAnalysisResponse {
    root_exec_id: string;
    threat_level: number;
    threat_type: string;
    confidence: number;
    summary: string;
    details: string;
    recommendations: string[];
    evidence: Record<string, unknown>[];
}

export interface SkillSecurityRunCreateRequest {
    source_type: string;
    source_ref: string;
    runner_mode: string;
    agent_type?: string | null;
    prompt_strategy?: string | null;
    prompt_input?: string | null;
    resolved_ref?: string | null;
    artifact_path?: string | null;
}

export interface SkillSecurityRunResponse {
    id: string;
    created_at?: string | null;
    updated_at?: string | null;
    source_type: string;
    source_ref: string;
    resolved_ref?: string | null;
    artifact_path?: string | null;
    agent_type: string;
    runner_mode: string;
    prompt_strategy: string;
    prompt_input?: string | null;
    status: string;
    error?: string | null;
    root_exec_id?: string | null;
    agent_run_id?: string | null;
}

export interface SkillSecurityUploadResponse {
    artifact_path: string;
    source_ref: string;
    size_bytes: number;
}
