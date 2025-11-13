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
export type PromptInjectionRecord = PkgHttpapiPromptInjectionRecord;
export type SecurityLLMAnalysisResponse = PkgHttpapiSecurityLLMAnalysisResponse;
export type HTTPRequestDetailResponse = PkgHttpapiHTTPRequestDetailResponse;
export type ProcessEventResponse = PkgHttpapiProcessEventResponse;
export type ProcessTreeNodeResponse = PkgHttpapiProcessTreeNodeResponse;
export type ProcessSummaryMeta = PkgHttpapiProcessSummaryMeta;
export type ProcessSummaryResponse = PkgHttpapiProcessSummaryResponse;
