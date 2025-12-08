/* eslint-disable */
/* tslint:disable */
// @ts-nocheck
/*
 * ---------------------------------------------------------------
 * ## THIS FILE WAS GENERATED VIA SWAGGER-TYPESCRIPT-API        ##
 * ##                                                           ##
 * ## AUTHOR: acacode                                           ##
 * ## SOURCE: https://github.com/acacode/swagger-typescript-api ##
 * ---------------------------------------------------------------
 */

export interface GithubComTensorchordWatchuGatewayPkgIngestExecEvent {
  args: string;
  comm: string;
  cwd: string;
  exec_id: string;
  host: string;
  p_exec_id: string;
  pid: number;
  ppid: number;
  timestamp: string;
}

export interface GithubComTensorchordWatchuGatewayPkgIngestHTTPRequestEvent {
  body?: number[];
  comm: string;
  content_length?: number;
  gid: number;
  headers?: number[];
  host: string;
  method: string;
  pid: number;
  protocol: string;
  tid: number;
  timestamp: string;
  truncated?: boolean;
  uid: number;
  url: string;
}

export interface GithubComTensorchordWatchuGatewayPkgIngestHTTPResponseEvent {
  body?: number[];
  comm: string;
  content_length?: number;
  gid: number;
  headers?: number[];
  host: string;
  pid: number;
  protocol: string;
  status_code: number;
  tid: number;
  timestamp: string;
  truncated?: boolean;
  uid: number;
}

export interface PkgHttpapiCorrelationSummaryResponse {
  best_argument_match_flag?: number;
  best_argument_score?: number;
  best_correlation_type?: string;
  best_event_args?: string;
  best_event_comm?: string;
  best_event_exec_id?: string;
  best_event_id?: string;
  best_gap_ms?: number;
  best_lineage_score?: number;
  best_temporal_score?: number;
  best_total_score?: number;
  event_root_exec_id?: string;
  event_root_pid?: number;
  evidence?: number[];
  host?: string;
  method?: string;
  response_id?: string;
  response_ts?: string;
  root_exec_id?: string;
  root_pid?: number;
  status_code?: number;
  system_actions?: number[];
  url?: string;
}

export interface PkgHttpapiErrorResponse {
  error?: string;
}

export interface PkgHttpapiExecEventBatch {
  events?: GithubComTensorchordWatchuGatewayPkgIngestExecEvent[];
}

export interface PkgHttpapiHTTPRequestBatch {
  events?: GithubComTensorchordWatchuGatewayPkgIngestHTTPRequestEvent[];
}

export interface PkgHttpapiHTTPRequestDetailResponse {
  body?: number[];
  comm?: string;
  content_length?: number;
  gid?: number;
  headers?: number[];
  host?: string;
  id?: string;
  method?: string;
  pid?: number;
  protocol?: string;
  tid?: number;
  timestamp?: string;
  truncated?: boolean;
  uid?: number;
  url?: string;
}

export interface PkgHttpapiHTTPResponseBatch {
  events?: GithubComTensorchordWatchuGatewayPkgIngestHTTPResponseEvent[];
}

export interface PkgHttpapiHealthResponse {
  status?: string;
}

export interface PkgHttpapiHeuristicAlertResponse {
  alert_id?: string;
  alert_type?: string;
  details?: number[];
  end_ts?: string;
  host?: string;
  root_exec_id?: string;
  root_pid?: number;
  score?: number;
  severity?: string;
  start_ts?: string;
  reason?: string;
}

export interface PkgHttpapiProcessEventResponse {
  args?: string;
  comm?: string;
  cwd?: string;
  depth?: number;
  end_ts?: string;
  exec_id?: string;
  host?: string;
  parent_exec_id?: string;
  pid?: number;
  ppid?: number;
  root_exec_id?: string;
  root_pid?: number;
  start_ts?: string;
}

export interface PkgHttpapiProcessHTTPEventResponse {
  body?: number[];
  depth?: number;
  exec_id?: string;
  headers?: number[];
  host?: string;
  http_id?: string;
  http_type?: string;
  is_mcp_http?: boolean;
  method?: string;
  pid?: number;
  protocol?: string;
  root_exec_id?: string;
  root_pid?: number;
  status_code?: number;
  tid?: number;
  timestamp?: string;
  truncated?: boolean;
  url?: string;
}

export interface PkgHttpapiProcessSummaryMeta {
  args?: string;
  comm?: string;
  event_count?: number;
  exec_id?: string;
  first_seen?: string;
  last_seen?: string;
}

export interface PkgHttpapiProcessSummaryResponse {
  alerts?: PkgHttpapiHeuristicAlertResponse[];
  meta?: PkgHttpapiProcessSummaryMeta;
}

export interface PkgHttpapiProcessTreeNodeResponse {
  args?: string;
  children?: PkgHttpapiProcessTreeNodeResponse[];
  comm?: string;
  cwd?: string;
  depth?: number;
  end_ts?: string;
  exec_id?: string;
  parent_exec_id?: string;
  pid?: number;
  ppid?: number;
  root_exec_id?: string;
  root_pid?: number;
  start_ts?: string;
}

export interface PkgHttpapiPromptInjectionRecord {
  categories?: string[];
  observed_at?: string;
  request_id?: string;
  severity?: string;
}

export interface PkgHttpapiSecurityLLMAnalysisResponse {
  prompt_injections?: PkgHttpapiPromptInjectionRecord[];
  semantic?: PkgHttpapiSecuritySemanticRecord[];
}

export interface PkgHttpapiSecuritySemanticRecord {
  analyzed_at?: string;
  confidence?: number;
  details?: string;
  evidence?: number[];
  id?: string;
  recommendations?: number[];
  root_exec_id?: string;
  summary?: string;
  threat_level?: number;
  threat_type?: string;
}
