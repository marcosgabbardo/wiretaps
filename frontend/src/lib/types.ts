export interface Agent {
  id: string;
  name: string;
  created_at: string;
}

export interface Session {
  id: string;
  agent_id: string;
  started_at: string;
  ended_at: string | null;
  pid: number | null;
  metadata: Record<string, unknown> | null;
}

export type EventType = "llm_call" | "shell_cmd" | "http_request";

export interface WiretapEvent {
  id: number;
  session_id: string;
  type: EventType;
  timestamp: string;
  duration_ms: number | null;
  data: Record<string, unknown>;
  pii_types: string[];
  status: number | null;
  error: string | null;
}

export interface Stats {
  total_events: number;
  total_tokens: number;
  events_with_pii: number;
  pii_percentage: number;
  errors: number;
  by_type: Record<string, number>;
}

export interface StatsByDay {
  day: string;
  events: number;
  pii_detections: number;
  llm_calls: number;
  shell_cmds: number;
  http_requests: number;
}

export interface StatsByType {
  type: string;
  count: number;
  avg_duration_ms: number;
  pii_detections: number;
  errors: number;
}
