import type { Agent, Session, WiretapEvent, Stats, StatsByDay, StatsByType } from "./types";

const BASE =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8899")
    : (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8899");

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json();
}

export const api = {
  agents: () => get<Agent[]>("/agents"),
  sessions: (limit = 100, offset = 0) =>
    get<Session[]>(`/sessions?limit=${limit}&offset=${offset}`),
  session: (id: string) => get<Session>(`/sessions/${id}`),
  sessionEvents: async (id: string, limit = 1000) => {
    const res = await fetch(`${BASE}/sessions/${id}/events?limit=${limit}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`API ${res.status}: /sessions/${id}/events?limit=${limit}`);
    const data = await res.json();
    return (Array.isArray(data) ? data : data.events ?? []) as WiretapEvent[];
  },
  events: async (params?: {
    type?: string;
    session_id?: string;
    pii_only?: boolean;
    limit?: number;
  }) => {
    const q = new URLSearchParams();
    if (params?.type) q.set("type", params.type);
    if (params?.session_id) q.set("session_id", params.session_id);
    if (params?.pii_only) q.set("pii_only", "true");
    if (params?.limit) q.set("limit", String(params.limit));
    const res = await fetch(`${BASE}/events?${q}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`API ${res.status}: /events?${q}`);
    const data = await res.json();
    // API returns {events: [], count, offset, limit} or plain array
    return (Array.isArray(data) ? data : data.events ?? []) as WiretapEvent[];
  },
  stats: () => get<Stats>("/stats"),
  statsByDay: () => get<StatsByDay[]>("/stats/by-day"),
  statsByType: () => get<StatsByType[]>("/stats/by-type"),
};
