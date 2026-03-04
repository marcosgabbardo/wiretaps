"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { Agent, Session, WiretapEvent } from "@/lib/types";

interface SessionSummary {
  llm_call: number;
  shell_cmd: number;
  http_request: number;
  pii: boolean;
}

function formatDuration(start: string, end: string | null): string {
  if (!end) return "running...";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString();
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [agents, setAgents] = useState<Record<string, Agent>>({});
  const [summaries, setSummaries] = useState<Record<string, SessionSummary>>(
    {}
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [sess, ags, evts] = await Promise.all([
          api.sessions(200),
          api.agents(),
          api.events({ limit: 1000 }),
        ]);

        setSessions(sess);

        const agMap: Record<string, Agent> = {};
        for (const a of ags) agMap[a.id] = a;
        setAgents(agMap);

        const sm: Record<string, SessionSummary> = {};
        for (const e of evts) {
          if (!sm[e.session_id])
            sm[e.session_id] = {
              llm_call: 0,
              shell_cmd: 0,
              http_request: 0,
              pii: false,
            };
          sm[e.session_id][e.type]++;
          if (e.pii_types?.length) sm[e.session_id].pii = true;
        }
        setSummaries(sm);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading)
    return (
      <div className="flex items-center justify-center h-64 text-neutral-500">
        Loading sessions...
      </div>
    );
  if (error)
    return (
      <div className="flex items-center justify-center h-64 text-red-400">
        {error}
      </div>
    );

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Sessions</h1>

      {sessions.length === 0 ? (
        <div className="text-neutral-500 text-center py-20">
          No sessions yet. Start an agent with{" "}
          <code className="text-accent">wiretaps run</code> to see data here.
        </div>
      ) : (
        <div className="space-y-2">
          {sessions.map((s) => {
            const agent = agents[s.agent_id];
            const sm = summaries[s.id];
            return (
              <Link
                key={s.id}
                href={`/sessions/${s.id}`}
                className="block bg-card border border-border rounded-lg p-4 hover:border-accent/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-semibold text-white">
                      {agent?.name ?? "unknown agent"}
                    </span>
                    {sm?.pii && (
                      <span className="px-2 py-0.5 text-xs rounded-full bg-red-500/20 text-red-400 font-medium">
                        PII
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-neutral-500 font-mono">
                    {s.id.slice(0, 8)}
                  </span>
                </div>

                <div className="flex items-center gap-4 mt-2 text-xs text-neutral-400">
                  <span>{formatTime(s.started_at)}</span>
                  <span className="text-neutral-600">|</span>
                  <span>{formatDuration(s.started_at, s.ended_at)}</span>
                </div>

                {sm && (
                  <div className="flex items-center gap-3 mt-2">
                    {sm.llm_call > 0 && (
                      <span className="text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-400">
                        🤖 {sm.llm_call} LLM
                      </span>
                    )}
                    {sm.shell_cmd > 0 && (
                      <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400">
                        💻 {sm.shell_cmd} shell
                      </span>
                    )}
                    {sm.http_request > 0 && (
                      <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400">
                        🌐 {sm.http_request} HTTP
                      </span>
                    )}
                  </div>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
