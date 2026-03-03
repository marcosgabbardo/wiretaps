"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import type { Session, WiretapEvent, EventType } from "@/lib/types";

const typeIcon: Record<EventType, string> = {
  llm_call: "🤖",
  shell_cmd: "💻",
  http_request: "🌐",
};

const typeColor: Record<EventType, string> = {
  llm_call: "text-purple-400",
  shell_cmd: "text-blue-400",
  http_request: "text-cyan-400",
};

function formatTs(iso: string): string {
  return new Date(iso).toLocaleTimeString();
}

function eventSummary(e: WiretapEvent): string {
  const d = e.data as Record<string, unknown>;
  switch (e.type) {
    case "llm_call":
      return (d.model as string) || (d.endpoint as string) || "LLM call";
    case "shell_cmd":
      return (d.command as string) || (d.cmd as string) || "shell command";
    case "http_request": {
      const method = (d.method as string) || "GET";
      const url = (d.url as string) || (d.endpoint as string) || "";
      return `${method} ${url}`;
    }
    default:
      return e.type;
  }
}

function ShellDetail({ data }: { data: Record<string, unknown> }) {
  const command = data.command as string | undefined;
  const stdout = data.stdout as string | undefined;
  const stderr = data.stderr as string | undefined;
  const exitCode = data.exit_code as number | undefined;

  return (
    <div className="space-y-3">
      {command && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">Command</div>
          <pre className="bg-black/50 rounded p-3 text-sm text-green-400 overflow-x-auto">
            {command}
          </pre>
        </div>
      )}
      {stdout && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">stdout</div>
          <pre className="bg-black/50 rounded p-3 text-sm text-neutral-300 overflow-x-auto max-h-64 overflow-y-auto">
            {stdout}
          </pre>
        </div>
      )}
      {stderr && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">stderr</div>
          <pre className="bg-black/50 rounded p-3 text-sm text-red-400 overflow-x-auto max-h-64 overflow-y-auto">
            {stderr}
          </pre>
        </div>
      )}
      {exitCode !== undefined && (
        <div className="text-xs text-neutral-400">
          Exit code:{" "}
          <span className={exitCode === 0 ? "text-accent" : "text-red-400"}>
            {exitCode}
          </span>
        </div>
      )}
    </div>
  );
}

function formatBody(v: unknown): string {
  if (typeof v === "string") return v;
  return JSON.stringify(v, null, 2);
}

function LlmDetail({ data }: { data: Record<string, unknown> }) {
  const model = data.model as string | undefined;
  const reqBody = data.request_body;
  const resBody = data.response_body;

  return (
    <div className="space-y-3">
      {model && (
        <div className="text-sm">
          <span className="text-neutral-500">Model:</span>{" "}
          <span className="text-white">{model}</span>
        </div>
      )}
      {reqBody != null && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">Request</div>
          <pre className="bg-black/50 rounded p-3 text-xs text-neutral-300 overflow-x-auto max-h-64 overflow-y-auto">
            {formatBody(reqBody)}
          </pre>
        </div>
      )}
      {resBody != null && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">Response</div>
          <pre className="bg-black/50 rounded p-3 text-xs text-neutral-300 overflow-x-auto max-h-64 overflow-y-auto">
            {formatBody(resBody)}
          </pre>
        </div>
      )}
    </div>
  );
}

function HttpDetail({ data }: { data: Record<string, unknown> }) {
  const method = (data.method as string) || "GET";
  const url = (data.url as string) || "";
  const statusCode = data.status_code as number | undefined;
  const reqBody = data.request_body;
  const resBody = data.response_body;

  return (
    <div className="space-y-3">
      {(method || url) && (
        <div className="text-sm">
          <span className="text-cyan-400 font-mono">{method}</span>{" "}
          <span className="text-neutral-300">{url}</span>
        </div>
      )}
      {statusCode != null && (
        <div className="text-sm">
          <span className="text-neutral-500">Status:</span>{" "}
          <span className={statusCode < 400 ? "text-accent" : "text-red-400"}>
            {statusCode}
          </span>
        </div>
      )}
      {reqBody != null && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">Request Body</div>
          <pre className="bg-black/50 rounded p-3 text-xs text-neutral-300 overflow-x-auto max-h-48 overflow-y-auto">
            {formatBody(reqBody)}
          </pre>
        </div>
      )}
      {resBody != null && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">Response Body</div>
          <pre className="bg-black/50 rounded p-3 text-xs text-neutral-300 overflow-x-auto max-h-48 overflow-y-auto">
            {formatBody(resBody)}
          </pre>
        </div>
      )}
    </div>
  );
}

function EventDetail({ event }: { event: WiretapEvent }) {
  const data = event.data as Record<string, unknown>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">
          {typeIcon[event.type]} Event #{event.id}
        </h3>
        {event.pii_types?.length > 0 && (
          <span className="px-2 py-0.5 text-xs rounded-full bg-red-500/20 text-red-400">
            PII: {event.pii_types.join(", ")}
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>
          <span className="text-neutral-500">Type</span>
          <div className={typeColor[event.type]}>{event.type}</div>
        </div>
        <div>
          <span className="text-neutral-500">Time</span>
          <div>{new Date(event.timestamp).toLocaleString()}</div>
        </div>
        <div>
          <span className="text-neutral-500">Duration</span>
          <div>{event.duration_ms != null ? `${event.duration_ms}ms` : "—"}</div>
        </div>
        <div>
          <span className="text-neutral-500">Status</span>
          <div
            className={
              event.status != null && event.status >= 400
                ? "text-red-400"
                : "text-accent"
            }
          >
            {event.status ?? "—"}
          </div>
        </div>
      </div>

      {event.error && (
        <div>
          <div className="text-xs text-neutral-500 mb-1">Error</div>
          <pre className="bg-red-500/10 border border-red-500/20 rounded p-3 text-sm text-red-400 overflow-x-auto">
            {event.error}
          </pre>
        </div>
      )}

      <div className="border-t border-border pt-4">
        {event.type === "shell_cmd" && <ShellDetail data={data} />}
        {event.type === "llm_call" && <LlmDetail data={data} />}
        {event.type === "http_request" && <HttpDetail data={data} />}
      </div>

      <details className="border-t border-border pt-4">
        <summary className="text-xs text-neutral-500 cursor-pointer hover:text-neutral-300">
          Raw JSON
        </summary>
        <pre className="mt-2 bg-black/50 rounded p-3 text-xs text-neutral-400 overflow-x-auto max-h-96 overflow-y-auto">
          {JSON.stringify(event, null, 2)}
        </pre>
      </details>
    </div>
  );
}

export default function SessionTimelinePage() {
  const params = useParams();
  const id = params.id as string;
  const [session, setSession] = useState<Session | null>(null);
  const [events, setEvents] = useState<WiretapEvent[]>([]);
  const [selected, setSelected] = useState<WiretapEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [sess, evts] = await Promise.all([
          api.session(id),
          api.sessionEvents(id),
        ]);
        setSession(sess);
        setEvents(evts);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  if (loading)
    return (
      <div className="flex items-center justify-center h-64 text-neutral-500">
        Loading timeline...
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
      <div className="flex items-center gap-3 mb-6">
        <Link
          href="/sessions"
          className="text-neutral-500 hover:text-white transition-colors"
        >
          ← Sessions
        </Link>
        <span className="text-neutral-600">/</span>
        <h1 className="text-xl font-bold">
          Session{" "}
          <span className="text-accent font-mono text-base">
            {id.slice(0, 8)}
          </span>
        </h1>
      </div>

      {session && (
        <div className="bg-card border border-border rounded-lg p-4 mb-6 flex items-center gap-6 text-sm text-neutral-400">
          <div>
            <span className="text-neutral-500">Started:</span>{" "}
            {new Date(session.started_at).toLocaleString()}
          </div>
          {session.ended_at && (
            <div>
              <span className="text-neutral-500">Ended:</span>{" "}
              {new Date(session.ended_at).toLocaleString()}
            </div>
          )}
          {session.pid && (
            <div>
              <span className="text-neutral-500">PID:</span> {session.pid}
            </div>
          )}
          <div>
            <span className="text-neutral-500">Events:</span> {events.length}
          </div>
        </div>
      )}

      <div className="flex gap-6">
        {/* Timeline */}
        <div className={`space-y-1 ${selected ? "w-1/2" : "w-full"} transition-all`}>
          {events.length === 0 ? (
            <div className="text-neutral-500 text-center py-10">
              No events in this session.
            </div>
          ) : (
            events.map((e) => (
              <button
                key={e.id}
                onClick={() => setSelected(selected?.id === e.id ? null : e)}
                className={`w-full text-left bg-card border rounded-lg p-3 transition-colors ${
                  selected?.id === e.id
                    ? "border-accent/50 bg-accent/5"
                    : "border-border hover:border-neutral-600"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span>{typeIcon[e.type]}</span>
                    <span className={`text-sm font-medium ${typeColor[e.type]}`}>
                      {e.type}
                    </span>
                    <span className="text-sm text-neutral-300 truncate max-w-md">
                      {eventSummary(e)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {e.pii_types?.length > 0 && (
                      <span className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/20 text-red-400">
                        PII
                      </span>
                    )}
                    {e.duration_ms != null && (
                      <span className="text-xs text-neutral-500 font-mono">
                        {e.duration_ms}ms
                      </span>
                    )}
                    {e.status != null && (
                      <span
                        className={`text-xs font-mono ${
                          e.status >= 400 ? "text-red-400" : "text-accent"
                        }`}
                      >
                        {e.status}
                      </span>
                    )}
                  </div>
                </div>
                <div className="text-[11px] text-neutral-600 mt-1">
                  {formatTs(e.timestamp)}
                </div>
              </button>
            ))
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-1/2 sticky top-8 self-start">
            <div className="bg-card border border-border rounded-lg p-5 max-h-[calc(100vh-8rem)] overflow-y-auto">
              <div className="flex justify-end mb-2">
                <button
                  onClick={() => setSelected(null)}
                  className="text-neutral-500 hover:text-white text-sm"
                >
                  ✕ Close
                </button>
              </div>
              <EventDetail event={selected} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
