"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Stats, StatsByDay, StatsByType } from "@/lib/types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const typeColors: Record<string, string> = {
  llm_call: "#a855f7",
  shell_cmd: "#3b82f6",
  http_request: "#06b6d4",
};

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: boolean;
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-5">
      <div className="text-xs text-neutral-500 uppercase tracking-wider mb-1">
        {label}
      </div>
      <div
        className={`text-2xl font-bold ${accent ? "text-red-400" : "text-white"}`}
      >
        {value}
      </div>
    </div>
  );
}

export default function StatsPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [byDay, setByDay] = useState<StatsByDay[]>([]);
  const [byType, setByType] = useState<StatsByType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState(0);

  useEffect(() => {
    async function load() {
      try {
        const [s, d, t, sess] = await Promise.all([
          api.stats(),
          api.statsByDay(),
          api.statsByType(),
          api.sessions(1000),
        ]);
        setStats(s);
        setByDay(d);
        setByType(t);
        setSessions(sess.length);
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
        Loading stats...
      </div>
    );
  if (error)
    return (
      <div className="flex items-center justify-center h-64 text-red-400">
        {error}
      </div>
    );
  if (!stats) return null;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Sessions" value={sessions} />
        <StatCard label="Total Events" value={stats.total_events} />
        <StatCard
          label="Total Tokens"
          value={stats.total_tokens.toLocaleString()}
        />
        <StatCard
          label="PII Alerts"
          value={stats.events_with_pii}
          accent={stats.events_with_pii > 0}
        />
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Events by day chart */}
        <div className="bg-card border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-neutral-400 mb-4">
            Events by Day
          </h2>
          {byDay.length === 0 ? (
            <div className="text-neutral-600 text-center py-10 text-sm">
              No data yet
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={byDay}>
                <XAxis
                  dataKey="day"
                  tick={{ fill: "#666", fontSize: 11 }}
                  axisLine={{ stroke: "#222" }}
                  tickLine={false}
                  tickFormatter={(v: string) => v.slice(5)}
                />
                <YAxis
                  tick={{ fill: "#666", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#111",
                    border: "1px solid #222",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "#999" }}
                />
                <Bar dataKey="events" fill="#22c55e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Events by type */}
        <div className="bg-card border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-neutral-400 mb-4">
            Events by Type
          </h2>
          {byType.length === 0 ? (
            <div className="text-neutral-600 text-center py-10 text-sm">
              No data yet
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={byType} layout="vertical">
                  <XAxis
                    type="number"
                    tick={{ fill: "#666", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    type="category"
                    dataKey="type"
                    tick={{ fill: "#999", fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                    width={100}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#111",
                      border: "1px solid #222",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {byType.map((entry) => (
                      <Cell
                        key={entry.type}
                        fill={typeColors[entry.type] || "#22c55e"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>

              <div className="mt-4 space-y-2">
                {byType.map((t) => (
                  <div
                    key={t.type}
                    className="flex items-center justify-between text-sm"
                  >
                    <div className="flex items-center gap-2">
                      <div
                        className="w-2.5 h-2.5 rounded-full"
                        style={{
                          backgroundColor: typeColors[t.type] || "#22c55e",
                        }}
                      />
                      <span className="text-neutral-300">{t.type}</span>
                    </div>
                    <div className="flex items-center gap-4 text-neutral-500 text-xs">
                      <span>{t.count} events</span>
                      <span>
                        avg {Math.round(t.avg_duration_ms)}ms
                      </span>
                      {t.pii_detections > 0 && (
                        <span className="text-red-400">
                          {t.pii_detections} PII
                        </span>
                      )}
                      {t.errors > 0 && (
                        <span className="text-red-400">
                          {t.errors} errors
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
