import { useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

// Lisible à distance : il est filmé dans le Clip Chrono et projeté pendant la démo.

const STATUS_STYLE = {
  ok: { bg: "bg-emerald-600", label: "SERVICE OPÉRATIONNEL", icon: "●" },
  remediating: { bg: "bg-amber-500", label: "INCIDENT — REMÉDIATION AUTOMATIQUE", icon: "⚙" },
  down: { bg: "bg-red-600", label: "SERVICE DÉGRADÉ", icon: "▲" },
  maintenance: { bg: "bg-slate-600", label: "MAINTENANCE PLANIFIÉE — remédiation suspendue", icon: "⏸" },
};

const STEP_STYLE = {
  DETECTED: "text-amber-300",
  REMEDIATING: "text-sky-300",
  VERIFYING: "text-violet-300",
  RESOLVED: "text-emerald-300",
  ESCALATED: "text-red-400",
};

const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString("fr-FR");

async function promQuery(q) {
  const r = await fetch(`/prom/query?query=${encodeURIComponent(q)}`);
  const j = await r.json();
  const v = j?.data?.result?.[0]?.value?.[1];
  return v === undefined ? null : parseFloat(v);
}

async function promRange(q, minutes = 5) {
  const end = Date.now() / 1000;
  const r = await fetch(
    `/prom/query_range?query=${encodeURIComponent(q)}&start=${end - minutes * 60}&end=${end}&step=5`,
  );
  const j = await r.json();
  return (j?.data?.result?.[0]?.values || []).map(([t, v]) => ({ t: t * 1000, v: parseFloat(v) }));
}

function usePolling(fn, ms, deps = []) {
  const [data, setData] = useState(null);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        const d = await fn();
        if (alive) setData(d);
      } catch {
        /* service momentanément indisponible : on garde la dernière valeur */
      }
    };
    run();
    const id = setInterval(run, ms);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return data;
}

function useIncidents() {
  const [incidents, setIncidents] = useState([]);
  useEffect(() => {
    let es;
    const load = () => fetch("/engine/incidents?limit=8").then((r) => r.json()).then(setIncidents).catch(() => {});
    load();
    const connect = () => {
      es = new EventSource("/engine/incidents/stream");
      es.addEventListener("incident", load);
      es.addEventListener("action", load);
      es.onerror = () => {
        es.close();
        setTimeout(connect, 2000);
      };
    };
    connect();
    const id = setInterval(load, 5000);
    return () => {
      es?.close();
      clearInterval(id);
    };
  }, []);
  return incidents;
}

function Kpi({ label, value, sub, tone = "text-white" }) {
  return (
    <div className="rounded-2xl bg-slate-900 p-5 ring-1 ring-slate-800">
      <p className="text-sm uppercase tracking-wide text-slate-400">{label}</p>
      <p className={`mt-2 text-5xl font-bold tabular-nums ${tone}`}>{value}</p>
      {sub && <p className="mt-1 text-sm text-slate-400">{sub}</p>}
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 250);
    return () => clearInterval(id);
  }, []);
  return <span className="font-mono tabular-nums">{now.toLocaleTimeString("fr-FR")}</span>;
}

function Timeline({ incidents }) {
  if (!incidents.length) return <p className="text-xl text-slate-500">Aucun incident enregistré.</p>;
  return (
    <div className="space-y-4">
      {incidents.slice(0, 3).map((inc) => {
        const ev = inc.events?.[0] || {};
        return (
          <div key={inc.id} className="rounded-xl bg-slate-900 p-4 ring-1 ring-slate-800">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="text-xl font-semibold">
                <span className={STEP_STYLE[inc.status]}>{inc.status}</span>
                <span className="ml-3 font-mono">{inc.type}</span>
                <span className="ml-3 text-base text-slate-400">source : {inc.source}</span>
              </p>
              {inc.rto_s != null && (
                <p className="text-2xl font-bold text-emerald-300">RTO {inc.rto_s.toFixed(1)} s</p>
              )}
            </div>
            <ul className="mt-3 space-y-1 font-mono text-base">
              <li className="text-amber-300">
                {fmtTime(inc.detected_at)} ⚠ DÉTECTÉ
                {ev.anomaly_score != null && ` — score ML ${ev.anomaly_score.toFixed(2)}`}
                {ev.suspects?.src_ip && ` — source ${ev.suspects.src_ip}`}
                {ev.detail && ` — ${ev.detail}`}
              </li>
              {inc.actions.map((a) => (
                <li
                  key={a.id}
                  className={a.result === "ok" ? "text-sky-300" : a.result === "skipped" ? "text-slate-400" : "text-red-400"}
                >
                  {fmtTime(a.at)} {a.result === "ok" ? "⚙" : a.result === "skipped" ? "↷" : "✖"} {a.action} — {a.detail}
                </li>
              ))}
              {inc.proof && (
                <li className="text-emerald-300">
                  {fmtTime(inc.proof.ts)} ✔ VÉRIFIÉ — transaction témoin {inc.proof.transaction_id.slice(0, 8)}… OK (
                  {inc.proof.latency_ms} ms)
                </li>
              )}
              {inc.status === "ESCALATED" && <li className="text-red-400">✖ {inc.summary}</li>}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

function Chart({ title, data, color, threshold, unit = "", domain = [0, "auto"] }) {
  return (
    <div className="rounded-2xl bg-slate-900 p-4 ring-1 ring-slate-800">
      <p className="mb-2 text-sm uppercase tracking-wide text-slate-400">{title}</p>
      <ResponsiveContainer width="100%" height={150}>
        <AreaChart data={data || []}>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} hide />
          <YAxis width={40} stroke="#64748b" fontSize={12} domain={domain} allowDataOverflow />
          <Tooltip
            labelFormatter={(t) => new Date(t).toLocaleTimeString("fr-FR")}
            formatter={(v) => [`${v.toFixed(2)}${unit}`, title]}
            contentStyle={{ background: "#0f172a", border: "1px solid #334155" }}
          />
          {threshold != null && <ReferenceLine y={threshold} stroke="#f59e0b" strokeDasharray="6 4" />}
          <Area dataKey="v" stroke={color} fill={color} fillOpacity={0.2} strokeWidth={2} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function Assistant({ incidents }) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState(null);
  const [busy, setBusy] = useState(false);

  async function call(path, body) {
    setBusy(true);
    setAnswer(null);
    try {
      const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!r.ok) throw new Error(r.status === 502 || r.status === 504 ? "assistant indisponible (profil rag non démarré ?)" : `erreur ${r.status}`);
      const d = await r.json();
      setAnswer({ text: d.answer || d.draft, sources: d.sources });
    } catch (e) {
      setAnswer({ text: `⚠ ${e.message}`, sources: [] });
    } finally {
      setBusy(false);
    }
  }

  const last = incidents.find((i) => i.status === "RESOLVED" || i.status === "ESCALATED");
  return (
    <section className="mt-6 rounded-2xl bg-slate-900 p-5 ring-1 ring-slate-800">
      <h2 className="text-xl font-semibold text-slate-300">Assistant (RAG local — aucun pouvoir d'action)</h2>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          call("/rag/ask", { question });
        }}
      >
        <input
          className="flex-1 rounded-lg bg-slate-800 px-3 py-2 text-slate-100 outline-none ring-1 ring-slate-700 focus:ring-indigo-500"
          placeholder="Ex. : que s'est-il passé lors du dernier incident ?"
          value={question}
          minLength={3}
          maxLength={500}
          onChange={(e) => setQuestion(e.target.value)}
        />
        <button className="rounded-lg bg-indigo-600 px-4 py-2 font-semibold disabled:opacity-50" disabled={busy}>
          Demander
        </button>
        {last && (
          <button
            type="button"
            className="rounded-lg bg-slate-700 px-4 py-2 font-semibold disabled:opacity-50"
            disabled={busy}
            onClick={() => call(`/rag/report/${last.id}`)}
          >
            Brouillon de notification ({last.id})
          </button>
        )}
      </form>
      {busy && <p className="mt-3 text-slate-400">Génération en cours…</p>}
      {answer && (
        <div className="mt-3 whitespace-pre-wrap rounded-lg bg-slate-950 p-4 text-slate-200">
          {answer.text}
          {answer.sources?.length > 0 && <p className="mt-2 text-sm text-slate-500">Sources : {answer.sources.join(", ")}</p>}
        </div>
      )}
    </section>
  );
}

export default function App() {
  const incidents = useIncidents();
  const probe = usePolling(() => fetch("/probe/last").then((r) => r.json()), 2000);
  const ml = usePolling(() => fetch("/ml/status").then((r) => r.json()), 5000);
  const status = usePolling(() => fetch("/engine/status").then((r) => r.json()), 3000);
  const kpis = usePolling(
    async () => ({
      tpm: await promQuery('sum(rate(payments_total{status="completed"}[1m])) * 60'),
      success: await promQuery("avg_over_time(probe_success[5m]) * 100"),
      score: await promQuery("ml_anomaly_score"),
      lastRto: await promQuery("remediation_last_rto_seconds"),
    }),
    3000,
  );
  const charts = usePolling(
    async () => ({
      tpm: await promRange('sum(rate(payments_total{status="completed"}[30s])) * 60'),
      errors: await promRange('sum(rate(http_requests_total{status=~"4..|5.."}[30s])) or vector(0)'),
      score: await promRange("ml_anomaly_score"),
    }),
    5000,
  );

  const open = incidents.find((i) => ["DETECTED", "REMEDIATING", "VERIFYING"].includes(i.status));
  const state = status?.paused_until
    ? "maintenance"
    : open
      ? "remediating"
      : probe && probe.ok === false
        ? "down"
        : "ok";
  const st = STATUS_STYLE[state];
  const probeAge = probe?.ts ? Math.max(0, Math.round(Date.now() / 1000 - probe.ts)) : null;

  return (
    <div className="min-h-screen p-6">
      <header className={`flex items-center justify-between rounded-2xl px-8 py-5 ${st.bg} transition-colors`}>
        <h1 className="text-3xl font-black tracking-tight">RESILIENCE-ALPHA</h1>
        <p className="text-3xl font-bold">
          {st.icon} {st.label}
        </p>
        <p className="text-3xl">
          <Clock />
        </p>
      </header>

      <section className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi label="Transactions / min" value={kpis?.tpm != null ? Math.round(kpis.tpm) : "—"} />
        <Kpi
          label="Succès sonde (5 min)"
          value={kpis?.success != null ? `${kpis.success.toFixed(1)} %` : "—"}
          tone={kpis?.success < 95 ? "text-amber-300" : "text-emerald-300"}
        />
        <Kpi
          label="Score anomalie ML"
          value={kpis?.score != null ? kpis.score.toFixed(2) : "—"}
          tone={kpis?.score >= 0.6 ? "text-red-400" : "text-white"}
          sub={
            ml?.state === "baseline"
              ? `apprentissage de la référence : ${Math.round((ml.baseline_progress || 0) * 100)} %`
              : `seuil d'alerte 0,60 — modèle ${ml?.model_version || "?"}`
          }
        />
        <Kpi
          label="Dernière transaction témoin"
          value={probe ? (probe.ok ? "✔ OK" : "✖ ÉCHEC") : "—"}
          tone={probe?.ok ? "text-emerald-300" : "text-red-400"}
          sub={probe?.ok ? `il y a ${probeAge} s — ${probe.latency_ms} ms` : probe?.error}
        />
      </section>

      <section className="mt-6 grid gap-4 lg:grid-cols-3">
        <Chart title="Transactions / min" data={charts?.tpm} color="#34d399" />
        <Chart title="Erreurs HTTP / s" data={charts?.errors} color="#f87171" />
        <Chart title="Score anomalie ML" data={charts?.score} color="#a78bfa" threshold={0.6} domain={[0, 1]} />
      </section>

      <section className="mt-6 grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <h2 className="mb-3 text-xl font-semibold text-slate-300">Timeline des incidents</h2>
          <Timeline incidents={incidents} />
        </div>
        <div>
          <h2 className="mb-3 text-xl font-semibold text-slate-300">Conteneurs</h2>
          <div className="grid grid-cols-2 gap-2">
            {(status?.containers || [])
              .filter((c) => c.service)
              .sort((a, b) => a.service.localeCompare(b.service))
              .map((c) => {
                const bad = c.state !== "running" || c.health === "unhealthy";
                return (
                  <div
                    key={c.id}
                    className={`rounded-lg px-3 py-2 text-sm ring-1 ${bad ? "bg-red-950 ring-red-700" : "bg-slate-900 ring-slate-800"}`}
                  >
                    <span className={bad ? "text-red-400" : c.health === "healthy" ? "text-emerald-400" : "text-slate-400"}>●</span>{" "}
                    {c.service}
                  </div>
                );
              })}
          </div>
          <p className="mt-4 text-sm text-slate-400">
            Blocages actifs au WAF : <span className="font-bold text-white">{status?.active_blocks ?? "—"}</span>
            {kpis?.lastRto != null && (
              <>
                {" "}— dernier RTO : <span className="font-bold text-emerald-300">{kpis.lastRto.toFixed(1)} s</span>
              </>
            )}
          </p>
        </div>
      </section>

      <Assistant incidents={incidents} />
    </div>
  );
}
