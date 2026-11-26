import React, { useEffect, useMemo, useState } from "react";
import { runLabel } from "./labels.js";

// Inspect view (Stage 6.4, M8; a tab since Stage 7 #13). Plays back ONE exported bundle
// (tools/export_dashboard.py, contract §6.14). Read-only: every value shown comes from the
// bundle; nothing is computed or judged here. No network: bundles arrive via
// public/data/bundles.js (window.ARENA_BUNDLES) or a local file picked by the user.

const bundles = () => (typeof window !== "undefined" && window.ARENA_BUNDLES) || {};
const usd = (x) => `$${(x ?? 0).toFixed(6)}`;
const yesNo = (v) => (v === true ? "yes" : v === false ? "no" : "—");

function Badge({ tone = "slate", children }) {
  const tones = {
    slate: "bg-slate-700 text-slate-100",
    red: "bg-rose-700 text-rose-50",
    green: "bg-emerald-700 text-emerald-50",
    amber: "bg-amber-600 text-amber-50",
    blue: "bg-sky-700 text-sky-50",
    violet: "bg-violet-700 text-violet-50",
  };
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${tones[tone]}`}>
      {children}
    </span>
  );
}

function Field({ label, children }) {
  return (
    <div className="flex gap-2 text-sm">
      <span className="w-32 shrink-0 text-slate-400">{label}</span>
      <span className="min-w-0 break-words text-slate-100">{children}</span>
    </div>
  );
}

function Panel({ title, accent, children }) {
  return (
    <section className="flex min-w-0 flex-col gap-2 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className={`text-sm font-bold uppercase tracking-wider ${accent}`}>{title}</h2>
      {children}
    </section>
  );
}

function RedColumn({ step }) {
  const r = step.red;
  const q = step.request;
  return (
    <Panel title="Red — what was sent" accent="text-rose-400">
      {r.kind === "attack" ? (
        <>
          <div className="flex gap-2">
            <Badge tone="red">attack · round {r.round}</Badge>
            <Badge>{r.label}</Badge>
            <Badge>{r.source}</Badge>
          </div>
          {r.rationale && <p className="text-sm italic text-slate-300">“{r.rationale}”</p>}
        </>
      ) : r.kind === "benign" ? (
        <div className="flex gap-2">
          <Badge tone="green">benign · {r.benign_id}</Badge>
          <Badge>{r.category}</Badge>
        </div>
      ) : (
        <Badge>unknown traffic</Badge>
      )}
      <div className="mt-1 rounded bg-slate-950 p-2 font-mono text-xs text-slate-200">
        <div>
          <span className="text-sky-400">{q.method}</span> {q.path}
          {q.query ? <span className="text-amber-300">?{q.query}</span> : null}
        </div>
        {q.body ? <div className="mt-1 break-all text-slate-400">{q.body}</div> : null}
      </div>
      <Field label="HTTP status">{q.status ?? "—"}</Field>
    </Panel>
  );
}

function JudgeColumn({ step }) {
  const j = step.judge;
  return (
    <Panel title="Judge — facts (pure code)" accent="text-amber-300">
      {j.kind === "attack" ? (
        <>
          <Field label="landed">
            {yesNo(j.landed)}
            {j.landed_reason ? ` (${j.landed_reason})` : ""}
          </Field>
          <Field label="newly solved">{j.newly_solved?.length ? j.newly_solved.join(", ") : "—"}</Field>
          <Field label="detected">
            {j.detected === true ? <Badge tone="green">detected</Badge> : <Badge tone="red">missed</Badge>}
            {j.detected_reason ? ` (${j.detected_reason})` : ""}
          </Field>
          <Field label="type correct">{yesNo(j.type_correct)}</Field>
        </>
      ) : j.kind === "benign" ? (
        <Field label="false positive">
          {j.false_positive === true ? (
            <Badge tone="red">false positive</Badge>
          ) : j.false_positive === false ? (
            <Badge tone="green">correctly benign</Badge>
          ) : (
            "—"
          )}
          {j.fp_reason ? ` (${j.fp_reason})` : ""}
        </Field>
      ) : (
        <span className="text-sm text-slate-400">no Judge record</span>
      )}
    </Panel>
  );
}

function BlueColumn({ step, rules }) {
  const b = step.blue;
  if (!b) {
    return (
      <Panel title="Blue — verdict" accent="text-sky-400">
        <span className="text-sm text-slate-400">no verdict</span>
      </Panel>
    );
  }
  const byId = Object.fromEntries(rules.map((r) => [r.rule_id, r]));
  return (
    <Panel title="Blue — verdict (log only)" accent="text-sky-400">
      <div className="flex flex-wrap gap-2">
        <Badge tone={b.verdict === "benign" ? "green" : "red"}>{b.verdict ?? "no verdict"}</Badge>
        <Badge tone={b.source === "rule" ? "violet" : "blue"}>source: {b.source ?? "—"}</Badge>
        {b.rule_origin && <Badge tone="amber">rule_origin: {b.rule_origin}</Badge>}
      </div>
      {b.fired_rule_ids?.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="text-xs text-slate-400">fired rules (first wins the tie-break)</span>
          {b.fired_rule_ids.map((id) => (
            <div key={id} className="rounded bg-slate-950 p-2 font-mono text-xs text-slate-200">
              <span className="text-violet-300">{id}</span>{" "}
              {byId[id]
                ? byId[id].conditions
                    .map((c) => `${c.field} ${c.op}${c.case_insensitive ? "/i" : ""} ${JSON.stringify(c.pattern)}`)
                    .join(" AND ")
                : ""}
            </div>
          ))}
        </div>
      )}
      {b.rationale && <p className="text-sm italic text-slate-300">“{b.rationale}”</p>}
      {b.no_verdict_reason && <Field label="no verdict">{b.no_verdict_reason}</Field>}
    </Panel>
  );
}

function CostStrip({ step, total }) {
  const c = step.cost_so_far;
  const t = c.tokens || {};
  const pct = total.usd > 0 ? Math.min(100, (100 * c.usd) / total.usd) : 0;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm text-slate-200">
        <span className="font-bold text-slate-100">Cost so far</span>
        <span>
          AI calls <b>{c.calls}</b> / {total.calls}
        </span>
        <span>
          tokens in {t.input ?? 0} · cached {t.cached_input ?? 0} · cache write {t.cache_write ?? 0} · out{" "}
          {t.output ?? 0}
        </span>
        <span>
          <b>{usd(c.usd)}</b> / {usd(total.usd)}
        </span>
      </div>
      <div className="mt-2 h-2 rounded bg-slate-800">
        <div className="h-2 rounded bg-emerald-500" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Timeline({ steps, index, onPick }) {
  return (
    <div className="flex flex-wrap gap-1">
      {steps.map((s, i) => {
        const attack = s.red.kind === "attack";
        const rule = s.blue?.source === "rule";
        const lib = s.blue?.rule_origin === "library";
        const base = attack ? "bg-rose-600" : "bg-emerald-700";
        return (
          <button
            key={s.request_id}
            title={`#${s.log_seq} ${attack ? `attack round ${s.red.round} ${s.red.label}` : `benign ${s.red.benign_id ?? ""}`} · ${s.blue?.source ?? "no verdict"}${s.blue?.rule_origin ? ` (${s.blue.rule_origin})` : ""}`}
            onClick={() => onPick(i)}
            className={`h-6 w-6 rounded text-[10px] font-bold text-white ${base} ${i === index ? "ring-2 ring-white" : "opacity-80"}`}
          >
            {lib ? "L" : rule ? "R" : ""}
          </button>
        );
      })}
    </div>
  );
}

// Optional deep link for demos: #bundle=<name>&step=<1-based line>
const fromHash = () => {
  const h = new URLSearchParams((typeof window !== "undefined" && window.location.hash.slice(1)) || "");
  return { bundle: h.get("bundle"), step: Number(h.get("step")) || 1 };
};

export default function Inspect() {
  const [loaded, setLoaded] = useState(bundles());
  const names = Object.keys(loaded).sort();
  const initial = fromHash();
  const [name, setName] = useState(names.includes(initial.bundle) ? initial.bundle : names[0] ?? null);
  const [index, setIndex] = useState(Math.max(0, initial.step - 1));
  const firstLoad = React.useRef(true);
  const [playing, setPlaying] = useState(false);
  const data = name ? loaded[name] : null;
  const steps = data?.steps ?? [];
  const step = steps[Math.min(index, Math.max(steps.length - 1, 0))];

  useEffect(() => {
    if (firstLoad.current) {
      firstLoad.current = false;
      return;
    }
    setIndex(0);
    setPlaying(false);
  }, [name]);

  useEffect(() => {
    if (!playing) return undefined;
    if (index >= steps.length - 1) {
      setPlaying(false);
      return undefined;
    }
    const t = setTimeout(() => setIndex((i) => i + 1), 900);
    return () => clearTimeout(t);
  }, [playing, index, steps.length]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "ArrowRight") setIndex((i) => Math.min(i + 1, steps.length - 1));
      if (e.key === "ArrowLeft") setIndex((i) => Math.max(i - 1, 0));
      if (e.key === " ") {
        e.preventDefault();
        setPlaying((p) => !p);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [steps.length]);

  const onFile = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const doc = JSON.parse(reader.result);
        if (doc.schema_version !== "0.1" || !Array.isArray(doc.steps)) throw new Error("not a bundle");
        setLoaded((l) => ({ ...l, [doc.name]: doc }));
        setName(doc.name);
      } catch (err) {
        alert(`Not a dashboard bundle: ${err.message}`);
      }
    };
    reader.readAsText(f);
  };

  const meta = data?.meta;
  const libraryLine = useMemo(() => {
    if (!meta?.library) return "no library";
    return `library v${meta.library.library_version} (${meta.library.entries} rules, read-only)`;
  }, [meta]);

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-4 p-4 text-slate-100">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold">Inspect — step through one bundle</h1>
          {data && (
            <p className="text-xs text-slate-400">
              {data.kind} <span className="font-mono">{data.run_id}</span>
              {data.kind === "replay" ? (
                <>
                  {" "}
                  of match <span className="font-mono">{data.match_id}</span>
                </>
              ) : null}{" "}
              · Red {meta.red_engine}
              {meta.models?.red ? ` (${meta.models.red.model})` : ""} · Blue {meta.blue_engine}
              {meta.models?.blue ? ` (${meta.models.blue.model})` : ""} · rules {meta.rules_mode ?? "—"} ·{" "}
              {libraryLine}
              {meta.purpose ? ` · purpose ${meta.purpose}` : ""} · Judge {meta.judge_version}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <select
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            value={name ?? ""}
            onChange={(e) => setName(e.target.value)}
          >
            {names.map((n) => (
              <option key={n} value={n}>
                {runLabel(n)}
              </option>
            ))}
          </select>
          <label className="cursor-pointer rounded border border-slate-700 px-2 py-1 text-sm hover:bg-slate-800">
            open bundle…
            <input type="file" accept=".json,application/json" className="hidden" onChange={onFile} />
          </label>
        </div>
      </header>

      {!data ? (
        <p className="text-slate-400">
          No bundle loaded. Export one with <code>tools/export_dashboard.py</code>, or open a bundle file.
        </p>
      ) : !step ? (
        <p className="text-slate-400">This bundle has no logged requests.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <button className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700" onClick={() => setIndex((i) => Math.max(i - 1, 0))}>
              ◀ prev
            </button>
            <button className="rounded bg-emerald-700 px-3 py-1 hover:bg-emerald-600" onClick={() => setPlaying((p) => !p)}>
              {playing ? "❚❚ pause" : "▶ play"}
            </button>
            <button
              className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700"
              onClick={() => setIndex((i) => Math.min(i + 1, steps.length - 1))}
            >
              next ▶
            </button>
            <span className="text-sm text-slate-300">
              line {index + 1} / {steps.length} · log_seq {step.log_seq}
            </span>
            <input
              type="range"
              min={0}
              max={steps.length - 1}
              value={index}
              onChange={(e) => setIndex(Number(e.target.value))}
              className="w-64"
            />
          </div>

          <CostStrip step={step} total={data.total_cost} />

          <main className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <RedColumn step={step} />
            <JudgeColumn step={step} />
            <BlueColumn step={step} rules={data.rules} />
          </main>

          <section className="flex flex-col gap-2 rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div className="flex flex-wrap gap-3 text-xs text-slate-400">
              <span>
                <span className="inline-block h-3 w-3 rounded bg-rose-600 align-middle" /> attack
              </span>
              <span>
                <span className="inline-block h-3 w-3 rounded bg-emerald-700 align-middle" /> benign
              </span>
              <span>L = answered by a library rule · R = answered by an in-match rule · blank = AI call</span>
            </div>
            <Timeline steps={steps} index={index} onPick={setIndex} />
          </section>

          <section className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm">
              <h3 className="mb-2 font-bold">Rules ({data.rules.length})</h3>
              <div className="flex max-h-64 flex-col gap-1 overflow-auto font-mono text-xs">
                {data.rules.map((r) => (
                  <div key={r.rule_id}>
                    <span className={r.origin === "library" ? "text-amber-300" : "text-violet-300"}>{r.rule_id}</span>{" "}
                    {r.cwe} ·{" "}
                    {r.origin === "library"
                      ? `library (from train match ${r.created_match ?? "?"})`
                      : `in-match, created at log_seq ${r.created_at_log_seq ?? "?"}`}
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 text-sm">
              <h3 className="mb-2 font-bold">Tripwires (from the artifacts)</h3>
              <div className="text-xs text-slate-300">
                {Object.entries(data.counts)
                  .map(([k, v]) => `${k} ${v}`)
                  .join(" · ")}
              </div>
              {data.anomalies.map((a, i) => (
                <div key={i} className="mt-1 text-xs text-amber-200">
                  anomaly: {a.kind} {a.detail ? JSON.stringify(a.detail) : ""}
                </div>
              ))}
              {data.unsent.map((u) => (
                <div key={u.round} className="mt-1 text-xs text-rose-200">
                  Red round {u.round} not sent: {u.kind}
                  {u.reason ? ` (${u.reason})` : ""}
                </div>
              ))}
            </div>
          </section>
          <footer className="text-xs text-slate-500">
            Source: <span className="font-mono">{data.source_path}</span>. Read-only playback of frozen artifacts;
            the dashboard computes and judges nothing. Keys: ← → step, space play/pause.
          </footer>
        </>
      )}
    </div>
  );
}
