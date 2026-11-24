import React, { useMemo, useState } from "react";
import { armCards, cell, defaultMatch, divergentCount, matchRows, pct } from "./compareModel.js";

// Compare view (Stage 7 #15, D52): N Blue arms over the SAME traffic, joined by request_id.
// The header aggregates every match; the per-match table is an illustrative selection;
// divergent rows are highlighted; the prompt-FP check is a separate panel; instability and
// audit timing are stated as limitations. Copy only: every number is the bundle's.

const compares = () => (typeof window !== "undefined" && window.ARENA_COMPARE) || {};

function Badge({ tone, children }) {
  const tones = { amber: "border-amber-500 bg-amber-950/60 text-amber-200",
    sky: "border-sky-600 bg-sky-950/60 text-sky-200", slate: "border-slate-600 bg-slate-900 text-slate-300" };
  return <span className={`rounded-lg border px-3 py-1 text-base ${tones[tone]}`}>{children}</span>;
}

function ArmCard({ a }) {
  const accent = a.blue === "original" ? "border-sky-500" : "border-violet-500";
  return (
    <div className={`flex flex-1 flex-col gap-2 rounded-2xl border-2 ${accent} bg-slate-900 p-5`}>
      <div className="flex items-center justify-between gap-2">
        <div className="text-2xl font-black text-white">{a.label}</div>
        <span className={`rounded px-2 py-1 text-sm font-bold uppercase ${a.blue === "original" ? "bg-sky-600 text-white" : "bg-violet-600 text-white"}`}>
          {a.role}
        </span>
      </div>
      <div className="flex items-baseline gap-3">
        <span className="text-6xl font-black text-white">{a.detected}<span className="text-3xl text-slate-400"> / {a.attempts}</span></span>
        <span className="text-2xl text-slate-300">attack attempts detected ({a.detPct}%)</span>
      </div>
      <div className="text-xl text-yellow-300">★ landed attacks caught: <b>{a.landedDetected} / {a.landedAttempts}</b></div>
    </div>
  );
}

function VerdictCell({ v, attempt }) {
  const c = cell(v, attempt);
  const tone = { hit: "bg-emerald-600 text-white", miss: "bg-rose-700 text-white", none: "bg-slate-800 text-slate-400" }[c.tone];
  return (
    <div className={`flex items-center gap-2 rounded-lg px-3 py-1 ${tone}`}>
      <span className="text-2xl font-black">{c.mark}</span>
      <span className="truncate font-mono text-base">{c.text}</span>
    </div>
  );
}

function Detail({ row, arms, onClose }) {
  if (!row) return null;
  return (
    <div className="flex flex-col gap-3 rounded-2xl border-2 border-white bg-slate-900 p-5">
      <div className="flex items-center justify-between">
        <div className="text-2xl font-black text-white">Match {row.match} · Red round {row.round} · {row.label}</div>
        <button className="rounded bg-slate-800 px-3 py-1 text-lg hover:bg-slate-700" onClick={onClose}>close ✕</button>
      </div>
      {row.technique && <div className="text-2xl text-rose-200">{row.technique}</div>}
      <div className="break-all rounded-xl bg-black/70 p-3 font-mono text-lg text-emerald-300">
        <span className="text-sky-400">{row.method} </span>{row.payload || row.path}
      </div>
      <div className="flex flex-wrap gap-2 text-lg">
        <Badge tone="slate">attack attempt (audit): {row.attack_attempt}</Badge>
        {row.headers_set.map((h) => <Badge key={h} tone="slate">with {h}</Badge>)}
        {row.solved.map((s) => <Badge key={s.challenge} tone="amber">★ {s.challenge}{s.category ? ` (${s.category})` : ""}</Badge>)}
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {arms.map((a) => (
          <div key={a.id} className="flex flex-col gap-1">
            <div className="text-lg font-bold text-slate-300">{a.label}</div>
            <VerdictCell v={row.verdicts[a.id]} attempt={row.attack_attempt} />
            <div className="text-base text-slate-400">
              source: {row.verdicts[a.id]?.source ?? "—"}{row.verdicts[a.id]?.reason ? ` · ${row.verdicts[a.id].reason}` : ""}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Compare() {
  const all = compares();
  const names = Object.keys(all).sort();
  const [name, setName] = useState(names[0] ?? null);
  const bundle = name ? all[name] : null;
  const [match, setMatch] = useState(() => (bundle ? defaultMatch(bundle) : 1));
  const [picked, setPicked] = useState(null);
  const cards = useMemo(() => (bundle ? armCards(bundle) : []), [bundle]);

  if (!bundle) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center text-3xl text-slate-400">
        No Compare bundle. Export one with tools/export_compare.py.
      </div>
    );
  }
  const rows = matchRows(bundle, match);
  const m = bundle.matches.find((x) => x.match === match);
  const nDiv = divergentCount(bundle);
  return (
    <div className="flex flex-col gap-4 p-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="text-3xl font-black text-white">{bundle.title}</div>
          <div className="text-lg text-slate-400">
            {bundle.matches.length} matches · {bundle.rows.length} Red rounds sent · the same requests judged by each Blue (joined by request_id) · {nDiv} rounds where the Blues disagree
          </div>
        </div>
        {names.length > 1 && (
          <select className="rounded border border-slate-700 bg-slate-900 px-2 py-1" value={name} onChange={(e) => setName(e.target.value)}>
            {names.map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        )}
      </header>

      <div className="flex flex-col gap-4 lg:flex-row">{cards.map((a) => <ArmCard key={a.id} a={a} />)}</div>

      <div className="flex flex-wrap gap-2">
        <Badge tone="amber">⚠ Limitation: {bundle.notes.audit_timing}</Badge>
        <Badge tone="amber">⚠ {bundle.notes.instability}</Badge>
        <Badge tone="sky">{bundle.notes.roles}</Badge>
      </div>

      <section className="rounded-2xl border border-slate-700 bg-slate-900/60 p-4">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <span className="text-xl font-bold text-white">Per-match detail</span>
          <span className="text-base text-slate-400">({bundle.notes.selection})</span>
          {bundle.matches.map((x) => (
            <button key={x.match} onClick={() => { setMatch(x.match); setPicked(null); }}
              className={`rounded-lg px-3 py-1 text-lg font-bold ${x.match === match ? "bg-white text-slate-950" : "bg-slate-800 text-slate-300 hover:bg-slate-700"}`}>
              Match {x.match}{bundle.rows.some((r) => r.match === x.match && r.divergent) ? " ◆" : ""}
            </button>
          ))}
          {m && (
            <span className="text-base text-slate-400">
              {bundle.arms.map((a) => {
                const d = m.per_arm[a.id].detection;
                return d ? `${a.id}: ${d.num}/${d.den} (${pct(d.num, d.den)}%)` : `${a.id}: audit incomplete`;
              }).join(" · ")}
            </span>
          )}
        </div>
        <table className="w-full table-fixed border-separate border-spacing-y-1 text-lg">
          <thead>
            <tr className="text-left text-base uppercase tracking-wide text-slate-400">
              <th className="w-16">round</th><th className="w-28">label</th><th>technique</th>
              <th className="w-28">attempt</th><th className="w-20">landed</th>
              {bundle.arms.map((a) => <th key={a.id} className="w-56">{a.id}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.request_id} onClick={() => setPicked(r)}
                className={`cursor-pointer ${r.divergent ? "outline outline-2 outline-yellow-400" : ""} ${r.attack_attempt === "no" ? "opacity-50" : ""} hover:bg-slate-800`}>
                <td className="px-2 font-mono text-white">{r.round}</td>
                <td className="px-2 font-mono text-slate-200">{r.label}</td>
                <td className="truncate px-2 text-slate-200" title={r.technique || ""}>{r.technique || "—"}</td>
                <td className="px-2 text-slate-300">{r.attack_attempt === "yes" ? "yes" : r.attack_attempt === "no" ? "not an attempt" : "unaudited"}</td>
                <td className="px-2 text-yellow-300">{r.landed ? "★" : ""}</td>
                {bundle.arms.map((a) => <td key={a.id} className="px-1"><VerdictCell v={r.verdicts[a.id]} attempt={r.attack_attempt} /></td>)}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-2 text-base text-slate-400">◆ / yellow outline = the Blues disagree · dimmed = audited as not an attack attempt (excluded from detection) · click a row for detail</div>
      </section>

      <Detail row={picked} arms={bundle.arms} onClose={() => setPicked(null)} />

      <section className="rounded-2xl border-2 border-dashed border-slate-600 bg-slate-900/40 p-4">
        <div className="text-xl font-bold text-white">Separate check: prompt false positives on sealed benign data (holdout + fixture)</div>
        {bundle.fp_check ? (
          <div className="mt-2 flex flex-wrap gap-6 text-2xl">
            {cards.map((a) => a.fpCheck && (
              <span key={a.id} className="text-slate-200">{a.id}: <b>{a.fpCheck.fp} / {a.fpCheck.n}</b> ({pct(a.fpCheck.fp, a.fpCheck.n)}%)</span>
            ))}
          </div>
        ) : (
          <div className="mt-2 text-lg text-slate-400">Not in this bundle. The D42 2c check reads the sealed holdout (test data) and needs its own GO to export.</div>
        )}
      </section>
    </div>
  );
}
