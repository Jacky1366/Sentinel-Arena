import React, { useMemo, useState } from "react";
import {
  ARM_NAMES, armCards, cell, defaultMatch, matchTabs, pct, plain, takeaway, visibleRows,
} from "./compareModel.js";

// Compare view (Stage 7 #15, D52; #29 clarity pass). Two defenders over the SAME attacks.
// For a non-technical audience: the question on top, detection AND false alarms side by side
// in the cards, one takeaway line, limitations in one expander. The header aggregates every
// match; the per-match table is an illustrative selection; the false-alarm figures are a
// separate check on held-back normal requests. Copy only: every number is the bundle's.

const compares = () => (typeof window !== "undefined" && window.ARENA_COMPARE) || {};

function ArmCard({ a }) {
  const accent = a.blue === "original" ? "border-sky-500" : "border-violet-500";
  const names = ARM_NAMES[a.blue] || { name: a.label, sub: "" };
  return (
    <div className={`flex flex-1 flex-col gap-3 rounded-2xl border-2 ${accent} bg-slate-900 p-5`}>
      <div>
        <div className="text-3xl font-black text-white">{names.name}</div>
        <div className="text-lg text-slate-400">{names.sub}</div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-xl bg-slate-950 p-3">
          <div className="text-5xl font-black text-emerald-300">{a.detected}<span className="text-2xl text-slate-400"> / {a.attempts}</span></div>
          <div className="text-xl text-slate-200">attacks caught ({a.detPct}%)</div>
          <div className="mt-1 text-lg text-yellow-300">★ successful attacks caught: <b>{a.landedDetected} / {a.landedAttempts}</b></div>
        </div>
        <div className="rounded-xl bg-slate-950 p-3">
          {a.fpCheck ? (
            <>
              <div className="text-5xl font-black text-orange-300">{a.fpCheck.fp}<span className="text-2xl text-slate-400"> / {a.fpCheck.n}</span></div>
              <div className="text-xl text-slate-200">false alarms ({pct(a.fpCheck.fp, a.fpCheck.n)}%)</div>
            </>
          ) : (
            <div className="text-xl text-slate-400">false alarms: not in this bundle</div>
          )}
          <div className="mt-1 text-sm text-slate-400">separate check on held-back normal requests</div>
        </div>
      </div>
    </div>
  );
}

function Verdict({ v, attempt }) {
  const c = cell(v, attempt);
  const tone = { hit: "bg-emerald-600 text-white", miss: "bg-rose-700 text-white", none: "bg-slate-800 text-slate-400" }[c.tone];
  const word = c.tone === "hit" ? "caught" : c.tone === "miss" ? "missed" : attempt === "no" ? "not an attack" : "no result";
  return <span className={`inline-flex items-center gap-2 rounded-lg px-3 py-1 text-lg font-bold ${tone}`}>{c.mark} {word}</span>;
}

function Detail({ row, arms, onClose }) {
  if (!row) return null;
  return (
    <div className="flex flex-col gap-3 rounded-2xl border-2 border-white bg-slate-900 p-5">
      <div className="flex items-center justify-between">
        <div className="text-2xl font-black text-white">Match {row.match} · attacker turn {row.round}</div>
        <button className="rounded bg-slate-800 px-3 py-1 text-lg hover:bg-slate-700" onClick={onClose}>close ✕</button>
      </div>
      {row.technique && <div className="text-2xl text-rose-200">{row.technique}</div>}
      <div className="break-all rounded-xl bg-black/70 p-3 font-mono text-lg text-emerald-300">
        <span className="text-sky-400">{row.method} </span>{row.payload || row.path}
      </div>
      <div className="flex flex-wrap gap-2 text-lg">
        {row.solved.map((s) => (
          <span key={s.challenge} className="rounded-lg border border-amber-500 bg-amber-950/60 px-3 py-1 text-amber-200">
            ★ succeeded: {s.challenge}{s.category ? ` (${s.category})` : ""}
          </span>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {arms.map((a) => (
          <div key={a.id} className="flex flex-col gap-1">
            <div className="text-lg font-bold text-slate-300">{(ARM_NAMES[a.blue] || { name: a.label }).name}</div>
            <div><Verdict v={row.verdicts[a.id]} attempt={row.attack_attempt} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Compare() {
  const all = compares();
  const names = Object.keys(all).sort();
  const [name] = useState(names[0] ?? null);
  const bundle = name ? all[name] : null;
  const [match, setMatch] = useState(() => (bundle ? defaultMatch(bundle) : 1));
  const [picked, setPicked] = useState(null);
  const [showAll, setShowAll] = useState(false);
  const [limits, setLimits] = useState(false);
  const cards = useMemo(() => (bundle ? armCards(bundle) : []), [bundle]);

  if (!bundle) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center text-3xl text-slate-400">
        Nothing to compare yet.
      </div>
    );
  }
  const tabs = matchTabs(bundle);
  const rows = visibleRows(bundle, match, showAll);
  const line = takeaway(bundle);
  const notes = [bundle.notes.audit_timing, bundle.notes.instability, bundle.notes.roles, bundle.notes.selection]
    .filter(Boolean).map(plain);
  return (
    <div className="flex flex-col gap-4 p-5">
      <header>
        <div className="text-4xl font-black text-white">What if the defender's idea of an attack were wider?</div>
        <div className="text-xl text-slate-400">
          The same requests from {bundle.matches.length} free-attacker matches, judged by both defenders ({cards[0]?.attempts} of the attacker's {bundle.rows.length} turns were attacks).
        </div>
      </header>

      <div className="flex flex-col gap-4 lg:flex-row">{cards.map((a) => <ArmCard key={a.id} a={a} />)}</div>
      {line && <div className="rounded-xl bg-slate-900 px-5 py-3 text-2xl font-bold text-white">{line}</div>}

      <details className="rounded-xl border border-amber-600/60 bg-amber-950/30 px-4 py-2" open={limits}
        onToggle={(e) => setLimits(e.currentTarget.open)}>
        <summary className="cursor-pointer text-lg font-bold text-amber-200">Limitations</summary>
        <ul className="mt-2 list-disc pl-6 text-lg text-amber-100">
          {notes.map((n) => <li key={n}>{n}</li>)}
        </ul>
      </details>

      <section className="rounded-2xl border border-slate-700 bg-slate-900/60 p-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {tabs.map((t) => (
            <button key={t.match} onClick={() => { setMatch(t.match); setPicked(null); }}
              className={`flex flex-col items-start rounded-lg px-4 py-2 text-left ${t.match === match ? "bg-white text-slate-950" : "bg-slate-800 text-slate-200 hover:bg-slate-700"}`}>
              <span className="text-lg font-black">Match {t.match}{t.date ? ` · ${t.date}` : ""}</span>
              <span className="text-sm">
                {t.attacks} attacks · {t.disagree.length ? `defenders disagree on turn${t.disagree.length > 1 ? "s" : ""} ${t.disagree.join(", ")}` : "defenders agree"}
              </span>
            </button>
          ))}
          <label className="ml-auto flex items-center gap-2 text-lg text-slate-300">
            <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
            show all rounds
          </label>
        </div>
        <table className="w-full table-fixed border-separate border-spacing-y-1 text-lg">
          <thead>
            <tr className="text-left text-base uppercase tracking-wide text-slate-400">
              <th className="w-20">turn</th><th>attack</th><th className="w-32">succeeded</th>
              {bundle.arms.map((a) => <th key={a.id} className="w-56">{(ARM_NAMES[a.blue] || { name: a.label }).name}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.match}-${r.round}`} onClick={() => setPicked(r)}
                className={`cursor-pointer ${r.divergent ? "outline outline-2 outline-yellow-400" : ""} ${r.attack_attempt === "no" ? "opacity-50" : ""} hover:bg-slate-800`}>
                <td className="px-2 font-mono text-white">{r.round}</td>
                <td className="truncate px-2 text-slate-200" title={r.technique || ""}>{r.technique || r.label}</td>
                <td className="px-2 text-yellow-300">{r.landed ? "★ yes" : ""}</td>
                {bundle.arms.map((a) => <td key={a.id} className="px-1"><Verdict v={r.verdicts[a.id]} attempt={r.attack_attempt} /></td>)}
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={3 + bundle.arms.length} className="px-2 py-3 text-slate-400">
                The defenders agree on every turn of this match and no attack succeeded. Tick “show all rounds” to see them.
              </td></tr>
            )}
          </tbody>
        </table>
        <div className="mt-2 text-base text-slate-400">
          yellow outline = the defenders disagree · dimmed = not an attack (left out of the count) · click a row for detail
        </div>
      </section>

      <Detail row={picked} arms={bundle.arms} onClose={() => setPicked(null)} />
    </div>
  );
}
