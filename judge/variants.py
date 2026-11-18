"""The variant mutator (Stage 6.1, M3, S6-2, D24). PURE and deterministic: no network, no
file access, no AI. Same inputs and seed -> byte-identical variants.

Retention criterion (d) asks whether a rule GENERALISES: does it also fire on a
variant of the attack it was written for? A variant is the source request (Red's frozen
proxy line) with ONE fixed, code-defined transformation applied. Variants are never sent:
they are syntactic equivalents of the attack, not attacks verified to land.

Seed per source = sha256(MUTATOR_VERSION | base_seed | match_id | request_id), so the
result never depends on processing order. Each applicable transformation is applied
once, in a fixed order, drawing its choices (case pattern, constant, replacement) from
a random.Random seeded with it. A transformation whose anchor is absent is not
applicable (no variant). At most MAX_VARIANTS per source.

WHICH VARIANTS COUNT. A variant tests the RULE only if normalization does not already
undo it, so each variant is classified on its own (the authority, not a table):

  normalizer-neutralized   for every field, forms(variant) is a superset of
                           forms(source) (rules/normalize.py v2). Every rule that fires
                           on the source then fires on the variant by construction
                           ("any form" matching), so it tests the normalizer: never counts.

A variant also never counts when it is:
  normalizer_probe   from a transformation that only re-encodes (E1, E2, T1, T2): kept
                     as a check that normalization neutralizes it, never counted
                     (double encoding is not even equivalent for a server that decodes
                     once); `neutralized` false on a probe is worth a look
  non_equivalent     from a transformation that is not an equivalent attack on this
                     Target (T4 backslash separator, T7 overlong UTF-8): recorded only
  above_root         its path climbs above the web root (rules/paths.py, D32): nginx
                     would log it as stray, so it can never appear in a real log
  encoding_only      (D24 amendment, proposed 2026-11-17, pending the designer) the
                     FULLY decoded request equals the source's (path fully unquoted;
                     query and body fully unquote_plus-ed): the variant differs only in
                     how it is encoded (E3, E4, E5, T1r). Any rule that matches decoded
                     forms blocks it through the normalizer, so counting it would make
                     criterion (d) true for almost every rule; recorded, never counted

"Blocks a variant" (judge/retention.py): the rule, validated and evaluated ALONE (no
hot-load), fires on at least one variant whose `counting` is true.

Transformations (ids as in docs/plans/stage6_1_step0.md §4):
  all  E1 percent-encode payload characters (probe)   E2 double-encode (probe)
       E3 flip the hex case of existing escapes        E4 decode one level where legal raw
       E5 swap '+' <-> '%20' in query / form body
  89   S1 keyword case   S2 whitespace -> tab   S3 inline comment as whitespace
       S4 tautology constant swap   S5 terminator swap ('--' <-> '/*')
  79   X1 self-firing vector swap   X2 tag / handler case   X3 tag separator -> '/'
       X4 attribute quoting   X5 sink swap   X6 HTML entity in the sink
       X7 'javascript:' case + embedded tab
  22   T1 encode traversal (probe)   T2 double-encode traversal (probe)
       T1r decode an encoded traversal   T3 redundant segment './'
       T5 null-byte extension swap   T6 target file swap within /ftp/
       T4 backslash separator (non_equivalent)   T7 overlong UTF-8 (non_equivalent)
Field encoding is respected: path and query and a form body are percent-encoded text;
a JSON body (starts with '{' or '[') is never URL-decoded by the server, so encoding
transformations skip it and whitespace / quotes use JSON-valid text there.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote_plus

from rules import normalize, paths

MUTATOR_VERSION = "1"
MAX_VARIANTS = 12
FIELDS = ("method", "path", "query", "body")
PROBES = frozenset({"E1", "E2", "T1", "T2"})
NON_EQUIVALENT = frozenset({"T4", "T7"})

SQL_KEYWORDS = ("union", "select", "from", "where", "and", "or", "order", "by", "null",
                "like", "sleep", "having", "group", "insert", "update", "delete", "drop")
TAGS = ("script", "img", "svg", "iframe", "body", "input", "details", "video", "audio",
        "a", "object", "embed", "marquee")
HANDLERS = ("onerror", "onload", "onmouseover", "onfocus", "onclick", "ontoggle",
            "onanimationstart")
SINKS = ("alert", "confirm", "prompt")
NULL_EXTS = ("md", "pdf", "txt", "json", "jpg", "yml")
FTP_FILES = ("acquisitions.md", "announcement_encrypted.md", "coupons_2013.md.bak",
             "eastere.gg", "encrypt.pyc", "incident-support.kdbx", "legal.md",
             "package.json.bak", "package-lock.json.bak", "suspicious_errors.yml")
ENCODE_CHARS = "'\"<>()=;"


@dataclass(frozen=True)
class Variant:
    variant_id: str
    transformation: str
    request: dict            # method, path, query, body
    neutralized: bool        # forms(variant) ⊇ forms(source), field by field
    encoding_only: bool      # fully decoded request equals the source's
    counting: bool
    exclusion_reason: str | None   # None iff counting


# --------------------------------------------------------------------------
# Field helpers
# --------------------------------------------------------------------------

def _kind(field: str, value: str) -> str:
    if field == "body":
        s = value.lstrip()
        return "json" if s[:1] in ("{", "[") else "form"
    return field  # path | query


def _ws(kind: str) -> str:
    """A regex for one whitespace token in this field's raw text."""
    return {"path": r"(?:%20|%09)+", "query": r"(?:\+|%20|%09)+",
            "form": r"(?:\+|%20|%09)+", "json": r"(?:[ \t]|\\t)+"}[kind]


def _tab(kind: str) -> str:
    return "\\t" if kind == "json" else "%09"


def _apply(req: dict, fields: tuple[str, ...], fn: Callable[[str, str], str]) -> dict | None:
    """Apply fn(kind, value) to each named field; None if nothing changed."""
    out, changed = dict(req), False
    for f in fields:
        v = req.get(f) or ""
        if not v:
            continue
        nv = fn(_kind(f, v), v)
        if nv != v:
            out[f], changed = nv, True
    return out if changed else None


def _flip_case(word: str, rng: random.Random) -> str:
    """A seeded mixed case of `word` that differs from it (if it has letters)."""
    letters = [i for i, c in enumerate(word) if c.isalpha()]
    if not letters:
        return word
    for _ in range(8):
        out = "".join(c.upper() if c.isalpha() and rng.random() < 0.5 else c.lower()
                      for c in word)
        if out != word:
            return out
    i = letters[0]
    return word[:i] + word[i].swapcase() + word[i + 1:]


def _pick(options, exclude, rng: random.Random):
    pool = [o for o in options if o.lower() != (exclude or "").lower()]
    return pool[rng.randrange(len(pool))] if pool else None


_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
# "Not inside a word": not preceded by a letter, unless that letter ends a %XX escape
# (e.g. the D of %3D or the 0 of %20 is not part of the next word).
_NW = r"(?:(?<=%[0-9A-Fa-f]{2})|(?<![A-Za-z0-9]))"
_NWL = r"(?:(?<=%[0-9A-Fa-f]{2})|(?<![A-Za-z]))"


def _values(kind: str, v: str, fn: Callable[[str], str]) -> str:
    """Apply fn to the VALUES of a query / form body only (never to '&', keys or the '='
    that separates them), so structure is kept."""
    out = []
    for pair in v.split("&"):
        k, sep, val = pair.partition("=")
        out.append(k + sep + fn(val) if sep else fn(k))
    return "&".join(out)
PAYLOAD = ("path", "query", "body")
URL_FIELDS = ("path", "query", "body")  # a JSON body is skipped by kind checks


# --------------------------------------------------------------------------
# Transformations: (request, rng) -> new request | None (not applicable)
# --------------------------------------------------------------------------

def _enc(val: str) -> str:
    return "".join(f"%{ord(c):02X}" if c in ENCODE_CHARS else c for c in val)


def e1_encode(req, rng):
    def fn(kind, v):
        if kind in ("json", "path"):
            return v
        return _values(kind, v, _enc)
    return _apply(req, ("query", "body"), fn)


def e2_double(req, rng):
    def fn(kind, v):
        if kind in ("json", "path"):
            return v
        return _values(kind, v, lambda val: _PCT.sub(lambda m: "%25" + m.group(1), _enc(val)))
    return _apply(req, ("query", "body"), fn)


def e3_hexcase(req, rng):
    def fn(kind, v):
        if kind == "json":
            return v
        return _PCT.sub(lambda m: "%" + (m.group(1).lower() if m.group(1) != m.group(1).lower()
                                         else m.group(1).upper()), v)
    return _apply(req, URL_FIELDS, fn)


_LEGAL_RAW_QUERY = set("'\"<>()*!;,:@$[]{}|^`~")


def e4_decode(req, rng):
    def fn(kind, v):
        if kind not in ("query", "form"):
            return v

        def dec(m):
            c = chr(int(m.group(1), 16))
            return c if c in _LEGAL_RAW_QUERY else m.group(0)
        return _values(kind, v, lambda val: _PCT.sub(dec, val))
    return _apply(req, ("query", "body"), fn)


def e5_plus(req, rng):
    def fn(kind, v):
        if kind not in ("query", "form"):
            return v
        if "+" in v:
            return v.replace("+", "%20")
        return re.sub(r"%20", "+", v)
    return _apply(req, ("query", "body"), fn)


_KW = re.compile(_NWL + r"(" + "|".join(SQL_KEYWORDS) + r")(?![A-Za-z])", re.I)


def s1_keyword_case(req, rng):
    def fn(kind, v):
        return _KW.sub(lambda m: _flip_case(m.group(1), rng), v)
    return _apply(req, PAYLOAD, fn)


def _kw_ws(kind: str):
    ws = _ws(kind)
    kws = "|".join(SQL_KEYWORDS)
    return re.compile(rf"({ws})(?=(?:{kws})(?![A-Za-z]))|{_NWL}((?:{kws}))({ws})", re.I)


def _replace_kw_ws(v: str, kind: str, new: str) -> str:
    def sub(m):
        if m.group(1) is not None:
            return new
        return m.group(2) + new
    return _kw_ws(kind).sub(sub, v)


def s2_whitespace(req, rng):
    return _apply(req, ("query", "body"), lambda kind, v: _replace_kw_ws(v, kind, _tab(kind)))


def s3_comment(req, rng):
    return _apply(req, ("query", "body"), lambda kind, v: _replace_kw_ws(v, kind, "/**/"))


_TAUT_NUM = re.compile(_NW + r"(\d+)((?:\s|\+|%20)*)(=|%3[dD])((?:\s|\+|%20)*)\1(?![0-9A-Za-z])")
_TAUT_STR = re.compile(r"(['\"]|%27|%22)([A-Za-z0-9]+)\1(=|%3[dD])\1\2\1")


def s4_tautology(req, rng):
    def fn(kind, v):
        def num(m):
            n = m.group(1)
            k = str(rng.randrange(2, 100))
            while k == n:
                k = str(rng.randrange(2, 100))
            return f"{k}{m.group(2)}{m.group(3)}{m.group(4)}{k}"

        def word(m):
            q, w, eq = m.group(1), m.group(2), m.group(3)
            k = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(len(w) + 1))
            return f"{q}{k}{q}{eq}{q}{k}{q}"
        return _TAUT_STR.sub(word, _TAUT_NUM.sub(num, v))
    return _apply(req, PAYLOAD, fn)


_TERM = re.compile(r"--(?=(?:\+|%20|%09|\s|-)*(?:$|&|\"|%22))")
_C_COMMENT = re.compile(r"/\*(?=(?:\+|%20|\s)*(?:$|&|\"|%22))")


def s5_terminator(req, rng):
    def fn(kind, v):
        if _TERM.search(v):
            return _TERM.sub("/*", v)
        return _C_COMMENT.sub("--", v)
    return _apply(req, PAYLOAD, fn)


_LT = r"(?:<|%3[cC])"
_EQ = r"(?:=|%3[dD])"
_HANDLER = re.compile(_NWL + r"(" + "|".join(HANDLERS) + r")((?:\s|\+|%20)*" + _EQ + ")", re.I)
_TAG = re.compile(rf"({_LT})(" + "|".join(TAGS) + r")(?![A-Za-z])", re.I)


# Self-firing event-handler vectors (tag, attributes before the handler, handler). X1
# replaces the element's opening part up to "handler=" with another vector's, keeping the
# field's own encoding of '<', the separator and '=' (a handler alone cannot be swapped:
# <img src=x onload=...> never fires).
VECTORS = (("img", ("src=x",), "onerror"), ("svg", (), "onload"), ("body", (), "onload"),
           ("details", ("open",), "ontoggle"), ("input", ("autofocus",), "onfocus"))
_VECTOR = re.compile(rf"({_LT})(" + "|".join(TAGS) + r")(?![A-Za-z])(.*?)" + _NWL
                     + r"(" + "|".join(HANDLERS) + r")((?:\s|\+|%20)*)(" + _EQ + ")", re.I)


def x1_vector(req, rng):
    def fn(kind, v):
        m = _VECTOR.search(v)
        if not m:
            return v
        sep = re.search(r"%20|\+|%09|\s|/", m.group(3))
        sp = sep.group(0) if sep else ("%20" if kind in ("query", "path", "form") else " ")
        eq = m.group(6)
        tag = m.group(2).lower()
        pool = [x for x in VECTORS if x[0] != tag]
        ntag, attrs, handler = pool[rng.randrange(len(pool))]
        attrs = [a.replace("=", eq) for a in attrs]
        new = m.group(1) + ntag + "".join(sp + a for a in attrs) + sp + handler + m.group(5) + eq
        return v[:m.start()] + new + v[m.end():]
    return _apply(req, PAYLOAD, fn)


def x2_case(req, rng):
    def fn(kind, v):
        v = _TAG.sub(lambda m: m.group(1) + _flip_case(m.group(2), rng), v)
        return _HANDLER.sub(lambda m: _flip_case(m.group(1), rng) + m.group(2), v)
    return _apply(req, PAYLOAD, fn)


def x3_separator(req, rng):
    def fn(kind, v):
        pat = re.compile(rf"({_LT}(?:" + "|".join(TAGS) + rf"))({_ws(kind)}|\s)+", re.I)
        return pat.sub(lambda m: m.group(1) + ("%2F" if kind in ("path",) else "/"), v)
    return _apply(req, PAYLOAD, fn)


def x4_quote(req, rng):
    def fn(kind, v):
        q = '\\"' if kind == "json" else "%22"
        quoted = re.compile(rf"((?:{'|'.join(HANDLERS)})(?:\s|\+|%20)*{_EQ})(\"|%22|'|%27|\\\\\")"
                            rf"([^\"'%\s+>]+)\2", re.I)
        if quoted.search(v):
            return quoted.sub(lambda m: m.group(1) + m.group(3), v)
        bare = re.compile(rf"((?:{'|'.join(HANDLERS)})(?:\s|\+|%20)*{_EQ})"
                          rf"(?!\"|%22|'|%27|\\\\)([^\s+>&\"]+?)(?=$|\s|\+|%20|>|%3[eE]|&|\")",
                          re.I)
        return bare.sub(lambda m: f"{m.group(1)}{q}{m.group(2)}{q}", v)
    return _apply(req, PAYLOAD, fn)


_SINK = re.compile(_NWL + r"(" + "|".join(SINKS) + r")((?:\s|\+|%20)*(?:\(|%28|`))", re.I)


def x5_sink(req, rng):
    def fn(kind, v):
        return _SINK.sub(lambda m: _pick(SINKS, m.group(1), rng) + m.group(2), v)
    return _apply(req, PAYLOAD, fn)


def x6_entity(req, rng):
    def fn(kind, v):
        if not _HANDLER.search(v):
            return v
        m = _SINK.search(v)
        if not m:
            return v
        c = m.group(1)[0]
        ent = f"&#x{ord(c):x};"
        if kind != "json":
            ent = "".join(f"%{ord(ch):02X}" if ch in "&#;" else ch for ch in ent)
        return v[:m.start(1)] + ent + v[m.start(1) + 1:]
    return _apply(req, PAYLOAD, fn)


_JS = re.compile(r"(javascript)(:|%3[aA])", re.I)


def x7_javascript(req, rng):
    def fn(kind, v):
        tab = _tab(kind)
        return _JS.sub(lambda m: _flip_case("java", rng) + tab + _flip_case("script", rng)
                       + m.group(2), v)
    return _apply(req, PAYLOAD, fn)


_TRAV_PLAIN = re.compile(r"\.\./")
_DOT = r"(?:%(?:25)*2[eE]|\.)"
_SEP = r"(?:%(?:25)*2[fF]|/)"
_TRAV_ENC = re.compile(_DOT + _DOT + _SEP)
TRAV_FIELDS = ("path", "query")


def t1_encode(req, rng):
    return _apply(req, TRAV_FIELDS, lambda kind, v: _TRAV_PLAIN.sub("%2e%2e%2f", v))


def t2_double(req, rng):
    return _apply(req, TRAV_FIELDS, lambda kind, v: _TRAV_ENC.sub("%252e%252e%252f", v))


def t1r_decode(req, rng):
    """Remove one level of percent-encoding from each encoded traversal sequence."""
    from urllib.parse import unquote

    def fn(kind, v):
        return _TRAV_ENC.sub(lambda m: unquote(m.group(0)), v)
    return _apply(req, TRAV_FIELDS, fn)


def t3_segment(req, rng):
    def fn(kind, v):
        m = _TRAV_ENC.search(v)
        if not m:
            return v
        ins = "./" if rng.random() < 0.5 else ".%2f"
        return v[:m.start()] + ins + v[m.start():]
    return _apply(req, TRAV_FIELDS, fn)


_NULL_EXT = re.compile(r"(%2500|%00)\.([A-Za-z0-9]+)$")


def t5_null_ext(req, rng):
    def fn(kind, v):
        return _NULL_EXT.sub(lambda m: f"{m.group(1)}.{_pick(NULL_EXTS, m.group(2), rng)}", v)
    return _apply(req, ("path",), fn)


def t6_file_swap(req, rng):
    def fn(kind, v):
        for name in sorted(FTP_FILES, key=len, reverse=True):
            i = v.find(name)
            if i >= 0 and (i == 0 or v[i - 1] in "/f"):  # '/' or the end of an encoded %2f
                return v[:i] + _pick(FTP_FILES, name, rng) + v[i + len(name):]
        return v
    return _apply(req, ("path",), fn)


def t4_backslash(req, rng):
    return _apply(req, TRAV_FIELDS, lambda kind, v: _TRAV_ENC.sub("..%5c", v))


def t7_overlong(req, rng):
    return _apply(req, TRAV_FIELDS, lambda kind, v: _TRAV_ENC.sub("%c0%ae%c0%ae/", v))


COMMON = (("E1", e1_encode), ("E2", e2_double), ("E3", e3_hexcase), ("E4", e4_decode),
          ("E5", e5_plus))
BY_CWE: dict[str, tuple] = {
    "CWE-89": COMMON + (("S1", s1_keyword_case), ("S2", s2_whitespace), ("S3", s3_comment),
                        ("S4", s4_tautology), ("S5", s5_terminator)),
    "CWE-79": COMMON + (("X1", x1_vector), ("X2", x2_case), ("X3", x3_separator),
                        ("X4", x4_quote), ("X5", x5_sink), ("X6", x6_entity),
                        ("X7", x7_javascript)),
    "CWE-22": (("T1", t1_encode), ("T2", t2_double), ("E3", e3_hexcase),
               ("T1r", t1r_decode), ("T3", t3_segment), ("T5", t5_null_ext),
               ("T6", t6_file_swap), ("T4", t4_backslash), ("T7", t7_overlong)),
}
TRANSFORMATIONS = sorted({t for v in BY_CWE.values() for t, _ in v})


# --------------------------------------------------------------------------
# Generation and classification
# --------------------------------------------------------------------------

def seed_for(base_seed: int, match_id: str, request_id: str) -> int:
    text = f"{MUTATOR_VERSION}|{base_seed}|{match_id}|{request_id}"
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")


def request_of(line: dict) -> dict:
    return {f: line.get(f, "") or "" for f in FIELDS}


def _forms(req: dict) -> dict[str, list[str]]:
    return normalize.request_forms(req["path"], req["query"], req["body"], req["method"])


def neutralized(source: dict, variant: dict) -> bool:
    """forms(variant) ⊇ forms(source), field by field: every rule that fires on the source
    fires on the variant by construction."""
    fs, fv = _forms(source), _forms(variant)
    return all(set(fs[f]) <= set(fv[f]) for f in FIELDS)


def _plus_all(value: str) -> str:
    seen = value
    for _ in range(normalize.MAX_ROUNDS):
        nxt = unquote_plus(seen)
        if nxt == seen:
            break
        seen = nxt
    return seen


def decoded(req: dict) -> dict[str, str]:
    """The fully decoded request: what is left once every encoding layer is removed."""
    return {"method": req["method"], "path": normalize.decode_all(req["path"]),
            "query": _plus_all(req["query"]), "body": _plus_all(req["body"])}


def encoding_only(source: dict, variant: dict) -> bool:
    return decoded(source) == decoded(variant)


def variant_id(req: dict) -> str:
    text = json.dumps({f: req[f] for f in FIELDS}, sort_keys=True, separators=(",", ":"))
    return "v-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def classify(source: dict, transformation: str, req: dict) -> Variant:
    neut = neutralized(source, req)
    enc = encoding_only(source, req)
    if transformation in PROBES:
        reason = "normalizer_probe"
    elif transformation in NON_EQUIVALENT:
        reason = "non_equivalent"
    elif paths.above_root(req["path"]):
        reason = "above_root"
    elif neut:
        reason = "normalizer_neutralized"
    elif enc:
        reason = "encoding_only"
    else:
        reason = None
    return Variant(variant_id(req), transformation, req, neut, enc, reason is None, reason)


def generate(source_line: dict, cwe: str, base_seed: int, match_id: str,
             request_id: str) -> list[Variant]:
    """Every variant of one source request, in transformation order (at most
    MAX_VARIANTS; a duplicate of the source or of an earlier variant is dropped)."""
    if cwe not in BY_CWE:
        raise ValueError(f"no transformations for {cwe!r}")
    source = request_of(source_line)
    rng = random.Random(seed_for(base_seed, match_id, request_id))
    out: list[Variant] = []
    seen = {variant_id(source)}
    for name, fn in BY_CWE[cwe]:
        new = fn(dict(source), rng)
        if new is None:
            continue
        v = classify(source, name, new)
        if v.variant_id in seen:
            continue
        seen.add(v.variant_id)
        out.append(v)
        if len(out) == MAX_VARIANTS:
            break
    return out


def row(v: Variant, match_id: str, request_id: str, cwe: str, base_seed: int) -> dict:
    """One variants.jsonl line (schemas/variant.schema.json)."""
    return {"schema_version": "0.1", "mutator_version": MUTATOR_VERSION,
            "base_seed": base_seed, "source_match_id": match_id,
            "source_request_id": request_id, "cwe": cwe, "variant_id": v.variant_id,
            "transformation": v.transformation, "request": v.request,
            "neutralized": v.neutralized, "encoding_only": v.encoding_only,
            "counting": v.counting,
            "exclusion_reason": v.exclusion_reason}
