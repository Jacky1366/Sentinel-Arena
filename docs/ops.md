# Operations

## API keys

Keys live only in `.env` (git-ignored; copy `.env.example`) or in the environment,
under these names:

| Provider | Variable |
|---|---|
| OpenAI | `ARENA_OPENAI_API_KEY` |
| Anthropic | `ARENA_ANTHROPIC_API_KEY` |
| Google | `ARENA_GEMINI_API_KEY` |

**Never use the SDKs' default names** (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY`). If `ANTHROPIC_API_KEY` is ever exported in your shell, **Claude Code
itself switches to billing that key**, so the arena's budget would pay for your
coding sessions (and the other way round). `agents/llm_client.py` reads only the
`ARENA_*` names and passes the key explicitly to each SDK; it never lets an SDK fall
back to its default variable. A missing `ARENA_*` key makes the client refuse the
call (`missing_key`), even if the default variable is set.

A key value never appears in `api_calls.jsonl`, `match.json`, terminal output, or
error / exception text: the client and `run_match.py` redact known key values and
anything shaped like a provider key.

## Secret scanning (two layers)

1. **Local: gitleaks pre-commit hook** (`.githooks/pre-commit`). It scans the staged
   changes and blocks the commit if it finds a secret. It fails closed: if gitleaks
   is not installed, the commit is blocked too. One-time setup per clone:

   ```bash
   brew install gitleaks                  # macOS; other OSes: see gitleaks releases
   git config core.hooksPath .githooks    # use the repo's tracked hooks
   ```

   `core.hooksPath` is local git config, so every new clone must run it once.
   Never bypass the hook with `--no-verify` to get a secret in.

2. **Server: GitHub secret scanning + push protection**, enabled on the repository
   by the designer. Push protection rejects a push that contains a recognised
   secret, even if the local hook was skipped.

A full-history scan (`gitleaks git .`) found no leaks on 2026-11-08 (25 commits).

## Key-leak playbook

If a key may have leaked (committed, pasted, logged, shared):

1. **Revoke** the key immediately in the provider console (OpenAI / Anthropic /
   Google). Do this first, before cleaning anything up: once revoked, the leaked
   copy is worthless.
2. **Rotate**: create a new key, put it in `.env` under its `ARENA_*` name, and
   confirm `.env` is still git-ignored.
3. **Check provider usage** for the revoked key's lifetime: look for calls, models,
   or spend that do not match our `api_calls.jsonl` files. Report unexpected usage to
   the provider.

Then remove the secret from wherever it leaked. Rewriting git history does not undo
a leak: anything pushed may already be copied. That is why revoking comes first.

## run_match.py exit codes

| Code | Meaning | Match directory | `match.json` |
|---|---|---|---|
| 0 | completed | yes | `status: "completed"` |
| 1 | match failed at a step (finalized) | yes | `status: "failed"`, `failed_step`, `error` |
| 2 | preflight refused (stack not ready, leftovers in `live/`, bad `config/llm.json` or `config/prices.json`) | no | none |
| 3 | lock held (`data/runs/live/match.lock` exists; remove a stale lock by hand) | no | none |
| 4 | stopped by the AI budget (a call was refused, or usage could not be priced; finalized) | yes | `status: "stopped"`, `budget.stopped_by` |
