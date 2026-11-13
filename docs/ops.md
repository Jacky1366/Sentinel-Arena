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

**Anthropic SDK (`anthropic==2.3.0`, Stage 5.4).** The 2.x SDK can also take
credentials from `ANTHROPIC_AUTH_TOKEN`, an `ant` profile or federation config, and
its host from `ANTHROPIC_BASE_URL`. The adapter passes `api_key` **and**
`base_url="https://api.anthropic.com"` explicitly (and turns off the SDK's
OpenTelemetry tracing), so none of those can change which key is used or where it is
sent; `tests/test_anthropic_adapter.py` checks this with a mock transport and
sentinel values in all of those variables. The SDK sends the key as
`Authorization: Bearer`. A real provider's model is called only if its price entry is
designer-verified (`price_unverified` refusal otherwise).

**OpenAI SDK (`openai==3.41.0`, Responses API, Stage 5.6).** The SDK reads
`OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID`,
`OPENAI_ADMIN_KEY` and `OPENAI_CUSTOM_HEADERS` from the environment whenever the
matching argument is unset. The adapter therefore **removes every `OPENAI_*` variable
from the environment while it builds the client** and passes `api_key` and
`base_url="https://api.openai.com/v1"` explicitly, so no env value can choose the key,
host, organization, project or headers; the variables are restored immediately after.
`tests/test_openai_adapter.py` keeps sentinel `OPENAI_*` values set **during the actual
request** and asserts only our key and host go out. Responses are sent with
`store=false`.

## Keeping keys out of Claude Code sessions

`.claude/settings.json` (committed, applies to every clone) **denies Claude Code
access to `.env` and `.env.*`**: `Read` / `Edit` rules for those paths, plus `Bash`
rules for the obvious ways to print them (`cat`, `head`, `tail`, `less`, `more`,
`grep`, `source`, `env`, `printenv`). A key must never enter a session transcript.
Verified 2026-11-08: a `Read` and a `cat` of a dummy `.env.*` file were both refused.
Two consequences:

- `.env.example` matches `.env.*`, so Claude Code cannot read it either. The designer
  edits it by hand (it holds variable names only).
- The `Bash` rules match command prefixes; they block the obvious reads, not every
  conceivable one. The real guarantee is that the code never prints a key
  (redaction, below) and that the implementer never runs commands that dump the
  environment or the file. Keep the rules; do not loosen them in `settings.local.json`.

`.env.*` is also git-ignored (except `.env.example`), so a `.env.local` cannot be
committed by accident.

## Keep the project out of iCloud-synced folders

Keep the working copy out of any iCloud-synced folder (on macOS, **Desktop and
Documents** when "Desktop & Documents Folders" is on, and iCloud Drive itself), e.g.
in `~/dev/Sentinel-Arena`. Reasons:

- **`.env` holds the API keys, and iCloud would upload it.** `.gitignore` and the
  Claude Code deny rules do not stop a sync client; the key would leave the machine.
  The same goes for `data/runs/` (match data) and `.venv`.
- iCloud may offload files ("Optimize Mac Storage"). Opening an offloaded file
  triggers a download, and a stalled download hangs the process (seen 2026-11-12:
  `import jsonschema` hung indefinitely because most of `.venv` was offloaded).

The project was moved from the Desktop to `~/dev/Sentinel-Arena` on 2026-11-12 (files
downloaded first, `docker compose down` before the move, `.venv` recreated from
`requirements.txt`, `git fsck` clean). If a key was ever in a synced `.env`, treat it
as exposed and rotate it (key-leak playbook below).

## Tests can never reach a real provider

`tests/conftest.py` has an **autouse fixture** that, for every test, removes every
`ARENA_*` environment variable and points `llm_client`'s `.env` path at a file that
does not exist. Those are the only two places `llm_client` reads keys from, and it
refuses any call without a key (`missing_key`) before an SDK is touched. So a test
whose fake is incomplete (a call that falls through to a real adapter, as happened
once in Stage 5.2 with the network fakes) is refused instead of making a real, paid
API call. This does not depend on the fakes being complete. A test that needs a key
sets an obviously fake one itself. `tests/test_key_hygiene.py` checks the guard: no
`ARENA_*` key is visible in the session, the `.env` path is redirected, and a call
with the real config, prices and adapters is refused. Do not remove or weaken this
fixture.

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

Together with the Claude Code deny rule above, this keeps a key out of git, out of
GitHub, and out of session transcripts.

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
| 2 | preflight refused (stack not ready, leftovers in `live/`, bad `config/llm.json` or `config/prices.json`; for `--blue claude`: no Blue model, or `chunk_size` > 1) | no | none |
| 3 | lock held (`data/runs/live/match.lock` exists; remove a stale lock by hand) | no | none |
| 4 | stopped by the AI budget (a call was refused, e.g. a cap, a missing key or an unverified price, or usage could not be priced; finalized) | yes | `status: "stopped"`, `budget.stopped_by` |

**Real API calls.** Only `run_match.py --blue claude`, `tools/stage5_4_smoke.py
--real-call` (Gate 1) and `tools/stage5_4_check.py --real-calls` (Gate 2) send real,
paid calls; the two gate tools refuse without their flag and run only after the
designer's GO. Every test runs on the fake provider (above).
