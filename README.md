# DepGuard
Video link : https://drive.google.com/file/d/1H4ibd5PrhpPaD7hjJXPET0NUw1lT6sv_/view?usp=drivesdk
**AI Dependency Risk & License-Conflict Triage Agent**

> Point DepGuard at a GitHub repository. It analyzes dependencies across six ecosystems, identifies actionable security/EOL/license risks, decides the smallest safe remediation, executes it through GitHub where it can, records and notifies the result either way, and can keep watching the repo on a schedule.

## Problem

Engineering teams accumulate vulnerable, end-of-life, or license-incompatible dependencies faster than anyone reviews them. Dependabot-style tools surface alerts; they don't reason about *which* upgrades are actually safe to apply automatically, and they don't close the loop with the rest of the team's tools (issue tracker of record, notification channel, audit log).

## Solution

DepGuard started as a narrow, npm-only agent and was deliberately extended (in phases, each gated on the reliability suite staying green) to cover six ecosystems total. It:

1. Reads a repository's real manifest/lockfiles from GitHub across npm, PyPI, crates.io, Go, Packagist, and RubyGems, plus five harder formats (`pom.xml`, `build.gradle`, `Pipfile.lock`, `pyproject.toml`, `*.csproj`) via an LLM extraction step whose output is independently verified (described below).
2. Checks every resolved dependency against **OSV.dev** (vulnerabilities), **deps.dev** (license metadata, npm), and **endoflife.date** (Node.js runtime support window).
3. Applies a small set of deterministic, conservative policy rules to decide, per finding, whether it's safe to auto-remediate, needs a human, or is merely detected (advisory real, no remediation path built yet for that ecosystem).
4. On explicit user confirmation, opens a **real GitHub pull request** on a new branch — never touching the default branch directly — covering every auto-fixable finding across every ecosystem in one PR.
5. Logs the remediation (and any detection-only findings, never silently dropped) to a **Google Sheet** and posts a **Slack** notification.
6. Runs from a single web dashboard where a user pastes a repo URL and (optionally) their own GitHub token, and can connect **their own** Slack workspace and Google account through real OAuth.
7. Can **monitor a repo on a schedule** (for example every 5 minutes, or twice a day), re-scanning unattended and alerting only when findings change.
8. Is judged on a 33-case evaluation harness that runs against live external data, not canned answers.

## How It Works

```
GitHub repository
   -> DepGuard reads whichever manifests/lockfiles exist:
        package.json+package-lock.json (npm), requirements.txt (PyPI),
        Cargo.lock (crates.io), go.sum (Go), composer.lock (Packagist),
        Gemfile.lock (RubyGems)  -- all parsed deterministically
        pom.xml, build.gradle, Pipfile.lock, pyproject.toml, *.csproj
        -- extracted by the LLM Manifest Agent, then independently verified
   -> OSV.dev vulnerability lookup, one batch per ecosystem (ground truth for "is this vulnerable")
   -> deps.dev license lookup for direct npm dependencies
   -> endoflife.date check on the Node.js engines range
   -> deterministic policy decision (auto-remediate / needs review / detection-only / informational)
   -> [user clicks "Create Remediation PR"]
   -> new branch -> every auto-fixable file patched (npm + PyPI so far) -> commit(s) -> PR opened
      (if an open PR already has these exact fixes, that PR is returned instead of a duplicate)
   -> Google Sheets remediation log row appended (including detection-only findings)
   -> Slack notification sent (including detection-only findings)

Scheduled monitoring (optional, unattended)
   -> every N minutes, or at fixed daily times: re-run the same analysis
   -> compare with the previous scan: which findings are new, which are resolved
   -> only if something changed: Slack alert + Google Sheets rows
   -> never opens a PR on its own
```

Every step is recorded in an execution trace shown in the UI (`Repository discovered -> Lockfile found -> Dependencies parsed -> OSV query -> deps.dev query -> EOL check -> LLM manifest parsing -> Decision made -> Safety check -> Branch created -> Files updated -> Commit created -> PR created -> Sheets updated -> Slack sent -> Final result`, repeated per ecosystem where applicable), so every claim on screen is traceable to an actual step DepGuard ran.

## Supported Ecosystems

| Ecosystem | Manifest/lockfile | Parsed by | Auto-remediation | OSV ecosystem string |
|---|---|---|---|---|
| npm | `package.json` + `package-lock.json` | Deterministic parser | Yes | `npm` |
| PyPI | `requirements.txt` | Deterministic parser | Yes | `PyPI` |
| crates.io | `Cargo.lock` | Deterministic parser (TOML) | Detection-only | `crates.io` |
| Go | `go.sum` | Deterministic parser | Detection-only | `Go` |
| Packagist | `composer.lock` | Deterministic parser (JSON) | Detection-only | `Packagist` |
| RubyGems | `Gemfile.lock` | Deterministic parser | Detection-only | `RubyGems` |
| Maven | `pom.xml`, `build.gradle` | LLM Manifest Agent + verifier | Detection-only | `Maven` |
| PyPI (LLM path) | `Pipfile.lock`, `pyproject.toml` | LLM Manifest Agent + verifier | Detection-only* | `PyPI` |
| NuGet | `*.csproj` | LLM Manifest Agent + verifier | Detection-only | `NuGet` |

\* Even though the OSV ecosystem is `PyPI`, dependencies extracted by the LLM path are always detection-only — the remediation code only knows how to patch an exact `requirements.txt` line, and applying that logic to a different file format would risk editing the wrong place. Only the deterministic `requirements.txt` parser feeds the PyPI remediation path.

**Remediation boundary, in one sentence:** DepGuard can *open a PR* for npm and PyPI (deterministic-parser path only); every other ecosystem gets a real, non-fabricated advisory surfaced everywhere (UI, PR body's "detected but not included" section, Sheets, Slack) with status `DETECTION_ONLY`, because no code-patching logic has been built for those file formats yet — not because the vulnerability data is less trustworthy.

## The LLM Manifest Agent

Five formats (`pom.xml`, `build.gradle`, `Pipfile.lock`, `pyproject.toml`, `*.csproj`) don't have a deterministic parser in this project — their syntax is more irregular (XML with inheritance, Groovy DSL, TOML with nested tables) and an LLM is a better fit for free-form extraction than a bespoke regex/grammar for each.

**What the LLM is allowed to do:** read the raw file text and propose a list of `{ecosystem, name, version, raw_line}` candidates. It is explicitly instructed to omit anything without a concrete literal version — no `${property}` placeholders, no ranges, no `latest`, no version inherited from a parent POM/BOM with no literal value in the file.

**What the LLM is never allowed to do:** decide whether a package is vulnerable, or which version fixes it. That is still 100% `policy.py`, completely unmodified by this feature — the exact same deterministic functions used for every other ecosystem.

**Every LLM-proposed candidate is verified before it can reach OSV, in this order, and dropped (with a recorded reason) on any failure:**
1. `raw_line` must appear **verbatim** in the source file — catches fabrication.
2. `version` must be a concrete literal (regex check; rejects placeholders/ranges).
3. `name@version` must exist in the real, live package registry — keyless public APIs: PyPI, crates.io, RubyGems, Packagist, Maven Central, plus NuGet and the Go module proxy (added here since the LLM path can plausibly hit `NuGet`/`Go`-shaped inputs too).

Findings that survive verification are always `DETECTION_ONLY` (see the remediation boundary above), and every rejected candidate is counted and shown, not silently dropped — see `llm_manifest_summary` in the `/api/analyze` response and the dashboard's LLM Manifest Agent panel.

## Integrations

| # | Integration | Role | Type |
|---|---|---|---|
| 1 | **GitHub** | Read repo/lockfile, create branch, patch files, commit, open PR | Action (write) |
| 2 | **Slack** | Notify the team when a remediation completes or a scheduled scan finds changes (user's own workspace via OAuth "Connect Slack", or a server-configured webhook) | Action (write) |
| 3 | **Google Sheets** | Append-only log of remediations and scheduled-scan changes (a fresh sheet in the user's own Drive via OAuth "Connect Google Sheets", or a server-configured service account) | Action (write) |
| 4 | **OSV.dev** | Ground truth for vulnerability existence + fixed versions | Intelligence (read) |
| 5 | **deps.dev** | SPDX license metadata for direct dependencies | Intelligence (read) |
| 6 | **endoflife.date** | Node.js runtime support/EOL status | Intelligence (read) |
| 7 | **Groq** (`openai/gpt-oss-120b`) | Extracts dependency candidates from manifests with no deterministic parser; never decides vulnerability | Extraction (verified) |
| 8 | **Package registries** (PyPI, crates.io, RubyGems, Packagist, Maven Central, NuGet, Go proxy, npm) | Confirm every LLM-proposed `name@version` really exists; npm registry supplies integrity hashes for lockfile patches | Verification (read) |

These form one pipeline, not separate demos: the GitHub read feeds the parsers and the LLM agent, whose verified output feeds OSV/deps.dev/endoflife.date, whose combined output drives the GitHub write, which in turn drives the Sheets and Slack actions.

## Agent Decision Logic

DepGuard does **not** ask an LLM whether a package is vulnerable, in any ecosystem, including the two (Maven-family, NuGet) whose *extraction* involves an LLM. Vulnerability existence and fixed versions come from OSV.dev; everything else is a small, explicit, deterministic rule set in [`backend/app/policy.py`](backend/app/policy.py), used identically for all nine manifest formats and all six OSV ecosystems:

- **Multi-advisory safety**: if several distinct advisories affect the same version, the target version must satisfy *all* of them (the max of each advisory's own minimum fix — not the min across the pool). A version that only fixes the cheapest advisory is rejected. (This also required fixing a real gap found while adding non-npm ecosystems: OSV advisories for PyPI/RubyGems/Packagist commonly use range `type: "ECOSYSTEM"` rather than `"SEMVER"`, and the original extractor was silently dropping their `fixed` events.)
- **Direct-only auto-remediation**: only direct dependencies (present in the manifest, not just the lockfile) are eligible for an automatic PR. Transitive-only fixes are flagged `NEEDS_REVIEW`. For the four deterministic-lockfile-only ecosystems (crates.io, Go, Packagist, RubyGems) direct-vs-transitive isn't computable from the lockfile alone without also parsing the corresponding manifest (`Cargo.toml`/`go.mod`/`composer.json`/`Gemfile`) — out of scope for this MVP, so those entries are treated as direct for messaging purposes; it's moot in practice since those ecosystems are gated to `DETECTION_ONLY` regardless (see below).
- **Ecosystem remediation gate**: even when the fix-safety rule above says a version would be safe to auto-apply, the action is only actually `AUTO_REMEDIATE` for npm and PyPI (via the deterministic `requirements.txt` parser). Every other ecosystem — including PyPI dependencies that came from the *LLM* path (`Pipfile.lock`/`pyproject.toml`), since no patcher exists for those file formats — is relabeled `DETECTION_ONLY`: the underlying advisory/version data is untouched, only the action and reason text are amended, and the finding is never dropped from the UI, PR body, Sheets, or Slack.
- **No confident fix -> no auto-action**: if OSV reports a vulnerability with no fixed version, or the current/fixed version strings can't be parsed as plain semver, the finding is routed to human review. DepGuard never guesses a version.
- **License conflict is a signal, not a verdict**: a small SPDX allow/deny list (`policy.PERMISSIVE_LICENSES` / `policy.COPYLEFT_LICENSES`) flags a permissive-project + copyleft-dependency combination for human/legal review. **This is not legal advice** and does not attempt a general license-compatibility engine.
- **EOL is informational**: Node.js EOL/nearing-EOL findings are surfaced but never trigger an automatic code change.
- **Bundled PR = union of auto-approved findings only**: "Create Remediation PR" opens one PR covering every finding that individually cleared every bar above, across every ecosystem in one branch/commit set; anything that didn't clear the bar is listed as skipped/needs-review/detection-only in the same response, never silently dropped.
- **No duplicate PRs**: before creating a branch, DepGuard checks whether an open PR already exists for the exact same set of fixes. If it does, that PR is returned and nothing new is created.
- **A human opens every PR**: scheduled monitoring re-scans and alerts on its own, but it can never open a pull request.

## Reliability & Evaluation

Reliability is a first-class feature, not an afterthought. [`eval/gold_set.json`](eval/gold_set.json) defines 33 cases; `GET /api/eval` runs all of them against **live** external services on every call (no cached/mocked answers) and returns measured metrics:

- **Vulnerability presence/absence** across real package@version pairs with published OSV.dev advisories spanning all six OSV ecosystems (npm, PyPI, crates.io, Go, Packagist, RubyGems), plus a clean negative control per ecosystem.
- **Fixed-version correctness**, including a transitive-dependency case that must resolve to `NEEDS_REVIEW` even though a fix exists, and a RubyGems case (`nokogiri`) with ~40 accumulated advisories that must all be satisfied simultaneously by one target version.
- **Policy unit cases** for the "no fixed version published" rule and both branches of the license-conflict rule, run directly against the deterministic policy functions (no external API involved, labeled `policy_unit_*`).
- **EOL classification** against real endoflife.date data for both an EOL (Node 12) and a supported (Node 22) runtime.
- **LLM verifier cases** (`llm_verify`) that require no API key at all: a hand-written synthetic LLM-shaped output tests each of the three deterministic rejection paths independently — a fabricated `raw_line`, a placeholder version (`${jackson.version}`), and a version that doesn't exist in the real Maven Central registry (this one does make a live registry call, just not an LLM call).

Last recorded run (see the in-app "Reliability & Evaluation" panel for a live re-run): **33/33 cases passed, 100% accuracy, 100% precision/recall on vulnerability detection, 0 unsafe automatic upgrades.**

**Scheduled monitoring is not part of the 33 cases**; it was verified separately, and those results are not included in the numbers above:
- Next-run times were unit-tested: same-day and next-day daily times, a scan landing exactly on a scheduled time, and rejection of invalid times.
- Change detection was run against the live demo repo with a simulated previous scan. It reported exactly one new and one resolved finding, and on the next run reported no change.
- A real 1-minute schedule on the running server sent its baseline alert to Slack and Sheets. A minute later it scanned again with no one clicking and correctly sent nothing, because nothing had changed.

Real bugs found and fixed during the build, all documented in the commit history:
- A policy bug where DepGuard would pick a fix version that satisfied only the cheapest of several advisories (fixed by taking the max of each advisory's own minimum fix).
- A stale assumption in the gold set itself — `lodash@4.17.21`, long treated as "the patched version," turned out to have a real, newly published OSV.dev advisory (`GHSA-f23m-r3pf-42rh`, fixed in 4.18.0). That case is kept in the gold set on purpose, as proof the system reasons from live data rather than memorized versions.
- (Caught by manual live testing, not the harness itself, but worth naming): `is_direct` was originally computed by checking presence in the npm lockfile, which is wrong for lockfileVersion 3 — transitive packages appear there too. Fixed to check the manifest's declared dependencies instead.
- OSV advisories for PyPI/RubyGems/Packagist often use range type `ECOSYSTEM` instead of `SEMVER`, and the fixed-version extractor was silently ignoring them — so real fixes (e.g. `flask 2.0.0 → 3.1.3`) showed up as "no fix available." Fixed, and `flask` is now a gold-set case.
- Clicking "Create Remediation PR" again while a PR for the same dependency set was still open caused a GitHub `409 Conflict`: DepGuard tried to patch the already-patched branch using stale file SHAs. It now detects the open PR and returns it instead of touching the branch. Separately, GitHub sometimes returns a one-off `409`/`5xx` on reads, so those requests now retry briefly.
- In that reuse case, the dashboard still ticked "Branch created / Files updated / Commit created" even though nothing new had been created. The API now returns `reused_existing_pr`, and the dashboard says an existing PR was reused.

All numbers shown anywhere in the app are computed from an actual run in that process; nothing is hardcoded.

## Setup

### Prerequisites
- Python 3.11+ (3.12 used for development; `tomllib` for `Cargo.lock` parsing requires 3.11+)
- A GitHub [fine-grained personal access token](https://github.com/settings/personal-access-tokens) with **Contents: Read and write** and **Pull requests: Read and write**, scoped to the repo(s) you'll analyze/remediate.
- (Optional) A Slack incoming webhook URL.
- (Optional) A Google Cloud service account with access to a target Google Sheet.
- (Optional) A [Groq](https://console.groq.com/) API key, only needed if you want the LLM Manifest Agent to analyze `pom.xml`/`build.gradle`/`Pipfile.lock`/`pyproject.toml`/`*.csproj`. Without it, those files are detected and reported as skipped rather than analyzed — everything else works unaffected.
- (Optional, for the dashboard's "Connect" buttons) OAuth apps:
  - **Slack**: create an app at [api.slack.com/apps](https://api.slack.com/apps). Under **OAuth & Permissions**, add the redirect URL `http://localhost:8010/oauth/slack/callback` and the bot scope `incoming-webhook`. Copy the Client ID and Client Secret.
  - **Google**: in Google Cloud, enable the **Google Sheets API**. Configure the OAuth consent screen (External, add yourself as a test user, add the `.../auth/spreadsheets` scope). Create an OAuth client of type **Web application** with redirect URI `http://localhost:8010/oauth/google/callback`, then copy the Client ID and Client Secret.

### Run it

```bash
cd backend
pip install -r requirements.txt
cp ../.env.example ../.env   # fill in GITHUB_TOKEN at minimum (or paste a token in the dashboard)
uvicorn app.main:app --port 8010
```

Open `http://localhost:8010/`. Use port 8010 (or change `OAUTH_REDIRECT_BASE` and both OAuth redirect URIs to match another port) — OAuth providers require the redirect URI to match exactly.

Restarting the server clears OAuth connections and schedules (both are held in memory), so reconnect Slack/Google and recreate schedules afterwards.

### Try it against the demo repo

Analyze **https://github.com/priyanshiiitr/depguard-demo-vulnerable** (source also mirrored in [`demo-repo-vulnerable/`](demo-repo-vulnerable/)) — it deliberately pins vulnerable dependencies across three ecosystems: `lodash@4.17.15`, `minimist@1.2.5`, `axios@0.21.0` (npm), `flask@2.0.0` (`requirements.txt`, PyPI), and a `pom.xml` containing `commons-collections@3.2.1` (the CVE-2015-4852 deserialization RCE) alongside a dependency whose version is deliberately left to a Spring Boot parent POM with no literal in the file — plus a Node.js `engines` range that is already end-of-life.

This exact flow was run for real while building DepGuard: analysis correctly found auto-remediable npm+PyPI vulnerabilities, a transitive npm vulnerability routed to human review, a `DETECTION_ONLY` Maven finding (extracted by the LLM agent and independently verified against Maven Central), and an informational EOL flag — and clicking "Create Remediation PR" opened a real pull request bundling every auto-fixable change into one branch, appended real rows to Google Sheets (including the detection-only finding), and delivered a real Slack notification.

Because every run proposes the same fixes for this repo, a new PR is only created when no DepGuard PR for them is open. Close or merge the previous one first if you want to watch a fresh PR being created.

## Using the Dashboard

1. **Connect Your Tools (optional)**: click **Connect Slack** to choose a workspace and channel, and **Connect Google Sheets** to sign in with Google. DepGuard creates a new "DepGuard Remediation Log" spreadsheet in your Drive. Each tile shows **Connected** with the workspace or a link to the sheet. When a service is connected, notifications and log rows go to your accounts instead of the server's defaults.
2. **Analyze a GitHub repository**: paste the repo URL and, optionally, a fine-grained GitHub token (Contents + Pull requests: Read and write). Leave the token blank to use the server's `GITHUB_TOKEN`.
3. **Read the results**:
   - **Repository Summary**: overall risk level and which ecosystems were found.
   - **LLM Manifest Agent Activity**: shown only when an LLM-parsed file was present. Lists each file the LLM read, with counts of dependencies extracted, verified, and rejected, plus the reason for each rejection.
   - **Findings**: grouped by ecosystem, with counts of auto-fixable, needs-review, detection-only, and informational findings. Findings that came from the LLM path are tagged 🤖 LLM.
   - **Agent Execution Trace**: a timeline of every step DepGuard ran. LLM steps are highlighted.
4. **Create Remediation PR**: opens one real PR for all auto-fixable findings, then shows a checklist (branch, files, commit, PR, Sheets, Slack) with a link to the PR. If an open PR already contains the same fixes, DepGuard doesn't create a duplicate. It links that PR, says nothing new was created, and tells you to merge or close it first if you want a fresh one.
5. **Scheduled Monitoring**: have DepGuard re-scan the repo on its own. See the next section.
6. **Run Evaluation Suite**: re-runs all 33 gold-set cases live and shows accuracy, precision/recall, and unsafe auto-upgrade count.

## Scheduled Monitoring

DepGuard can watch a repository on a schedule, so nobody has to remember to click Analyze.

- In the **Scheduled Monitoring** card, pick a schedule and click **Start Monitoring**. The options are **every 5 minutes**, **every 15 minutes**, **every hour**, **twice a day (09:00 and 18:00)**, a custom interval (minimum 1 minute), or custom daily times in 24-hour `HH:MM` (server local time). The schedule uses the repo URL and token from the Analyze section.
- The first scan runs immediately and becomes the baseline. Every later scan runs the same deterministic analysis and compares its findings with the previous scan.
- Slack gets an alert, and Google Sheets gets a row per change, only when something changed: a **new** finding appeared, or an existing one was **resolved** (for example after a remediation PR is merged). A scan with no changes sends nothing, so even a 5-minute schedule doesn't spam the channel. Alerts can be turned off per schedule.
- Each schedule shows a live countdown to its next scan, the latest result, whether the alert went out, and its last 10 runs. You can run it immediately, pause, resume, or delete it. **View latest results** loads that scan into the main dashboard, where you can open a PR as usual.
- **Scheduled scans never open a pull request.** Monitoring is automatic, but changing code still requires a person to click **Create Remediation PR**.

API: `GET`/`POST /api/schedules`, `POST /api/schedules/{id}/run`, `POST /api/schedules/{id}/pause`, `POST /api/schedules/{id}/resume`, `DELETE /api/schedules/{id}`, `GET /api/schedules/{id}/latest`.

## Environment Variables

See [`.env.example`](.env.example):

```
GITHUB_TOKEN=              # fine-grained PAT: Contents R/W, Pull requests R/W
SLACK_WEBHOOK_URL=         # incoming webhook URL; remediation step is skipped (not faked) if unset
GOOGLE_SHEETS_ID=          # target spreadsheet ID; logging step is skipped (not faked) if unset
GOOGLE_SERVICE_ACCOUNT_JSON=  # raw JSON or a path to the service account key file
GROQ_API_KEY=              # optional: enables the LLM Manifest Agent (pom.xml/build.gradle/Pipfile.lock/pyproject.toml/*.csproj); those files are skipped (not faked) if unset

SLACK_CLIENT_ID=           # optional: enables the dashboard's "Connect Slack" OAuth button
SLACK_CLIENT_SECRET=
GOOGLE_CLIENT_ID=          # optional: enables the dashboard's "Connect Google Sheets" OAuth button
GOOGLE_CLIENT_SECRET=
OAUTH_REDIRECT_BASE=http://localhost:8010   # must match the redirect URIs registered with Slack and Google
```

All secrets are read server-side only (`backend/app/config.py`) and never sent to the frontend. A GitHub token pasted into the dashboard is sent only to this app's own backend for that request, and is never logged, stored, or echoed back.

## Demo

[Demo Video](https://drive.google.com/drive/folders/1987xPGfap-lzamntTgDoiii1QXoCVLRz?usp=sharing)

## Limitations

- **Nine manifest formats, six OSV ecosystems** — still not exhaustive (no Docker base-image scanning, no monorepo workspace resolution).
- **Auto-remediation is npm + PyPI only**, and PyPI remediation only covers the deterministic `requirements.txt` parser path (not the LLM-derived `Pipfile.lock`/`pyproject.toml` path). Every other ecosystem is `DETECTION_ONLY` by design — see "Remediation boundary" above.
- **No semver solver**: DepGuard does not resolve a full dependency graph or attempt to satisfy peer-dependency constraints. It patches the specific package entries it targets and tells reviewers to run `npm install` after merging to fully reconcile the npm lockfile.
- **Direct dependencies only for auto-remediation**: transitive-only vulnerabilities are always routed to human review. For crates.io/Go/Packagist/RubyGems, direct-vs-transitive isn't computed at all (would require also parsing the manifest, not just the lockfile) — moot since those ecosystems are detection-only regardless.
- **License analysis is a policy signal, not legal advice**: a small SPDX allow/deny list, not a compatibility engine, and only runs for npm (via deps.dev). Always have a human (ideally legal) review a flagged conflict.
- **EOL detection** only covers the Node.js runtime via `engines.node`, using endoflife.date data as-is (no forecasting).
- **OSV lookups are capped** at 300 unique package@version pairs per ecosystem per analysis for latency; larger monorepos would need pagination.
- **LLM extraction has a fixed 12,000-character input cap** per file to bound token usage; an unusually large `pom.xml` could be truncated (surfaced, not silent — the raw dependency count reported still reflects what was actually sent).
- **A `last_affected`-only OSV range** (the last known-bad version, with no explicit `fixed` version) is deliberately left unresolved rather than guessed into a "next version" by querying the registry's full version list — this shows up as `NEEDS_REVIEW` for a few real-world packages (e.g. `paramiko`, `cryptography` at certain versions) even though *a* fix conceptually exists upstream.
- **OAuth connections are single-user and in-memory**: this was built for a live demo, so there are no per-user sessions and no database. A restart clears the connections, and anyone using the same running server shares them. While the Google OAuth app is in "Testing" mode, only accounts added as test users can connect.
- **Schedules also live in server memory**: they only run while the server is running and disappear on restart. Daily times use the server's local time zone. For always-on monitoring you'd deploy the server somewhere persistent, or call `POST /api/schedules/{id}/run` from an external cron job.

## Safety

- DepGuard never modifies the default branch. All changes land on a `depguard/fix-<dependency>` branch via a pull request that a human must review and merge.
- OAuth tokens (Slack webhook, Google credentials) exist only in server memory, are never written to disk, and are never sent to the browser. OAuth callbacks are protected with a one-time `state` value.
- Scheduled monitoring only analyzes and alerts, and can never open a pull request. A GitHub token given when creating a schedule is kept in memory for that schedule only and is never returned by the API.
- Ground truth for "is this vulnerable" and "what version fixes it" always comes from OSV.dev, never from an LLM guess — in any ecosystem, including the ones whose *extraction* involves an LLM (see "The LLM Manifest Agent" above). The LLM's output is treated as untrusted input and independently verified against the source file and the real package registry before it can influence anything.
- When the system cannot confidently establish a safe remediation (no fixed version, unparsable versions, transitive-only fix, a version that wouldn't satisfy every known advisory, or an ecosystem with no remediation path built) it marks the finding `NEEDS_REVIEW` or `DETECTION_ONLY` and does not open an automatic PR for it — and never drops it from the UI, PR body, Sheets, or Slack just because no code change was made.
- Every action reported in the UI (branch created, files updated, commit created, PR opened, Sheets updated, Slack sent) reflects the real status of that external call. A failed Slack post or Sheets write is shown as failed or skipped, never as a fabricated success, and a reused PR is reported as reused rather than as a new branch and commit.
- No CVE, PR URL, Slack message, Sheets row, or evaluation score in this project is fabricated — everything shown was produced by an actual run of the system against live external services, including the LLM-derived findings (each one traceable to a real registry hit and a real, verbatim line in the source file).

---

Built for a 6.5-hour multi-app AI agent hackathon.
