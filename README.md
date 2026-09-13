# DepGuard

**AI Dependency Risk & License-Conflict Triage Agent**

> Point DepGuard at a GitHub repository. It analyzes npm dependencies, identifies actionable security/EOL/license risks, decides the smallest safe remediation, executes it through GitHub, records the result, and notifies the engineering team.

## Problem

Engineering teams accumulate vulnerable, end-of-life, or license-incompatible dependencies faster than anyone reviews them. Dependabot-style tools surface alerts; they don't reason about *which* upgrades are actually safe to apply automatically, and they don't close the loop with the rest of the team's tools (issue tracker of record, notification channel, audit log).

## Solution

DepGuard is a narrow, single-ecosystem (npm) agent that:

1. Reads a repository's real `package.json` / `package-lock.json` from GitHub.
2. Checks every resolved dependency against **OSV.dev** (vulnerabilities), **deps.dev** (license metadata), and **endoflife.date** (Node.js runtime support window).
3. Applies a small set of deterministic, conservative policy rules to decide, per finding, whether it's safe to auto-remediate or needs a human.
4. On explicit user confirmation, opens a **real GitHub pull request** on a new branch — never touching the default branch directly.
5. Logs the remediation to a **Google Sheet** and posts a **Slack** notification.
6. Is judged on a 20-case evaluation harness that runs against live external data, not canned answers.

## How It Works

```
GitHub repository
   -> DepGuard agent reads package.json + package-lock.json
   -> OSV.dev vulnerability lookup (batch query, ground truth for "is this vulnerable")
   -> deps.dev license lookup for direct dependencies
   -> endoflife.date check on the Node.js engines range
   -> deterministic policy decision (auto-remediate / needs review / informational)
   -> [user clicks "Create Remediation PR"]
   -> new branch -> package.json + package-lock.json patched -> commit -> PR opened
   -> Google Sheets remediation log row appended
   -> Slack notification sent
```

Every step is recorded in an execution trace shown in the UI (`Repository discovered -> Lockfile found -> Dependencies parsed -> OSV query -> deps.dev query -> EOL check -> Decision made -> Safety check -> Branch created -> Files updated -> Commit created -> PR created -> Sheets updated -> Slack sent -> Final result`), so every claim on screen is traceable to an actual step DepGuard ran.

## Integrations

| # | Integration | Role | Type |
|---|---|---|---|
| 1 | **GitHub** | Read repo/lockfile, create branch, patch files, commit, open PR | Action (write) |
| 2 | **Slack** | Notify the team when a remediation completes | Action (write) |
| 3 | **Google Sheets** | Append-only remediation log (audit trail) | Action (write) |
| 4 | **OSV.dev** | Ground truth for vulnerability existence + fixed versions | Intelligence (read) |
| 5 | **deps.dev** | SPDX license metadata for direct dependencies | Intelligence (read) |
| 6 | **endoflife.date** | Node.js runtime support/EOL status | Intelligence (read) |

These six form one pipeline, not six demos: the GitHub read feeds OSV/deps.dev/endoflife.date, whose combined output drives the GitHub write, which in turn drives the Sheets and Slack actions.

## Agent Decision Logic

DepGuard does **not** ask an LLM whether a package is vulnerable. Vulnerability existence and fixed versions come from OSV.dev; everything else is a small, explicit, deterministic rule set in [`backend/app/policy.py`](backend/app/policy.py):

- **Multi-advisory safety**: if several distinct advisories affect the same version, the target version must satisfy *all* of them (the max of each advisory's own minimum fix — not the min across the pool). A version that only fixes the cheapest advisory is rejected.
- **Direct-only auto-remediation**: only direct dependencies (present in `package.json`) are eligible for an automatic PR. Transitive-only fixes are flagged `NEEDS_REVIEW` — this MVP does not run a dependency resolver.
- **No confident fix -> no auto-action**: if OSV reports a vulnerability with no fixed version, or the current/fixed version strings can't be parsed as plain semver, the finding is routed to human review. DepGuard never guesses a version.
- **License conflict is a signal, not a verdict**: a small SPDX allow/deny list (`policy.PERMISSIVE_LICENSES` / `policy.COPYLEFT_LICENSES`) flags a permissive-project + copyleft-dependency combination for human/legal review. **This is not legal advice** and does not attempt a general license-compatibility engine.
- **EOL is informational**: Node.js EOL/nearing-EOL findings are surfaced but never trigger an automatic code change.
- **Bundled PR = union of auto-approved findings only**: "Create Remediation PR" opens one PR covering every finding that individually cleared the bar above; anything that didn't clear the bar is listed as skipped/needs-review in the same response, never silently dropped.

## Reliability & Evaluation

Reliability is a first-class feature, not an afterthought. [`eval/gold_set.json`](eval/gold_set.json) defines 20 cases; `GET /api/eval` runs all of them against **live** external services on every call (no cached/mocked answers) and returns measured metrics:

- **Vulnerability presence/absence** across 14 real npm package@version pairs with published OSV.dev advisories, plus 2 clean negative controls.
- **Fixed-version correctness**, including a transitive-dependency case that must resolve to `NEEDS_REVIEW` even though a fix exists.
- **Policy unit cases** for the "no fixed version published" rule and both branches of the license-conflict rule, run directly against the deterministic policy functions (no external API involved, labeled `policy_unit_*` so it's clear what is and isn't hitting live data).
- **EOL classification** against real endoflife.date data for both an EOL (Node 12) and a supported (Node 22) runtime.

Last recorded run (see the in-app "Reliability & Evaluation" panel for a live re-run): **20/20 cases passed, 100% accuracy, 100% precision/recall on vulnerability detection, 0 unsafe automatic upgrades.**

While building this harness, it caught two real bugs before the demo: a policy bug where DepGuard would pick a fix version that satisfied only the cheapest of several advisories (fixed by taking the max of each advisory's own minimum fix), and a stale assumption in the gold set itself — `lodash@4.17.21`, long treated as "the patched version," turned out to have a real, newly published OSV.dev advisory (`GHSA-f23m-r3pf-42rh`, fixed in 4.18.0). That case is kept in the gold set on purpose, as proof the system reasons from live data rather than memorized versions.

All numbers shown anywhere in the app are computed from an actual run in that process; nothing is hardcoded.

## Setup

### Prerequisites
- Python 3.11+
- A GitHub [fine-grained personal access token](https://github.com/settings/personal-access-tokens) with **Contents: Read and write** and **Pull requests: Read and write**, scoped to the repo(s) you'll analyze/remediate.
- (Optional) A Slack incoming webhook URL.
- (Optional) A Google Cloud service account with access to a target Google Sheet.

### Run it

```bash
cd backend
pip install -r requirements.txt
cp ../.env.example ../.env   # fill in GITHUB_TOKEN at minimum
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000/`.

### Try it against the demo repo

Analyze **https://github.com/priyanshiiitr/depguard-demo-vulnerable** (source also mirrored in [`demo-repo-vulnerable/`](demo-repo-vulnerable/)) — it deliberately pins `lodash@4.17.15`, `minimist@1.2.5`, and `axios@0.21.0`, each with a real, fixable OSV.dev advisory, plus a Node.js `engines` range that is already end-of-life.

This exact flow was run for real while building DepGuard: analysis found 5 findings (3 direct vulnerabilities auto-remediable, 1 transitive vulnerability correctly routed to human review, 1 informational EOL flag) and clicking "Create Remediation PR" opened a real pull request, appended real rows to Google Sheets, and delivered a real Slack notification.

## Environment Variables

See [`.env.example`](.env.example):

```
GITHUB_TOKEN=              # fine-grained PAT: Contents R/W, Pull requests R/W
SLACK_WEBHOOK_URL=         # incoming webhook URL; remediation step is skipped (not faked) if unset
GOOGLE_SHEETS_ID=          # target spreadsheet ID; logging step is skipped (not faked) if unset
GOOGLE_SERVICE_ACCOUNT_JSON=  # raw JSON or a path to the service account key file
```

The token is read server-side only (`backend/app/config.py`) and is never sent to the frontend.

## Demo

[Demo Video](YOUR_VIDEO_URL)

## Limitations

- **Single ecosystem**: npm only, via `package.json` + `package-lock.json`. No Python/Java/Go/Docker support.
- **No semver solver**: DepGuard does not resolve a full dependency graph or attempt to satisfy peer-dependency constraints. It patches the specific package entries it targets and tells reviewers to run `npm install` after merging to fully reconcile the lockfile.
- **Direct dependencies only for auto-remediation**: transitive-only vulnerabilities are always routed to human review in this MVP.
- **License analysis is a policy signal, not legal advice**: a small SPDX allow/deny list, not a compatibility engine. Always have a human (ideally legal) review a flagged conflict.
- **EOL detection** only covers the Node.js runtime via `engines.node`, using endoflife.date data as-is (no forecasting).
- **OSV lookups are capped** at 300 unique package@version pairs per analysis for latency; larger monorepos would need pagination.

## Safety

- DepGuard never modifies the default branch. All changes land on a `depguard/fix-<dependency>` branch via a pull request that a human must review and merge.
- Ground truth for "is this vulnerable" and "what version fixes it" always comes from OSV.dev, never from an LLM guess.
- When the system cannot confidently establish a safe remediation (no fixed version, unparsable versions, transitive-only fix, or a version that wouldn't satisfy every known advisory), it marks the finding `NEEDS_REVIEW` and does not open an automatic PR for it.
- Every action reported in the UI (branch created, files updated, commit created, PR opened, Sheets updated, Slack sent) reflects the real status of that external call; a failed Slack post or Sheets write is shown as failed/skipped, never as a fabricated success.
- No CVE, PR URL, Slack message, Sheets row, or evaluation score in this project is fabricated — everything shown was produced by an actual run of the system against live external services.

---

Built for a 6.5-hour multi-app AI agent hackathon.
