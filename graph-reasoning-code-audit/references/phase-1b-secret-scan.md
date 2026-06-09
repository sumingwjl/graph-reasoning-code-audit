# Phase 1b: Secret Scan Track

Use this phase for hardcoded secret discovery. Secret scanning is a deterministic
tool track, not a graph-reasoning task. The LLM should judge context and impact,
not try to discover secrets by reading the whole repo.

Run this phase early, in parallel with SCA and graph context work.

## Betterleaks First

Prefer Betterleaks when available. If `betterleaks` is not in `PATH`, ask the
user for the executable path and use that absolute path.

Run both Git-history and current-directory scans when the repo has Git history:

```bash
# Create the output directory first. Betterleaks does not create parent
# directories for --report-path.
mkdir -p /path/to/repo/.audit
# PowerShell:
# New-Item -ItemType Directory -Force -Path C:\path\to\repo\.audit

betterleaks git /path/to/repo \
  --report-path /path/to/repo/.audit/betterleaks-git.json \
  --report-format json \
  --exit-code 0

betterleaks dir /path/to/repo \
  --report-path /path/to/repo/.audit/betterleaks-dir.json \
  --report-format json \
  --exit-code 0
```

If the local Betterleaks version uses different flag names, run
`betterleaks --help`, `betterleaks git --help`, and `betterleaks dir --help`,
then preserve the same artifact contract:

- raw Git scan: `.audit/betterleaks-git.json`
- raw directory scan: `.audit/betterleaks-dir.json`
- normalized findings: `.audit/secret_findings.json`
- Markdown summary: `.audit/secret_report.md`

Betterleaks may return a non-zero exit code when secrets are found. Treat a
valid JSON report as successful evidence collection.

On Windows or sandboxed agents, `betterleaks git` can fail with Git
`safe.directory` / dubious ownership errors. Do not change global Git config
without user approval. Prefer a one-command environment override or ask the user
to mark the repository safe, then rerun the Git-history scan. Directory scan can
still proceed while Git-history scan is blocked.

## Normalize and Render

Normalize each raw Betterleaks result. If both Git and directory scans exist,
normalize them separately and merge by `fingerprint` or `path:line:rule_id`.

```bash
python scripts/normalize_betterleaks.py \
  --betterleaks-results /path/to/repo/.audit/betterleaks-git.json \
  --repo-root /path/to/repo \
  --source-kind betterleaks-git \
  --output /path/to/repo/.audit/secret_findings.git.json

python scripts/normalize_betterleaks.py \
  --betterleaks-results /path/to/repo/.audit/betterleaks-dir.json \
  --repo-root /path/to/repo \
  --source-kind betterleaks-dir \
  --output /path/to/repo/.audit/secret_findings.dir.json

python scripts/merge_secret_findings.py \
  --inputs /path/to/repo/.audit/secret_findings.git.json /path/to/repo/.audit/secret_findings.dir.json \
  --output /path/to/repo/.audit/secret_findings.json

python scripts/render_secret_report.py \
  --secret-findings /path/to/repo/.audit/secret_findings.json \
  --output /path/to/repo/.audit/secret_report.md
```

If Betterleaks is unavailable, use Gitleaks or TruffleHog as fallback and adapt
their JSON into the same `secret_findings.json` schema. If no scanner is
available, use `rg` as a last-resort keyword pass for project-specific names:

```bash
rg -n --hidden --glob '!/.git/**' --glob '!/.audit/**' \
  "(?i)(secret|token|apikey|api_key|private_key|client_secret|jwt_secret|issuerSigningKey|connectionString|password)" \
  /path/to/repo
```

## Secret Validation Rules

Scanner matches are not automatically confirmed vulnerabilities. During source
validation, decide whether each high-value match is:

- effective secret: real key/token/password/private key used by runtime code;
- exposed credential: committed to source, Git history, package, container, or
  deployable artifact;
- placeholder/test fixture: dummy value, sample config, test-only credential, or
  intentionally inert fixture;
- false positive: not a secret or not sensitive.

Confirmed secret vulnerabilities require concrete impact, such as JWT/session
forgery, cloud/service access, database access, webhook/API abuse, private-key
misuse, or cross-tenant/admin access. Otherwise keep the item in
`needs_review`, `false_positive`, or optional hardening notes.

## How It Feeds Later Phases

- Phase 2 should use `secret_findings.json` to create F-class hypotheses for
  high-confidence secret exposure, especially validated or runtime-used secrets.
- Phase 4 should attach `secret_findings.json` as auxiliary context in the
  source-validation packet.
- Final reports must include `secret_report.md` or a Secret Exposure section,
  separated from generic SCA and source-code logic bugs.
