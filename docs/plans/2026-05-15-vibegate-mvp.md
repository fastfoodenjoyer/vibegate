# Vibegate MVP Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build a Python-first CLI that gives a ship/no-ship pre-deploy security sanity check for AI-generated backend apps and bots.

**Architecture:** Vibegate is an opinionated local scanner, not a full AppSec platform. The scanner walks a project directory, runs deterministic rule checks, optionally wraps external tools later, and emits a concise verdict with findings grouped by severity and template. The first wedge is backend-focused: Telegram bots, FastAPI services, Railway/Docker deployments, webhook handlers, and simple crypto/bot backends.

**Tech Stack:** Python 3.11+, Typer CLI, Rich console output, Pydantic models, pytest, ruff. Packaging via `pyproject.toml` for PyPI/uvx/pipx.

---

## Product positioning

### What Vibegate is

A fast pre-deploy gate for solo builders and small teams shipping AI-generated backend code:

```bash
uvx vibegate scan
vibegate scan --template telegram-bot
vibegate scan --template fastapi-railway
```

It should answer one question clearly:

> Can I ship this, or did my coding agent accidentally publish the keys to the kingdom?

### What Vibegate is not

- Not a replacement for Snyk, Semgrep, CodeQL, TruffleHog, or a professional security review.
- Not a compliance certification.
- Not a broad vulnerability scanner that promises complete coverage.
- Not JS-only; npm can come later as a wrapper if adoption demands it.

### Initial wedge

Start with backend footguns that AI-generated projects frequently produce:

- committed secrets and `.env` files;
- Telegram bot token exposure and webhook misconfiguration;
- unsigned webhook handlers;
- public admin/debug endpoints;
- dangerous CORS and debug mode;
- shell/tool execution from user input;
- Railway/Docker deployment footguns;
- missing dependency audit signal when package manifests exist.

---

## Repository baseline

Current files:

- `README.md`
- `LICENSE`
- `.gitignore`
- `pyproject.toml`
- `src/vibegate/__init__.py`
- `src/vibegate/cli.py`
- `docs/plans/2026-05-15-vibegate-mvp.md`

---

## Implementation principles

1. **TDD:** Every behavior change gets a failing test first.
2. **Deterministic checks first:** LLMs may explain findings later, but primary detection should be rules and parsers.
3. **Useful verdict over noisy findings:** A short ranked list beats a majestic pile of warnings.
4. **Templates over broad claims:** `telegram-bot`, `fastapi-railway`, and `crypto-bot` should be concrete and opinionated.
5. **No secrets in output:** Findings may show variable names and file paths, but must redact secret values.
6. **Local-first:** No network calls in the core scanner unless explicitly enabled later.

---

## Data model

Create `src/vibegate/models.py`.

Core models:

```python
from enum import Enum
from pathlib import Path
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    path: Path | None = None
    line: int | None = None
    evidence: str | None = None
    why_it_matters: str
    fix: str
    tags: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    target: Path
    template: str | None = None
    findings: list[Finding] = Field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(f.severity == Severity.critical for f in self.findings):
            return "DO_NOT_SHIP"
        if any(f.severity == Severity.high for f in self.findings):
            return "REVIEW_BEFORE_SHIP"
        return "SHIP_WITH_CAUTION"
```

---

## Task 1: Add models and verdict tests

**Objective:** Define the stable internal data model and verdict rules.

**Files:**

- Create: `src/vibegate/models.py`
- Create: `tests/test_models.py`

**Step 1: Write failing tests**

Create `tests/test_models.py`:

```python
from pathlib import Path

from vibegate.models import Finding, ScanSummary, Severity


def test_verdict_is_do_not_ship_when_critical_finding_exists():
    summary = ScanSummary(
        target=Path("."),
        findings=[
            Finding(
                rule_id="secret.env",
                title="Committed .env file",
                severity=Severity.critical,
                why_it_matters="Secrets in git can be stolen.",
                fix="Remove the file and rotate exposed secrets.",
            )
        ],
    )

    assert summary.verdict == "DO_NOT_SHIP"


def test_verdict_is_review_before_ship_when_high_finding_exists():
    summary = ScanSummary(
        target=Path("."),
        findings=[
            Finding(
                rule_id="cors.wildcard",
                title="Wildcard CORS",
                severity=Severity.high,
                why_it_matters="Browsers may allow unsafe cross-origin access.",
                fix="Restrict allowed origins.",
            )
        ],
    )

    assert summary.verdict == "REVIEW_BEFORE_SHIP"


def test_verdict_is_ship_with_caution_without_high_or_critical_findings():
    summary = ScanSummary(target=Path("."), findings=[])

    assert summary.verdict == "SHIP_WITH_CAUTION"
```

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_models.py -v
```

Expected: FAIL because `vibegate.models` does not exist.

**Step 3: Implement models**

Create `src/vibegate/models.py` using the data model above.

**Step 4: Run test to verify pass**

```bash
python -m pytest tests/test_models.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/models.py tests/test_models.py
git commit -m "feat: add scan data models"
```

---

## Task 2: Add file collection utilities

**Objective:** Walk a project safely while skipping noisy directories.

**Files:**

- Create: `src/vibegate/files.py`
- Create: `tests/test_files.py`

**Step 1: Write failing tests**

Test requirements:

- `collect_files(root)` returns regular files under root.
- It skips `.git`, `.venv`, `node_modules`, `__pycache__`, `dist`, `build`.
- It returns relative paths or objects that preserve both absolute and relative paths.

Suggested API:

```python
from vibegate.files import collect_files


def test_collect_files_skips_noisy_directories(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("x")

    files = collect_files(tmp_path)

    rels = {f.relative_path.as_posix() for f in files}
    assert rels == {"app.py"}
```

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_files.py -v
```

Expected: FAIL because `vibegate.files` does not exist.

**Step 3: Implement minimal file walker**

Create a `ProjectFile` dataclass with `absolute_path` and `relative_path`. Skip known directories.

**Step 4: Run tests**

```bash
python -m pytest tests/test_files.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/files.py tests/test_files.py
git commit -m "feat: add project file collection"
```

---

## Task 3: Add rule interface and scanner engine

**Objective:** Provide a small rule API and central scanner that runs rules over collected files.

**Files:**

- Create: `src/vibegate/rules/base.py`
- Create: `src/vibegate/scanner.py`
- Create: `tests/test_scanner.py`

**Step 1: Write failing test**

Test a fake rule that always returns one finding:

```python
from pathlib import Path

from vibegate.models import Finding, Severity
from vibegate.rules.base import Rule
from vibegate.scanner import scan_path


class AlwaysFindingRule(Rule):
    rule_id = "test.always"

    def check(self, context):
        return [
            Finding(
                rule_id=self.rule_id,
                title="Always bad",
                severity=Severity.high,
                why_it_matters="Testing scanner aggregation.",
                fix="Use real rules.",
            )
        ]


def test_scan_path_runs_rules_and_returns_summary(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')")

    summary = scan_path(tmp_path, rules=[AlwaysFindingRule()])

    assert summary.target == tmp_path
    assert len(summary.findings) == 1
    assert summary.verdict == "REVIEW_BEFORE_SHIP"
```

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_scanner.py -v
```

Expected: FAIL because scanner/rule modules do not exist.

**Step 3: Implement rule API**

`ScanContext` should include:

- `root: Path`
- `files: list[ProjectFile]`
- `template: str | None`

`Rule` protocol/base class should define:

- `rule_id: str`
- `check(context) -> list[Finding]`

**Step 4: Implement scanner**

`scan_path(path, rules, template=None)`:

- resolves path;
- collects files;
- builds context;
- runs all rules;
- returns `ScanSummary`.

**Step 5: Run tests**

```bash
python -m pytest tests/test_scanner.py -v
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src/vibegate/rules/base.py src/vibegate/scanner.py tests/test_scanner.py
git commit -m "feat: add scanner rule engine"
```

---

## Task 4: Add committed env/secrets rules

**Objective:** Detect committed `.env` files and likely secret literals without printing secret values.

**Files:**

- Create: `src/vibegate/rules/secrets.py`
- Create: `tests/test_rules_secrets.py`

**Step 1: Write failing tests**

Test cases:

1. `.env` is critical.
2. `.env.example` is allowed.
3. `TELEGRAM_BOT_TOKEN=123:abc` finding redacts value.
4. Generic secret-looking assignments are detected in source files.

Expected evidence should include variable name but not full value.

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_rules_secrets.py -v
```

Expected: FAIL.

**Step 3: Implement rules**

Rules:

- `CommittedEnvFileRule`
- `SecretLiteralRule`

Initial token/key names:

- `TELEGRAM_BOT_TOKEN`
- `BOT_TOKEN`
- `DISCORD_TOKEN`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `STRIPE_SECRET_KEY`
- `JWT_SECRET`
- `PRIVATE_KEY`

Redaction pattern:

```text
TELEGRAM_BOT_TOKEN=<redacted>
```

Never include the raw value.

**Step 4: Run tests**

```bash
python -m pytest tests/test_rules_secrets.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/rules/secrets.py tests/test_rules_secrets.py
git commit -m "feat: detect committed secrets"
```

---

## Task 5: Add Telegram bot template rules

**Objective:** Catch common Telegram bot backend deployment mistakes.

**Files:**

- Create: `src/vibegate/rules/telegram.py`
- Create: `tests/test_rules_telegram.py`

**Step 1: Write failing tests**

Initial checks:

1. Detect hardcoded Telegram token pattern in Python files:
   - regex: `\d{8,12}:[A-Za-z0-9_-]{20,}`
   - severity: critical
2. Detect webhook handlers that do not check Telegram secret token header:
   - if file mentions `webhook` and Telegram bot handling but not `X-Telegram-Bot-Api-Secret-Token`, emit high severity.
3. Detect polling and webhook both configured in the same simple file, emit medium severity.

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_rules_telegram.py -v
```

Expected: FAIL.

**Step 3: Implement minimal deterministic checks**

Keep heuristics conservative. False negatives are acceptable for MVP; noisy false positives are not.

**Step 4: Run tests**

```bash
python -m pytest tests/test_rules_telegram.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/rules/telegram.py tests/test_rules_telegram.py
git commit -m "feat: add telegram bot safety checks"
```

---

## Task 6: Add FastAPI/backend web rules

**Objective:** Catch high-signal FastAPI/backend mistakes.

**Files:**

- Create: `src/vibegate/rules/backend.py`
- Create: `tests/test_rules_backend.py`

**Step 1: Write failing tests**

Initial checks:

1. `debug=True` in app/server startup -> high severity.
2. CORS allow origins wildcard with credentials -> high severity.
3. Route path containing `/admin` with no auth/security dependency in nearby file -> medium/high severity.
4. `subprocess.*(... shell=True)` in request-handling file -> high severity.

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_rules_backend.py -v
```

Expected: FAIL.

**Step 3: Implement conservative text-pattern checks**

Prefer clear patterns. Do not attempt full Python AST security analysis in MVP.

**Step 4: Run tests**

```bash
python -m pytest tests/test_rules_backend.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/rules/backend.py tests/test_rules_backend.py
git commit -m "feat: add backend deployment safety checks"
```

---

## Task 7: Add Docker/Railway deployment rules

**Objective:** Catch simple deploy footguns for Railway/Docker projects.

**Files:**

- Create: `src/vibegate/rules/deploy.py`
- Create: `tests/test_rules_deploy.py`

**Step 1: Write failing tests**

Initial checks:

1. `Dockerfile` uses `--reload` in production command -> medium/high.
2. `Dockerfile` exposes common debug ports unexpectedly (`5678`, `9229`) -> medium.
3. `railway.toml` or `nixpacks.toml` command includes reload/debug flags -> medium/high.
4. Missing `.env.example` when source references known env vars -> low/medium actionable warning.

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_rules_deploy.py -v
```

Expected: FAIL.

**Step 3: Implement deploy rules**

Keep all findings actionable with exact file paths and concise fixes.

**Step 4: Run tests**

```bash
python -m pytest tests/test_rules_deploy.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/rules/deploy.py tests/test_rules_deploy.py
git commit -m "feat: add deployment footgun checks"
```

---

## Task 8: Wire default templates and CLI output

**Objective:** Make `vibegate scan` run useful default rules and print a concise verdict.

**Files:**

- Modify: `src/vibegate/cli.py`
- Create: `src/vibegate/templates.py`
- Create: `src/vibegate/reporters/console.py`
- Create: `tests/test_cli.py`

**Step 1: Write failing CLI tests**

Use Typer's `CliRunner`:

- `vibegate scan <tmp_path>` exits 0 when no critical findings.
- Output includes `Verdict:`.
- If a `.env` file exists, output includes `DO_NOT_SHIP` and does not include the secret value.
- `--template telegram-bot` runs Telegram rules.
- `--json` emits parseable JSON.

**Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_cli.py -v
```

Expected: FAIL.

**Step 3: Implement templates**

Templates:

- `backend` default: secrets + backend + deploy
- `telegram-bot`: backend + secrets + deploy + telegram
- `fastapi-railway`: backend + secrets + deploy
- `crypto-bot`: backend + secrets + deploy + telegram, with future placeholder for wallet/private-key checks

**Step 4: Implement console reporter**

Output shape:

```text
Vibegate scan: /path/to/project
Verdict: DO_NOT_SHIP

Critical
1. Committed .env file
   path: .env
   why: Secrets in git can be stolen.
   fix: Remove the file and rotate exposed secrets.
```

**Step 5: Run tests**

```bash
python -m pytest tests/test_cli.py -v
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src/vibegate/cli.py src/vibegate/templates.py src/vibegate/reporters/console.py tests/test_cli.py
git commit -m "feat: wire scan cli"
```

---

## Task 9: Add Markdown report output

**Objective:** Support shareable reports for PRs/issues.

**Files:**

- Create: `src/vibegate/reporters/markdown.py`
- Create: `tests/test_markdown_report.py`
- Modify: `src/vibegate/cli.py`

**Step 1: Write failing tests**

- `render_markdown(summary)` includes verdict, severity sections, paths, fixes.
- `vibegate scan --report report.md` writes a file.

**Step 2: Run failing tests**

```bash
python -m pytest tests/test_markdown_report.py tests/test_cli.py -v
```

Expected: FAIL.

**Step 3: Implement reporter and CLI flag**

CLI flag:

```bash
vibegate scan --report vibegate-report.md
```

**Step 4: Run tests**

```bash
python -m pytest tests/test_markdown_report.py tests/test_cli.py -v
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vibegate/reporters/markdown.py src/vibegate/cli.py tests/test_markdown_report.py tests/test_cli.py
git commit -m "feat: add markdown reports"
```

---

## Task 10: Add CI

**Objective:** Run lint and tests on GitHub.

**Files:**

- Create: `.github/workflows/ci.yml`

**Step 1: Add CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv sync --extra dev
      - run: uv run ruff check .
      - run: uv run pytest -q
```

**Step 2: Run locally first**

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -q
```

Expected: PASS.

**Step 3: Commit**

```bash
git add .github/workflows/ci.yml uv.lock
git commit -m "ci: add test workflow"
```

---

## Task 11: Polish README for first public release

**Objective:** Make the repo understandable and demoable.

**Files:**

- Modify: `README.md`

**Required sections:**

- What Vibegate is.
- Install/run commands.
- Backend-first templates.
- Example output.
- What it catches.
- What it does not guarantee.
- Development commands.
- Roadmap.

**Step 1: Update README**

Include example:

```bash
uvx vibegate scan --template telegram-bot
```

**Step 2: Verify links and commands**

```bash
python -m pytest -q
```

Expected: PASS.

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: expand readme"
```

---

## Release criteria for MVP v0.1.0

- `uvx vibegate scan` works after package publication or from local checkout.
- `vibegate scan --template telegram-bot` catches committed `.env`, hardcoded Telegram token, unsigned webhook, and obvious backend/deploy footguns.
- Output never prints secret values.
- Tests cover every rule family.
- README has a copy-paste demo.
- CI passes on GitHub.

---

## First-user validation plan

### Target users

- Solo builders shipping AI-generated bots/backends.
- Telegram bot developers.
- Indie hackers deploying FastAPI/Railway projects.
- Crypto bot builders who handle private keys/API keys.

### First distribution posts

1. Telegram channel post:
   - “I built a ship/no-ship gate for vibe-coded backend apps.”
   - show `DO_NOT_SHIP` example with leaked `.env` / unsigned webhook.
2. X post:
   - short GIF of `uvx vibegate scan` catching a dangerous Telegram bot.
3. GitHub README/demo repo:
   - intentionally vulnerable bot project.

### Validation success

Within first week after MVP:

- 10+ people run it or ask for a template.
- 3+ concrete issues/feature requests.
- At least one user says it caught something non-obvious before deploy.

### Kill/adjust signal

If people only say “cool” but do not run it, narrow further to one painful template:

- `telegram-bot`
- or `nextjs-supabase` later through an npm wrapper.

---

## Immediate next step

Implement Task 1 with strict TDD, then proceed task-by-task with commits after each coherent slice.
