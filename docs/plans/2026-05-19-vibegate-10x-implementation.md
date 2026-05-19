# Vibegate 10x Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Expand Vibegate from the initial Python/Railway/Telegram wedge into a trusted profile-aware security gate covering the most common vibe-coded backend, frontend, and hosted-service stacks.

**Architecture:** Keep `NO-SHIP` findings high-confidence. Add profiles and rule modules incrementally, with baseline secret/deploy safety always active. Every new blocking rule must have true-positive tests, false-positive regression tests, and at least one CLI or scanner integration test when it affects profile behavior.

**Tech Stack:** Python 3.11+, Typer, Rich, Pydantic, pytest, ruff.

---

## Subagent execution protocol

1. The orchestrator reads this plan once and passes the relevant task text directly to each subagent.
2. Use a fresh implementer subagent per task or tightly-coupled micro-batch. Do not run parallel implementers on tasks that touch the same files.
3. For every behavior change: write/update the failing test first, run the targeted test, implement the smallest change, rerun targeted tests, then run the regression slice named in the task.
4. After each task or micro-batch, run two reviews before continuing:
   - **Spec compliance review** against exact task requirements.
   - **Code quality/security review** after spec compliance passes.
5. If either review requests changes, dispatch a fresh fix subagent with exact findings, then repeat the failed review.
6. Commit after each coherent completed task or micro-batch. Commit only files intentionally changed for that task.
7. Push `main` after each atomic commit only after tests and review pass.

## Global conventions

- Follow `python-engineering-conventions`:
  - no silent exception suppression;
  - f-strings only for Python interpolation/loggers;
  - fix source-of-truth layers, not CLI output symptoms.
- Follow strict TDD for production code.
- Keep public docs public-safe; internal notes belong in ignored `memory/`.
- Prefer high-confidence regex/AST heuristics over speculative broad scanners.
- Advisory rules must not flip verdict to `NO-SHIP`.

## Phase 0: Planning and research artifacts

### Task 0.1: Commit research and implementation plan

**Objective:** Save public research and phased plan so future agents have stable context.

**Files:**
- Create: `docs/research/10x-security-baseline-best-practices.md`
- Create: `docs/plans/2026-05-19-vibegate-10x-implementation.md`

**Verification:**

Run:

```bash
python -m pytest tests/ -q
python -m ruff check .
git status --short
```

**Commit:**

```bash
git add docs/research/10x-security-baseline-best-practices.md docs/plans/2026-05-19-vibegate-10x-implementation.md
git commit -m "docs: add 10x implementation roadmap"
git push origin main
```

## Phase 1: Core rule infrastructure and reporting

### Task 1.1: Add categories, blocking flag, and references to findings

**Objective:** Prepare the model for blocking vs advisory rules without breaking existing output.

**Files:**
- Modify: `src/vibegate/models.py`
- Modify: tests in `tests/test_models.py`, `tests/test_cli.py`

**Requirements:**

- Add optional fields to `Finding`:
  - `category: str | None`
  - `blocking: bool = True`
  - `references: list[str] = []`
- Update verdict logic so only blocking High/Critical findings cause `NO-SHIP`.
- Existing findings remain blocking by default.
- CLI should still print existing output; optionally include category later, but do not create noisy output in this task.

**TDD:**

- Add test: High finding with `blocking=False` yields `SHIP`.
- Add test: High finding with default blocking yields `NO-SHIP`.
- Add test: references default does not share mutable list.

**Commands:**

```bash
python -m pytest tests/test_models.py tests/test_cli.py -q
python -m pytest tests/ -q
python -m ruff check .
```

**Commit:** `feat: support advisory findings`

### Task 1.2: Add profile metadata for stack/platform families

**Objective:** Expand profiles without adding all rules yet.

**Files:**
- Modify: `src/vibegate/profiles.py`
- Modify: `tests/test_profiles.py`

**Requirements:**

Add profiles:

- `nextjs-vercel`
- `vite-frontend`
- `netlify-frontend`
- `supabase`
- `firebase`
- `stripe-webhooks`
- `authjs`
- `clerk`
- `github-actions`
- `node-api`
- `docker-vps`

Detection should be conservative:

- `package.json` + `next` dependency/scripts -> `nextjs-vercel`.
- `vite.config.*` or package scripts using `vite` -> `vite-frontend`.
- `netlify.toml` -> `netlify-frontend`.
- `supabase/` dir or Supabase env names -> `supabase`.
- `firebase.json`, `firestore.rules`, `storage.rules` -> `firebase`.
- Stripe webhook code/env names -> `stripe-webhooks`.
- Auth.js/NextAuth dependency/env names -> `authjs`.
- Clerk dependency/env names -> `clerk`.
- `.github/workflows/*.yml` -> `github-actions`.
- Express/Nest dependencies or common entrypoint patterns -> `node-api`.
- Docker/Compose should map to the existing deployment profile; if renaming from `vps-docker` to `docker-vps`, provide backward-compatible alias or keep both.

**TDD:**

- Add focused detection tests for each profile using minimal files.
- Add false-positive tests where generic words should not activate narrow profiles.

**Commands:**

```bash
python -m pytest tests/test_profiles.py -q
python -m pytest tests/ -q
python -m ruff check .
```

**Commit:** `feat: add 10x stack profiles`

## Phase 2: Frontend/client exposure rules

### Task 2.1: Detect public env secret leakage

**Objective:** Block common client-exposed secret mistakes across Next.js/Vite/React.

**Files:**
- Create: `src/vibegate/rules/frontend.py`
- Modify: `src/vibegate/scanner.py` / rule registration source
- Modify: `src/vibegate/profiles.py`
- Create: `tests/rules/test_frontend.py`

**Requirements:**

Blocking findings for likely secret names/values under public prefixes:

- `NEXT_PUBLIC_*`
- `VITE_*`
- `PUBLIC_*`
- `REACT_APP_*`

Secret-like names:

- `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE`, `DATABASE`, `SERVICE_ROLE`, `OPENAI_API_KEY`, `STRIPE_SECRET`, `CLERK_SECRET`, `AUTH_SECRET`, `NEXTAUTH_SECRET`, `AWS_SECRET`, `R2_SECRET`.

Scan `.env*`, `.js`, `.ts`, `.tsx`, `.jsx`, `.json`, `.toml`, `.yaml`, `.yml`.

Avoid false positives:

- Public non-secret config like `NEXT_PUBLIC_SITE_URL`.
- Placeholder values in examples.
- Documentation that says not to expose secrets unless it includes a real-looking value.

**TDD:**

- True positives for `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, `VITE_STRIPE_SECRET_KEY`, `REACT_APP_OPENAI_API_KEY`.
- False positives for `NEXT_PUBLIC_SITE_URL`, `.env.example` placeholder.
- Scanner integration under `nextjs-vercel` / `vite-frontend` profiles.

**Commands:**

```bash
python -m pytest tests/rules/test_frontend.py tests/test_scanner.py -q
python -m pytest tests/ -q
python -m ruff check .
```

**Commit:** `feat: detect public frontend secret leaks`

### Task 2.2: Detect production source map exposure

**Objective:** Block public production source map exposure in common frontend configs/artifacts.

**Files:**
- Modify: `src/vibegate/rules/frontend.py`
- Modify: `tests/rules/test_frontend.py`

**Requirements:**

Blocking findings for:

- `productionBrowserSourceMaps: true` in Next config.
- `build.sourcemap: true` or `build.sourcemap: "inline"` in Vite config.
- Public `*.map` artifacts under `dist/`, `.next/static/`, `out/`, `build/`.

False positives:

- Source map options set to false.
- `.map` files outside public build dirs.
- Explicit allowlist marker if introduced later; do not add config system in this task.

**Commit:** `feat: detect public frontend source maps`

### Task 2.3: Detect unsafe React HTML rendering

**Objective:** Block obvious XSS sinks when user-controlled data is rendered as HTML.

**Files:**
- Modify: `src/vibegate/rules/frontend.py`
- Modify: `tests/rules/test_frontend.py`

**Requirements:**

Blocking findings for:

- `dangerouslySetInnerHTML` using non-literal expressions without sanitizer evidence.
- `innerHTML`, `outerHTML`, `insertAdjacentHTML` assignments with non-literal data.
- Markdown renderers with raw HTML enabled and no sanitizer evidence.

False positives:

- Literal/static HTML snippets.
- Use of `DOMPurify.sanitize(...)` or obvious sanitizer wrapper.

**Commit:** `feat: detect unsafe frontend HTML sinks`

## Phase 3: Python and Node backend hardening rules

### Task 3.1: Python debug/CORS/admin/docs rules

**Objective:** Add high-confidence Python backend rules from existing roadmap.

**Files:**
- Create: `src/vibegate/rules/python_backend.py`
- Create: `tests/rules/test_python_backend.py`
- Modify: rule registration/profile mapping.

**Blocking findings:**

- FastAPI `allow_origins=["*"]` with `allow_credentials=True`.
- Flask `debug=True`, `FLASK_DEBUG=1`, `app.run(debug=True)`.
- Django `DEBUG=True`, `ALLOWED_HOSTS=["*"]`, weak obvious `SECRET_KEY`.
- Uvicorn `--reload` in production-ish scripts/config.
- FastAPI docs/OpenAPI public for private API if a production profile is active and no disable/auth evidence. If too heuristic, start advisory.

**False positives:**

- Test files/fixtures should not trigger production findings unless scanner target is intentionally a fixture project.
- Debug false in config.
- CORS wildcard without credentials on public unauthenticated examples should be advisory or ignored.

**Commit:** `feat: add python backend safety rules`

### Task 3.2: Shell execution from request input

**Objective:** Block obvious command injection across Python and Node.

**Files:**
- Create or modify: `src/vibegate/rules/code_execution.py`
- Create: `tests/rules/test_code_execution.py`

**Blocking findings:**

- Python `os.system`, `subprocess.*(shell=True)`, `eval`, `exec` using request/query/body/path variables.
- Node `child_process.exec*` using `req.query`, `req.body`, `req.params` or template strings with request data.

**False positives:**

- Static commands with no user input.
- `subprocess.run([...], shell=False)` with fixed argv.
- Test/demo files may still be scanned if they look deployable; keep fixture tests explicit.

**Commit:** `feat: detect request-driven command execution`

### Task 3.3: Node/Express/Nest baseline rules

**Objective:** Add first Node API profile rules.

**Files:**
- Create: `src/vibegate/rules/node_backend.py`
- Create: `tests/rules/test_node_backend.py`

**Blocking findings:**

- `cors({ origin: "*", credentials: true })`.
- `cors({ origin: true, credentials: true })` with no allowlist.
- `app.enableCors({ origin: true, credentials: true })`.
- `app.set("trust proxy", true)` advisory/high depending on deployment profile.
- Production scripts with `NODE_ENV=development`.

**Advisory:**

- Missing Helmet in public Express/Nest app.
- Missing body size limits.

**Commit:** `feat: add node api safety rules`

## Phase 4: Hosted service and webhook rules

### Task 4.1: Stripe and generic signed webhook rules

**Objective:** Block payment/auth webhook handlers that skip signature verification.

**Files:**
- Create: `src/vibegate/rules/webhooks.py`
- Create: `tests/rules/test_webhooks.py`

**Blocking findings:**

- Stripe webhook handler processing events without `Stripe-Signature` and `constructEvent`/equivalent.
- Stripe webhook verification after JSON body parsing where raw body is required.
- Clerk/Svix webhook handler without `svix-id`, `svix-timestamp`, `svix-signature` verification.

**False positives:**

- Generic non-provider webhooks.
- Stripe route that verifies signature correctly.
- Test fixtures with placeholders only.

**Commit:** `feat: detect unsigned provider webhooks`

### Task 4.2: Supabase/Firebase hosted backend rules

**Objective:** Add hosted backend footgun checks.

**Files:**
- Create: `src/vibegate/rules/hosted_backend.py`
- Create: `tests/rules/test_hosted_backend.py`

**Blocking findings:**

- Supabase service-role key in public env/client code.
- SQL migrations with grants to `anon` and no RLS enablement for same table.
- Firebase rules `allow read, write: if true;`.
- Firebase Admin SDK service account private key committed.

**Advisory:**

- Broad Supabase redirect wildcards.
- Firebase broad `request.auth != null` on global collections.

**Commit:** `feat: add hosted backend safety rules`

### Task 4.3: Auth secrets and callback config rules

**Objective:** Catch Auth.js/NextAuth/Clerk secret misconfiguration.

**Files:**
- Create or modify: `src/vibegate/rules/auth.py`
- Create: `tests/rules/test_auth.py`

**Blocking findings:**

- Auth.js/NextAuth dependency or env usage but missing/weak `AUTH_SECRET` / `NEXTAUTH_SECRET` in production env/deploy config.
- Secret shorter than 32 chars or obvious placeholder.
- `NEXTAUTH_URL` / callback/base URL still localhost in production-ish config.
- Clerk secret key in public env/client code.

**Advisory:**

- Reverse-proxy deployment with Auth.js but no `AUTH_TRUST_HOST=true`.

**Commit:** `feat: add auth configuration rules`

## Phase 5: Deployment, CI, storage, and infrastructure rules

### Task 5.1: Docker/VPS/Coolify exposure rules

**Objective:** Block common self-hosting exposure mistakes.

**Files:**
- Create: `src/vibegate/rules/deployment.py`
- Create: `tests/rules/test_deployment.py`

**Blocking findings:**

- Docker socket mount into app service.
- Docker daemon `tcp://0.0.0.0:2375`.
- Compose `ports:` exposing DB/cache/admin ports publicly: 5432, 6379, 27017, 3306, 9200, 15672, etc.
- Public HTTP-only reverse proxy config without HTTPS redirect/TLS evidence where detectable.

**False positives:**

- Loopback-only ports like `127.0.0.1:5432:5432`.
- Internal `expose:` only.

**Commit:** `feat: detect docker deployment exposures`

### Task 5.2: DB/Redis/object storage rules

**Objective:** Block obvious data-plane credential and public exposure mistakes.

**Files:**
- Modify or create: `src/vibegate/rules/data_services.py`
- Create: `tests/rules/test_data_services.py`

**Blocking findings:**

- Real-looking DB URLs with credentials in tracked source.
- DB URLs under public env prefixes.
- `sslmode=disable` / `ssl=false` on production DB URLs.
- Redis config `bind 0.0.0.0` + `protected-mode no` or no auth.
- S3 bucket policy with principal `*` and write permissions.
- R2/S3 access keys in frontend/client code.

**Commit:** `feat: add data service exposure rules`

### Task 5.3: GitHub Actions deploy hardening rules

**Objective:** Add CI/deploy profile checks.

**Files:**
- Create: `src/vibegate/rules/github_actions.py`
- Create: `tests/rules/test_github_actions.py`

**Blocking findings:**

- `pull_request_target` workflow checks out PR code and has secrets/write token indicators.
- `permissions: write-all` in deploy/release workflows.
- Production deploy job runs on all branches/PRs without environment protection.
- Workflow dumps env/secrets via `env`, `printenv`, `set -x`, `echo $SECRET`.

**Advisory:**

- Third-party actions not pinned to SHA.
- No production environment reviewers.

**Commit:** `feat: add github actions safety rules`

## Phase 6: Reports, docs, and validation

### Task 6.1: Markdown report output

**Objective:** Implement README-promised `--report report.md` output.

**Files:**
- Modify: `src/vibegate/cli.py`
- Create: `src/vibegate/reporting.py`
- Create: `tests/test_reporting.py`
- Modify: `tests/test_cli.py`

**Requirements:**

- `vibegate scan --report report.md` writes a Markdown report.
- Report includes target, profiles, verdict, summary counts, findings with remediation and references.
- CLI still prints concise output.
- Nonexistent report parent should fail clearly.

**Commit:** `feat: add markdown scan reports`

### Task 6.2: Update README public docs

**Objective:** Align README with implemented profile UX and actual shipped behavior.

**Files:**
- Modify: `README.md`

**Requirements:**

- Replace old `--template` examples with `--profile` examples.
- List shipped profiles/rules accurately.
- Include “not a replacement for real security review” caveat.
- Include validation examples and contribution guidance for rule quality.

**Commit:** `docs: update profile scanning docs`

### Task 6.3: Real-project validation shortlist

**Objective:** Prepare candidate real projects for user approval before cloning/scanning anything unfamiliar.

**Candidate categories:**

- Python Telegram/FastAPI bots.
- Railway example apps.
- Next.js + Vercel starters.
- Supabase example apps.
- Docker Compose self-hosting templates.
- Node/Express webhook examples.

**Output:**

Ask user to approve 3-5 targets from a shortlist before cloning. Do not install arbitrary dependencies; use static scanning only unless user approves deeper validation.

## Suggested execution order

1. Phase 0 docs.
2. Phase 1 model/profile infrastructure.
3. Phase 2.1 public env secret leakage.
4. Phase 3.1 Python backend safety rules.
5. Phase 5.1 Docker/Coolify/VPS exposure rules.
6. Phase 4.1 Stripe/webhook signatures.
7. Phase 2.2 source maps.
8. Phase 5.3 GitHub Actions rules.
9. Phase 6 report/docs.
10. Remaining service/frontend hardening in smaller follow-up commits.

This order maximizes high-confidence value early while avoiding the classic “universal scanner” tragedy: a huge rule set with the judgment of a caffeinated autocomplete.
