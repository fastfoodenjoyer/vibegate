# Vibegate 10x Security Baseline Best Practices

Research snapshot for expanding Vibegate from the first Python/Railway/Telegram wedge into a broader vibe-coded app pre-deploy gate.

## Product rule

Vibegate should block only high-confidence, high-impact mistakes. Advisory findings are useful, but `NO-SHIP` must stay trusted. Broad but noisy coverage is not a product; it is a smoke alarm taped to a blender.

## Severity model

### NO-SHIP / blocking

Use for issues that can directly expose credentials, private data, payment/auth integrity, production deploy authority, or privileged infrastructure:

- Real-looking secrets in tracked source, client env prefixes, Docker/CI config, or generated frontend bundles.
- Missing webhook signature/secret validation for payment/auth/bot webhooks.
- Debug/dev servers or debug mode in production deploy config.
- Wildcard/reflected CORS with credentials or cookie/session auth.
- Shell command execution from request-controlled input.
- Docker socket or private databases/caches exposed to public interfaces.
- Public admin/debug/metrics endpoints without visible auth/network restriction.
- Hosted-backend data exposure: Supabase tables exposed without RLS, Firebase rules open to all.
- Frontend source maps/public env/SSR boundary mistakes that expose source or secrets.
- GitHub Actions patterns that expose secrets to untrusted PR code.

### Advisory

Use for hardening gaps that may be legitimate depending on architecture:

- Missing secondary headers such as Permissions-Policy, COOP/CORP/COEP.
- Weak but present CSP.
- Public docs/OpenAPI for intentionally public APIs.
- Missing rate limits on auth endpoints.
- Missing HSTS when TLS is handled by platform but not visible in repo.
- Actions not pinned to SHAs.
- No App Check / no webhook idempotency / no environment protection.

## Frontend / Next.js / Vite / React / Vercel / Netlify

### Client-exposed secrets

Blocking rules:

- Flag likely secrets in public env prefixes:
  - `NEXT_PUBLIC_*`
  - `VITE_*`
  - `PUBLIC_*`
  - `REACT_APP_*`
- Secret-like names include `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE`, `DATABASE`, `SERVICE_ROLE`, `OPENAI_API_KEY`, `STRIPE_SECRET`, `CLERK_SECRET`, `AUTH_SECRET`, `NEXTAUTH_SECRET`, `AWS_SECRET`, `R2_SECRET`.
- Flag `next.config.js` / `vite.config.*` env blocks that embed secret-like values.

Why:

- Next.js public env vars are inlined into browser JS at build time.
- Vite exposes `VITE_*` variables to client code.

Sources:

- Next.js environment variables: https://nextjs.org/docs/pages/guides/environment-variables
- Vite env and modes: https://vite.dev/guide/env-and-mode
- Vercel sensitive env vars: https://vercel.com/docs/environment-variables/sensitive-environment-variables

### Production source maps

Blocking rules:

- Next.js: `productionBrowserSourceMaps: true` in production config.
- Vite: `build.sourcemap: true` or `build.sourcemap: "inline"` for public production deploys.
- Public deploy artifacts containing `*.map` under `dist/`, `.next/static/`, `out/`, or `build/` without explicit allowlist/protected source map setup.

Advisory:

- Source maps can be acceptable for protected previews or when uploaded to an error tracker and removed from public artifacts.

Sources:

- Next.js `productionBrowserSourceMaps`: https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps
- Vite build sourcemap: https://vite.dev/config/build-options
- Vercel Protected Source Maps: https://vercel.com/docs/deployment-protection/protected-source-maps
- Vercel conformance source maps: https://vercel.com/docs/conformance/rules/nextjs_no_production_source_maps

### Security headers

Blocking rules for production frontend routes if no deploy mechanism is visible:

- Missing CSP mechanism entirely for non-trivial apps.
- Missing `X-Content-Type-Options: nosniff`.
- Missing clickjacking protection (`Content-Security-Policy: frame-ancestors ...` or `X-Frame-Options`).
- Missing `Strict-Transport-Security` where custom HTTPS production domain is visible.

Advisory:

- Missing `Permissions-Policy`.
- Missing COOP/CORP/COEP.
- Weak CSP with excessive `unsafe-inline` / `unsafe-eval`.

Sources:

- OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- Next.js CSP guide: https://nextjs.org/docs/app/guides/content-security-policy
- Vercel missing security headers: https://vercel.com/docs/conformance/rules/nextjs_missing_security_headers
- Netlify headers: https://docs.netlify.com/manage/routing/headers/

### Auth/session/cookies and CSRF

Blocking rules:

- Session/auth cookies missing `HttpOnly`.
- Session/auth cookies missing `Secure` in production.
- Session/auth cookies missing `SameSite=Lax` / `Strict`, unless `SameSite=None; Secure` is clearly required.
- Auth/access/refresh/JWT tokens stored in `localStorage`, `sessionStorage`, IndexedDB, or non-HttpOnly cookies.
- Cookie-authenticated mutating endpoints with no visible CSRF token/header/origin validation.

Sources:

- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP CSRF Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP HTML5 Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html

### CORS

Blocking rules:

- `Access-Control-Allow-Origin: *` with credentials intent.
- Dynamic origin reflection without allowlist.
- Framework equivalents:
  - Express/Nest `cors({ origin: true, credentials: true })`.
  - FastAPI `allow_origins=["*"]` with `allow_credentials=True`.
  - Flask-CORS broad defaults with credentials.
  - Django `CORS_ALLOW_ALL_ORIGINS=True` with credentials.

Sources:

- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS
- MDN Access-Control-Allow-Credentials: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials

### SSR/API boundary

Blocking rules:

- Secret-bearing modules imported from files marked `"use client"`.
- DB/admin SDK/service-role clients imported into client components.
- Server-only env vars referenced in client paths.
- API keys/secrets passed as props to client components.
- Server actions/API routes trusting client-provided user IDs, roles, prices, or ownership without server-side authorization checks.

Advisory:

- Recommend `import "server-only"` in modules that access secrets, DBs, private APIs, or privileged SDKs.

Sources:

- Next.js composition patterns: https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns
- Vercel Academy env/security: https://vercel.com/academy/nextjs-foundations/env-and-security

### React unsafe rendering

Blocking rules:

- `dangerouslySetInnerHTML` with non-literal/user-controlled data and no sanitizer.
- `innerHTML`, `outerHTML`, `insertAdjacentHTML` with user-controlled data.
- Markdown/HTML renderers with raw HTML enabled and no sanitizer.
- User-controlled URLs used in `href`, `src`, redirects, or `window.location` without protocol allowlist.

Sources:

- React `dangerouslySetInnerHTML`: https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### Vite dev/preview exposure

Blocking rules:

- `vite --host 0.0.0.0` in production start scripts.
- `server.host: true` / `0.0.0.0` in deployment-intended configs.
- `server.allowedHosts: true`.
- `server.fs.strict: false`.

Sources:

- Vite server options: https://vite.dev/config/server-options
- Vite preview options: https://vite.dev/config/preview-options

## Hosted services / Supabase / Firebase / Stripe / Auth

### Supabase

Blocking rules:

- Supabase service-role or secret key in frontend/client-exposed code.
- `SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_SECRET_KEY` under public env prefixes.
- SQL/migrations that expose tables to `anon` or `authenticated` without `enable row level security`.
- Broad grants to `anon` on sensitive tables.
- Production auth URLs still pointing to localhost.

Advisory:

- Broad redirect URL wildcards in production.
- Public schema used as broad API surface.
- Data API enabled when app appears to use only server-side DB access.

Sources:

- Supabase securing data: https://supabase.com/docs/guides/database/secure-data
- Supabase securing API: https://supabase.com/docs/guides/api/securing-your-api
- Supabase RLS: https://supabase.com/docs/guides/database/postgres/row-level-security
- Supabase Auth redirect URLs: https://supabase.com/docs/guides/auth/redirect-urls

### Firebase

Blocking rules:

- Firestore/Storage rules: `allow read, write: if true;`.
- Realtime DB rules: `".read": true`, `".write": true`.
- Broad `request.auth != null` read/write rules for sensitive global data.
- Firebase Admin SDK service account JSON committed or imported into frontend/client code.

Advisory:

- Public Firebase API key without domain/API restriction evidence.
- No App Check evidence for direct client access.

Sources:

- Firebase Security Rules basics: https://firebase.google.com/docs/rules/basics
- Firebase Admin SDK and rules: https://firebase.blog/posts/2019/03/firebase-security-rules-admin-sdk-tips/

### Stripe and signed webhooks

Blocking rules:

- Stripe webhook route processes events without `Stripe-Signature` verification and `constructEvent(...)`.
- Stripe webhook verification uses parsed/mutated JSON body instead of raw body.
- Stripe secrets in client-exposed env or frontend code: `sk_live_`, `sk_test_`, `rk_live_`, `whsec_`.
- Payment/auth provider webhook routes without signature header verification.

Advisory:

- No event ID deduplication/idempotency evidence.
- Stripe CLI webhook secret mixed with production config.

Sources:

- Stripe webhook signatures: https://docs.stripe.com/webhooks/signature
- Stripe webhooks: https://docs.stripe.com/webhooks

### Auth.js / NextAuth / Clerk

Blocking rules:

- Auth.js/NextAuth used without production `AUTH_SECRET` / `NEXTAUTH_SECRET`.
- Weak/placeholder auth secret shorter than 32 chars.
- OAuth client secrets in public env prefixes.
- Production callback/base URL still localhost.
- Clerk/Svix webhooks without signature verification headers: `svix-id`, `svix-timestamp`, `svix-signature`.
- `CLERK_SECRET_KEY` in frontend/client code.

Advisory:

- Reverse-proxy deployment without `AUTH_TRUST_HOST=true` / explicit trusted host config where required.
- Protected routes appear to lack auth middleware.

Sources:

- Auth.js deployment: https://authjs.dev/getting-started/deployment
- NextAuth options: https://next-auth.js.org/configuration/options
- Clerk webhooks: https://clerk.com/docs/webhooks/overview

## Object storage / DB / Redis / admin surfaces

### S3 / R2

Blocking rules:

- S3 public access blocks disabled for private-looking buckets.
- Bucket policy allows principal `*` on `s3:GetObject`, `s3:PutObject`, or broader for private-looking buckets.
- R2 `r2.dev` public URL enabled for production/private assets.
- S3/R2 access keys in frontend/client code.

Advisory:

- Public bucket without static asset purpose documented.
- R2 production custom domain without WAF/Access/bot-control note.

Sources:

- S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- Cloudflare R2 public buckets: https://developers.cloudflare.com/r2/buckets/public-buckets/

### Database URLs

Blocking rules:

- Real-looking `postgres://`, `postgresql://`, `mysql://`, `mongodb+srv://`, `redis://` URLs with credentials in tracked source.
- DB URLs under public env prefixes.
- Production DB URLs with `sslmode=disable` / `ssl=false`.
- Runtime app DB user appears to be `postgres`, `root`, `admin`, `supabase_admin`, or migration owner.

Advisory:

- Same DB URL used across staging/production deploy configs.
- DB URLs in comments/examples that look real.

Sources:

- PostgreSQL SSL: https://www.postgresql.org/docs/current/ssl-tcp.html

### Redis

Blocking rules:

- `bind 0.0.0.0` with `protected-mode no` or no auth.
- Production `redis://host:6379` without password/TLS where host is not localhost/private.
- Redis URL under public env prefixes.

Advisory:

- No ACL/command restriction for shared/multitenant Redis.

Source:

- Redis security: https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### Admin / metrics / debug endpoints

Blocking rules:

- Production routes exposing unauthenticated `/admin`, `/debug`, `/__debug`, `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/metrics`, `/swagger`, `/api-docs`, `/graphql`, `/graphiql`, `/phpmyadmin`, `/pgadmin`, `/flower`.
- Public Prometheus `/metrics` without auth/network restriction.
- Default credentials like `admin/admin`, `admin:password`, `root/root`, `changeme` in admin config/docs.

Advisory:

- Public OpenAPI/Swagger for private APIs.
- Health/status endpoints leaking dependency URLs, versions, env, or internals.

Sources:

- Prometheus security model: https://prometheus.io/docs/operating/security/

## Deployment / Railway / Render / Fly / Coolify / Docker / VPS

### Railway

Blocking/advisory split:

- Block: committed `.env`, public URL used for DB/internal services when private networking is expected, internal-only services exposed publicly.
- Advisory: prefer private networking for service-to-service traffic, use Railway variables for secrets.

Sources:

- Railway best practices: https://docs.railway.com/overview/best-practices
- Railway private networking: https://docs.railway.com/networking/private-networking
- Railway public networking: https://docs.railway.com/networking/public-networking

### Render / Fly.io

Blocking rules:

- Internal-only service deployed as public web service.
- Production internal app allocated public IP/domain unnecessarily.
- App trusts arbitrary forwarded headers in public topology.

Advisory:

- Prefer private services/networks for service-to-service communication.
- Use platform secrets/env instead of committed files.

Sources:

- Render web/private services: https://render.com/docs/web-services
- Render env vars/secrets: https://render.com/docs/configure-environment-variables
- Fly private networking: https://fly.io/docs/networking/private-networking/
- Flycast: https://fly.io/docs/networking/flycast/

### Coolify / Docker / VPS

Blocking rules:

- Docker Compose `ports:` exposes DB/cache/internal services on public interface.
- Docker socket mounted into arbitrary app containers.
- Docker daemon TCP `2375` exposed.
- Public HTTP app without HTTPS redirect/TLS termination evidence.
- Reverse proxy forwards/trusts untrusted `X-Forwarded-*` headers.
- App directly reachable on backend port, bypassing reverse proxy auth/TLS.

Advisory:

- Containers run as root.
- Missing read-only filesystem / dropped capabilities / resource limits.
- Missing firewall rules.

Sources:

- Docker port publishing: https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/
- Coolify Compose warning: https://coolify.io/docs/knowledge-base/docker/compose
- Coolify firewall: https://coolify.io/docs/knowledge-base/server/firewall
- NGINX reverse proxy: https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/
- Caddy reverse proxy: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- Caddy trusted proxies: https://caddyserver.com/docs/json/apps/http/servers/routes/handle/reverse_proxy/trusted_proxies

## Backend stacks

### Python FastAPI / Flask / Django

Blocking rules:

- FastAPI/Starlette CORS wildcard with credentials.
- FastAPI docs/OpenAPI public for private API without auth/env guard.
- Uvicorn `--reload` in production deploy scripts.
- Uvicorn `--proxy-headers --forwarded-allow-ips="*"` in untrusted topology.
- Flask `debug=True`, `FLASK_DEBUG=1`, dev server in production.
- Flask-CORS broad defaults with credentials.
- Django `DEBUG=True`, weak/committed `SECRET_KEY`, `ALLOWED_HOSTS=["*"]`.
- Django missing `SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE` for HTTPS production.
- Shell execution/eval/exec from request input.

Advisory:

- Missing rate limits on auth endpoints.
- Missing HSTS / HTTPS redirect if platform/proxy not visible.
- Public admin/API docs with auth present but weak/no MFA.

Sources:

- FastAPI CORS: https://fastapi.tiangolo.com/tutorial/cors/
- FastAPI behind proxy: https://fastapi.tiangolo.com/advanced/behind-a-proxy/
- Flask API/debug docs: https://flask.palletsprojects.com/en/stable/api/
- Flask-CORS: https://flask-cors.readthedocs.io/en/latest/api.html
- Django deployment checklist: https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/
- OWASP command injection: https://owasp.org/www-community/attacks/Command_Injection

### Node / Express / NestJS

Blocking rules:

- `NODE_ENV` not production in deployed service.
- Express/Nest wildcard/reflected CORS with credentials.
- `app.set("trust proxy", true)` without trusted proxy constraints.
- `child_process.exec*` / `execSync` using request input.
- Stack traces returned in production error handlers.
- Missing Helmet/equivalent security headers for public APIs where framework evidence is present.

Advisory:

- Missing body size limits.
- Missing CSRF for cookie-auth apps.
- Missing rate limit on auth endpoints.

Sources:

- Express behind proxies: https://expressjs.com/en/guide/behind-proxies.html
- NestJS Helmet: https://docs.nestjs.com/security/helmet
- NestJS CSRF: https://docs.nestjs.com/security/csrf

## GitHub Actions / CI / deploy

Blocking rules:

- `pull_request_target` workflow checks out/builds/tests PR-controlled code with secrets or write token.
- `permissions: write-all` or broad top-level write permissions in deploy/release workflows.
- Production deploys from arbitrary branches/PR events without environment protection.
- Static cloud deploy credentials committed or printed in workflow logs.
- `echo $SECRET`, `printenv`, `env`, `set -x`, or dumping `.env` near secret usage.

Advisory:

- Third-party actions not pinned to immutable SHAs.
- No GitHub Environments/reviewers for production deploy.
- No CODEOWNERS/review for workflow files.
- Long-lived cloud credentials where OIDC would be feasible.

Sources:

- GitHub Actions security hardening: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- GitHub OIDC hardening: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- GitHub Well-Architected Actions security: https://wellarchitected.github.com/library/application-security/recommendations/actions-security/
