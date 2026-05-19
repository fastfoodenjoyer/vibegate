# Vibegate

**Ship/no-ship pre-deploy gate for AI-generated backend apps and bots.**

Vibegate is a Python-first CLI for checking small backend projects before deployment. The first wedge is deliberately narrow: AI-generated Telegram bots, FastAPI services, Railway/Docker deployments, webhook handlers, and simple crypto/bot backends.

It is not a replacement for Snyk, Semgrep, CodeQL, or a real security review. It is the fast sanity check you run before shipping a vibe-coded backend to the internet and discovering that `/admin` was a public attraction.

## Planned MVP

```bash
uvx vibegate scan
vibegate scan --template telegram-bot
vibegate scan --template fastapi-railway
vibegate scan --report report.md
```

Initial checks will focus on:

- leaked secrets and committed `.env` files;
- Telegram bot token and webhook mistakes;
- unsigned webhook handlers;
- dangerous CORS and debug settings;
- public admin/debug endpoints;
- obvious shell/tool execution hazards;
- Docker/Railway deployment footguns;
- dependency audit integration where available.

## Status

Planning phase. See [`docs/plans/`](docs/plans/) for the implementation plan.

## License

MIT
