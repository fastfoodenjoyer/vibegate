from pathlib import Path

from vibegate.models import Severity, Verdict
from vibegate.rules.webhooks import StripeWebhookSignatureRule, SvixWebhookSignatureRule
from vibegate.scanner import ScanContext, Scanner


def test_stripe_python_handler_without_signature_verification_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.post('/webhook/stripe')\n"
        "def stripe_webhook():\n"
        "    event = request.get_json()\n"
        "    if event['type'] == 'checkout.session.completed':\n"
        "        fulfill_order(event['data']['object'])\n"
        "    return '', 200\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "webhooks.stripe-unsigned"
    assert finding.severity is Severity.HIGH
    assert finding.blocking is True
    assert finding.path == "app.py"
    assert finding.line == 3
    assert finding.remediation is not None


def test_stripe_nextjs_handler_without_signature_verification_blocks(tmp_path: Path) -> None:
    route_dir = tmp_path / "app" / "api" / "stripe" / "webhook"
    route_dir.mkdir(parents=True)
    (route_dir / "route.ts").write_text(
        "import Stripe from 'stripe';\n"
        "export async function POST(req: Request) {\n"
        "  const event = await req.json();\n"
        "  if (event.type === 'payment_intent.succeeded') {\n"
        "    await handle(event.data.object);\n"
        "  }\n"
        "  return Response.json({ received: true });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.stripe-unsigned"]
    assert findings[0].path == "app/api/stripe/webhook/route.ts"
    assert findings[0].line == 2


def test_stripe_json_body_before_signature_verification_blocks(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "app.post('/stripe/webhook', async (req, res) => {\n"
        "  const payload = await req.json();\n"
        "  const event = stripe.webhooks.constructEvent(payload, req.headers['stripe-signature'], secret);\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.stripe-json-before-signature"]
    assert findings[0].line == 2


def test_stripe_global_express_json_before_signature_verification_blocks(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.json());\n"
        "app.post('/stripe/webhook', (req, res) => {\n"
        "  const sig = req.headers['stripe-signature'];\n"
        "  const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);\n"
        "  res.sendStatus(200);\n"
        "});\n"
        "app.listen(3000);\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.stripe-json-before-signature"]
    assert findings[0].line == 3


def test_stripe_route_with_construct_event_and_raw_body_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "app.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {\n"
        "  const sig = req.headers['stripe-signature'];\n"
        "  const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);\n"
        "  res.json({received: true});\n"
        "});\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_stripe_construct_event_without_signature_header_blocks(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "app.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {\n"
        "  const event = stripe.webhooks.constructEvent(req.body, undefined, secret);\n"
        "  if (event.type === 'checkout.session.completed') fulfill(event);\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.stripe-unsigned"]


def test_stripe_import_elsewhere_does_not_make_generic_webhook_stripe(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "import Stripe from 'stripe';\n"
        "const stripe = new Stripe(process.env.STRIPE_KEY!);\n"
        "app.post('/webhook/github', (req, res) => {\n"
        "  const event = req.body;\n"
        "  if (event.type === 'push') syncRepository(event);\n"
        "  res.sendStatus(204);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_stripe_signature_header_plus_generic_crypto_does_not_count_as_verified(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const crypto = require('crypto');\n"
        "app.post('/stripe/webhook', (req, res) => {\n"
        "  const sig = req.headers['stripe-signature'];\n"
        "  verifySessionCookie(req);\n"
        "  const event = req.body;\n"
        "  if (event.type === 'checkout.session.completed') fulfill(event);\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.stripe-unsigned"]


def test_stripe_json_before_signature_is_scoped_to_handler_block(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "app.post('/api/profile', async (req, res) => {\n"
        "  const profile = await req.json();\n"
        "  res.json(profile);\n"
        "});\n"
        "app.post('/stripe/webhook', async (req, res) => {\n"
        "  const payload = await req.text();\n"
        "  const sig = req.headers['stripe-signature'];\n"
        "  const event = stripe.webhooks.constructEvent(payload, sig, secret);\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_webhook_rules_scan_modern_js_ts_module_suffixes(tmp_path: Path) -> None:
    (tmp_path / "route.mts").write_text(
        "export async function POST(req: Request) {\n"
        "  const event = await req.json();\n"
        "  if (event.type === 'payment_intent.succeeded') fulfill(event);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.stripe-unsigned"]


def test_non_provider_generic_webhook_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.post('/webhook/github')\n"
        "def github_webhook():\n"
        "    payload = request.get_json()\n"
        "    process(payload)\n"
        "    return '', 200\n",
        encoding="utf-8",
    )

    stripe_findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))
    svix_findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert stripe_findings == []
    assert svix_findings == []


def test_svix_generic_event_type_webhook_does_not_block_under_node_api_or_default_scan(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"latest"}}\n', encoding="utf-8")
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.json());\n"
        "app.post('/webhook/github', (req, res) => {\n"
        "  const event = req.body;\n"
        "  if (event.type === 'push') syncRepository(event);\n"
        "  res.sendStatus(204);\n"
        "});\n"
        "app.listen(3000);\n",
        encoding="utf-8",
    )

    rule_findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))
    node_result = Scanner().scan(tmp_path, profile_ids=["node-api"])
    default_result = Scanner().scan(tmp_path)

    assert rule_findings == []
    assert not any(finding.rule_id.startswith("webhooks.svix") for finding in node_result.findings)
    assert not any(finding.rule_id.startswith("webhooks.svix") for finding in default_result.findings)


def test_webhook_rules_ignore_tests_and_docs(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_webhook.py").write_text(
        "def test_stripe_fixture(client):\n"
        "    client.post('/stripe/webhook', json={'type': 'checkout.session.completed'})\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "Example: parse a Stripe webhook JSON payload and process payment_intent.succeeded.\n",
        encoding="utf-8",
    )

    stripe_findings = StripeWebhookSignatureRule().scan(ScanContext(root=tmp_path))
    svix_findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert stripe_findings == []
    assert svix_findings == []


def test_svix_clerk_handler_without_required_header_verification_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.post('/api/clerk/webhook')\n"
        "def clerk_webhook():\n"
        "    event = request.get_json()\n"
        "    if event['type'] == 'user.created':\n"
        "        sync_user(event['data'])\n"
        "    return '', 200\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "webhooks.svix-unsigned"
    assert finding.severity is Severity.HIGH
    assert finding.blocking is True
    assert finding.path == "app.py"
    assert finding.line == 1


def test_svix_clerk_handler_with_required_header_verification_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "import { Webhook } from 'svix';\n"
        "export async function POST(req: Request) {\n"
        "  const payload = await req.text();\n"
        "  const headers = {\n"
        "    'svix-id': req.headers.get('svix-id'),\n"
        "    'svix-timestamp': req.headers.get('svix-timestamp'),\n"
        "    'svix-signature': req.headers.get('svix-signature'),\n"
        "  };\n"
        "  const event = new Webhook(process.env.CLERK_WEBHOOK_SECRET!).verify(payload, headers);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_svix_headers_plus_unrelated_verify_does_not_count_as_verified(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "export async function POST(req: Request) {\n"
        "  const payload = await req.text();\n"
        "  const headers = {\n"
        "    'svix-id': req.headers.get('svix-id'),\n"
        "    'svix-timestamp': req.headers.get('svix-timestamp'),\n"
        "    'svix-signature': req.headers.get('svix-signature'),\n"
        "  };\n"
        "  auth.verify(req);\n"
        "  const event = JSON.parse(payload);\n"
        "  if (event.type === 'user.created') syncUser(event.data);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.svix-unsigned"]


def test_svix_json_body_before_signature_verification_blocks(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "import { Webhook } from 'svix';\n"
        "export async function POST(req: Request) {\n"
        "  const payload = await req.json();\n"
        "  const headers = {\n"
        "    'svix-id': req.headers.get('svix-id'),\n"
        "    'svix-timestamp': req.headers.get('svix-timestamp'),\n"
        "    'svix-signature': req.headers.get('svix-signature'),\n"
        "  };\n"
        "  const event = new Webhook(process.env.CLERK_WEBHOOK_SECRET!).verify(payload, headers);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.svix-json-before-signature"]
    assert findings[0].line == 3


def test_svix_global_express_json_before_signature_verification_blocks(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const { Webhook } = require('svix');\n"
        "const app = express();\n"
        "app.use(express.json());\n"
        "app.post('/api/clerk/webhook', (req, res) => {\n"
        "  const headers = {\n"
        "    'svix-id': req.headers['svix-id'],\n"
        "    'svix-timestamp': req.headers['svix-timestamp'],\n"
        "    'svix-signature': req.headers['svix-signature'],\n"
        "  };\n"
        "  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET);\n"
        "  const event = wh.verify(req.body, headers);\n"
        "  res.json({ ok: true });\n"
        "});\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == ["webhooks.svix-json-before-signature"]
    assert findings[0].line == 4


def test_svix_raw_body_before_signature_verification_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "import { Webhook } from 'svix';\n"
        "export async function POST(req: Request) {\n"
        "  const payload = await req.text();\n"
        "  const headers = {\n"
        "    'svix-id': req.headers.get('svix-id'),\n"
        "    'svix-timestamp': req.headers.get('svix-timestamp'),\n"
        "    'svix-signature': req.headers.get('svix-signature'),\n"
        "  };\n"
        "  const event = new Webhook(process.env.CLERK_WEBHOOK_SECRET!).verify(payload, headers);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_svix_python_webhook_assignment_verify_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from svix.webhooks import Webhook\n"
        "@app.post('/api/clerk/webhook')\n"
        "def clerk_webhook():\n"
        "    payload = request.get_data(as_text=True)\n"
        "    headers = {\n"
        "        'svix-id': request.headers.get('svix-id'),\n"
        "        'svix-timestamp': request.headers.get('svix-timestamp'),\n"
        "        'svix-signature': request.headers.get('svix-signature'),\n"
        "    }\n"
        "    wh = Webhook(CLERK_WEBHOOK_SECRET)\n"
        "    event = wh.verify(payload, headers)\n"
        "    if event['type'] == 'user.created':\n"
        "        sync_user(event['data'])\n"
        "    return '', 200\n",
        encoding="utf-8",
    )

    findings = SvixWebhookSignatureRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_webhook_rules_are_mapped_to_provider_and_backend_profiles(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"latest","stripe":"latest"}}\n', encoding="utf-8")
    (tmp_path / "server.js").write_text(
        "app.post('/stripe/webhook', (req, res) => {\n"
        "  const event = req.body;\n"
        "  if (event.type === 'checkout.session.completed') fulfill(event);\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )

    for profile_id in ("stripe-webhooks", "node-api"):
        result = Scanner().scan(tmp_path, profile_ids=[profile_id])

        assert result.summary.verdict is Verdict.NO_SHIP
        assert any(finding.rule_id == "webhooks.stripe-unsigned" for finding in result.findings)


def test_stripe_webhook_profile_is_auto_detected_from_code_handler(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "app.post('/stripe/webhook', (req, res) => {\n"
        "  const event = req.body;\n"
        "  if (event.type === 'checkout.session.completed') fulfill(event);\n"
        "  res.sendStatus(200);\n"
        "});\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    assert "stripe-webhooks" in result.active_profile_ids
    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "webhooks.stripe-unsigned" for finding in result.findings)
