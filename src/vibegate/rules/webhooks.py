from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, cast

from vibegate.models import Finding, Severity
from vibegate.rules.secrets import ignored_path

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


_CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
_STRIPE_EVENT_PATTERN = re.compile(
    r"checkout\.session\.|payment_intent\.|invoice\.|customer\.subscription\.|charge\.",
    re.IGNORECASE,
)
_STRIPE_VERIFY_PATTERN = re.compile(
    r"construct_event\s*\(|constructEvent\s*\(|Webhook\.construct_event\s*\(",
)
_EXPLICIT_STRIPE_VERIFY_PATTERN = re.compile(
    r"verifyStripeSignature\s*\(|stripeSignatureVerifier\s*\(|verify_stripe_signature\s*\(",
    re.IGNORECASE,
)
_STRIPE_SIGNATURE_PATTERN = re.compile(r"stripe[-_]signature|Stripe-Signature", re.IGNORECASE)
_JSON_BODY_PATTERN = re.compile(
    r"\.json\s*\(|get_json\s*\(|json\.loads\s*\(|bodyParser\.json|express\.json",
    re.IGNORECASE,
)
_RAW_BODY_PATTERN = re.compile(
    r"\.text\s*\(|get_data\s*\(|express\.raw|rawBody|raw_body|request\.body|req\.body",
    re.IGNORECASE,
)
_SVIX_HEADERS = ("svix-id", "svix-timestamp", "svix-signature")
_SVIX_DIRECT_VERIFY_PATTERN = re.compile(r"(?:new\s+)?Webhook\s*\([^\n;]*\)\.verify\s*\(", re.IGNORECASE)
_SVIX_WEBHOOK_VAR_PATTERN = re.compile(
    r"(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?Webhook\s*\(",
)


class StripeWebhookSignatureRule:
    rule_id = "webhooks.stripe-unsigned"
    max_file_size_bytes = 1_000_000

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_code_files(context.root):
            content = _read_text(path)
            if content is None or not _looks_like_stripe_webhook(path, context.root, content):
                continue

            block = _stripe_webhook_block(path, context.root, content)
            block_text = cast(str, block["text"]) if block is not None else content
            block_line = cast(int, block["line"]) if block is not None else _handler_line_number(content)
            if _has_stripe_signature_verification(block_text):
                json_line = _first_json_body_line_before_verification(block_text, start_line=block_line)
                if json_line is None:
                    json_line = _first_global_json_middleware_line_before_handler(content, handler_line=block_line)
                if json_line is not None:
                    findings.append(
                        _finding(
                            context=context,
                            path=path,
                            line_number=json_line,
                            rule_id="webhooks.stripe-json-before-signature",
                            title="Stripe webhook parses JSON before signature verification",
                            message=(
                                "Stripe webhook signature verification requires the raw request body, but this "
                                "handler parses JSON before calling Stripe signature verification."
                            ),
                            snippet=_line_at(path, json_line),
                            remediation=(
                                "Read the raw request body and pass it directly to Stripe construct_event/"
                                "constructEvent before any JSON parsing or body mutation."
                            ),
                        )
                    )
                continue

            findings.append(
                _finding(
                    context=context,
                    path=path,
                    line_number=block_line,
                    rule_id=self.rule_id,
                    title="Stripe webhook is not signature verified",
                    message=(
                        "A Stripe webhook handler appears to process payment events without verifying the "
                        "Stripe-Signature header with Stripe's construct_event/constructEvent flow."
                    ),
                    snippet=_line_at(path, block_line),
                    remediation=(
                        "Read the raw request body, read the Stripe-Signature header, and verify the event "
                        "with stripe.Webhook.construct_event/stripe.webhooks.constructEvent before processing."
                    ),
                )
            )
        return findings


class SvixWebhookSignatureRule:
    rule_id = "webhooks.svix-unsigned"
    max_file_size_bytes = 1_000_000

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_code_files(context.root):
            content = _read_text(path)
            if content is None or not _looks_like_svix_or_clerk_webhook(path, context.root, content):
                continue
            block = _svix_webhook_block(path, context.root, content)
            block_text = cast(str, block["text"]) if block is not None else content
            block_line = cast(int, block["line"]) if block is not None else _handler_line_number(content)
            if _has_svix_signature_verification(block_text):
                json_line = _first_json_body_line_before_svix_verification(block_text, start_line=block_line)
                if json_line is None:
                    json_line = _first_global_json_middleware_line_before_handler(content, handler_line=block_line)
                if json_line is not None:
                    findings.append(
                        _finding(
                            context=context,
                            path=path,
                            line_number=json_line,
                            rule_id="webhooks.svix-json-before-signature",
                            title="Clerk/Svix webhook parses JSON before signature verification",
                            message=(
                                "Svix webhook signature verification requires the raw request body, but this "
                                "handler parses JSON before calling Svix Webhook.verify."
                            ),
                            snippet=_line_at(path, json_line),
                            remediation=(
                                "Read the raw request body and pass it directly to Svix Webhook.verify before "
                                "any JSON parsing or body mutation."
                            ),
                        )
                    )
                continue
            line_number = block_line
            findings.append(
                _finding(
                    context=context,
                    path=path,
                    line_number=line_number,
                    rule_id=self.rule_id,
                    title="Clerk/Svix webhook is not signature verified",
                    message=(
                        "A Clerk/Svix webhook handler appears to process authentication events without "
                        "verifying svix-id, svix-timestamp, and svix-signature."
                    ),
                    snippet=_line_at(path, line_number),
                    remediation=(
                        "Verify the raw payload with Svix Webhook.verify using svix-id, svix-timestamp, "
                        "and svix-signature before processing Clerk events."
                    ),
                )
            )
        return findings


def _iter_code_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ignored_path(path, root) or _is_test_path(path, root):
            continue
        if path.suffix.lower() not in _CODE_SUFFIXES or _too_large(path, 1_000_000):
            continue
        paths.append(path)
    return paths


def _looks_like_stripe_webhook(path: Path, root: Path, content: str) -> bool:
    return _stripe_webhook_block(path, root, content) is not None


def _looks_like_svix_or_clerk_webhook(path: Path, root: Path, content: str) -> bool:
    return _svix_webhook_block(path, root, content) is not None


def _stripe_webhook_block(path: Path, root: Path, content: str) -> dict[str, int | str] | None:
    normalized_path = path.relative_to(root).as_posix().lower()
    normalized_content = content.lower()
    for block in _handler_blocks(content):
        block_text = str(block["text"])
        normalized_block = block_text.lower()
        route_is_stripe = "stripe" in normalized_block and "webhook" in normalized_block
        path_is_stripe_webhook = "stripe" in normalized_path and "webhook" in normalized_path
        processes_stripe_event = _STRIPE_EVENT_PATTERN.search(block_text) is not None
        explicit_stripe_verification = _STRIPE_VERIFY_PATTERN.search(block_text) is not None
        if route_is_stripe or path_is_stripe_webhook or processes_stripe_event or explicit_stripe_verification:
            return block
    if not _has_webhook_handler_shape(content):
        return None
    if "stripe" not in normalized_path and "stripe" not in normalized_content:
        return None
    if _STRIPE_EVENT_PATTERN.search(content) is None and _STRIPE_VERIFY_PATTERN.search(content) is None:
        return None
    return {"line": _handler_line_number(content), "text": content}


def _svix_webhook_block(path: Path, root: Path, content: str) -> dict[str, int | str] | None:
    normalized_path = path.relative_to(root).as_posix().lower()
    normalized_content = content.lower()
    file_has_svix_evidence = any(marker in normalized_path or marker in normalized_content for marker in ("clerk", "svix"))
    for block in _handler_blocks(content):
        block_text = str(block["text"])
        normalized_block = block_text.lower()
        route_is_svix = any(marker in normalized_block for marker in ("clerk", "svix")) and "webhook" in normalized_block
        path_is_svix = any(marker in normalized_path for marker in ("clerk", "svix")) and "webhook" in normalized_path
        has_event_processing = _has_svix_event_processing(normalized_block)
        has_svix_headers = all(header in normalized_block for header in _SVIX_HEADERS)
        if route_is_svix or path_is_svix or (has_event_processing and file_has_svix_evidence) or has_svix_headers:
            return block
    if not _has_webhook_handler_shape(content):
        return None
    mentions_provider = any(marker in normalized_path or marker in normalized_content for marker in ("clerk", "svix"))
    if mentions_provider and ("webhook" in normalized_path or "webhook" in normalized_content):
        return {"line": _handler_line_number(content), "text": content}
    return None


def _has_svix_event_processing(normalized_content: str) -> bool:
    return "user.created" in normalized_content or "event['type']" in normalized_content or "event.type" in normalized_content


def _handler_blocks(content: str) -> list[dict[str, int | str]]:
    route_pattern = re.compile(
        r"@(app|router)\.(post|route)\s*\(|\b(app|router)\.post\s*\(|export\s+async\s+function\s+POST\s*\(",
    )
    lines = content.splitlines()
    starts = [index for index, line in enumerate(lines) if route_pattern.search(line)]
    blocks: list[dict[str, int | str]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        blocks.append({"line": start + 1, "text": "\n".join(lines[start:end])})
    return blocks


def _has_webhook_handler_shape(content: str) -> bool:
    return bool(
        re.search(r"@(app|router)\.(post|route)\s*\(", content)
        or re.search(r"\b(app|router)\.post\s*\(", content)
        or re.search(r"export\s+async\s+function\s+POST\s*\(", content)
    )


def _has_stripe_signature_verification(content: str) -> bool:
    has_signature_header = _STRIPE_SIGNATURE_PATTERN.search(content) is not None
    has_construct_event = _STRIPE_VERIFY_PATTERN.search(content) is not None
    return has_signature_header and has_construct_event


def _first_json_body_line_before_verification(content: str, *, start_line: int = 1) -> int | None:
    verification_line = _first_matching_line(content, _STRIPE_VERIFY_PATTERN)
    if verification_line is None:
        verification_line = _first_matching_line(content, _EXPLICIT_STRIPE_VERIFY_PATTERN)
    if verification_line is None:
        return None
    json_line = _first_matching_line(content, _JSON_BODY_PATTERN)
    if json_line is None or json_line >= verification_line:
        return None
    if _line_matches(content, json_line, _RAW_BODY_PATTERN) and not _line_matches(content, json_line, _JSON_BODY_PATTERN):
        return None
    return start_line + json_line - 1


def _first_global_json_middleware_line_before_handler(content: str, *, handler_line: int) -> int | None:
    for line_number, line in enumerate(content.splitlines(), start=1):
        if line_number >= handler_line:
            return None
        if _is_global_express_json_middleware_line(line):
            return line_number
    return None


def _is_global_express_json_middleware_line(line: str) -> bool:
    return re.search(r"\b(?:app|server)\.use\s*\(\s*(?:express\.json|bodyParser\.json)", line) is not None


def _has_svix_signature_verification(content: str) -> bool:
    normalized = content.lower()
    if not all(header in normalized for header in _SVIX_HEADERS):
        return False
    if _SVIX_DIRECT_VERIFY_PATTERN.search(content):
        return True
    verifier_names = {match.group("name") for match in _SVIX_WEBHOOK_VAR_PATTERN.finditer(content)}
    return any(re.search(rf"\b{re.escape(name)}\.verify\s*\(", content) for name in verifier_names)


def _first_json_body_line_before_svix_verification(content: str, *, start_line: int = 1) -> int | None:
    verification_line = _first_svix_verification_line(content)
    if verification_line is None:
        return None
    json_line = _first_matching_line(content, _JSON_BODY_PATTERN)
    if json_line is None or json_line >= verification_line:
        return None
    if _line_matches(content, json_line, _RAW_BODY_PATTERN) and not _line_matches(content, json_line, _JSON_BODY_PATTERN):
        return None
    return start_line + json_line - 1


def _first_svix_verification_line(content: str) -> int | None:
    direct_line = _first_matching_line(content, _SVIX_DIRECT_VERIFY_PATTERN)
    verifier_names = {match.group("name") for match in _SVIX_WEBHOOK_VAR_PATTERN.finditer(content)}
    variable_lines = [
        line
        for name in verifier_names
        if (line := _first_matching_line(content, re.compile(rf"\b{re.escape(name)}\.verify\s*\("))) is not None
    ]
    candidates = [line for line in [direct_line, *variable_lines] if line is not None]
    return min(candidates) if candidates else None


def _handler_line_number(content: str) -> int:
    route_pattern = re.compile(
        r"@(app|router)\.(post|route)\s*\(|\b(app|router)\.post\s*\(|export\s+async\s+function\s+POST\s*\(",
    )
    line_number = _first_matching_line(content, route_pattern)
    return line_number if line_number is not None else 1


def _first_matching_line(content: str, pattern: re.Pattern[str]) -> int | None:
    for line_number, line in enumerate(content.splitlines(), start=1):
        if pattern.search(line):
            return line_number
    return None


def _line_matches(content: str, line_number: int, pattern: re.Pattern[str]) -> bool:
    lines = content.splitlines()
    if line_number < 1 or line_number > len(lines):
        return False
    return pattern.search(lines[line_number - 1]) is not None


def _is_test_path(path: Path, root: Path) -> bool:
    relative_parts = path.relative_to(root).parts
    return any(part in {"tests", "test", "testing", "__tests__"} for part in relative_parts[:-1]) or path.name.startswith(
        "test_"
    )


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _too_large(path: Path, max_file_size_bytes: int) -> bool:
    try:
        return path.stat().st_size > max_file_size_bytes
    except OSError:
        return True


def _line_at(path: Path, line_number: int) -> str | None:
    content = _read_text(path)
    if content is None:
        return None
    lines = content.splitlines()
    if line_number < 1 or line_number > len(lines):
        return None
    return lines[line_number - 1].strip()


def _finding(
    *,
    context: ScanContext,
    path: Path,
    line_number: int,
    rule_id: str,
    title: str,
    message: str,
    snippet: str | None,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.HIGH,
        message=message,
        blocking=True,
        path=path.relative_to(context.root).as_posix(),
        line=line_number,
        snippet=snippet,
        remediation=remediation,
    )
