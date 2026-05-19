from pathlib import Path

from vibegate.scanner import Scanner


def test_default_scanner_flags_fastapi_telegram_webhook_without_secret_token_check(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text(
        """
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    update = await request.json()
    return {"ok": True}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    finding = next(f for f in result.findings if f.rule_id == "telegram.webhook-secret-token")
    assert finding.path == "bot.py"
    assert finding.line == 6
    assert finding.remediation is not None
    assert "X-Telegram-Bot-Api-Secret-Token" in finding.remediation


def test_default_scanner_does_not_flag_fastapi_webhook_with_secret_token_check(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text(
        """
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

@app.post("/telegram/webhook")
async def telegram_webhook(x_telegram_bot_api_secret_token: str = Header()):
    if x_telegram_bot_api_secret_token != "expected-secret":
        raise HTTPException(status_code=401)
    return {"ok": True}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    assert not any(f.rule_id == "telegram.webhook-secret-token" for f in result.findings)


def test_default_scanner_flags_flask_telegram_webhook_without_secret_token_check(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from flask import Flask, request

app = Flask(__name__)

@app.route("/bot/update", methods=["POST"])
def bot_update():
    update = request.get_json()
    return "ok"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    finding = next(f for f in result.findings if f.rule_id == "telegram.webhook-secret-token")
    assert finding.path == "app.py"
    assert finding.line == 6
    assert finding.remediation is not None
    assert "X-Telegram-Bot-Api-Secret-Token" in finding.remediation


def test_default_scanner_does_not_flag_non_route_update_functions(tmp_path: Path) -> None:
    (tmp_path / "repo.py").write_text(
        """
def update_user_profile(user_id: int):
    return {"ok": True}

async def notify_bot_owner(message: str):
    return None
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    assert not any(f.rule_id == "telegram.webhook-secret-token" for f in result.findings)


def test_default_scanner_does_not_flag_ordinary_telegram_crud_routes(tmp_path: Path) -> None:
    (tmp_path / "accounts.py").write_text(
        """
from fastapi import APIRouter

router = APIRouter(prefix="/telegram/accounts")

@router.patch("/{account_id}")
async def update_telegram_profile(account_id: int):
    return {"ok": True}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    assert not any(f.rule_id == "telegram.webhook-secret-token" for f in result.findings)


def test_default_scanner_flags_hardcoded_telegram_webhook_url_token(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        'WEBHOOK_URL = "https://api.telegram.org/bot123456789:AAabcdefghijklmnopqrstuvwxyzABCDEFG/setWebhook"\n',
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    finding = next(f for f in result.findings if f.rule_id == "telegram.webhook-token-exposure")
    assert finding.path == "setup.py"
    assert finding.line == 1
    assert "webhook" in finding.message.lower()
