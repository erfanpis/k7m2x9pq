#!/usr/bin/env python3
"""
SibStar IPA Scanner — Telegram bot (stdlib only, no extra dependencies).

Send the bot a .ipa file in Telegram and it scans it and replies in Persian
with a short summary + the full report (.md) and data (.json) as documents.

Telegram bot file limit is 20 MB — files larger than that are refused with
a clear Persian message (the Bot API itself will not deliver them).

Setup (token is NEVER hardcoded and NEVER logged):
  export TELEGRAM_BOT_TOKEN='123456:ABC...'   # from @BotFather
  python3 bot.py

Checks (no scanning, no token in output):
  python3 bot.py --check-token    # calls getMe; on 401/403/404 prints a clear
                                  # "token invalid, get a new one from @BotFather"
  python3 bot.py --selftest test/TestGame.ipa   # scans locally, prints the
                                  # exact Persian summary the bot would send

Run forever (long polling):  python3 bot.py
The bot must stay running somewhere always-on (a small VPS, or your own
computer). This VM is NOT a permanent host — see DEPLOY.md.
"""
import json, mimetypes, os, sys, tempfile, time, traceback, urllib.error, urllib.parse, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scanner import scan_ipa, render_report

API = "https://api.telegram.org/bot{token}/{method}"
MAX_FILE_BYTES = 20 * 1024 * 1024  # Telegram Bot API document limit
POLL_TIMEOUT = 30

class TokenInvalid(Exception):
    pass

def get_token():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise TokenInvalid("TELEGRAM_BOT_TOKEN is not set. Get a token from @BotFather and export it.")
    return token

def _request(method, payload=None, token=None, timeout=60):
    """POST JSON to the Bot API. Token goes only in the URL path, never in logs."""
    token = token or get_token()
    url = API.format(token=urllib.parse.quote(token, safe=""), method=method)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        if e.code in (401, 403, 404):
            raise TokenInvalid(
                f"Telegram returned HTTP {e.code} ({body}). The bot token is invalid "
                "or the bot was deleted. Get a new token from @BotFather and set "
                "TELEGRAM_BOT_TOKEN again.")
        raise RuntimeError(f"Telegram HTTP {e.code}: {body}")

def _multipart_send(method, fields, files, token=None, timeout=120):
    """Send multipart/form-data (for sendDocument). stdlib only."""
    token = token or get_token()
    boundary = "----SibStarBotBoundary7d8f3a1b"
    body = bytearray()
    for name, value in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += f"{value}\r\n".encode()
    for name, (filename, content, ctype) in files.items():
        body += f"--{boundary}\r\n".encode()
        body += (f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                 f"Content-Type: {ctype}\r\n\r\n").encode()
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    url = API.format(token=urllib.parse.quote(token, safe=""), method=method)
    req = urllib.request.Request(url, data=bytes(body), method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode("utf-8", "replace")[:300]
        if e.code in (401, 403, 404):
            raise TokenInvalid("Telegram token is invalid — get a new token from @BotFather.")
        raise RuntimeError(f"Telegram HTTP {e.code}: {body_txt}")

def send_message(chat_id, text, token=None):
    # Telegram message limit is 4096 chars — truncate with a marker.
    if len(text) > 4000:
        text = text[:4000] + "\n…(ادامه در فایل گزارش)"
    return _request("sendMessage", {"chat_id": chat_id, "text": text}, token=token)

def send_document(chat_id, filename, content, caption, token=None):
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return _multipart_send("sendDocument",
                           {"chat_id": str(chat_id), "caption": caption[:1024]},
                           {"document": (filename, content, ctype)}, token=token)

def build_summary(r):
    """The short Persian summary the bot sends as a chat message."""
    ident = r.get("identity", {})
    risk = r.get("risk", {})
    name = ident.get("display_name") or "برنامه"
    lines = [f"🔍 اسکن {name} تمام شد",
             f"📦 {ident.get('bundle_id') or '—'} — نسخه {ident.get('version') or '—'} (حداقل iOS {ident.get('minimum_os') or '—'})",
             f"⚠️ ریسک: {risk.get('score', '?')}/100 — {risk.get('level_fa', '')}"]
    if r.get("binary", {}).get("encrypted") is True:
        lines.append("🔒 باینری رمزگذاری‌شده (FairPlay) است — تحلیل رشته‌های باینری انجام نشد.")
    perms = r.get("permissions", [])
    lines.append(f"🔑 دسترسی‌ها ({len(perms)}): " +
                 (", ".join(p["label_fa"] for p in perms[:6]) or "هیچ‌کدام") +
                 ("…" if len(perms) > 6 else ""))
    trackers = r.get("known_trackers", [])
    lines.append("📡 ترکرها: " + (", ".join(t["tracker"] for t in trackers[:5]) or "پیدا نشد") +
                 ("…" if len(trackers) > 5 else ""))
    http_urls = r.get("insecure_http_urls", [])
    lines.append(f"🌐 دامنه‌ها: {len(r.get('domains', []))} — لینک ناامن http: {len(http_urls)}")
    pm = r.get("privacy_manifest")
    if pm and not pm.get("error"):
        lines.append(f"🛡 مانیفست حریم خصوصی: ردیابی={'بله' if pm.get('tracking') else 'خیر'}"
                     + (f"، دامنه ردیابی: {len(pm.get('tracking_domains', []))}" if pm.get("tracking_domains") else ""))
    top = [b["reason"] for b in risk.get("breakdown", []) if b.get("points", 0) >= 8][:4]
    if top:
        lines.append("📌 مهم‌ترین دلایل ریسک:")
        for t in top:
            lines.append(f"• {t}")
    lines.append("📄 گزارش کامل و فایل JSON ضمیمه شد.")
    return "\n".join(lines)

HELP_FA = (
    "سلام! من ربات اسکنر IPA سیب‌استار هستم 👋\n\n"
    "یک فایل .ipa برام بفرست تا امنیت و حریم خصوصی‌ش رو بررسی کنم و گزارش بدم.\n\n"
    "چی بررسی می‌شه:\n"
    "• دسترسی‌ها (دوربین، میکروفون، لوکیشن، مخاطبین، ردیابی…)\n"
    "• مانیفست حریم خصوصی (PrivacyInfo.xcprivacy)\n"
    "• ترکرها و SDKها (Firebase، AppsFlyer و…)\n"
    "• لینک‌های ناامن http و تنظیمات ATS\n"
    "• باینری: رمزگذاری FairPlay، کتابخانه‌های لینک‌شده، الگوهای مشکوک\n\n"
    "⚠️ محدودیت تلگرام: فایل باید حداکثر ۲۰ مگابایت باشد.\n"
    "🔒 IPAهای اپ‌استور رمزگذاری‌شده‌اند؛ تحلیل کامل باینری‌شان بدون نسخه‌ی رمزگشایی‌شده ممکن نیست.\n\n"
    "دستورها: /start و /help"
)

def download_telegram_file(file_id, token, dest_path):
    info = _request("getFile", {"file_id": file_id}, token=token)
    if not info.get("ok"):
        raise RuntimeError(f"getFile failed: {info}")
    file_path = info["result"]["file_path"]
    url = f"https://api.telegram.org/file/bot{urllib.parse.quote(token, safe='')}/{file_path}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    return dest_path

def handle_update(update, token):
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    if not chat_id:
        return
    text = (msg.get("text") or "").strip()
    if text in ("/start", "/help"):
        send_message(chat_id, HELP_FA, token=token)
        return
    doc = msg.get("document")
    if not doc:
        if text:
            send_message(chat_id, "برای اسکن، یک فایل .ipa بفرست. راهنما: /help", token=token)
        return
    file_name = doc.get("file_name", "")
    file_size = doc.get("file_size", 0)
    if not file_name.lower().endswith(".ipa"):
        send_message(chat_id, f"فایل «{file_name}» پسوند .ipa ندارد. لطفاً فایل IPA بفرست.", token=token)
        return
    if file_size and file_size > MAX_FILE_BYTES:
        send_message(
            chat_id,
            f"فایل {file_size / 1048576:.1f} مگابایت است؛ تلگرام برای ربات‌ها حداکثر ۲۰ مگابایت می‌پذیرد. "
            "فایل را فشرده‌تر بفرست یا از نسخه‌ی سبک‌تر استفاده کن.",
            token=token)
        return
    send_message(chat_id, "⏳ دارم اسکن می‌کنم… چند لحظه صبر کن.", token=token)
    with tempfile.TemporaryDirectory(prefix="ipa-bot-") as tmp:
        ipa_path = Path(tmp) / file_name
        try:
            download_telegram_file(doc["file_id"], token, ipa_path)
        except Exception as e:
            send_message(chat_id, f"دانلود فایل از تلگرام ناموفق بود: {e}", token=token)
            return
        if ipa_path.stat().st_size > MAX_FILE_BYTES:
            send_message(chat_id, "فایل دانلودشده بزرگ‌تر از ۲۰ مگابایت است و اسکن نمی‌شود.", token=token)
            return
        try:
            result = scan_ipa(ipa_path, Path(tmp) / "work")
        except Exception as e:
            send_message(chat_id, f"اسکن ناموفق بود: {e}", token=token)
            return
        report_md = render_report(result)
        report_json = json.dumps(result, ensure_ascii=False, indent=2)
        base = Path(file_name).stem or "app"
        try:
            send_message(chat_id, build_summary(result), token=token)
            send_document(chat_id, f"{base}-scan-report.md", report_md.encode("utf-8"),
                          "گزارش کامل اسکن (Markdown)", token=token)
            send_document(chat_id, f"{base}-scan.json", report_json.encode("utf-8"),
                          "داده‌ی کامل اسکن (JSON)", token=token)
        except TokenInvalid:
            raise
        except Exception as e:
            send_message(chat_id, f"ارسال گزارش ناموفق بود: {e}", token=token)

def check_token(token=None):
    """getMe test. Returns bot info dict or raises TokenInvalid with a clear message."""
    token = token or get_token()
    res = _request("getMe", None, token=token, timeout=30)
    if not res.get("ok"):
        raise TokenInvalid(f"getMe failed: {res}. Token is invalid — get a new one from @BotFather.")
    return res["result"]

def run_polling(token=None):
    token = token or get_token()
    me = check_token(token)
    print(f"Bot started: @{me.get('username')} (id {me.get('id')}). Listening (long polling)…", flush=True)
    offset = None
    while True:
        try:
            res = _request("getUpdates", {"offset": offset, "timeout": POLL_TIMEOUT},
                           token=token, timeout=POLL_TIMEOUT + 15)
        except TokenInvalid:
            raise
        except Exception as e:
            print(f"getUpdates error (retrying in 5s): {e}", file=sys.stderr, flush=True)
            time.sleep(5)
            continue
        for update in res.get("result", []):
            offset = update["update_id"] + 1
            try:
                handle_update(update, token)
            except TokenInvalid:
                raise
            except Exception:
                traceback.print_exc()

def main(argv=None):
    args = list(argv if argv is not None else sys.argv[1:])
    if "--check-token" in args:
        try:
            me = check_token()
        except TokenInvalid as e:
            print(f"TOKEN INVALID: {e}", file=sys.stderr)
            print("Fix: open @BotFather in Telegram, create/revoke the bot, copy the new token, "
                  "then: export TELEGRAM_BOT_TOKEN='<new token>'", file=sys.stderr)
            return 2
        print(f"Token OK. Bot: @{me.get('username')} — {me.get('first_name')} (id {me.get('id')})")
        return 0
    if "--selftest" in args:
        idx = args.index("--selftest")
        ipa = args[idx + 1] if idx + 1 < len(args) else "test/TestGame.ipa"
        with tempfile.TemporaryDirectory(prefix="ipa-selftest-") as tmp:
            result = scan_ipa(ipa, Path(tmp) / "work")
        print(build_summary(result))
        print(f"\n[risk={result['risk']['score']} level={result['risk']['level_en']}]")
        return 0
    try:
        run_polling()
    except TokenInvalid as e:
        print(f"TOKEN INVALID: {e}", file=sys.stderr)
        print("Fix: get a new token from @BotFather and set TELEGRAM_BOT_TOKEN.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
