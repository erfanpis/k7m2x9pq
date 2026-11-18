#!/usr/bin/env python3
"""
SibStar IPA Scanner — Telegram bot v3 (Telethon / MTProto).

Send the bot a .ipa file, or a direct http(s) link to an .ipa file, and it
scans it and replies in Persian with a short summary + the full report (.md)
and data (.json) as documents.

Why MTProto instead of the Bot API (v2)?
The Bot API `getFile` download limit is 20 MB. Telethon talks MTProto
directly (like the LinkYar project) and can download documents up to
Telegram's 2 GB file limit, so large IPA files work.

Setup — secrets are NEVER hardcoded and NEVER logged:
  export TELEGRAM_BOT_TOKEN='...'   # from @BotFather
  export TELEGRAM_API_ID='123456'   # from https://my.telegram.org
  export TELEGRAM_API_HASH='...'    # from https://my.telegram.org
  export ADMIN_USER_IDS='123456789'  # comma-separated Telegram user IDs;
                                      # ONLY these users may use the bot
  pip install -r requirements.txt
  python3 bot.py

Checks (no scanning, no secret in output):
  python3 bot.py --check-config  # env presence only, no network
  python3 bot.py --check-token   # connects and calls get_me
  python3 bot.py --selftest test/TestGame.ipa  # local scan, Persian summary

Cleanup (important): every downloaded IPA and every generated report lives
only inside a temporary directory. The IPA is deleted right after the scan
and after the reports have been sent — and the whole temp directory is
removed even if the download, scan, or send fails. Nothing is ever written
to the repo checkout and nothing is committed: .gitignore blocks *.ipa,
*.json reports and *.session files. This keeps the GitHub Actions runner
disk from filling up with 2 GB files.

Run forever (long polling over MTProto):  python3 bot.py
The bot must stay running somewhere always-on. On GitHub Actions it runs
via .github/workflows/bot.yml (already in the repo); see DEPLOY.md.
This VM is NOT a permanent host.
"""
import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scanner import scan_ipa, render_report

try:
    from telethon import TelegramClient, events
except ImportError:  # pragma: no cover - handled with a clear message in main()
    TelegramClient = None
    events = None

MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024  # Telegram MTProto file limit: 2 GB
MAX_FILE_LABEL = "۲ گیگابایت"
PROGRESS_MIN_BYTES = 50 * 1024 * 1024   # show progress only for files > 50 MB
PROGRESS_STEP_PCT = 10                  # edit the progress message every 10%
SCAN_EXTRA_DISK_BYTES = 512 * 1024 * 1024  # free space needed beyond the IPA itself
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+")


class ConfigError(Exception):
    """Startup config problem (missing/invalid env). Message names the variable."""


class OversizeError(Exception):
    pass


class NotAnIPAError(Exception):
    pass


# ---------------------------------------------------------------- config

def parse_admin_ids(raw):
    """Comma-separated Telegram user IDs -> set[int]. Empty/invalid parts ignored."""
    ids = set()
    for part in (raw or "").replace(";", ",").split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            ids.add(int(part))
    return ids


def load_config(env=None):
    """Read required config from env. Raises ConfigError naming what's missing.

    Never logs or returns secret values.
    """
    env = os.environ if env is None else env
    missing = []
    token = (env.get("TELEGRAM_BOT_TOKEN") or "").strip()
    api_id_raw = (env.get("TELEGRAM_API_ID") or "").strip()
    api_hash = (env.get("TELEGRAM_API_HASH") or "").strip()
    if not token:
        missing.append("TELEGRAM_BOT_TOKEN")
    if not api_id_raw:
        missing.append("TELEGRAM_API_ID")
    if not api_hash:
        missing.append("TELEGRAM_API_HASH")
    if missing:
        raise ConfigError(
            "Missing required setting(s): " + ", ".join(missing) +
            ". Set them as environment variables / GitHub Actions secrets "
            "(see DEPLOY.md).")
    try:
        api_id = int(api_id_raw)
    except ValueError:
        raise ConfigError("TELEGRAM_API_ID must be a number (from https://my.telegram.org).")
    return {
        "token": token,
        "api_id": api_id,
        "api_hash": api_hash,
        "admin_ids": parse_admin_ids(env.get("ADMIN_USER_IDS", "")),
    }


def is_admin(sender_id, admin_ids):
    """True only for the owner(s). Empty admin list = nobody is allowed."""
    if not admin_ids:
        return False
    try:
        return int(sender_id) in admin_ids
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------- helpers

def format_size(nbytes):
    """Persian-friendly size, e.g. 2.0 گیگابایت / 150.5 مگابایت / 12 کیلوبایت."""
    try:
        n = float(nbytes)
    except (TypeError, ValueError):
        return "نامشخص"
    for unit in ("بایت", "کیلوبایت", "مگابایت", "گیگابایت"):
        if n < 1024 or unit == "گیگابایت":
            return f"{n:.1f} {unit}" if unit != "بایت" else f"{int(n)} {unit}"
        n /= 1024
    return f"{n:.1f} گیگابایت"


def check_size_limit(size_bytes):
    """Persian error message if a declared size exceeds 2 GB, else None."""
    if size_bytes and size_bytes > MAX_FILE_BYTES:
        return (f"فایل {format_size(size_bytes)} است؛ حداکثر حجم قابل قبول "
                f"{MAX_FILE_LABEL} است (محدودیت تلگرام).")
    return None


def validate_file(file_name, file_size):
    """Persian error message for a Telegram document, else None."""
    if not (file_name or "").lower().endswith(".ipa"):
        return (f"فایل «{file_name or 'بدون نام'}» پسوند .ipa ندارد. "
                "لطفاً فایل IPA بفرست یا لینک مستقیم یک فایل .ipa بده.")
    return check_size_limit(file_size)


def validate_url(url):
    """Persian error message for a link, else None.

    Only http(s) links whose path ends in .ipa are accepted.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "فقط لینک‌های http و https پذیرفته می‌شوند."
    if not parsed.netloc:
        return "لینک معتبر نیست."
    if not parsed.path.lower().endswith(".ipa"):
        return "لینک باید مستقیماً به یک فایل .ipa ختم شود."
    return None


def find_ipa_url(text):
    """First http(s) URL in a message, cleaned of trailing punctuation, or None."""
    for m in URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,!؟")
        return url
    return None


def check_disk_space(directory, needed_bytes):
    """Persian error if free disk is less than the file + scan workspace, else None."""
    try:
        free = shutil.disk_usage(directory).free
    except OSError:
        return None
    if free < needed_bytes + SCAN_EXTRA_DISK_BYTES:
        return (f"فضای خالی دیسک ({format_size(free)}) برای دانلود و اسکن این فایل "
                f"({format_size(needed_bytes)}) کافی نیست.")
    return None


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
    if r.get("dylib_count"):
        lines.append(f"📚 فایل‌های dylib: {r['dylib_count']} — الگوی مشکوک در dylib: {r.get('dylib_suspicious_count', 0)}")
    answers = {a["id"]: a for a in (r.get("privacy_answers", []) or [])}
    if answers:
        lines.append("")
        lines.append("🔐 حریم خصوصی:")
        for qid, label in (("sends_photos_to_server", "ارسال عکس به سرور"),
                            ("third_party_can_see_photos", "دسترسی شخص ثالث به عکس"),
                            ("collects_photo_info", "جمع‌آوری اطلاعات عکس"),
                            ("verdict", "حکم نهایی")):
            a = answers.get(qid)
            if a:
                lines.append(f"• {label}: {a['answer_fa']}")
    pm = r.get("privacy_manifest")
    if pm and not pm.get("error"):
        lines.append(f"🛡 مانیفست حریم خصوصی: ردیابی={'بله' if pm.get('tracking') else 'خیر'}"
                     + (f"، دامنه ردیابی: {len(pm.get('tracking_domains', []))}" if pm.get("tracking_domains") else ""))
    top = [b["reason"] for b in risk.get("breakdown", []) if b.get("points", 0) >= 8][:4]
    if top:
        lines.append("📌 مهم‌ترین دلایل ریسک:")
        for t in top:
            lines.append(f"• {t}")
    lines.append("📄 گزارش کامل و فایل JSON ضمیمه شد. فایل IPA دانلودشده حذف شد.")
    return "\n".join(lines)


HELP_FA = (
    "سلام! من ربات اسکنر IPA سیب‌استار هستم 👋\n\n"
    "یک فایل .ipa برام بفرست، یا لینک مستقیم دانلود یک فایل .ipa بده، تا امنیت و "
    "حریم خصوصی‌ش رو بررسی کنم و گزارش بدم.\n\n"
    "چی بررسی می‌شه:\n"
    "• دسترسی‌ها (دوربین، میکروفون، لوکیشن، مخاطبین، ردیابی…)\n"
    "• مانیفست حریم خصوصی (PrivacyInfo.xcprivacy)\n"
    "• ترکرها و SDKها (Firebase، AppsFlyer و…)\n"
    "• لینک‌های ناامن http و تنظیمات ATS\n"
    "• باینری: رمزگذاری FairPlay، کتابخانه‌های لینک‌شده، الگوهای مشکوک\n\n"
    "📦 حداکثر حجم فایل: ۲ گیگابایت (دانلود با MTProto، مثل لینک‌یار).\n"
    "🔗 یا لینک مستقیم یک فایل .ipa بده تا دانلود و اسکنش کنم.\n"
    "🖼 بعد از اسکن، یک کارت تصویری خلاصه هم می‌فرستم.\n"
    "🗑 فایل IPA بعد از اسکن و ارسال گزارش حذف می‌شود؛ چیزی ذخیره نمی‌شود.\n"
    "🔒 IPAهای اپ‌استور رمزگذاری‌شده‌اند؛ تحلیل کامل باینری‌شان بدون نسخه‌ی رمزگشایی‌شده ممکن نیست.\n\n"
    "دستورها: /start و /help"
)

ACCESS_DENIED_FA = "⛔ این ربات فقط برای صاحبش است و به بقیه جواب نمی‌دهد."


# ---------------------------------------------------------------- progress

class ProgressTracker:
    """Thread-safe download progress. Records the next 10% mark to report."""

    def __init__(self, total=None):
        self.total = total
        self.current = 0
        self.lock = threading.Lock()
        self.next_mark = PROGRESS_STEP_PCT
        self.pending_pct = None
        self.done = False

    def update(self, current, total=None):
        with self.lock:
            self.current = current
            if total:
                self.total = total
            if not self.total:
                return
            pct = int(self.current * 100 / self.total)
            if pct >= self.next_mark:
                self.pending_pct = pct
                self.next_mark = ((pct // PROGRESS_STEP_PCT) + 1) * PROGRESS_STEP_PCT

    def take_pending(self):
        with self.lock:
            pct, self.pending_pct = self.pending_pct, None
            return pct

    def finish(self):
        with self.lock:
            self.done = True


async def progress_watcher(tracker, prog_msg, label):
    """Edit the progress message at each 10% mark until the download finishes."""
    try:
        while not tracker.done:
            await asyncio.sleep(3)
            pct = tracker.take_pending()
            if pct is not None and prog_msg is not None:
                try:
                    await prog_msg.edit(f"⬇️ در حال دانلود {label}… {pct}٪")
                except Exception:
                    pass
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------- download

def download_url_to(url, dest_path, tracker):
    """Stream-download an http(s) URL to dest_path (runs in an executor).

    Raises OversizeError if it grows past 2 GB, NotAnIPAError if the file
    does not start with the ZIP magic bytes of an IPA.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "SibStar-IPAScanner/3.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        declared = resp.headers.get("Content-Length")
        if declared:
            try:
                err = check_size_limit(int(declared))
            except ValueError:
                err = None
            if err:
                raise OversizeError(err)
            tracker.update(0, int(declared))
        downloaded = 0
        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                tracker.update(downloaded)
                if downloaded > MAX_FILE_BYTES:
                    raise OversizeError(check_size_limit(downloaded))
    with open(dest_path, "rb") as f:
        if f.read(4) != b"PK\x03\x04":
            raise NotAnIPAError("فایل دانلودشده یک IPA معتبر نیست (فایل ZIP نیست).")
    return dest_path


def check_ipa_magic(path):
    with open(path, "rb") as f:
        return f.read(4) == b"PK\x03\x04"


# ---------------------------------------------------------------- bot

class ScannerBot:
    def __init__(self, config):
        self.config = config
        self.client = None

    def make_client(self):
        if TelegramClient is None:
            raise ConfigError(
                "Telethon is not installed. Run: pip install -r requirements.txt")
        # Session file in the OS temp dir, never in the repo checkout.
        session_path = str(Path(tempfile.gettempdir()) / "sibstar_ipa_bot")
        return TelegramClient(session_path, self.config["api_id"], self.config["api_hash"])

    async def start(self):
        self.client = self.make_client()
        self.client.add_event_handler(self.on_message, events.NewMessage())
        await self.client.start(bot_token=self.config["token"])
        me = await self.client.get_me()
        print(f"Bot started: @{me.username} (id {me.id}). Listening over MTProto…",
              flush=True)
        await self.client.run_until_disconnected()

    async def reply(self, event, text):
        if len(text) > 4000:
            text = text[:4000] + "\n…(ادامه در فایل گزارش)"
        await event.reply(text)

    async def on_message(self, event):
        try:
            await self._on_message(event)
        except Exception:
            traceback.print_exc()
            try:
                await self.reply(event, "خطای داخلی رخ داد. دوباره امتحان کن.")
            except Exception:
                pass

    async def _on_message(self, event):
        if not event.is_private:
            return  # only direct messages, never groups/channels
        sender_id = event.sender_id
        if not is_admin(sender_id, self.config["admin_ids"]):
            await self.reply(event, ACCESS_DENIED_FA)
            return
        text = (event.message.message or "").strip()
        if text in ("/start", "/help"):
            await self.reply(event, HELP_FA)
            return

        message = event.message
        doc = getattr(message, "document", None)
        if doc is not None:
            f = getattr(message, "file", None)
            file_name = (f.name if f and f.name else "app.ipa")
            file_size = (f.size if f and f.size else 0)
            err = validate_file(file_name, file_size)
            if err:
                await self.reply(event, err)
                return
            await self.scan_telegram_file(event, file_name, file_size)
            return

        url = find_ipa_url(text)
        if url:
            err = validate_url(url)
            if err:
                await self.reply(event, err)
                return
            await self.scan_url(event, url)
            return

        if text:
            await self.reply(event,
                             "برای اسکن، یک فایل .ipa بفرست یا لینک مستقیم یک فایل .ipa بده. راهنما: /help")

    async def scan_telegram_file(self, event, file_name, file_size):
        await self.reply(event, "⏳ دارم دانلود و اسکن می‌کنم… چند لحظه صبر کن.")
        prog_msg = None
        tracker = None
        if file_size and file_size > PROGRESS_MIN_BYTES:
            tracker = ProgressTracker(file_size)
            prog_msg = await event.reply(f"⬇️ در حال دانلود… 0٪")
            watcher = asyncio.create_task(progress_watcher(tracker, prog_msg, file_name))
        else:
            watcher = None
        try:
            # Everything (IPA + reports + scan workdir) lives in one temp dir
            # that is deleted when this block exits — even on failure.
            with tempfile.TemporaryDirectory(prefix="ipa-bot-") as tmp:
                tmpdir = Path(tmp)
                disk_err = check_disk_space(tmpdir, file_size or 0)
                if disk_err:
                    await self.reply(event, disk_err)
                    return
                ipa_path = tmpdir / file_name
                try:
                    await self.client.download_media(
                        event.message, file=str(ipa_path),
                        progress_callback=(tracker.update if tracker else None))
                except Exception as e:
                    await self.reply(event, f"دانلود فایل از تلگرام ناموفق بود: {e}")
                    return
                if tracker:
                    tracker.finish()
                if not ipa_path.exists() or ipa_path.stat().st_size == 0:
                    await self.reply(event, "دانلود فایل کامل نشد. دوباره بفرست.")
                    return
                err = check_size_limit(ipa_path.stat().st_size)
                if err:
                    await self.reply(event, err)
                    return
                if not check_ipa_magic(ipa_path):
                    await self.reply(event, "فایل دانلودشده یک IPA معتبر نیست.")
                    return
                await self.scan_and_report(event, ipa_path, file_name, tmpdir)
                # Explicit delete of the IPA right after the reports were sent;
                # the temp dir itself is removed by the context manager below.
                ipa_path.unlink(missing_ok=True)
        finally:
            if tracker:
                tracker.finish()
            if watcher is not None:
                watcher.cancel()

    async def scan_url(self, event, url):
        await self.reply(event, "⏳ دارم لینک رو دانلود و اسکن می‌کنم… چند لحظه صبر کن.")
        tracker = ProgressTracker()
        prog_msg = await event.reply("⬇️ در حال دانلود لینک…")
        watcher = asyncio.create_task(progress_watcher(tracker, prog_msg, "لینک"))
        file_name = Path(urllib.parse.urlparse(url).path).name or "app.ipa"
        try:
            with tempfile.TemporaryDirectory(prefix="ipa-bot-") as tmp:
                tmpdir = Path(tmp)
                ipa_path = tmpdir / file_name
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(
                        None, download_url_to, url, ipa_path, tracker)
                except OversizeError as e:
                    await self.reply(event, str(e))
                    return
                except NotAnIPAError as e:
                    await self.reply(event, str(e))
                    return
                except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                    await self.reply(event, f"دانلود لینک ناموفق بود: {e}")
                    return
                finally:
                    tracker.finish()
                disk_err = check_disk_space(tmpdir, ipa_path.stat().st_size if ipa_path.exists() else 0)
                if disk_err:
                    await self.reply(event, disk_err)
                    return
                await self.scan_and_report(event, ipa_path, file_name, tmpdir)
                ipa_path.unlink(missing_ok=True)
        finally:
            tracker.finish()
            watcher.cancel()

    async def scan_and_report(self, event, ipa_path, file_name, tmpdir):
        """Scan an IPA already on disk and send the Persian summary + reports.

        Caller owns the temp dir; the IPA and reports are deleted by the
        caller/context manager after this returns.
        """
        await event.reply("🔍 دانلود کامل شد، دارم اسکن می‌کنم…")
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                None, scan_ipa, ipa_path, tmpdir / "work")
        except Exception as e:
            await self.reply(event, f"اسکن ناموفق بود: {e}")
            return
        report_md = render_report(result)
        report_json = json.dumps(result, ensure_ascii=False, indent=2)
        base = Path(file_name).stem or "app"
        md_path = tmpdir / f"{base}-scan-report.md"
        json_path = tmpdir / f"{base}-scan.json"
        md_path.write_text(report_md, encoding="utf-8")
        json_path.write_text(report_json, encoding="utf-8")
        # Summary image card (Pillow). If Pillow is missing the scan still
        # succeeds — the card is skipped, never a reason to fail the scan.
        card_path = None
        try:
            from report_card import generate_report_card
            card_path = tmpdir / f"{base}-scan-card.png"
            generate_report_card(result, card_path)
        except Exception as e:
            print(f"report card skipped: {e}", file=sys.stderr)
            card_path = None
        try:
            await event.reply(build_summary(result))
            if card_path is not None and card_path.is_file():
                await self.client.send_file(event.chat_id, str(card_path),
                                            caption="کارت خلاصه‌ی اسکن",
                                            force_document=False)
            await self.client.send_file(event.chat_id, str(md_path),
                                        caption="گزارش کامل اسکن (Markdown)",
                                        force_document=True)
            await self.client.send_file(event.chat_id, str(json_path),
                                        caption="داده‌ی کامل اسکن (JSON)",
                                        force_document=True)
        except Exception as e:
            await self.reply(event, f"ارسال گزارش ناموفق بود: {e}")
        finally:
            # Reports are temp outputs too: remove them as soon as they are sent.
            md_path.unlink(missing_ok=True)
            json_path.unlink(missing_ok=True)
            if card_path is not None:
                card_path.unlink(missing_ok=True)


# ---------------------------------------------------------------- CLI

async def check_token_async(config):
    """Connect with MTProto + bot token and call get_me. Returns bot info."""
    bot = ScannerBot(config)
    client = bot.make_client()
    try:
        await client.start(bot_token=config["token"])
        me = await client.get_me()
        return {"username": me.username, "first_name": me.first_name, "id": me.id}
    finally:
        await client.disconnect()


def selftest(ipa):
    with tempfile.TemporaryDirectory(prefix="ipa-selftest-") as tmp:
        result = scan_ipa(ipa, Path(tmp) / "work")
    print(build_summary(result))
    print(f"\n[risk={result['risk']['score']} level={result['risk']['level_en']}]")
    return 0


def main(argv=None):
    args = list(argv if argv is not None else sys.argv[1:])
    if "--help" in args or "-h" in args:
        print("Usage: python3 bot.py [--check-config | --check-token | --selftest <file.ipa>]")
        print("Env: TELEGRAM_BOT_TOKEN, TELEGRAM_API_ID, TELEGRAM_API_HASH, ADMIN_USER_IDS")
        return 0
    if "--check-config" in args:
        try:
            cfg = load_config()
        except ConfigError as e:
            print(f"CONFIG ERROR: {e}", file=sys.stderr)
            return 2
        print("Config OK: TELEGRAM_BOT_TOKEN, TELEGRAM_API_ID, TELEGRAM_API_HASH are set; "
              f"ADMIN_USER_IDS has {len(cfg['admin_ids'])} id(s).")
        return 0
    if "--selftest" in args:
        idx = args.index("--selftest")
        ipa = args[idx + 1] if idx + 1 < len(args) else "test/TestGame.ipa"
        return selftest(ipa)
    try:
        config = load_config()
    except ConfigError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        return 2
    if "--check-token" in args:
        try:
            me = asyncio.run(check_token_async(config))
        except Exception as e:
            print(f"TOKEN INVALID: {e}", file=sys.stderr)
            print("Fix: get a new token from @BotFather and set TELEGRAM_BOT_TOKEN; "
                  "also check TELEGRAM_API_ID / TELEGRAM_API_HASH from https://my.telegram.org.",
                  file=sys.stderr)
            return 2
        print(f"Token OK. Bot: @{me.get('username')} — {me.get('first_name')} (id {me.get('id')})")
        return 0
    try:
        asyncio.run(ScannerBot(config).start())
    except ConfigError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
        return 0
    except Exception as e:
        print(f"Bot failed to start: {e}", file=sys.stderr)
        print("Check TELEGRAM_BOT_TOKEN (@BotFather) and TELEGRAM_API_ID / "
              "TELEGRAM_API_HASH (https://my.telegram.org).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
