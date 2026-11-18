#!/usr/bin/env python3
"""SibStar IPA Scanner — PNG summary card (v3).

Generates a polished, readable PNG report card for one scan result:
app name, bundle ID, version, risk score 0-100 with a clear colour
(green / amber / red), risk level in Persian, the four privacy-question
verdicts, key counts (permissions, trackers, domains, insecure links,
dylibs, suspicious patterns) and the top findings.

Persian text is drawn right-aligned. When Pillow has libraqm (the usual
case, including the official wheels) the raw Persian text is drawn and
raqm shapes it; when raqm is missing, arabic-reshaper + python-bidi shape
it first. DejaVu Sans is used because it covers Arabic script as well as
Latin letters, digits and punctuation (—, •, /) in one font, so mixed
Persian+Latin lines never turn into tofu boxes.

Usage:
  python3 report_card.py test/TestGame.ipa --out /tmp/card.png
  # or from code:
  from report_card import generate_report_card
  generate_report_card(scan_result_dict, Path("card.png"))
"""
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from PIL import Image, ImageDraw, ImageFont
from PIL import features as _pil_features

# Pillow wheels ship with libraqm, which shapes Arabic script and handles
# bidi itself. If raqm is present we must draw RAW Persian text — feeding it
# pre-shaped (presentation-form) text would double-shape into garbage.
# Only when raqm is missing do we shape with arabic-reshaper + python-bidi.
_RAQM = _pil_features.check("raqm")

ARABIC_RE = re.compile(r"[\u0600-\u06FF]")

try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    _RESHAPER = arabic_reshaper.ArabicReshaper(
        configuration={"delete_harakat": False, "support_ligatures": True})
except Exception:  # pragma: no cover - graceful fallback without the libs
    _RESHAPER = None


def fa(text):
    """Prepare Persian/Arabic text for Pillow.

    With raqm: return the raw text untouched (raqm shapes it).
    Without raqm: reshape + bidi so connected letters render correctly.
    Latin text is untouched either way.
    """
    text = str(text or "")
    if _RAQM or not ARABIC_RE.search(text) or _RESHAPER is None:
        return text
    try:
        return get_display(_RESHAPER.reshape(text))
    except Exception:
        return text


def is_persian(text):
    return bool(ARABIC_RE.search(str(text or "")))


VERDICT_FA = {
    "yes": "بله", "possible": "ممکن است", "no-evidence": "شواهدی نیست",
    "unknown": "نامشخص", "partial": "بررسی ناقص", "risky": "پرخطر",
    "caution": "احتیاط", "ok": "کم‌ریسک",
}

RISK_COLORS = {
    "low": (22, 163, 74),      # green
    "medium": (217, 119, 6),   # amber
    "high": (220, 38, 38),     # red
}
RISK_DARK = {"low": (20, 83, 45), "medium": (120, 53, 15), "high": (127, 29, 29)}

FONT_CANDIDATES = [
    # DejaVu first: it covers Arabic script AND Latin/punctuation
    # (—, •, /, digits) in one font, so mixed Persian+Latin lines never
    # fall back to tofu boxes. Noto Sans Arabic is the fallback.
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansArabic-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansArabicUI-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansArabicUI-Regular.ttf",
]


def find_font(bold=False):
    """Best available TTF font path (bold first, then regular)."""
    cands = FONT_CANDIDATES
    if bold:
        cands = [p for p in FONT_CANDIDATES if "Bold" in p] + \
                [p for p in FONT_CANDIDATES if "Bold" not in p]
    else:
        cands = [p for p in FONT_CANDIDATES if "Bold" not in p] + \
                [p for p in FONT_CANDIDATES if "Bold" in p]
    for p in cands:
        if Path(p).is_file():
            return p
    return None


def load_font(size, bold=False):
    path = find_font(bold=bold)
    if path:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default(size=size) if hasattr(ImageFont, "load_default") \
        else ImageFont.load_default()


def wrap_text(draw, text, font, max_width):
    """Wrap a (possibly Persian) string into lines fitting max_width."""
    words = str(text).split()
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(fa(trial), font=font) <= max_width:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


def draw_rtl(draw, x_right, y, text, font, fill):
    """Draw one line right-aligned (Persian) or left-aligned (Latin)."""
    shaped = fa(text)
    if is_persian(text):
        draw.text((x_right, y), shaped, font=font, fill=fill, anchor="ra")
    else:
        draw.text((x_right, y), shaped, font=font, fill=fill, anchor="ra")
    return y + int(font.size * 1.35)


def generate_report_card(result, out_path):
    """Render the summary card PNG for a scan result dict. Returns out_path."""
    out_path = Path(out_path)
    W, H = 1200, 1180
    M = 64  # margin
    BG = (238, 241, 245)
    CARD = (255, 255, 255)
    INK = (17, 24, 39)
    MUTED = (107, 114, 128)
    LINE = (229, 231, 235)

    risk = result.get("risk", {}) or {}
    score = int(risk.get("score", 0) or 0)
    level_en = risk.get("level_en", "low") or "low"
    level_fa = risk.get("level_fa", "") or ""
    color = RISK_COLORS.get(level_en, RISK_COLORS["low"])
    dark = RISK_DARK.get(level_en, RISK_DARK["low"])
    ident = result.get("identity", {}) or {}
    name = ident.get("display_name") or "برنامه"
    bundle = ident.get("bundle_id") or "—"
    version = ident.get("version") or "—"
    min_os = ident.get("minimum_os") or "—"
    sdk = (result.get("sdk_info", {}) or {}).get("sdk_name") or ""
    answers = {a["id"]: a for a in (result.get("privacy_answers", []) or [])}
    verdict = answers.get("verdict", {}) or {}

    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    # Card
    draw.rounded_rectangle([24, 24, W - 24, H - 24], radius=28, fill=CARD,
                           outline=LINE, width=2)
    # Header band
    draw.rounded_rectangle([24, 24, W - 24, 130], radius=28, fill=color)
    draw.rectangle([24, 102, W - 24, 130], fill=color)
    f_title = load_font(34, bold=True)
    draw.text((W - M, 48), fa("سیب‌استار — گزارش اسکن IPA"), font=f_title,
              fill=(255, 255, 255), anchor="ra")
    f_sub = load_font(24)
    draw.text((W - M, 96), fa("SibStar IPA Scanner v3"), font=f_sub,
              fill=(255, 255, 255), anchor="ra")

    # App name + score circle
    y = 170
    f_name = load_font(46, bold=True)
    for line in wrap_text(draw, name, f_name, W - 2 * M - 260):
        y = draw_rtl(draw, W - M, y, line, f_name, INK)
    f_meta = load_font(26)
    meta = f"{bundle}  •  نسخه {version}  •  حداقل iOS {min_os}"
    if sdk:
        meta += f"  •  SDK {sdk}"
    for line in wrap_text(draw, meta, f_meta, W - 2 * M - 260):
        y = draw_rtl(draw, W - M, y, line, f_meta, MUTED)

    # Score circle (top-right area is taken by the name; circle goes left)
    cx, cy, r = 150, 250, 92
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)
    f_score = load_font(64, bold=True)
    draw.text((cx, cy - 8), str(score), font=f_score, fill=(255, 255, 255),
              anchor="mm")
    f_outof = load_font(22)
    draw.text((cx, cy + 52), "/100", font=f_outof, fill=(255, 255, 255), anchor="mm")
    f_level = load_font(30, bold=True)
    draw.text((cx, cy + r + 34), fa(f"ریسک {level_fa}"), font=f_level,
              fill=dark, anchor="mm")

    # Verdict line
    y = max(y, cy + r + 84) + 8
    f_verdict = load_font(28, bold=True)
    verdict_text = verdict.get("answer_fa") or ""
    if verdict_text:
        for line in wrap_text(draw, f"حکم نهایی: {verdict_text}", f_verdict, W - 2 * M):
            y = draw_rtl(draw, W - M, y, line, f_verdict, dark)

    y += 18
    draw.line([M, y, W - M, y], fill=LINE, width=2)
    y += 22

    # Stats grid: 3 columns x 2 rows
    bin_strings = result.get("binary_strings", {}) or {}
    suspicious = len(bin_strings.get("suspicious", []) or []) if not bin_strings.get("unavailable") else 0
    stats = [
        ("دسترسی‌ها", str(result.get("permission_count", 0))),
        ("ترکرها", str(len(result.get("known_trackers", []) or []))),
        ("دامنه‌ها", str(len(result.get("domains", []) or []))),
        ("لینک ناامن http", str(len(result.get("insecure_http_urls", []) or []))),
        ("فایل dylib", str(result.get("dylib_count", 0))),
        ("الگوی مشکوک", str(suspicious + int(result.get("dylib_suspicious_count", 0) or 0))),
    ]
    col_w = (W - 2 * M) // 3
    f_stat_n = load_font(40, bold=True)
    f_stat_l = load_font(24)
    for i, (label, value) in enumerate(stats):
        col, row = i % 3, i // 3
        x0 = M + col * col_w
        yy = y + row * 96
        draw.rounded_rectangle([x0, yy, x0 + col_w - 16, yy + 80], radius=14,
                               fill=(249, 250, 251), outline=LINE, width=1)
        draw.text((x0 + (col_w - 16) // 2, yy + 12), value, font=f_stat_n,
                  fill=INK, anchor="ma")
        draw.text((x0 + (col_w - 16) // 2, yy + 52), fa(label), font=f_stat_l,
                  fill=MUTED, anchor="ma")
    y += 2 * 96 + 22

    # Four privacy questions (short verdicts)
    f_q = load_font(26, bold=True)
    f_a = load_font(26)
    q_labels = [
        ("sends_photos_to_server", "ارسال عکس به سرور:"),
        ("third_party_can_see_photos", "دسترسی شخص ثالث به عکس:"),
        ("collects_photo_info", "جمع‌آوری اطلاعات عکس:"),
        ("verdict", "حکم نهایی:"),
    ]
    draw.text((W - M, y), fa("پاسخ به سؤال‌های حریم خصوصی"), font=f_q, fill=INK, anchor="ra")
    y += 44
    for qid, label in q_labels:
        a = answers.get(qid, {}) or {}
        verdict_word = VERDICT_FA.get(a.get("verdict", ""), a.get("answer_fa", "—"))
        line = f"{label} {verdict_word}"
        for wrapped in wrap_text(draw, line, f_a, W - 2 * M):
            y = draw_rtl(draw, W - M, y, wrapped, f_a, INK)
    y += 10

    # Top findings (max 3)
    top = [f for f in (result.get("findings", []) or [])
           if f.get("severity") in ("critical", "high")][:3]
    if top:
        draw.line([M, y, W - M, y], fill=LINE, width=2)
        y += 18
        draw.text((W - M, y), fa("مهم‌ترین یافته‌ها"), font=f_q, fill=INK, anchor="ra")
        y += 44
        for f in top:
            # "http://" inside RTL text gets bidi-mirrored to "//:http";
            # the card is a visual summary, so shorten it here only.
            text = "• " + (f.get("title_fa", "") or "").replace("http://", "http")
            for wrapped in wrap_text(draw, text, f_a, W - 2 * M):
                y = draw_rtl(draw, W - M, y, wrapped, f_a, MUTED)

    # Footer
    f_foot = load_font(22)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    draw.text((W - M, H - 64), fa(f"sibstars.ir  •  {stamp}"), font=f_foot,
              fill=MUTED, anchor="ra")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, format="PNG")
    return out_path


def main(argv=None):
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or "--help" in args or "-h" in args:
        print("Usage: python3 report_card.py <file.ipa> [--out card.png]")
        return 0 if args else 2
    ipa = args[0]
    out = Path("card.png")
    if "--out" in args:
        out = Path(args[args.index("--out") + 1])
    from scanner import scan_ipa
    with tempfile.TemporaryDirectory(prefix="ipa-card-") as tmp:
        result = scan_ipa(ipa, Path(tmp) / "work")
    generate_report_card(result, out)
    print(f"Card written: {out} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
