#!/usr/bin/env python3
"""SibStar IPA Scanner — PNG summary card (v6).

A clean, professional summary card for one scan result: app name,
bundle ID, version, risk score 0-100 in a calm colour (green / amber /
muted red — never red-everywhere), the tampering verdict in a soft
banner, the unknown tweak server when one exists, the original-vs-tweak
risk split, key counts, the four privacy answers as EVIDENCE verdicts
(تأیید شد / شواهدی نیست / فقط توانایی دارد — never a scary "بله" on
capability alone), and the top findings. The final verdict is shown
once at the top, not repeated as a fifth answer row.

Design rules (v6, after the v5 card was judged unprofessional):
- White card on a soft grey background, one dark-slate header band.
- Generous spacing; every block is laid out from a running y cursor,
  so nothing overlaps or clips.
- Persian text is drawn right-aligned. When Pillow has libraqm (the
  usual case, including the official wheels) the raw Persian text is
  drawn and raqm shapes it; when raqm is missing, arabic-reshaper +
  python-bidi shape it first. DejaVu Sans covers Arabic script as
  well as Latin letters, digits and punctuation in one font, so mixed
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


# v5 evidence verdicts: never a scary "بله" on capability alone.
# "confirmed" = direct evidence, "no-evidence" = no evidence found,
# "capability" = the capability exists but sending/seeing is NOT proven.
VERDICT_FA = {
    "confirmed": "تأیید شد",
    "no-evidence": "شواهدی نیست",
    "capability": "فقط توانایی دارد",
    "yes": "بله", "possible": "ممکن است", "unknown": "نامشخص",
    "partial": "بررسی ناقص", "risky": "بالا",
    "caution": "متوسط", "ok": "کم‌ریسک",
}

# Calm palette: the score circle is the only strongly coloured element.
RISK_COLORS = {
    "low": (21, 128, 61),      # calm green
    "medium": (180, 83, 9),    # calm amber
    "high": (185, 28, 28),     # muted red (not bright alarm red)
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
    draw.text((x_right, y), shaped, font=font, fill=fill, anchor="ra")
    return y + int(font.size * 1.4)


def generate_report_card(result, out_path):
    """Render the summary card PNG for a scan result dict. Returns out_path.

    v6: the card height is dynamic — content is drawn on a tall
    transparent layer, then composited onto a white rounded card sized
    to the content. A clean app no longer gets a half-empty card, and
    a busy one never overflows the footer. The final verdict appears
    once (at the top), the four privacy answers follow, the unknown
    tweak server (if any) is shown under the tampering banner, and the
    one-line static-analysis limit sits above the footer.
    """
    out_path = Path(out_path)
    W = 1200
    M = 64  # margin
    BG = (244, 245, 247)
    CARD = (255, 255, 255)
    INK = (17, 24, 39)
    MUTED = (107, 114, 128)
    LINE = (229, 231, 235)
    HEADER = (31, 41, 55)  # dark slate, not red

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
    answers = {a["id"]: a for a in (result.get("privacy_answers", []) or [])}
    verdict = answers.get("verdict", {}) or {}
    tamp = result.get("tampering") or {}

    # Content layer (transparent); the card is sized to the content
    # afterwards, so nothing can overflow or leave a half-empty card.
    layer = Image.new("RGBA", (W, 1700), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)

    # Header band (dark slate, calm)
    draw.rounded_rectangle([24, 24, W - 24, 132], radius=28, fill=HEADER + (255,))
    draw.rectangle([24, 104, W - 24, 132], fill=HEADER + (255,))
    f_title = load_font(32, bold=True)
    draw.text((W - M, 46), fa("سیب‌استار — گزارش اسکن IPA"), font=f_title,
              fill=(255, 255, 255, 255), anchor="ra")
    f_sub = load_font(23)
    draw.text((W - M, 94), fa("SibStar IPA Scanner  •  تحلیل ایستا"),
              font=f_sub, fill=(203, 213, 225, 255), anchor="ra")

    # Score circle (left) + app name/meta (right). The name column is
    # width-limited so it can never run into the circle.
    cx, cy, r = 152, 252, 88
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color + (255,))
    f_score = load_font(62, bold=True)
    draw.text((cx, cy - 10), str(score), font=f_score, fill=(255, 255, 255, 255),
              anchor="mm")
    f_outof = load_font(21)
    draw.text((cx, cy + 50), "/100", font=f_outof, fill=(255, 255, 255, 255), anchor="mm")
    f_level = load_font(28, bold=True)
    draw.text((cx, cy + r + 32), fa(f"ریسک {level_fa}"), font=f_level,
              fill=dark + (255,), anchor="mm")

    y = 176
    f_name = load_font(42, bold=True)
    for line in wrap_text(draw, name, f_name, W - 2 * M - 250):
        y = draw_rtl(draw, W - M, y, line, f_name, INK + (255,))
    f_meta = load_font(25)
    meta = f"{bundle}  •  نسخه {version}  •  حداقل iOS {min_os}"
    for line in wrap_text(draw, meta, f_meta, W - 2 * M - 250):
        y = draw_rtl(draw, W - M, y, line, f_meta, MUTED + (255,))

    # Everything below starts under both the name block and the circle.
    y = max(y, cy + r + 78) + 10

    # Tampering banner: soft amber if tampered, soft green if clean.
    # Never a red background — the verdict is in plain words.
    # The banner wraps properly (y advances per line) and, when the
    # tweak talks to a server the original app never talks to, that
    # server is shown right under the banner — it is the single most
    # important fact for a tampered app.
    if tamp.get("tampered"):
        banner_bg, banner_ink = (254, 243, 199), (146, 64, 14)
        banner = (f"دستکاری شخص ثالث: تأیید شد — "
                  f"{tamp.get('injected_dylib_count', 0)} dylib تزریقی "
                  f"(MobileSubstrate)")
    else:
        banner_bg, banner_ink = (236, 253, 245), (6, 95, 70)
        banner = "دستکاری شخص ثالث: شواهدی نیست"
    f_banner = load_font(27, bold=True)
    banner_lines = wrap_text(draw, banner, f_banner, W - 2 * M - 32)
    banner_h = 62 + max(0, len(banner_lines) - 1) * 38
    draw.rounded_rectangle([M, y, W - M, y + banner_h], radius=14,
                           fill=banner_bg + (255,))
    by = y + 14
    for line in banner_lines:
        by = draw_rtl(draw, W - M - 16, by, line, f_banner, banner_ink + (255,))
    y += banner_h + 12
    if tamp.get("unknown_tweak_servers"):
        f_warn = load_font(25, bold=True)
        warn = "سرور ناشناخته‌ی توئیک: " + "، ".join(tamp["unknown_tweak_servers"])
        for line in wrap_text(draw, warn, f_warn, W - 2 * M):
            y = draw_rtl(draw, W - M, y, line, f_warn, (146, 64, 14, 255))
        y += 6

    # Risk split, plain language.
    f_split = load_font(25)
    split = (f"ریسک برنامه‌ی اصلی: {risk.get('original_points', '?')}  •  "
             f"ریسک توئیک: {risk.get('tweak_points', '?')}")
    y = draw_rtl(draw, W - M, y, split, f_split, MUTED + (255,))
    y += 8
    # Verdict line (plain language, not alarmist).
    f_verdict = load_font(25, bold=True)
    verdict_text = verdict.get("answer_fa") or ""
    if verdict_text:
        for line in wrap_text(draw, f"حکم نهایی: {verdict_text}", f_verdict, W - 2 * M):
            y = draw_rtl(draw, W - M, y, line, f_verdict, dark + (255,))

    y += 16
    draw.line([M, y, W - M, y], fill=LINE + (255,), width=2)
    y += 20

    # Stats grid: 3 columns x 2 rows, light boxes.
    bin_strings = result.get("binary_strings", {}) or {}
    suspicious = len(bin_strings.get("suspicious", []) or []) if not bin_strings.get("unavailable") else 0
    stats = [
        ("دسترسی‌ها", str(result.get("permission_count", 0))),
        ("ترکرها", str(len(result.get("known_trackers", []) or []))),
        ("دامنه‌های واقعی", str(len(result.get("domains", []) or []))),
        ("لینک ناامن", str(len(result.get("insecure_http_urls", []) or []))),
        ("فایل dylib", str(result.get("dylib_count", 0))),
        ("بسته .deb", str(result.get("deb_count", 0))),
    ]
    col_w = (W - 2 * M) // 3
    f_stat_n = load_font(38, bold=True)
    f_stat_l = load_font(23)
    for i, (label, value) in enumerate(stats):
        col, row = i % 3, i // 3
        x0 = M + col * col_w
        yy = y + row * 102
        # Box is 86 tall: number (38px) + label (23px) with room for
        # Persian dots/descenders — a 76px box clipped the label bottoms.
        draw.rounded_rectangle([x0, yy, x0 + col_w - 16, yy + 86], radius=14,
                               fill=(249, 250, 251, 255), outline=LINE + (255,), width=1)
        draw.text((x0 + (col_w - 16) // 2, yy + 10), value, font=f_stat_n,
                  fill=INK + (255,), anchor="ma")
        draw.text((x0 + (col_w - 16) // 2, yy + 52), fa(label), font=f_stat_l,
                  fill=MUTED + (255,), anchor="ma")
    y += 2 * 102 + 20

    # Privacy answers (4 rows): label in ink, verdict word in a calm colour.
    # Only the four questions — the final verdict is already shown at
    # the top of the card, so a fifth "حکم نهایی" row would duplicate it.
    f_q = load_font(26, bold=True)
    f_a = load_font(25)
    draw.text((W - M, y), fa("پاسخ به سؤال‌های حریم خصوصی"), font=f_q, fill=INK + (255,), anchor="ra")
    y += 42
    q_labels = [
        ("tampering", "دستکاری شخص ثالث:"),
        ("sends_photos_to_server", "ارسال عکس به سرور:"),
        ("third_party_can_see_photos", "دسترسی شخص ثالث به عکس:"),
        ("collects_photo_info", "جمع‌آوری اطلاعات عکس:"),
    ]
    for qid, label in q_labels:
        a = answers.get(qid, {}) or {}
        verdict_word = VERDICT_FA.get(a.get("verdict", ""), a.get("answer_fa", "—"))
        # One wrapped line per answer, all in ink: the score circle is
        # the only coloured verdict element, keeping the card calm.
        line = f"{label} {verdict_word}"
        for wrapped in wrap_text(draw, line, f_a, W - 2 * M):
            y = draw_rtl(draw, W - M, y, wrapped, f_a, INK + (255,))
    y += 8

    # Top findings (max 3), muted. Finding titles are shortened first:
    # a long mixed Persian/Latin title wraps into an orphan word
    # ("است)") on its own line, which looks broken.
    top = [f for f in (result.get("findings", []) or [])
           if f.get("severity") in ("critical", "high")][:3]
    if top:
        draw.line([M, y, W - M, y], fill=LINE + (255,), width=2)
        y += 16
        draw.text((W - M, y), fa("مهم‌ترین یافته‌ها"), font=f_q, fill=INK + (255,), anchor="ra")
        y += 40
        for f in top:
            # "http://" inside RTL text gets bidi-mirrored to "//:http";
            # the card is a visual summary, so shorten it here only.
            # The bullet is drawn separately at the right edge: a "•"
            # prefix inside an RTL line ends up at the visual left.
            text = (f.get("title_fa", "") or "").replace("http://", "http")
            if len(text) > 85:
                # Cut at a word boundary, never mid-word: a truncated
                # fragment like "اس…" on its own line looks broken.
                cut = text[:84]
                cut = cut[:cut.rfind(" ")].rstrip() if " " in cut else cut
                text = cut + "…"
            for wrapped in wrap_text(draw, text, f_a, W - 2 * M - 28):
                draw.text((W - M, y + 6), "•", font=f_a, fill=MUTED + (255,), anchor="ra")
                y = draw_rtl(draw, W - M - 28, y, wrapped, f_a, MUTED + (255,))
    else:
        draw.line([M, y, W - M, y], fill=LINE + (255,), width=2)
        y += 16
        y = draw_rtl(draw, W - M, y, "یافته‌ی مهمی نیست — جزئیات کامل در گزارش ضمیمه است.",
                     f_a, MUTED + (255,))

    # Card height follows the content: room for the limit line, the
    # footer, and the bottom margin — nothing more.
    H = y + 118
    f_foot = load_font(21)
    draw.text((W - M, H - 96), fa("تحلیل ایستا است — ترافیک واقعی شبکه را نمی‌بیند."),
              font=f_foot, fill=MUTED + (255,), anchor="ra")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    draw.text((W - M, H - 62), fa(f"sibstars.ir  •  {stamp}"), font=f_foot,
              fill=MUTED + (255,), anchor="ra")

    # Compose: soft-grey page, white rounded card, content on top.
    img = Image.new("RGBA", (W, H), BG + (255,))
    card_draw = ImageDraw.Draw(img)
    card_draw.rounded_rectangle([24, 24, W - 24, H - 24], radius=28,
                                fill=CARD + (255,), outline=LINE + (255,), width=2)
    img.alpha_composite(layer.crop((0, 0, W, H)))
    img = img.convert("RGB")

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
