#!/usr/bin/env python3
"""SibStar IPA Scanner — PNG summary card (customer version).

The card is shown to NON-TECHNICAL end customers who do not
understand security terms, so it speaks plain simple Persian:
- No jargon anywhere on the card: no "dylib", no "MobileSubstrate",
  no "توئیک", no "IPA", no "تحلیل ایستا", no "ATS", no bundle ID,
  no technical finding titles. Technical detail stays in the .md
  report only.
- The verdict is one friendly sentence a regular person
  understands ("این نسخه دستکاری شده است؛ با احتیاط استفاده
  کنید" / "مشکلی پیدا نشد؛ با خیال راحت استفاده کنید").
- The four privacy answers are plain questions ("عکس‌ها
  فرستاده می‌شوند؟") with plain one-line answers and
  descriptive verdict pills ("سالم"، "دستکاری شده"، "نه") —
  never a bare alarming "بله".
- The score is shown as a ring gauge with one plain line
  explaining it ("هرچه عدد کمتر باشد، بهتر است").
- Calm colours, generous spacing, no red-everywhere: the gauge
  arc, the verdict dot, the tampering panel and the pills are
  the only coloured elements.

Design:
- Soft-grey page, white rounded card, one dark-slate header band
  with a thin accent strip in the risk colour.
- Every block is laid out from a running y cursor on a tall layer;
  the card height follows the content, so a clean app gets a
  shorter card and nothing ever overflows the footer.
- When Pillow has libraqm the raw Persian text is drawn and raqm
  shapes it; when raqm is missing, arabic-reshaper + python-bidi
  shape it first. DejaVu Sans covers Arabic script as well as
  Latin letters, digits and punctuation in one font, so mixed
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


# Verdict words for the detailed report / bot summary. The CARD does
# not use these: its pills use plain customer words from
# _customer_pill ("سالم"، "دستکاری شده"، "نه") instead.
VERDICT_FA = {
    "confirmed": "تأیید شد",
    "no-evidence": "شواهدی نیست",
    "suspicious": "مشکوک",
    "yes": "بله", "possible": "ممکن است", "unknown": "نامشخص",
    "partial": "بررسی ناقص", "risky": "بالا",
    "caution": "متوسط", "ok": "کم‌ریسک",
}

# Calm palette. Colour is used sparingly: the gauge arc, the verdict
# dot, the tampering panel and the verdict pills — never red-everywhere.
RISK_COLORS = {
    "low": (21, 128, 61),      # calm green
    "medium": (180, 83, 9),    # calm amber
    "high": (185, 28, 28),     # muted red (not bright alarm red)
}
RISK_DARK = {"low": (20, 83, 45), "medium": (120, 53, 15), "high": (127, 29, 29)}

# Verdict pills: green = good news, red = bad news, amber = caution.
PILL_GREEN = ((220, 252, 231), (22, 101, 52))
PILL_RED = ((254, 226, 226), (153, 27, 27))
PILL_AMBER = ((254, 243, 199), (146, 64, 14))
PILL_SLATE = ((241, 245, 249), (51, 65, 85))


def _customer_pill(qid, verdict):
    """(pill text, (bg, fg)) for a privacy answer — plain words a
    regular person understands, never a bare alarming "بله".

    "سالم" (clean) for no tampering, "دستکاری شده" for confirmed
    tampering, "نه" for "no, your photos are not sent", "اعلام شده"
    for declared photo collection (a neutral fact, amber).
    """
    if verdict == "suspicious":
        return "مشکوک", PILL_AMBER
    if qid == "tampering":
        return {"confirmed": ("دستکاری شده", PILL_RED),
                "no-evidence": ("سالم", PILL_GREEN)}.get(verdict, ("—", PILL_SLATE))
    if qid == "collects_photo_info":
        return {"confirmed": ("اعلام شده", PILL_AMBER),
                "no-evidence": ("نه", PILL_GREEN)}.get(verdict, ("—", PILL_SLATE))
    # sends_photos_to_server / third_party_can_see_photos
    if qid == "sends_photos_to_server":
        return {"confirmed": ("فرستاده می‌شود", PILL_RED),
                "no-evidence": ("نه", PILL_GREEN)}.get(verdict, ("—", PILL_SLATE))
    return {"confirmed": ("دیده می‌شود", PILL_RED),
            "no-evidence": ("نه", PILL_GREEN)}.get(verdict, ("—", PILL_SLATE))


def _customer_answers(result, answers):
    """Plain one-line answers for the four questions, in the
    customer's language. The scanner's answer_fa strings are for
    the detailed .md report; the card rephrases them here so no
    jargon ("نقطه‌ی آپلودی"، "dylib"، "توئیک") ever reaches a
    customer."""
    tamp = result.get("tampering") or {}
    n_injected = tamp.get("injected_dylib_count", 0)
    unknown = tamp.get("unknown_tweak_servers") or []
    try:
        from scanner import _photo_upload_domains
        has_upload = bool(_photo_upload_domains(result.get("domains", []) or []))
    except Exception:
        has_upload = False
    out = {}
    v5 = (answers.get("tampering", {}) or {}).get("verdict", "")
    if v5 == "confirmed":
        out["tampering"] = (f"این نسخه دستکاری شده؛ {n_injected} بخش اضافه "
                            "از یک منبع دیگر داخل آن هست")
    elif v5 == "suspicious":
        out["tampering"] = "به نظر می‌رسد دستکاری شده باشد؛ با احتیاط استفاده کنید"
    else:
        out["tampering"] = "نشانه‌ای از دستکاری پیدا نشد"
    if has_upload:
        out["sends_photos_to_server"] = "مدرکی از فرستادن عکس پیدا نشد"
    else:
        out["sends_photos_to_server"] = "عکس‌های شما جایی فرستاده نمی‌شود"
    if unknown:
        out["third_party_can_see_photos"] = "مدرکی از دیدن عکس پیدا نشد"
    else:
        out["third_party_can_see_photos"] = "کسی عکس‌های شما را نمی‌بیند"
    v3 = (answers.get("collects_photo_info", {}) or {}).get("verdict", "")
    if v3 == "confirmed":
        out["collects_photo_info"] = "در توضیحات برنامه اعلام شده است"
    else:
        out["collects_photo_info"] = "جمع‌آوری عکس اعلام نشده است"
    return out


def _customer_headline(result, level_en):
    """The verdict as ONE friendly sentence a regular person
    understands."""
    tamp = result.get("tampering") or {}
    if tamp.get("tampered"):
        return "این نسخه دستکاری شده است؛ با احتیاط استفاده کنید"
    if level_en == "low":
        return "مشکلی پیدا نشد؛ با خیال راحت استفاده کنید"
    if level_en == "medium":
        return "خطر جدی پیدا نشد؛ چند نکته‌ی کوچک هست"
    return "چند نکته‌ی مهم پیدا شد؛ با احتیاط استفاده کنید"


def _customer_notes(result):
    """Plain-language notes (max 3) for the "نکته‌های مهم" section,
    derived from the result data — never from technical finding
    titles, which are full of jargon and live in the .md report."""
    tamp = result.get("tampering") or {}
    unknown = tamp.get("unknown_tweak_servers") or []
    notes = []
    if tamp.get("tampered"):
        notes.append("این نسخه دستکاری شده؛ بخش‌های اضافه داخل آن هست")
    if unknown:
        notes.append("بخش اضافه با یک آدرس ناشناس در تماس است")
    n_http = len(result.get("insecure_http_urls", []) or [])
    if n_http:
        notes.append(f"{n_http} اتصال بدون محافظت پیدا شد")
    n_trackers = len(result.get("known_trackers", []) or [])
    if n_trackers:
        notes.append(f"{n_trackers} ابزار ردیابی در برنامه هست")
    notes = notes[:3]
    return notes or ["چیز مهم دیگری پیدا نشد."]


FONT_CANDIDATES = [
    # DejaVu first: it covers Arabic script AND Latin/punctuation
    # (—, •, /, digits, ✓) in one font, so mixed Persian+Latin lines
    # never fall back to tofu boxes. Noto Sans Arabic is the fallback.
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


def draw_pill(draw, x0, y_center, text, font, bg, fg, h=40, pad_x=20):
    """A rounded verdict pill, vertically centred on y_center.
    Returns the pill width. Text is centred (anchor mm)."""
    tw = draw.textlength(fa(text), font=font)
    w = max(132, int(tw) + 2 * pad_x)
    y0 = y_center - h // 2
    draw.rounded_rectangle([x0, y0, x0 + w, y0 + h], radius=h // 2,
                           fill=bg + (255,))
    draw.text(((2 * x0 + w) // 2, y_center), fa(text), font=font,
              fill=fg + (255,), anchor="mm")
    return w


def draw_gauge(draw, cx, cy, r, score, color):
    """A ring gauge: light track + coloured arc (score % of 360°)."""
    track = (226, 232, 240)
    draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                 outline=track + (255,), width=13)
    if score > 0:
        sweep = 360 * max(0, min(100, score)) / 100
        draw.arc([cx - r, cy - r, cx + r, cy + r], start=-90,
                 end=-90 + sweep, fill=color + (255,), width=13)


def draw_split_bar(layer, x, y, w, h, orig, tweak, total):
    """A rounded horizontal bar split original (slate, from the right)
    vs added parts (amber, to its left). Rounded corners via a mask, so
    the segments never poke out of the track's rounded ends."""
    bar = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    bd = ImageDraw.Draw(bar)
    bd.rectangle([0, 0, w, h], fill=(226, 232, 240, 255))
    if total > 0:
        ow = int(round(w * orig / total))
        tw = w - ow
        if ow > 0:
            bd.rectangle([w - ow, 0, w, h], fill=(51, 65, 85, 255))
        if tw > 0:
            bd.rectangle([w - ow - tw, 0, w - ow, h], fill=(217, 119, 6, 255))
    mask = Image.new("L", (w, h), 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([0, 0, w, h], radius=h // 2, fill=255)
    layer.paste(bar, (x, y), mask)


def generate_report_card(result, out_path):
    """Render the summary card PNG for a scan result dict. Returns out_path."""
    out_path = Path(out_path)
    W = 1200
    M = 72  # margin — wider than before, for a more premium feel
    BG = (243, 244, 246)
    CARD = (255, 255, 255)
    INK = (15, 23, 42)
    MUTED = (100, 116, 139)
    LINE = (226, 232, 240)
    HEADER = (30, 41, 59)  # dark slate, not red
    BOX = (249, 250, 251)

    risk = result.get("risk", {}) or {}
    score = int(risk.get("score", 0) or 0)
    level_en = risk.get("level_en", "low") or "low"
    level_fa = risk.get("level_fa", "") or ""
    color = RISK_COLORS.get(level_en, RISK_COLORS["low"])
    dark = RISK_DARK.get(level_en, RISK_DARK["low"])
    ident = result.get("identity", {}) or {}
    name = ident.get("display_name") or "برنامه"
    version = ident.get("version") or "—"
    min_os = ident.get("minimum_os") or "—"
    answers = {a["id"]: a for a in (result.get("privacy_answers", []) or [])}
    tamp = result.get("tampering") or {}
    orig_pts = risk.get("original_points", 0) or 0
    tweak_pts = risk.get("tweak_points", 0) or 0
    plain_answers = _customer_answers(result, answers)

    # Content layer (transparent); the card is sized to the content
    # afterwards, so nothing can overflow or leave a half-empty card.
    layer = Image.new("RGBA", (W, 2400), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    CW = W - 2 * M  # content width

    # ---- Header band (dark slate) with a thin accent strip ----
    draw.rounded_rectangle([24, 24, W - 24, 138], radius=28, fill=HEADER + (255,))
    draw.rectangle([24, 110, W - 24, 138], fill=HEADER + (255,))
    # Accent strip in the risk colour, clipped to the band's bottom.
    strip = Image.new("RGBA", (W - 48, 6), (0, 0, 0, 0))
    sd = ImageDraw.Draw(strip)
    sd.rectangle([0, 0, W - 48, 6], fill=color + (255,))
    layer.paste(strip, (24, 132), strip)
    f_title = load_font(32, bold=True)
    draw.text((W - M, 44), fa("سیب‌استار — گزارش بررسی برنامه"), font=f_title,
              fill=(255, 255, 255, 255), anchor="ra")
    f_sub = load_font(22)
    draw.text((W - M, 92), fa("بررسی امنیت و حریم خصوصی"),
              font=f_sub, fill=(203, 213, 225, 255), anchor="ra")

    # ---- Hero: app identity (right) + score ring (left) ----
    # No bundle ID on the card: customers do not care about it and
    # it only jumbles the bidi layout. One plain version line only.
    y = 172
    f_name = load_font(42, bold=True)
    for line in wrap_text(draw, name, f_name, CW - 260):
        y = draw_rtl(draw, W - M, y, line, f_name, INK + (255,))
    y += 6
    f_meta = load_font(24)
    y = draw_rtl(draw, W - M, y, f"نسخه {version}  •  نیاز به iOS {min_os} به بالا",
                 f_meta, MUTED + (255,))
    hero_text_bottom = y

    cx, cy, r = 168, 282, 76
    draw_gauge(draw, cx, cy, r, score, color)
    f_score = load_font(56, bold=True)
    draw.text((cx, cy - 6), str(score), font=f_score, fill=INK + (255,),
              anchor="mm")
    f_outof = load_font(20)
    draw.text((cx, cy + 40), "/100", font=f_outof, fill=MUTED + (255,), anchor="mm")
    f_level = load_font(26, bold=True)
    draw.text((cx, cy + r + 28), fa(f"ریسک {level_fa}"), font=f_level,
              fill=dark + (255,), anchor="mm")
    # The score explained in one plain line: lower is better.
    f_caption = load_font(20)
    draw.text((cx, cy + r + 62), fa("هرچه عدد کمتر باشد، بهتر است"),
              font=f_caption, fill=MUTED + (255,), anchor="mm")
    y = max(hero_text_bottom, cy + r + 62 + 26) + 26

    # ---- Verdict headline: ONE friendly sentence, with a coloured dot ----
    f_verdict = load_font(28, bold=True)
    headline = _customer_headline(result, level_en)
    draw.ellipse([W - M - 13, y + 12, W - M + 1, y + 26],
                 fill=color + (255,))
    for line in wrap_text(draw, headline, f_verdict, CW - 28):
        y = draw_rtl(draw, W - M - 28, y, line, f_verdict, INK + (255,))
    y += 6

    # ---- Tampering panel: soft background, icon circle at the right ----
    # Plain words only: "بخش اضافه" instead of "dylib"/"MobileSubstrate",
    # "آدرس ناشناس" instead of "سرور ناشناخته‌ی توئیک".
    tampered = bool(tamp.get("tampered"))
    suspicious = tamp.get("verdict") == "suspicious"
    if tampered:
        panel_bg, panel_ink = (254, 243, 199), (146, 64, 14)
        icon, icon_bg = "!", (217, 119, 6)
        panel_line = "این نسخه دستکاری شده است"
    elif suspicious:
        panel_bg, panel_ink = (254, 243, 199), (146, 64, 14)
        icon, icon_bg = "!", (217, 119, 6)
        panel_line = "به نظر می‌رسد این نسخه دستکاری شده باشد"
    else:
        panel_bg, panel_ink = (236, 253, 245), (6, 95, 70)
        icon, icon_bg = "✓", (22, 163, 74)
        panel_line = "این نسخه دستکاری نشده است"
    f_panel = load_font(26, bold=True)
    panel_lines = wrap_text(draw, panel_line, f_panel, CW - 32 - 56)
    sub_lines = []
    if tamp.get("unknown_tweak_servers"):
        f_sub2 = load_font(24, bold=True)
        sub_lines = wrap_text(
            draw, "آدرس ناشناس: " + "، ".join(tamp["unknown_tweak_servers"]),
            f_sub2, CW - 32 - 56)
    panel_h = 24 + 36 * len(panel_lines) + (34 * len(sub_lines) if sub_lines else 0) + 22
    draw.rounded_rectangle([M, y, W - M, y + panel_h], radius=16,
                           fill=panel_bg + (255,))
    # Icon circle at the panel's right edge.
    icx, icy = W - M - 16 - 17, y + panel_h // 2
    draw.ellipse([icx - 17, icy - 17, icx + 17, icy + 17], fill=icon_bg + (255,))
    f_icon = load_font(24, bold=True)
    draw.text((icx, icy - 1), icon, font=f_icon, fill=(255, 255, 255, 255),
              anchor="mm")
    py = y + 22
    for line in panel_lines:
        py = draw_rtl(draw, W - M - 16 - 46, py, line, f_panel, panel_ink + (255,))
    if sub_lines:
        f_sub2 = load_font(24, bold=True)
        for line in sub_lines:
            py = draw_rtl(draw, W - M - 16 - 46, py, line, f_sub2, panel_ink + (255,))
    y += panel_h + 24

    # ---- Risk composition bar: where did this score come from? ----
    f_bar_label = load_font(22)
    y = draw_rtl(draw, W - M, y, "این امتیاز از کجا آمده؟", f_bar_label, MUTED + (255,))
    y += 4
    total_pts = orig_pts + tweak_pts
    draw_split_bar(layer, M, y, CW, 16, orig_pts, tweak_pts,
                   total_pts if total_pts > 0 else 1)
    y += 16 + 10
    f_split = load_font(24)
    split = (f"برنامه‌ی اصلی: {orig_pts}  •  بخش‌های اضافه: {tweak_pts}")
    y = draw_rtl(draw, W - M, y, split, f_split, MUTED + (255,))
    y += 26

    # ---- Plain facts: one row of four boxes, no unexplained numbers ----
    stats = [
        ("دسترسی‌ها", str(result.get("permission_count", 0))),
        ("آدرس‌های اینترنتی", str(len(result.get("domains", []) or []))),
        ("بخش‌های اضافه", str(tamp.get("injected_dylib_count", 0))),
        ("اتصال بدون محافظت", str(len(result.get("insecure_http_urls", []) or []))),
    ]
    col_w = CW // 4
    f_stat_n = load_font(38, bold=True)
    f_stat_l = load_font(22)
    for i, (label, value) in enumerate(stats):
        x0 = M + i * col_w
        draw.rounded_rectangle([x0, y, x0 + col_w - 14, y + 92], radius=16,
                               fill=BOX + (255,), outline=LINE + (255,), width=1)
        draw.text((x0 + (col_w - 14) // 2, y + 12), value, font=f_stat_n,
                  fill=INK + (255,), anchor="ma")
        draw.text((x0 + (col_w - 14) // 2, y + 56), fa(label), font=f_stat_l,
                  fill=MUTED + (255,), anchor="ma")
    y += 92 + 26

    # ---- The four questions, in the customer's own words ----
    f_q = load_font(26, bold=True)
    f_a_label = load_font(25, bold=True)
    f_a_text = load_font(24)
    draw.text((W - M, y), fa("سؤال‌های مهم"), font=f_q,
              fill=INK + (255,), anchor="ra")
    y += 44
    q_labels = [
        ("tampering", "دستکاری شده؟"),
        ("sends_photos_to_server", "عکس‌ها فرستاده می‌شوند؟"),
        ("third_party_can_see_photos", "کسی دیگر عکس‌ها را می‌بیند؟"),
        ("collects_photo_info", "اطلاعات عکس جمع می‌شود؟"),
    ]
    f_pill = load_font(23, bold=True)
    for idx, (qid, label) in enumerate(q_labels):
        a = answers.get(qid, {}) or {}
        pill_text, (bg, fg) = _customer_pill(qid, a.get("verdict", ""))
        answer_text = plain_answers.get(qid, "")
        text_w = CW - 190
        ans_lines = wrap_text(draw, answer_text, f_a_text, text_w)
        if len(ans_lines) > 2:
            # Truncate at a word boundary, never mid-word.
            cut = ans_lines[1]
            cut = cut[:cut.rfind(" ")].rstrip() if " " in cut else cut
            ans_lines = [ans_lines[0], cut + "…"]
        row_h = 35 + 34 * len(ans_lines) + 16
        # Pill, vertically centred on the row, at the far left.
        draw_pill(draw, M, y + row_h // 2, pill_text, f_pill, bg, fg)
        # Label (bold) + short answer (muted), right-aligned.
        ty = y
        ty = draw_rtl(draw, W - M, ty, label, f_a_label, INK + (255,))
        for line in ans_lines:
            ty = draw_rtl(draw, W - M, ty, line, f_a_text, MUTED + (255,))
        y += row_h
        if idx < len(q_labels) - 1:
            draw.line([M, y - 4, W - M, y - 4], fill=LINE + (255,), width=1)
    y += 18

    # ---- Important notes, in plain words ----
    draw.text((W - M, y), fa("نکته‌های مهم"), font=f_q, fill=INK + (255,),
              anchor="ra")
    y += 42
    for note in _customer_notes(result):
        lines = wrap_text(draw, note, f_a_text, CW - 34)
        if len(lines) > 2:
            cut = lines[1]
            cut = cut[:cut.rfind(" ")].rstrip() if " " in cut else cut
            lines = [lines[0], cut + "…"]
        draw.ellipse([W - M - 13, y + 9, W - M + 1, y + 23],
                     fill=(100, 116, 139, 255))
        for line in lines:
            y = draw_rtl(draw, W - M - 26, y, line, f_a_text,
                         (51, 65, 85, 255))
        y += 8
    y += 14

    # ---- Footer ----
    draw.line([M, y, W - M, y], fill=LINE + (255,), width=1)
    y += 16
    H = y + 96
    f_foot = load_font(21)
    draw.text((W - M, H - 84), fa("این بررسی فقط روی فایل برنامه انجام شده است."),
              font=f_foot, fill=MUTED + (255,), anchor="ra")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    draw.text((W - M, H - 52), fa(f"sibstars.ir  •  {stamp}"), font=f_foot,
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
