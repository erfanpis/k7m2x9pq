#!/usr/bin/env python3
"""SibStar IPA Scanner — PNG summary card (customer version).

The card is shown to NON-TECHNICAL end customers who do not
understand security terms, so it is MINIMAL and BEAUTIFUL: a regular
person must understand the whole card in 5 seconds and find it
beautiful — this is what Erfan shows the customer.
- App name + version, ONE score with ONE plain line explaining it
  ("هرچه عدد کمتر باشد، بهتر است"), ONE headline sentence with the
  verdict, and at most 4 short question lines — each a plain
  question, a one-word pill ("نه" / "بله") and one short evidence line.
- NO stats row with big scary numbers, NO "41 اتصال بدون محافظت"
  counts, NO technical notes, NO duplicated messages, NO jargon of
  any kind (no "dylib", no "MobileSubstrate", no "توئیک", no "IPA",
  no "تحلیل ایستا", no "ATS", no bundle ID, no raw domains).
  The full detail stays in the deep .md report and the JSON, which
  are for Erfan only.
- v9: the unlocked version is NORMAL in this store, so the card
  never says the mod is a problem. The question row is "نسخه آنلاک
  شده؟" with a NEUTRAL pill "بله" (grey/blue, never red) and a plain
  line; the headline is about DATA SAFETY — "مشکلی پیدا نشد؛ با
  خیال راحت استفاده کنید" when no exfiltration evidence, and
  "این نسخه اطلاعات شما را به سروری ناشناس می‌فرستد؛ نصب نکنید"
  only when the added part really sends data (its own unknown
  server AND an upload endpoint). The word for the mod is
  "آنلاک شده" — the word "دستکاری" appears nowhere on the card.
- Calm colours, generous white space, clean spacing, elegant
  typography. The score ring is the only large coloured element, and
  the headline sits on a soft tinted band in the risk colour.

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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scanner import _photo_upload_domains

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
# _customer_pill ("بله"، "نه") instead.
VERDICT_FA = {
    "confirmed": "تأیید شد",
    "no-evidence": "شواهدی نیست",
    "suspicious": "مشکوک",
    "yes": "بله", "possible": "ممکن است", "unknown": "نامشخص",
    "partial": "بررسی ناقص", "risky": "بالا",
    "caution": "متوسط", "ok": "کم‌ریسک",
}

# Calm palette. Colour is used sparingly: the gauge arc, the verdict
# dot and the verdict pills — never red-everywhere.
RISK_COLORS = {
    "low": (21, 128, 61),      # calm green
    "medium": (180, 83, 9),    # calm amber
    "high": (185, 28, 28),     # muted red (not bright alarm red)
}

# Verdict pills: green = good news, red = bad news, amber = caution.
PILL_GREEN = ((220, 252, 231), (22, 101, 52))
PILL_RED = ((254, 226, 226), (153, 27, 27))
PILL_AMBER = ((254, 243, 199), (146, 64, 14))
PILL_SLATE = ((241, 245, 249), (51, 65, 85))


def _customer_pill(qid, verdict):
    """(pill text, (bg, fg)) for a privacy answer — plain words a
    regular person understands, never a bare alarming "بله".

    v9: the unlocked row is NEUTRAL — "بله" in grey/blue slate,
    never red: an unlocked version is normal in this store. "نه"
    (green) for the original version. "مشکوک" (amber) only when a
    single weak signal was found.
    "اعلام شده" for declared photo collection (a neutral fact, amber).
    """
    if verdict == "suspicious":
        return "مشکوک", PILL_AMBER
    if qid == "tampering":
        return {"confirmed": ("بله", PILL_SLATE),
                "no-evidence": ("نه", PILL_GREEN)}.get(verdict, ("—", PILL_SLATE))
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
    """Plain one-line answers for the questions, in the customer's
    language. The scanner's answer_fa strings are for the detailed
    .md report; the card rephrases them here so no jargon
    ("نقطه‌ی آپلودی"، "dylib"، "توئیک") ever reaches a customer.

    The answers follow the ANSWER VERDICTS, not a re-derivation:
    when the verdict is "confirmed" (the dangerous case — the added
    part has its own server AND a photo-upload endpoint exists), the
    card says YES plainly. Otherwise it says a decisive "no".
    The unlocked line states the fact ONCE, neutrally: this version
    is unlocked, and either no data goes to an unknown server, or —
    in the dangerous case — it does. No counts, no jargon.
    """
    tamp = result.get("tampering") or {}
    _unknown = tamp.get("unknown_tweak_servers") or []
    _upload = _photo_upload_domains(result.get("domains", []))
    _dangerous = bool(_unknown and _upload)
    out = {}
    v5 = (answers.get("tampering", {}) or {}).get("verdict", "")
    if v5 == "confirmed":
        if _dangerous:
            out["tampering"] = "این نسخه آنلاک شده است؛ اطلاعات به سرور ناشناس فرستاده می‌شود"
        elif _unknown:
            out["tampering"] = "این نسخه آنلاک شده است؛ با یک سرور ناشناس حرف می‌زند"
        else:
            out["tampering"] = "این نسخه آنلاک شده است؛ داده‌ای به سرور ناشناس فرستاده نمی‌شود"
    elif v5 == "suspicious":
        out["tampering"] = "یک بخش اضافه پیدا شد؛ مدرکی از ارسال داده نیست"
    else:
        out["tampering"] = "این نسخه آنلاک نشده است"
    v1 = (answers.get("sends_photos_to_server", {}) or {}).get("verdict", "")
    if v1 == "confirmed":
        out["sends_photos_to_server"] = "عکس‌ها به یک آدرس ناشناس فرستاده می‌شوند"
    else:
        out["sends_photos_to_server"] = "عکس‌های شما جایی فرستاده نمی‌شود"
    v2 = (answers.get("third_party_can_see_photos", {}) or {}).get("verdict", "")
    if v2 == "confirmed":
        out["third_party_can_see_photos"] = "عکس‌های شما به یک آدرس ناشناس می‌رسد"
    else:
        out["third_party_can_see_photos"] = "کسی عکس‌های شما را نمی‌بیند"
    v3 = (answers.get("collects_photo_info", {}) or {}).get("verdict", "")
    if v3 == "confirmed":
        out["collects_photo_info"] = "در توضیحات برنامه اعلام شده است"
    else:
        # v8: decisive — "اعلام نشده است" hedged and implied it might
        # still collect. The app does not collect photo info.
        out["collects_photo_info"] = "این برنامه اطلاعات عکس جمع نمی‌کند"
    return out


def _card_questions(result, answers):
    """The question rows the card actually shows — a list of
    {"qid", "label", "pill", "text"} dicts.

    v9: photo questions are shown ONLY when the app can READ photos.
    Otherwise there is ONE plain row saying the app does not read
    the user's photos (add-only: it can only save a screenshot).
    The first row is always the unlocked question, neutral.
    """
    plain_answers = _customer_answers(result, answers)
    rows = []
    a = answers.get("tampering", {}) or {}
    pill_text, pill_colors = _customer_pill("tampering", a.get("verdict", ""))
    rows.append({"qid": "tampering", "label": "نسخه آنلاک شده؟",
                 "pill": (pill_text, pill_colors),
                 "text": plain_answers.get("tampering", "")})
    if result.get("photo_read_access", True):
        for qid, label in (
                ("sends_photos_to_server", "عکس‌ها فرستاده می‌شوند؟"),
                ("third_party_can_see_photos", "کسی دیگر عکس‌ها را می‌بیند؟"),
                ("collects_photo_info", "اطلاعات عکس جمع می‌شود؟")):
            a = answers.get(qid, {}) or {}
            pill_text, pill_colors = _customer_pill(qid, a.get("verdict", ""))
            rows.append({"qid": qid, "label": label,
                         "pill": (pill_text, pill_colors),
                         "text": plain_answers.get(qid, "")})
    else:
        # v8: one plain row, not three photo questions the app
        # cannot answer — it never touches the user's photos.
        if result.get("photo_access") == "add-only":
            text = ("این برنامه عکس‌های شما را نمی‌خواند؛ فقط می‌تواند "
                    "اسکرین‌شات ذخیره کند")
        else:
            text = "این برنامه به عکس‌های شما دسترسی ندارد"
        rows.append({"qid": "photos_not_applicable", "label": "عکس‌های شما",
                     "pill": ("نه", PILL_GREEN), "text": text})
    return rows


def _customer_headline(result, level_en):
    """The verdict as ONE friendly sentence a regular person
    understands. v9: the verdict is about DATA SAFETY, not about the
    mod — a modded app with no exfiltration evidence gets the calm
    "no problem" headline. Only confirmed sending (the added part's
    own unknown server AND an upload endpoint) gets the decisive
    "don't install" headline. Otherwise the headline follows the
    risk level."""
    tamp = result.get("tampering") or {}
    _unknown = tamp.get("unknown_tweak_servers") or []
    _upload = _photo_upload_domains(result.get("domains", []))
    if _unknown and _upload:
        return "این نسخه اطلاعات شما را به سروری ناشناس می‌فرستد؛ نصب نکنید"
    if level_en == "low":
        return "مشکلی پیدا نشد؛ با خیال راحت استفاده کنید"
    if level_en == "medium":
        return "خطر جدی پیدا نشد؛ چند نکته‌ی کوچک هست"
    return "چند نکته‌ی مهم پیدا شد؛ با احتیاط استفاده کنید"


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


def draw_pill(draw, x0, y_center, text, font, bg, fg, h=44, pad_x=22):
    """A rounded verdict pill, vertically centred on y_center.
    Returns the pill width. Text is centred (anchor mm)."""
    tw = draw.textlength(fa(text), font=font)
    w = max(136, int(tw) + 2 * pad_x)
    y0 = y_center - h // 2
    draw.rounded_rectangle([x0, y0, x0 + w, y0 + h], radius=h // 2,
                           fill=bg + (255,))
    draw.text(((2 * x0 + w) // 2, y_center), fa(text), font=font,
              fill=fg + (255,), anchor="mm")
    return w


def draw_gauge(draw, cx, cy, r, score, color):
    """A ring gauge: light track + coloured arc (score % of 360°)."""
    track = (229, 231, 235)
    draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                 outline=track + (255,), width=14)
    if score > 0:
        sweep = 360 * max(0, min(100, score)) / 100
        draw.arc([cx - r, cy - r, cx + r, cy + r], start=-90,
                 end=-90 + sweep, fill=color + (255,), width=14)


def _tint(color, frac=0.08):
    """A very soft tint of a risk colour (mostly white) for the
    headline band — calm, never alarming."""
    return tuple(int(255 * (1 - frac) + c * frac) for c in color)


def generate_report_card(result, out_path):
    """Render the summary card PNG for a scan result dict. Returns out_path."""
    out_path = Path(out_path)
    W = 1200
    M = 76  # margin — wide, for a premium feel
    BG = (247, 248, 250)
    CARD = (255, 255, 255)
    SHADOW = (222, 226, 232)
    INK = (15, 23, 42)
    MUTED = (100, 116, 139)
    LINE = (229, 231, 235)
    HEADER = (27, 38, 55)  # deep slate, not red

    risk = result.get("risk", {}) or {}
    score = int(risk.get("score", 0) or 0)
    level_en = risk.get("level_en", "low") or "low"
    color = RISK_COLORS.get(level_en, RISK_COLORS["low"])
    ident = result.get("identity", {}) or {}
    name = ident.get("display_name") or "برنامه"
    version = ident.get("version") or "—"
    min_os = ident.get("minimum_os") or "—"
    answers = {a["id"]: a for a in (result.get("privacy_answers", []) or [])}
    # v9: every customer-facing string drawn on this card, in order —
    # tests use it to prove no scary or technical word reaches a
    # customer, and the photo questions are gone when they do not apply.
    texts = []

    # Content layer (transparent); the card is sized to the content
    # afterwards, so nothing can overflow or leave a half-empty card.
    layer = Image.new("RGBA", (W, 2600), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    CW = W - 2 * M  # content width

    # ---- Header band (deep slate) with a thin accent strip ----
    draw.rounded_rectangle([24, 24, W - 24, 150], radius=30, fill=HEADER + (255,))
    draw.rectangle([24, 118, W - 24, 150], fill=HEADER + (255,))
    # Accent strip in the risk colour, clipped to the band's bottom.
    strip = Image.new("RGBA", (W - 48, 6), (0, 0, 0, 0))
    sd = ImageDraw.Draw(strip)
    sd.rectangle([0, 0, W - 48, 6], fill=color + (255,))
    layer.paste(strip, (24, 144), strip)
    f_title = load_font(34, bold=True)
    draw.text((W - M, 48), fa("سیب‌استار — گزارش بررسی برنامه"), font=f_title,
              fill=(255, 255, 255, 255), anchor="ra")
    f_sub = load_font(22)
    draw.text((W - M, 100), fa("بررسی امنیت و حریم خصوصی"),
              font=f_sub, fill=(203, 213, 225, 255), anchor="ra")

    # ---- Hero: app identity (right) + score ring (left) ----
    # No bundle ID on the card: customers do not care about it and
    # it only jumbles the bidi layout. One plain version line only.
    y = 186
    f_name = load_font(44, bold=True)
    for line in wrap_text(draw, name, f_name, CW - 280):
        y = draw_rtl(draw, W - M, y, line, f_name, INK + (255,))
    y += 10
    f_meta = load_font(24)
    y = draw_rtl(draw, W - M, y, f"نسخه {version}  •  نیاز به iOS {min_os} به بالا",
                 f_meta, MUTED + (255,))
    hero_text_bottom = y

    cx, cy, r = 172, 300, 82
    draw_gauge(draw, cx, cy, r, score, color)
    f_score = load_font(60, bold=True)
    draw.text((cx, cy - 6), str(score), font=f_score, fill=INK + (255,),
              anchor="mm")
    f_outof = load_font(20)
    draw.text((cx, cy + 42), "/100", font=f_outof, fill=MUTED + (255,), anchor="mm")
    # The score explained in ONE plain line: lower is better. No
    # "ریسک بالا" label under the ring — the headline sentence below
    # carries the verdict, and a second verdict word next to the
    # number only repeats (and scares).
    f_caption = load_font(20)
    draw.text((cx, cy + r + 30), fa("هرچه عدد کمتر باشد، بهتر است"),
              font=f_caption, fill=MUTED + (255,), anchor="mm")
    y = max(hero_text_bottom, cy + r + 30 + 26) + 36

    # ---- Verdict headline: ONE friendly sentence on a soft tinted
    # band in the risk colour, with a coloured dot ----
    f_verdict = load_font(29, bold=True)
    headline = _customer_headline(result, level_en)
    texts.append(headline)
    _hl_lines = wrap_text(draw, headline, f_verdict, CW - 96)
    _hl_h = int(len(_hl_lines) * f_verdict.size * 1.4)
    draw.rounded_rectangle([M - 16, y - 18, W - M + 16, y + _hl_h + 18],
                           radius=24, fill=_tint(color) + (255,))
    draw.ellipse([W - M - 13, y + 14, W - M + 1, y + 28],
                 fill=color + (255,))
    for line in _hl_lines:
        y = draw_rtl(draw, W - M - 30, y, line, f_verdict, INK + (255,))
    y += 18 + 18

    # ---- Divider: the headline is the verdict; everything below is
    # just the questions. No panel, no composition bar, no stats row
    # — the v7 card's extra numbers and repeated warnings are gone.
    # The unknown server, when one exists, is already inside the
    # photo answers ("به یک آدرس ناشناس فرستاده می‌شوند"), never as
    # a separate scary line with a raw address.
    draw.line([M, y, W - M, y], fill=LINE + (255,), width=1)
    y += 30

    # ---- The questions, in the customer's own words ----
    # v9: _card_questions decides which rows exist — photo questions
    # only when the app can READ photos; otherwise one plain row
    # saying it does not read the user's photos.
    f_q = load_font(27, bold=True)
    f_a_label = load_font(26, bold=True)
    f_a_text = load_font(24)
    draw.text((W - M, y), fa("سؤال‌های مهم"), font=f_q,
              fill=INK + (255,), anchor="ra")
    y += 50
    q_rows = _card_questions(result, answers)
    f_pill = load_font(23, bold=True)
    for idx, row in enumerate(q_rows):
        pill_text, (bg, fg) = row["pill"]
        answer_text = row["text"]
        label = row["label"]
        texts.append(label)
        texts.append(answer_text)
        text_w = CW - 200
        ans_lines = wrap_text(draw, answer_text, f_a_text, text_w)
        if len(ans_lines) > 2:
            # Truncate at a word boundary, never mid-word.
            cut = ans_lines[1]
            cut = cut[:cut.rfind(" ")].rstrip() if " " in cut else cut
            ans_lines = [ans_lines[0], cut + "…"]
        row_h = 46 + 34 * len(ans_lines) + 20
        # Pill, vertically centred on the row, at the far left.
        draw_pill(draw, M, y + row_h // 2, pill_text, f_pill, bg, fg)
        # Label (bold) + short answer (muted), right-aligned.
        ty = y
        ty = draw_rtl(draw, W - M, ty, label, f_a_label, INK + (255,))
        for line in ans_lines:
            ty = draw_rtl(draw, W - M, ty, line, f_a_text, MUTED + (255,))
        y += row_h
        if idx < len(q_rows) - 1:
            draw.line([M, y - 4, W - M, y - 4], fill=LINE + (255,), width=1)
    y += 32

    # ---- Footer: one plain line about what the check covered, and the
    # brand. No timestamp, no counts, no notes section — the v7
    # "نکته‌های مهم" ("41 اتصال بدون محافظت…") scared customers with
    # bare numbers; the detail lives in the deep report and the JSON
    # for Erfan only.
    draw.line([M, y, W - M, y], fill=LINE + (255,), width=1)
    y += 22
    H = y + 100
    f_foot = load_font(21)
    draw.text((W - M, H - 88), fa("این بررسی فقط روی فایل برنامه انجام شده است."),
              font=f_foot, fill=MUTED + (255,), anchor="ra")
    draw.text((W - M, H - 54), fa("sibstars.ir"), font=f_foot,
              fill=MUTED + (255,), anchor="ra")

    # Compose: soft-grey page, white rounded card with a soft shadow,
    # content on top.
    img = Image.new("RGBA", (W, H), BG + (255,))
    card_draw = ImageDraw.Draw(img)
    card_draw.rounded_rectangle([24, 32, W - 24, H - 18], radius=32,
                                fill=SHADOW + (255,))
    card_draw.rounded_rectangle([24, 24, W - 24, H - 24], radius=32,
                                fill=CARD + (255,), outline=LINE + (255,), width=2)
    img.alpha_composite(layer.crop((0, 0, W, H)))
    img = img.convert("RGB")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, format="PNG")
    # Every customer-facing string on this card, in order — tests use
    # it to prove no scary or technical word reaches a customer, the
    # photo questions are gone when they do not apply, and the
    # unlocked fact is stated once, neutrally.
    generate_report_card.last_texts = texts
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
