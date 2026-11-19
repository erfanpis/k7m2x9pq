"""deep_scan.py — SibStar IPA scanner v10: added-part (injection) analysis,
known-app profiles, honest privacy answers and calm verdicts.

Standard library only. Imported by scanner.py.

Design (v10):
  * WHAT WAS ADDED is decided from the Mach-O load commands, not from
    file names: every LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB /
    LC_REEXPORT_DYLIB of the main binary AND of every embedded
    framework/dylib is read in order. The linker always writes the
    dylib commands before LC_FUNCTION_STARTS / LC_DATA_IN_CODE /
    LC_CODE_SIGNATURE; a dylib command that sits AFTER one of those
    was appended later by an injector (insert_dylib / optool / azule /
    a signer's "inject" option). Hooking-engine links (CydiaSubstrate,
    ElleKit, libhooker, substitute), Logos/MSHook markers, known tweak
    names and jailbreak-only load paths are the other signals. Libraries
    reached only through an added part are added parts too.
  * .dylib AND .framework binaries are both examined.
  * Each added part is analysed on its own: its servers (compared with
    the original app's own servers), hidden/encoded addresses, known
    data-drop endpoints (Telegram bot API, Discord webhooks …), and what
    it touches (photos, keychain, cookies, contacts, clipboard,
    location) plus whether it can send (NSURLSession/upload/socket).
  * An unlocked version is NORMAL in this store. A .deb file inside the
    bundle is inert (iOS never runs it). SibStar's own packages
    (fixcrash1/fixcrash2, ellekit) and common unlock/hook libraries are
    recognised and never raise an alarm on their own.
  * Danger needs a COMPLETE path: an added part that can read personal
    data AND send it to a server that is not the app's own (or a known
    data-drop endpoint). A server alone is "review" (shown to the owner
    in the technical report, worded calmly for the customer).
  * Wording never promises 100% safety, and never scares without
    evidence: "نشانه‌ی خطری پیدا نشد".
"""
import base64
import binascii
import os
import re
import struct
from pathlib import Path

# ---------------------------------------------------------------- limits
MAX_HEADER_BYTES = 4 * 1024 * 1024      # load-command region cap
MAX_PART_BYTES = 256 * 1024 * 1024      # an added part bigger than this is still
                                        # scanned, in chunks (see _iter_chunks)
CHUNK = 16 * 1024 * 1024
OVERLAP = 4096

LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB = 0xC, 0x80000018, 0x8000001F
LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB = 0x20, 0x80000023
DYLIB_CMDS = {LC_LOAD_DYLIB: "LC_LOAD_DYLIB", LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
              0x18: "LC_LOAD_WEAK_DYLIB", LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
              0x1F: "LC_REEXPORT_DYLIB", LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
              LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB", 0x23: "LC_LOAD_UPWARD_DYLIB"}
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
# Commands the linker always writes AFTER every dylib command.
TAIL_CMDS = {0x26, 0x29, 0x1D, 0x2B}   # FUNCTION_STARTS, DATA_IN_CODE, CODE_SIGNATURE, DYLIB_CODE_SIGN_DRS

SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/", "/System/iOSSupport/")
JB_PREFIXES = ("/Library/MobileSubstrate/", "/Library/Frameworks/", "/var/jb/",
               "/usr/local/lib/", "/private/preboot/", "/var/mobile/",
               "/Library/TweakInject/", "/usr/lib/TweakInject/")

# ---------------------------------------------------------------- knowledge
# Hooking engines: the runtime an unlocked/tweaked build needs. Normal.
HOOK_ENGINES = ("cydiasubstrate", "libsubstrate", "substrate", "ellekit",
                "libhooker", "substitute", "libellekit", "fishhook")
# SibStar's own packages (anti-crash / injection helpers).
SIBSTAR_PACKAGES = ("fixcrash", "sibstar", "sib_star", "sibfix", "ellekit")
# Well-known unlock / fix / feature tweaks (lower-case substrings of the
# library file name). Recognised = described plainly, never an alarm on
# its own; their strings are still analysed like any added part.
KNOWN_TWEAKS = {
    "satella": "آنلاک خرید درون‌برنامه‌ای (Satella)",
    "sideloadfix": "رفع مشکل نصب سایدلود", "sideloadly": "رفع مشکل نصب سایدلود",
    "keychainfix": "رفع مشکل کی‌چین در نصب سایدلود",
    "appsyncunified": "رفع مشکل نصب", "zxplugin": "رفع مشکل افزونه‌ها در سایدلود",
    "noads": "حذف تبلیغات", "adblock": "حذف تبلیغات", "removeads": "حذف تبلیغات",
    "unlock": "آنلاک امکانات", "premium": "آنلاک امکانات", "pro_unlock": "آنلاک امکانات",
    "ytlite": "قابلیت‌های اضافه‌ی یوتیوب", "uyou": "قابلیت‌های اضافه‌ی یوتیوب",
    "youpip": "پخش تصویر در تصویر", "ytuhd": "کیفیت بالای ویدیو",
    "isponsorblock": "رد کردن تبلیغ داخل ویدیو", "returnyoutubedislike": "نمایش دیس‌لایک",
    "ytabconfig": "تنظیمات یوتیوب", "dontEatMyContent".lower(): "رفع مشکل نمایش",
    "youtimestamp": "قابلیت‌های اضافه", "youmute": "قابلیت‌های اضافه",
    "youquality": "قابلیت‌های اضافه", "ytvideooverlay": "قابلیت‌های اضافه",
    "eeveespotify": "آنلاک اسپاتیفای", "sposify": "آنلاک اسپاتیفای",
    "spotilife": "آنلاک اسپاتیفای",
    "rocket": "قابلیت‌های اضافه‌ی اینستاگرام", "bhinsta": "قابلیت‌های اضافه‌ی اینستاگرام",
    "scinsta": "قابلیت‌های اضافه‌ی اینستاگرام", "instanoads": "حذف تبلیغات اینستاگرام",
    "bhtiktok": "قابلیت‌های اضافه‌ی تیک‌تاک",
    "neofreebird": "قابلیت‌های اضافه‌ی توییتر", "watusi": "قابلیت‌های اضافه‌ی واتساپ",
    "flex": "ابزار دیباگ FLEX", "improvedcustomapi": "رفع مشکل API",
    "openyoutubesafari": "قابلیت‌های اضافه", "appdata": "مدیریت داده‌ی برنامه",
    "bhtwitter": "قابلیت‌های اضافه‌ی توییتر (BHTwitter)",
    "cephei": "کتابخانه‌ی تنظیمات توئیک (Cephei)", "altlist": "کتابخانه‌ی لیست برنامه‌ها",
    "alderis": "کتابخانه‌ی انتخاب رنگ", "libcolorpicker": "کتابخانه‌ی انتخاب رنگ",
    "libsandy": "کتابخانه‌ی سازگاری", "orion": "موتور توئیک‌های Swift (Orion)",
    "libundirect": "کتابخانه‌ی سازگاری", "libroot": "کتابخانه‌ی سازگاری",
    "ytuhd": "کیفیت بالای ویدیو", "youtubeextension": "قابلیت‌های اضافه‌ی یوتیوب",
}
# Hosts that are LINKS (credits, socials, donations) — not servers that
# receive data.
LINK_HOSTS = ("t.me", "telegram.me", "twitter.com", "x.com", "github.com",
              "discord.gg", "discord.com/invite", "paypal.me", "paypal.com", "ko-fi.com",
              "buymeacoffee.com", "patreon.com", "instagram.com", "youtube.com",
              "youtu.be", "reddit.com", "iosgods.com", "apple.com", "apps.apple.com",
              "itunes.apple.com", "linktr.ee", "www.youtube.com", "m.youtube.com")
# Services that well-known tweaks legitimately call.
KNOWN_TWEAK_SERVICES = ("sponsor.ajay.app", "dearrow-thumb.ajay.app", "ajay.app",
                        "returnyoutubedislikeapi.com", "api.github.com",
                        "raw.githubusercontent.com", "github.io",
                        "objects.githubusercontent.com", "ryd-proxy", "unavatar.io",
                        "canister.me", "saurik.com", "chariz.com", "havoc.app",
                        "packix.com", "dynastic.co", "theos.dev", "getdelta.co",
                        "youtube.com", "googlevideo.com", "ytimg.com")
# Data-drop endpoints: a stealer's favourite way to receive stolen data.
EXFIL_HOSTS = ("api.telegram.org", "webhook.site", "pipedream.net", "requestbin",
               "ngrok.io", "ngrok-free.app", "ngrok.app", "pastebin.com",
               "hastebin.com", "transfer.sh", "file.io", "anonfiles", "duckdns.org",
               "ddns.net", "no-ip.", "serveo.net", "localtunnel.me", "loca.lt",
               "interact.sh", "oast.", "burpcollaborator", "canarytokens")
EXFIL_URL_RE = re.compile(r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|"
                          r"/sendPhoto|/sendDocument|hooks\.slack\.com/services)", re.I)
BOT_TOKEN_RE = re.compile(rb"(?<![0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])")

# Capabilities: what an added part touches (byte patterns, boundary-free:
# ObjC selectors/classes are unique enough).
CAPS = {
    # READING the library (saving a downloaded photo is not reading)
    "photos": (rb"PHImageManager|PHCachingImageManager|requestImageDataAndOrientation|"
               rb"requestImageDataForAsset|fetchAssetsWithMediaType|fetchAssetsWithOptions|"
               rb"PHAssetResourceManager|requestAVAssetForVideo|ALAssetsLibrary"),
    "photos_save": rb"creationRequestForAsset|UIImageWriteToSavedPhotosAlbum|PHAssetChangeRequest",
    "keychain": rb"SecItemCopyMatching|kSecClassGenericPassword|kSecClassInternetPassword",
    "cookies": rb"NSHTTPCookieStorage|WKHTTPCookieStore|getAllCookies|sharedHTTPCookieStorage",
    "contacts": rb"CNContactStore|ABAddressBookCopy|CNContactFetchRequest",
    "clipboard": rb"generalPasteboard|UIPasteboard",
    "location": rb"CLLocationManager|startUpdatingLocation|requestLocation",
    "messages": rb"MFMessageCompose|CKMessage|IMChat",
    "device_id": rb"identifierForVendor|advertisingIdentifier",
    "send": (rb"NSURLSession|NSURLConnection|uploadTaskWithRequest|dataTaskWithRequest|"
             rb"setHTTPBody|multipart/form-data|AFHTTPSessionManager|Alamofire|"
             rb"CFStreamCreatePairWithSocketToHost|nw_connection_create|GCDAsyncSocket|"
             rb"SRWebSocket|NSStream"),
    "hooking": (rb"MSHookMessageEx|MSHookFunction|_logos_|LHHookFunctions|"
                rb"rebind_symbols|method_exchangeImplementations|class_replaceMethod|"
                rb"method_setImplementation|MSHookIvar"),
}
CAPS_RX = {k: re.compile(v) for k, v in CAPS.items()}
CAP_FA = {
    "photos": "خواندن عکس‌های گالری", "photos_save": "ذخیره در گالری", "keychain": "کی‌چین (رمزهای ذخیره‌شده)",
    "cookies": "کوکی/نشست ورود", "contacts": "مخاطبین", "clipboard": "کلیپ‌بورد",
    "location": "موقعیت مکانی", "messages": "پیام‌ها", "device_id": "شناسه‌ی دستگاه",
    "send": "ارسال در شبکه", "hooking": "تغییر رفتار برنامه (هوک)",
}
SENSITIVE = ("photos", "keychain", "cookies", "contacts", "messages")
QUICK_HOOK_MARKERS = (b"_logos_", b"MSHookMessageEx", b"MSHookFunction",
                      b"LHHookFunctions", b"%hook ", b"MSHookIvar")

URL_RX = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}")
B64_RX = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
HEX_HTTP_RX = re.compile(rb"68747470(?:73)?3a2f2f(?:[0-9a-f]{2}){4,}", re.I)
REV_HTTP_RX = re.compile(rb"[A-Za-z0-9\-._/]{4,}//:s?ptth")
HOST_RX = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# Domain noise — never an endpoint worth listing (docs, schemas, Apple
# system services, private/loopback addresses).
NOISE_SUFFIXES = ("w3.org", "xml.org", "purl.org", "schemas.xmlsoap.org", "example.com",
                  "example.org", "example.net", "localhost", "iana.org", "ietf.org",
                  "unicode.org", "openssl.org", "gnu.org", "opensource.org",
                  "apache.org", "mozilla.org", "creativecommons.org", "swift.org",
                  "llvm.org", "json-schema.org", "ns.adobe.com", "xmlns.com",
                  "openxmlformats.org", "oasis-open.org", "microsoft.com/schemas",
                  # media / codec specs embedded by FFmpeg & co (docs, not servers)
                  "dashif.org", "iso.org", "ffmpeg.org", "videolan.org", "xiph.org",
                  "webmproject.org", "mpeg.org", "3gpp.org", "itu.int", "aomedia.org",
                  "khronos.org", "opengl.org", "json.org", "cocoapods.org",
                  "chromium.org", "webkit.org", "sqlite.org", "zlib.net", "libpng.org",
                  "ijg.org", "freetype.org", "harfbuzz.org", "boost.org", "curl.se",
                  "curl.haxx.se", "openssl.org", "google.com/policies", "rfc-editor.org",
                  "ecma-international.org", "whatwg.org", "github.com")
APPLE_SUFFIXES = ("apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
                  "cdn-apple.com", "itunes.com", "me.com", "aaplimg.com")
PRIVATE_IP_RX = re.compile(r"^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)")
TWO_LEVEL_SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}

# ---------------------------------------------------------------- known apps
# Official behaviour of popular apps — so their own servers are never
# called "unknown", and the photo answer states what the original app
# does by design. (Bundle-ID prefixes survive SibStar's numeric
# duplicate suffix.)
KNOWN_APPS = [
    {"ids": ("com.picsart.",), "name": "Picsart",
     "domains": ("picsart.com", "picsart.io", "picsartstatic.com", "picsart.tools"),
     "cloud_fa": ("ویرایش‌های معمولی (برش، فیلتر، متن، استیکر) روی خود گوشی انجام می‌شود. "
                  "قابلیت‌های هوش مصنوعی و ابری Picsart (مثل حذف پس‌زمینه، AI Enhance، "
                  "تولید تصویر و ذخیره در فضای ابری Picsart) طبق طراحی خود Picsart "
                  "عکس را برای پردازش به سرورهای خود Picsart می‌فرستند؛ این در نسخه‌ی "
                  "اصلی هم دقیقاً همین‌طور است.")},
    {"ids": ("com.adobe.lrmobile", "com.adobe.ps", "com.adobe.photoshop", "com.adobe.",),
     "name": "Adobe", "domains": ("adobe.com", "adobe.io", "adobelogin.com", "behance.net",
                                   "typekit.net", "adobess.com"),
     "cloud_fa": ("ویرایش روی گوشی انجام می‌شود؛ همگام‌سازی ابری و قابلیت‌های هوش مصنوعی "
                  "Adobe عکس را به سرورهای خود Adobe می‌فرستند (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.canva.",), "name": "Canva", "domains": ("canva.com", "canva.cn", "canva-apps.com"),
     "cloud_fa": ("Canva طرح‌ها و عکس‌هایی که در طرح می‌گذارید را در فضای ابری خود Canva "
                  "ذخیره می‌کند؛ این طراحی خود Canva است (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.lemon.lvoverseas", "com.lemon.", "com.bytedance."), "name": "CapCut",
     "domains": ("capcut.com", "capcutapi.com", "byteoversea.com", "bytedance.com",
                 "ibytedtos.com", "tiktokv.com", "byteimg.com", "ibyteimg.com"),
     "cloud_fa": ("ویرایش معمولی روی گوشی است؛ قابلیت‌های هوش مصنوعی و ذخیره‌ی ابری "
                  "CapCut فایل را به سرورهای خود سازنده می‌فرستند (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.bigwinepot.", "com.bendingspoons."), "name": "Remini / Bending Spoons",
     "domains": ("bendingspoons.com", "bendingspoonsapps.com", "remini.ai", "splice.com"),
     "cloud_fa": ("بهبود عکس با هوش مصنوعی روی سرورهای سازنده انجام می‌شود؛ عکس برای "
                  "پردازش به سرور خود سازنده فرستاده می‌شود (مثل نسخه‌ی اصلی).")},
    {"ids": ("io.faceapp",), "name": "FaceApp", "domains": ("faceapp.io", "faceapp.com"),
     "cloud_fa": ("افکت‌های FaceApp روی سرور خود سازنده پردازش می‌شوند؛ عکس برای پردازش "
                  "به سرور FaceApp فرستاده می‌شود (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.lightricks.",), "name": "Lightricks (Facetune/Photoleap)",
     "domains": ("lightricks.com", "facetuneapp.com"),
     "cloud_fa": ("ویرایش اصلی روی گوشی است؛ بعضی قابلیت‌های هوش مصنوعی عکس را به "
                  "سرورهای خود سازنده می‌فرستند (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.vsco.",), "name": "VSCO", "domains": ("vsco.co", "vsco.com", "vscocdn.com"),
     "cloud_fa": ("ویرایش روی گوشی است؛ همگام‌سازی گالری VSCO و انتشار، عکس را به "
                  "سرورهای خود VSCO می‌فرستد (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.camerasideas.",), "name": "InShot", "domains": ("inshot.cc", "inshot.com"),
     "cloud_fa": ("ویرایش روی گوشی است؛ بعضی قابلیت‌های هوش مصنوعی ممکن است از سرور "
                  "خود سازنده استفاده کنند (مثل نسخه‌ی اصلی).")},
    {"ids": ("com.google.snapseed",), "name": "Snapseed", "domains": ("google.com", "googleapis.com"),
     "cloud_fa": "ویرایش عکس در Snapseed روی خود گوشی انجام می‌شود."},
    {"ids": ("com.meitu.",), "name": "Meitu / BeautyPlus",
     "domains": ("meitu.com", "meitudata.com", "beautyplus.com", "meiyan.com"),
     "cloud_fa": ("بعضی افکت‌های هوش مصنوعی روی سرورهای خود سازنده پردازش می‌شوند "
                  "(مثل نسخه‌ی اصلی).")},
    {"ids": ("com.burbn.instagram",), "name": "Instagram",
     "domains": ("instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net"),
     "cloud_fa": "عکس‌هایی که پست یا ارسال می‌کنید به سرورهای خود اینستاگرام می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("com.google.ios.youtube",), "name": "YouTube",
     "domains": ("youtube.com", "googlevideo.com", "ytimg.com", "googleapis.com", "google.com"),
     "cloud_fa": "فقط ویدیو یا عکسی که خودتان آپلود کنید به سرورهای یوتیوب می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("ph.telegra.", "org.telegram."), "name": "Telegram",
     "domains": ("telegram.org", "t.me"),
     "cloud_fa": "فایل‌هایی که در چت می‌فرستید به سرورهای تلگرام می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("net.whatsapp.",), "name": "WhatsApp", "domains": ("whatsapp.net", "whatsapp.com"),
     "cloud_fa": "فایل‌هایی که در چت می‌فرستید رمزنگاری‌شده به سرورهای واتساپ می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("com.spotify.",), "name": "Spotify", "domains": ("spotify.com", "scdn.co", "spotifycdn.com"),
     "cloud_fa": "اسپاتیفای فقط برای عکس پروفایل/پلی‌لیست، عکسی را که خودتان انتخاب کنید آپلود می‌کند."},
    {"ids": ("com.zhiliaoapp.musically",), "name": "TikTok",
     "domains": ("tiktok.com", "tiktokv.com", "byteoversea.com", "tiktokcdn.com", "ibytedtos.com"),
     "cloud_fa": "ویدیوهایی که منتشر می‌کنید به سرورهای تیک‌تاک می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("com.toyopagroup.picaboo",), "name": "Snapchat",
     "domains": ("snapchat.com", "sc-cdn.net", "snap.com", "snapkit.com"),
     "cloud_fa": "اسنپ‌هایی که می‌فرستید به سرورهای اسنپ‌چت می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("com.atebits.tweetie2",), "name": "X (Twitter)",
     "domains": ("twitter.com", "x.com", "twimg.com"),
     "cloud_fa": "عکس‌هایی که توییت می‌کنید به سرورهای X می‌رود (مثل نسخه‌ی اصلی)."},
    {"ids": ("com.sibstar.", "ir.sibstars."), "name": "SibStar",
     "domains": ("sibstars.ir",), "cloud_fa": None},
]


def known_app(bundle_id):
    bid = (bundle_id or "").lower()
    for app in KNOWN_APPS:
        if any(bid.startswith(p) for p in app["ids"]):
            return app
    return None


# ---------------------------------------------------------------- domains
def registrable(host):
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in TWO_LEVEL_SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _suffix_match(host, suffixes):
    h = (host or "").lower()
    return any(h == s or h.endswith("." + s) for s in suffixes)


def is_noise_domain(host):
    h = (host or "").lower()
    if not h or "." not in h:
        return True
    if PRIVATE_IP_RX.match(h):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    return _suffix_match(h, NOISE_SUFFIXES)


def is_apple_domain(host):
    return _suffix_match(host, APPLE_SUFFIXES)


def compact_domains(domains, own_suffixes=()):
    """Deduplicated, noise-filtered domain view for reports.

    Returns {"relevant": [...], "noise_count": n, "apple_count": n,
             "groups": [(registrable, count), ...] (sorted by count)}."""
    relevant, noise, apple = [], 0, 0
    for d in sorted(set(x.lower() for x in (domains or []) if x)):
        if is_noise_domain(d):
            noise += 1
            continue
        if is_apple_domain(d):
            apple += 1
            continue
        relevant.append(d)
    groups = {}
    for d in relevant:
        g = registrable(d)
        groups[g] = groups.get(g, 0) + 1
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))
    return {"relevant": relevant, "noise_count": noise, "apple_count": apple,
            "groups": ordered, "group_count": len(ordered)}


# ---------------------------------------------------------------- file io
def _iter_chunks(path, limit=None):
    """Yield (offset, bytes) chunks with a small overlap, so a match that
    straddles two chunks is never lost. Whole file, no 64 MB cut."""
    size = os.path.getsize(path)
    if limit:
        size = min(size, limit)
    with open(path, "rb") as f:
        pos = 0
        while pos < size:
            start = max(0, pos - OVERLAP) if pos else 0
            f.seek(start)
            data = f.read(min(CHUNK, size - pos) + (pos - start))
            if not data:
                break
            yield start, data
            pos = start + len(data)


def _file_contains_any(path, needles):
    try:
        for _, data in _iter_chunks(path):
            for n in needles:
                if n in data:
                    return True
    except Exception:
        return False
    return False


def is_macho_file(path):
    try:
        with open(path, "rb") as f:
            m = f.read(4)
    except Exception:
        return False
    return m in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                 b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")


# ---------------------------------------------------------------- Mach-O
def _parse_slice(f, base, fsize):
    f.seek(base)
    hdr = f.read(32)
    if len(hdr) < 28:
        return None
    magic = hdr[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        fmt = "<"
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        fmt = ">"
    else:
        return None
    is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    cputype, _sub, filetype, ncmds, sizeofcmds, _flags = struct.unpack(fmt + "IIIIII", hdr[4:28])
    hsize = 32 if is64 else 28
    sizeofcmds = min(sizeofcmds, MAX_HEADER_BYTES)
    f.seek(base + hsize)
    cmds_blob = f.read(sizeofcmds)
    out = {"cputype": cputype, "filetype": filetype, "is64": is64, "cmds": [],
           "dylibs": [], "rpaths": [], "encrypted": None, "id_name": None,
           "signing_id": None, "team_id": None, "adhoc": None}
    cur, idx = 0, 0
    tail_seen = False
    codesig = None
    while idx < min(ncmds, 4096) and cur + 8 <= len(cmds_blob):
        cmd, cmdsize = struct.unpack(fmt + "II", cmds_blob[cur:cur + 8])
        if cmdsize < 8 or cur + cmdsize > len(cmds_blob):
            break
        body = cmds_blob[cur:cur + cmdsize]
        out["cmds"].append(cmd)
        if cmd in TAIL_CMDS:
            tail_seen = True
        if cmd in DYLIB_CMDS or (cmd & 0x7FFFFFFF) in (0xC, 0x18, 0x1F, 0x20, 0x23):
            try:
                noff = struct.unpack(fmt + "I", body[8:12])[0]
                name = body[noff:].split(b"\x00", 1)[0].decode("utf-8", "replace")
            except Exception:
                name = ""
            out["dylibs"].append({"name": name, "cmd": DYLIB_CMDS.get(cmd, hex(cmd)),
                                  "index": idx, "after_tail": tail_seen,
                                  "weak": (cmd & 0x7FFFFFFF) == 0x18})
        elif cmd == 0xD:  # LC_ID_DYLIB
            try:
                noff = struct.unpack(fmt + "I", body[8:12])[0]
                out["id_name"] = body[noff:].split(b"\x00", 1)[0].decode("utf-8", "replace")
            except Exception:
                pass
        elif cmd == LC_RPATH or cmd == 0x1C:
            try:
                poff = struct.unpack(fmt + "I", body[8:12])[0]
                out["rpaths"].append(body[poff:].split(b"\x00", 1)[0].decode("utf-8", "replace"))
            except Exception:
                pass
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            try:
                out["encrypted"] = struct.unpack(fmt + "I", body[16:20])[0] == 1
            except Exception:
                pass
        elif cmd == LC_CODE_SIGNATURE:
            try:
                codesig = struct.unpack(fmt + "II", body[8:16])
            except Exception:
                pass
        cur += cmdsize
        idx += 1
    if codesig and codesig[1] and base + codesig[0] + codesig[1] <= fsize:
        try:
            f.seek(base + codesig[0])
            _parse_codesig(f.read(min(codesig[1], 4 * 1024 * 1024)), out)
        except Exception:
            pass
    return out


def _parse_codesig(blob, out):
    if len(blob) < 12 or struct.unpack(">I", blob[:4])[0] != 0xFADE0CC0:
        return
    count = struct.unpack(">I", blob[8:12])[0]
    for i in range(min(count, 64)):
        typ, off = struct.unpack(">II", blob[12 + i * 8:20 + i * 8])
        if typ != 0 or off + 52 > len(blob):
            continue
        if struct.unpack(">I", blob[off:off + 4])[0] != 0xFADE0C02:
            continue
        version, flags = struct.unpack(">II", blob[off + 8:off + 16])
        ident_off = struct.unpack(">I", blob[off + 20:off + 24])[0]
        out["signing_id"] = blob[off + ident_off:off + ident_off + 256].split(b"\x00", 1)[0].decode("utf-8", "replace")
        out["adhoc"] = bool(flags & 0x2)
        if version >= 0x20200:
            team_off = struct.unpack(">I", blob[off + 48:off + 52])[0]
            if team_off:
                out["team_id"] = blob[off + team_off:off + team_off + 32].split(b"\x00", 1)[0].decode("utf-8", "replace")
        return


def parse_macho_loads(path):
    """Load commands of a Mach-O (arm64 slice preferred). None if not Mach-O."""
    try:
        fsize = os.path.getsize(path)
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
                n = struct.unpack(">I", f.read(4))[0]
                is64fat = magic == b"\xca\xfe\xba\xbf"
                arches = []
                for _ in range(min(n, 16)):
                    if is64fat:
                        cpu, _s, off, _sz, _al, _r = struct.unpack(">IIQQII", f.read(32))
                    else:
                        cpu, _s, off, _sz, _al = struct.unpack(">IIIII", f.read(20))
                    arches.append((cpu, off))
                arches.sort(key=lambda a: 0 if a[0] == 0x0100000C else 1)
                for cpu, off in arches:
                    s = _parse_slice(f, off, fsize)
                    if s:
                        return s
                return None
            return _parse_slice(f, 0, fsize)
    except Exception:
        return None


# ---------------------------------------------------------------- strings
def scan_part_bytes(path):
    """Capability + address scan of one added part, whole file, chunked."""
    caps = {k: set() for k in CAPS}
    urls, hidden, tokens = set(), [], set()
    try:
        for _off, data in _iter_chunks(path):
            for k, rx in CAPS_RX.items():
                for m in rx.finditer(data):
                    if len(caps[k]) < 12:
                        caps[k].add(m.group(0).decode("ascii", "ignore"))
            for m in URL_RX.finditer(data):
                urls.add(m.group(0).decode("ascii", "ignore").rstrip(".,);\"'"))
            tokens.update(hash(t) for t in BOT_TOKEN_RE.findall(data))
            for m in HEX_HTTP_RX.finditer(data):
                try:
                    dec = binascii.unhexlify(m.group(0)).decode("utf-8", "ignore")
                    hidden.append(("hex", dec[:200]))
                except Exception:
                    pass
            for m in REV_HTTP_RX.finditer(data):
                hidden.append(("reversed", m.group(0)[::-1].decode("ascii", "ignore")[:200]))
            for m in B64_RX.finditer(data):
                s = m.group(0)
                if len(s) > 4096:
                    continue
                try:
                    dec = base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
                except Exception:
                    continue
                if b"http://" in dec or b"https://" in dec or b"wss://" in dec:
                    try:
                        txt = dec.decode("utf-8", "ignore")
                    except Exception:
                        continue
                    if txt.isprintable() or "http" in txt:
                        hidden.append(("base64", txt[:200]))
    except Exception as e:
        return {"error": str(e)}
    seen, uniq = set(), []
    for kind, txt in hidden:
        if (kind, txt) not in seen:
            seen.add((kind, txt))
            uniq.append({"kind": kind, "text": txt})
    return {"caps": {k: sorted(v) for k, v in caps.items() if v},
            "urls": sorted(urls), "hidden_urls": uniq[:20], "bot_tokens": len(tokens)}


def _host_of(url):
    try:
        rest = url.split("://", 1)[1]
    except IndexError:
        return None
    host = rest.split("/")[0].split("?")[0].split("#")[0].split("@")[-1].split(":")[0].lower()
    return host if HOST_RX.match(host) else None


# ---------------------------------------------------------------- detection
def _lib_name_key(p):
    return Path(p).name.lower()


def _classify_name(name_low):
    if any(k in name_low for k in ("fixcrash", "sibstar", "sib_star", "sibfix")):
        return "sibstar", "بسته‌ی رسمی سیب‌استار (ضد کرش / سازگاری)"
    if any(k in name_low for k in HOOK_ENGINES):
        return "hook_engine", "موتور اجرای قابلیت‌های اضافه (مثل ElleKit/Substrate) — عادی"
    for k, label in KNOWN_TWEAKS.items():
        if k in name_low:
            return "known_tweak", label
    return "unknown", "بخش اضافه‌ی ناشناس"


def discover_libs(app_dir):
    """Every Mach-O library in the .app (not app extensions): .dylib files
    and .framework executables, keyed by relative path."""
    libs = {}
    app_dir = Path(app_dir)
    for p in app_dir.rglob("*"):
        try:
            rel = p.relative_to(app_dir)
        except ValueError:
            continue
        parts = rel.parts
        if any(x.endswith(".appex") for x in parts[:-1]) or "Watch" in parts[:1]:
            continue
        if p.is_symlink() or not p.is_file():
            continue
        is_fw_exe = (len(parts) >= 2 and parts[-2].endswith(".framework")
                     and p.name == parts[-2][:-len(".framework")])
        if p.suffix == ".dylib" or is_fw_exe:
            if is_macho_file(p):
                libs[str(rel)] = p
    return libs


def _resolve(name, loader_rel, app_dir, rpaths, libs):
    """Map an install name to a bundled library (relative path) or None."""
    app_dir = Path(app_dir)
    loader_dir = (app_dir / loader_rel).parent if loader_rel else app_dir
    cands = []
    if name.startswith("@executable_path/"):
        cands.append(app_dir / name[len("@executable_path/"):])
    elif name.startswith("@loader_path/"):
        cands.append(loader_dir / name[len("@loader_path/"):])
    elif name.startswith("@rpath/"):
        tail = name[len("@rpath/"):]
        for rp in list(rpaths) + ["@executable_path/Frameworks"]:
            if rp.startswith("@executable_path"):
                base = app_dir / rp[len("@executable_path"):].lstrip("/")
            elif rp.startswith("@loader_path"):
                base = loader_dir / rp[len("@loader_path"):].lstrip("/")
            else:
                continue
            cands.append(base / tail)
    for c in cands:
        try:
            rel = str(Path(os.path.normpath(c)).relative_to(app_dir))
        except ValueError:
            continue
        if rel in libs:
            return rel
    if name.startswith("@"):
        base = _lib_name_key(name)
        for rel in libs:
            if _lib_name_key(rel) == base:
                return rel
    return None


def detect_added_parts(app_dir, exe_path):
    """Find the parts that were ADDED to the original app.

    Returns (parts: list[dict], loads: dict, unreferenced: list[str])."""
    app_dir = Path(app_dir)
    libs = discover_libs(app_dir)
    loads = {}
    main_rel = str(Path(exe_path).relative_to(app_dir)) if exe_path else None
    if exe_path:
        loads[main_rel] = parse_macho_loads(exe_path)
    for rel, p in libs.items():
        loads[rel] = parse_macho_loads(p)
    main_team = (loads.get(main_rel) or {}).get("team_id")

    reasons = {}      # rel -> [reason_fa]
    jb_paths = []     # (loader, name) — load paths that only exist on a jailbroken phone
    missing = []      # (loader, name) — appended command pointing to a missing file

    def add_reason(rel, why):
        reasons.setdefault(rel, [])
        if why not in reasons[rel]:
            reasons[rel].append(why)

    normal_refs = {}  # rel -> set(loader) through ORIGINAL (non-appended) commands
    added_refs = {}   # rel -> set(loader) through appended commands
    for loader, info in loads.items():
        if not info:
            continue
        rpaths = info.get("rpaths") or []
        for d in info.get("dylibs", []):
            name = d["name"]
            if name.startswith(SYSTEM_PREFIXES):
                continue
            if name.startswith(JB_PREFIXES):
                jb_paths.append((loader, name))
                continue
            tgt = _resolve(name, loader if loader != main_rel else None, app_dir, rpaths, libs)
            if d["after_tail"]:
                if tgt:
                    added_refs.setdefault(tgt, set()).add(loader)
                    add_reason(tgt, f"دستور بارگذاری آن بعداً به انتهای `{loader}` اضافه شده است "
                                    f"({d['cmd']} بعد از امضای کد)")
                else:
                    missing.append((loader, name))
            elif tgt:
                normal_refs.setdefault(tgt, set()).add(loader)

    # Name / content signals.
    for rel, p in libs.items():
        low = _lib_name_key(rel)
        kind, _ = _classify_name(low)
        if kind in ("sibstar", "known_tweak"):
            add_reason(rel, "نام آن یک بسته‌ی شناخته‌شده‌ی آنلاک/سازگاری است")
        info = loads.get(rel) or {}
        hook_links = [d["name"] for d in info.get("dylibs", [])
                      if any(h in d["name"].lower() for h in
                             ("cydiasubstrate", "libsubstrate", "ellekit", "libhooker",
                              "substitute", "mobilesubstrate"))]
        if hook_links and kind != "hook_engine":
            add_reason(rel, "از موتور هوک استفاده می‌کند: " + Path(hook_links[0]).name)
        if kind != "hook_engine" and _file_contains_any(p, QUICK_HOOK_MARKERS):
            add_reason(rel, "نشانه‌ی کد تغییردهنده‌ی رفتار برنامه (Logos/MSHook) در آن هست")

    # Hook engines are added parts when something added uses them or
    # nothing original loads them.
    for rel in libs:
        low = _lib_name_key(rel)
        if _classify_name(low)[0] == "hook_engine" and rel not in normal_refs:
            add_reason(rel, "موتور هوک است و برنامه‌ی اصلی آن را لود نمی‌کند")

    # Propagate: a library loaded ONLY by added parts is an added part.
    changed = True
    while changed:
        changed = False
        for rel in libs:
            if rel in reasons:
                continue
            loaders = normal_refs.get(rel, set())
            if loaders and all(l in reasons for l in loaders):
                add_reason(rel, "فقط توسط بخش اضافه لود می‌شود")
                changed = True

    # A normally-linked library is ORIGINAL unless it carries real
    # injection evidence (appended command, hooks, known tweak name).
    parts = []
    for rel, why in sorted(reasons.items()):
        p = libs[rel]
        low = _lib_name_key(rel)
        kind, label = _classify_name(low)
        info = loads.get(rel) or {}
        team = info.get("team_id")
        entry = {"path": rel, "name": Path(rel).name, "kind": kind, "label_fa": label,
                 "reasons_fa": why, "size_bytes": p.stat().st_size,
                 "team_id": team, "signing_id": info.get("signing_id"),
                 "adhoc": info.get("adhoc"), "encrypted": info.get("encrypted"),
                 "linked": [d["name"] for d in info.get("dylibs", [])
                            if not d["name"].startswith(SYSTEM_PREFIXES)][:20],
                 "loaded_by": sorted(added_refs.get(rel, set()) | normal_refs.get(rel, set()))}
        if main_team and team and team != main_team:
            entry["reasons_fa"] = why + [f"امضای آن (تیم {team}) با برنامه‌ی اصلی فرق دارد"]
        parts.append(entry)

    referenced = set(normal_refs) | set(added_refs)
    unreferenced = sorted(r for r in libs if r not in referenced and r not in reasons)
    extra = {"jb_load_paths": [{"loader": l, "name": n} for l, n in jb_paths],
             "missing_appended": [{"loader": l, "name": n} for l, n in missing],
             "main_team_id": main_team, "lib_count": len(libs),
             "unreferenced": unreferenced[:50]}
    return parts, loads, extra


# ---------------------------------------------------------------- analysis
def classify_host(host, url, original_domains, own_suffixes, tracker_family):
    h = host.lower()
    if EXFIL_URL_RE.search(url or "") or _suffix_match(h, EXFIL_HOSTS):
        return "exfil"
    if h in original_domains or _suffix_match(h, own_suffixes):
        return "original"
    if is_noise_domain(h) or is_apple_domain(h):
        return "system"
    if _suffix_match(h, LINK_HOSTS):
        return "link"
    if _suffix_match(h, KNOWN_TWEAK_SERVICES) or any(k in h for k in ("ryd-proxy",)):
        return "known_service"
    if tracker_family and tracker_family(h):
        return "tracker"
    # registrable domain shared with the original app = same company
    reg = registrable(h)
    if any(registrable(o) == reg for o in original_domains):
        return "original"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
        return "ip"
    return "unknown"


UPLOADISH_PATH_RX = re.compile(r"/(upload|uploads|exfil|steal|grab|collect|harvest|dump|"
                               r"loot|gate|panel|stealer)(\b|/|\.php|\?)", re.I)


def analyze_part(part, app_dir, original_domains, own_suffixes, tracker_family,
                 url_classifier=None):
    p = Path(app_dir) / part["path"]
    if part.get("encrypted"):
        part.update({"verdict": "unreadable", "servers": [], "caps": {},
                     "note_fa": "این فایل قفل (رمزگذاری) است و محتوایش قابل بررسی نیست."})
        return part
    s = scan_part_bytes(p)
    if s.get("error"):
        part.update({"verdict": "unreadable", "servers": [], "caps": {},
                     "note_fa": "خواندن فایل ناموفق بود: " + s["error"]})
        return part
    servers = []
    seen = set()
    for u in s["urls"]:
        host = _host_of(u)
        if not host or host in seen:
            continue
        if url_classifier and not EXFIL_URL_RE.search(u):
            try:
                if url_classifier(u) != "network":
                    continue  # namespace / docs / licence / invalid string
            except Exception:
                pass
        seen.add(host)
        servers.append({"host": host, "kind": classify_host(host, u, original_domains,
                                                           own_suffixes, tracker_family),
                        "sample": u[:160],
                        "uploadish": bool(UPLOADISH_PATH_RX.search(u.split(host, 1)[-1]))})
    for hu in s["hidden_urls"]:
        host = _host_of(hu["text"]) or "?"
        kind = classify_host(host, hu["text"], original_domains, own_suffixes,
                             tracker_family) if host != "?" else "unknown"
        servers.append({"host": host, "kind": kind if kind not in ("link", "system") else kind,
                        "hidden": hu["kind"], "sample": hu["text"][:160]})
    caps = s["caps"]
    unknown = [x for x in servers if x["kind"] in ("unknown", "ip", "exfil")]
    hidden_unknown = [x for x in servers if x.get("hidden")
                      and x["kind"] not in ("original", "system", "link", "known_service")]
    exfil = [x for x in servers if x["kind"] == "exfil"]
    ip_servers = [x for x in unknown if x["kind"] == "ip"]
    uploadish = [x for x in unknown if x.get("uploadish")]
    sensitive = [c for c in SENSITIVE if c in caps]
    can_send = "send" in caps
    sens_fa = "، ".join(CAP_FA[c] for c in sensitive)
    # danger = a COMPLETE, stealer-like path (never just "has a server").
    if exfil or s["bot_tokens"]:
        verdict = "danger"
        why = ("آدرس دریافت داده‌ی معروف برای سرقت اطلاعات (مثل ربات تلگرام/وب‌هوک) در آن هست: "
               + "، ".join(x["host"] for x in exfil[:2]) if exfil
               else "توکن ربات تلگرام داخل آن جاسازی شده است (روش رایج ارسال اطلاعات دزدیده‌شده)")
    elif hidden_unknown and can_send:
        verdict = "danger"
        why = ("آدرس سرور را پنهان (رمزگذاری) کرده و امکان ارسال دارد: "
               + "، ".join(x["host"] for x in hidden_unknown[:2]))
    elif (ip_servers or uploadish) and can_send and sensitive:
        verdict = "danger"
        why = (f"به {sens_fa} دسترسی دارد و به آدرس مستقیم/آپلود "
               + "، ".join(x["host"] for x in (ip_servers or uploadish)[:2]) + " ارسال می‌کند")
    elif unknown and can_send and sensitive:
        verdict = "review"
        why = (f"به {sens_fa} دسترسی دارد و با سرور " +
               "، ".join(x["host"] for x in unknown[:3]) +
               " در ارتباط است؛ مدرکی از ارسال اطلاعات شخصی نیست — برای اطمینان بررسی دستی شود")
    elif unknown or hidden_unknown:
        verdict = "info"
        why = ("با سرور " + "، ".join(x["host"] for x in (unknown or hidden_unknown)[:3]) +
               " در ارتباط است، ولی به اطلاعات شخصی شما دسترسی ندارد")
    else:
        verdict = "ok"
        why = "هیچ سرور ناشناسی ندارد؛ مسیری برای فرستادن اطلاعات شما به جای دیگر در آن نیست"
    part.update({"verdict": verdict, "why_fa": why, "servers": servers, "caps": caps,
                 "sensitive_caps": sensitive, "can_send": can_send,
                 "bot_tokens": s["bot_tokens"],
                 "unknown_servers": sorted({x["host"] for x in unknown}),
                 "hidden_urls": s["hidden_urls"]})
    return part


RANK = {"ok": 0, "info": 1, "unreadable": 1, "review": 2, "danger": 3}


def build_tampering(parts, extra, deb_packages, original_domains, jailbreak_markers=()):
    """Compatible tampering dict (v9 keys kept) + v10 fields."""
    debs = []
    for d in deb_packages or []:
        name = (d.get("package") or d.get("name") or "").lower()
        debs.append({"name": d.get("package") or d.get("name"), "path": d.get("path"),
                     "sibstar": any(k in name or k in (d.get("path") or "").lower()
                                    for k in SIBSTAR_PACKAGES),
                     "note_fa": "فایل .deb داخل برنامه اجرا نمی‌شود؛ فقط یک فایل همراه است."})
    real_parts = [p for p in parts if p["kind"] != "hook_engine"]
    overall = "ok"
    for p in parts:
        if RANK.get(p.get("verdict", "ok"), 0) > RANK[overall]:
            overall = p["verdict"]
    if extra.get("missing_appended") or extra.get("jb_load_paths"):
        overall = max(overall, "info", key=lambda v: RANK[v])
    unknown = sorted({h for p in parts for h in p.get("unknown_servers", [])})
    tampered = bool(parts or extra.get("missing_appended") or extra.get("jb_load_paths"))
    if not tampered:
        verdict_fa = "نسخه‌ی اصلی — هیچ بخش اضافه‌ای به برنامه اضافه نشده است"
    elif overall == "danger":
        verdict_fa = "نسخه‌ی آنلاک — یک بخش اضافه مسیر کامل ارسال اطلاعات به سرور ناشناس دارد"
    elif overall == "review":
        verdict_fa = ("نسخه‌ی آنلاک — یک بخش اضافه هم به اطلاعات شخصی دسترسی دارد هم با "
                      "سرور غیررسمی در ارتباط است؛ مدرکی از ارسال نیست (بررسی دستی پیشنهاد می‌شود)")
    elif overall == "info":
        verdict_fa = ("نسخه‌ی آنلاک — بخش اضافه با سرویس دیگری هم در ارتباط است، ولی به "
                      "اطلاعات شخصی شما دسترسی ندارد")
    else:
        verdict_fa = (f"نسخه‌ی آنلاک — {len(real_parts) or len(parts)} بخش اضافه دارد؛ "
                      "هیچ‌کدام سرور ناشناس یا مسیر ارسال اطلاعات ندارند")
    signals = []
    for p in parts:
        for r in p["reasons_fa"][:2]:
            signals.append(f"{p['name']}: {r}")
    for m in extra.get("missing_appended", []):
        signals.append(f"دستور بارگذاری اضافه‌شده به فایلی که در برنامه نیست: {m['name']}")
    for m in extra.get("jb_load_paths", []):
        signals.append(f"مسیر بارگذاری مخصوص گوشی جیلبریک‌شده: {m['name']}")
    note = ("بخش‌های اضافه هیچ سرور ناشناسی ندارند — یعنی مسیری برای فرستادن اطلاعات شما "
            "به سازنده‌ی نسخه یا شخص ثالث در آن‌ها دیده نشد." if not unknown else
            "سرورهای بخش اضافه: " + "، ".join(unknown))
    return {
        "verdict": "tampered" if tampered else "not-found",
        "tampered": tampered,
        "verdict_fa": verdict_fa,
        "safety": overall,
        "added_parts": parts,
        "added_part_count": len(parts),
        "injected_dylibs": [{"name": p["name"], "path": p["path"], "size_bytes": p["size_bytes"],
                             "reasons_fa": p["reasons_fa"],
                             "domains": [s["host"] for s in p.get("servers", [])],
                             "insecure_http_urls": [], "suspicious": [],
                             "kind": p["kind"]} for p in parts],
        "injected_dylib_count": len(parts),
        "tweak_deb_packages": [d["name"] for d in debs if d["name"]],
        "deb_files": debs,
        "substrate_files": [p["path"] for p in parts if p["kind"] == "hook_engine"],
        "tweak_domains": sorted({s["host"] for p in parts for s in p.get("servers", [])}),
        "unknown_tweak_servers": unknown,
        "signals": signals, "signal_count": len(signals),
        "evidence": signals[:],
        "server_note_fa": note,
        "extra": extra,
        "jailbreak_markers": list(jailbreak_markers or []),
    }


# ---------------------------------------------------------------- answers
def _ans(id_, q, verdict, tone, pill, short, card, evidence):
    return {"id": id_, "question_fa": q, "verdict": verdict, "tone": tone,
            "pill_fa": pill, "answer_fa": short, "card_fa": card,
            "evidence": evidence, "limits": []}


LIMIT_LINE_FA = ("این بررسی محتوای فایل برنامه را می‌سنجد، نه رفتار لحظه‌ای آن؛ برای همین "
                 "هیچ بررسی‌ای نمی‌تواند ۱۰۰٪ تضمین بدهد، ولی هر چیزی که به نسخه اضافه شده "
                 "بود دقیق بررسی شد.")


def build_answers(r):
    tamp = r.get("tampering") or {}
    safety = tamp.get("safety", "ok")
    parts = tamp.get("added_parts") or []
    ident = r.get("identity") or {}
    app = known_app(ident.get("bundle_id"))
    app_name = (app or {}).get("name") or ident.get("display_name") or "برنامه"
    photo_read = bool(r.get("photo_read_access"))
    add_only = r.get("photo_access") == "add-only"
    encrypted = (r.get("binary") or {}).get("encrypted") is True
    own_domains = r.get("own_domains_compact") or {}
    has_servers = bool(own_domains.get("relevant"))
    pm = r.get("privacy_manifest") or {}
    collected = pm.get("collected_data_types", []) if isinstance(pm, dict) else []
    trackers = [t.get("tracker") for t in (r.get("known_trackers") or [])]
    danger_parts = [p for p in parts if p.get("verdict") == "danger"]
    review_parts = [p for p in parts if p.get("verdict") in ("review", "info")]
    photo_danger = [p for p in danger_parts if "photos" in (p.get("caps") or {})]

    # ---- unlocked? ----
    if not tamp.get("tampered"):
        a_t = _ans("tampering", "آیا این نسخه آنلاک شده است؟", "no-evidence", "good", "نه",
                   "نه — نسخه‌ی اصلی است؛ چیزی به برنامه اضافه نشده",
                   "نسخه‌ی اصلی؛ چیزی به برنامه اضافه نشده",
                   ["هیچ کتابخانه‌ی اضافه یا دستور بارگذاری اضافه‌شده‌ای پیدا نشد."])
    else:
        n = len(parts)
        if safety == "danger":
            a_t = _ans("tampering", "آیا این نسخه آنلاک شده است؟", "confirmed", "bad", "بله",
                       "بله — آنلاک شده؛ یک بخش اضافه مسیر ارسال اطلاعات به سرور ناشناس دارد",
                       "آنلاک شده؛ بخش اضافه مسیر ارسال اطلاعات دارد",
                       [p.get("why_fa", "") for p in danger_parts[:2]])
        else:
            a_t = _ans("tampering", "آیا این نسخه آنلاک شده است؟", "confirmed", "neutral", "بله",
                       f"بله — آنلاک شده ({n} بخش اضافه)؛ این عادی است و به‌تنهایی خطری ندارد",
                       "آنلاک شده؛ این عادی است و خطری ندارد",
                       ["؛ ".join(f"{p['name']} ({p['label_fa']})" for p in parts[:4])])

    # ---- Q1: app sends photos to a server? (the ORIGINAL app's own design) ----
    if photo_danger and safety == "danger":
        a1 = _ans("sends_photos_to_server",
                  "آیا برنامه عکس‌ها را به سرور یا فضای ابری می‌فرستد؟",
                  "confirmed", "bad", "خطر",
                  "بخش اضافه‌شده امکان فرستادن عکس به سرور ناشناس را دارد",
                  "بخش اضافه می‌تواند عکس را به سرور ناشناس بفرستد",
                  [p.get("why_fa", "") for p in photo_danger[:2]])
    elif app and app.get("cloud_fa"):
        a1 = _ans("sends_photos_to_server",
                  "آیا برنامه عکس‌ها را به سرور یا فضای ابری می‌فرستد؟",
                  "own-servers", "neutral", "مثل نسخه اصلی",
                  app["cloud_fa"],
                  f"فقط قابلیت‌های آنلاین/AI خود {app_name}، به سرور خود {app_name}",
                  [f"این رفتار طراحی رسمی خود {app_name} است و در نسخه‌ی اصلی هم هست"
                   + ("؛ بخش اضافه‌شده مسیر جدیدی برای ارسال عکس اضافه نکرده است."
                      if tamp.get("tampered") else ".")])
    elif has_servers:
        a1 = _ans("sends_photos_to_server",
                  "آیا برنامه عکس‌ها را به سرور یا فضای ابری می‌فرستد؟",
                  "own-servers", "neutral", "مثل نسخه اصلی",
                  ("ویرایش و کار معمولی روی خود گوشی است. اگر برنامه قابلیت آنلاین/ابری "
                   "داشته باشد، عکس فقط برای همان قابلیت به سرور خود سازنده‌ی برنامه می‌رود — "
                   "دقیقاً مثل نسخه‌ی اصلی." + (" نسخه‌ی آنلاک مسیر جدیدی برای ارسال عکس "
                   "اضافه نکرده است." if tamp.get("tampered") else "")),
                  "فقط برای قابلیت‌های آنلاین، به سرور خود سازنده (مثل نسخه اصلی)",
                  ["برنامه با سرورهای خود سازنده‌اش در ارتباط است؛ هیچ مسیر ارسالی به "
                   "سرور ناشناس پیدا نشد."])
    else:
        a1 = _ans("sends_photos_to_server",
                  "آیا برنامه عکس‌ها را به سرور یا فضای ابری می‌فرستد؟",
                  "no-evidence", "good", "نه",
                  "نشانه‌ای از ارسال عکس پیدا نشد؛ هیچ آدرس سروری در برنامه نیست",
                  "هیچ آدرس سروری در برنامه نیست",
                  ["در فایل برنامه هیچ آدرس سروری پیدا نشد."])

    # ---- Q2: can the unlock maker / SibStar see photos? (ADDED parts) ----
    if safety == "danger":
        a2 = _ans("third_party_can_see_photos",
                  "آیا سازنده‌ی نسخه‌ی آنلاک یا تیم سیب‌استار می‌تواند عکس‌ها/ویدیوهای کاربر را ببیند یا دریافت کند؟",
                  "confirmed", "bad", "خطر",
                  "احتمال جدی — بخش اضافه‌شده مسیر ارسال اطلاعات به سرور ناشناس دارد؛ نصب نکنید",
                  "بخش اضافه مسیر ارسال به سرور ناشناس دارد",
                  [p.get("why_fa", "") for p in danger_parts[:2]])
    elif review_parts:
        a2 = _ans("third_party_can_see_photos",
                  "آیا سازنده‌ی نسخه‌ی آنلاک یا تیم سیب‌استار می‌تواند عکس‌ها/ویدیوهای کاربر را ببیند یا دریافت کند؟",
                  "no-evidence", "good", "نه",
                  ("نه — نشانه‌ای از ارسال عکس به سازنده‌ی نسخه یا سیب‌استار پیدا نشد؛ "
                   "بخش اضافه به عکس‌ها دسترسی جداگانه‌ای ندارد"),
                  "نشانه‌ای از ارسال عکس به کسی پیدا نشد",
                  [p.get("why_fa", "") for p in review_parts[:2]])
    elif tamp.get("tampered"):
        a2 = _ans("third_party_can_see_photos",
                  "آیا سازنده‌ی نسخه‌ی آنلاک یا تیم سیب‌استار می‌تواند عکس‌ها/ویدیوهای کاربر را ببیند یا دریافت کند؟",
                  "no-evidence", "good", "نه",
                  ("نه — بخش اضافه‌شده (آنلاک) هیچ سرور ناشناسی ندارد؛ مسیری برای رسیدن "
                   "عکس‌های شما به سازنده‌ی نسخه یا سیب‌استار در آن پیدا نشد"),
                  "بخش اضافه سرور ناشناسی ندارد؛ عکسی به کسی نمی‌رسد",
                  ["بخش‌های اضافه بررسی شدند: سرور ناشناس، آدرس پنهان یا مسیر ارسال ندارند."])
    else:
        a2 = _ans("third_party_can_see_photos",
                  "آیا سازنده‌ی نسخه‌ی آنلاک یا تیم سیب‌استار می‌تواند عکس‌ها/ویدیوهای کاربر را ببیند یا دریافت کند؟",
                  "no-evidence", "good", "نه",
                  "نه — چیزی به برنامه اضافه نشده که بتواند عکس‌ها را به کسی بفرستد",
                  "چیزی اضافه نشده؛ عکسی به کسی نمی‌رسد",
                  ["هیچ بخش اضافه‌ای در برنامه نیست."])

    # ---- Q3: collects photo/file info? ----
    photo_types = [c for c in collected if (c.get("type") or "") in (
        "NSPrivacyCollectedDataTypePhotosorVideos", "NSPrivacyCollectedDataTypeOtherUserContent")]
    extra_collect = [p for p in parts if p.get("verdict") in ("danger",)
                     and set(p.get("sensitive_caps") or [])]
    if extra_collect:
        a3 = _ans("collects_photo_info", "آیا برنامه اطلاعات عکس/فایل کاربر را جمع‌آوری می‌کند؟",
                  "confirmed", "bad", "خطر",
                  "بخش اضافه‌شده به اطلاعات شخصی دسترسی دارد و می‌تواند آن را بفرستد",
                  "بخش اضافه می‌تواند اطلاعات شخصی را جمع کند",
                  [p.get("why_fa", "") for p in extra_collect[:2]])
    elif photo_types:
        a3 = _ans("collects_photo_info", "آیا برنامه اطلاعات عکس/فایل کاربر را جمع‌آوری می‌کند؟",
                  "declared", "neutral", "اعلام شده",
                  (f"سازنده‌ی اصلی {app_name} اعلام کرده برای کارکرد برنامه با محتوای شما "
                   "(عکس/ویدیو) کار می‌کند — مثل نسخه‌ی اصلی. بخش اضافه‌شده چیزی جمع نمی‌کند."),
                  "فقط همان چیزی که سازنده‌ی اصلی اعلام کرده (مثل نسخه اصلی)",
                  ["در مانیفست حریم خصوصی برنامه «عکس/ویدیو یا محتوای کاربر» اعلام شده است."])
    else:
        tr = f" (ابزار آمار/تبلیغات خود برنامه مثل {', '.join(trackers[:2])} فقط آمار استفاده را می‌فرستد، نه عکس)" if trackers else ""
        a3 = _ans("collects_photo_info", "آیا برنامه اطلاعات عکس/فایل کاربر را جمع‌آوری می‌کند؟",
                  "no-evidence", "good", "نه",
                  "نشانه‌ای از جمع‌آوری اطلاعات عکس‌ها پیدا نشد" + tr,
                  "نشانه‌ای از جمع‌آوری اطلاعات عکس پیدا نشد",
                  ["سازنده‌ی برنامه جمع‌آوری عکس اعلام نکرده و بخش اضافه هم چنین کاری ندارد."])

    # ---- final verdict ----
    if safety == "danger":
        v = _ans("verdict", "حکم نهایی — این نسخه بررسی شده است؟", "risky", "bad", "خطر",
                 "این نسخه ممکن است اطلاعات شما را به سرور ناشناس بفرستد؛ نصب نکنید",
                 "", [p.get("why_fa", "") for p in danger_parts[:2]])
    elif encrypted and not tamp.get("tampered"):
        v = _ans("verdict", "حکم نهایی — این نسخه بررسی شده است؟", "partial", "neutral", "ناقص",
                 "بخش اصلی برنامه قفل است؛ چیزی به آن اضافه نشده و نشانه‌ی خطری پیدا نشد",
                 "", ["باینری اصلی رمزگذاری‌شده (FairPlay) است."])
    elif safety == "review":
        v = _ans("verdict", "حکم نهایی — این نسخه بررسی شده است؟", "caution", "warn", "بررسی شد",
                 "نشانه‌ی خطر جدی پیدا نشد؛ یک مورد برای اطمینان بیشتر بررسی شد", "",
                 [p.get("why_fa", "") for p in review_parts[:2]])
    else:
        v = _ans("verdict", "حکم نهایی — این نسخه بررسی شده است؟", "ok", "good", "بررسی شد",
                 "نشانه‌ی خطری پیدا نشد", "",
                 ["همه‌ی بخش‌های اضافه، سرورها و دسترسی‌ها بررسی شدند."])
    v["checked_fa"] = ("بله — امضا، دسترسی‌ها، کتابخانه‌ها و دستورهای بارگذاری، سرورها و "
                       "تک‌تک بخش‌های اضافه‌شده بررسی شدند.")

    if photo_read:
        photo_answers = [a1, a2, a3]
    else:
        txt = ("این برنامه عکس‌های شما را نمی‌خواند؛ فقط می‌تواند عکس ذخیره کند" if add_only
               else "این برنامه به عکس‌های شما دسترسی ندارد")
        na = _ans("photos_not_applicable", "آیا این برنامه به عکس‌های شما دسترسی دارد؟",
                  "no-evidence", "good", "نه", "نه — " + txt, txt,
                  ["دسترسی خواندن گالری در برنامه اعلام نشده است."])
        photo_answers = [na, a2] if safety == "danger" else [na]
    return [a_t, *photo_answers, v]


# ---------------------------------------------------------------- report md
def render_added_parts_md(r):
    tamp = r.get("tampering") or {}
    L = ["## نسخه‌ی آنلاک — بخش‌های اضافه‌شده (تحلیل دقیق v10)",
         f"**وضعیت: {tamp.get('verdict_fa', '—')}**",
         f"- ایمنی بخش‌های اضافه: **{ {'ok': 'سالم — نشانه‌ی خطری نیست', 'info': 'سالم — فقط با سرویس دیگری در ارتباط است (بدون دسترسی به اطلاعات شخصی)', 'review': 'نیاز به نگاه شما — دسترسی به اطلاعات شخصی + سرور غیررسمی، بدون مدرک ارسال', 'danger': 'خطرناک', 'unreadable': 'قابل خواندن نبود'}.get(tamp.get('safety', 'ok')) }**",
         f"- {tamp.get('server_note_fa', '')}"]
    ex = tamp.get("extra") or {}
    L.append(f"- کتابخانه‌های بررسی‌شده: {ex.get('lib_count', 0)} (dylib و framework)؛ "
             f"تیم امضای برنامه‌ی اصلی: {ex.get('main_team_id') or '—'}")
    for m in ex.get("missing_appended", []):
        L.append(f"- ⚠️ دستور بارگذاری اضافه‌شده در `{m['loader']}` به فایلی که نیست: `{m['name']}`")
    for m in ex.get("jb_load_paths", []):
        L.append(f"- ⚠️ مسیر بارگذاری مخصوص جیلبریک در `{m['loader']}`: `{m['name']}`")
    for d in tamp.get("deb_files", []):
        tag = " (بسته‌ی سیب‌استار)" if d.get("sibstar") else ""
        L.append(f"- فایل .deb: `{d.get('path')}`{tag} — {d['note_fa']}")
    if ex.get("unreferenced"):
        L.append("- کتابخانه‌هایی که هیچ‌جا لود نمی‌شوند (اطلاعاتی، بی‌اثر مگر با dlopen): "
                 + "، ".join(f"`{u}`" for u in ex["unreferenced"][:10]))
    for p in tamp.get("added_parts", []):
        L.append("")
        icon = {"ok": "✅", "info": "ℹ️", "review": "🔎", "danger": "⛔", "unreadable": "❔"}.get(p.get("verdict"), "")
        L.append(f"### {icon} `{p['path']}` — {p['label_fa']} — {p.get('size_bytes', 0):,} بایت")
        for why in p.get("reasons_fa", []):
            L.append(f"- چرا اضافه است: {why}")
        if p.get("signing_id") or p.get("team_id"):
            L.append(f"- امضا: {p.get('signing_id') or '—'} / تیم {p.get('team_id') or '—'}"
                     + (" (ad-hoc)" if p.get("adhoc") else ""))
        if p.get("loaded_by"):
            L.append("- لود می‌شود توسط: " + "، ".join(f"`{x}`" for x in p["loaded_by"]))
        L.append(f"- نتیجه: {p.get('why_fa') or p.get('note_fa', '')}")
        caps = p.get("caps") or {}
        if caps:
            L.append("- چه چیزهایی را لمس می‌کند: " + "؛ ".join(
                f"{CAP_FA.get(k, k)} ({', '.join(v[:3])})" for k, v in caps.items()))
        srv = p.get("servers") or []
        if srv:
            kind_fa = {"original": "سرور خود برنامه", "system": "سیستمی/مستندات", "link": "لینک (اعتبار/شبکه اجتماعی)",
                       "known_service": "سرویس شناخته‌شده‌ی توئیک", "tracker": "آمار/تبلیغات",
                       "unknown": "ناشناس", "ip": "IP مستقیم", "exfil": "⛔ دریافت داده (سرقت)"}
            for s in srv[:25]:
                h = f" [پنهان‌شده با {s['hidden']}]" if s.get("hidden") else ""
                L.append(f"  - {s['host']} — {kind_fa.get(s['kind'], s['kind'])}{h}")
        else:
            L.append("- هیچ آدرس سروری در این بخش نیست.")
        if p.get("bot_tokens"):
            L.append(f"- ⛔ {p['bot_tokens']} توکن ربات تلگرام داخل فایل (مقدار نمایش داده نمی‌شود)")
    L.append("")
    return L


def render_domains_md(r):
    c = r.get("domains_compact") or compact_domains(r.get("domains", []))
    L = [f"## دامنه‌ها — {len(c['relevant'])} دامنه‌ی واقعی در {c['group_count']} گروه "
         f"(حذف‌شده: {c['noise_count']} مستندات/شبکه‌ی محلی، {c['apple_count']} سرویس اپل)"]
    for g, n in c["groups"][:40]:
        L.append(f"- {g}" + (f" ({n} زیردامنه)" if n > 1 else ""))
    if c["group_count"] > 40:
        L.append(f"- … و {c['group_count'] - 40} گروه دیگر (لیست کامل در JSON)")
    return L
