#!/usr/bin/env python3
"""
SibStar IPA Scanner v2 — deep scan (stdlib only, no paid dependencies)
Scans an iOS .ipa (ZIP containing Payload/*.app) WITHOUT decryption:

  v2 vs v1:
  - PrivacyInfo.xcprivacy manifest (tracking, tracking domains, collected
    data types + purposes, accessed API types + reasons)
  - Full Mach-O load-command parse: linked dylibs, rpaths, LC_BUILD_VERSION
    / LC_VERSION_MIN_IPHONEOS (min iOS), UUID, CPU type, FAT slices
  - Binary strings analysis (ONLY when decrypted): URLs/domains + suspicious
    API/selector patterns (advertisingIdentifier, location, contacts, keychain,
    pasteboard, dlopen/dlsym, IOKit, sysctl, ...)
  - Code-signature presence (_CodeSignature/CodeResources)
  - App-size breakdown (total / binary / frameworks)
  - Expanded tracker SDK list (30+), Apple-DTD false positive fixed
  - Granular 0-100 risk score with a per-item point breakdown

Cannot do on an encrypted App Store IPA: binary strings / API-pattern
analysis needs a decrypted IPA. FairPlay encryption is detected (cryptid)
and reported explicitly; that section is marked "unavailable", never faked.

Usage:
  python3 scanner.py app.ipa [--json out.json] [--report out.md]
"""
import argparse, hashlib, json, plistlib, re, struct, sys, tempfile, zipfile
from pathlib import Path
from urllib.parse import urlparse

MAX_IPA_BYTES = 2 * 1024 * 1024 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_FILES = 5000
MIN_STR_LEN = 4

# key -> (Persian label, English label, risk 0-10)
PERMISSIONS = {
    "NSCameraUsageDescription": ("دوربین", "Camera", 7),
    "NSMicrophoneUsageDescription": ("میکروفون", "Microphone", 8),
    "NSLocationWhenInUseUsageDescription": ("موقعیت مکانی (هنگام استفاده)", "Location When In Use", 7),
    "NSLocationAlwaysUsageDescription": ("موقعیت مکانی (همیشه)", "Location Always", 10),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("موقعیت مکانی (همیشه و هنگام استفاده)", "Location Always & When In Use", 10),
    "NSLocationTemporaryUsageDescriptionDictionary": ("موقعیت مکانی موقت", "Temporary Location", 6),
    "NSContactsUsageDescription": ("مخاطبین", "Contacts", 9),
    "NSPhotoLibraryUsageDescription": ("گالری عکس (خواندن)", "Photo Library (read)", 7),
    "NSPhotoLibraryAddUsageDescription": ("گالری عکس (ذخیره)", "Photo Library (add)", 4),
    "NSBluetoothAlwaysUsageDescription": ("بلوتوث", "Bluetooth", 5),
    "NSBluetoothPeripheralUsageDescription": ("بلوتوث (جانبی)", "Bluetooth Peripheral", 5),
    "NSHealthShareUsageDescription": ("سلامت (خواندن)", "Health Share", 8),
    "NSHealthUpdateUsageDescription": ("سلامت (نوشتن)", "Health Update", 8),
    "NSHealthClinicalUsageDescription": ("سلامت بالینی", "Health Clinical Records", 9),
    "NSMotionUsageDescription": ("حرکت / سنسور حرکتی", "Motion", 5),
    "NSAppleMusicUsageDescription": ("اپل موزیک", "Apple Music", 5),
    "NSSpeechRecognitionUsageDescription": ("تشخیص گفتار", "Speech Recognition", 7),
    "NSFaceIDUsageDescription": ("فیس‌آیدی", "Face ID", 6),
    "NSLocalNetworkUsageDescription": ("شبکه محلی", "Local Network", 6),
    "NSUserTrackingUsageDescription": ("ردیابی بین‌برنامه‌ای (ATT)", "App Tracking Transparency", 8),
    "NSCalendarsUsageDescription": ("تقویم", "Calendars", 6),
    "NSCalendarsFullAccessUsageDescription": ("تقویم (دسترسی کامل)", "Calendars Full Access", 7),
    "NSRemindersUsageDescription": ("یادآورها", "Reminders", 5),
    "NSRemindersFullAccessUsageDescription": ("یادآورها (دسترسی کامل)", "Reminders Full Access", 6),
    "NSHomeKitUsageDescription": ("هوم‌کیت", "HomeKit", 6),
    "NSVideoSubscriberAccountUsageDescription": ("حساب ویدیو", "Video Subscriber Account", 4),
    "NSSiriUsageDescription": ("سیری", "Siri", 5),
    "NSWalletUsageDescription": ("والت", "Wallet", 6),
    "NSNFCUsageDescription": ("NFC", "NFC", 5),
    "NSAppleEventsUsageDescription": ("رویدادهای اپل (اتوماسیون)", "Apple Events", 6),
    "NSSystemExtensionUsageDescription": ("اکستنشن سیستم", "System Extension", 6),
    "NSFileProviderUsageDescription": ("فایل‌پرووایدر", "File Provider", 5),
    "NSLocationDefaultAccuracyReducedUsageDescription": ("موقعیت با دقت کم", "Location Reduced Accuracy", 4),
}

KNOWN_TRACKERS = {
    "firebase": "Firebase (Google Analytics/Crashlytics)",
    "fbaudience": "Facebook Audience Network",
    "fbsdk": "Facebook SDK",
    "facebook": "Facebook SDK",
    "appsflyer": "AppsFlyer",
    "adjust": "Adjust",
    "branch": "Branch.io",
    "flurry": "Flurry",
    "amplitude": "Amplitude",
    "mixpanel": "Mixpanel",
    "onesignal": "OneSignal",
    "clevertap": "CleverTap",
    "appcenter": "App Center",
    "sentry": "Sentry",
    "bugsnag": "Bugsnag",
    "admob": "Google AdMob",
    "googlemobileads": "Google Mobile Ads",
    "ironsource": "ironSource",
    "unityads": "Unity Ads",
    "applovin": "AppLovin",
    "tiktok": "TikTok SDK",
    "snapkit": "Snap Kit",
    "chartboost": "Chartboost",
    "vungle": "Vungle / Liftoff",
    "mopub": "MoPub",
    "kochava": "Kochava",
    "singular": "Singular",
    "tenjin": "Tenjin",
    "braze": "Braze (Appboy)",
    "intercom": "Intercom",
    "zendesk": "Zendesk",
    "crashlytics": "Crashlytics",
    "pendo": "Pendo",
    "heap": "Heap Analytics",
    "airship": "Airship (Urban Airship)",
    "leanplum": "Leanplum",
    "countly": "Countly",
    "matomo": "Matomo",
    "tealium": "Tealium",
    "mparticle": "mParticle",
}

# Suspicious binary patterns (checked ONLY on decrypted binaries).
# (regex, Persian label, English label, risk points)
SUSPICIOUS_PATTERNS = [
    (r"advertisingIdentifier", "شناسه تبلیغاتی (IDFA)", "advertisingIdentifier (IDFA)", 6),
    (r"identifierForVendor", "شناسه فروشنده (IDFV)", "identifierForVendor (IDFV)", 3),
    (r"CLLocationManager", "مدیر موقعیت مکانی", "CLLocationManager", 5),
    (r"CNContactStore|CNContactFetchRequest", "دسترسی به مخاطبین در کد", "Contacts store access in code", 6),
    (r"AVCaptureDevice|AVCaptureSession", "دسترسی به دوربین در کد", "Camera capture in code", 5),
    (r"UIPasteboard|generalPasteboard", "دسترسی به کلیپ‌بورد", "Pasteboard access", 6),
    (r"SecItemCopyMatching|SecItemAdd", "دسترسی به کی‌چین", "Keychain access", 4),
    (r"sysctlbyname|sysctl\(", "خواندن اطلاعات سیستم (sysctl)", "sysctl system info", 4),
    (r"dlopen|dlsym", "بارگذاری داینامیک کد (dlopen/dlsym)", "Dynamic loading (dlopen/dlsym)", 7),
    (r"IOKit|IOServiceGetMatchingServices", "دسترسی سطح پایین سخت‌افزار (IOKit)", "Low-level hardware access (IOKit)", 5),
    (r"CTCarrier|CTTelephonyNetworkInfo", "اطلاعات اپراتور سیم‌کارت", "Carrier info", 4),
    (r"ASIdentifierManager", "مدیر شناسه تبلیغاتی اپل", "ASIdentifierManager", 5),
    (r"requestTrackingAuthorization", "درخواست مجوز ردیابی (ATT)", "ATT tracking authorization request", 3),
]

URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
ASCII_STR_RE = re.compile(rb"[ -~]{4,}")
UTF16_STR_RE = re.compile(rb"(?:[ -~]\x00){4,}")
# Apple DTD is a known false positive inside mobileprovision — never count it.
APPLE_DTD_HOST = "www.apple.com"

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_extract(ipa_path, dest):
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    with zipfile.ZipFile(ipa_path) as z:
        if sum(i.file_size for i in z.infolist()) > MAX_IPA_BYTES:
            raise ValueError("IPA too large")
        for info in z.infolist():
            if len(out) > MAX_FILES:
                raise ValueError("Too many files in IPA")
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest)):
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                out.append(str(target.relative_to(dest)))
    return out

def find_app_dir(root):
    payload = Path(root) / "Payload"
    if not payload.is_dir():
        return None
    apps = sorted(p for p in payload.iterdir() if p.suffix == ".app" and p.is_dir())
    return apps[0] if apps else None

def _cstr(data, off):
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    try:
        return data[off:end].decode("utf-8", "replace")
    except Exception:
        return ""

# ---------------- Mach-O deep parse ----------------
LC = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_UUID", 0x18: "LC_LOAD_WEAK_DYLIB", 0x1B: "LC_UUID",
    0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE", 0x1F: "LC_REEXPORT_DYLIB",
    0x21: "LC_ENCRYPTION_INFO", 0x24: "LC_VERSION_MIN_IPHONEOS",
    0x25: "LC_VERSION_MIN_MACOSX", 0x26: "LC_FUNCTION_STARTS",
    0x28: "LC_MAIN", 0x32: "LC_BUILD_VERSION",
    0x2C: "LC_ENCRYPTION_INFO_64", 0x19: "LC_SEGMENT_64",
}
CPU_TYPES = {0x0100000C: "arm64", 0x01000007: "x86_64", 0x0000000C: "arm",
             0x00000007: "x86", 0x01000012: "arm64_32", 0x00000012: "armv7"}

def _parse_macho_slice(data, base_off=0):
    """Parse one Mach-O slice starting at base_off. Returns dict."""
    if len(data) - base_off < 28:
        return {"is_macho": False, "error": "slice too small"}
    magic_le = struct.unpack("<I", data[base_off:base_off + 4])[0]
    magic_be = struct.unpack(">I", data[base_off:base_off + 4])[0]
    is64 = magic_le == 0xFEEDFACF or magic_be == 0xFEEDFACF
    is32 = magic_le == 0xFEEDFACE or magic_be == 0xFEEDFACE
    if not (is64 or is32):
        return {"is_macho": False, "error": "not a Mach-O binary (magic mismatch)"}
    le = magic_le in (0xFEEDFACF, 0xFEEDFACE)
    fmt = "<" if le else ">"
    off = base_off
    try:
        if is64:
            # 64-bit header after magic: cputype, cpusubtype, filetype,
            # ncmds, sizeofcmds, flags, reserved (7 x uint32 = 28 bytes)
            cputype, cpusubtype, _ft, ncmds, sizeofcmds, _fl, _res = struct.unpack(
                fmt + "IIIIIII", data[off + 4:off + 32])
            cmd_off = off + 32
        else:
            # 32-bit header after magic: 6 x uint32 = 24 bytes
            cputype, cpusubtype, _ft, ncmds, sizeofcmds, _fl = struct.unpack(
                fmt + "IIIIII", data[off + 4:off + 28])
            cmd_off = off + 28
    except Exception as e:
        return {"is_macho": True, "error": str(e)}
    out = {"is_macho": True, "is64": bool(is64),
           "cpu": CPU_TYPES.get(cputype, f"0x{cputype:08x}"),
           "cryptid": None, "encrypted": None,
           "linked_dylibs": [], "rpaths": [], "min_os": None,
           "uuid": None, "has_code_signature": False, "has_main": False,
           "load_commands": [], "platform": None}
    end = cmd_off + sizeofcmds
    cur = cmd_off
    for _ in range(ncmds):
        if cur + 8 > len(data) or cur >= end:
            break
        cmd, cmdsize = struct.unpack(fmt + "II", data[cur:cur + 8])
        if cmdsize < 8:
            break
        out["load_commands"].append(LC.get(cmd, f"0x{cmd:x}"))
        try:
            if cmd in (0xC, 0x18, 0x1F, 0xD):  # dylib commands: name at +24
                name_off = struct.unpack(fmt + "I", data[cur + 8:cur + 12])[0]
                out["linked_dylibs"].append(_cstr(data, cur + name_off))
            elif cmd == 0x1C:  # LC_RPATH: path at +12
                p_off = struct.unpack(fmt + "I", data[cur + 8:cur + 12])[0]
                out["rpaths"].append(_cstr(data, cur + p_off))
            elif cmd in (0x21, 0x2C):  # encryption info
                if cur + 20 <= len(data):
                    _, _, cryptid = struct.unpack(fmt + "III", data[cur + 8:cur + 20])
                    out["cryptid"] = cryptid
                    out["encrypted"] = (cryptid == 1)
            elif cmd == 0x1D:  # code signature
                out["has_code_signature"] = True
            elif cmd == 0x1B:  # UUID
                out["uuid"] = data[cur + 8:cur + 24].hex()
            elif cmd == 0x28:  # LC_MAIN
                out["has_main"] = True
            elif cmd == 0x24:  # VERSION_MIN_IPHONEOS: version at +8
                v = struct.unpack(fmt + "I", data[cur + 8:cur + 12])[0]
                out["min_os"] = f"{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"
            elif cmd == 0x32:  # BUILD_VERSION: platform at +8, minos at +12
                platform, minos = struct.unpack(fmt + "II", data[cur + 8:cur + 16])
                out["platform"] = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS",
                                   5: "bridgeOS", 7: "iOSMac"}.get(platform, str(platform))
                out["min_os"] = f"{(minos >> 16) & 0xFF}.{(minos >> 8) & 0xFF}.{minos & 0xFF}"
        except Exception:
            pass
        cur += cmdsize
    out["linked_dylibs"] = sorted(set(out["linked_dylibs"]))
    out["rpaths"] = sorted(set(out["rpaths"]))
    return out

def parse_macho_deep(exe_path):
    """Parse Mach-O incl. FAT slices. Returns dict with slices + merged view."""
    try:
        size = exe_path.stat().st_size
        data = exe_path.read_bytes()[:MAX_SCAN_BYTES]
    except Exception as e:
        return {"is_macho": False, "error": str(e), "size_bytes": 0}
    base = {"size_bytes": size}
    if len(data) < 8:
        return {**base, "is_macho": False, "error": "executable too small"}
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):
        # FAT: BE header, nfat_arch uint32 BE, each arch: cputype, cpusubtype,
        # offset, size, align (5 x uint32 BE)
        try:
            n = struct.unpack(">I", data[4:8])[0]
        except Exception:
            return {**base, "is_macho": True, "fat": True, "error": "bad FAT header"}
        slices = []
        for i in range(min(n, 8)):
            try:
                _, _, off, sz, _ = struct.unpack(">IIIII", data[8 + i * 20:28 + i * 20])
                slices.append(_parse_macho_slice(data, off))
            except Exception as e:
                slices.append({"is_macho": False, "error": str(e)})
        merged = dict(slices[0]) if slices else {"is_macho": False}
        merged.update({"fat": True, "slices": slices, "slice_count": len(slices)})
        # encrypted if ANY slice is encrypted
        cryptids = [s.get("cryptid") for s in slices if s.get("is_macho")]
        if cryptids:
            merged["cryptid"] = max([c for c in cryptids if c is not None], default=None)
            merged["encrypted"] = (merged["cryptid"] == 1)
        return {**base, **merged}
    single = _parse_macho_slice(data, 0)
    return {**base, **single}

def extract_strings(data):
    """Printable ASCII + UTF-16LE strings, min length 4. Returns list of str."""
    out = []
    for m in ASCII_STR_RE.finditer(data):
        out.append(m.group(0).decode("ascii", "ignore"))
    for m in UTF16_STR_RE.finditer(data):
        try:
            out.append(m.group(0).decode("utf-16-le", "ignore"))
        except Exception:
            pass
    return out

def scan_binary_strings(exe_path, max_bytes=MAX_SCAN_BYTES):
    """Only call when NOT encrypted. Returns URLs/domains + suspicious hits."""
    try:
        data = exe_path.read_bytes()[:max_bytes]
    except Exception as e:
        return {"error": str(e)}
    urls, domains, http_urls = set(), set(), set()
    for m in URL_RE.finditer(data):
        u = m.group(0).decode("ascii", "ignore").rstrip(".,);\"'")
        urls.add(u)
        host = urlparse(u).hostname
        if host:
            domains.add(host.lower())
        if u.startswith("http://") and host != APPLE_DTD_HOST:
            http_urls.add(u)
    strings = extract_strings(data)
    hits = []
    for pat, fa, en, pts in SUSPICIOUS_PATTERNS:
        rx = re.compile(pat)
        count = sum(1 for s in strings if rx.search(s))
        if count:
            hits.append({"pattern": pat, "label_fa": fa, "label_en": en,
                         "points": pts, "matches": count})
    return {"string_count": len(strings), "urls": sorted(urls),
            "domains": sorted(domains), "insecure_http_urls": sorted(http_urls),
            "suspicious": hits}

def scan_bundle_files(app_dir):
    """URLs/domains from all small files inside .app (plists, json, configs).
    Apple DTD host is excluded from the insecure list (v1 false positive)."""
    urls, domains, http_urls = set(), set(), set()
    for p in sorted(app_dir.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > MAX_SCAN_BYTES:
                continue
            data = p.read_bytes()
        except Exception:
            continue
        for m in URL_RE.finditer(data):
            u = m.group(0).decode("ascii", "ignore").rstrip(".,);\"'")
            urls.add(u)
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
            if u.startswith("http://") and host != APPLE_DTD_HOST:
                http_urls.add(u)
    return sorted(urls), sorted(domains), sorted(http_urls)

def parse_mobileprovision(path):
    try:
        raw = path.read_bytes()
    except Exception:
        return None
    start = raw.find(b"<?xml")
    if start < 0:
        return None
    end = raw.find(b"</plist>", start)
    if end < 0:
        return None
    try:
        return plistlib.loads(raw[start:end + len(b"</plist>")])
    except Exception:
        return None

def parse_xcprivacy(app_dir):
    """PrivacyInfo.xcprivacy — Apple's privacy manifest (iOS 17+)."""
    path = app_dir / "PrivacyInfo.xcprivacy"
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as f:
            pl = plistlib.load(f)
    except Exception as e:
        return {"error": str(e)}
    collected = []
    for d in pl.get("NSPrivacyCollectedDataTypes", []) or []:
        collected.append({
            "type": d.get("NSPrivacyCollectedDataType"),
            "linked": bool(d.get("NSPrivacyCollectedDataTypeLinked")),
            "tracking": bool(d.get("NSPrivacyCollectedDataTypeTracking")),
            "purposes": d.get("NSPrivacyCollectedDataTypePurposes") or [],
        })
    accessed = []
    for d in pl.get("NSPrivacyAccessedAPITypes", []) or []:
        accessed.append({
            "api": d.get("NSPrivacyAccessedAPIType"),
            "reasons": d.get("NSPrivacyAccessedAPITypeReasons") or [],
        })
    return {
        "tracking": bool(pl.get("NSPrivacyTracking", False)),
        "tracking_domains": sorted(pl.get("NSPrivacyTrackingDomains", []) or []),
        "collected_data_types": collected,
        "accessed_api_types": accessed,
    }

# ---------------- main scan ----------------
def scan_ipa(ipa_path, workdir):
    ipa_path = Path(ipa_path)
    if not ipa_path.is_file():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")
    result = {
        "file": str(ipa_path),
        "sha256": sha256_of(ipa_path),
        "size_bytes": ipa_path.stat().st_size,
        "scanner": "sibstar-ipa-scanner 2.0 (stdlib only)",
        "limits": [
            "App Store IPAs are FairPlay-encrypted: binary string / API-pattern analysis needs a decrypted IPA.",
            "This scan reads Info.plist, PrivacyInfo.xcprivacy, frameworks, entitlements, ATS and embedded URLs without decryption.",
        ],
        "errors": [],
        "warnings": [],
    }
    root = Path(workdir) / "extracted"
    safe_extract(ipa_path, root)
    app_dir = find_app_dir(root)
    if not app_dir:
        result["errors"].append("No Payload/*.app found — not a valid IPA layout")
        return result
    result["app_dir"] = app_dir.name
    plist_path = app_dir / "Info.plist"
    if not plist_path.is_file():
        result["errors"].append("Info.plist not found in .app")
        return result
    try:
        with open(plist_path, "rb") as f:
            info = plistlib.load(f)
    except Exception as e:
        result["errors"].append(f"Info.plist parse failed: {e}")
        return result

    result["identity"] = {
        "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        "bundle_id": info.get("CFBundleIdentifier"),
        "version": info.get("CFBundleShortVersionString"),
        "build": info.get("CFBundleVersion"),
        "minimum_os": info.get("MinimumOSVersion"),
        "executable": info.get("CFBundleExecutable"),
        "supported_platforms": info.get("CFBundleSupportedPlatforms"),
        "supported_devices": info.get("UISupportedDevices"),
        "requires_iphone_os": bool(info.get("LSRequiresIPhoneOS", False)),
    }

    perms = []
    for key, (fa, en, risk) in PERMISSIONS.items():
        if key in info:
            desc = info.get(key)
            if isinstance(desc, dict):
                desc = "; ".join(f"{k}: {v}" for k, v in desc.items())
            perms.append({"key": key, "label_fa": fa, "label_en": en,
                          "risk": risk, "description": str(desc)[:300]})
    result["permissions"] = perms
    result["permission_count"] = len(perms)

    schemes = []
    for d in info.get("CFBundleURLTypes", []) or []:
        schemes.extend(d.get("CFBundleURLSchemes", []) or [])
    result["url_schemes"] = sorted(set(schemes))
    result["queries_schemes"] = sorted(set(info.get("LSApplicationQueriesSchemes", []) or []))

    ats = info.get("NSAppTransportSecurity") or {}
    result["ats"] = {
        "allows_arbitrary_loads": bool(ats.get("NSAllowsArbitraryLoads", False)),
        "allows_local_networking": bool(ats.get("NSAllowsLocalNetworking", False)),
        "allows_arbitrary_loads_in_web_content": bool(ats.get("NSAllowsArbitraryLoadsInWebContent", False)),
        "allows_arbitrary_loads_for_media": bool(ats.get("NSAllowsArbitraryLoadsForMedia", False)),
        "exception_domains": sorted((ats.get("NSExceptionDomains") or {}).keys()),
        "raw": ats,
    }

    # Privacy manifest
    result["privacy_manifest"] = parse_xcprivacy(app_dir)

    # Frameworks / dylibs / extensions / size breakdown
    fw_dir = app_dir / "Frameworks"
    frameworks = sorted(p.name for p in fw_dir.glob("*.framework")) if fw_dir.is_dir() else []
    fw_size = sum(p.stat().st_size for p in fw_dir.rglob("*") if p.is_file()) if fw_dir.is_dir() else 0
    dylibs = sorted(p.name for p in app_dir.glob("*.dylib"))
    extensions = sorted(p.name for p in app_dir.glob("PlugIns/*.appex")) if (app_dir / "PlugIns").is_dir() else []
    result["frameworks"] = frameworks
    result["dylibs"] = dylibs
    result["app_extensions"] = extensions
    result["size_breakdown"] = {
        "total_bytes": sum(p.stat().st_size for p in app_dir.rglob("*") if p.is_file()),
        "frameworks_bytes": fw_size,
        "framework_count": len(frameworks),
    }
    trackers = []
    for name in frameworks + dylibs:
        low = name.lower()
        for needle, label in KNOWN_TRACKERS.items():
            if needle in low:
                trackers.append({"framework": name, "tracker": label})
    # de-dup by tracker label
    seen = set()
    dedup = []
    for t in trackers:
        if t["tracker"] not in seen:
            seen.add(t["tracker"])
            dedup.append(t)
    result["known_trackers"] = dedup

    # Entitlements + provisioning
    ent = {}
    for cand in app_dir.glob("*.entitlements"):
        try:
            with open(cand, "rb") as f:
                ent.update(plistlib.load(f))
        except Exception as e:
            result["errors"].append(f"entitlements parse failed ({cand.name}): {e}")
    prov = app_dir / "embedded.mobileprovision"
    prov_info = None
    if prov.is_file():
        parsed = parse_mobileprovision(prov)
        if parsed:
            prov_info = {"name": parsed.get("Name"),
                         "team": (parsed.get("TeamIdentifier") or [None])[0],
                         "app_id_name": parsed.get("AppIDName"),
                         "creation_date": str(parsed.get("CreationDate")) if parsed.get("CreationDate") else None,
                         "expiration_date": str(parsed.get("ExpirationDate")) if parsed.get("ExpirationDate") else None}
            if isinstance(parsed.get("Entitlements"), dict):
                ent.update(parsed["Entitlements"])
    result["provisioning"] = prov_info
    result["entitlements"] = ent
    result["entitlement_keys"] = sorted(ent.keys())

    # Code signature presence
    code_sig = (app_dir / "_CodeSignature").is_dir()
    result["code_signature"] = {
        "has_code_signature_dir": code_sig,
        "has_code_resources": (app_dir / "_CodeSignature" / "CodeResources").is_file(),
        "has_embedded_provision": prov.is_file(),
    }
    if not code_sig:
        result["warnings"].append("پوشه _CodeSignature پیدا نشد — برنامه امضا نشده یا امضا ناقص است")

    # Binary deep parse
    exe_name = info.get("CFBundleExecutable")
    exe_path = (app_dir / exe_name) if exe_name else None
    binary = {"name": exe_name}
    bin_strings = None
    if exe_path and exe_path.is_file():
        binary.update(parse_macho_deep(exe_path))
        binary["size_bytes"] = exe_path.stat().st_size
        result["size_breakdown"]["binary_bytes"] = exe_path.stat().st_size
        if binary.get("min_os") and not result["identity"]["minimum_os"]:
            result["identity"]["minimum_os"] = binary["min_os"]
        if binary.get("encrypted") is True:
            result["warnings"].append(
                "باینری رمزگذاری‌شده (FairPlay) است — تحلیل رشته‌ها و الگوهای API باینری بدون نسخه‌ی رمزگشایی‌شده ممکن نیست")
            bin_strings = {"unavailable": True, "reason": "FairPlay-encrypted (cryptid=1)"}
        elif binary.get("encrypted") is False:
            bin_strings = scan_binary_strings(exe_path)
        else:
            bin_strings = {"unavailable": True, "reason": "وضعیت رمزگذاری باینری مشخص نشد"}
    else:
        binary["error"] = "executable not found in .app"
        bin_strings = {"unavailable": True, "reason": "executable not found"}
    result["binary"] = binary
    result["binary_strings"] = bin_strings

    # URLs / domains: bundle files + (decrypted) binary strings, merged
    urls, domains, http_urls = scan_bundle_files(app_dir)
    if bin_strings and not bin_strings.get("unavailable"):
        urls = sorted(set(urls) | set(bin_strings.get("urls", [])))
        domains = sorted(set(domains) | set(bin_strings.get("domains", [])))
        http_urls = sorted(set(http_urls) | set(bin_strings.get("insecure_http_urls", [])))
    result["urls"] = urls[:200]
    result["url_count"] = len(urls)
    result["domains"] = domains
    result["insecure_http_urls"] = http_urls

    # ---- Risk score v2: granular breakdown, 0-100 ----
    score, breakdown = 0, []
    def add(points, reason):
        nonlocal score
        score += points
        breakdown.append({"points": points, "reason": reason})
    if result["ats"]["allows_arbitrary_loads"]:
        add(25, "NSAllowsArbitraryLoads فعال است — ترافیک رمزنگاری‌نشده مجاز است")
    if result["ats"]["allows_arbitrary_loads_for_media"]:
        add(5, "NSAllowsArbitraryLoadsForMedia فعال است")
    if http_urls:
        add(15, f"{len(http_urls)} آدرس http:// ناامن پیدا شد")
    if result["ats"]["exception_domains"]:
        add(5, f"دامنه‌های استثنا در ATS: {', '.join(result['ats']['exception_domains'])}")
    for p in perms:
        if p["risk"] >= 9:
            add(8, f"دسترسی حساس: {p['label_fa']} ({p['label_en']})")
        elif p["risk"] >= 7:
            add(5, f"دسترسی پرریسک: {p['label_fa']} ({p['label_en']})")
    pm = result["privacy_manifest"]
    if pm and not pm.get("error"):
        if pm.get("tracking"):
            add(10, "مانیفست حریم خصوصی: NSPrivacyTracking = true (ردیابی کاربر)")
        if pm.get("tracking_domains"):
            add(8, f"دامنه‌های ردیابی در مانیفست: {', '.join(pm['tracking_domains'][:5])}")
        tracking_types = [c for c in pm.get("collected_data_types", []) if c.get("tracking")]
        if tracking_types:
            add(10, f"{len(tracking_types)} نوع داده‌ی جمع‌آوری‌شده با ردیابی مرتبط است")
        linked_types = [c for c in pm.get("collected_data_types", []) if c.get("linked")]
        if linked_types:
            add(5, f"{len(linked_types)} نوع داده‌ی جمع‌آوری‌شده به هویت کاربر متصل است")
    if dedup:
        add(min(15, 5 * len(dedup)), f"{len(dedup)} ترکر/SDK شناخته‌شده: {', '.join(t['tracker'] for t in dedup)}")
    if ent.get("get-task-allow") is True:
        add(10, "get-task-allow = true — باینری قابل دیباگ است (نسخه‌ی توسعه، نه انتشار)")
    if bin_strings and not bin_strings.get("unavailable"):
        for hit in bin_strings.get("suspicious", []):
            add(hit["points"], f"الگوی مشکوک در باینری: {hit['label_fa']} ({hit['matches']} مورد)")
    if not code_sig:
        add(5, "امضای کد پیدا نشد")
    if binary.get("encrypted") is True:
        breakdown.append({"points": 0, "reason": "باینری رمزگذاری‌شده (FairPlay) است — تحلیل کامل باینری بدون نسخه‌ی رمزگشایی‌شده ممکن نیست"})
    elif binary.get("encrypted") is False:
        breakdown.append({"points": 0, "reason": "باینری رمزگذاری نشده — تحلیل رشته‌ها انجام شد"})
    score = min(100, score)
    level = "کم" if score < 25 else ("متوسط" if score < 55 else "بالا")
    result["risk"] = {"score": score, "level_fa": level,
                      "level_en": "low" if score < 25 else ("medium" if score < 55 else "high"),
                      "breakdown": breakdown,
                      "reasons": [b["reason"] for b in breakdown]}
    return result

def render_report(r):
    L = []
    ident = r.get("identity", {})
    L.append(f"# گزارش اسکن IPA — {ident.get('display_name') or r.get('file')}")
    L.append("")
    L.append(f"- فایل: `{r['file']}`")
    L.append(f"- SHA-256: `{r.get('sha256','')}`")
    L.append(f"- اندازه فایل: {r.get('size_bytes',0):,} بایت")
    L.append(f"- Bundle ID: `{ident.get('bundle_id')}` | نسخه: {ident.get('version')} (build {ident.get('build')}) | حداقل iOS: {ident.get('minimum_os')}")
    sb = r.get("size_breakdown", {})
    L.append(f"- حجم باندل: {sb.get('total_bytes',0):,} بایت (باینری: {sb.get('binary_bytes','—')}، فریم‌ورک‌ها: {sb.get('frameworks_bytes',0):,} بایت)")
    if r.get("risk"):
        L.append(f"- **ریسک کلی: {r['risk']['score']}/100 — {r['risk']['level_fa']}**")
        for b in r["risk"]["breakdown"]:
            L.append(f"  - (+{b['points']}) {b['reason']}")
    L.append("")
    L.append("## محدودیت مهم")
    for lim in r.get("limits", []):
        L.append(f"- {lim}")
    if r.get("binary", {}).get("encrypted") is True:
        L.append("- ⚠️ این IPA رمزگذاری‌شده است (FairPlay). تحلیل رشته‌ها و الگوهای API باینری بدون IPA رمزگشایی‌شده ممکن نیست.")
    if r.get("warnings"):
        L.append("")
        L.append("## هشدارها")
        for w in r["warnings"]:
            L.append(f"- ⚠️ {w}")
    L.append("")
    L.append(f"## دسترسی‌ها (Permissions) — {r.get('permission_count',0)} مورد")
    for p in r.get("permissions", []):
        L.append(f"- **{p['label_fa']}** ({p['label_en']}) — ریسک {p['risk']}/10 — `{p['key']}`: {p['description']}")
    if not r.get("permissions"):
        L.append("- هیچ دسترسی حساسی در Info.plist اعلام نشده است.")
    pm = r.get("privacy_manifest")
    L.append("")
    L.append("## مانیفست حریم خصوصی (PrivacyInfo.xcprivacy)")
    if pm is None:
        L.append("- فایل PrivacyInfo.xcprivacy در باندل پیدا نشد (برای iOS 17+ توصیه می‌شود).")
    elif pm.get("error"):
        L.append(f"- خطا در خواندن مانیفست: {pm['error']}")
    else:
        L.append(f"- ردیابی (NSPrivacyTracking): {pm.get('tracking')}")
        L.append(f"- دامنه‌های ردیابی: {', '.join(pm.get('tracking_domains', [])) or '—'}")
        for c in pm.get("collected_data_types", []):
            L.append(f"- داده: `{c['type']}` — متصل به هویت: {c['linked']}، ردیابی: {c['tracking']}، اهداف: {', '.join(c['purposes']) or '—'}")
        for a in pm.get("accessed_api_types", []):
            L.append(f"- API دسترسی‌یافته: `{a['api']}` — دلایل: {', '.join(a['reasons']) or '—'}")
        if not pm.get("collected_data_types") and not pm.get("accessed_api_types"):
            L.append("- مانیفست خالی است (بدون داده‌ی جمع‌آوری‌شده).")
    L.append("")
    L.append("## App Transport Security")
    ats = r.get("ats", {})
    L.append(f"- AllowsArbitraryLoads: {ats.get('allows_arbitrary_loads')}")
    L.append(f"- AllowsArbitraryLoadsForMedia: {ats.get('allows_arbitrary_loads_for_media')}")
    L.append(f"- AllowsLocalNetworking: {ats.get('allows_local_networking')}")
    L.append(f"- Exception domains: {', '.join(ats.get('exception_domains', [])) or '—'}")
    L.append("")
    L.append(f"## فریم‌ورک‌ها ({len(r.get('frameworks',[]))}) و ترکرها ({len(r.get('known_trackers',[]))})")
    for f in r.get("frameworks", []):
        L.append(f"- {f}")
    for t in r.get("known_trackers", []):
        L.append(f"- ⚠️ ترکر: {t['framework']} → {t['tracker']}")
    if r.get("dylibs"):
        L.append(f"- dylibها: {', '.join(r['dylibs'])}")
    if r.get("app_extensions"):
        L.append(f"- App Extensions: {', '.join(r['app_extensions'])}")
    b = r.get("binary", {})
    L.append("")
    L.append("## باینری (Mach-O)")
    L.append(f"- فایل اجرایی: `{b.get('name')}` — {b.get('size_bytes','—')} بایت — CPU: {b.get('cpu','—')} — ۶۴ بیتی: {b.get('is64')} — FAT: {b.get('fat', False)}")
    L.append(f"- رمزگذاری‌شده (FairPlay): {b.get('encrypted')} (cryptid={b.get('cryptid')})")
    L.append(f"- UUID: {b.get('uuid') or '—'} — حداقل iOS (از باینری): {b.get('min_os') or '—'} — پلتفرم: {b.get('platform') or '—'}")
    L.append(f"- امضای کد (LC_CODE_SIGNATURE): {b.get('has_code_signature')} — پوشه _CodeSignature: {r.get('code_signature', {}).get('has_code_signature_dir')}")
    if b.get("linked_dylibs"):
        L.append(f"- کتابخانه‌های لینک‌شده ({len(b['linked_dylibs'])}):")
        for d in b["linked_dylibs"][:30]:
            L.append(f"  - {d}")
    if b.get("rpaths"):
        L.append(f"- RPATHها: {', '.join(b['rpaths'])}")
    bs = r.get("binary_strings") or {}
    L.append("")
    L.append("## تحلیل رشته‌های باینری")
    if bs.get("unavailable"):
        L.append(f"- در دسترس نیست: {bs.get('reason')}")
    else:
        L.append(f"- تعداد رشته‌های قابل خواندن: {bs.get('string_count',0)}")
        for h in bs.get("suspicious", []):
            L.append(f"- ⚠️ {h['label_fa']} ({h['label_en']}) — {h['matches']} مورد — (+{h['points']})")
        if not bs.get("suspicious"):
            L.append("- هیچ الگوی مشکوک شناخته‌شده‌ای در باینری پیدا نشد.")
    L.append("")
    L.append(f"## URL Schemes: {', '.join(r.get('url_schemes', [])) or '—'}")
    L.append(f"## دامنه‌ها ({len(r.get('domains',[]))}) و URLها ({r.get('url_count',0)})")
    for d in r.get("domains", [])[:50]:
        L.append(f"- {d}")
    if r.get("insecure_http_urls"):
        L.append("")
        L.append("### ⚠️ URLهای ناامن http://")
        for u in r["insecure_http_urls"][:20]:
            L.append(f"- {u}")
    L.append("")
    L.append(f"## Entitlements ({len(r.get('entitlement_keys',[]))})")
    for k in r.get("entitlement_keys", []):
        L.append(f"- `{k}`: {r['entitlements'].get(k)}")
    if not r.get("entitlement_keys"):
        L.append("- هیچ فایل entitlements / mobileprovision خوانایی پیدا نشد.")
    if r.get("provisioning"):
        L.append(f"- Provisioning: {r['provisioning'].get('name')} — تیم: {r['provisioning'].get('team')} — انقضا: {r['provisioning'].get('expiration_date')}")
    L.append("")
    if r.get("errors"):
        L.append("## خطاها")
        for e in r["errors"]:
            L.append(f"- {e}")
    return "\n".join(L) + "\n"

def main(argv=None):
    ap = argparse.ArgumentParser(description="SibStar IPA scanner v2 (deep scan)")
    ap.add_argument("ipa", help="Path to .ipa file")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--report", dest="report_out", default=None)
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args(argv)
    workdir = args.workdir or tempfile.mkdtemp(prefix="ipa-scan-v2-")
    try:
        result = scan_ipa(args.ipa, workdir)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON written: {args.json_out}")
    if args.report_out:
        Path(args.report_out).write_text(render_report(result), encoding="utf-8")
        print(f"Report written: {args.report_out}")
    print(render_report(result))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
