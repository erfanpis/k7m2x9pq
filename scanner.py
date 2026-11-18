#!/usr/bin/env python3
"""
SibStar IPA Scanner v3 — deep scan (stdlib only, no paid dependencies)
Scans an iOS .ipa (ZIP containing Payload/*.app) WITHOUT decryption:

  v3 vs v2:
  - More Info.plist coverage: background modes, file sharing, Bonjour
    services, required device capabilities, SDK/Xcode build info (DT* keys)
  - Privacy manifest: per-data-type risk (sensitive types flagged),
    cross-check of tracking domains against the domains found in the bundle
  - Tracker SDK list expanded (60+), also matched against static libs (.a)
    and .bundle names, not only .framework/.dylib names
  - Suspicious binary patterns expanded (30): HealthKit, PhotoKit,
    Bluetooth, NFC, Face ID, speech, motion, anti-debug (ptrace), process
    spawning, runtime introspection, network-interface enumeration
  - URL/domain analysis with per-domain risk: http-only, IP-literal hosts,
    known tracker/ad domains, manifest tracking domains
  - Entitlements analysed per key with severity (get-task-allow, push,
    associated domains, HealthKit, HomeKit, NFC, multicast, VPN, …)
  - Provisioning profile: type (development/distribution/enterprise),
    expiry check, team, app ID
  - ATS: per-exception-domain details (insecure loads, forward secrecy,
    minimum TLS, subdomains)
  - Embedded frameworks: per-framework bundle ID, version, size, own
    PrivacyInfo.xcprivacy
  - Every finding now carries a severity (critical/high/medium/low/info)
    in result["findings"], alongside the 0-100 risk breakdown

Cannot do on an encrypted App Store IPA: binary strings / API-pattern
analysis needs a decrypted IPA. FairPlay encryption is detected (cryptid)
and reported explicitly; that section is marked "unavailable", never faked.

Usage:
  python3 scanner.py app.ipa [--json out.json] [--report out.md]
"""
import argparse, hashlib, json, plistlib, re, struct, sys, tempfile, zipfile
from datetime import datetime, timezone
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
    "NSLocationUsageDescription": ("موقعیت مکانی (کلید قدیمی و منسوخ)", "Location (deprecated key)", 7),
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
    "segment": "Segment",
    "fullstory": "FullStory",
    "instabug": "Instabug",
    "rollbar": "Rollbar",
    "datadog": "Datadog",
    "newrelic": "New Relic",
    "appmetrica": "AppMetrica (Yandex)",
    "yandexmetrica": "Yandex Metrica",
    "adcolony": "AdColony",
    "tapjoy": "Tapjoy",
    "fyber": "Fyber",
    "inmobi": "InMobi",
    "smaato": "Smaato",
    "pubmatic": "PubMatic",
    "revenuecat": "RevenueCat",
    "adapty": "Adapty",
    "qonversion": "Qonversion",
    "airbridge": "Airbridge",
    "moloco": "Moloco",
    "mintegral": "Mintegral",
    "pangle": "Pangle (TikTok)",
    "startapp": "StartApp",
    "supersonic": "Supersonic (ironSource)",
    "mytarget": "myTarget",
    "openmeasurement": "Open Measurement SDK",
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
    (r"ABAddressBookCreate|ABAddressBookRequestAccess", "دسترسی به مخاطبین با API قدیمی", "Legacy AddressBook access", 6),
    (r"PHPhotoLibrary|PHAsset", "دسترسی به گالری در کد (PhotoKit)", "PhotoKit access in code", 6),
    (r"HKHealthStore", "دسترسی به سلامت در کد (HealthKit)", "HealthKit access in code", 6),
    (r"EKEventStore", "دسترسی به تقویم در کد (EventKit)", "EventKit access in code", 5),
    (r"CBCentralManager|CBPeripheralManager", "اسکن بلوتوث در کد", "Bluetooth scanning in code", 5),
    (r"NFCNDEFReaderSession|NFCTagReaderSession", "خواندن NFC در کد", "NFC reading in code", 5),
    (r"LAContext", "احراز هویت بیومتریک در کد (Face ID / Touch ID)", "Biometric auth in code", 3),
    (r"ASWebAuthenticationSession", "ورود وب و اشتراک کوکی (ASWebAuthenticationSession)", "Web auth session", 4),
    (r"AVAudioRecorder|AVAudioSession", "ضبط صدا / میکروفون در کد", "Audio recording in code", 6),
    (r"CMMotionManager|CMSensorRecorder", "سنسور حرکتی در کد", "Motion sensors in code", 4),
    (r"SFSpeechRecognizer", "تشخیص گفتار در کد", "Speech recognition in code", 5),
    (r"NEVPNManager|NEHotspotHelper", "مدیریت VPN / هات‌اسپات در کد", "VPN / hotspot management in code", 5),
    (r"CXCallObserver|CTCallCenter", "مشاهده تماس‌ها در کد", "Call observation in code", 6),
    (r"getifaddrs", "خواندن اینترفیس‌های شبکه (MAC / IP)", "Network interface enumeration", 5),
    (r"\buname\(", "خواندن اطلاعات دستگاه (uname)", "Device info via uname", 3),
    (r"\bptrace\(", "ضد دیباگ (ptrace)", "Anti-debugging (ptrace)", 6),
    (r"posix_spawn|execve|fork\(", "اجرای پروسس دیگر (spawn/exec/fork)", "Spawning another process", 7),
    (r"objc_copyClassList|objc_getClass", "جستجوی کلاس‌ها در ران‌تایم", "Runtime class introspection", 5),
    (r"_dyld_get_image_name|dyld_get_image", "بازرسی لودر داینامیک (dyld)", "Dynamic loader introspection", 4),
    (r"DYLD_INSERT_LIBRARIES", "بررسی تزریق کتابخانه (DYLD_INSERT_LIBRARIES)", "Library injection check", 4),
]

# Data types in PrivacyInfo.xcprivacy that are sensitive by themselves.
HIGH_RISK_DATA_TYPES = {
    "NSPrivacyCollectedDataTypePreciseLocation": ("موقعیت دقیق", 8),
    "NSPrivacyCollectedDataTypeCoarseLocation": ("موقعیت تقریبی", 5),
    "NSPrivacyCollectedDataTypeHealth": ("داده سلامت", 9),
    "NSPrivacyCollectedDataTypeFitness": ("داده تناسب اندام", 7),
    "NSPrivacyCollectedDataTypeContacts": ("مخاطبین", 8),
    "NSPrivacyCollectedDataTypePhotosorVideos": ("عکس‌ها یا ویدیوها", 9),
    "NSPrivacyCollectedDataTypeAudioData": ("داده صوتی", 7),
    "NSPrivacyCollectedDataTypeEmailsorTextMessages": ("ایمیل یا پیامک", 8),
    "NSPrivacyCollectedDataTypeOtherUserContent": ("محتوای دیگر کاربر", 7),
    "NSPrivacyCollectedDataTypePaymentInfo": ("اطلاعات پرداخت", 9),
    "NSPrivacyCollectedDataTypeCreditInfo": ("اطلاعات اعتباری", 9),
    "NSPrivacyCollectedDataTypeSensitiveInfo": ("اطلاعات حساس", 9),
}

# Known analytics / ads / tracking domain suffixes (for domain risk analysis).
TRACKER_DOMAIN_SUFFIXES = [
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "googlesyndication.com", "graph.facebook.com", "facebook.com",
    "appsflyer.com", "adjust.com", "app.adjust.com", "branch.io",
    "mixpanel.com", "amplitude.com", "api.amplitude.com", "sentry.io",
    "crashlytics.com", "fabric.io", "flurry.com", "data.flurry.com",
    "onesignal.com", "clevertap.com", "braze.com", "intercom.io",
    "zendesk.com", "bugsnag.com", "heap.io", "pendo.io", "countly.com",
    "matomo.cloud", "tealiumiq.com", "mparticle.com", "kochava.com",
    "singular.net", "tenjin.io", "applovin.com", "ironsource.com",
    "vungle.com", "mopub.com", "chartboost.com", "adcolony.com",
    "tapjoy.com", "inmobi.com", "fyber.com", "smaato.com", "pubmatic.com",
    "segment.com", "segment.io", "fullstory.com", "instabug.com",
    "appcenter.ms", "appmetrica.yandex", "yandexmetrica", "revenuecat.com",
    "api.revenuecat.com", "pangle.io", "mintegral.com", "moloco.com",
    "airbridge.io", "snapchat.com", "tiktok.com", "api.tiktok.com",
]

# Entitlement key -> (Persian label, severity, risk points)
SENSITIVE_ENTITLEMENTS = {
    "get-task-allow": ("قابل دیباگ بودن باینری (نسخه توسعه)", "high", 10),
    "aps-environment": ("پوش نوتیفیکیشن (APNs)", "low", 0),
    "com.apple.developer.associated-domains": ("دامنه‌های مرتبط (Universal Links)", "medium", 3),
    "com.apple.developer.healthkit": ("دسترسی HealthKit", "high", 6),
    "com.apple.developer.homekit": ("دسترسی HomeKit", "medium", 4),
    "com.apple.developer.healthkit.access": ("دسترسی HealthKit", "high", 6),
    "com.apple.developer.in-app-payments": ("پرداخت درون‌برنامه‌ای", "low", 0),
    "com.apple.developer.nfc.readersession.formats": ("خواندن تگ NFC", "medium", 4),
    "com.apple.developer.siri": ("دسترسی سیری", "low", 2),
    "com.apple.developer.networking.multicast": ("مالتی‌کست شبکه محلی", "medium", 4),
    "com.apple.developer.networking.networkextension": ("اکستنشن شبکه / VPN", "high", 5),
    "com.apple.developer.networking.wifi-info": ("اطلاعات وای‌فای (SSID/BSSID)", "high", 6),
    "com.apple.developer.devicecheck.appattest-environment": ("App Attest (DeviceCheck)", "low", 0),
    "com.apple.developer.applesignin": ("ورود با اپل (Sign in with Apple)", "low", 0),
    "com.apple.developer.fileprovider.testing-mode": ("File Provider (دسترسی فایل)", "medium", 3),
    "com.apple.developer.default-data-protection": ("محافظت داده پیش‌فرض", "info", 0),
    "com.apple.developer.associated-appclip-app-identifiers": ("App Clip مرتبط", "low", 0),
    "com.apple.security.application-groups": ("گروه اپلیکیشن (اشتراک داده بین برنامه‌ها)", "medium", 3),
    "com.apple.developer.kernel.extended-virtual-addressing": ("آدرس‌دهی مجازی گسترده کرنل", "medium", 3),
    "com.apple.developer.playable-content": ("محتوای قابل پخش", "info", 0),
    "com.apple.developer.usernotifications.filtering": ("فیلتر نوتیفیکیشن", "low", 0),
}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def severity_for_points(points):
    if points >= 10:
        return "critical"
    if points >= 7:
        return "high"
    if points >= 4:
        return "medium"
    if points >= 1:
        return "low"
    return "info"


def analyze_domains(domains, http_urls, tracking_domains):
    """Per-domain risk: http-only, IP literal, known tracker/ad domain,
    or listed in the privacy manifest as a tracking domain."""
    http_hosts = {urlparse(u).hostname for u in (http_urls or []) if urlparse(u).hostname}
    tracking = set(tracking_domains or [])
    out = []
    for d in sorted(domains or []):
        low = d.lower()
        is_tracker = any(low == s or low.endswith("." + s) for s in TRACKER_DOMAIN_SUFFIXES)
        is_ip = bool(IP_RE.match(d))
        http_only = d in http_hosts
        points = 0
        reasons = []
        if is_tracker:
            points += 4
            reasons.append("دامنه ترکر/تبلیغات شناخته‌شده")
        if d in tracking:
            points += 4
            reasons.append("در مانیفست حریم خصوصی به‌عنوان دامنه ردیابی اعلام شده")
        if http_only:
            points += 5
            reasons.append("فقط با http ناامن فراخوانی می‌شود")
        if is_ip:
            points += 3
            reasons.append("آدرس IP مستقیم به‌جای دامنه (پنهان‌کاری)")
        out.append({
            "domain": d, "is_tracker_domain": is_tracker,
            "in_tracking_manifest": d in tracking,
            "http_only": http_only, "is_ip_literal": is_ip,
            "risk_points": points, "severity": severity_for_points(points),
            "reasons_fa": reasons,
        })
    return out


def analyze_entitlements(ent):
    """Per-entitlement findings with severity. Only keys present are listed."""
    out = []
    for key, value in (ent or {}).items():
        if key == "get-task-allow" and value is not True:
            continue  # False means a release build — not a finding
        if key in SENSITIVE_ENTITLEMENTS:
            label_fa, sev, pts = SENSITIVE_ENTITLEMENTS[key]
            out.append({"key": key, "value": str(value)[:200], "label_fa": label_fa,
                        "severity": sev, "points": pts})
    return sorted(out, key=lambda f: -f["points"])


def analyze_provisioning(parsed):
    """Provisioning profile: type, expiry, team. Dates are strings (JSON-safe)."""
    if not parsed:
        return None
    out = {
        "name": parsed.get("Name"),
        "team": (parsed.get("TeamIdentifier") or [None])[0],
        "app_id_name": parsed.get("AppIDName"),
        "creation_date": str(parsed.get("CreationDate")) if parsed.get("CreationDate") else None,
        "expiration_date": str(parsed.get("ExpirationDate")) if parsed.get("ExpirationDate") else None,
        "expired": None, "days_until_expiry": None, "profile_type": "unknown",
    }
    if parsed.get("ProvisionedDevices"):
        out["profile_type"] = "development"
    elif parsed.get("ProvisionsAllDevices"):
        out["profile_type"] = "enterprise"
    elif parsed.get("Entitlements", {}).get("get-task-allow") is True:
        out["profile_type"] = "development"
    else:
        out["profile_type"] = "distribution"
    exp = parsed.get("ExpirationDate")
    if exp:
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            exp_naive = exp.replace(tzinfo=None) if getattr(exp, "tzinfo", None) else exp
            delta = (exp_naive - now).days
            out["days_until_expiry"] = delta
            out["expired"] = delta < 0
        except Exception:
            pass
    return out


def parse_plist_security(info):
    """Security-relevant Info.plist keys beyond permissions and ATS."""
    bg = info.get("UIBackgroundModes") or []
    return {
        "background_modes": sorted(bg),
        "background_location": "location" in bg,
        "background_fetch": "fetch" in bg,
        "background_audio": "audio" in bg,
        "background_voip": "voip" in bg,
        "background_processing": "processing" in bg,
        "file_sharing_enabled": bool(info.get("UIFileSharingEnabled", False)),
        "supports_opening_documents_in_place": bool(info.get("LSSupportsOpeningDocumentsInPlace", False)),
        "supports_document_browser": bool(info.get("UISupportsDocumentBrowser", False)),
        "bonjour_services": sorted(info.get("NSBonjourServices") or []),
        "document_types": sorted(
            {d.get("CFBundleTypeName") for d in (info.get("CFBundleDocumentTypes") or []) if d.get("CFBundleTypeName")}),
        "required_device_capabilities": sorted(info.get("UIRequiredDeviceCapabilities") or []),
        "device_family": info.get("UIDeviceFamily"),
        "uses_non_exempt_encryption": info.get("ITSAppUsesNonExemptEncryption"),
    }


def parse_sdk_info(info):
    """Build/SDK metadata from the DT* keys Xcode writes into Info.plist."""
    return {
        "sdk_name": info.get("DTSDKName"),
        "sdk_build": info.get("DTSDKBuild"),
        "platform_name": info.get("DTPlatformName"),
        "platform_version": info.get("DTPlatformVersion"),
        "platform_build": info.get("DTPlatformBuild"),
        "xcode": info.get("DTXcode"),
        "xcode_build": info.get("DTXcodeBuild"),
        "compiler": info.get("DTCompiler"),
        "build_machine_os": info.get("BuildMachineOSBuild"),
    }


def framework_details(app_dir, frameworks):
    """Per-framework: bundle ID, version, size, own privacy manifest."""
    out = []
    fw_dir = Path(app_dir) / "Frameworks"
    for name in frameworks:
        fdir = fw_dir / name
        entry = {"name": name, "bundle_id": None, "version": None,
                 "size_bytes": 0, "has_privacy_manifest": False}
        try:
            entry["size_bytes"] = sum(p.stat().st_size for p in fdir.rglob("*") if p.is_file())
        except Exception:
            pass
        plist = fdir / "Info.plist"
        if plist.is_file():
            try:
                with open(plist, "rb") as f:
                    pl = plistlib.load(f)
                entry["bundle_id"] = pl.get("CFBundleIdentifier")
                entry["version"] = pl.get("CFBundleShortVersionString")
            except Exception:
                pass
        entry["has_privacy_manifest"] = (fdir / "PrivacyInfo.xcprivacy").is_file()
        out.append(entry)
    return out


def build_privacy_answers(r):
    """Answer the four Picsart-style privacy questions for this IPA, in Persian.

    Each answer has: question, short answer (verdict word), verdict level
    (yes / possible / no-evidence / unknown), evidence bullets and honest
    limits. Static analysis can show capability + endpoints, never the
    actual runtime traffic — the answers say so explicitly.
    """
    ident = r.get("identity", {})
    name = ident.get("display_name") or "این برنامه"
    perms = {p["key"] for p in r.get("permissions", [])}
    pm = r.get("privacy_manifest") or {}
    ats = r.get("ats", {})
    domains = r.get("domains", [])
    http_urls = r.get("insecure_http_urls", [])
    trackers = r.get("known_trackers", [])
    plist_sec = r.get("plist_security", {})
    bin_strings = r.get("binary_strings") or {}
    encrypted = r.get("binary", {}).get("encrypted") is True
    suspicious = [] if bin_strings.get("unavailable") else bin_strings.get("suspicious", [])
    photo_perm = bool(perms & {"NSPhotoLibraryUsageDescription",
                               "NSPhotoLibraryAddUsageDescription"})
    bg = plist_sec.get("background_modes", [])

    # ---- Q1: does it send photos/files to a server or cloud? ----
    q1_evidence, q1_limits = [], []
    if photo_perm:
        q1_evidence.append("دسترسی به گالری عکس در Info.plist اعلام شده است.")
    else:
        q1_evidence.append("دسترسی به گالری عکس در Info.plist اعلام نشده است.")
    if domains:
        q1_evidence.append(f"برنامه با {len(domains)} سرور ارتباط برقرار می‌کند: "
                            + "، ".join(domains[:10]) + ("…" if len(domains) > 10 else ""))
    else:
        q1_evidence.append("هیچ دامنه‌ی شبکه‌ای در باندل پیدا نشد.")
    if bg:
        q1_evidence.append("حالت‌های پس‌زمینه: " + "، ".join(bg) +
                            " (اجرای پس‌زمینه یعنی امکان آپلود بدون باز بودن برنامه).")
    if ats.get("allows_arbitrary_loads"):
        q1_evidence.append("ATS اجازه‌ی ترافیک رمزنگاری‌نشده (http) را می‌دهد.")
    if http_urls:
        q1_evidence.append(f"{len(http_urls)} آدرس http:// ناامن در باندل پیدا شد.")
    q1_limits.append("تحلیل ایستا فقط «توانایی» و «آدرس سرورها» را نشان می‌دهد؛ "
                     "اینکه واقعاً چه فایلی و چه زمانی ارسال می‌شود فقط با رصد ترافیک زمان اجرا مشخص می‌شود.")
    if photo_perm and domains:
        q1_verdict, q1_short = "possible", "ممکن است — دسترسی به عکس + سرور دارد"
    elif photo_perm:
        q1_verdict, q1_short = "possible", "ممکن است — دسترسی به عکس دارد ولی سروری پیدا نشد"
    elif domains:
        q1_verdict, q1_short = "possible", "ممکن است — سرور دارد ولی دسترسی عکس اعلام نشده"
    else:
        q1_verdict, q1_short = "no-evidence", "شواهدی نیست"

    # ---- Q2: could the mod maker / a third party see user photos/videos? ----
    q2_evidence, q2_limits = [], []
    if trackers:
        q2_evidence.append(f"{len(trackers)} ترکر/SDK شخص ثالث در باندل است: "
                            + "، ".join(t["tracker"] for t in trackers[:8]))
    else:
        q2_evidence.append("هیچ ترکر/SDK شناخته‌شده‌ای در باندل پیدا نشد.")
    tracker_domains = [d["domain"] for d in r.get("domain_analysis", []) if d["is_tracker_domain"]]
    if tracker_domains:
        q2_evidence.append("دامنه‌های ترکر/تبلیغات: " + "، ".join(tracker_domains[:8]))
    if pm.get("tracking"):
        q2_evidence.append("مانیفست حریم خصوصی ردیابی کاربر را تأیید می‌کند (NSPrivacyTracking).")
    if pm.get("tracking_domains"):
        q2_evidence.append("دامنه‌های ردیابی اعلام‌شده در مانیفست: "
                            + "، ".join(pm["tracking_domains"][:5]))
    if http_urls:
        q2_evidence.append(f"ارسال با http ناامن ({len(http_urls)} آدرس) یعنی محتوای ارسالی "
                            "در مسیر قابل شنود است.")
    if suspicious:
        names = [h["label_fa"] for h in suspicious]
        q2_evidence.append("الگوهای مشکوک در باینری: " + "، ".join(names[:6]))
    if encrypted:
        q2_limits.append("باینری رمزگذاری‌شده است؛ الگوهای API باینری قابل بررسی نبود، "
                         "پس نبودِ نشانه دلیل قطعی بر نبودِ دسترسی نیست.")
    q2_limits.append("این اسکن نمی‌تواند بگوید سازنده‌ی ماد واقعاً چه می‌بیند؛ "
                     "فقط نشان می‌دهد چه کانال‌هایی برای خروج داده وجود دارد.")
    if trackers or tracker_domains or http_urls or pm.get("tracking"):
        q2_verdict, q2_short = "possible", "ممکن است — کانال خروج داده به شخص ثالث وجود دارد"
    elif encrypted:
        q2_verdict, q2_short = "unknown", "قابل بررسی نیست — باینری رمزگذاری‌شده است"
    else:
        q2_verdict, q2_short = "no-evidence", "شواهدی نیست — ولی رد قطعی هم نمی‌شود"

    # ---- Q3: does it collect user photo/file info? ----
    q3_evidence, q3_limits = [], []
    collected = pm.get("collected_data_types", []) if isinstance(pm, dict) else []
    photo_types = [c for c in collected
                   if (c.get("type") or "") in ("NSPrivacyCollectedDataTypePhotosorVideos",
                                                "NSPrivacyCollectedDataTypeOtherUserContent",
                                                "NSPrivacyCollectedDataTypeAudioData")]
    if photo_types:
        for c in photo_types:
            q3_evidence.append(f"مانیفست اعلام می‌کند «{c['type']}» جمع‌آوری می‌شود "
                               f"(متصل به هویت: {c.get('linked')}، ردیابی: {c.get('tracking')}، "
                               f"اهداف: {', '.join(c.get('purposes') or []) or '—'}).")
    elif collected:
        q3_evidence.append(f"مانیفست {len(collected)} نوع داده اعلام می‌کند، ولی «عکس/ویدیو» "
                            "در آن نیست: " + "، ".join(c.get("type", "?") for c in collected[:5]))
    else:
        q3_evidence.append("مانیفست حریم خصوصی هیچ نوع داده‌ی جمع‌آوری‌شده‌ای اعلام نکرده است.")
    if photo_perm:
        q3_evidence.append("دسترسی به گالری عکس اعلام شده است.")
    analytics = [t["tracker"] for t in trackers
                 if any(k in t["tracker"].lower() for k in
                        ("firebase", "amplitude", "mixpanel", "flurry", "segment",
                         "appsflyer", "adjust", "countly", "matomo", "heap", "pendo"))]
    if analytics:
        q3_evidence.append("SDKهای تحلیلی/تبلیغاتی در باندل است: " + "، ".join(analytics[:6]) +
                            " (این‌ها معمولاً رویدادها و شناسه‌های کاربر را جمع می‌کنند).")
    if not pm:
        q3_limits.append("فایل PrivacyInfo.xcprivacy در باندل پیدا نشد؛ "
                         "یعنی اعلامیه‌ی رسمی جمع‌آوری داده وجود ندارد.")
    q3_limits.append("جمع‌آوری اعلام‌نشده با تحلیل ایستا قابل رد نیست؛ "
                     "مانیفست فقط چیزی را نشان می‌دهد که سازنده اعلام کرده است.")
    if photo_types:
        q3_verdict, q3_short = "yes", "بله — در مانیفست اعلام شده است"
    elif collected or analytics:
        q3_verdict, q3_short = "possible", "احتمالاً — داده جمع می‌شود ولی عکس در مانیفست نیست"
    else:
        q3_verdict, q3_short = "no-evidence", "اعلام نشده است"

    # ---- Q4: clear verdict — what was verified, what could not be verified ----
    verified, unverified = [], []
    verified.append(f"اسکن ایستا کامل انجام شد (ریسک {r.get('risk', {}).get('score', '?')}/100 — "
                    f"{r.get('risk', {}).get('level_fa', '')}).")
    verified.append(f"Info.plist، مانیفست حریم خصوصی، {len(trackers)} ترکر، "
                    f"{len(domains)} دامنه و تنظیمات ATS بررسی شد.")
    verified.append("امضای کد و پروفایل provisioning بررسی شد.")
    if encrypted:
        unverified.append("باینری رمزگذاری‌شده است (FairPlay)؛ تحلیل رشته‌ها و الگوهای API باینری انجام نشد.")
    else:
        verified.append(f"باینری رمزگذاری نشده؛ {len(suspicious)} الگوی مشکوک در رشته‌های باینری بررسی شد.")
    unverified.append("محتوای واقعی ترافیک شبکه و رفتار زمان اجرا با اسکن ایستا قابل بررسی نیست.")
    unverified.append("اینکه سازنده‌ی ماد واقعاً چه داده‌ای می‌بیند، فقط با رصد ترافیک و تست زمان اجرا مشخص می‌شود.")
    if encrypted:
        q4_verdict, q4_short = "partial", "بررسی ناقص — باینری رمزگذاری‌شده است"
    elif r.get("risk", {}).get("score", 0) >= 55:
        q4_verdict, q4_short = "risky", "پرخطر — نشانه‌های جدی حریم خصوصی دارد"
    elif r.get("risk", {}).get("score", 0) >= 25:
        q4_verdict, q4_short = "caution", "احتیاط — چند نشانه‌ی حریم خصوصی دارد"
    else:
        q4_verdict, q4_short = "ok", "کم‌ریسک — نشانه‌ی جدی پیدا نشد"

    return [
        {"id": "sends_photos_to_server",
         "question_fa": "آیا برنامه عکس‌ها/فایل‌ها را به سرور یا فضای ابری می‌فرستد؟",
         "verdict": q1_verdict, "answer_fa": q1_short,
         "evidence": q1_evidence, "limits": q1_limits},
        {"id": "third_party_can_see_photos",
         "question_fa": "آیا سازنده‌ی ماد یا شخص ثالث می‌تواند عکس‌ها/ویدیوهای کاربر را ببیند یا دریافت کند؟",
         "verdict": q2_verdict, "answer_fa": q2_short,
         "evidence": q2_evidence, "limits": q2_limits},
        {"id": "collects_photo_info",
         "question_fa": "آیا برنامه اطلاعات عکس/فایل کاربر را جمع‌آوری می‌کند؟",
         "verdict": q3_verdict, "answer_fa": q3_short,
         "evidence": q3_evidence, "limits": q3_limits},
        {"id": "verdict",
         "question_fa": "حکم نهایی — این نسخه بررسی شده است؟ چه چیزی تأیید شد و چه چیزی قابل بررسی نیست؟",
         "verdict": q4_verdict, "answer_fa": q4_short,
         "evidence": verified, "limits": unverified},
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
        dtype = d.get("NSPrivacyCollectedDataType")
        risk_label, risk_pts = HIGH_RISK_DATA_TYPES.get(dtype, (None, 0))
        collected.append({
            "type": dtype,
            "linked": bool(d.get("NSPrivacyCollectedDataTypeLinked")),
            "tracking": bool(d.get("NSPrivacyCollectedDataTypeTracking")),
            "purposes": d.get("NSPrivacyCollectedDataTypePurposes") or [],
            "sensitive": risk_label,
            "risk_points": risk_pts,
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

def analyze_dylib(path, app_dir):
    """Analyse one embedded .dylib separately: Mach-O type, encryption,
    linked libraries, suspicious strings/patterns, and its own risk.

    Encrypted or unparseable dylibs are reported with an explicit reason —
    never skipped silently.
    """
    rel = str(path.relative_to(app_dir)) if str(path).startswith(str(app_dir)) else path.name
    entry = {"name": path.name, "path": rel, "size_bytes": 0,
             "is_macho": False, "cpu": None, "is64": None, "fat": False,
             "encrypted": None, "cryptid": None, "min_os": None,
             "linked_dylibs": [], "suspicious": [], "string_count": 0,
             "urls": [], "domains": [], "insecure_http_urls": [],
             "risk_points": 0, "severity": "info", "unavailable": None,
             "error": None, "tracker": None}
    try:
        entry["size_bytes"] = path.stat().st_size
    except Exception as e:
        entry["error"] = str(e)
        return entry
    macho = parse_macho_deep(path)
    entry.update({k: macho.get(k) for k in
                  ("is_macho", "cpu", "is64", "fat", "encrypted", "cryptid", "min_os",
                   "linked_dylibs", "uuid", "has_code_signature") if k in macho})
    if macho.get("error") and not macho.get("is_macho"):
        entry["error"] = macho["error"]
        entry["unavailable"] = "Mach-O نیست یا قابل خواندن نیست: " + str(macho["error"])
        return entry
    low = path.name.lower()
    for needle, label in KNOWN_TRACKERS.items():
        if needle in low:
            entry["tracker"] = label
            break
    if macho.get("encrypted") is True:
        entry["unavailable"] = "رمزگذاری‌شده (FairPlay) — تحلیل رشته‌ها و الگوهای باینری ممکن نیست"
        entry["severity"] = "info"
        return entry
    if macho.get("encrypted") is None and macho.get("cryptid") is None:
        entry["unavailable"] = "وضعیت رمزگذاری مشخص نشد — تحلیل رشته‌ها انجام نشد"
        return entry
    strings_result = scan_binary_strings(path)
    if strings_result.get("error"):
        entry["error"] = strings_result["error"]
        entry["unavailable"] = "خواندن رشته‌های باینری ناموفق بود: " + str(strings_result["error"])
        return entry
    entry["string_count"] = strings_result.get("string_count", 0)
    entry["urls"] = strings_result.get("urls", [])
    entry["domains"] = strings_result.get("domains", [])
    entry["insecure_http_urls"] = strings_result.get("insecure_http_urls", [])
    entry["suspicious"] = strings_result.get("suspicious", [])
    pts = sum(h.get("points", 0) for h in entry["suspicious"])
    if entry["tracker"]:
        pts += 5
    entry["risk_points"] = pts
    entry["severity"] = severity_for_points(pts)
    return entry


# ---------------- main scan ----------------
def scan_ipa(ipa_path, workdir):
    ipa_path = Path(ipa_path)
    if not ipa_path.is_file():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")
    result = {
        "file": str(ipa_path),
        "sha256": sha256_of(ipa_path),
        "size_bytes": ipa_path.stat().st_size,
        "scanner": "sibstar-ipa-scanner 3.0 (stdlib only)",
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
    result["sdk_info"] = parse_sdk_info(info)
    result["plist_security"] = parse_plist_security(info)

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
    exc_details = {}
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if isinstance(cfg, dict):
            exc_details[domain] = {
                "includes_subdomains": bool(cfg.get("NSIncludesSubdomains", False)),
                "allows_insecure_http": bool(cfg.get("NSExceptionAllowsInsecureHTTPLoads", False)),
                "requires_forward_secrecy": cfg.get("NSExceptionRequiresForwardSecrecy", True),
                "minimum_tls": cfg.get("NSExceptionMinimumTLSVersion"),
            }
    result["ats"] = {
        "allows_arbitrary_loads": bool(ats.get("NSAllowsArbitraryLoads", False)),
        "allows_local_networking": bool(ats.get("NSAllowsLocalNetworking", False)),
        "allows_arbitrary_loads_in_web_content": bool(ats.get("NSAllowsArbitraryLoadsInWebContent", False)),
        "allows_arbitrary_loads_for_media": bool(ats.get("NSAllowsArbitraryLoadsForMedia", False)),
        "exception_domains": sorted((ats.get("NSExceptionDomains") or {}).keys()),
        "exception_domain_details": exc_details,
        "raw": ats,
    }

    # Privacy manifest
    result["privacy_manifest"] = parse_xcprivacy(app_dir)

    # Frameworks / dylibs / extensions / size breakdown
    fw_dir = app_dir / "Frameworks"
    frameworks = sorted(p.name for p in fw_dir.glob("*.framework")) if fw_dir.is_dir() else []
    fw_size = sum(p.stat().st_size for p in fw_dir.rglob("*") if p.is_file()) if fw_dir.is_dir() else 0
    dylibs = sorted(p.name for p in app_dir.glob("*.dylib"))
    static_libs = sorted(p.name for p in app_dir.glob("*.a"))
    bundles = sorted(p.name for p in app_dir.glob("*.bundle"))
    extensions = sorted(p.name for p in app_dir.glob("PlugIns/*.appex")) if (app_dir / "PlugIns").is_dir() else []
    result["frameworks"] = frameworks
    result["dylibs"] = dylibs
    result["static_libs"] = static_libs
    result["bundles"] = bundles
    result["app_extensions"] = extensions
    result["framework_details"] = framework_details(app_dir, frameworks)
    result["size_breakdown"] = {
        "total_bytes": sum(p.stat().st_size for p in app_dir.rglob("*") if p.is_file()),
        "frameworks_bytes": fw_size,
        "framework_count": len(frameworks),
    }
    trackers = []
    for name in frameworks + dylibs + static_libs + bundles:
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
            prov_info = analyze_provisioning(parsed)
            if isinstance(parsed.get("Entitlements"), dict):
                ent.update(parsed["Entitlements"])
    result["provisioning"] = prov_info
    result["entitlements"] = ent
    result["entitlement_keys"] = sorted(ent.keys())
    result["entitlement_findings"] = analyze_entitlements(ent)

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

    # Embedded .dylib files — each analysed separately (never skipped silently)
    dylib_paths = sorted(p for p in app_dir.rglob("*.dylib") if p.is_file())[:50]
    dylib_analysis = [analyze_dylib(p, app_dir) for p in dylib_paths]
    result["dylib_analysis"] = dylib_analysis
    result["dylib_count"] = len(dylib_analysis)
    result["dylib_suspicious_count"] = sum(len(d.get("suspicious", [])) for d in dylib_analysis)

    # URLs / domains: bundle files + (decrypted) binary strings, merged
    urls, domains, http_urls = scan_bundle_files(app_dir)
    if bin_strings and not bin_strings.get("unavailable"):
        urls = sorted(set(urls) | set(bin_strings.get("urls", [])))
        domains = sorted(set(domains) | set(bin_strings.get("domains", [])))
        http_urls = sorted(set(http_urls) | set(bin_strings.get("insecure_http_urls", [])))
    for d in dylib_analysis:
        if not d.get("unavailable"):
            urls = sorted(set(urls) | set(d.get("urls", [])))
            domains = sorted(set(domains) | set(d.get("domains", [])))
            http_urls = sorted(set(http_urls) | set(d.get("insecure_http_urls", [])))
    result["urls"] = urls[:200]
    result["url_count"] = len(urls)
    result["domains"] = domains
    result["insecure_http_urls"] = http_urls
    pm_for_domains = result.get("privacy_manifest") or {}
    result["domain_analysis"] = analyze_domains(
        domains, http_urls, pm_for_domains.get("tracking_domains", []))

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
    for f in result.get("entitlement_findings", []):
        if f["points"] > 0 and f["key"] != "get-task-allow":
            add(f["points"], f"Entitlement حساس: {f['label_fa']} (`{f['key']}`)")
    if pm and not pm.get("error"):
        sensitive_types = [c for c in pm.get("collected_data_types", [])
                           if c.get("risk_points", 0) >= 8]
        if sensitive_types:
            add(8, "مانیفست داده‌ی حساس جمع می‌کند: " +
                "، ".join(c.get("sensitive") or c.get("type", "?") for c in sensitive_types[:4]))
    for domain_entry in result.get("domain_analysis", []):
        if domain_entry.get("is_tracker_domain"):
            add(3, f"دامنه ترکر/تبلیغات: {domain_entry['domain']}")
    insecure_exc = [d for d, cfg in result["ats"].get("exception_domain_details", {}).items()
                    if cfg.get("allows_insecure_http")]
    if insecure_exc:
        add(5, f"ATS برای این دامنه‌ها http ناامن را مجاز می‌کند: {', '.join(insecure_exc)}")
    plist_sec = result.get("plist_security", {})
    if plist_sec.get("background_location"):
        add(6, "حالت پس‌زمینه location فعال است — ردیابی موقعیت در پس‌زمینه")
    if plist_sec.get("file_sharing_enabled"):
        add(4, "UIFileSharingEnabled فعال است — فایل‌های برنامه از طریق iTunes قابل دسترسی‌اند")
    if plist_sec.get("bonjour_services"):
        add(3, f"سرویس‌های Bonjour (شبکه محلی): {', '.join(plist_sec['bonjour_services'][:4])}")
    if bin_strings and not bin_strings.get("unavailable"):
        for hit in bin_strings.get("suspicious", []):
            add(hit["points"], f"الگوی مشکوک در باینری: {hit['label_fa']} ({hit['matches']} مورد)")
    for d in dylib_analysis:
        for hit in d.get("suspicious", []):
            add(hit["points"], f"الگوی مشکوک در dylib {d['name']}: {hit['label_fa']} ({hit['matches']} مورد)")
        if d.get("tracker"):
            add(5, f"dylib ترکر: {d['name']} → {d['tracker']}")
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

    # ---- Per-finding severity list (v3) ----
    findings = []
    for b in breakdown:
        if b.get("points", 0) > 0:
            findings.append({"severity": severity_for_points(b["points"]),
                             "category": "risk", "title_fa": b["reason"],
                             "points": b["points"]})
    for d in dylib_analysis:
        if d.get("unavailable"):
            findings.append({"severity": "info", "category": "dylib",
                             "title_fa": f"dylib {d['name']}: {d['unavailable']}", "points": 0})
    if not (pm and not pm.get("error")) and result.get("privacy_manifest") is None:
        findings.append({"severity": "medium", "category": "privacy-manifest",
                         "title_fa": "مانیفست حریم خصوصی (PrivacyInfo.xcprivacy) در باندل نیست", "points": 0})
    if result.get("provisioning") and result["provisioning"].get("expired"):
        findings.append({"severity": "high", "category": "provisioning",
                         "title_fa": "پروفایل provisioning منقضی شده است", "points": 0})
    result["findings"] = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f["severity"]])

    # ---- Answers to the four privacy questions (Picsart-style) ----
    result["privacy_answers"] = build_privacy_answers(result)
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
    if r.get("privacy_answers"):
        L.append("## پاسخ به سؤال‌های حریم خصوصی")
        L.append("")
        for a in r["privacy_answers"]:
            L.append(f"### {a['question_fa']}")
            L.append(f"**پاسخ: {a['answer_fa']}**")
            for ev in a.get("evidence", []):
                L.append(f"- {ev}")
            for lim in a.get("limits", []):
                L.append(f"- ⚠️ محدودیت: {lim}")
            L.append("")
    if r.get("findings"):
        L.append("## یافته‌ها بر اساس شدت")
        sev_fa = {"critical": "بحرانی", "high": "بالا", "medium": "متوسط",
                  "low": "کم", "info": "اطلاعاتی"}
        for f in r["findings"]:
            L.append(f"- [{sev_fa.get(f['severity'], f['severity'])}] {f['title_fa']}"
                     + (f" (+{f['points']})" if f.get("points") else ""))
        L.append("")
    sdk = r.get("sdk_info", {})
    if any(sdk.values()):
        L.append("## نسخه SDK و ابزار ساخت")
        L.append(f"- SDK: {sdk.get('sdk_name') or '—'} (build {sdk.get('sdk_build') or '—'}) — پلتفرم: {sdk.get('platform_name') or '—'} {sdk.get('platform_version') or ''}")
        L.append(f"- Xcode: {sdk.get('xcode') or '—'} (build {sdk.get('xcode_build') or '—'}) — کامپایلر: {sdk.get('compiler') or '—'}")
        L.append("")
    ps = r.get("plist_security", {})
    if ps:
        L.append("## امنیت Info.plist (فراتر از دسترسی‌ها)")
        L.append(f"- حالت‌های پس‌زمینه: {', '.join(ps.get('background_modes', [])) or '—'}")
        L.append(f"- اشتراک فایل با iTunes (UIFileSharingEnabled): {ps.get('file_sharing_enabled')}")
        L.append(f"- باز کردن اسناد در جای خود: {ps.get('supports_opening_documents_in_place')}")
        L.append(f"- سرویس‌های Bonjour: {', '.join(ps.get('bonjour_services', [])) or '—'}")
        L.append(f"- قابلیت‌های دستگاه موردنیاز: {', '.join(ps.get('required_device_capabilities', [])) or '—'}")
        L.append(f"- رمزنگاری غیرمعاف (ITSAppUsesNonExemptEncryption): {ps.get('uses_non_exempt_encryption')}")
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
            sensitive = f" — داده حساس: {c['sensitive']}" if c.get("sensitive") else ""
            L.append(f"- داده: `{c['type']}` — متصل به هویت: {c['linked']}، ردیابی: {c['tracking']}، اهداف: {', '.join(c['purposes']) or '—'}{sensitive}")
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
    for d, cfg in (ats.get("exception_domain_details") or {}).items():
        L.append(f"  - `{d}`: زیر دامنه‌ها: {cfg.get('includes_subdomains')}، http ناامن: {cfg.get('allows_insecure_http')}، "
                 f"Forward Secrecy لازم: {cfg.get('requires_forward_secrecy')}، حداقل TLS: {cfg.get('minimum_tls') or '—'}")
    L.append("")
    L.append(f"## فریم‌ورک‌ها ({len(r.get('frameworks',[]))}) و ترکرها ({len(r.get('known_trackers',[]))})")
    for f in r.get("frameworks", []):
        L.append(f"- {f}")
    for t in r.get("known_trackers", []):
        L.append(f"- ⚠️ ترکر: {t['framework']} → {t['tracker']}")
    for fd in r.get("framework_details", []):
        L.append(f"- جزئیات فریم‌ورک `{fd['name']}`: bundle={fd.get('bundle_id') or '—'}، نسخه={fd.get('version') or '—'}، "
                 f"حجم={fd.get('size_bytes', 0):,} بایت، مانیفست حریم خصوصی خودش: {fd.get('has_privacy_manifest')}")
    if r.get("dylibs"):
        L.append(f"- dylibها: {', '.join(r['dylibs'])}")
    if r.get("static_libs"):
        L.append(f"- کتابخانه‌های استاتیک (.a): {', '.join(r['static_libs'])}")
    if r.get("bundles"):
        L.append(f"- باندل‌ها (.bundle): {', '.join(r['bundles'])}")
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
    L.append(f"## کتابخانه‌های داینامیک (.dylib) — {r.get('dylib_count', 0)} مورد")
    if not r.get("dylib_analysis"):
        L.append("- هیچ فایل .dylib در باندل پیدا نشد.")
    for d in r.get("dylib_analysis", []):
        L.append(f"### `{d['path']}` — {d.get('size_bytes', 0):,} بایت")
        if d.get("error") and not d.get("is_macho"):
            L.append(f"- ⚠️ قابل تحلیل نیست: {d['error']}")
            continue
        L.append(f"- نوع Mach-O: CPU {d.get('cpu') or '—'}، ۶۴ بیتی: {d.get('is64')}، FAT: {d.get('fat')}")
        L.append(f"- رمزگذاری‌شده: {d.get('encrypted')} (cryptid={d.get('cryptid')}) — حداقل iOS: {d.get('min_os') or '—'}")
        if d.get("linked_dylibs"):
            L.append(f"- کتابخانه‌های لینک‌شده: {', '.join(d['linked_dylibs'][:10])}")
        if d.get("tracker"):
            L.append(f"- ⚠️ ترکر: {d['tracker']}")
        if d.get("unavailable"):
            L.append(f"- ⚠️ در دسترس نیست: {d['unavailable']}")
        else:
            L.append(f"- رشته‌های قابل خواندن: {d.get('string_count', 0)} — ریسک: {d.get('risk_points', 0)} ({d.get('severity')})")
            for h in d.get("suspicious", []):
                L.append(f"  - ⚠️ {h['label_fa']} ({h['label_en']}) — {h['matches']} مورد — (+{h['points']})")
            if not d.get("suspicious"):
                L.append("  - هیچ الگوی مشکوک شناخته‌شده‌ای پیدا نشد.")
    L.append("")
    L.append(f"## URL Schemes: {', '.join(r.get('url_schemes', [])) or '—'}")
    L.append(f"## دامنه‌ها ({len(r.get('domains',[]))}) و URLها ({r.get('url_count',0)})")
    for d in r.get("domain_analysis", [])[:50]:
        flags = []
        if d.get("is_tracker_domain"):
            flags.append("ترکر/تبلیغات")
        if d.get("in_tracking_manifest"):
            flags.append("در مانیفست ردیابی")
        if d.get("http_only"):
            flags.append("فقط http")
        if d.get("is_ip_literal"):
            flags.append("IP مستقیم")
        L.append(f"- {d['domain']}" + (f" — {', '.join(flags)} (ریسک {d['risk_points']}, {d['severity']})" if flags else ""))
    if not r.get("domain_analysis"):
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
    if r.get("entitlement_findings"):
        L.append("")
        L.append("### یافته‌های Entitlement (با شدت)")
        sev_fa = {"critical": "بحرانی", "high": "بالا", "medium": "متوسط",
                  "low": "کم", "info": "اطلاعاتی"}
        for f in r["entitlement_findings"]:
            L.append(f"- [{sev_fa.get(f['severity'], f['severity'])}] {f['label_fa']} — `{f['key']}`: {f['value']}"
                     + (f" (+{f['points']})" if f.get("points") else ""))
    if not r.get("entitlement_keys"):
        L.append("- هیچ فایل entitlements / mobileprovision خوانایی پیدا نشد.")
    if r.get("provisioning"):
        prov = r["provisioning"]
        L.append(f"- Provisioning: {prov.get('name')} — تیم: {prov.get('team')} — نوع: {prov.get('profile_type')} — "
                 f"انقضا: {prov.get('expiration_date')}" +
                 (f" (منقضی شده!)" if prov.get("expired") else
                  (f" ({prov.get('days_until_expiry')} روز مانده)" if prov.get("days_until_expiry") is not None else "")))
    L.append("")
    if r.get("errors"):
        L.append("## خطاها")
        for e in r["errors"]:
            L.append(f"- {e}")
    return "\n".join(L) + "\n"

def main(argv=None):
    ap = argparse.ArgumentParser(description="SibStar IPA scanner v3 (deep scan)")
    ap.add_argument("ipa", help="Path to .ipa file")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--report", dest="report_out", default=None)
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args(argv)
    workdir = args.workdir or tempfile.mkdtemp(prefix="ipa-scan-v3-")
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
