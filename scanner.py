#!/usr/bin/env python3
"""
SibStar IPA Scanner v6 — deep scan (stdlib only, no paid dependencies)
Scans an iOS .ipa (ZIP containing Payload/*.app) WITHOUT decryption:

  v6 vs v5:
  - Calibration: a clean legit app must score LOW. Trackers are now
    2 points each (cap 6, was 5 each / cap 10) — Firebase in a normal
    app is not a threat on its own. The privacy-manifest lines no
    longer triple-count the same tracking fact (tracking 3, tracking
    domains 2, tracking types 3, linked types 2). ATS arbitrary loads
    10 -> 6. Code cap 12 -> 15 so a hardcoded secret is never starved
    out by the cap. Maximum possible score is now 90, never a lazy 100.
  - Capped findings are no longer silently hidden: when a category cap
    is full, the finding still appears in the breakdown with 0 points
    and a note that the category cap was reached — the breakdown stays
    complete and honest.
  - Privacy answers are now exactly 3 short plain-Persian lines each:
    one short answer, one evidence line, one limit line. No jargon,
    no raw manifest constants in the answer text, no repeated warnings.
  - Report restructured: the first screen shows the verdict, the risk
    with its split, the tampering verdict and the privacy answers;
    file hashes and technical detail moved below. Redundant sections
    removed (the findings list duplicated the breakdown; the
    jailbreak-artifact section duplicated the tampering evidence).
  - "associated-domains" entitlement is a normal capability, not a
    risk: 0 points, low severity.

  v5 vs v4:
  - Evidence verdicts: privacy answers use confirmed / no-evidence /
    capability only. Capability (photo permission + analytics servers)
    is NEVER reported as "yes" — it is not proof photos are sent.
  - Generic iOS APIs (ASIdentifierManager, IDFA/IDFV, PhotoKit, Speech)
    score 0 and are listed as info, never as suspicious patterns.
  - No double counting: an injected dylib's patterns are counted ONCE
    inside the single tampering line; the risk breakdown sums exactly
    to the total score.
  - Binary protections: Stack Canary / ARC are reported as "unknown"
    when the symbol table cannot prove them (they are on by default
    in iOS release builds) — never as "missing", never scored.
  - No duplicated sections: the tampering verdict appears once as a
    full section; the privacy answer for it is a 2-line summary with
    a pointer to that section.
  - Calm scoring kept (per-category caps, max 87).

  v4 vs v3:
  - False positives fixed: XML/XMP/SVG namespace URLs (ns.adobe.com,
    w3.org, purl.org, iec.ch, videolan.org, …) and documentation domains
    (github.com, docs.github.com, developer.android.com, reactjs.org,
    slack.com, t.me, …) are NO LONGER counted as network domains or
    insecure http endpoints. They are listed separately as ignored
    namespace/docs strings and never add risk. Only real network http
    endpoints count. Junk hosts such as "$" are rejected as invalid.
  - Third-party tampering verdict: a dedicated "دستکاری شخص ثالث / تویک"
    section. Injected dylibs are detected by their MobileSubstrate
    install name (/Library/MobileSubstrate/DynamicLibraries/…), reported
    separately with per-dylib domains/URLs, and the verdict says whether
    a tweak dylib talks to an unknown server — or explicitly that none
    was found in static strings, with the static-vs-runtime limit.
  - .deb analysis: any .deb inside the IPA is extracted and analysed
    separately (control metadata, contained files, install scripts).
  - Risk is split: original app vs injected tweak (dylib/.deb), so a
    100/100 shows which part is the tweak.
  - Privacy answers are decisive where the evidence allows it, with
    evidence per answer and honest limits (static vs runtime traffic).

  Standards the method follows (learned from public sources, methods
  only — no text copied):
  - MobSF iOS binary scan: permissions, signing certificate, ATS
    config, Mach-O binary protections (PIE, stack canary, ARC),
    hardcoded secrets in plists/strings, tracker inventory.
  - OWASP MASVS / MASTG: findings are mapped to MASVS categories
    (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE,
    PRIVACY); the standard's own warning is honoured — automated
    static analysis is assistive, not conclusive, and its output can
    contain both false positives and false negatives. Every finding
    therefore carries a confidence level, and what only dynamic
    analysis can prove (real traffic, certificate pinning behaviour,
    server-side auth) is listed as a limit, never claimed.
  - iOS static-assessment practice: hash the artifact first, read
    identity/signature/entitlements before code, check the encryption
    state (cryptid) before planning any deeper read, compare what the
    provisioning profile grants with what the entitlements claim, and
    treat findings on a development/ad-hoc build as build-configuration
    findings, not properties of the distributed app.
  - Jailbreak/tweak detection practice: an injected dylib is found by
    enumerating loaded libraries (dyld image names) and comparing
    them with the legitimate set — statically, that means the
    dylib's install name and the presence of MobileSubstrate /
    CydiaSubstrate / Frida artifacts in the bundle.

Cannot do on an encrypted App Store IPA: binary strings / API-pattern
analysis needs a decrypted IPA. FairPlay encryption is detected (cryptid)
and reported explicitly; that section is marked "unavailable", never faked.

Usage:
  python3 scanner.py app.ipa [--json out.json] [--report out.md]
"""
import argparse, hashlib, io, json, plistlib, re, struct, sys, tarfile, tempfile, zipfile
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
    (r"CLLocationManager", "مدیر موقعیت مکانی", "CLLocationManager", 5),
    (r"CNContactStore|CNContactFetchRequest", "دسترسی به مخاطبین در کد", "Contacts store access in code", 6),
    (r"AVCaptureDevice|AVCaptureSession", "دسترسی به دوربین در کد", "Camera capture in code", 5),
    (r"UIPasteboard|generalPasteboard", "دسترسی به کلیپ‌بورد", "Pasteboard access", 6),
    (r"SecItemCopyMatching|SecItemAdd", "دسترسی به کی‌چین", "Keychain access", 4),
    (r"sysctlbyname|sysctl\(", "خواندن اطلاعات سیستم (sysctl)", "sysctl system info", 4),
    (r"dlopen|dlsym", "بارگذاری داینامیک کد (dlopen/dlsym)", "Dynamic loading (dlopen/dlsym)", 7),
    (r"IOKit|IOServiceGetMatchingServices", "دسترسی سطح پایین سخت‌افزار (IOKit)", "Low-level hardware access (IOKit)", 5),
    (r"CTCarrier|CTTelephonyNetworkInfo", "اطلاعات اپراتور سیم‌کارت", "Carrier info", 4),
    (r"requestTrackingAuthorization", "درخواست مجوز ردیابی (ATT)", "ATT tracking authorization request", 3),
    (r"ABAddressBookCreate|ABAddressBookRequestAccess", "دسترسی به مخاطبین با API قدیمی", "Legacy AddressBook access", 6),
    (r"HKHealthStore", "دسترسی به سلامت در کد (HealthKit)", "HealthKit access in code", 6),
    (r"EKEventStore", "دسترسی به تقویم در کد (EventKit)", "EventKit access in code", 5),
    (r"CBCentralManager|CBPeripheralManager", "اسکن بلوتوث در کد", "Bluetooth scanning in code", 5),
    (r"NFCNDEFReaderSession|NFCTagReaderSession", "خواندن NFC در کد", "NFC reading in code", 5),
    (r"LAContext", "احراز هویت بیومتریک در کد (Face ID / Touch ID)", "Biometric auth in code", 3),
    (r"ASWebAuthenticationSession", "ورود وب و اشتراک کوکی (ASWebAuthenticationSession)", "Web auth session", 4),
    (r"AVAudioRecorder|AVAudioSession", "ضبط صدا / میکروفون در کد", "Audio recording in code", 6),
    (r"CMMotionManager|CMSensorRecorder", "سنسور حرکتی در کد", "Motion sensors in code", 4),
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

# Generic iOS APIs (v5): used by thousands of legitimate apps — calling
# them is normal, not suspicious. They are reported as info with 0 points
# and never enter the suspicious list, the risk score, or the findings.
# (regex, Persian label, English label)
GENERIC_API_PATTERNS = [
    (r"ASIdentifierManager", "مدیر شناسه تبلیغاتی اپل", "ASIdentifierManager"),
    (r"advertisingIdentifier", "شناسه تبلیغاتی (IDFA)", "advertisingIdentifier (IDFA)"),
    (r"identifierForVendor", "شناسه فروشنده (IDFV)", "identifierForVendor (IDFV)"),
    (r"PHPhotoLibrary|PHAsset", "دسترسی به گالری در کد (PhotoKit)", "PhotoKit access in code"),
    (r"SFSpeechRecognizer", "تشخیص گفتار در کد", "Speech recognition in code"),
]

# Weak-crypto patterns (MobSF-style SAST rules, static strings only).
# Presence in strings does NOT prove the code path is reachable — these
# are low-severity notes, never a verdict on their own.
WEAK_CRYPTO_PATTERNS = [
    (r"\bCC_MD5\b", "رمزنگاری ضعیف MD5 در کد", "Weak crypto: MD5", 3),
    (r"\bCC_SHA1\b", "رمزنگاری ضعیف SHA1 در کد", "Weak crypto: SHA1", 3),
    (r"kCCAlgorithmDES\b", "رمزنگاری DES در کد", "Weak crypto: DES", 4),
    (r"kCCOptionECBMode\b", "حالت ECB در رمزنگاری (بدون IV)", "Weak crypto: ECB mode", 4),
    (r"\bCCCrypt\b", "استفاده از CommonCrypto (CCCrypt) در کد", "CommonCrypto use", 1),
]

# Hardcoded-secret patterns (MobSF-style secret discovery). Only
# well-known token prefixes and private-key markers are flagged, to
# keep false positives low. Values are NEVER stored or printed — only
# the secret type, the file it was found in, and a masked preview.
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "کلید دسترسی AWS", "AWS access key"),
    (r"ghp_[A-Za-z0-9]{20,}", "توکن شخصی گیت‌هاب", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "توکن گیت‌هاب (fine-grained)", "GitHub fine-grained token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "توکن Slack", "Slack token"),
    (r"sk_live_[A-Za-z0-9]{10,}", "کلید زنده Stripe", "Stripe live secret key"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "کلید خصوصی در باندل", "Private key in bundle"),
]

# File paths that only exist on a jailbroken device / with substrate
# injection. Found in strings, they are tampering evidence (dyld-image
# enumeration is the runtime equivalent of this check).
JAILBREAK_PATH_MARKERS = [
    "/Library/MobileSubstrate/",
    "CydiaSubstrate",
    "FridaGadget",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/private/var/lib/apt",
    "/usr/sbin/sshd",
    "DYLD_INSERT_LIBRARIES",
]

# MASVS category per risk category (OWASP MASVS 2.x).
MASVS_BY_CATEGORY = {
    "network": "MASVS-NETWORK",
    "permissions": "MASVS-PLATFORM",
    "privacy": "MASVS-PRIVACY",
    "code": "MASVS-CODE",
    "tweak": "MASVS-RESILIENCE",
}
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
    "com.apple.developer.associated-domains": ("دامنه‌های مرتبط (Universal Links)", "low", 0),
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
    "com.apple.security.application-groups": ("گروه اپلیکیشن (اشتراک داده بین برنامه‌ها)", "low", 0),
    "com.apple.developer.kernel.extended-virtual-addressing": ("آدرس‌دهی مجازی گسترده کرنل", "medium", 3),
    "com.apple.developer.playable-content": ("محتوای قابل پخش", "info", 0),
    "com.apple.developer.usernotifications.filtering": ("فیلتر نوتیفیکیشن", "low", 0),
}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# --- URL classification (v4 false-positive fix) ---------------------------
# These hosts/paths are XML/XMP/SVG *namespaces* or documentation strings
# embedded in files — they are identifiers, not network endpoints the app
# calls. Counting them as "domains" or "insecure http" inflated the risk
# (e.g. the PDF Hero report listed ns.adobe.com, w3.org, purl.org,
# iec.ch, videolan.org and 18 "insecure http" namespace URLs).
NAMESPACE_HOSTS = {
    "ns.adobe.com", "www.w3.org", "w3.org", "purl.org", "www.purl.org",
    "www.iec.ch", "iec.ch", "www.videolan.org", "videolan.org",
    "schemas.xmlsoap.org", "schemas.microsoft.com",
    "www.w3schools.com", "www.w3.org",
}
NAMESPACE_PATH_PREFIXES = (
    "/1998/", "/1999/", "/2000/", "/2001/", "/XML/", "/Graphics/",
    "/dc/", "/xap/", "/pdf/", "/sType/", "/xmp/", "/svg",
    "/1999/02/22-rdf-syntax-ns", "/2000/svg",
)
# Documentation / company-homepage hosts: strings found in frameworks,
# privacy bundles and docs, not API endpoints the app calls at runtime.
# (github.com, api.github.com, docs.github.com, git.io,
# developer.android.com, reactjs.org, slack.com, t.me, www.adobe.com …)
DOCS_HOSTS = {
    "github.com", "api.github.com", "docs.github.com", "git.io",
    "developer.android.com", "developer.apple.com", "www.apple.com",
    "reactjs.org", "slack.com", "t.me", "telegram.org",
    "stackoverflow.com", "www.adobe.com", "adobe.com",
    "www.bendingspoons.com", "bendingspoons.com",
}
VALID_HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def classify_url(url):
    """Classify an embedded URL string.

    Returns one of: "network" (a real network endpoint),
    "namespace" (XML/XMP/SVG namespace identifier),
    "docs" (documentation / homepage string, not an API call),
    "invalid" (not a usable host at all, e.g. "$").
    """
    try:
        host = (urlparse(url).hostname or "").lower()
        path = urlparse(url).path or ""
    except Exception:
        return "invalid"
    if not host or not VALID_HOST_RE.match(host):
        return "invalid"
    if host in NAMESPACE_HOSTS:
        return "namespace"
    if any(path.startswith(p) for p in NAMESPACE_PATH_PREFIXES):
        return "namespace"
    if host in DOCS_HOSTS:
        return "docs"
    return "network"


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


# Evidence levels for privacy answers (v5): static analysis can only ever
# show capability + endpoints, never the actual runtime traffic. So every
# answer uses one of three honest verdicts:
#   "confirmed"   — direct evidence in the artifact (e.g. a manifest
#                   declaration, an injected dylib present in the bundle)
#   "no-evidence" — no evidence of it in static analysis
#   "capability"  — the capability exists (permission / same-process
#                   code), but sending/seeing it is NOT proven
# Answering "بله" on capability alone is forbidden: having photo
# permission and talking to analytics servers is NOT proof photos are sent.

_UPLOAD_DOMAIN_KEYWORDS = ("upload", "photo", "image", "storage", "s3.",
                           "blob.", "drive.", "dropbox", "icloud",
                           "cloudinary", "firebasestorage")


def _photo_upload_domains(domains):
    """Domains that look like a photo/file upload or cloud-storage
    endpoint. Analytics / OTA / logging domains are NOT upload
    endpoints — they do not count as evidence photos are sent."""
    out = []
    for d in (domains or []):
        low = d.lower()
        if any(k in low for k in _UPLOAD_DOMAIN_KEYWORDS):
            out.append(d)
    return out


def _plain_data_kind(dtype):
    """Plain-Persian name for a manifest collected-data type (no raw
    NSPrivacyCollectedDataType constants in user-facing answer text)."""
    kinds = {
        "NSPrivacyCollectedDataTypePhotosorVideos": "عکس و ویدیو",
        "NSPrivacyCollectedDataTypeOtherUserContent": "محتوای دیگر شما",
        "NSPrivacyCollectedDataTypeAudioData": "صدا",
        "NSPrivacyCollectedDataTypePreciseLocation": "موقعیت دقیق",
        "NSPrivacyCollectedDataTypeCoarseLocation": "موقعیت تقریبی",
        "NSPrivacyCollectedDataTypeContacts": "مخاطبین",
        "NSPrivacyCollectedDataTypeHealth": "داده سلامت",
        "NSPrivacyCollectedDataTypePaymentInfo": "اطلاعات پرداخت",
        "NSPrivacyCollectedDataTypeEmailsorTextMessages": "ایمیل یا پیامک",
    }
    return kinds.get(dtype, "داده کاربر")


def build_privacy_answers(r):
    """Answer the privacy questions for this IPA, in Persian.

    Each answer has exactly three short plain-Persian lines:
    a short answer, ONE evidence line and ONE limit line. No jargon,
    no raw manifest constants in the answer text, no repeated warnings.
    The tampering answer is a short summary — the full tampering
    section lives elsewhere in the report and is never copy-pasted here.
    """
    perms = {p["key"] for p in r.get("permissions", [])}
    pm = r.get("privacy_manifest") or {}
    domains = r.get("domains", [])
    trackers = r.get("known_trackers", [])
    encrypted = r.get("binary", {}).get("encrypted") is True
    tamp = r.get("tampering") or {}
    photo_perm = bool(perms & {"NSPhotoLibraryUsageDescription",
                               "NSPhotoLibraryAddUsageDescription"})
    upload_domains = _photo_upload_domains(domains)

    # ---- Q5 first (the user's main question): tampering ----
    if tamp.get("tampered"):
        q5_verdict = "confirmed"
        q5_short = (f"تأیید شد — {tamp.get('injected_dylib_count', 0)} dylib تزریقی "
                     "(MobileSubstrate) در باندل است")
    else:
        q5_verdict = "no-evidence"
        q5_short = "شواهدی از دستکاری پیدا نشد"
    q5_evidence = [tamp.get("server_note_fa", "")]
    q5_limits = ["این بررسی فقط فایل‌های برنامه را می‌بیند؛ اینکه توئیک واقعاً "
                 "چه داده‌ای می‌فرستد، فقط با رصد ترافیک زمان اجرا معلوم می‌شود."]

    # ---- Q1: does it send photos/files to a server or cloud? ----
    # A photo-upload endpoint is required even for "capability": photo
    # permission + analytics servers (adjust-skadnetwork, firebaselogging,
    # lokalise OTA, firebaseio) is NOT evidence of photo upload.
    if upload_domains:
        q1_verdict = "capability"
        q1_short = ("فقط توانایی دارد — نقطه‌ی آپلود عکس هست، "
                     "ولی ارسال واقعی عکس اثبات نشده است")
        q1_evidence = [f"یک نقطه‌ی آپلود/ذخیره‌ی ابری پیدا شد "
                       f"({', '.join(upload_domains)})؛ ولی اینکه واقعاً عکسی "
                       "فرستاده شده باشد، اثبات نشده است."]
    else:
        q1_verdict = "no-evidence"
        q1_short = "شواهدی نیست — مدرکی از ارسال عکس به سرور پیدا نشد"
        if photo_perm and domains:
            q1_evidence = ["دسترسی به گالری عکس اعلام شده است، ولی هیچ‌کدام از "
                           f"{len(domains)} سروری که برنامه با آن‌ها حرف می‌زند "
                           "جای آپلود عکس نیست."]
        elif photo_perm:
            q1_evidence = ["دسترسی به گالری عکس اعلام شده است، ولی هیچ سروری "
                           "در باندل پیدا نشد."]
        elif domains:
            q1_evidence = ["دسترسی به گالری عکس اعلام نشده است و هیچ نقطه‌ی "
                           "آپلودی پیدا نشد."]
        else:
            q1_evidence = ["دسترسی به گالری عکس اعلام نشده است و هیچ سروری "
                           "در باندل پیدا نشد."]
    q1_limits = ["اینکه واقعاً چه فایلی و چه زمانی فرستاده می‌شود، فقط با رصد "
                 "ترافیک زمان اجرا معلوم می‌شود."]

    # ---- Q2: could the mod maker / a third party see user photos/videos? ----
    # A tweak runs inside the app process, so it can technically reach
    # what the app reaches — that is capability, never proof of seeing.
    if tamp.get("tampered"):
        q2_verdict = "capability"
        q2_short = ("فقط توانایی دارد — توئیک در همان پروسس برنامه اجرا می‌شود و "
                     "از نظر فنی به عکس‌ها دسترسی دارد، ولی دیدن یا دریافت "
                     "آن‌ها اثبات نشده است")
        unknown = tamp.get("unknown_tweak_servers") or []
        if unknown:
            q2_evidence = [f"توئیک در همان پروسس برنامه اجرا می‌شود و با این سرور "
                           f"ناشناخته حرف می‌زند: {', '.join(unknown)}؛ ولی اینکه "
                           "واقعاً عکسی فرستاده باشد، اثبات نشده است."]
        else:
            q2_evidence = ["توئیک در همان پروسس برنامه اجرا می‌شود و از نظر فنی "
                           "به عکس‌ها دسترسی دارد، ولی سروری برای ارسال آن‌ها "
                           "پیدا نشد."]
    elif trackers:
        q2_verdict = "capability"
        q2_short = ("فقط توانایی دارد — ترکرها داده می‌فرستند، ولی دیدن عکس "
                     "اثبات نشده است")
        q2_evidence = ["ترکرهایی مثل "
                       + "، ".join(t["tracker"] for t in trackers[:3])
                       + " در برنامه‌اند؛ آن‌ها رویداد و شناسه می‌فرستند، نه عکس."]
    else:
        q2_verdict = "no-evidence"
        q2_short = "شواهدی نیست"
        q2_evidence = ["نه دستکاری تأیید شد، نه ترکر/SDK شناخته‌شده‌ای پیدا شد."]
    if encrypted:
        q2_evidence = [q2_evidence[0] + " باینری رمزگذاری‌شده است؛ الگوهای "
                       "باینری اصلی بررسی نشد."]
    q2_limits = ["اینکه توئیک یا ترکر واقعاً چه دیده، فقط با رصد ترافیک زمان "
                 "اجرا معلوم می‌شود."]

    # ---- Q3: does it collect user photo/file info? ----
    # A manifest declaration IS direct evidence of declared collection.
    collected = pm.get("collected_data_types", []) if isinstance(pm, dict) else []
    photo_types = [c for c in collected
                   if (c.get("type") or "") in ("NSPrivacyCollectedDataTypePhotosorVideos",
                                                "NSPrivacyCollectedDataTypeOtherUserContent",
                                                "NSPrivacyCollectedDataTypeAudioData")]
    analytics = [t["tracker"] for t in trackers
                 if any(k in t["tracker"].lower() for k in
                        ("firebase", "amplitude", "mixpanel", "flurry", "segment",
                         "appsflyer", "adjust", "countly", "matomo", "heap", "pendo"))]
    if photo_types:
        kinds = "، ".join(_plain_data_kind(c.get("type")) for c in photo_types[:2])
        linked = any(c.get("linked") for c in photo_types)
        tracking = any(c.get("tracking") for c in photo_types)
        if linked and tracking:
            how = "و آن را به هویت شما وصل می‌کند و برای ردیابی استفاده می‌کند"
        elif linked:
            how = "و آن را به هویت شما وصل می‌کند"
        elif tracking:
            how = "و برای ردیابی استفاده می‌کند"
        else:
            how = "بدون اتصال به هویت و بدون ردیابی، فقط برای کارکرد برنامه"
        q3_verdict = "confirmed"
        q3_short = "تأیید شد — در مانیفست اعلام شده است"
        q3_evidence = [f"سازنده در مانیفست اعلام کرده «{kinds}» جمع می‌کند، {how}."]
    elif collected or analytics:
        q3_verdict = "capability"
        q3_short = "فقط توانایی دارد — داده جمع می‌شود، ولی جمع‌آوری عکس اعلام نشده است"
        if analytics:
            q3_evidence = [f"مانیفست {len(collected)} نوع داده اعلام می‌کند، ولی "
                           "«عکس/ویدیو» در آن نیست؛ ترکرهای تحلیلی در برنامه‌اند و "
                           "رویداد و شناسه می‌فرستند، نه عکس."]
        else:
            q3_evidence = [f"مانیفست {len(collected)} نوع داده اعلام می‌کند، ولی "
                           "«عکس/ویدیو» در آن نیست."]
    else:
        q3_verdict = "no-evidence"
        q3_short = "شواهدی نیست — جمع‌آوری عکس اعلام نشده است"
        q3_evidence = ["مانیفست حریم خصوصی هیچ نوع داده‌ی جمع‌آوری‌شده‌ای اعلام "
                       "نکرده است."]
    q3_limits = ["مانیفست فقط چیزی را نشان می‌دهد که سازنده اعلام کرده است؛ "
                 "جمع‌آوری اعلام‌نشده با این اسکن قابل رد نیست."]

    # ---- Q4: clear verdict — what was verified, what could not be verified ----
    # v5: the final verdict follows the risk SCORE, not the tampering
    # flag alone — otherwise a medium-score app with a confirmed tweak
    # would show "بالا" next to a "متوسط" score. The tampering fact is
    # still in the text; only the verdict level follows the score.
    _score = r.get("risk", {}).get("score", 0)
    q4_evidence = [f"اسکن ایستا کامل شد؛ امضا، مانیفست، دامنه‌ها و باینری بررسی "
                   f"شد و ریسک {_score} از 100 شد."]
    if tamp.get("tampered"):
        q4_evidence = [q4_evidence[0] +
                       f" دستکاری شخص ثالث تأیید شد: {tamp.get('injected_dylib_count', 0)} "
                       "dylib تزریقی."]
    if encrypted:
        q4_evidence = [q4_evidence[0] +
                       " باینری رمزگذاری‌شده است (FairPlay)؛ تحلیل رشته‌ها انجام نشد."]
    q4_limits = ["ترافیک واقعی شبکه و اینکه سازنده‌ی ماد واقعاً چه می‌بیند، فقط با "
                 "رصد ترافیک زمان اجرا مشخص می‌شود."]
    if encrypted and not tamp.get("tampered"):
        q4_verdict, q4_short = "partial", "بررسی ناقص — باینری رمزگذاری‌شده است"
    elif _score >= 60:
        q4_verdict, q4_short = ("risky",
            "دستکاری شخص ثالث تأیید شد؛ با احتیاط استفاده کنید"
            if tamp.get("tampered") else
            "چند نشانه‌ی واقعی دارد؛ با احتیاط استفاده کنید")
    elif _score >= 30:
        q4_verdict, q4_short = ("caution",
            "دستکاری شخص ثالث تأیید شد؛ با احتیاط استفاده کنید"
            if tamp.get("tampered") else
            "چند نکته‌ی حریم خصوصی دارد، جای نگرانی جدی نیست")
    else:
        q4_verdict, q4_short = "ok", "نشانه‌ی جدی پیدا نشد"

    return [
        {"id": "tampering",
         "question_fa": "آیا این نسخه (توئیک) غیر از شرکت اصلی، توسط شخص ثالث دستکاری شده تا داده به خودش برسد؟",
         "verdict": q5_verdict, "answer_fa": q5_short,
         "evidence": q5_evidence, "limits": q5_limits},
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
         "evidence": q4_evidence, "limits": q4_limits},
    ]



URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
ASCII_STR_RE = re.compile(rb"[ -~]{4,}")
UTF16_STR_RE = re.compile(rb"(?:[ -~]\x00){4,}")
# Apple DTD is a known false positive inside mobileprovision — never count it.
APPLE_DTD_HOST = "www.apple.com"

def hashes_of(path):
    """SHA-256 + MD5 + SHA-1 of the artifact (MobSF/iOS static practice:
    record the hashes alongside bundle id/version before any analysis)."""
    out = {"sha256": hashlib.sha256(), "md5": hashlib.md5(),
           "sha1": hashlib.sha1()}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in out.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in out.items()}

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
            cputype, cpusubtype, _ft, ncmds, sizeofcmds, flags, _res = struct.unpack(
                fmt + "IIIIIII", data[off + 4:off + 32])
            cmd_off = off + 32
        else:
            # 32-bit header after magic: 6 x uint32 = 24 bytes
            cputype, cpusubtype, _ft, ncmds, sizeofcmds, flags = struct.unpack(
                fmt + "IIIIII", data[off + 4:off + 28])
            cmd_off = off + 28
    except Exception as e:
        return {"is_macho": True, "error": str(e)}
    out = {"is_macho": True, "is64": bool(is64),
           "cpu": CPU_TYPES.get(cputype, f"0x{cputype:08x}"),
           "filetype": _ft, "flags": flags,
           # MH_PIE (0x200000): position-independent executable.
           "pie": bool(flags & 0x200000),
           "cryptid": None, "encrypted": None,
           "linked_dylibs": [], "rpaths": [], "min_os": None,
           "uuid": None, "has_code_signature": False, "has_main": False,
           "load_commands": [], "platform": None, "symtab": None}
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
            elif cmd == 0x2:  # LC_SYMTAB: symoff, nsyms, stroff, strsize
                symoff, nsyms, stroff, strsize = struct.unpack(
                    fmt + "IIII", data[cur + 8:cur + 24])
                out["symtab"] = {"symoff": symoff, "nsyms": nsyms,
                                 "stroff": stroff, "strsize": strsize,
                                 "fmt": fmt, "slice_off": base_off}
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
    """Only call when NOT encrypted. Returns URLs/domains + suspicious hits.

    v4: only *network* URLs are counted. Namespace/docs/invalid URL
    strings are returned separately in "ignored_urls" with their reason
    and never add risk.
    """
    try:
        data = exe_path.read_bytes()[:max_bytes]
    except Exception as e:
        return {"error": str(e)}
    urls, domains, http_urls, ignored = set(), set(), set(), []
    for m in URL_RE.finditer(data):
        u = m.group(0).decode("ascii", "ignore").rstrip(".,);\"'")
        kind = classify_url(u)
        if kind != "network":
            ignored.append({"url": u, "reason": kind})
            continue
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
    # Generic iOS APIs (v5): counted separately, 0 points, never suspicious.
    generic = []
    for pat, fa, en in GENERIC_API_PATTERNS:
        rx = re.compile(pat)
        count = sum(1 for s in strings if rx.search(s))
        if count:
            generic.append({"pattern": pat, "label_fa": fa, "label_en": en,
                            "points": 0, "matches": count})
    return {"string_count": len(strings), "urls": sorted(urls),
            "domains": sorted(domains), "insecure_http_urls": sorted(http_urls),
            "ignored_urls": ignored, "suspicious": hits, "generic_apis": generic}

def scan_bundle_files(app_dir):
    """URLs/domains from all small files inside .app (plists, json, configs).
    Apple DTD host is excluded from the insecure list (v1 false positive).
    v4: only *network* URLs are counted; namespace/docs/invalid strings
    go to the ignored list and never add risk."""
    urls, domains, http_urls = set(), set(), set()
    ignored = []
    for p in sorted(app_dir.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        # v4: .dylib files are analysed separately per-dylib (analyze_dylib)
        # and their URLs are merged afterwards. Scanning them here too
        # would leak a tweak dylib's servers into the "original app"
        # domain set — exactly the bug that hid tweak-evil.example.com
        # in the PDF Hero scan's tampering verdict.
        if p.suffix == ".dylib":
            continue
        try:
            if p.stat().st_size > MAX_SCAN_BYTES:
                continue
            data = p.read_bytes()
        except Exception:
            continue
        for m in URL_RE.finditer(data):
            u = m.group(0).decode("ascii", "ignore").rstrip(".,);\"'")
            kind = classify_url(u)
            if kind != "network":
                ignored.append({"url": u, "reason": kind,
                                "file": str(p.relative_to(app_dir))})
                continue
            urls.add(u)
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
            if u.startswith("http://") and host != APPLE_DTD_HOST:
                http_urls.add(u)
    return sorted(urls), sorted(domains), sorted(http_urls), ignored

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
             "generic_apis": [],
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
    entry["generic_apis"] = strings_result.get("generic_apis", [])
    entry["urls"] = strings_result.get("urls", [])
    entry["domains"] = strings_result.get("domains", [])
    entry["insecure_http_urls"] = strings_result.get("insecure_http_urls", [])
    hits = strings_result.get("suspicious", [])
    # v4: dlopen/dlsym inside Swift stdlib dylibs (libswift_*.dylib) is
    # normal Swift-runtime behaviour, not a suspicious signal — the
    # PDF Hero report wrongly flagged libswift_Concurrency.dylib for it.
    if path.name.lower().startswith("libswift"):
        hits = [h for h in hits if h.get("pattern") != r"dlopen|dlsym"]
    entry["suspicious"] = hits
    pts = sum(h.get("points", 0) for h in entry["suspicious"])
    if entry["tracker"]:
        pts += 5
    entry["risk_points"] = pts
    entry["severity"] = severity_for_points(pts)
    return entry


# ---------------- MobSF-style checks (binary protections, secrets,
# weak crypto, runtime family, app extensions, jailbreak artifacts) ----
def extract_macho_symbol_names(exe_path, macho):
    """Symbol names from LC_SYMTAB (the reliable way to check for
    stack-canary / ARC symbols). Returns (names:set, has_symtab:bool).

    A stripped binary has no symtab — that means "unknown", never
    "missing": on iOS these protections are on by default in release
    builds, so absence of a symbol table proves nothing."""
    names, has_symtab = set(), False
    try:
        data = Path(exe_path).read_bytes()[:MAX_SCAN_BYTES]
    except Exception:
        return names, has_symtab
    slices = macho.get("slices") or [macho]
    for s in slices:
        st = (s or {}).get("symtab")
        if not st or not s.get("is64"):
            continue
        has_symtab = True
        fmt, base = st["fmt"], st["slice_off"]
        for i in range(min(st["nsyms"], 100000)):
            off = base + st["symoff"] + i * 16
            if off + 16 > len(data):
                break
            try:
                n_strx = struct.unpack(fmt + "I", data[off:off + 4])[0]
            except Exception:
                break
            if n_strx == 0 or n_strx >= st["strsize"]:
                continue
            so = base + st["stroff"] + n_strx
            end = data.find(b"\x00", so, base + st["stroff"] + st["strsize"])
            if end < 0:
                end = base + st["stroff"] + st["strsize"]
            try:
                names.add(data[so:end].decode("utf-8", "replace"))
            except Exception:
                pass
    return names, has_symtab


def binary_protections(macho, symbols=None, has_symtab=False):
    """Mach-O hardening evidence (MobSF binary_analysis).

    PIE is read from the MH_PIE header flag — reliable. Stack Canary
    and ARC are read from the symbol table: found -> True, otherwise
    None ("unknown"). They are NEVER reported as missing and NEVER
    scored: on iOS they are on by default in release builds, and a
    stripped binary simply has no symbol table to prove them from."""
    if not macho.get("is_macho"):
        return {"available": False, "reason": "Mach-O نیست"}
    symbols = symbols or set()
    stack = True if ("___stack_chk_guard" in symbols
                     or "__stack_chk_fail" in symbols) else None
    arc = True if symbols & {"objc_storeStrong", "objc_retain",
                             "objc_release",
                             "objc_retainAutoreleasedReturnValue"} else None
    return {
        "available": True,
        "pie": bool(macho.get("pie")),
        "stack_canary": stack,   # True = found, None = unknown (never "missing")
        "arc": arc,              # True = found, None = unknown (never "missing")
        "has_symtab": bool(has_symtab),
        "note": ("Stack Canary و ARC در بیلد انتشار iOS به‌طور پیش‌فرض فعال‌اند؛ "
                 "با تحلیل ایستا نمی‌شود قطعی گفت نیستند — نبودِ نماد در جدول "
                 "نمادها به‌معنی نبودِ محافظت نیست."),
    }


def scan_secrets(strings, source_label):
    """Hardcoded-secret discovery over extracted strings.

    Only well-known token prefixes / private-key markers are flagged.
    The secret VALUE is never returned — only its type, where it was
    found, and a masked preview (first 4 chars + length)."""
    found = []
    for s in strings or []:
        for pat, label_fa, label_en in SECRET_PATTERNS:
            m = re.search(pat, s)
            if m:
                val = m.group(0)
                found.append({
                    "type_fa": label_fa, "type_en": label_en,
                    "source": source_label,
                    "masked": (val[:4] + "…" + f"({len(val)} chars)"),
                })
                break
    seen, out = set(), []
    for f in found:
        key = (f["type_en"], f["source"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scan_weak_crypto(strings):
    """Weak-crypto string patterns. Low severity by design: presence in
    strings does not prove the code path runs."""
    hits = []
    for pat, fa, en, pts in WEAK_CRYPTO_PATTERNS:
        rx = re.compile(pat)
        count = sum(1 for s in (strings or []) if rx.search(s))
        if count:
            hits.append({"pattern": pat, "label_fa": fa, "label_en": en,
                         "points": pts, "matches": count})
    return hits


def detect_runtime_family(app_dir, frameworks, bundles):
    """Which runtime the app's logic lives in (native / React Native /
    Flutter / Unity / …), from the frameworks actually present. This
    matters because in a Flutter/React Native app the interesting
    payload is a JS bundle or AOT blob, not the Mach-O."""
    names = " ".join((frameworks or []) + (bundles or [])).lower()
    files = {p.name.lower() for p in Path(app_dir).rglob("*") if p.is_file()}
    if "flutter.framework" in names or "app.framework" in files:
        return "Flutter"
    if "unityframework.framework" in names or "unityframework" in names:
        return "Unity"
    if "hermes" in names or any("libreact" in n for n in names.split()):
        return "React Native"
    if "cordova" in names or "cdv" in names:
        return "Cordova"
    if "xamarin" in names:
        return "Xamarin"
    return "Native (Swift/Objective-C)"


def analyze_appex(app_dir):
    """Each .appex is a separate process with its own entitlements and
    container — an extension granted an app group the app lacks has
    widened reach without the app binary. Read each extension's own
    Info.plist (identity + permissions) and code-signature presence."""
    plugins = app_dir / "PlugIns"
    out = []
    if not plugins.is_dir():
        return out
    for appex in sorted(plugins.glob("*.appex")):
        entry = {"name": appex.name, "bundle_id": None,
                 "permissions": [], "has_code_signature": False,
                 "has_embedded_provision": False}
        plist = appex / "Info.plist"
        if plist.is_file():
            try:
                with open(plist, "rb") as f:
                    pl = plistlib.load(f)
                entry["bundle_id"] = pl.get("CFBundleIdentifier")
                for key, (fa, en, _risk) in PERMISSIONS.items():
                    if key in pl:
                        entry["permissions"].append(
                            {"key": key, "label_fa": fa, "label_en": en})
            except Exception:
                pass
        entry["has_code_signature"] = (appex / "_CodeSignature").is_dir()
        entry["has_embedded_provision"] = (appex / "embedded.mobileprovision").is_file()
        out.append(entry)
    return out


def find_jailbreak_artifacts(strings_by_source):
    """Jailbreak/substrate artifact paths found in binary/dylib strings.

    The runtime equivalent is enumerating dyld images and comparing
    them with the legitimate set; statically, a substrate path string
    in the main binary is evidence the code knows about (or ships)
    jailbreak tooling. Returns [{marker, source}]."""
    found, seen = [], set()
    for source, strings in (strings_by_source or {}).items():
        for s in strings or []:
            for marker in JAILBREAK_PATH_MARKERS:
                if marker in s and (marker, source) not in seen:
                    seen.add((marker, source))
                    found.append({"marker": marker, "source": source})
    return found


# ---------------- .deb analysis (v4) ----------------
MAX_DEB_BYTES = 512 * 1024 * 1024


def _parse_ar(data):
    """Parse a Unix ar archive (the .deb container). Returns {name: bytes}."""
    if not data.startswith(b"!<arch>\n"):
        return None
    members = {}
    off = 8
    while off + 60 <= len(data):
        header = data[off:off + 60]
        try:
            name = header[0:16].decode("ascii", "ignore").strip()
            size = int(header[48:58].decode("ascii", "ignore").strip() or "0")
        except ValueError:
            break
        if name.endswith("/"):
            name = name[:-1]
        members[name] = data[off + 60:off + 60 + size]
        off += 60 + size + (size % 2)
    return members


def _open_tar_member(data):
    """Open a .deb control/data tar member (gz/bz2/xz). Returns TarFile or None."""
    try:
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, EOFError, OSError):
        return None


def _parse_debian_control(text):
    """Parse a Debian control file (Package/Version/Maintainer/…)."""
    out = {}
    key = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and key:
            out[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            out[key] = val.strip()
        else:
            key = None
    return out


def analyze_deb(path, app_dir):
    """Analyse one .deb file inside the IPA, separately.

    Extracts control metadata (package, version, maintainer, description,
    depends), the list of contained files, and pre/post-install scripts.
    A .deb whose files live under Library/MobileSubstrate is a jailbreak
    tweak package — that is flagged, not hidden.
    """
    rel = str(path.relative_to(app_dir)) if str(path).startswith(str(app_dir)) else path.name
    entry = {"name": path.name, "path": rel, "size_bytes": 0,
             "package": None, "version": None, "architecture": None,
             "maintainer": None, "description": None, "depends": None,
             "section": None, "files": [], "scripts": {},
             "dylib_files": [], "is_tweak": False,
             "unavailable": None, "error": None}
    try:
        size = path.stat().st_size
        entry["size_bytes"] = size
    except Exception as e:
        entry["error"] = str(e)
        return entry
    if size > MAX_DEB_BYTES:
        entry["unavailable"] = "فایل .deb خیلی بزرگ است — تحلیل نشد"
        return entry
    try:
        data = path.read_bytes()
    except Exception as e:
        entry["error"] = str(e)
        return entry
    members = _parse_ar(data)
    if members is None:
        entry["unavailable"] = "فرمت ar/deb نیست — قابل استخراج نیست"
        return entry
    # --- control.tar.* ---
    control_tar = None
    for name, blob in members.items():
        if name.startswith("control.tar"):
            control_tar = blob
            break
    if control_tar is None:
        entry["unavailable"] = "بخش control.tar در .deb پیدا نشد"
    else:
        tf = _open_tar_member(control_tar)
        if tf is None:
            entry["unavailable"] = "control.tar قابل باز کردن نیست (شاید zstd)"
        else:
            with tf:
                for m in tf.getmembers():
                    base = m.name.lstrip("./")
                    if base in ("control", "./control"):
                        try:
                            text = tf.extractfile(m).read().decode("utf-8", "replace")
                            ctl = _parse_debian_control(text)
                            entry["package"] = ctl.get("package")
                            entry["version"] = ctl.get("version")
                            entry["architecture"] = ctl.get("architecture")
                            entry["maintainer"] = ctl.get("maintainer")
                            entry["description"] = (ctl.get("description") or "")[:300]
                            entry["depends"] = ctl.get("depends")
                            entry["section"] = ctl.get("section")
                        except Exception as e:
                            entry["error"] = f"control parse failed: {e}"
                    elif base in ("preinst", "postinst", "prerm", "postrm"):
                        try:
                            entry["scripts"][base] = tf.extractfile(m).read().decode(
                                "utf-8", "replace")[:2000]
                        except Exception:
                            pass
    # --- data.tar.* ---
    data_tar = None
    for name, blob in members.items():
        if name.startswith("data.tar"):
            data_tar = blob
            break
    if data_tar is not None:
        tf = _open_tar_member(data_tar)
        if tf is not None:
            with tf:
                for m in tf.getmembers():
                    entry["files"].append(m.name)
                    if m.name.endswith(".dylib"):
                        entry["dylib_files"].append(m.name)
    entry["files"] = sorted(entry["files"])[:200]
    entry["dylib_files"] = sorted(entry["dylib_files"])
    tweak_markers = ("MobileSubstrate", "CydiaSubstrate", "Library/MobileSubstrate")
    if any(mk in f for f in entry["files"] for mk in tweak_markers) \
            or any(mk in (entry["package"] or "") for mk in ("substrate",)):
        entry["is_tweak"] = True
    return entry


# ---------------- third-party tampering detection (v4) ----------------
TWEAK_NAME_HINTS = ("patch", "blatant", "sideload", "keychainfix",
                    "substrate", "tweak", "crack", "unlock")


def detect_tampering(result, dylib_analysis, deb_packages, substrate_files):
    """Decide whether this IPA was tampered with by a third party besides
    the original company, and whether the injected code talks to its own
    server. Returns the tampering dict stored in result["tampering"].

    Signals (strongest first):
    1. A dylib whose install name lives in /Library/MobileSubstrate/
       DynamicLibraries/ — normal App Store apps never ship those; that
       is a jailbreak tweak injected into the app process.
    2. A .deb package whose files live under Library/MobileSubstrate.
    3. Substrate loader files present in the bundle.
    Per-dylib domains/URLs are compared against the original app's
    network domains: a tweak dylib domain that the original app never
    talks to is an "unknown tweak server".
    """
    injected = []
    for d in (dylib_analysis or []):
        reasons = []
        linked = d.get("linked_dylibs") or []
        ms_names = [l for l in linked
                    if "/Library/MobileSubstrate/" in l or "MobileSubstrate" in l
                    or "CydiaSubstrate" in l]
        if ms_names:
            reasons.append("install name در MobileSubstrate است: " + ms_names[0])
        name_low = (d.get("name") or "").lower()
        if any(h in name_low for h in ("patch", "blatant", "sideload", "keychainfix")):
            reasons.append("نام فایل نشانه‌ی پچ/توئیک است: " + d.get("name", ""))
        if d.get("path", "").startswith("Frameworks/") and ms_names:
            reasons.append("در Frameworks برنامه قرار دارد ولی لودر آن MobileSubstrate است")
        if reasons:
            injected.append({
                "name": d.get("name"), "path": d.get("path"),
                "size_bytes": d.get("size_bytes"),
                "risk_points": d.get("risk_points", 0),
                "severity": d.get("severity"),
                "reasons_fa": reasons,
                "domains": d.get("domains", []),
                "insecure_http_urls": d.get("insecure_http_urls", []),
                "urls": d.get("urls", []),
                "suspicious": d.get("suspicious", []),
                "unavailable": d.get("unavailable"),
            })
    tweak_debs = [p for p in (deb_packages or []) if p.get("is_tweak")]
    evidence = []
    for d in injected:
        evidence.append(
            f"dylib تزریقی `{d['name']}` — " + "؛ ".join(d["reasons_fa"]))
        for h in d.get("suspicious", [])[:4]:
            evidence.append(
                f"  • در `{d['name']}`: {h['label_fa']} ({h['matches']} مورد)")
        if d.get("unavailable"):
            evidence.append(f"  • `{d['name']}`: {d['unavailable']}")
    for p in tweak_debs:
        evidence.append(
            f"بسته‌ی .deb توئیک: `{p.get('package') or p['name']}`"
            f" نسخه‌ی {p.get('version') or '—'} — فایل‌های آن زیر Library/MobileSubstrate است")
    for f in (substrate_files or [])[:5]:
        evidence.append(f"فایل MobileSubstrate در باندل: `{f}`")

    # Per-tweak-dylib servers vs the original app's own network domains.
    original_domains = set(result.get("_original_domains") or [])
    known_tracker_hosts = set()
    for dom in (result.get("domain_analysis") or []):
        if dom.get("is_tracker_domain"):
            known_tracker_hosts.add(dom["domain"])
    tweak_domains = sorted({dom for d in injected for dom in (d.get("domains") or [])})
    unknown_tweak_servers = [
        dom for dom in tweak_domains
        if dom not in original_domains and dom not in known_tracker_hosts
    ]
    tweak_http = sorted({u for d in injected for u in (d.get("insecure_http_urls") or [])})

    tampered = bool(injected or tweak_debs or substrate_files)
    if tampered:
        verdict_fa = "تأیید شد — دستکاری شخص ثالث"
        verdict_en = "tampered"
        if unknown_tweak_servers:
            server_note = ("dylibهای تزریقی با این سرورهای ناشناخته صحبت می‌کنند: "
                           + "، ".join(unknown_tweak_servers))
        elif tweak_domains:
            server_note = ("dylibهای تزریقی دامنه دارند ولی همه‌ی آن‌ها دامنه‌های "
                           "خود برنامه‌ی اصلی یا ترکرهای شناخته‌شده‌اند؛ "
                           "سرور ناشناخته‌ی جداگانه‌ای پیدا نشد.")
        else:
            server_note = ("در رشته‌های ایستای dylibهای تزریقی هیچ دامنه/سروری "
                           "پیدا نشد — یعنی شواهدی از ارسال مستقیم داده به "
                           "سرور شخص ثالث نیست.")
    else:
        verdict_fa = "شواهدی از دستکاری شخص ثالث پیدا نشد"
        verdict_en = "not-found"
        server_note = ("هیچ dylib تزریقی (MobileSubstrate)، بسته‌ی .deb توئیک "
                       "یا فایل Substrate در باندل پیدا نشد.")
    limits = [
        "تحلیل ایستا فقط رشته‌ها و دامنه‌های ثابت در فایل را می‌بیند؛ "
        "آدرس سرور می‌تواند در زمان اجرا ساخته شود یا dylib می‌تواند از "
        "اتصال شبکه‌ی خود برنامه استفاده کند، بدون اینکه سرور جداگانه‌ای داشته باشد.",
        "اینکه dylib تزریقی واقعاً چه داده‌ای می‌فرستد فقط با رصد ترافیک "
        "زمان اجرا (پراکسی/لاگ شبکه) مشخص می‌شود.",
    ]
    if result.get("binary", {}).get("encrypted") is True:
        limits.append("باینری اصلی رمزگذاری‌شده است؛ الگوهای باینری اصلی قابل بررسی نبود.")
    return {
        "tampered": tampered,
        "verdict": verdict_en,
        "verdict_fa": verdict_fa,
        "confidence": "high" if tampered else "medium",
        "injected_dylibs": injected,
        "injected_dylib_count": len(injected),
        "tweak_deb_packages": [p.get("package") or p.get("name") for p in tweak_debs],
        "substrate_files": list(substrate_files or []),
        "tweak_domains": tweak_domains,
        "unknown_tweak_servers": unknown_tweak_servers,
        "tweak_insecure_http_urls": tweak_http,
        "server_note_fa": server_note,
        "evidence": evidence,
        "limits": limits,
    }


# ---------------- main scan ----------------
def scan_ipa(ipa_path, workdir):
    ipa_path = Path(ipa_path)
    if not ipa_path.is_file():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")
    result = {
        "file": str(ipa_path),
        **hashes_of(ipa_path),
        "size_bytes": ipa_path.stat().st_size,
        "scanner": "sibstar-ipa-scanner 6.0 (stdlib only)",
        "limits": [
            "IPAهای اپ‌استور با FairPlay رمزگذاری شده‌اند؛ تحلیل رشته‌ها و الگوهای باینری بدون نسخه‌ی رمزگشایی‌شده ممکن نیست.",
            "این اسکن بدون رمزگشایی، Info.plist، مانیفست حریم خصوصی، فریم‌ورک‌ها، entitlements، ATS و URLها را می‌خواند.",
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
    # Runtime family (native / Flutter / React Native / Unity …) — in a
    # Flutter/React Native app the logic lives in a JS bundle or AOT blob,
    # not in the Mach-O, so the binary-pattern section must be read
    # with that in mind.
    result["runtime_family"] = detect_runtime_family(app_dir, frameworks, bundles)
    # App extensions are separate processes with their own entitlements.
    result["app_extension_details"] = analyze_appex(app_dir)
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

    # MobSF-style binary checks (only on a decrypted binary).
    _main_strings = []
    if bin_strings and not bin_strings.get("unavailable") and exe_path and exe_path.is_file():
        try:
            _main_strings = extract_strings(exe_path.read_bytes()[:MAX_SCAN_BYTES])
        except Exception:
            _main_strings = []
    # Symbol-table based protections (v5): only on a decrypted binary;
    # an encrypted binary's __LINKEDIT cannot be read reliably, so its
    # protections are reported as unavailable, never as "missing".
    _main_symbols, _has_symtab = set(), False
    if (bin_strings and not bin_strings.get("unavailable")
            and exe_path and exe_path.is_file()):
        _main_symbols, _has_symtab = extract_macho_symbol_names(exe_path, binary)
    if binary.get("encrypted") is True:
        result["binary_protections"] = {
            "available": False,
            "reason": "باینری رمزگذاری‌شده (FairPlay) است — محافظت‌های باینری "
                      "بدون نسخه‌ی رمزگشایی‌شده قابل بررسی نیست"}
    else:
        result["binary_protections"] = binary_protections(
            binary, _main_symbols, _has_symtab)
    result["hardcoded_secrets"] = scan_secrets(_main_strings, "باینری اصلی")
    result["weak_crypto"] = scan_weak_crypto(_main_strings)
    # Secrets can also hide in plist values: keys that look like
    # api-key / secret / password / token with a long random-looking value.
    for _fname, _plist in (("Info.plist", info),):
        for _k, _v in _plist.items():
            if isinstance(_v, str) and len(_v) >= 20 and re.search(
                    r"(?i)(api[_-]?key|secret|password|token)", _k):
                if not _v.startswith(("http://", "https://")):
                    result["hardcoded_secrets"].append({
                        "type_fa": f"مقدار مشکوک در Info.plist ({_k})",
                        "type_en": f"suspicious plist value ({_k})",
                        "source": "Info.plist",
                        "masked": f"({len(_v)} chars)",
                    })
    _jb_sources = {"باینری اصلی": _main_strings}
    result["jailbreak_artifacts"] = find_jailbreak_artifacts(_jb_sources)

    # Embedded .dylib files — each analysed separately (never skipped silently)
    dylib_paths = sorted(p for p in app_dir.rglob("*.dylib") if p.is_file())[:50]
    dylib_analysis = [analyze_dylib(p, app_dir) for p in dylib_paths]
    result["dylib_analysis"] = dylib_analysis
    result["dylib_count"] = len(dylib_analysis)
    result["dylib_suspicious_count"] = sum(len(d.get("suspicious", [])) for d in dylib_analysis)

    # .deb packages inside the IPA (v4) — analysed separately
    deb_paths = sorted({p for p in root.rglob("*.deb") if p.is_file()})[:20]
    deb_packages = [analyze_deb(p, app_dir) for p in deb_paths]
    result["deb_packages"] = deb_packages
    result["deb_count"] = len(deb_packages)

    # Jailbreak artifacts inside dylib strings too (dyld-image check).
    _jb_dylib_sources = {}
    for _d in dylib_analysis:
        if _d.get("unavailable") or not _d.get("is_macho"):
            continue
        try:
            _dp = app_dir / _d["path"]
            if _dp.is_file():
                _jb_dylib_sources[f"dylib {_d['name']}"] = extract_strings(
                    _dp.read_bytes()[:MAX_SCAN_BYTES])
        except Exception:
            pass
    if _jb_dylib_sources:
        _jb_sources.update(_jb_dylib_sources)
        result["jailbreak_artifacts"] = find_jailbreak_artifacts(_jb_sources)
        # Secrets / weak crypto inside dylibs as well (values never stored).
        for _src, _strs in _jb_dylib_sources.items():
            result["hardcoded_secrets"].extend(scan_secrets(_strs, _src))
            for _hit in scan_weak_crypto(_strs):
                _hit = dict(_hit, source=_src)
                if _hit not in result["weak_crypto"]:
                    result["weak_crypto"].append(_hit)

    # Substrate loader files anywhere in the bundle (tampering signal)
    substrate_files = sorted(
        str(p.relative_to(app_dir)) for p in app_dir.rglob("*")
        if p.is_file() and ("MobileSubstrate" in str(p) or "CydiaSubstrate" in str(p)))

    # URLs / domains: bundle files + (decrypted) binary strings, merged.
    # v4: only real network URLs count; namespace/docs strings are kept
    # separately in result["ignored_urls"] and never add risk.
    urls, domains, http_urls, ignored = scan_bundle_files(app_dir)
    ignored_urls = list(ignored)
    # Original app's own network domains (bundle + main binary only,
    # excluding dylibs) — used to judge whether a tweak dylib talks to
    # a server the original app never talks to.
    _orig_urls, _orig_domains, _orig_http = set(urls), set(domains), set(http_urls)
    if bin_strings and not bin_strings.get("unavailable"):
        urls = sorted(set(urls) | set(bin_strings.get("urls", [])))
        domains = sorted(set(domains) | set(bin_strings.get("domains", [])))
        http_urls = sorted(set(http_urls) | set(bin_strings.get("insecure_http_urls", [])))
        _orig_urls |= set(bin_strings.get("urls", []))
        _orig_domains |= set(bin_strings.get("domains", []))
        _orig_http |= set(bin_strings.get("insecure_http_urls", []))
        ignored_urls.extend(bin_strings.get("ignored_urls", []))
    result["_original_domains"] = sorted(_orig_domains)
    for d in dylib_analysis:
        if not d.get("unavailable"):
            urls = sorted(set(urls) | set(d.get("urls", [])))
            domains = sorted(set(domains) | set(d.get("domains", [])))
            http_urls = sorted(set(http_urls) | set(d.get("insecure_http_urls", [])))
    result["urls"] = urls[:200]
    result["url_count"] = len(urls)
    result["domains"] = domains
    result["insecure_http_urls"] = http_urls
    # De-duplicate the ignored list (same namespace URL can appear in
    # many files) and keep only the reason + a short sample.
    seen_ign, ignored_dedup = set(), []
    for item in ignored_urls:
        key = (item.get("url"), item.get("reason"))
        if key not in seen_ign:
            seen_ign.add(key)
            ignored_dedup.append(item)
    result["ignored_urls"] = ignored_dedup[:50]
    result["ignored_url_count"] = len(ignored_dedup)
    result["ignored_domains"] = sorted({urlparse(i["url"]).hostname
                                        for i in ignored_dedup
                                        if urlparse(i["url"]).hostname})
    pm_for_domains = result.get("privacy_manifest") or {}
    result["domain_analysis"] = analyze_domains(
        domains, http_urls, pm_for_domains.get("tracking_domains", []))

    # Third-party tampering verdict (v4) — before risk scoring, so the
    # risk breakdown can attribute tweak findings to the tweak.
    result["tampering"] = detect_tampering(
        result, dylib_analysis, deb_packages, substrate_files)
    # Jailbreak/substrate artifact strings are weaker evidence than an
    # injected dylib: they join the evidence list but do not by
    # themselves flip the verdict.
    for _art in result.get("jailbreak_artifacts", []):
        result["tampering"]["evidence"].append(
            f"نشانه‌ی جیلبریک/توئیک در رشته‌ها ({_art['source']}): {_art['marker']}")

    # ---- Risk score v6: calm and accurate, never inflated ----
    # v6 recalibration (a clean legit app must score LOW):
    #  * trackers are 2 points each (cap 6), not 5 each (cap 10) —
    #    Firebase in a normal app is not a threat on its own;
    #  * the privacy-manifest lines no longer triple-count the same
    #    tracking fact (tracking 3, tracking domains 2, tracking
    #    types 3, linked types 2, sensitive linked/tracking type 4);
    #  * ATS arbitrary loads 10 -> 6 (a config flag, not a breach);
    #  * code cap 12 -> 15, and hardcoded secrets are scored BEFORE
    #    generic code patterns, so a real secret is never starved
    #    out by the cap. Caps: network 20, permissions 15,
    #    privacy 15, code 15, tweak 25 (maximum possible score: 90).
    #  * a finding whose category cap is already full is collected and
    #    rendered as ONE summary line per category in the report — never
    #    silently hidden, never seven "(سقف پر شد)" lines either.
    # The breakdown lists the points actually counted, per category.
    CATEGORY_CAPS = {"network": 20, "permissions": 15, "privacy": 15,
                     "code": 15, "tweak": 25}
    cat_used = {k: 0 for k in CATEGORY_CAPS}
    # v6: findings whose category cap is full are collected here and
    # rendered as ONE summary line per category in the report — the
    # breakdown never silently hides a finding, but it also doesn't
    # drown in seven "(سقف پر شد)" lines.
    capped_by_cat = {k: [] for k in CATEGORY_CAPS}
    score, breakdown = 0, []

    def add(points, reason, source="original", category="code",
            masvs=None, confidence="medium"):
        nonlocal score
        cap = CATEGORY_CAPS.get(category, 12)
        counted = max(0, min(points, cap - cat_used.get(category, 0)))
        if counted <= 0:
            if points > 0:
                capped_by_cat[category].append(reason)
            return
        cat_used[category] = cat_used.get(category, 0) + counted
        score += counted
        breakdown.append({"points": counted, "reason": reason,
                          "source": source, "category": category,
                          "masvs": masvs or MASVS_BY_CATEGORY.get(category, "MASVS-CODE"),
                          "confidence": confidence})
    if result["ats"]["allows_arbitrary_loads"]:
        add(6, "NSAllowsArbitraryLoads فعال است — ترافیک رمزنگاری‌نشده مجاز است",
            category="network")
    if result["ats"]["allows_arbitrary_loads_for_media"]:
        add(3, "NSAllowsArbitraryLoadsForMedia فعال است", category="network")
    if http_urls:
        add(min(9, 3 * len(http_urls)),
            f"{len(http_urls)} آدرس http:// ناامن (واقعی) پیدا شد", category="network")
    if result["ats"]["exception_domains"]:
        add(3, f"دامنه‌های استثنا در ATS: {', '.join(result['ats']['exception_domains'])}",
            category="network")
    # Permissions: de-duplicate location (strongest key only) and cap.
    LOCATION_KEYS = {"NSLocationUsageDescription",
                     "NSLocationWhenInUseUsageDescription",
                     "NSLocationAlwaysUsageDescription",
                     "NSLocationAlwaysAndWhenInUseUsageDescription",
                     "NSLocationTemporaryUsageDescriptionDictionary"}
    loc_perms = [p for p in perms if p["key"] in LOCATION_KEYS]
    keep_loc = max(loc_perms, key=lambda p: p["risk"])["key"] if loc_perms else None
    # v5: permissions score LOW. A permission is a capability, not a
    # threat on its own. When the usage description says the access is
    # for ads, it scores 1 point at most and the reason says so in plain
    # words — it is never presented as a medium/high threat.
    for p in perms:
        if p["key"] in LOCATION_KEYS and p["key"] != keep_loc:
            continue  # same access, already counted under the strongest key
        desc = str(p.get("description") or "").lower()
        is_ads = ("ads" in desc) or ("advertis" in desc) or ("تبلیغ" in desc)
        pts = 2 if p["risk"] >= 9 else (1 if p["risk"] >= 5 else 0)
        if is_ads:
            pts = min(pts, 1)
        if pts <= 0:
            continue
        reason = f"دسترسی: {p['label_fa']} ({p['label_en']})"
        if is_ads:
            reason += " — توضیح استفاده: تبلیغات؛ بدون مدرک ارسال داده، تهدید نیست"
        add(pts, reason, category="permissions")
    pm = result["privacy_manifest"]
    if pm and not pm.get("error"):
        if pm.get("tracking"):
            add(3, "مانیفست حریم خصوصی: NSPrivacyTracking = true (ردیابی کاربر)",
                category="privacy")
        if pm.get("tracking_domains"):
            add(2, f"دامنه‌های ردیابی در مانیفست: {', '.join(pm['tracking_domains'][:5])}",
                category="privacy")
        tracking_types = [c for c in pm.get("collected_data_types", []) if c.get("tracking")]
        if tracking_types:
            add(3, f"{len(tracking_types)} نوع داده‌ی جمع‌آوری‌شده با ردیابی مرتبط است",
                category="privacy")
        linked_types = [c for c in pm.get("collected_data_types", []) if c.get("linked")]
        if linked_types:
            add(2, f"{len(linked_types)} نوع داده‌ی جمع‌آوری‌شده به هویت کاربر متصل است",
                category="privacy")
    if dedup:
        add(min(6, 2 * len(dedup)),
            f"{len(dedup)} ترکر/SDK شناخته‌شده: {', '.join(t['tracker'] for t in dedup)}",
            category="privacy")
    if ent.get("get-task-allow") is True:
        add(8, "get-task-allow = true — باینری قابل دیباگ است (نسخه‌ی توسعه، نه انتشار)",
            category="code")
    for f in result.get("entitlement_findings", []):
        if f["points"] > 0 and f["key"] != "get-task-allow":
            add(f["points"], f"Entitlement حساس: {f['label_fa']} (`{f['key']}`)",
                category="code")
    if pm and not pm.get("error"):
        # Only sensitive types that are linked to identity or used for
        # tracking add points. A functionality-only, unlinked entry
        # (e.g. Photos/Videos in a PDF editor) is normal, not a risk.
        sensitive_types = [c for c in pm.get("collected_data_types", [])
                           if c.get("risk_points", 0) >= 8
                           and (c.get("linked") or c.get("tracking"))]
        if sensitive_types:
            add(4, "مانیفست داده‌ی حساس جمع می‌کند (متصل به هویت یا با ردیابی): " +
                "، ".join(c.get("sensitive") or c.get("type", "?") for c in sensitive_types[:4]),
                category="privacy")
    for domain_entry in result.get("domain_analysis", []):
        if domain_entry.get("is_tracker_domain"):
            add(2, f"دامنه ترکر/تبلیغات: {domain_entry['domain']}",
                category="privacy")
    insecure_exc = [d for d, cfg in result["ats"].get("exception_domain_details", {}).items()
                    if cfg.get("allows_insecure_http")]
    if insecure_exc:
        add(3, f"ATS برای این دامنه‌ها http ناامن را مجاز می‌کند: {', '.join(insecure_exc)}",
            category="network")
    plist_sec = result.get("plist_security", {})
    if plist_sec.get("background_location"):
        add(3, "حالت پس‌زمینه location فعال است — ردیابی موقعیت در پس‌زمینه",
            category="code")
    if plist_sec.get("file_sharing_enabled"):
        add(2, "UIFileSharingEnabled فعال است — فایل‌های برنامه از طریق iTunes قابل دسترسی‌اند",
            category="code")
    if plist_sec.get("bonjour_services"):
        add(2, f"سرویس‌های Bonjour (شبکه محلی): {', '.join(plist_sec['bonjour_services'][:4])}",
            category="code")
    # MobSF-style: hardcoded secrets FIRST (high confidence — they must
    # never be starved out by the code cap), then binary patterns.
    for sec in result.get("hardcoded_secrets", []):
        add(6, f"رمز/توکن سخت‌کدشده در باندل: {sec['type_fa']} ({sec['source']})",
            category="code", masvs="MASVS-STORAGE", confidence="high")
    if bin_strings and not bin_strings.get("unavailable"):
        for hit in bin_strings.get("suspicious", []):
            add(hit["points"], f"الگوی مشکوک در باینری: {hit['label_fa']} ({hit['matches']} مورد)",
                category="code")
    for wc in result.get("weak_crypto", []):
        add(wc["points"], f"{wc['label_fa']} ({wc.get('source', 'باینری اصلی')}) — "
            "وجود رشته به‌تنهایی به معنی استفاده نیست",
            category="code", masvs="MASVS-CRYPTO", confidence="low")
    prot = result.get("binary_protections") or {}
    if prot.get("available"):
        if not prot.get("pie"):
            add(3, "باینری PIE نیست (Position Independent Executable فعال نیست)",
                category="code", masvs="MASVS-CODE", confidence="medium")
    # v5: NO double counting. An injected dylib's patterns are counted
    # ONCE, inside the single tampering line below (base 8 + the dylibs'
    # pattern points, capped at the 25-point tweak cap). They are NOT
    # added again as individual findings. Non-injected dylibs are still
    # scored individually (source "original").
    tamp = result.get("tampering") or {}
    injected_names = {d["name"] for d in tamp.get("injected_dylibs", [])}
    if tamp.get("tampered"):
        injected_pts = sum(
            h.get("points", 0)
            for d in dylib_analysis if d.get("name") in injected_names
            for h in d.get("suspicious", []))
        add(min(25, 8 + injected_pts),
            f"دستکاری شخص ثالث: {tamp.get('injected_dylib_count', 0)} dylib تزریقی "
            "(MobileSubstrate) در باندل است", source="tweak", category="tweak",
            confidence="high")
    for d in dylib_analysis:
        if d.get("name") in injected_names:
            continue  # counted once inside the tampering line above
        for hit in d.get("suspicious", []):
            add(hit["points"], f"الگوی مشکوک در dylib {d['name']}: {hit['label_fa']} ({hit['matches']} مورد)",
                source="original", category="code")
        if d.get("tracker"):
            add(5, f"dylib ترکر: {d['name']} → {d['tracker']}",
                source="original", category="code")
    for p in deb_packages:
        if p.get("is_tweak"):
            add(8, f"بسته‌ی .deb توئیک: {p.get('package') or p['name']}",
                source="tweak", category="tweak")
    if not code_sig:
        add(3, "امضای کد پیدا نشد", category="code")
    if binary.get("encrypted") is True:
        breakdown.append({"points": 0, "source": "original", "category": "code",
                          "reason": "باینری رمزگذاری‌شده (FairPlay) است — تحلیل کامل باینری بدون نسخه‌ی رمزگشایی‌شده ممکن نیست"})
    elif binary.get("encrypted") is False:
        breakdown.append({"points": 0, "source": "original", "category": "code",
                          "reason": "باینری رمزگذاری نشده — تحلیل رشته‌ها انجام شد"})
    score = min(100, score)
    level = "کم" if score < 30 else ("متوسط" if score < 60 else "بالا")
    original_points = sum(b.get("points", 0) for b in breakdown if b.get("source") != "tweak")
    tweak_points = sum(b.get("points", 0) for b in breakdown if b.get("source") == "tweak")
    result["risk"] = {"score": score, "level_fa": level,
                      "level_en": "low" if score < 30 else ("medium" if score < 60 else "high"),
                      "breakdown": breakdown,
                      "category_points": dict(cat_used),
                      "category_caps": dict(CATEGORY_CAPS),
                      "original_points": original_points,
                      "tweak_points": tweak_points,
                      "capped_notes": {k: v for k, v in capped_by_cat.items() if v},
                      "reasons": [b["reason"] for b in breakdown]}

    # ---- Per-finding severity list (v3) ----
    findings = []
    for b in breakdown:
        if b.get("points", 0) > 0:
            findings.append({"severity": severity_for_points(b["points"]),
                             "category": "risk", "title_fa": b["reason"],
                             "points": b["points"],
                             "masvs": b.get("masvs", "MASVS-CODE"),
                             "confidence": b.get("confidence", "medium")})
    for d in dylib_analysis:
        if d.get("unavailable"):
            findings.append({"severity": "info", "category": "dylib",
                             "title_fa": f"dylib {d['name']}: {d['unavailable']}", "points": 0,
                             "masvs": "MASVS-RESILIENCE", "confidence": "high"})
    if not (pm and not pm.get("error")) and result.get("privacy_manifest") is None:
        findings.append({"severity": "medium", "category": "privacy-manifest",
                         "title_fa": "مانیفست حریم خصوصی (PrivacyInfo.xcprivacy) در باندل نیست", "points": 0,
                         "masvs": "MASVS-PRIVACY", "confidence": "high"})
    if result.get("provisioning") and result["provisioning"].get("expired"):
        findings.append({"severity": "high", "category": "provisioning",
                         "title_fa": "پروفایل provisioning منقضی شده است", "points": 0,
                         "masvs": "MASVS-PLATFORM", "confidence": "high"})
    result["findings"] = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f["severity"]])

    # ---- MASVS coverage (OWASP MASVS 2.x) ----
    _checked = {b.get("masvs") for b in breakdown if b.get("masvs")}
    if result.get("hardcoded_secrets") is not None and not binary.get("encrypted"):
        _checked.add("MASVS-STORAGE")
    if result.get("weak_crypto") is not None and not binary.get("encrypted"):
        _checked.add("MASVS-CRYPTO")
    if result.get("privacy_manifest") is not None:
        _checked.add("MASVS-PRIVACY")
    result["masvs_coverage"] = {
        "checked": sorted(_checked),
        "dynamic_only": [
            "MASVS-NETWORK — رفتار واقعی TLS و certificate pinning فقط با تست زمان اجرا",
            "MASVS-AUTH — بررسی‌های سمت سرور (توکن، نشست) فقط با تست زمان اجرا",
            "MASVS-RESILIENCE — ضد دستکاری و ضد دیباگ در زمان اجرا فقط با تست زمان اجرا",
        ],
        "note": ("تحلیل ایستا خودکار راهنماست، نه حکم قطعی (OWASP MASTG): "
                 "خروجی می‌تواند مثبت کاذب و منفی کاذب داشته باشد. هر یافته "
                 "یک سطح اطمینان دارد؛ یافته‌های با اطمینان پایین فقط نشانه‌اند، نه اثبات."),
    }

    # ---- Answers to the privacy questions (Picsart-style + tampering) ----
    result["privacy_answers"] = build_privacy_answers(result)
    result.pop("_original_domains", None)
    return result

def render_report(r):
    """Markdown report (v6 layout).

    First screen first: the verdict, the risk score with its
    original/tweak split, the tampering verdict, and the privacy
    answers — then "why this score" (the breakdown), then a "جزئیات"
    part with everything technical. Redundant sections were removed:
    the severity findings list duplicated the breakdown (only the top
    5 remain), and the jailbreak-artifact section duplicated the
    tampering evidence (one deduped line remains inside tampering).
    """
    L = []
    ident = r.get("identity", {})
    answers = {a["id"]: a for a in (r.get("privacy_answers", []) or [])}
    verdict_a = answers.get("verdict", {}) or {}
    tamp = r.get("tampering") or {}

    # ---- First screen: verdict, risk, tampering, answers ----
    L.append(f"# گزارش اسکن IPA — {ident.get('display_name') or r.get('file')}")
    L.append("")
    L.append(f"**حکم نهایی: {verdict_a.get('answer_fa', '—')}**")
    if r.get("risk"):
        L.append(f"**ریسک کلی: {r['risk']['score']}/100 — {r['risk']['level_fa']}** "
                 f"(برنامه‌ی اصلی: {r['risk'].get('original_points', '?')}، "
                 f"توئیک/تزریقی: {r['risk'].get('tweak_points', '?')})")
    L.append("")
    L.append("## دستکاری شخص ثالث / توئیک")
    L.append(f"**حکم: {tamp.get('verdict_fa', '—')}**")
    if tamp.get("unknown_tweak_servers"):
        L.append(f"- ⚠️ سرورهای ناشناخته‌ی توئیک: {', '.join(tamp['unknown_tweak_servers'])}")
    else:
        L.append(f"- {tamp.get('server_note_fa', '')}")
    if tamp.get("tweak_deb_packages"):
        L.append(f"- بسته‌های .deb توئیک: {', '.join(tamp['tweak_deb_packages'])}")
    _jb_markers = sorted({a["marker"] for a in (r.get("jailbreak_artifacts") or [])})
    if _jb_markers:
        L.append(f"- نشانه‌ی جیلبریک/توئیک در رشته‌ها: {', '.join(_jb_markers)}")
    if tamp.get("injected_dylibs"):
        L.append("")
        L.append("### dylibهای تزریقی — هر کدام جدا")
        for d in tamp["injected_dylibs"]:
            L.append(f"#### `{d['path']}` — {d.get('size_bytes', 0):,} بایت")
            for reason in d.get("reasons_fa", []):
                L.append(f"- چرا تزریقی است: {reason}")
            if d.get("domains"):
                L.append(f"- دامنه‌های این dylib: {', '.join(d['domains'])}")
            else:
                L.append("- دامنه/سروری در رشته‌های این dylib پیدا نشد.")
            if d.get("insecure_http_urls"):
                L.append(f"- لینک ناامن http در این dylib: {', '.join(d['insecure_http_urls'][:5])}")
            if d.get("unavailable"):
                L.append(f"- ⚠️ در دسترس نیست: {d['unavailable']}")
            L.append("- جزئیات کامل الگوهای این dylib در بخش «کتابخانه‌های داینامیک» است.")
        L.append("")
        L.append("امتیاز الگوهای این dylibها توصیفی است و فقط یک بار، در خط «دستکاری شخص ثالث» "
                 "در ریسک کلی، حساب شده است؛ جدا جمع نمی‌شود.")
    L.append("- محدودیت‌ها: پایین گزارش، بخش «محدودیت‌های اسکن».")
    L.append("")
    if r.get("privacy_answers"):
        L.append("## پاسخ به سؤال‌های حریم خصوصی")
        L.append("")
        for a in r["privacy_answers"]:
            L.append(f"### {a['question_fa']}")
            L.append(f"**{a['answer_fa']}**")
            for ev in a.get("evidence", [])[:1]:
                L.append(f"- دلیل: {ev}")
            for lim in a.get("limits", [])[:1]:
                L.append(f"- محدودیت: {lim}")
            L.append("")
    if r.get("risk"):
        L.append("## چرا این امتیاز؟ — تفکیک ریسک")
        for b in r["risk"]["breakdown"]:
            tag = " [توئیک]" if b.get("source") == "tweak" else ""
            L.append(f"- (+{b['points']}) {b['reason']}{tag}")
        _cat_fa = {"network": "شبکه", "permissions": "دسترسی‌ها",
                   "privacy": "حریم خصوصی", "code": "کد", "tweak": "توئیک"}
        for _cat in ("network", "permissions", "privacy", "code", "tweak"):
            _notes = (r["risk"].get("capped_notes") or {}).get(_cat) or []
            if _notes:
                L.append(f"- (سقف دسته‌ی {_cat_fa[_cat]} پر شد — امتیازی اضافه نشد): "
                         + "؛ ".join(_notes))
        L.append("- جمع امتیازهای بالا دقیقاً برابر ریسک کلی است (بدون دوباره‌شماری).")
        L.append("")
    L.append("---")
    L.append("")
    L.append("## جزئیات")
    L.append("")
    # ---- File identity ----
    L.append("### مشخصات فایل")
    L.append(f"- فایل: `{r['file']}`")
    L.append(f"- SHA-256: `{r.get('sha256','')}`")
    L.append(f"- MD5: `{r.get('md5','')}` — SHA-1: `{r.get('sha1','')}`")
    L.append(f"- اندازه فایل: {r.get('size_bytes',0):,} بایت")
    L.append(f"- Bundle ID: `{ident.get('bundle_id')}` | نسخه: {ident.get('version')} (build {ident.get('build')}) | حداقل iOS: {ident.get('minimum_os')}")
    sb = r.get("size_breakdown", {})
    L.append(f"- حجم باندل: {sb.get('total_bytes',0):,} بایت (باینری: {sb.get('binary_bytes','—')}، فریم‌ورک‌ها: {sb.get('frameworks_bytes',0):,} بایت)")
    L.append("")
    # ---- .deb packages (v4) ----
    L.append(f"## بسته‌های .deb — {r.get('deb_count', 0)} مورد")
    if not r.get("deb_packages"):
        L.append("- هیچ فایل .deb در باندل پیدا نشد.")
    for p in r.get("deb_packages", []):
        L.append(f"### `{p['path']}` — {p.get('size_bytes', 0):,} بایت")
        if p.get("unavailable"):
            L.append(f"- ⚠️ در دسترس نیست: {p['unavailable']}")
            continue
        L.append(f"- بسته: `{p.get('package') or '—'}` — نسخه: {p.get('version') or '—'} — "
                 f"معماری: {p.get('architecture') or '—'}")
        L.append(f"- نگهدارنده (Maintainer): {p.get('maintainer') or '—'}")
        if p.get("description"):
            L.append(f"- توضیح: {p['description']}")
        if p.get("depends"):
            L.append(f"- وابستگی‌ها: {p['depends']}")
        L.append(f"- توئیک (MobileSubstrate): {'بله' if p.get('is_tweak') else 'خیر'}")
        if p.get("dylib_files"):
            L.append(f"- فایل‌های dylib داخل بسته: {', '.join(p['dylib_files'][:10])}")
        if p.get("files"):
            L.append(f"- فایل‌های داخل بسته ({len(p['files'])}): {', '.join(p['files'][:15])}"
                     + ("…" if len(p['files']) > 15 else ""))
        for name, body in (p.get("scripts") or {}).items():
            first = body.strip().splitlines()[0] if body.strip() else ""
            L.append(f"- اسکریپت `{name}`: {first[:200]}")
    L.append("")
    # ---- Methodology & standards (MobSF / OWASP MASVS) ----
    L.append("## روش‌شناسی و استانداردها")
    L.append("روش اسکن از شیوه‌های استاندارد تحلیل ایستای iOS پیروی می‌کند: "
             "اسکن باینری MobSF (دسترسی‌ها، امضا، ATS، محافظت‌های باینری، "
             "رمزهای سخت‌کدشده، ترکرها) و دسته‌بندی OWASP MASVS/MASTG.")
    cov = r.get("masvs_coverage") or {}
    if cov.get("checked"):
        L.append(f"- دسته‌های MASVS بررسی‌شده: {', '.join(cov['checked'])}")
    for d in cov.get("dynamic_only", []):
        L.append(f"- فقط با تست زمان اجرا: {d}")
    if cov.get("note"):
        L.append(f"- ⚠️ {cov['note']}")
    L.append("- امتیاز ریسک سقف دارد: هر دسته (شبکه ۲۰، دسترسی ۱۵، حریم خصوصی ۱۵، "
             "کد ۱۵، توئیک ۲۵) جداگانه محدود می‌شود تا یک دسته‌ی پر سر و صدا "
             "به‌تنهایی امتیاز را به ۱۰۰ نرساند. حداکثر امتیاز ممکن ۹۰ است.")
    L.append("")
    L.append(f"## خانواده‌ی ران‌تایم: {r.get('runtime_family') or '—'}")
    if r.get("app_extension_details"):
        L.append("")
        L.append(f"## اکستنشن‌های برنامه ({len(r['app_extension_details'])}) — هر کدام پروسس جداگانه")
        for ex in r["app_extension_details"]:
            perms_txt = ", ".join(p["label_fa"] for p in ex.get("permissions", [])) or "بدون دسترسی حساس"
            L.append(f"- `{ex['name']}` — bundle: `{ex.get('bundle_id') or '—'}` — "
                     f"دسترسی‌ها: {perms_txt} — امضای کد: {ex.get('has_code_signature')}")
    prot = r.get("binary_protections") or {}
    if not prot.get("available") and prot.get("reason"):
        L.append("")
        L.append("## محافظت‌های باینری (PIE / Stack Canary / ARC)")
        L.append(f"- در دسترس نیست: {prot['reason']}")
    if prot.get("available"):
        L.append("")
        L.append("## محافظت‌های باینری (PIE / Stack Canary / ARC)")
        L.append(f"- PIE (Position Independent Executable): {'بله' if prot.get('pie') else 'خیر — در بیلد انتشار غیرعادی است'}")
        L.append(f"- Stack Canary: {'بله' if prot.get('stack_canary') else 'نامشخص — با تحلیل ایستا قابل تشخیص قطعی نیست'}")
        L.append(f"- ARC: {'بله' if prot.get('arc') else 'نامشخص — با تحلیل ایستا قابل تشخیص قطعی نیست'}")
        if prot.get("note"):
            L.append(f"- {prot['note']}")
    secrets = r.get("hardcoded_secrets", []) or []
    L.append("")
    L.append(f"## رمزها و توکن‌های سخت‌کدشده — {len(secrets)} مورد")
    if not secrets:
        L.append("- هیچ توکن/کلید شناخته‌شده‌ای در رشته‌ها و مقادیر plist پیدا نشد. "
                 "(مقدار رمزها هرگز در گزارش چاپ نمی‌شود؛ فقط نوع و محل آن‌ها.)")
    for s in secrets:
        L.append(f"- ⚠️ {s['type_fa']} — محل: {s['source']} — نمونه‌ی مخفی‌شده: `{s['masked']}`")
    wc = r.get("weak_crypto", []) or []
    if wc:
        L.append("")
        L.append("## رمزنگاری ضعیف (وجود رشته ≠ استفاده)")
        for h in wc:
            L.append(f"- {h['label_fa']} ({h.get('source', 'باینری اصلی')}) — {h['matches']} مورد")
    sdk = r.get("sdk_info", {})
    if any(sdk.values()):
        L.append("")
        L.append("## نسخه SDK و ابزار ساخت")
        L.append(f"- SDK: {sdk.get('sdk_name') or '—'} (build {sdk.get('sdk_build') or '—'}) — پلتفرم: {sdk.get('platform_name') or '—'} {sdk.get('platform_version') or ''}")
        L.append(f"- Xcode: {sdk.get('xcode') or '—'} (build {sdk.get('xcode_build') or '—'}) — کامپایلر: {sdk.get('compiler') or '—'}")
    ps = r.get("plist_security", {})
    if ps:
        L.append("")
        L.append("## امنیت Info.plist (فراتر از دسترسی‌ها)")
        L.append(f"- حالت‌های پس‌زمینه: {', '.join(ps.get('background_modes', [])) or '—'}")
        L.append(f"- اشتراک فایل با iTunes (UIFileSharingEnabled): {ps.get('file_sharing_enabled')}")
        L.append(f"- باز کردن اسناد در جای خود: {ps.get('supports_opening_documents_in_place')}")
        L.append(f"- سرویس‌های Bonjour: {', '.join(ps.get('bonjour_services', [])) or '—'}")
        L.append(f"- قابلیت‌های دستگاه موردنیاز: {', '.join(ps.get('required_device_capabilities', [])) or '—'}")
        L.append(f"- رمزنگاری غیرمعاف (ITSAppUsesNonExemptEncryption): {ps.get('uses_non_exempt_encryption')}")
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
        if bs.get("generic_apis"):
            L.append("- APIهای معمولی iOS (اطلاعاتی — امتیازی ندارند، در هزاران برنامه‌ی سالم هم هستند):")
            for g in bs["generic_apis"]:
                L.append(f"  - {g['label_fa']} ({g['label_en']}) — {g['matches']} مورد")
    L.append("")
    L.append(f"## کتابخانه‌های داینامیک (.dylib) — {r.get('dylib_count', 0)} مورد")
    if not r.get("dylib_analysis"):
        L.append("- هیچ فایل .dylib در باندل پیدا نشد.")
    _injected_names = {dd.get("name") for dd in (r.get("tampering") or {}).get("injected_dylibs", [])}
    for d in r.get("dylib_analysis", []):
        _is_injected = d.get("name") in _injected_names
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
                if _is_injected:
                    # v5: counted once inside the tampering line — no (+points) here.
                    L.append(f"  - ⚠️ {h['label_fa']} ({h['label_en']}) — {h['matches']} مورد (در حکم دستکاری حساب شده است)")
                else:
                    L.append(f"  - ⚠️ {h['label_fa']} ({h['label_en']}) — {h['matches']} مورد — (+{h['points']})")
            if not d.get("suspicious"):
                L.append("  - هیچ الگوی مشکوک شناخته‌شده‌ای پیدا نشد.")
            if d.get("generic_apis"):
                L.append("  - APIهای معمولی iOS (اطلاعاتی — امتیازی ندارند): "
                         + "، ".join(f"{g['label_fa']} ({g['matches']} مورد)" for g in d["generic_apis"]))
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
        L.append("### ⚠️ URLهای ناامن http:// (فقط آدرس‌های واقعی شبکه)")
        for u in r["insecure_http_urls"][:20]:
            L.append(f"- {u}")
    if r.get("ignored_urls"):
        L.append("")
        L.append(f"### رشته‌های URL نادیده‌گرفته‌شده ({r.get('ignored_url_count', 0)} مورد — در ریسک حساب نمی‌شوند)")
        L.append("این‌ها فضای نام XML/XMP/SVG یا رشته‌های مستندات‌اند، نه آدرس شبکه‌ای که برنامه صدا بزند:")
        for item in r["ignored_urls"][:15]:
            L.append(f"- `{item['url'][:120]}` — دلیل: {item['reason']}")
        if r.get("ignored_domains"):
            L.append(f"- دامنه‌های نادیده‌گرفته‌شده: {', '.join(r['ignored_domains'][:20])}")
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
    # ---- Top findings only (v6): the full severity list duplicated the
    # risk breakdown above; the complete list stays in the JSON.
    if r.get("findings"):
        L.append("## مهم‌ترین یافته‌ها (۵ مورد اول — لیست کامل در JSON است)")
        sev_fa = {"critical": "بحرانی", "high": "بالا", "medium": "متوسط",
                  "low": "کم", "info": "اطلاعاتی"}
        for f in r["findings"][:5]:
            L.append(f"- [{sev_fa.get(f['severity'], f['severity'])}] {f['title_fa']}"
                     + (f" (+{f['points']})" if f.get("points") else ""))
        L.append("")
    # ---- Scan limits, once, in Persian (v6) ----
    L.append("## محدودیت‌های اسکن")
    for lim in r.get("limits", []):
        L.append(f"- {lim}")
    L.append("- ترافیک واقعی شبکه و رفتار زمان اجرا با اسکن ایستا دیده نمی‌شود؛ "
             "برای اثبات ارسال داده، رصد ترافیک لازم است.")
    if r.get("binary", {}).get("encrypted") is True:
        L.append("- ⚠️ این IPA رمزگذاری‌شده است (FairPlay). تحلیل رشته‌ها و الگوهای API باینری بدون IPA رمزگشایی‌شده ممکن نیست.")
    if r.get("warnings"):
        L.append("")
        L.append("## هشدارها")
        for w in r["warnings"]:
            L.append(f"- ⚠️ {w}")
    L.append("")
    if r.get("errors"):
        L.append("## خطاها")
        for e in r["errors"]:
            L.append(f"- {e}")
    return "\n".join(L) + "\n"

def main(argv=None):
    ap = argparse.ArgumentParser(description="SibStar IPA scanner v6 (deep scan)")
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
