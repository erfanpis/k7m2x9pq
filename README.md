# اسکنر IPA + ربات تلگرام — سیب‌استار

[English summary below](#english-summary)

ربات تلگرام برای اسکن امنیت و حریم خصوصی فایل‌های `.ipa` (برنامه و بازی آیفون).
یک فایل IPA در تلگرام بفرستید، ربات آن را اسکن می‌کند و به فارسی گزارش می‌دهد:
خلاصه کوتاه در چت + گزارش کامل (`.md`) و داده (`‌.json`) به‌صورت فایل ضمیمه.

فقط با کتابخانه‌ی استاندارد پایتون نوشته شده — هیچ وابستگی پولی یا اضافه‌ای لازم نیست.

## اسکن عمیق نسخه ۲ — چه چیزی بیشتر از نسخه ۱ چک می‌شود؟

| بخش | نسخه ۱ | نسخه ۲ |
|---|---|---|
| دسترسی‌های Info.plist | ۲۷ کلید | ۳۳ کلید (سلامت بالینی، تقویم کامل، بلوتوث، Face ID، شبکه محلی، تشخیص گفتار و…) با برچسب فارسی |
| مانیفست حریم خصوصی | ❌ | ✅ `PrivacyInfo.xcprivacy`: ردیابی، دامنه‌های ردیابی، نوع داده‌های جمع‌آوری‌شده (متصل/ردیابی/اهداف)، APIهای دسترسی‌یافته و دلایلشان |
| باینری Mach-O | فقط `cryptid` | ✅ پارس کامل load commandها: کتابخانه‌های لینک‌شده، RPATH، حداقل iOS از `LC_BUILD_VERSION`، UUID، نوع CPU، FAT slices، امضای کد |
| رشته‌های باینری | فقط URL از فایل‌های کوچک | ✅ استخراج رشته‌ها + ۱۳ الگوی مشکوک (IDFA، لوکیشن، مخاطبین، کلیپ‌بورد، کی‌چین، `dlopen`، IOKit و…) — فقط وقتی باینری رمزگذاری نشده باشد |
| ترکرها | ۱۹ مورد | ✅ ۳۰+ مورد (Firebase، Facebook، AppsFlyer، Adjust، Branch، AdMob، Flurry، Mixpanel، Amplitude، Sentry، Bugsnag، OneSignal، Braze، Chartboost و…) |
| امضای کد | ❌ | ✅ پوشه `_CodeSignature` + `CodeResources` + `embedded.mobileprovision` |
| حجم باندل | ❌ | ✅ تفکیک حجم کل / باینری / فریم‌ورک‌ها |
| امتیاز ریسک | جمع ساده | ✅ امتیاز ۰ تا ۱۰۰ با **جزئیات امتیاز هر مورد** (چند امتیاز بابت چه چیزی) |
| مثبت کاذب | DTD اپل در `http://` می‌افتاد | ✅ دامنه‌ی `apple.com` از لیست ناامن حذف شد |

## محدودیت مهم — FairPlay

فایل‌های IPA دانلودشده از اپ‌استور با FairPlay رمزگذاری شده‌اند.
باینری رمزگذاری‌شده را نمی‌شود بدون رمزگشایی خواند؛ اسکنر این را تشخیص می‌دهد
(`cryptid=1`) و بخش «رشته‌های باینری» را **«در دسترس نیست»** اعلام می‌کند،
نه اینکه چیزی را جعل کند. برای تحلیل کامل باینری، به نسخه‌ی رمزگشایی‌شده نیاز است.
این پروژه هیچ راهی برای دور زدن FairPlay ادعا نمی‌کند و ندارد.

## استفاده سریع

```bash
# ۱) اسکنر خط فرمان
python3 scanner.py app.ipa --json report.json --report report.md

# ۲) ربات تلگرام (توکن هرگز داخل کد نیست)
export TELEGRAM_BOT_TOKEN='توکن-از-BotFather'
python3 bot.py

# ۳) تست توکن بدون اسکن
python3 bot.py --check-token

# ۴) تست آفلاین خلاصه‌ی ربات (بدون تلگرام)
python3 bot.py --selftest test/TestGame.ipa
python3 test/test_bot_offline.py
```

در تلگرام: فایل `.ipa` را برای ربات بفرستید. حداکثر حجم فایل در تلگرام برای ربات‌ها **۲۰ مگابایت** است؛
فایل بزرگ‌تر با پیام فارسی رد می‌شود. دستورها: `/start` و `/help`.

## ساختار ریپو

```
scanner.py                  # اسکنر عمیق نسخه ۲ (اصلی)
bot.py                      # ربات تلگرام (فقط stdlib)
requirements.txt            # خالی — فقط استاندارد پایتون
test/
  make_test_ipa_v2.py       # ساخت IPA مصنوعی تست (غنی‌تر از نسخه ۱)
  test_bot_offline.py       # تست آفلاین ربات (بدون توکن، بدون شبکه)
  TestGame.ipa              # IPA تست (رمزگذاری‌نشده) — ساخته‌شده با اسکریپت بالا
  TestGame-encrypted.ipa    # همان IPA با cryptid=1
  report-v2.json / .md       # خروجی تست
  report-v2-encrypted.json / .md
scanner_v1_reference.py     # کپی نسخه ۱ برای مرجع (دست نخورده)
README.md / DEPLOY.md / LICENSE / .gitignore
```

## تست — نتیجه‌ی واقعی

IPA مصنوعی تست (نه برنامه‌ی واقعی اپ‌استور) با `test/make_test_ipa_v2.py` ساخته و اسکن شد:

- برنامه: TestGame — `com.example.testgame`، نسخه 1.2.3، حداقل iOS 15.0 (از باینری: 16.0.0)
- **ریسک: 100/100 — بالا**
- دسترسی‌ها (۱۱): دوربین، میکروفون، موقعیت همیشه، مخاطبین، گالری، بلوتوث، سلامت، تشخیص گفتار، Face ID، شبکه محلی، ردیابی ATT
- مانیفست حریم خصوصی: ردیابی = بله، ۲ دامنه‌ی ردیابی، ۲ نوع داده با ردیابی مرتبط
- ترکرها (۶): Firebase، AppsFlyer، Amplitude، Flurry، Mixpanel، Sentry
- باینری: Mach-O ۶۴ بیتی arm64، رمزگذاری‌نشده، UUID و ۲ کتابخانه‌ی لینک‌شده، ۸ الگوی مشکوک (IDFA، لوکیشن، مخاطبین، کلیپ‌بورد، `dlopen` و…)
- دامنه‌ها: ۵ — URL ناامن `http://`: ۲

نسخه‌ی رمزگذاری‌شده هم تست شد: اسکنر درست تشخیص داد `encrypted=True, cryptid=1`،
تحلیل رشته‌ها را «در دسترس نیست» اعلام کرد و هشدار FairPlay را در گزارش آورد.

ربات هم آفلاین تست شد: `/start` راهنمای فارسی را می‌دهد، فایل غیر IPA رد می‌شود،
فایل بالای ۲۰ مگابایت با پیام حد تلگرام رد می‌شود، و خلاصه‌ی فارسی همان ریسک 100/100 را برمی‌گرداند.
تست زنده با تلگرام (دانلود فایل و ارسال گزارش) به توکن معتبر نیاز دارد — فعلاً توکن ذخیره‌شده
با خطای 404 برمی‌گردد، پس احتمالاً نامعتبر است (نگاه کنید به DEPLOY.md).

## گیت‌هاب

حساب کاربری: **erfanpis** — ریپوی پیشنهادی: `github.com/erfanpis/ipa-scanner-bot`
(هنوز push نشده؛ برای push به تایید و دسترسی خودتان نیاز است.)

## امنیت توکن

- توکن فقط از متغیر محیطی `TELEGRAM_BOT_TOKEN` خوانده می‌شود.
- توکن هرگز در کد، لاگ یا فایل‌ها ذخیره نمی‌شود.
- اگر توکن نامعتبر باشد، ربات با پیام واضح «توکن نامعتبر است؛ از BotFather توکن جدید بگیرید» متوقف می‌شود.

## <a name="english-summary"></a>English summary

A Telegram bot + deep IPA scanner for SibStar (Persian iOS App Store). Send an `.ipa`
to the bot; it replies in Persian with a risk score (0–100) summary plus full
Markdown/JSON reports. Stdlib-only Python. v2 adds: `PrivacyInfo.xcprivacy`
manifest parsing, full Mach-O load-command parsing (linked dylibs, min iOS, UUID,
FAT slices), binary-string analysis with 13 suspicious-API patterns (decrypted
binaries only), code-signature checks, 30+ tracker SDKs, and a per-item risk
breakdown. FairPlay-encrypted App Store IPAs are detected (`cryptid=1`) and the
binary-string section is honestly reported as unavailable — no FairPlay bypass
is claimed or implemented. Telegram Bot API limit: 20 MB per file.
