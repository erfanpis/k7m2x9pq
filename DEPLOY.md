# راهنمای اجرا و استقرار — اسکنر IPA + ربات تلگرام (نسخه ۴)

## ۱) ساخت ربات تلگرام و گرفتن API ID/Hash

ربات نسخه ۴ با MTProto کار می‌کند و به سه چیز نیاز دارد:

1. **توکن ربات** — در تلگرام به `@BotFather` بروید، `/newbot` بزنید، نام و یوزرنیم
   بدهید و توکن را کپی کنید. توکن را **هرگز** در چت، کد یا فایل نفرستید.
   اگر توکن کار نمی‌کند: در `@BotFather` دستور `/revoke` را بزنید و توکن تازه بگیرید.
2. **API ID و API HASH** — به https://my.telegram.org بروید، با شماره‌ی تلگرام خودتان
   وارد شوید، بخش «API development tools» را باز کنید و یک اپ بسازید
   (نام و پلتفرم دلخواه، مثلاً «SibStar Scanner» — iOS). `api_id` (عدد) و
   `api_hash` (رشته) را کپی کنید. این‌ها مال حساب تلگرام شماست، نه ربات؛
   همان مقادیری که لینک‌یار هم استفاده می‌کند.
3. **آیدی عددی تلگرام خودتان** — از ربات `@userinfobot` بگیرید؛ فقط همین آیدی
   در `ADMIN_USER_IDS` می‌آید تا فقط شما بتوانید از ربات استفاده کنید.

## ۲) اجرا روی کامپیوتر خودتان (ساده‌ترین راه، رایگان)

```bash
git clone https://github.com/erfanpis/k7m2x9pq.git
cd k7m2x9pq
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN='توکن-از-BotFather'
export TELEGRAM_API_ID='123456'        # عدد از my.telegram.org
export TELEGRAM_API_HASH='...'         # رشته از my.telegram.org
export ADMIN_USER_IDS='123456789'      # آیدی عددی تلگرام خودت
python3 bot.py --check-config   # اول تنظیمات را تست کنید (بدون شبکه)
python3 bot.py --check-token    # بعد توکن و اتصال را تست کنید
python3 bot.py                  # ربات شروع می‌شود و گوش می‌دهد
```

- پایتون ۳.۸ به بالا کافی است.
- تا وقتی این ترمینال باز است و کامپیوتر روشن است، ربات جواب می‌دهد.
- برای اجرای دائمی در پس‌زمینه (لینوکس):

```bash
nohup python3 bot.py > bot.log 2>&1 &
```

## ۳) اجرا ۲۴ ساعته روی گیت‌هاب اکشنز (بدون سرور جدا، مثل لینک‌یار)

ورک‌فلو `.github/workflows/bot.yml` از قبل در ریپوی `erfanpis/k7m2x9pq` هست:
با زمان‌بندی + `workflow_dispatch` اجرا می‌شود، هر جاب چند ساعت ربات را با
long-polling اجرا می‌کند و آخرش با `RESPAWN_PAT` خودش جاب بعدی را روشن می‌کند.

Secrets لازم در ریپو (Settings → Secrets and variables → Actions):

| Secret | از کجا | برای چه |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | @BotFather | توکن ربات |
| `TELEGRAM_API_ID` | my.telegram.org | ورود MTProto |
| `TELEGRAM_API_HASH` | my.telegram.org | ورود MTProto |
| `ADMIN_USER_IDS` | @userinfobot | فقط آیدی شما (مثال: `123456789`) |
| `RESPAWN_PAT` | GitHub → Settings → Developer settings → Personal access tokens (classic) با اسکوپ `workflow` | روشن کردن خودکار جاب بعدی؛ بدون آن، بعد از اولین جاب ربات متوقف می‌شود |

برای روشن کردن دستی: در گیت‌هاب بروید Actions → Telegram bot → Run workflow →
Branch: main → Run workflow. اولین اجرا را از همان‌جا چک کنید؛ اگر خطایی بود،
لاگ همان run را ببینید.

نکته: ربات فقط وقتی یک رانر گیت‌هاب اکشنز در حال اجرایش است زنده است؛
این ماشین مجازی (VM) میزبان دائمی نیست.

## ۴) تست

```bash
python3 bot.py --check-config                 # تنظیمات کامل است؟ (بدون شبکه)
python3 bot.py --check-token                  # توکن و اتصال سالم است؟
python3 bot.py --selftest test/TestGame.ipa   # خلاصه‌ی فارسی بدون تلگرام
python3 test/test_bot_offline.py              # تست آفلاین ربات نسخه ۴
python3 test/test_scanner_v3.py               # تست اسکنر نسخه ۴ + کارت PNG
python3 scanner.py test/TestGame.ipa --json test/report-v2.json --report test/report-v2.md
python3 scanner.py test/TestGame-encrypted.ipa --json test/report-v2-encrypted.json --report test/report-v2-encrypted.md
python3 report_card.py test/TestGame.ipa --out /tmp/card.png
```

## ۵) استفاده در تلگرام

1. ربات را در تلگرام باز کنید، `/start` بزنید.
2. فایل `.ipa` را بفرستید (حداکثر **۲ گیگابایت**)، یا لینک مستقیم دانلود یک
   فایل `.ipa` بدهید. ربات یک پیام پیشرفت با ۶ مرحله نشان می‌دهد (دانلود با
   درصد، استخراج، اسکن باینری، آنالیز dylib و deb، ساخت کارت و گزارش، ارسال
   و پاک کردن).
3. ربات خلاصه‌ی فارسی + کارت تصویری + گزارش کامل `.md` + داده‌ی `.json` را
   برمی‌گرداند — و **فایل IPA دانلودشده را بلافاصله بعد از اسکن حذف می‌کند**.
   پیام خلاصه با حکم دستکاری شخص ثالث و ریسک (جدا: برنامه‌ی اصلی و توئیک)
   شروع می‌شود.

## ۶) پاک‌سازی (مهم برای فایل‌های ۲ گیگابایتی)

- IPA دانلودشده، گزارش‌ها و پوشه‌ی کار اسکن فقط در یک پوشه‌ی موقت‌اند.
- بعد از ارسال گزارش، IPA حذف می‌شود؛ اگر دانلود، اسکن یا ارسال هم ناموفق
  باشد، پوشه‌ی موقت باز هم کامل پاک می‌شود.
- هیچ IPA یا گزارشی وارد ریپو نمی‌شود (`.gitignore`) و هیچ‌وقت commit نمی‌شود.
- قبل از دانلود، فضای خالی دیسک چک می‌شود؛ اگر جا نباشد، ربات با پیام فارسی
  رد می‌کند.

## ۷) عیب‌یابی

| پیام / مشکل | معنی و راه‌حل |
|---|---|
| `CONFIG ERROR: Missing ... TELEGRAM_BOT_TOKEN` | متغیر محیطی / secret ست نشده؛ بخش ۱ و ۳ را چک کنید. |
| `TELEGRAM_API_ID must be a number` | API ID باید عدد باشد (از my.telegram.org). |
| `TOKEN INVALID ...` | توکن اشتباه یا باطل شده؛ از `@BotFather` توکن تازه بگیرید (`/revoke`). |
| فایل بالای ۲ گیگابایت رد می‌شود | محدودیت تلگرام است، نه ربات. |
| لینک رد می‌شود | فقط لینک `http(s)` که مستقیماً به `.ipa` ختم شود پذیرفته می‌شود. |
| `باینری رمزگذاری‌شده است` در گزارش | IPA از اپ‌استور است (FairPlay)؛ تحلیل رشته‌های باینری ممکن نیست، بقیه‌ی گزارش معتبر است. |
| ربات جواب نمی‌دهد | چک کنید پروسه‌ی `bot.py` در حال اجراست، یا در گیت‌هاب اکشنز یک run فعال هست؛ لاگ را ببینید. |
| ربات بعد از چند ساعت خاموش شد | `RESPAWN_PAT` را چک کنید (بخش ۳)؛ بدون آن زنجیره‌ی respawn کار نمی‌کند. |
| کارت PNG ساخته نشد ولی گزارش آمد | Pillow نصب نیست (`pip install -r requirements.txt`)؛ اسکن به‌خاطر کارت متوقف نمی‌شود. |

## ۸) انتشار در گیت‌هاب (erfanpis)

ریپو: `github.com/erfanpis/k7m2x9pq` (پابلیک، اسم بی‌معنی). برای به‌روز کردن کد:

```bash
git add scanner.py bot.py report_card.py requirements.txt README.md DEPLOY.md test/
git commit -m "IPA scanner v4: calm scoring, tampering verdict, .deb, MASVS, redesigned card"
git push origin main
```

(فایل `.gitignore` جلوی commit شدن توکن، session، IPA و گزارش‌ها را می‌گیرد.)
