# دليل نشر WARAKA على Neon وRender

هذا الدليل يخص خادم التراخيص في مستودع `Redadz19/waraka`. لا ترسل كلمات المرور أو مفاتيح API أو مفاتيح التوقيع إلى المحادثة أو إلى مستودع GitHub.

## 1. إنشاء قاعدة البيانات في Neon

1. أنشئ مشروع PostgreSQL باسم `waraka-production`.
2. اختر منطقة Frankfurt إذا كانت متاحة في حسابك، لتكون قريبة من خدمة Render التي نحددها في Frankfurt.
3. أنشئ قاعدة باسم `waraka` إن لم تكن هي الافتراضية.
4. من زر **Connect** انسخ connection string، ويفضّل اختيار pooled connection string إذا أتاحته Neon.
5. احتفظ بالرابط في مكان آمن؛ فهو يحتوي على بيانات دخول قاعدة البيانات.

## 2. إنشاء خدمة Render

1. افتح Render واختر **New → Blueprint**.
2. اربط حساب GitHub واختر المستودع `Redadz19/waraka`.
3. وافق على إنشاء الخدمة المعرّفة في `render.yaml` باسم `waraka-licensing-api`.
4. تأكد أن المنطقة هي Frankfurt والخطة Free للمرحلة التجريبية.
5. أدخل المتغيرات السرية التالية في صفحة Environment للخدمة:

| المتغير | القيمة المطلوبة |
|---|---|
| `DATABASE_URL` | رابط PostgreSQL من Neon |
| `ADMIN_API_KEY` | مفتاح عشوائي طويل للإدارة |
| `OTP_SECRET` | سر عشوائي لا يقل عن 32 محرفاً |
| `LICENSE_PRIVATE_KEY_B64` | المفتاح الخاص الناتج من أداة توليد المفاتيح |
| `LICENSE_PUBLIC_KEY_B64` | المفتاح العام المقابل، ويجب أن يطابق المفتاح الخاص |
| `SMTP_HOST` | خادم SMTP للبريد |
| `SMTP_PORT` | غالباً 587 |
| `SMTP_USERNAME` | حساب SMTP |
| `SMTP_PASSWORD` | كلمة مرور أو App Password |
| `SMTP_FROM` | عنوان البريد المرسل |
| `LICENSE_SERIAL_ENCRYPTION_KEY` | مفتاح Fernet لتشفير أرقام التراخيص المخزنة |
| `CHARGILY_API_SECRET_KEY` | مفتاح Chargily السري لوضع الاختبار أولاً |
| `CHARGILY_MODE` | `test` حالياً؛ لا تغيّره إلى `live` قبل موافقة Chargily |
| `WARAKA_PRICE_DZD` | سعر الرخصة بالدينار؛ يبقى 0 إلى حين اعتماد السعر |
| `CHARGILY_FEES_ALLOCATION` | من يتحمل رسوم البوابة: `merchant` أو `customer` أو `split` |
| `PUBLIC_BASE_URL` | عنوان HTTPS الفعلي لخدمة Render |

المتغيران `OFFLINE_GRACE_DAYS` و`RECHECK_DAYS` مضبوطان افتراضياً على 14 و7 أيام في ملف Render.

## 3. توليد مفاتيح الأمان

من نسخة محلية موثوقة للمستودع شغّل:

```bash
python scripts/generate_keys.py
```

ضع `LICENSE_PRIVATE_KEY_B64` في Render فقط. سيُستخدم المفتاح العام لاحقاً داخل تطبيق Windows، ويمكن وضع نسخته في Render للتحقق من تطابق المفتاحين. لا ترفع أيّاً منهما إلى GitHub، ولا ترسلهما في المحادثة.

ولإنشاء مفتاح تشفير أرقام التراخيص التي تُحفظ مؤقتاً لإعادة إرسالها بأمان عند فشل البريد:

```bash
python scripts/generate_serial_encryption_key.py
```

ضع الناتج `LICENSE_SERIAL_ENCRYPTION_KEY` في Render secrets فقط. لا تغيّره بعد بدء إصدار التراخيص، وإلا لن يمكن فك تشفير الأرقام القديمة لإعادة إرسالها.

ولإنشاء سرّي الإدارة وOTP محلياً باستخدام Python:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

نفّذ الأمر مرتين بقيمتين مختلفتين، واحدة لـ `ADMIN_API_KEY` والأخرى لـ `OTP_SECRET`.

## 4. التحقق من النشر

بعد اكتمال النشر، افتح:

- `https://YOUR-RENDER-SERVICE.onrender.com/health`
- `https://YOUR-RENDER-SERVICE.onrender.com/v1/public-key`

يجب أن يعيد الأول حالة الخدمة، والثاني المفتاح العام. استبدل الجزء الوهمي بعنوان الخدمة الفعلي الذي يمنحه Render.

تُطبّق ترحيلات قاعدة البيانات تلقائياً قبل تشغيل الخادم. إذا فشل النشر، راجع Render Logs ولا تشارك أي قيمة سرية عند طلب المساعدة.

## 5. تهيئة Chargily Pay للاختبار

1. أنشئ حساباً في لوحة Chargily Pay، ثم أنشئ تطبيقاً من Developers Corner.
2. ابدأ في Test Mode وخذ مفتاح API السري الخاص بالاختبار.
3. ضع المفتاح في `CHARGILY_API_SECRET_KEY`، واجعل `CHARGILY_MODE=test`.
4. حدّد السعر بعد اعتماده، ثم غيّر `WARAKA_PRICE_DZD` إلى مبلغ صحيح بالدينار.
5. ضع عنوان خدمة Render الفعلي في `PUBLIC_BASE_URL`. عنوان Webhook الذي يجب إدخاله في لوحة Chargily هو:
   `https://YOUR-RENDER-SERVICE.onrender.com/v1/payments/chargily/webhook`
6. نفّذ عملية اختبار كاملة وتأكد من وصول Webhook وتوليد الرخصة والبريد.

لا تنتقل إلى Live Mode قبل اعتماد حساب التاجر والتطبيق من Chargily. يتطلب الدفع الحقيقي التحقق من حساب المستخدم ثم التحقق من التطبيق. راجع إعدادات Chargily الرسمية قبل التبديل.

## 6. ما لا يزال يتطلب إعداداً منفصلاً

- حساب SMTP فعّال لإرسال رموز OTP ورخص الشراء.
- إنشاء مشروع Neon وربطه بخدمة Render.
- تهيئة مفاتيح التوقيع والتشفير السرية في Render.
- تفعيل حساب وتطبيق Chargily للحصول على مفاتيح Live.
- ربط تطبيق Windows بعنوان API الحي والمفتاح العام.
- اختبار التفعيل، والتحقق الدوري، وفترة العمل دون اتصال.
- تكامل دولي مستقل عندما تصبح وسائل Visa وMastercard متاحة فعلياً لحساب التاجر.

## ملاحظات حول نموذج البيع

WARAKA يعتمد شراءً واحداً وترخيصاً دائماً، وليس اشتراكاً متجدداً. قيمة الشراء ستُحدد في إعدادات الدفع عند اعتماد السعر. سجل المدفوعات في قاعدة البيانات جاهز كأساس تقني، لكن بوابة الدفع وWebhook الموثّق لم يُفعّلا بعد.
