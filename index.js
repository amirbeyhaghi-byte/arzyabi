const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');

app.set('trust proxy', 1);

// ==================== هدرهای امنیتی (helmet) ====================
// توجه: این برنامه از handlerهای inline (onclick="...") و <script> داخل صفحه
// به‌شدت استفاده می‌کند، پس فعال‌سازی Content-Security-Policy پیش‌فرض همه‌ی
// آن‌ها را می‌شکند. بقیه‌ی محافظت‌های helmet (X-Frame-Options به‌عنوان
// ضدclickjacking، X-Content-Type-Options، HSTS و ...) فعال باقی می‌مانند.
app.use(helmet({ contentSecurityPolicy: false }));

// فایل‌های ثابت PWA (مانیفست، service worker، آیکون‌ها) و فایل‌های آپلودشده
// برخلاف بقیه‌ی صفحات، نه به نشست وابسته‌اند و نه تغییر می‌کنند؛ پس هم از
// قانون no-store و هم از الزام لاگین (پایین‌تر) مستثنا می‌شوند.
function isPublicAsset(reqPath) {
    return reqPath.startsWith('/uploads/') || reqPath.startsWith('/icons/') ||
        reqPath === '/manifest.json' || reqPath === '/sw.js';
}

// همه‌ی صفحات این برنامه پویا و وابسته به نشست/توکن CSRF هستند؛ اگر مرورگر
// نسخه‌ی قدیمی صفحه را از کش نمایش بدهد، توکن CSRF داخلش دیگر با نشست فعلی
// سرور هم‌خوان نیست و درخواست‌های POST با خطای CSRF رد می‌شوند. پس صریحاً
// کش کردن صفحات را (به‌جز فایل‌های ثابت PWA و فایل‌های آپلودشده) غیرفعال می‌کنیم.
app.use((req, res, next) => {
    if (!isPublicAsset(req.path)) {
        res.set('Cache-Control', 'no-store');
    }
    next();
});

app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));

// ==================== نشست (Session) ====================
const SESSION_SECRET_PATH = path.join(__dirname, 'data', '.session-secret');
function getSessionSecret() {
    if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
    try {
        if (fs.existsSync(SESSION_SECRET_PATH)) return fs.readFileSync(SESSION_SECRET_PATH, 'utf8').trim();
    } catch (e) {}
    const secret = crypto.randomBytes(32).toString('hex');
    try {
        if (!fs.existsSync(path.dirname(SESSION_SECRET_PATH))) fs.mkdirSync(path.dirname(SESSION_SECRET_PATH), { recursive: true });
        fs.writeFileSync(SESSION_SECRET_PATH, secret, { mode: 0o600 });
    } catch (e) {}
    return secret;
}
app.use(session({
    secret: getSessionSecret(),
    name: 'sid',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 8 * 60 * 60 * 1000, // ۸ ساعت
        secure: process.env.NODE_ENV === 'production'
    }
}));

// ==================== توکن CSRF ====================
// یک توکن به‌ازای هر نشست ساخته می‌شود، در تگ <meta> هر صفحه چاپ می‌شود،
// اسکریپت مشترک صفحات آن را به‌صورت خودکار به هدر هر fetch اضافه می‌کند،
// و فرم‌های خام (غیر fetch) آن را در یک input مخفی حمل می‌کنند.
app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(24).toString('hex');
    }
    next();
});
// توجه: /hr/update-organization چون multipart/form-data است، توسط
// express.json()/urlencoded() پارس نمی‌شود، پس توکن CSRF را خودش به‌صورت
// دستی از بدنه‌ی چندبخشی می‌خواند و درون همان route هندلر تایید می‌کند.
const CSRF_EXEMPT_PATHS = new Set(['/login', '/api/reset-password', '/hr/update-organization']);
// درخواست‌های fetch مبتنی بر JSON (چه زیر /api/ باشند چه نباشند، مثل
// /hr/add-unit-batch) باید همیشه پاسخ JSON بگیرند، وگرنه res.json() سمت
// کلاینت با خطای parse مواجه می‌شود و کل خطا بی‌صدا از بین می‌رود.
function wantsJson(req) {
    return req.path.startsWith('/api/') || (req.headers['content-type'] || '').includes('application/json');
}

function csrfProtection(req, res, next) {
    if (CSRF_EXEMPT_PATHS.has(req.path)) return next();
    const token = req.headers['x-csrf-token'] || req.body?._csrf;
    if (!token || token !== req.session.csrfToken) {
        if (wantsJson(req)) {
            return res.status(403).json({ success: false, message: 'درخواست نامعتبر است (CSRF). لطفاً صفحه را رفرش کنید.' });
        }
        return res.status(403).send('<h2>درخواست نامعتبر است (CSRF)</h2><p>لطفاً صفحه را رفرش کرده و دوباره تلاش کنید.</p><a href="javascript:history.back()">بازگشت</a>');
    }
    next();
}
app.use((req, res, next) => {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return csrfProtection(req, res, next);
    next();
});

// ==================== محدودسازی نرخ درخواست (Rate limiting) ====================
const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'تعداد تلاش‌ها بیش از حد مجاز است؛ لطفاً چند دقیقه دیگر دوباره تلاش کنید.' }
});

// ==================== قفل موقت حساب بعد از چند ورود ناموفق ====================
const loginAttempts = new Map(); // username -> { count, lockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
function isLockedOut(username) {
    const entry = loginAttempts.get(username);
    if (!entry || !entry.lockedUntil) return false;
    if (entry.lockedUntil <= Date.now()) { loginAttempts.delete(username); return false; }
    return true;
}
function recordFailedLogin(username) {
    const entry = loginAttempts.get(username) || { count: 0, lockedUntil: null };
    entry.count++;
    if (entry.count >= MAX_LOGIN_ATTEMPTS) {
        entry.lockedUntil = Date.now() + LOCKOUT_MS;
        entry.count = 0;
    }
    loginAttempts.set(username, entry);
}
function clearFailedLogins(username) {
    loginAttempts.delete(username);
}

// ==================== احراز هویت مبتنی بر نشست ====================
// هویت و نقش کاربر همیشه از req.session خوانده می‌شود، نه از پارامترهای URL؛
// یعنی حتی اگر کاربر آدرس را دستکاری کند، تشخیص هویت/دسترسی او تغییر نمی‌کند.
const PUBLIC_PATHS = new Set(['/', '/login', '/api/reset-password']);
app.use((req, res, next) => {
    if (PUBLIC_PATHS.has(req.path) || isPublicAsset(req.path)) return next();
    if (!req.session.user) {
        if (wantsJson(req)) return res.status(401).json({ success: false, message: 'ابتدا وارد سیستم شوید' });
        return res.redirect('/');
    }
    next();
});
function requireRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.session.user.effectiveRole)) {
            if (wantsJson(req)) return res.status(403).json({ success: false, message: 'دسترسی غیرمجاز' });
            return res.redirect('/');
        }
        next();
    };
}

// ایجاد پوشه uploads اگر وجود ندارد
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

app.use('/uploads', express.static(uploadDir));

// ==================== فایل‌های PWA (مانیفست، service worker، آیکون‌ها) ====================
app.use(express.static(path.join(__dirname, 'public')));

// ==================== دیتابیس (SQLite) ====================
// تمام داده‌ها اکنون در فایل data/app.db نگهداری می‌شوند؛ توابع کمکی db.js را ببینید.
function addLog(event, user, details = '') {
    db.Logs.add(event, user, details);
}

// ==================== توابع تبدیل اعداد فارسی/انگلیسی ====================
const PERSIAN_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
function toPersianDigits(input) {
    if (input === null || input === undefined) return '';
    return String(input).replace(/[0-9]/g, d => PERSIAN_DIGITS[d]);
}
function toEnglishDigits(input) {
    if (input === null || input === undefined) return '';
    return String(input)
        .replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
        .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
}

// ==================== جلوگیری از XSS: escape کردن متن قبل از چاپ در HTML ====================
// همه‌ی متن‌های آزادی که کاربر وارد کرده (نام، متن سوال، نام واحد/پست و ...)
// باید قبل از قرارگیری داخل HTML از این تابع عبور کنند تا کدهای اسکریپت
// احتمالی به‌صورت متن ساده نمایش داده شوند، نه اجرا شوند.
function escapeHtml(input) {
    if (input === null || input === undefined) return '';
    return String(input)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
// وقتی JSON.stringify(...) مستقیم داخل یک تگ <script> چاپ می‌شود، اگر یکی از
// مقادیر شامل رشته‌ی "</script>" باشد، مرورگر تگ اسکریپت را همان‌جا می‌بندد و
// باقی محتوا را به‌عنوان HTML اجرا می‌کند. با escape کردن کاراکتر "<" این خطر
// از بین می‌رود بدون این‌که ساختار JSON خراب شود.
function safeJson(value) {
    return JSON.stringify(value).replace(/</g, '\\u003c');
}

// ==================== هدر ثابت مشترک همه صفحات ====================
function renderTopBar(opts) {
    opts = opts || {};
    const backSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>';
    const logoutSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>';
    const userSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/></svg>';

    const action = opts.isDashboard
        ? `<button type="button" onclick="doLogout()" class="top-bar-icon-btn top-bar-logout" title="خروج از سیستم">${logoutSvg}</button>`
        : `<a href="${opts.backHref}" class="top-bar-icon-btn" title="بازگشت">${backSvg}</a>`;

    const organizationInfo = db.Organization.get();
    const brand = `<div class="top-bar-brand">${organizationInfo.logo ? `<img src="${organizationInfo.logo}" alt="logo">` : ''}<span class="top-bar-orgname">${escapeHtml(organizationInfo.name)}</span></div>`;

    let rightContent = brand;
    if (opts.isDashboard && opts.userFullname) {
        rightContent = `
            <div class="top-bar-profile">
                <div class="profile-avatar" onclick="toggleProfile()">${escapeHtml(opts.userFullname.charAt(0).toUpperCase())}</div>
                <div class="profile-dropdown" id="profileDropdown">
                    <div class="user-info">
                        <div class="name">${userSvg} ${escapeHtml(opts.userFullname)}</div>
                        <div class="position">${escapeHtml(opts.userPosition || '')}</div>
                    </div>
                    <div class="dropdown-item" onclick="location.href='/dashboard?user=${encodeURIComponent(opts.username)}&role=${encodeURIComponent(opts.role)}'">
                        <span>${userSvg}</span> نام کاربری: ${escapeHtml(opts.username)}
                    </div>
                </div>
            </div>
            ${brand}
        `;
    }

    return `<div class="top-bar"><div class="top-bar-inner">
        <div class="top-bar-left">${action}<div class="top-bar-clock" id="topBarClock"></div></div>
        <div class="top-bar-title">سامانه ارزیابی ۳۶۰ درجه کارکنان</div>
        <div class="top-bar-right">${rightContent}</div>
    </div></div>`;
}

function renderContactFooter() {
    const telegramSvg = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9.78 18.65l.28-4.23 7.68-6.92c.34-.31-.07-.46-.52-.19L7.74 13.3 3.64 12c-.88-.25-.89-.86.2-1.3l15.97-6.16c.73-.33 1.43.18 1.15 1.3l-2.72 12.81c-.19.91-.74 1.13-1.5.71l-4.14-3.05-2 1.92c-.23.23-.42.42-.82.42z"/></svg>';
    const whatsappSvg = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.5 14.4c-.3-.1-1.7-.9-2-1-.3-.1-.5-.1-.7.1-.2.3-.8 1-.9 1.1-.2.2-.3.2-.6.1-.3-.2-1.2-.4-2.3-1.4-.9-.8-1.4-1.7-1.6-2-.2-.3 0-.5.1-.6.1-.1.3-.3.4-.5.1-.1.2-.3.3-.4.1-.2 0-.4 0-.5C10.1 9 9.6 7.8 9.4 7.3c-.2-.5-.4-.4-.6-.4h-.5c-.2 0-.5.1-.7.3-.3.3-1 1-1 2.4s1 2.8 1.2 3c.1.2 2 3.1 4.9 4.3.7.3 1.2.5 1.6.6.7.2 1.3.2 1.8.1.5-.1 1.7-.7 1.9-1.3.2-.7.2-1.2.2-1.3-.1-.1-.3-.2-.6-.3z"/><path d="M12 2C6.5 2 2 6.5 2 12c0 1.9.5 3.6 1.4 5.1L2 22l5.1-1.3C8.6 21.5 10.3 22 12 22c5.5 0 10-4.5 10-10S17.5 2 12 2zm0 18c-1.6 0-3.1-.4-4.4-1.2l-.3-.2-3 .8.8-2.9-.2-.3C4.4 15 4 13.5 4 12c0-4.4 3.6-8 8-8s8 3.6 8 8-3.6 8-8 8z"/></svg>';
    const globeSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18"/><path d="M12 3a15 15 0 0 0 0 18"/></svg>';
    return `<div class="footer">
        <a href="https://t.me/Idehpardazan_ins" target="_blank" rel="noopener" class="footer-link" title="تلگرام">${telegramSvg}</a>
        <a href="https://api.whatsapp.com/send/?phone=989158121700&text&type=phone_number&app_absent=0" target="_blank" rel="noopener" class="footer-link" title="واتساپ">${whatsappSvg}</a>
        <a href="https://www.idehpardazan.org" target="_blank" rel="noopener" class="footer-link" title="وبسایت">${globeSvg}</a>
    </div>`;
}

// تابع بررسی اینکه کاربر قبلاً برای هدف مورد نظر ارزیابی ثبت کرده است
function hasUserEvaluated(evaluator, target, type) {
    return db.Evaluations.hasEvaluated(evaluator, target, type);
}

// ==================== تابع آپلود لوگو ====================
const ALLOWED_LOGO_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5MB

function parseMultipartData(req, callback) {
    let body = [];
    let totalBytes = 0;
    let aborted = false;
    req.on('data', chunk => {
        if (aborted) return;
        totalBytes += chunk.length;
        if (totalBytes > MAX_UPLOAD_BYTES) {
            aborted = true;
            callback({ error: 'حجم فایل بیش از حد مجاز (۵ مگابایت) است' });
            req.destroy();
            return;
        }
        body.push(chunk);
    });
    req.on('end', () => {
        if (aborted) return;
        const boundary = req.headers['content-type'].split('boundary=')[1];
        const buffer = Buffer.concat(body);
        const bufferStr = buffer.toString('binary');
        let result = {};

        const csrfMatch = bufferStr.match(/name="_csrf"\r\n\r\n([^\r\n]+)/);
        result._csrf = csrfMatch ? csrfMatch[1] : '';

        const nameMatch = bufferStr.match(/name="orgName"\r\n\r\n([^\r\n]+)/);
        if (nameMatch) result.orgName = decodeURIComponent(escape(nameMatch[1]));

        const fileMatch = bufferStr.match(/name="logo"; filename="([^"]+)"/);
        if (fileMatch && fileMatch[1]) {
            const fileName = fileMatch[1];
            const ext = path.extname(fileName).toLowerCase().replace(/[^a-z0-9.]/g, '');
            if (!ALLOWED_LOGO_EXTENSIONS.has(ext)) {
                return callback({ error: 'فرمت فایل مجاز نیست. فقط تصاویر PNG، JPG، GIF یا WEBP مجاز هستند' });
            }
            const newFileName = 'logo-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext;
            const fileStart = bufferStr.indexOf('\r\n\r\n', bufferStr.indexOf('name="logo"')) + 4;
            let fileEnd = bufferStr.indexOf('--' + boundary, fileStart);
            let fileContent = bufferStr.substring(fileStart, fileEnd);
            fileContent = fileContent.replace(/\r\n$/, '');
            const fileBuffer = Buffer.from(fileContent, 'binary');
            if (fileBuffer.length > MAX_UPLOAD_BYTES) {
                return callback({ error: 'حجم فایل بیش از حد مجاز (۵ مگابایت) است' });
            }
            const filePath = path.join(uploadDir, newFileName);
            fs.writeFileSync(filePath, fileBuffer);
            result.logoUrl = '/uploads/' + newFileName;
        }

        const userMatch = bufferStr.match(/name="username"\r\n\r\n([^\r\n]+)/);
        if (userMatch) result.username = userMatch[1];
        callback(result);
    });
}

// ==================== تابع همگام‌سازی کاربران از پرسنل ====================
// حساب کاربری هر پرسنل اکنون در db.Personnel.add/update به‌صورت خودکار
// ساخته/به‌روزرسانی می‌شود (رجوع کنید به db.js)، پس این تابع دیگر کاری لازم ندارد
// انجام دهد؛ به‌عنوان no-op نگه داشته شده تا فراخوانی‌های موجود نشکنند.
function syncUsersFromPersonnel() {}

// ==================== صفحات ====================

// صفحه ورود
app.get('/', (req, res) => {
    const organizationInfo = db.Organization.get();
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>ورود به سامانه</title>
            <style>
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    margin: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .login-box {
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    text-align: center;
                    width: 350px;
                    max-width: 90%;
                }
                .logo-area { margin-bottom: 20px; }
                .logo-area img { max-width: 120px; max-height: 80px; }
                h1 { color: #1A1A1A; margin-bottom: 10px; font-weight: bold; }
                .company { color: #3E9188; margin-bottom: 30px; font-weight: bold; font-size: 18px; }
                input {
                    width: 100%;
                    padding: 12px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    box-sizing: border-box;
                }
                button {
                    background: #3E9188;
                    color: white;
                    padding: 12px 30px;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-top: 10px;
                }
                button:hover { background: #2F6F68; }
                .info { margin-top: 20px; font-size: 12px; color: #888; }
                .forgot-password {
                    margin-top: 15px;
                    font-size: 14px;
                    color: #E8963E;
                    cursor: pointer;
                    text-decoration: underline;
                }
                .forgot-password:hover { color: #C97F2E; }
                .modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    justify-content: center;
                    align-items: center;
                    z-index: 1000;
                }
                .modal-content {
                    background: white;
                    padding: 30px;
                    border-radius: 15px;
                    width: 400px;
                    max-width: 90%;
                }
                .modal-content input {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    box-sizing: border-box;
                }
                .modal-content .btn {
                    background: #3E9188;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    margin: 5px;
                }
                .modal-content .btn-cancel {
                    background: #666;
                }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            .footer {
                background: #1A1A1A;
                padding: 10px 18px;
                border-radius: 999px;
                display: flex;
                align-items: center;
                gap: 14px;
                position: fixed;
                bottom: 22px;
                left: 50%;
                transform: translateX(-50%);
                box-shadow: 0 10px 28px rgba(0,0,0,0.4);
                z-index: 10;
            }
            .footer-link { display: flex; align-items: center; justify-content: center; width: 30px; height: 30px; border-radius: 50%; color: white; transition: all 0.2s ease; }
            .footer-link:hover { background: #3E9188; transform: translateY(-2px); }
            .footer-link svg { width: 16px; height: 16px; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <div class="logo-area">${organizationInfo.logo ? `<img src="${organizationInfo.logo}" alt="logo">` : ''}</div>
                <h1>سامانه ارزیابی عملکرد</h1>
                <div class="company">${escapeHtml(organizationInfo.name)}</div>
                <form method="POST" action="/login">
                    <input type="text" name="username" placeholder="نام کاربری (کد ملی)" required oninput="this.value=this.value.replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))">
                    <input type="password" name="password" placeholder="رمز عبور" required>
                    <button type="submit">ورود به سامانه</button>
                </form>
                <div class="forgot-password" onclick="showForgotPassword()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><circle cx="8" cy="15" r="4"/><path d="M10.5 12.5 20 3M17 6l3 3M14 9l2 2"/></svg> فراموشی رمز عبور</div>
                <div class="info">نام کاربری: admin<br>رمز عبور: 123456</div>
            </div>
            ${renderContactFooter()}

            <div id="forgotModal" class="modal">
                <div class="modal-content">
                    <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><circle cx="8" cy="15" r="4"/><path d="M10.5 12.5 20 3M17 6l3 3M14 9l2 2"/></svg> بازیابی رمز عبور</h2>
                    <p style="color:#666; font-size:14px;">کد ملی خود را وارد کنید تا رمز عبور جدید برای شما تنظیم شود.</p>
                    <input type="text" id="resetNationalCode" placeholder="کد ملی" maxlength="10" oninput="this.value=this.value.replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))">
                    <div>
                        <button class="btn" onclick="resetPassword()">ارسال رمز جدید</button>
                        <button class="btn btn-cancel" onclick="closeForgotModal()">انصراف</button>
                    </div>
                    <div id="resetResult" style="margin-top:15px; font-size:14px;"></div>
                </div>
            </div>

            <script>
                function showForgotPassword() {
                    document.getElementById('forgotModal').style.display = 'flex';
                    document.getElementById('resetResult').innerHTML = '';
                }
                function closeForgotModal() {
                    document.getElementById('forgotModal').style.display = 'none';
                }
                async function resetPassword() {
                    const nationalCode = document.getElementById('resetNationalCode').value;
                    const resultDiv = document.getElementById('resetResult');
                    
                    if (!nationalCode || !/^[0-9]{10}$/.test(nationalCode)) {
                        resultDiv.innerHTML = '<span style="color:#ff4444;">لطفاً کد ملی 10 رقمی خود را وارد کنید</span>';
                        return;
                    }
                    
                    try {
                        resultDiv.innerHTML = '<span style="color:#666;">در حال پردازش...</span>';
                        
                        const res = await fetch('/api/reset-password', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ nationalCode: nationalCode })
                        });
                        
                        const result = await res.json();
                        
                        if (result.success) {
                            resultDiv.innerHTML = '<span style="color:#3E9188;">رمز عبور جدید تنظیم شد!<br>رمز عبور جدید: <strong>' + result.newPassword + '</strong><br><span style="font-size:12px;">لطفاً با رمز جدید وارد شوید.</span></span>';
                            document.getElementById('resetNationalCode').value = '';
                        } else {
                            resultDiv.innerHTML = '<span style="color:#ff4444;">' + (result.message || 'خطا در بازیابی رمز عبور') + '</span>';
                        }
                    } catch (error) {
                        resultDiv.innerHTML = '<span style="color:#ff4444;">خطا در ارتباط با سرور</span>';
                    }
                }
                
                window.onclick = function(event) {
                    if (event.target === document.getElementById('forgotModal')) {
                        closeForgotModal();
                    }
                }
                
                document.getElementById('resetNationalCode').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        resetPassword();
                    }
                });
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

app.post('/login', authRateLimiter, (req, res) => {
    const username = toEnglishDigits(req.body.username);
    const password = toEnglishDigits(req.body.password);

    if (isLockedOut(username)) {
        addLog('ورود مسدود شده (قفل موقت)', username || 'نامشخص', 'به دلیل تلاش‌های ناموفق پیاپی، حساب موقتاً قفل است');
        return res.send('<h2 style="color: red;">به دلیل تلاش‌های ناموفق پیاپی، این حساب موقتاً قفل شده است. چند دقیقه دیگر دوباره تلاش کنید.</h2><a href="/">بازگشت</a>');
    }

    const account = db.Accounts.verifyLogin(username, password);
    if (account) {
        clearFailedLogins(username);
        req.session.regenerate((err) => {
            if (err) return res.status(500).send('خطای سرور، لطفاً دوباره تلاش کنید.');
            // regenerate() یک نشست کاملاً خالی می‌سازد، پس توکن CSRF قبلی از بین
            // می‌رود و باید همین‌جا دوباره ساخته شود، نه اینکه منتظر درخواست بعدی بمانیم.
            req.session.csrfToken = crypto.randomBytes(24).toString('hex');
            const effectiveRole = account.role === 'admin' ? 'admin' : (account.accessLevel || 'normal');
            req.session.user = {
                username: account.username,
                role: account.role,
                accessLevel: account.accessLevel,
                effectiveRole,
                fullname: account.fullname
            };
            if (account.role === 'admin') {
                addLog('ورود به سیستم', username, 'ورود با حساب ادمین');
            } else {
                addLog('ورود به سیستم', username, 'ورود با حساب کاربری (سطح: ' + effectiveRole + ')');
            }
            req.session.save(() => {
                res.redirect("/dashboard?user=" + username + "&role=" + effectiveRole);
            });
        });
        return;
    }

    recordFailedLogin(username);
    addLog('تلاش ناموفق برای ورود', username || 'نامشخص', 'رمز عبور یا نام کاربری اشتباه');
    res.send('<h2 style="color: red;">نام کاربری یا رمز عبور اشتباه است!</h2><a href="/">بازگشت</a>');
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// صفحه داشبورد اصلی
app.get('/dashboard', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    let isManagement = false;

    if (role === 'admin') {
        isManagement = true;
    } else {
        isManagement = (role === 'management');
    }

    const user = db.Accounts.findByUsername(username);
    if (!user) return res.redirect('/');
    
    const now = new Date();
    const time = now.toLocaleTimeString('fa-IR');
    const date = now.toLocaleDateString('fa-IR');
    
    let menuItems = '';
    if (role === 'admin') {
        menuItems = `
            <div class="icon-card" onclick="location.href='/hr?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 21V5a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v16"/><path d="M17 21V10a1 1 0 0 0-1-1h-2"/><path d="M3 21h18"/><path d="M9 8h1M9 11h1M9 14h1M9 17h1"/></svg></div>
                <div class="icon-title">واحد منابع انسانی</div>
                <div class="icon-desc">مدیریت پرسنل و چارت</div>
            </div>
            <div class="icon-card" onclick="location.href='/exam/general?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg></div>
                <div class="icon-title">شروع ارزیابی عمومی</div>
                <div class="icon-desc">ارزیابی ۳۶۰ درجه عمومی</div>
            </div>
            <div class="icon-card" onclick="location.href='/exam/specialized?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg></div>
                <div class="icon-title">شروع ارزیابی تخصصی</div>
                <div class="icon-desc">ارزیابی ۳۶۰ درجه تخصصی</div>
            </div>
        `;
    } else if (isManagement) {
        menuItems = `
            <div class="icon-card" onclick="location.href='/hr?user=${username}&role=management'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 21V5a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v16"/><path d="M17 21V10a1 1 0 0 0-1-1h-2"/><path d="M3 21h18"/><path d="M9 8h1M9 11h1M9 14h1M9 17h1"/></svg></div>
                <div class="icon-title">واحد منابع انسانی</div>
                <div class="icon-desc">مدیریت پرسنل و چارت</div>
            </div>
            <div class="icon-card" onclick="location.href='/exam/general?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg></div>
                <div class="icon-title">شروع ارزیابی عمومی</div>
                <div class="icon-desc">ارزیابی ۳۶۰ درجه عمومی</div>
            </div>
            <div class="icon-card" onclick="location.href='/exam/specialized?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg></div>
                <div class="icon-title">شروع ارزیابی تخصصی</div>
                <div class="icon-desc">ارزیابی ۳۶۰ درجه تخصصی</div>
            </div>
        `;
    } else {
        menuItems = `
            <div class="icon-card" onclick="location.href='/exam/general?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg></div>
                <div class="icon-title">شروع ارزیابی عمومی</div>
                <div class="icon-desc">ارزیابی ۳۶۰ درجه عمومی</div>
            </div>
            <div class="icon-card" onclick="location.href='/exam/specialized?user=${username}&role=${role}'">
                <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg></div>
                <div class="icon-title">شروع ارزیابی تخصصی</div>
                <div class="icon-desc">ارزیابی ۳۶۰ درجه تخصصی</div>
            </div>
        `;
    }
    
    const userFullname = user.fullname || username;
    const userPosition = user.position || 'کاربر';
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>داشبورد - ارزیابی 360 درجه</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    overflow-x: hidden;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                    display: flex;
                    flex-direction: column;
                    padding-top: 76px;
                }
                .header {
                    background: rgba(255,255,255,0.95);
                    padding: 15px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    flex-wrap: wrap;
                    gap: 10px;
                }
                .logo-header { display: flex; align-items: center; gap: 15px; }
                .logo-header img { max-height: 40px; }
                .company-name { font-size: 1rem; color: #3E9188; font-weight: bold; }
                .welcome-message { 
                    font-size: 1rem; 
                    color: #1A1A1A; 
                    font-weight: bold; 
                    text-align: center; 
                    flex: 1;
                    min-width: 150px;
                }
                .profile-menu {
                    position: relative;
                    display: inline-block;
                    flex-shrink: 0;
                }
                .profile-avatar {
                    width: 45px;
                    height: 45px;
                    border-radius: 50%;
                    background: #3E9188;
                    color: white;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 20px;
                    font-weight: bold;
                    cursor: pointer;
                    border: 2px solid #fff;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                    transition: 0.3s;
                }
                .profile-avatar:hover {
                    transform: scale(1.05);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                }
                .profile-dropdown {
                    display: none;
                    position: absolute;
                    left: 0;
                    top: 55px;
                    background: white;
                    min-width: 220px;
                    border-radius: 12px;
                    box-shadow: 0 8px 25px rgba(0,0,0,0.2);
                    padding: 10px 0;
                    z-index: 1000;
                }
                .profile-dropdown.show {
                    display: block;
                }
                .profile-dropdown .user-info {
                    padding: 12px 20px;
                    border-bottom: 1px solid #eee;
                    margin-bottom: 5px;
                }
                .profile-dropdown .user-info .name {
                    font-weight: bold;
                    color: #1A1A1A;
                    font-size: 14px;
                }
                .profile-dropdown .user-info .position {
                    color: #666;
                    font-size: 12px;
                    margin-top: 3px;
                }
                .profile-dropdown .dropdown-item {
                    padding: 10px 20px;
                    color: #1A1A1A;
                    text-decoration: none;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    cursor: pointer;
                    transition: 0.2s;
                }
                .profile-dropdown .dropdown-item:hover {
                    background: #f5f5f5;
                }
                .profile-dropdown .dropdown-item.logout {
                    color: #ff4444;
                    border-top: 1px solid #eee;
                    margin-top: 5px;
                }
                .profile-dropdown .dropdown-item.logout:hover {
                    background: #ffebee;
                }
                .icons-container {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 40px;
                    padding: 60px 20px;
                    flex-wrap: wrap;
                    flex: 1;
                }
                .sync-toast {
                    position: fixed;
                    bottom: 28px;
                    left: 50%;
                    transform: translateX(-50%) translateY(20px);
                    background: #1A1A1A;
                    color: white;
                    padding: 14px 24px;
                    border-radius: 999px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    font-size: 14px;
                    font-weight: 600;
                    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
                    z-index: 3000;
                    opacity: 0;
                    pointer-events: none;
                    transition: opacity 0.3s ease, transform 0.3s ease;
                }
                .sync-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
                .sync-toast svg { width: 20px; height: 20px; color: #3E9188; flex-shrink: 0; }
                .welcome-toast { top: 90px; bottom: auto; transform: translateX(-50%) translateY(-20px); }
                .welcome-toast.show { transform: translateX(-50%) translateY(0); }
                .icon-card {
                    background: white;
                    width: 260px;
                    padding: 40px 24px;
                    border-radius: 20px;
                    text-align: center;
                    cursor: pointer;
                    transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
                    box-shadow: 0 10px 30px rgba(26,26,26,0.12);
                    border: 1px solid rgba(26,26,26,0.05);
                }
                .icon-card:hover { transform: translateY(-8px); box-shadow: 0 16px 36px rgba(26,26,26,0.18); border-color: rgba(62,145,136,0.35); }
                .icon {
                    width: 76px;
                    height: 76px;
                    margin: 0 auto 18px;
                    border-radius: 50%;
                    background: rgba(62,145,136,0.12);
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .icon svg { width: 36px; height: 36px; }
                .icon-title { font-size: 1.3rem; font-weight: 700; color: #1A1A1A; margin-bottom: 10px; }
                .icon-desc { font-size: 0.85rem; color: #666; }
                .footer {
                    background: #1A1A1A;
                    padding: 10px 18px;
                    border-radius: 999px;
                    display: flex;
                    align-items: center;
                    gap: 14px;
                    position: fixed;
                    bottom: 22px;
                    left: 50%;
                    transform: translateX(-50%);
                    box-shadow: 0 10px 28px rgba(0,0,0,0.4);
                    z-index: 10;
                }
                .footer-link { display: flex; align-items: center; justify-content: center; width: 30px; height: 30px; border-radius: 50%; color: white; transition: all 0.2s ease; }
                .footer-link:hover { background: #3E9188; transform: translateY(-2px); }
                .footer-link svg { width: 16px; height: 16px; }
                @media (max-width: 768px) {
                    .header { padding: 10px 15px; }
                    .welcome-message { font-size: 0.85rem; order: 3; width: 100%; text-align: center; }
                    .icons-container { gap: 20px; padding: 40px 15px; }
                    .icon-card { width: 200px; padding: 28px 16px; }
                    .icon { width: 64px; height: 64px; }
                    .icon svg { width: 30px; height: 30px; }
                    .icon-title { font-size: 1.1rem; }
                    .profile-dropdown { min-width: 200px; }
                }
                @media (max-width: 480px) {
                    .icon-card { width: 100%; max-width: 280px; }
                    .profile-avatar { width: 38px; height: 38px; font-size: 16px; }
                    .profile-dropdown { min-width: 180px; }
                }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ isDashboard: true, userFullname, userPosition, username, role })}
            <div class="icons-container">
                ${menuItems}
            </div>
            <div id="welcomeToast" class="sync-toast welcome-toast">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 5-5"/></svg>
                <span>به سامانه ارزیابی عملکرد ۳۶۰ درجه پرسنل خوش آمدید</span>
            </div>

            <script>
                function toggleProfile() {
                    document.getElementById('profileDropdown').classList.toggle('show');
                }
                window.onclick = function(event) {
                    if (!event.target.closest('.top-bar-profile')) {
                        document.getElementById('profileDropdown').classList.remove('show');
                    }
                }
                (function() {
                    var toast = document.getElementById('welcomeToast');
                    if (!toast) return;
                    setTimeout(function() { toast.classList.add('show'); }, 300);
                    setTimeout(function() { toast.classList.remove('show'); }, 4000);
                })();
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== صفحه اصلی منابع انسانی ====================
app.get('/hr', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const user = db.Accounts.findByUsername(username);
    if (!user) return res.redirect('/');

    const reportsIcon = role === 'admin' ? `
        <div class="icon-card" onclick="location.href='/system-reports?user=${username}&role=${role}'">
            <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg></div>
            <div class="icon-title">گزارش سیستم</div>
            <div class="icon-desc">مشاهده لاگ‌های فعالیت‌های سیستم</div>
        </div>
    ` : '';
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>منابع انسانی</title>
            <style>
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    margin: 0;
                    padding: 20px;
                    padding-top: 100px;
                    min-height: 100vh;
                    overflow-x: hidden;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .container { max-width: 1400px; margin: 0 auto; }
                .header {
                    background: rgba(255,255,255,0.95);
                    padding: 20px;
                    border-radius: 15px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin-bottom: 40px;
                    flex-wrap: wrap;
                    gap: 10px;
                }
                .welcome-message { font-size: 1.2rem; color: #1A1A1A; font-weight: bold; text-align: center; flex: 1; min-width: 150px; }
                .back-btn { background: #666; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; flex-shrink: 0; }
                .icons-grid {
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 25px;
                    margin: 40px 0;
                }
                .icon-card {
                    background: white;
                    padding: 32px 16px;
                    border-radius: 20px;
                    text-align: center;
                    cursor: pointer;
                    transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
                    box-shadow: 0 10px 30px rgba(26,26,26,0.12);
                    border: 1px solid rgba(26,26,26,0.05);
                }
                .icon-card:hover { transform: translateY(-8px); box-shadow: 0 16px 36px rgba(26,26,26,0.18); border-color: rgba(62,145,136,0.35); }
                .icon {
                    width: 60px;
                    height: 60px;
                    margin: 0 auto 14px;
                    border-radius: 50%;
                    background: rgba(62,145,136,0.12);
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .icon svg { width: 28px; height: 28px; }
                .icon-title { font-size: 1.1rem; font-weight: 700; color: #1A1A1A; margin-bottom: 8px; }
                .icon-desc { font-size: 0.75rem; color: #666; }
                .badge-coming {
                    display: inline-block;
                    background: #F2B90D;
                    color: #1A1A1A;
                    font-size: 0.7rem;
                    padding: 3px 8px;
                    border-radius: 20px;
                    margin-top: 10px;
                }
                .footer {
                    background: #1A1A1A;
                    padding: 10px 18px;
                    border-radius: 999px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 14px;
                    margin: 40px auto 0;
                    width: fit-content;
                    box-shadow: 0 8px 20px rgba(0,0,0,0.25);
                }
                .footer-link { display: flex; align-items: center; justify-content: center; width: 30px; height: 30px; border-radius: 50%; color: white; transition: all 0.2s ease; }
                .footer-link:hover { background: #3E9188; transform: translateY(-2px); }
                .footer-link svg { width: 16px; height: 16px; }
                @media (max-width: 1200px) { .icons-grid { grid-template-columns: repeat(3, 1fr); } }
                @media (max-width: 768px) { .icons-grid { grid-template-columns: repeat(2, 1fr); } .header { flex-direction: column; text-align: center; } .welcome-message { font-size: 1rem; } }
                @media (max-width: 500px) { .icons-grid { grid-template-columns: 1fr; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/dashboard?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="icons-grid">
                    <div class="icon-card" onclick="location.href='/hr/organization?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10l9-6 9 6"/><path d="M4 10v10M9 10v10M15 10v10M20 10v10"/><path d="M2 20h20"/></svg></div>
                        <div class="icon-title">تعریف اطلاعات سازمان</div>
                        <div class="icon-desc">تعریف مشخصات، واحدها و پستهای سازمانی</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/hr/personnel/add?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="8" r="4"/><path d="M2 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/><path d="M19 8v4M17 10h4"/></svg></div>
                        <div class="icon-title">تعریف پرسنل</div>
                        <div class="icon-desc">ثبت اطلاعات پرسنل جدید</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/hr/personnel/list?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg></div>
                        <div class="icon-title">لیست پرسنل</div>
                        <div class="icon-desc">مشاهده و جستجوی پرسنل</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/hr/general-questions?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></div>
                        <div class="icon-title">ثبت سوالات ارزیابی عمومی</div>
                        <div class="icon-desc">تعریف سوالات ارزیابی عمومی</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/hr/specialized-questions?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M2 9l10-5 10 5-10 5-10-5Z"/><path d="M6 11v5c0 1.5 2.7 3 6 3s6-1.5 6-3v-5"/><path d="M22 9v6"/></svg></div>
                        <div class="icon-title">ثبت سوالات ارزیابی تخصصی</div>
                        <div class="icon-desc">تعریف سوالات تخصصی بر اساس پست</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/user-management?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z"/><path d="M9.5 12l1.8 1.8L14.8 10"/></svg></div>
                        <div class="icon-title">اطلاعات وضعیت کاربران</div>
                        <div class="icon-desc">نام کاربری، رمز عبور و سطح دسترسی ها</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/exam/results?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg></div>
                        <div class="icon-title">کارنامه ارزیابی فردی</div>
                        <div class="icon-desc">مشاهده کارنامه عملکرد هر پرسنل</div>
                    </div>
                    
                    <div class="icon-card" onclick="location.href='/exam/reports?user=${username}&role=${role}'">
                        <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M15 7h6v6"/></svg></div>
                        <div class="icon-title">گزارش‌های کلی ارزیابی</div>
                        <div class="icon-desc">گزارش‌های تجمیعی و تحلیلی</div>
                    </div>
                    
                    ${reportsIcon}
                </div>
            </div>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== صفحه گزارش سیستم (فقط ادمین) ====================
app.get('/system-reports', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin') return res.redirect('/');
    
    let rows = '';
    const logCount = db.Logs.count();
    const logs = db.Logs.list(100);
    for (const log of logs) {
        rows += '<tr>';
        rows += '<td style="text-align:center;">' + toPersianDigits(log.id) + '</td>';
        rows += '<td style="text-align:center;">' + log.date + '</td>';
        rows += '<td style="text-align:center;">' + log.time + '</td>';
        rows += '<td style="text-align:right;">' + escapeHtml(log.event) + '</td>';
        rows += '<td style="text-align:center;">' + escapeHtml(toPersianDigits(log.user)) + '</td>';
        rows += '<td style="text-align:right; font-size:12px; color:#666;">' + escapeHtml(toPersianDigits(log.details || '')) + '</td>';
        rows += '</tr>';
    }
    
    if (logs.length === 0) {
        rows = '<tr><td colspan="6" style="text-align:center; padding:30px;">هیچ گزارشی ثبت نشده است</td></tr>';
    }
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>گزارش سیستم</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                h1 { color: #1A1A1A; font-weight: bold; }
                .stats { background: #E6F2F0; padding: 10px; border-radius: 6px; margin: 15px 0; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
                th, td { padding: 12px 14px; border-bottom: 1px solid #eee; }
                th { background: #3E9188; color: white; text-align: center; padding: 14px 12px; font-weight: 600; letter-spacing: 0.3px; }
                tbody tr { transition: background 0.15s ease; }
                tbody tr:nth-child(even) { background: #FAFBFB; }
                tbody tr:hover { background: #EFF7F6; }
                .table-container { max-height: 500px; overflow-y: auto; overflow-x: hidden; border: 1px solid #eee; border-radius: 12px; }
                .filter-box { display: flex; gap: 10px; margin: 15px 0; flex-wrap: wrap; }
                .filter-box input, .filter-box select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; margin: 0; }
                .filter-box input[type="text"] { flex: 3 1 220px; }
                .filter-box .custom-date-wrap { flex: 1.5 1 160px; }
                .filter-box .btn { flex: 1 1 130px; white-space: nowrap; }
                .custom-date-wrap { position: relative; }
                .date-trigger { width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; background: white; cursor: pointer; font-family: inherit; font-size: 14px; display: flex; align-items: center; justify-content: space-between; gap: 8px; color: #1A1A1A; }
                .date-trigger:hover { border-color: #3E9188; }
                .date-trigger.open { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,0.15); }
                .date-calendar {
                    display: none; position: absolute; top: calc(100% + 6px); right: 0; z-index: 2000;
                    background: white; border-radius: 14px; border: 1px solid #eee; box-shadow: 0 14px 34px rgba(0,0,0,0.2);
                    padding: 14px; width: 260px;
                }
                .date-calendar.open { display: block; animation: csFadeIn .15s ease; }
                .dc-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
                .dc-header .dc-title { font-weight: 700; font-size: 14px; }
                .dc-nav { width: 28px; height: 28px; border-radius: 50%; border: none; background: #F4F1EC; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all .15s ease; }
                .dc-nav:hover { background: #3E9188; color: white; }
                .dc-nav svg { width: 14px; height: 14px; }
                .dc-weekdays, .dc-days { display: grid; grid-template-columns: repeat(7, 1fr); gap: 3px; text-align: center; }
                .dc-weekdays span { font-size: 11px; color: #888; padding: 4px 0; }
                .dc-day { padding: 6px 0; border-radius: 8px; cursor: pointer; font-size: 13px; transition: background .12s ease; }
                .dc-day:hover { background: #F0F7F6; }
                .dc-day.dc-empty { cursor: default; }
                .dc-day.dc-empty:hover { background: none; }
                .dc-day.dc-today { border: 1px solid #3E9188; }
                .dc-day.dc-selected { background: #3E9188; color: white; font-weight: 700; }
                .dc-footer { display: flex; gap: 8px; margin-top: 10px; }
                .dc-footer button { flex: 1; padding: 7px; border-radius: 8px; border: none; cursor: pointer; font-size: 12px; font-weight: 600; }
                .dc-today-btn { background: #E6F2F0; color: #3E9188; }
                .dc-clear-btn { background: #f5f5f5; color: #666; }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; }
                .btn-clear { background: #F2B90D; color: #1A1A1A; }
                .log-count { font-size: 14px; color: #666; margin-top: 10px; }
                @media (max-width: 768px) { .container { padding: 15px; } table { font-size: 12px; } th, td { padding: 6px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg></div><h1>گزارش سیستم</h1></div>
                <div class="stats"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل رویدادهای ثبت شده: ${toPersianDigits(logCount)}</div>

                <div class="filter-box">
                    <input type="text" id="searchInput" placeholder="جستجو در رویدادها..." onkeyup="filterLogs()">
                    <div class="custom-date-wrap" id="dateFilterWrap">
                        <button type="button" class="cs-trigger date-trigger" id="dateFilterTrigger" onclick="toggleDateCalendar()">
                            <span class="cs-label">انتخاب تاریخ</span>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;flex-shrink:0;"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>
                        </button>
                        <input type="hidden" id="dateFilter">
                        <div class="date-calendar" id="dateCalendar"></div>
                    </div>
                    <button class="btn" onclick="filterLogs()">جستجو</button>
                    <button class="btn btn-clear" onclick="clearFilters()">پاک کردن فیلتر</button>
                    <button class="btn btn-clear" onclick="clearLogs()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg> پاک کردن همه</button>
                </div>
                
                <div class="table-container">
                    <table id="logsTable">
                        <thead><tr><th>#</th><th>تاریخ</th><th>ساعت</th><th>رویداد</th><th>کاربر</th><th>جزئیات</th></tr></thead>
                        <tbody id="tableBody">${rows}</tbody>
                    </table>
                </div>
                <div class="log-count">نمایش ${toPersianDigits(logs.length)} از ${toPersianDigits(logCount)} رویداد</div>
            </div>
            
            <script>
                function toFa(n) { return String(n).replace(/[0-9]/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]); }

                function gregorianToJalali(gy, gm, gd) {
                    var g_d_m = [0,31,59,90,120,151,181,212,243,273,304,334];
                    var jy = (gy <= 1600) ? 0 : 979;
                    gy -= (gy <= 1600) ? 621 : 1600;
                    var gy2 = (gm > 2) ? (gy + 1) : gy;
                    var days = (365*gy) + (Math.floor((gy2+3)/4)) - (Math.floor((gy2+99)/100)) + (Math.floor((gy2+399)/400)) - 80 + gd + g_d_m[gm-1];
                    jy += 33*Math.floor(days/12053);
                    days %= 12053;
                    jy += 4*Math.floor(days/1461);
                    days %= 1461;
                    if (days > 365) { jy += Math.floor((days-1)/365); days = (days-1)%365; }
                    var jm, jd;
                    if (days < 186) { jm = 1 + Math.floor(days/31); jd = 1 + (days%31); }
                    else { jm = 7 + Math.floor((days-186)/30); jd = 1 + ((days-186)%30); }
                    return [jy, jm, jd];
                }
                function jalaliToGregorian(jy, jm, jd) {
                    var gy = (jy <= 979) ? 621 : 1600;
                    jy -= (jy <= 979) ? 0 : 979;
                    var days = (365*jy) + (Math.floor(jy/33)*8) + Math.floor(((jy%33)+3)/4) + 78 + jd + ((jm < 7) ? (jm-1)*31 : ((jm-7)*30)+186);
                    gy += 400*Math.floor(days/146097);
                    days %= 146097;
                    if (days > 36524) {
                        days--;
                        gy += 100*Math.floor(days/36524);
                        days %= 36524;
                        if (days >= 365) days++;
                    }
                    gy += 4*Math.floor(days/1461);
                    days %= 1461;
                    if (days > 365) { gy += Math.floor((days-1)/365); days = (days-1)%365; }
                    var gd = days + 1;
                    var isLeap = (gy%4===0 && gy%100!==0) || (gy%400===0);
                    var sal_a = [0,31, isLeap?29:28,31,30,31,30,31,31,30,31,30,31];
                    var gm;
                    for (gm = 0; gm < 13; gm++) {
                        var v = sal_a[gm];
                        if (gd <= v) break;
                        gd -= v;
                    }
                    return new Date(gy, gm-1, gd);
                }
                var JALALI_MONTHS = ['فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'];
                var JALALI_WEEKDAYS = ['ش','ی','د','س','چ','پ','ج'];
                function isLeapJalali(jy) { return ((((jy - (jy > 0 ? 474 : 473)) % 2820) + 474 + 38) * 682 % 2816) < 682; }
                var todayJ = gregorianToJalali(new Date().getFullYear(), new Date().getMonth()+1, new Date().getDate());
                var calView = { jy: todayJ[0], jm: todayJ[1] };
                var selectedJ = null;

                function toggleDateCalendar() {
                    var cal = document.getElementById('dateCalendar');
                    var trigger = document.getElementById('dateFilterTrigger');
                    var willOpen = !cal.classList.contains('open');
                    cal.classList.toggle('open', willOpen);
                    trigger.classList.toggle('open', willOpen);
                    if (willOpen) renderCalendar();
                }
                function renderCalendar() {
                    var cal = document.getElementById('dateCalendar');
                    var firstOfMonthG = jalaliToGregorian(calView.jy, calView.jm, 1);
                    var startWeekday = (firstOfMonthG.getDay() + 1) % 7;
                    var daysInMonth = (calView.jm <= 6) ? 31 : (calView.jm <= 11 ? 30 : (isLeapJalali(calView.jy) ? 30 : 29));
                    var html = '<div class="dc-header">' +
                        '<button type="button" class="dc-nav" onclick="calNav(1)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6l-6 6 6 6"/></svg></button>' +
                        '<span class="dc-title">' + JALALI_MONTHS[calView.jm-1] + ' ' + toFa(calView.jy) + '</span>' +
                        '<button type="button" class="dc-nav" onclick="calNav(-1)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></button>' +
                        '</div><div class="dc-weekdays">' + JALALI_WEEKDAYS.map(function(w){return '<span>'+w+'</span>';}).join('') + '</div><div class="dc-days">';
                    for (var i = 0; i < startWeekday; i++) html += '<div class="dc-day dc-empty"></div>';
                    for (var d = 1; d <= daysInMonth; d++) {
                        var cls = 'dc-day';
                        if (calView.jy === todayJ[0] && calView.jm === todayJ[1] && d === todayJ[2]) cls += ' dc-today';
                        if (selectedJ && selectedJ[0] === calView.jy && selectedJ[1] === calView.jm && selectedJ[2] === d) cls += ' dc-selected';
                        html += '<div class="' + cls + '" onclick="selectDay(' + d + ')">' + toFa(d) + '</div>';
                    }
                    html += '</div><div class="dc-footer"><button type="button" class="dc-today-btn" onclick="selectToday()">امروز</button><button type="button" class="dc-clear-btn" onclick="clearDate()">پاک کردن</button></div>';
                    cal.innerHTML = html;
                }
                function calNav(dir) {
                    calView.jm += dir;
                    if (calView.jm > 12) { calView.jm = 1; calView.jy++; }
                    if (calView.jm < 1) { calView.jm = 12; calView.jy--; }
                    renderCalendar();
                }
                function selectDay(d) {
                    selectedJ = [calView.jy, calView.jm, d];
                    var label = calView.jy + '/' + calView.jm + '/' + d;
                    document.getElementById('dateFilter').value = toFa(label);
                    document.getElementById('dateFilterTrigger').querySelector('.cs-label').textContent = toFa(label);
                    toggleDateCalendar();
                    filterLogs();
                }
                function selectToday() { calView = { jy: todayJ[0], jm: todayJ[1] }; selectDay(todayJ[2]); }
                function clearDate() {
                    selectedJ = null;
                    document.getElementById('dateFilter').value = '';
                    document.getElementById('dateFilterTrigger').querySelector('.cs-label').textContent = 'انتخاب تاریخ';
                    toggleDateCalendar();
                    filterLogs();
                }
                document.addEventListener('click', function(e) {
                    var wrap = document.getElementById('dateFilterWrap');
                    if (wrap && !wrap.contains(e.target)) {
                        document.getElementById('dateCalendar').classList.remove('open');
                        document.getElementById('dateFilterTrigger').classList.remove('open');
                    }
                });

                function filterLogs() {
                    const search = document.getElementById('searchInput').value.toLowerCase();
                    const date = document.getElementById('dateFilter').value;
                    const rows = document.getElementById('tableBody').getElementsByTagName('tr');
                    let visible = 0;
                    for (let i = 0; i < rows.length; i++) {
                        const row = rows[i];
                        let show = true;
                        const cells = row.getElementsByTagName('td');
                        if (cells.length > 0) {
                            const eventText = cells[3]?.innerText?.toLowerCase() || '';
                            const detailText = cells[5]?.innerText?.toLowerCase() || '';
                            const dateText = cells[1]?.innerText || '';
                            if (search && !eventText.includes(search) && !detailText.includes(search)) show = false;
                            if (date && !dateText.includes(date)) show = false;
                        }
                        if (show) { row.style.display = ''; visible++; } else { row.style.display = 'none'; }
                    }
                    document.querySelector('.log-count').innerHTML = 'نمایش ' + toFa(visible) + ' از ' + toFa(${logCount}) + ' رویداد';
                }
                function clearFilters() { document.getElementById('searchInput').value = ''; document.getElementById('dateFilter').value = ''; selectedJ = null; document.getElementById('dateFilterTrigger').querySelector('.cs-label').textContent = 'انتخاب تاریخ'; filterLogs(); }
                async function clearLogs() {
                    if (!confirm('آیا از پاک کردن تمام گزارش‌ها مطمئن هستید؟')) return;
                    const res = await fetch('/api/clear-logs', { method: 'POST' });
                    const result = await res.json();
                    if (result.success) { alert('تمام گزارش‌ها پاک شدند'); location.reload(); } else alert('خطا در پاک کردن گزارش‌ها');
                }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API پاک کردن لاگ‌ها ====================
app.post('/api/clear-logs', requireRole('admin'), (req, res) => {
    db.Logs.clear();
    res.json({ success: true });
});

// ==================== صفحه مدیریت وضعیت کاربران ====================
app.get('/user-management', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const personnelAccounts = db.Accounts.listPersonnelAccounts();

    let rows = '';
    for (const user of personnelAccounts) {
        const nationalCode = user.nationalCode;
        const currentAccessLevel = user.accessLevel || 'normal';
        const selectedNormal = (currentAccessLevel === 'normal') ? 'selected' : '';
        const selectedManagement = (currentAccessLevel === 'management') ? 'selected' : '';
        const selectedOrganizational = (currentAccessLevel === 'organizational') ? 'selected' : '';
        
        rows += '<tr>';
        rows += '<td style="text-align:center">' + escapeHtml(user.fullname) + '</td>';
        rows += '<td style="text-align:center">' + escapeHtml(toPersianDigits(user.personnelCode || '-')) + '</td>';
        rows += '<td style="text-align:center">' + escapeHtml(user.unit || '-') + '</td>';
        rows += '<td style="text-align:center">' + escapeHtml(user.position || '-') + '</td>';
        rows += '<td style="text-align:center">' + escapeHtml(toPersianDigits(nationalCode)) + '</td>';
        rows += '<td style="text-align:center"><div class="cell-actions">';
        rows += '<input type="password" id="pass_' + nationalCode + '" value="" placeholder="' + (user.hasPassword ? 'رمز جدید (اختیاری)' : 'هنوز رمزی تنظیم نشده') + '" autocomplete="new-password">';
        rows += '<button class="btn-save" onclick="savePassword(\'' + nationalCode + '\')">ذخیره</button>';
        rows += '</div></td>';
        rows += '<td style="text-align:center"><div class="cell-actions">';
        rows += '<select id="level_' + nationalCode + '">';
        rows += '<option value="normal" ' + selectedNormal + '>عادی</option>';
        rows += '<option value="management" ' + selectedManagement + '>مدیریتی</option>';
        rows += '<option value="organizational" ' + selectedOrganizational + '>سازمانی</option>';
        rows += '</select>';
        rows += '<button class="btn-save-level" onclick="saveAccessLevel(\'' + nationalCode + '\')">ذخیره</button>';
        rows += '</div></td>';
        rows += '</tr>';
    }
    
    if (personnelAccounts.length === 0) {
        rows = '<tr><td colspan="7" style="text-align:center; padding:30px;">هیچ پرسنلی تعریف نشده است. ابتدا در بخش لیست پرسنل، پرسنل را تعریف کنید.</td></tr>';
    }
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>مدیریت کاربران</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1400px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .header-buttons { text-align: right; margin-bottom: 20px; }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-size: 14px; font-weight: 600; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-save { background: #E8963E; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; flex-shrink: 0; white-space: nowrap; }
                .btn-save-level { background: #F2B90D; color: #1A1A1A; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; flex-shrink: 0; white-space: nowrap; }
                .cell-actions { display: flex; align-items: center; justify-content: center; gap: 6px; flex-wrap: nowrap; }
                .cell-actions input[type="password"] { width: 90px; margin: 0; }
                .cell-actions .select-wrap { width: auto; min-width: 100px; flex: 1 1 auto; }
                .sync-toast {
                    position: fixed;
                    bottom: 28px;
                    left: 50%;
                    transform: translateX(-50%) translateY(20px);
                    background: #1A1A1A;
                    color: white;
                    padding: 14px 24px;
                    border-radius: 999px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    font-size: 14px;
                    font-weight: 600;
                    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
                    z-index: 3000;
                    opacity: 0;
                    pointer-events: none;
                    transition: opacity 0.3s ease, transform 0.3s ease;
                }
                .sync-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
                .sync-toast svg { width: 20px; height: 20px; color: #3E9188; flex-shrink: 0; }
                .btn-back { background: #666; }
                .btn-refresh { background: #F2B90D; color: #1A1A1A; }
                .btn-refresh.spinning svg { animation: btnSpin .6s linear; }
                @keyframes btnSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
                .search-box { display: flex; gap: 10px; margin: 20px 0; flex-wrap: wrap; align-items: center; }
                .search-box input[type="text"] { flex: 2 1 220px; margin: 0; }
                .search-box .select-wrap { flex: 1 1 170px; width: auto; }
                .search-box .btn { flex-shrink: 0; white-space: nowrap; }
                .search-box input { flex: 2; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; min-width: 150px; }
                .search-box select { flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; min-width: 120px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
                th { background: #3E9188; color: white; padding: 14px 12px; text-align: center; font-weight: 600; letter-spacing: 0.3px; }
                td { padding: 12px 14px; text-align: center; border-bottom: 1px solid #eee; vertical-align: middle; }
                tbody tr { transition: background 0.15s ease; }
                tbody tr:nth-child(even) { background: #FAFBFB; }
                tbody tr:hover { background: #EFF7F6; }
                .stats { background: #E6F2F0; padding: 10px; border-radius: 6px; margin: 15px 0; font-weight: bold; }
                .table-container { max-height: 500px; overflow-y: auto; overflow-x: hidden; border: 1px solid #eee; border-radius: 12px; }
                h1 { color: #1A1A1A; margin-bottom: 20px; font-size: 22px; }
                .guide-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 20px 0; }
                .guide-card { display: flex; align-items: flex-start; gap: 10px; background: #FBE9D3; padding: 14px; border-radius: 12px; border-right: 4px solid #E8963E; }
                .guide-icon { width: 30px; height: 30px; min-width: 30px; border-radius: 50%; background: rgba(232,150,62,0.2); color: #C97F2E; display: flex; align-items: center; justify-content: center; }
                .guide-icon svg { width: 16px; height: 16px; }
                .guide-text { font-size: 13px; line-height: 1.7; color: #1A1A1A; }
                select, input { padding: 5px 8px; border-radius: 4px; border: 1px solid #ddd; }
                button:hover { opacity: 0.85; }
                @media (max-width: 768px) { .container { padding: 15px; } table { font-size: 12px; } th, td { padding: 6px; } .search-box input { min-width: 100px; } }
                @media (max-width: 480px) { .search-box { flex-direction: column; } .search-box input, .search-box select { width: 100%; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z"/><path d="M9.5 12l1.8 1.8L14.8 10"/></svg></div><h1>مدیریت کاربران سیستم</h1></div>
                
                <div class="guide-grid">
                    <div class="guide-card">
                        <div class="guide-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg></div>
                        <div class="guide-text">هر پرسنلی که در بخش «لیست پرسنل» تعریف شود، به‌طور خودکار در این لیست قرار می‌گیرد.</div>
                    </div>
                    <div class="guide-card">
                        <div class="guide-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="8" r="4"/><path d="M2 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/><path d="M19 8v4M17 10h4"/></svg></div>
                        <div class="guide-text"><strong>نام کاربری</strong> هر فرد، <strong>کد ملی</strong> او می‌باشد.</div>
                    </div>
                    <div class="guide-card">
                        <div class="guide-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.5 12.5 20 3M17 6l3 3M14 9l2 2"/></svg></div>
                        <div class="guide-text">برای فعال کردن حساب کاربری، رمز عبور تعیین کنید و دکمه ذخیره را بزنید.</div>
                    </div>
                    <div class="guide-card">
                        <div class="guide-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z"/><path d="M9.5 12l1.8 1.8L14.8 10"/></svg></div>
                        <div class="guide-text"><strong>سطح دسترسی «مدیریتی»</strong> دسترسی کامل به واحد منابع انسانی می‌دهد.</div>
                    </div>
                    <div class="guide-card">
                        <div class="guide-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 2 8l10 5 10-5-10-5Z"/><path d="M2 13l10 5 10-5"/></svg></div>
                        <div class="guide-text"><strong>سطح دسترسی «سازمانی»</strong> سطحی بین عادی و مدیریتی است.</div>
                    </div>
                </div>
                
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="جستجو..." onkeyup="searchTable()">
                    <select id="searchField">
                        <option value="all">همه ستون‌ها</option>
                        <option value="0">نام و نام خانوادگی</option>
                        <option value="1">کد پرسنلی</option>
                        <option value="2">واحد خدمتی</option>
                        <option value="3">پست سازمانی</option>
                        <option value="4">کد ملی</option>
                    </select>
                    <button class="btn" onclick="clearSearch()">پاک کردن</button>
                    <button class="btn btn-refresh" onclick="refreshUsers()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 4v5h5"/><path d="M20 20v-5h-5"/><path d="M5.5 9A7 7 0 0 1 19 12"/><path d="M18.5 15A7 7 0 0 1 5 12"/></svg> بروزرسانی</button>
                </div>

                <div class="stats" id="stats"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل کاربران: ${toPersianDigits(personnelAccounts.length)} نفر</div>
                
                <div class="table-container">
                    <table id="usersTable">
                        <thead><tr><th>نام و نام خانوادگی</th><th>کد پرسنلی</th><th>واحد خدمتی</th><th>پست سازمانی</th><th>نام کاربری (کد ملی)</th><th>رمز عبور</th><th>سطح دسترسی</th></tr></thead>
                        <tbody id="tableBody">${rows}</tbody>
                    </table>
                </div>
            </div>
            <div id="saveToast" class="sync-toast">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 5-5"/></svg>
                <span id="saveToastText">با موفقیت ذخیره شد</span>
            </div>

            <script>
                function toFa(n) { return String(n).replace(/[0-9]/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]); }
                function escHtml(s) {
                    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
                }
                function showSaveToast(text) {
                    const toast = document.getElementById('saveToast');
                    document.getElementById('saveToastText').textContent = text;
                    toast.classList.add('show');
                    clearTimeout(window.__saveToastTimer);
                    window.__saveToastTimer = setTimeout(function() { toast.classList.remove('show'); }, 2500);
                }
                const allUsers = ${safeJson(personnelAccounts.map(u => ({
                    nationalCode: u.nationalCode,
                    fullname: u.fullname,
                    personnelCode: u.personnelCode || '-',
                    unit: u.unit || '-',
                    position: u.position || '-',
                    hasPassword: !!u.hasPassword,
                    accessLevel: u.accessLevel || 'normal'
                })))};
                
                function searchTable() {
                    const term = document.getElementById('searchInput').value.toLowerCase();
                    const fieldIndex = parseInt(document.getElementById('searchField').value);
                    const tbody = document.getElementById('tableBody');
                    const rows = tbody.getElementsByTagName('tr');
                    let visibleCount = 0;
                    for (let i = 0; i < rows.length; i++) {
                        const row = rows[i];
                        let showRow = false;
                        if (fieldIndex === 'all' || isNaN(fieldIndex)) {
                            for (let j = 0; j < row.cells.length - 2; j++) {
                                const cellText = row.cells[j].innerText.toLowerCase();
                                if (cellText.includes(term)) { showRow = true; break; }
                            }
                        } else {
                            if (row.cells[fieldIndex]) {
                                const cellText = row.cells[fieldIndex].innerText.toLowerCase();
                                showRow = cellText.includes(term);
                            }
                        }
                        if (term === '') showRow = true;
                        if (showRow) { row.style.display = ''; visibleCount++; } else { row.style.display = 'none'; }
                    }
                    document.getElementById('stats').innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل کاربران: ' + toFa(allUsers.length) + ' | نمایش: ' + toFa(visibleCount);
                }
                function clearSearch() { document.getElementById('searchInput').value = ''; searchTable(); }
                async function savePassword(nationalCode) {
                    const password = document.getElementById('pass_' + nationalCode).value;
                    if (!password) { alert('لطفاً رمز عبور را وارد کنید'); return; }
                    const res = await fetch('/api/user/password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ nationalCode: nationalCode, password: password })
                    });
                    const result = await res.json();
                    if (result.success) { await refreshUsers(); showSaveToast('رمز عبور با موفقیت ذخیره شد'); } else alert('خطا: ' + (result.message || 'مشخص نیست'));
                }
                async function saveAccessLevel(nationalCode) {
                    const accessLevel = document.getElementById('level_' + nationalCode).value;
                    const res = await fetch('/api/user/access-level', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ nationalCode: nationalCode, accessLevel: accessLevel })
                    });
                    const result = await res.json();
                    if (result.success) { await refreshUsers(); showSaveToast('سطح دسترسی با موفقیت ذخیره شد'); } else alert('خطا: ' + (result.message || 'مشخص نیست'));
                }
                function buildUserRow(u) {
                    const nc = u.nationalCode;
                    const sel = { normal: '', management: '', organizational: '' };
                    sel[u.accessLevel || 'normal'] = 'selected';
                    return '<tr>' +
                        '<td style="text-align:center">' + escHtml(u.fullname) + '</td>' +
                        '<td style="text-align:center">' + escHtml(toFa(u.personnelCode || '-')) + '</td>' +
                        '<td style="text-align:center">' + escHtml(u.unit || '-') + '</td>' +
                        '<td style="text-align:center">' + escHtml(u.position || '-') + '</td>' +
                        '<td style="text-align:center">' + escHtml(toFa(nc)) + '</td>' +
                        '<td style="text-align:center"><div class="cell-actions">' +
                            '<input type="password" id="pass_' + nc + '" value="" placeholder="' + (u.hasPassword ? 'رمز جدید (اختیاری)' : 'هنوز رمزی تنظیم نشده') + '" autocomplete="new-password">' +
                            '<button class="btn-save" onclick="savePassword(\\'' + nc + '\\')">ذخیره</button>' +
                        '</div></td>' +
                        '<td style="text-align:center"><div class="cell-actions">' +
                            '<select id="level_' + nc + '">' +
                                '<option value="normal" ' + sel.normal + '>عادی</option>' +
                                '<option value="management" ' + sel.management + '>مدیریتی</option>' +
                                '<option value="organizational" ' + sel.organizational + '>سازمانی</option>' +
                            '</select>' +
                            '<button class="btn-save-level" onclick="saveAccessLevel(\\'' + nc + '\\')">ذخیره</button>' +
                        '</div></td>' +
                    '</tr>';
                }
                async function refreshUsers() {
                    const btn = document.querySelector('.btn-refresh');
                    if (btn) btn.classList.add('spinning');
                    try {
                        const res = await fetch('/api/system-users');
                        allUsers.length = 0;
                        Array.prototype.push.apply(allUsers, await res.json());
                        const tbody = document.getElementById('tableBody');
                        tbody.innerHTML = allUsers.length
                            ? allUsers.map(buildUserRow).join('')
                            : '<tr><td colspan="7" style="text-align:center; padding:30px;">هیچ پرسنلی تعریف نشده است. ابتدا در بخش لیست پرسنل، پرسنل را تعریف کنید.</td></tr>';
                        if (window.csEnhanceAll) window.csEnhanceAll();
                        searchTable();
                    } finally {
                        if (btn) setTimeout(() => btn.classList.remove('spinning'), 400);
                    }
                }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API لیست کاربران سیستم ====================
app.get('/api/system-users', requireRole('admin', 'management'), (req, res) => {
    res.json(db.Accounts.listPersonnelAccounts().map(u => ({
        nationalCode: u.nationalCode,
        fullname: u.fullname,
        personnelCode: u.personnelCode || '-',
        unit: u.unit || '-',
        position: u.position || '-',
        hasPassword: !!u.hasPassword,
        accessLevel: u.accessLevel || 'normal'
    })));
});

// ==================== API مدیریت رمز عبور و سطح دسترسی کاربران ====================
app.post('/api/user/password', requireRole('admin', 'management'), (req, res) => {
    const { nationalCode, password } = req.body;
    if (!nationalCode || !password) return res.json({ success: false, message: 'اطلاعات ناقص است' });
    if (db.Accounts.setPassword(nationalCode, password)) {
        addLog('تغییر رمز عبور', req.session.user.username, 'رمز عبور کاربر ' + nationalCode + ' تغییر کرد');
        res.json({ success: true, message: 'رمز عبور با موفقیت ذخیره شد' });
    } else {
        res.json({ success: false, message: 'کاربر یافت نشد' });
    }
});

const VALID_ACCESS_LEVELS = new Set(['normal', 'management', 'organizational']);
app.post('/api/user/access-level', requireRole('admin', 'management'), (req, res) => {
    const { nationalCode, accessLevel } = req.body;
    if (!nationalCode || !accessLevel) return res.json({ success: false, message: 'اطلاعات ناقص است' });
    if (!VALID_ACCESS_LEVELS.has(accessLevel)) return res.json({ success: false, message: 'سطح دسترسی نامعتبر است' });
    if (db.Accounts.setAccessLevel(nationalCode, accessLevel)) {
        addLog('تغییر سطح دسترسی', req.session.user.username, 'سطح دسترسی کاربر ' + nationalCode + ' به ' + accessLevel + ' تغییر کرد');
        res.json({ success: true, message: 'سطح دسترسی با موفقیت ذخیره شد' });
    } else {
        res.json({ success: false, message: 'کاربر یافت نشد' });
    }
});

// ==================== API بازیابی رمز عبور ====================
app.post('/api/reset-password', authRateLimiter, (req, res) => {
    const nationalCode = toEnglishDigits(req.body.nationalCode);
    if (!nationalCode || !/^[0-9]{10}$/.test(nationalCode)) {
        return res.json({ success: false, message: 'کد ملی نامعتبر است' });
    }
    const account = db.Accounts.findByUsername(nationalCode);
    if (account) {
        const newPassword = db.Accounts.setRandomPassword(nationalCode);
        addLog('بازیابی رمز عبور', nationalCode, account.role === 'admin' ? 'رمز عبور جدید برای ادمین تنظیم شد' : 'رمز عبور جدید برای کاربر تنظیم شد');
        return res.json({ success: true, newPassword: newPassword });
    }
    res.json({ success: false, message: 'کاربری با این کد ملی یافت نشد' });
});

// ==================== صفحه تعریف اطلاعات سازمان ====================
app.get('/hr/organization', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin') {
        return res.send(`
            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>دسترسی ممنوع</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: rgba(255,68,68,0.12);
                    color: #ff4444;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/></svg></div>
                    <h1>دسترسی غیرمجاز</h1>
                    <p>شما دسترسی لازم برای مشاهده این بخش را ندارید.</p>
                    <button class="btn-back" onclick="location.href='/hr?user=${username}&role=${role}'">بازگشت</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }

    const organizationInfo = db.Organization.get();
    const organizationalUnits = db.Units.list();
    const organizationalPositions = db.Positions.list();
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>تعریف اطلاعات سازمان</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1100px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .org-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; margin-top: 10px; }
                .org-col h2 { font-size: 1.05rem; margin-top: 0; }
                .inline-add-row { display: flex; gap: 8px; margin-top: 10px; }
                .inline-add-row input { flex: 1; margin: 0; }
                .import-row { display: flex; gap: 8px; align-items: stretch; }
                .import-row textarea { flex: 1; margin: 0 !important; min-height: 42px; }
                .import-row .btn-import { flex-shrink: 0; white-space: nowrap; margin: 0 !important; }
                .btn-add-inline { background: #3E9188; color: white; border: none; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; padding: 9px 16px; white-space: nowrap; flex-shrink: 0; transition: all .2s ease; }
                .btn-add-inline:hover { background: #337971; }
                @media (max-width: 820px) { .org-grid { grid-template-columns: 1fr; } }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; }
                .btn-import { background: #E8963E; }
                .btn-import:hover { background: #C97F2E; }
                .form-box { background: #f9f9f9; padding: 20px; border-radius: 10px; margin: 20px 0; }
                input { width: 100%; padding: 8px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
                .preview-logo { max-width: 60px; max-height: 44px; border: 1px solid #ddd; border-radius: 6px; padding: 3px; flex-shrink: 0; }
                .org-info-row { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; }
                .org-info-field { flex: 1; min-width: 180px; }
                .org-info-field label { font-weight: bold; display: block; margin-bottom: 6px; font-size: 13px; }
                .org-info-field input { margin: 0; }
                .org-info-save { flex-shrink: 0; white-space: nowrap; margin: 0 !important; }
                @media (max-width: 700px) { .org-info-row { flex-direction: column; align-items: stretch; } }
                .item-with-delete {
                    background: #E6F2F0;
                    padding: 9px 16px;
                    margin: 5px;
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    border-radius: 999px;
                    border: 1px solid rgba(62,145,136,0.25);
                    font-size: 14px;
                    font-weight: 500;
                    color: #1A1A1A;
                    transition: all 0.2s ease;
                }
                .item-with-delete:hover { background: #daf0ec; border-color: rgba(62,145,136,0.45); }
                .delete-icon {
                    color: #ff4444;
                    cursor: pointer;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    width: 22px;
                    height: 22px;
                    border-radius: 50%;
                    background: rgba(255,68,68,0.12);
                    transition: all 0.2s ease;
                }
                .delete-icon:hover { color: white; background: #ff4444; }
                h2 { color: #555; border-bottom: 2px solid #eee; padding-bottom: 10px; font-weight: bold; }
                h3 { font-weight: bold; }
                .list-container { max-height: 300px; overflow-y: auto; margin: 15px 0; padding: 10px; border: 1px solid #eee; border-radius: 8px; }
                .import-box { background: #FBE9D3; padding: 15px; border-radius: 10px; margin: 15px 0; border: 1px dashed #E8963E; }
                .import-box textarea { width: 100%; padding: 8px; font-family: monospace; font-size: 12px; direction: ltr; text-align: left; border: 1px solid #ddd; border-radius: 5px; margin: 10px 0; box-sizing: border-box; resize: vertical; max-width: 100%; }
                .import-box small { color: #666; font-size: 11px; }
                @media (max-width: 768px) { .container { padding: 15px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10l9-6 9 6"/><path d="M4 10v10M9 10v10M15 10v10M20 10v10"/><path d="M2 20h20"/></svg></div><h1>تعریف اطلاعات سازمان</h1></div>
                <div class="form-box">
                    <h3><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M6 21V5a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v16"/><path d="M17 21V10a1 1 0 0 0-1-1h-2"/><path d="M3 21h18"/><path d="M9 8h1M9 11h1M9 14h1M9 17h1"/></svg> اطلاعات سازمان</h3>
                    <form method="POST" action="/hr/update-organization" enctype="multipart/form-data" class="org-info-row">
                        <input type="hidden" name="_csrf" value="${req.session.csrfToken}">
                        <div class="org-info-field">
                            <label>نام سازمان/شرکت:</label>
                            <input type="text" name="orgName" value="${escapeHtml(organizationInfo.name)}" required>
                        </div>
                        <div class="org-info-field">
                            <label>آپلود لوگو:</label>
                            <input type="file" name="logo" accept="image/*">
                        </div>
                        ${organizationInfo.logo ? `<img src="${organizationInfo.logo}" class="preview-logo">` : ''}
                        <button type="submit" class="btn org-info-save"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M5 4h11l3 3v13H5V4Z"/><path d="M8 4v5h7V4"/><path d="M8 13h8v7H8z"/></svg> ذخیره</button>
                    </form>
                </div>
                
                <div class="org-grid">
                    <div class="org-col">
                        <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 3 2 8l10 5 10-5-10-5Z"/><path d="M2 13l10 5 10-5"/></svg> واحدهای سازمانی</h2>
                        <div class="import-box">
                            <div class="import-row">
                                <textarea id="importUnits" rows="1" placeholder="هر واحد در یک خط&#10;منابع انسانی&#10;فنی و مهندسی"></textarea>
                                <button class="btn btn-import" onclick="importUnits()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 21h16"/></svg> ایمپورت</button>
                            </div>
                            <div class="inline-add-row">
                                <input type="text" id="singleUnitName" placeholder="یا نام یک واحد را وارد کنید...">
                                <button class="btn btn-add-inline" onclick="addSingleUnit()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:15px;height:15px;display:inline-block;"><path d="M12 5v14M5 12h14"/></svg> ثبت</button>
                            </div>
                        </div>
                        <div class="list-container">
                            ${organizationalUnits.length === 0 ? '<span style="color:gray;">هنوز واحدی تعریف نشده است</span>' :
                                organizationalUnits.map(u => `<div class="item-with-delete"><span class="delete-icon" onclick="if(confirm('حذف شود؟')) fetch('/hr/delete-unit?id=${u.id}&user=${username}&role=${role}').then(()=>location.reload())"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg></span><span>${escapeHtml(u.name)}</span></div>`).join('')
                            }
                        </div>
                    </div>
                    <div class="org-col">
                        <h2><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><rect x="3" y="7" width="18" height="13" rx="2"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M3 12h18"/></svg> پست‌های سازمانی</h2>
                        <div class="import-box">
                            <div class="import-row">
                                <textarea id="importPositions" rows="1" placeholder="هر پست در یک خط&#10;مدیر&#10;کارشناس"></textarea>
                                <button class="btn btn-import" onclick="importPositions()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 21h16"/></svg> ایمپورت</button>
                            </div>
                            <div class="inline-add-row">
                                <input type="text" id="singlePositionName" placeholder="یا نام یک پست را وارد کنید...">
                                <button class="btn btn-add-inline" onclick="addSinglePosition()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:15px;display:inline-block;height:15px;"><path d="M12 5v14M5 12h14"/></svg> ثبت</button>
                            </div>
                        </div>
                        <div class="list-container">
                            ${organizationalPositions.length === 0 ? '<span style="color:gray;">هنوز پستی تعریف نشده است</span>' :
                                organizationalPositions.map(p => `<div class="item-with-delete"><span class="delete-icon" onclick="if(confirm('حذف شود؟')) fetch('/hr/delete-position?id=${p.id}&user=${username}&role=${role}').then(()=>location.reload())"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg></span><span>${escapeHtml(p.name)}</span></div>`).join('')
                            }
                        </div>
                    </div>
                </div>
            </div>
            <script>
                let currentUser = '${username}';
                let currentRole = '${role}';
                
                async function importUnits() {
                    const raw = document.getElementById('importUnits').value;
                    const lines = raw.trim().split(/\\r?\\n/);
                    let success = 0, fail = 0, errors = [];
                    const existingUnits = ${safeJson(organizationalUnits.map(u => u.name))};
                    for (let i = 0; i < lines.length; i++) {
                        const unitName = lines[i].trim();
                        if (unitName === '') continue;
                        if (existingUnits.includes(unitName)) { fail++; errors.push('واحد "' + unitName + '" تکراری است'); continue; }
                        const res = await fetch('/hr/add-unit-batch', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ unitName, username: currentUser })
                        });
                        const result = await res.json();
                        if (result.success) success++; else { fail++; errors.push('واحد "' + unitName + '": ' + (result.message || 'خطا')); }
                    }
                    let message = 'ایمپورت واحدها انجام شد!\\nموفق: ' + success + '\\nناموفق: ' + fail;
                    if (errors.length > 0 && errors.length <= 5) message += '\\n\\nخطاها:\\n' + errors.join('\\n');
                    alert(message);
                    location.reload();
                }
                
                async function importPositions() {
                    const raw = document.getElementById('importPositions').value;
                    const lines = raw.trim().split(/\\r?\\n/);
                    let success = 0, fail = 0, errors = [];
                    const existingPositions = ${safeJson(organizationalPositions.map(p => p.name))};
                    for (let i = 0; i < lines.length; i++) {
                        const positionName = lines[i].trim();
                        if (positionName === '') continue;
                        if (existingPositions.includes(positionName)) { fail++; errors.push('پست "' + positionName + '" تکراری است'); continue; }
                        const res = await fetch('/hr/add-position-batch', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ positionName, username: currentUser })
                        });
                        const result = await res.json();
                        if (result.success) success++; else { fail++; errors.push('پست "' + positionName + '": ' + (result.message || 'خطا')); }
                    }
                    let message = 'ایمپورت پست‌ها انجام شد!\\nموفق: ' + success + '\\nناموفق: ' + fail;
                    if (errors.length > 0 && errors.length <= 5) message += '\\n\\nخطاها:\\n' + errors.join('\\n');
                    alert(message);
                    location.reload();
                }
                async function addSingleUnit() {
                    const input = document.getElementById('singleUnitName');
                    const unitName = input.value.trim();
                    if (!unitName) return;
                    const res = await fetch('/hr/add-unit-batch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ unitName, username: currentUser })
                    });
                    const result = await res.json();
                    if (result.success) { location.reload(); } else alert(result.message || 'خطا در ثبت واحد');
                }
                async function addSinglePosition() {
                    const input = document.getElementById('singlePositionName');
                    const positionName = input.value.trim();
                    if (!positionName) return;
                    const res = await fetch('/hr/add-position-batch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ positionName, username: currentUser })
                    });
                    const result = await res.json();
                    if (result.success) { location.reload(); } else alert(result.message || 'خطا در ثبت پست');
                }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

app.post('/hr/update-organization', requireRole('admin'), (req, res) => {
    parseMultipartData(req, (result) => {
        if (result._csrf !== req.session.csrfToken) {
            return res.status(403).send('<h2>درخواست نامعتبر است (CSRF)</h2><p>لطفاً صفحه را رفرش کرده و دوباره تلاش کنید.</p><a href="javascript:history.back()">بازگشت</a>');
        }
        if (result.error) {
            return res.status(400).send('<h2>' + result.error + '</h2><a href="javascript:history.back()">بازگشت</a>');
        }
        const update = {};
        if (result.orgName) update.name = result.orgName;
        if (result.logoUrl) update.logo = result.logoUrl;
        if (Object.keys(update).length) db.Organization.update(update);
        const username = req.session.user.username;
        addLog('به‌روزرسانی اطلاعات سازمان', username, 'نام یا لوگو شرکت تغییر کرد');
        res.redirect("/hr/organization?user=" + username + "&role=admin");
    });
});

// ==================== ایمپورت دسته‌جمعی واحدها و پست‌ها ====================
app.post('/hr/add-unit-batch', requireRole('admin'), (req, res) => {
    const { unitName, username } = req.body;
    if (db.Units.add(unitName)) {
        addLog('افزودن واحد سازمانی', username || 'سیستم', 'واحد "' + unitName + '" اضافه شد');
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'نام واحد معتبر نیست یا تکراری است' });
    }
});

app.post('/hr/add-position-batch', requireRole('admin'), (req, res) => {
    const { positionName, username } = req.body;
    if (db.Positions.add(positionName)) {
        addLog('افزودن پست سازمانی', username || 'سیستم', 'پست "' + positionName + '" اضافه شد');
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'نام پست معتبر نیست یا تکراری است' });
    }
});

// ==================== صفحه تعریف پرسنل ====================
app.get('/hr/personnel/add', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const unitOptions = db.Units.list().map(unit => `<option value="${escapeHtml(unit.name)}">${escapeHtml(unit.name)}</option>`).join('');
    const positionOptions = db.Positions.list().map(pos => `<option value="${escapeHtml(pos.name)}">${escapeHtml(pos.name)}</option>`).join('');

    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>تعریف پرسنل جدید</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 11px 20px; border-radius: 10px; cursor: pointer; margin: 5px; width: 100%; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; width: auto; }
                .form-group { margin-bottom: 15px; }
                label { font-weight: bold; display: block; margin-bottom: 5px; }
                input, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
                h1 { color: #1A1A1A; font-weight: bold; }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="8" r="4"/><path d="M2 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/><path d="M19 8v4M17 10h4"/></svg></div><h1>تعریف پرسنل جدید</h1></div>
                <form method="POST" action="/hr/add-personnel" onsubmit="return validateNationalCode()">
                    <input type="hidden" name="_csrf" value="${req.session.csrfToken}">
                    <div class="form-group"><label>نام و نام خانوادگی:</label><input type="text" name="fullname" required></div>
                    <div class="form-group"><label>کد پرسنلی:</label><input type="text" name="personnelCode" required oninput="this.value=this.value.replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))"></div>
                    <div class="form-group"><label>واحد محل خدمتی:</label><select name="unit" required><option value="">-- انتخاب کنید --</option>${unitOptions || '<option>ابتدا واحد تعریف کنید</option>'}</select></div>
                    <div class="form-group"><label>پست سازمانی:</label><select name="position" required><option value="">-- انتخاب کنید --</option>${positionOptions || '<option>ابتدا پست تعریف کنید</option>'}</select></div>
                    <div class="form-group"><label>کد ملی (10 رقم):</label><input type="text" name="nationalCode" id="nationalCode" required pattern="[0-9]{10}" title="کد ملی باید 10 رقم باشد" maxlength="10" oninput="this.value=this.value.replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))"></div>
                    <input type="hidden" name="username" value="${username}">
                    <button type="submit" class="btn">ثبت پرسنل</button>
                </form>
            </div>
            <script>
                function validateNationalCode() {
                    const nationalCode = document.getElementById('nationalCode').value;
                    if (!/^[0-9]{10}$/.test(nationalCode)) {
                        alert('کد ملی باید دقیقاً 10 رقم باشد!');
                        return false;
                    }
                    return true;
                }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== صفحه لیست پرسنل ====================
app.get('/hr/personnel/list', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const organizationalUnits = db.Units.list();
    const organizationalPositions = db.Positions.list();
    const personnel = db.Personnel.list();
    const hasChartData = organizationalUnits.length > 0 && organizationalPositions.length > 0;
    const validUnits = organizationalUnits.map(u => u.name);
    const validPositions = organizationalPositions.map(p => p.name);

    let personnelRows = '';
    for (const p of personnel) {
        personnelRows += '<tr>';
        personnelRows += '<td style="text-align:center">' + escapeHtml(p.fullname) + '</td>';
        personnelRows += '<td style="text-align:center">' + escapeHtml(toPersianDigits(p.personnelCode)) + '</td>';
        personnelRows += '<td style="text-align:center">' + escapeHtml(p.unit || '-') + '</td>';
        personnelRows += '<td style="text-align:center">' + escapeHtml(p.position || '-') + '</td>';
        personnelRows += '<td style="text-align:center">' + escapeHtml(toPersianDigits(p.nationalCode)) + '</td>';
        personnelRows += '<td style="text-align:center">';
        personnelRows += '<button class="btn-edit" onclick="editPersonnel(' + p.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg> ویرایش</button> ';
        personnelRows += '<button class="btn-danger" onclick="deletePersonnel(' + p.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg> حذف</button>';
        personnelRows += '</td>';
        personnelRows += '</tr>';
    }
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>لیست پرسنل</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1300px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-edit { background: #E8963E; color: white; border: none; padding: 6px 12px; border-radius: 8px; cursor: pointer; margin: 2px; font-weight: 600; font-size: 13px; transition: all 0.2s ease; }
                .btn-edit:hover { background: #C97F2E; transform: translateY(-1px); }
                .btn-back { background: #666; }
                .btn-danger { background: #ff4444; padding: 6px 12px; border-radius: 8px; cursor: pointer; border: none; color: white; margin: 2px; font-weight: 600; font-size: 13px; transition: all 0.2s ease; }
                .btn-danger:hover { background: #cc0000; transform: translateY(-1px); }
                .btn-disabled { background: #ccc; cursor: not-allowed; }
                .btn-sync { background: #F2B90D; color: #1A1A1A; }
                .sync-toast {
                    position: fixed;
                    bottom: 28px;
                    left: 50%;
                    transform: translateX(-50%) translateY(20px);
                    background: #1A1A1A;
                    color: white;
                    padding: 14px 24px;
                    border-radius: 999px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    font-size: 14px;
                    font-weight: 600;
                    box-shadow: 0 12px 32px rgba(0,0,0,0.35);
                    z-index: 3000;
                    opacity: 0;
                    pointer-events: none;
                    transition: opacity 0.3s ease, transform 0.3s ease;
                }
                .sync-toast.show {
                    opacity: 1;
                    transform: translateX(-50%) translateY(0);
                }
                .sync-toast svg { width: 20px; height: 20px; color: #3E9188; flex-shrink: 0; }
                .import-box { background: #f9f9f9; padding: 20px; border-radius: 10px; margin: 20px 0; border: 1px dashed #3E9188; }
                .warning-box { background: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 12px; border-radius: 8px; margin: 10px 0; font-size: 13px; }
                textarea { width: 100%; padding: 10px; font-family: monospace; font-size: 13px; direction: ltr; text-align: left; border: 1px solid #ddd; border-radius: 6px; height: 100px; box-sizing: border-box; resize: vertical; max-width: 100%; }
                .search-box { display: flex; gap: 10px; margin: 20px 0; flex-wrap: wrap; align-items: center; }
                .search-box input[type="text"] { flex: 2 1 220px; margin: 0; }
                .search-box .select-wrap { flex: 1 1 170px; width: auto; }
                .search-box .btn { flex-shrink: 0; white-space: nowrap; }
                .search-box input { flex: 2; padding: 8px; border: 1px solid #ddd; border-radius: 5px; min-width: 150px; }
                .search-box select { flex: 1; padding: 8px; border: 1px solid #ddd; border-radius: 5px; min-width: 120px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
                th, td { padding: 12px 14px; border-bottom: 1px solid #eee; }
                th { background: #3E9188; color: white; position: sticky; top: 0; font-weight: 600; text-align: center; padding: 14px 12px; letter-spacing: 0.3px; }
                td { text-align: center; }
                tbody tr { transition: background 0.15s ease; }
                tbody tr:nth-child(even) { background: #FAFBFB; }
                tbody tr:hover { background: #EFF7F6; }
                .stats { background: #E6F2F0; padding: 8px; border-radius: 6px; margin: 10px 0; font-weight: bold; font-size: 13px; }
                .table-container { max-height: 500px; overflow-y: auto; overflow-x: hidden; border: 1px solid #eee; border-radius: 12px; }
                h1, h3 { font-weight: bold; }
                .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; }
                .modal-content { background: white; padding: 30px; border-radius: 15px; width: 500px; max-width: 90%; }
                .modal-content input, .modal-content select { width: 100%; padding: 8px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
                .modal-content .btn { background: #3E9188; color: white; border: none; padding: 10px 20px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .modal-content .btn:hover { background: #337971; transform: translateY(-1px); }
                .modal-content .btn-cancel { background: #666; }
                .modal-content label { font-weight: bold; display: block; margin-top: 10px; }
                @media (max-width: 768px) { .container { padding: 15px; } table { font-size: 12px; } th, td { padding: 6px; } .search-box input { min-width: 100px; } }
                @media (max-width: 480px) { .search-box { flex-direction: column; } .search-box input, .search-box select { width: 100%; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg></div><h1>مدیریت پرسنل</h1></div>
                <div class="import-box">
                    <h3 style="margin-bottom: 10px;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M21 12.5 12.5 21a5 5 0 0 1-7-7L14 5.5a3.5 3.5 0 0 1 5 5L10.5 19a2 2 0 0 1-3-3L15 8"/></svg> ایمپورت از اکسل</h3>
                    ${!hasChartData ? '<div class="warning-box"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg> ابتدا در بخش "تعریف اطلاعات سازمان" واحد و پست تعریف کنید</div>' : ''}
                    <textarea id="pasteArea" rows="3" placeholder="مثال:&#10;علی رضایی,1001,منابع انسانی,کارشناس,1234567890&#10;سارا احمدی,1002,فنی,مدیر,0987654321" ${!hasChartData ? 'disabled' : ''}></textarea>
                    <br>
                    <button class="btn ${!hasChartData ? 'btn-disabled' : ''}" onclick="importFromClipboard()" ${!hasChartData ? 'disabled' : ''}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 21h16"/></svg> ایمپورت اطلاعات</button>
                </div>
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="جستجو..." onkeyup="searchTable()">
                    <select id="searchField">
                        <option value="all">همه ستون‌ها</option>
                        <option value="fullname">نام و نام خانوادگی</option>
                        <option value="personnelCode">کد پرسنلی</option>
                        <option value="unit">واحد خدمتی</option>
                        <option value="position">پست سازمانی</option>
                        <option value="nationalCode">کد ملی</option>
                    </select>
                    <button class="btn" onclick="clearSearch()">پاک کردن</button>
                    <button class="btn btn-sync" onclick="syncToUsers(true)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 4v5h5"/><path d="M20 20v-5h-5"/><path d="M5.5 9A7 7 0 0 1 19 12"/><path d="M18.5 15A7 7 0 0 1 5 12"/></svg> همگام‌سازی با کاربران</button>
                </div>
                <div class="stats" id="stats"></div>
                <div id="syncToast" class="sync-toast">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 5-5"/></svg>
                    <span>همگام‌سازی با موفقیت انجام شد</span>
                </div>
                <div class="table-container">
                    <table id="personnelTable">
                        <thead><tr><th>نام و نام خانوادگی</th><th>کد پرسنلی</th><th>واحد خدمتی</th><th>پست سازمانی</th><th>کد ملی</th><th>عملیات</th></tr></thead>
                        <tbody id="tableBody">${personnelRows}</tbody>
                    </table>
                </div>
            </div>
            
            <div id="editModal" class="modal">
                <div class="modal-content">
                    <h2 id="modalTitle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg> ویرایش پرسنل</h2>
                    <form id="editForm" onsubmit="updatePersonnel(event)">
                        <input type="hidden" id="editId">
                        <label>نام و نام خانوادگی:</label>
                        <input type="text" id="editFullname" required>
                        <label>کد پرسنلی:</label>
                        <input type="text" id="editPersonnelCode" required oninput="this.value=this.value.replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))">
                        <label>واحد خدمتی:</label>
                        <select id="editUnit" required>
                            <option value="">-- انتخاب کنید --</option>
                            ${organizationalUnits.map(u => `<option value="${escapeHtml(u.name)}">${escapeHtml(u.name)}</option>`).join('')}
                        </select>
                        <label>پست سازمانی:</label>
                        <select id="editPosition" required>
                            <option value="">-- انتخاب کنید --</option>
                            ${organizationalPositions.map(p => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)}</option>`).join('')}
                        </select>
                        <label>کد ملی:</label>
                        <input type="text" id="editNationalCode" required pattern="[0-9]{10}" maxlength="10" oninput="this.value=this.value.replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))">
                        <div style="margin-top:20px; text-align:right;">
                            <button type="submit" class="btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M5 4h11l3 3v13H5V4Z"/><path d="M8 4v5h7V4"/><path d="M8 13h8v7H8z"/></svg> ذخیره تغییرات</button>
                            <button type="button" class="btn btn-cancel" onclick="closeEditModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M6 6l12 12M18 6L6 18"/></svg> انصراف</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <script>
                let allPersonnel = ${safeJson(personnel)};
                let currentUser = '${username}';
                let currentRole = '${role}';
                let hasChartData = ${hasChartData};
                let validUnits = ${safeJson(validUnits)};
                let validPositions = ${safeJson(validPositions)};
                
                function toFa(n) { return String(n).replace(/[0-9]/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]); }
                function escHtml(s) {
                    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
                }
                function renderTable() {
                    const term = document.getElementById('searchInput').value.toLowerCase();
                    const field = document.getElementById('searchField').value;
                    let filtered = allPersonnel;
                    if (term) {
                        filtered = allPersonnel.filter(p => {
                            if (field === 'all') {
                                return p.fullname.toLowerCase().includes(term) || p.personnelCode.includes(term) || p.unit.toLowerCase().includes(term) || p.position.toLowerCase().includes(term) || p.nationalCode.includes(term);
                            } else {
                                return p[field] && p[field].toString().toLowerCase().includes(term);
                            }
                        });
                    }
                    const tbody = document.getElementById('tableBody');
                    tbody.innerHTML = '';
                    if (filtered.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">هیچ داده‌ای یافت نشد</td></tr>';
                    } else {
                        filtered.forEach(p => {
                            tbody.innerHTML += '<tr>' +
                                '<td style="text-align:center">' + escHtml(p.fullname) + '</td>' +
                                '<td style="text-align:center">' + escHtml(toFa(p.personnelCode)) + '</td>' +
                                '<td style="text-align:center">' + escHtml(p.unit) + '</td>' +
                                '<td style="text-align:center">' + escHtml(p.position) + '</td>' +
                                '<td style="text-align:center">' + escHtml(toFa(p.nationalCode)) + '</td>' +
                                '<td style="text-align:center"><button class="btn-edit" onclick="editPersonnel(' + p.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg> ویرایش</button> <button class="btn-danger" onclick="deletePersonnel(' + p.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg> حذف</button></td>' +
                                '</tr>';
                        });
                    }
                    document.getElementById('stats').innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل: ' + toFa(allPersonnel.length) + ' | نمایش: ' + toFa(filtered.length);
                }
                
                function searchTable() { renderTable(); }
                function clearSearch() { document.getElementById('searchInput').value = ''; renderTable(); }
                
                function editPersonnel(id) {
                    const p = allPersonnel.find(item => item.id === id);
                    if (p) {
                        document.getElementById('editId').value = p.id;
                        document.getElementById('editFullname').value = p.fullname;
                        document.getElementById('editPersonnelCode').value = p.personnelCode;
                        document.getElementById('editUnit').value = p.unit;
                        document.getElementById('editPosition').value = p.position;
                        document.getElementById('editNationalCode').value = p.nationalCode;
                        document.getElementById('editModal').style.display = 'flex';
                    }
                }
                
                function closeEditModal() { document.getElementById('editModal').style.display = 'none'; }
                
                async function updatePersonnel(e) {
                    e.preventDefault();
                    const id = document.getElementById('editId').value;
                    const fullname = document.getElementById('editFullname').value;
                    const personnelCode = document.getElementById('editPersonnelCode').value;
                    const unit = document.getElementById('editUnit').value;
                    const position = document.getElementById('editPosition').value;
                    const nationalCode = document.getElementById('editNationalCode').value;
                    
                    if (!/^[0-9]{10}$/.test(nationalCode)) { alert('کد ملی باید دقیقاً 10 رقم باشد!'); return; }
                    
                    const res = await fetch('/api/personnel/' + id, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ fullname, personnelCode, unit, position, nationalCode })
                    });
                    const result = await res.json();
                    if (result.success) {
                        alert('اطلاعات پرسنل با موفقیت ویرایش شد');
                        await syncToUsers();
                        const loadRes = await fetch('/api/personnel');
                        allPersonnel = await loadRes.json();
                        renderTable();
                        closeEditModal();
                    } else {
                        alert('خطا: ' + (result.message || 'مشخص نیست'));
                    }
                }
                
                async function deletePersonnel(id) {
                    if (confirm('آیا از حذف این رکورد مطمئن هستید؟')) {
                        const res = await fetch('/api/personnel/' + id, { method: 'DELETE' });
                        const result = await res.json();
                        if (result.success) {
                            await syncToUsers();
                            const loadRes = await fetch('/api/personnel');
                            allPersonnel = await loadRes.json();
                            renderTable();
                        }
                    }
                }
                
                async function syncToUsers(showToast) {
                    const res = await fetch('/api/sync-users', { method: 'POST' });
                    const result = await res.json();
                    if (result.success) console.log('همگام‌سازی انجام شد:', result.message);
                    if (showToast) {
                        const toast = document.getElementById('syncToast');
                        toast.classList.add('show');
                        clearTimeout(toast._hideTimer);
                        toast._hideTimer = setTimeout(() => toast.classList.remove('show'), 2600);
                    }
                }
                
                async function importFromClipboard() {
                    if (!hasChartData) { alert('ابتدا چارت سازمانی را تکمیل کنید!'); return; }
                    const raw = document.getElementById('pasteArea').value;
                    const rows = raw.trim().split(/\\r?\\n/);
                    let success = 0, fail = 0, errorMessages = [];
                    
                    for (let i = 0; i < rows.length; i++) {
                        const row = rows[i];
                        let cols = row.split(/\\t|,/).filter(c => c.trim() !== '');
                        if (cols.length >= 5) {
                            const toEnDigits = s => s.replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
                            const fullname = cols[0].trim();
                            const personnelCode = toEnDigits(cols[1].trim());
                            const unit = cols[2].trim();
                            const position = cols[3].trim();
                            const nationalCode = toEnDigits(cols[4].trim());
                            if (!/^[0-9]{10}$/.test(nationalCode)) { fail++; errorMessages.push('ردیف ' + (i+1) + ': کد ملی "' + nationalCode + '" باید دقیقاً 10 رقم باشد'); continue; }
                            if (!validUnits.includes(unit)) { fail++; errorMessages.push('ردیف ' + (i+1) + ': واحد "' + unit + '" در چارت سازمانی تعریف نشده است'); continue; }
                            if (!validPositions.includes(position)) { fail++; errorMessages.push('ردیف ' + (i+1) + ': پست "' + position + '" در چارت سازمانی تعریف نشده است'); continue; }
                            const exists = allPersonnel.find(p => p.personnelCode === personnelCode || p.nationalCode === nationalCode);
                            if (exists) { fail++; errorMessages.push('ردیف ' + (i+1) + ': کد پرسنلی "' + personnelCode + '" یا کد ملی "' + nationalCode + '" تکراری است'); continue; }
                            const res = await fetch('/api/personnel', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ fullname, personnelCode, unit, position, nationalCode })
                            });
                            const result = await res.json();
                            if (result.success) success++; else { fail++; errorMessages.push('ردیف ' + (i+1) + ': ' + (result.message || 'خطا در ثبت')); }
                        } else {
                            fail++; errorMessages.push('ردیف ' + (i+1) + ': تعداد ستون‌ها کمتر از 5 است (' + cols.length + ' ستون)');
                        }
                    }
                    
                    let message = 'ایمپورت انجام شد!\\nموفق: ' + success + '\\nناموفق: ' + fail;
                    if (errorMessages.length > 0) {
                        message += '\\n━━━━━━━━━━━━━━━━━━━━\\nدلایل خطا:\\n' + errorMessages.slice(0, 10).join('\\n');
                        if (errorMessages.length > 10) message += '\\n... و ' + (errorMessages.length-10) + ' خطای دیگر';
                    }
                    alert(message);
                    await syncToUsers();
                    const loadRes = await fetch('/api/personnel');
                    allPersonnel = await loadRes.json();
                    renderTable();
                    document.getElementById('pasteArea').value = '';
                }
                
                window.onclick = function(event) {
                    if (event.target === document.getElementById('editModal')) closeEditModal();
                }
                renderTable();
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== مدیریت سوالات ارزیابی ====================

// سوالات عمومی
app.get('/hr/general-questions', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const generalQuestions = db.GeneralQuestions.listWithOptions();
    let rows = '';
    for (let i = 0; i < generalQuestions.length; i++) {
        const q = generalQuestions[i];
        const optionsPreview = q.options.map(o => escapeHtml(o.text) + ' <span class="opt-score">(' + toPersianDigits(o.score) + ')</span>').join('<br>');
        rows += '<tr><td style="text-align:center;">' + toPersianDigits(i+1) + '</td><td style="text-align:right;">' + escapeHtml(q.question) + '</td><td style="text-align:right; font-size:12px; color:#666;">' + optionsPreview + '</td><td style="text-align:center;"><button class="btn btn-edit" onclick="editQuestion(' + q.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg> ویرایش</button> <button class="btn btn-delete" onclick="deleteQuestion(' + q.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg> حذف</button></td></tr>';
    }
    if (generalQuestions.length === 0) {
        rows = '<tr><td colspan="4" style="text-align:center;">هیچ سوالی ثبت نشده است</td></tr>';
    }
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>مدیریت سوالات عمومی</title>
        <style>
            body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
            .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
            .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
            .btn:active { transform: translateY(0); }
            .btn-edit { background: #E8963E; } .btn-delete { background: #ff4444; } .btn-add { background: #3E9188; font-size: 16px; } .btn-back { background: #666; }
            .inline-add-form { display: none; gap: 10px; margin-top: 14px; align-items: flex-start; background: #f9f9f9; padding: 16px; border-radius: 12px; border: 1px dashed #3E9188; }
            .inline-add-panel.open .inline-add-form { display: flex; }
            .inline-add-form textarea { flex: 1; margin: 0; min-height: 44px; }
            .inline-add-form .btn { margin: 0; flex-shrink: 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; } th, td { padding: 12px 14px; border-bottom: 1px solid #eee; } th { background: #3E9188; color: white; text-align: center; padding: 14px 12px; font-weight: 600; letter-spacing: 0.3px; } tbody tr:nth-child(even) { background: #FAFBFB; } tbody tr:hover { background: #EFF7F6; }
            .stats { background: #E6F2F0; padding: 10px; border-radius: 6px; margin: 15px 0; font-weight: bold; }
            .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; overflow-y: auto; padding: 20px 0; box-sizing: border-box; }
            .modal-content { background: white; padding: 25px; border-radius: 15px; width: 560px; max-width: 90%; max-height: 90vh; overflow-y: auto; }
            .modal-content textarea { width: 100%; padding: 8px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; height: 90px; resize: vertical; font-family: inherit; }
            .opt-score { color: #999; }
            .options-builder { margin: 14px 0; }
            .options-builder-title { font-weight: 600; font-size: 13px; color: #666; margin-bottom: 8px; }
            .option-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
            .option-row input[type="text"] { flex: 1; padding: 8px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; font-family: inherit; }
            .option-row input[type="number"] { width: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; font-family: inherit; }
            .option-row .btn-remove-option { background: #ff4444; color: white; border: none; border-radius: 5px; width: 32px; height: 32px; cursor: pointer; flex-shrink: 0; }
            .btn-add-option { background: #E6F2F0; color: #3E9188; border: 1px dashed #3E9188; border-radius: 8px; padding: 8px 14px; cursor: pointer; font-weight: 600; font-size: 13px; }
            @media (max-width: 768px) { .container { padding: 15px; } table { font-size: 12px; } th, td { padding: 8px; } }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #3E9188;
            box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
        }
        input, select, textarea, button {
            font-family: inherit;
        }
        input, select, textarea {
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
            .page-header {
                display: flex;
                flex-direction: column;
                align-items: center;
                text-align: center;
                gap: 14px;
                margin: 4px auto 30px;
                padding-bottom: 24px;
                border-bottom: 1px solid #eee;
            }
            .page-header-icon {
                width: 64px;
                height: 64px;
                min-width: 64px;
                border-radius: 50%;
                background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                color: #3E9188;
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 4px 14px rgba(62,145,136,0.18);
            }
            .page-header-icon svg { width: 30px; height: 30px; }
            .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
            .page-header::after {
                content: '';
                display: block;
                width: 46px;
                height: 3px;
                border-radius: 3px;
                background: #3E9188;
                margin-top: 2px;
            }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></div><h1>مدیریت سوالات ارزیابی عمومی</h1></div>
                <div class="stats"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل سوالات: ${toPersianDigits(generalQuestions.length)}</div>
                <div style="margin-bottom:10px;">
                    <button class="btn btn-add" onclick="openAddModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 5v14M5 12h14"/></svg> افزودن سوال جدید</button>
                </div>
                <table><thead><tr><th>ردیف</th><th>متن سوال</th><th>گزینه‌های پاسخ (امتیاز)</th><th>عملیات</th></tr></thead><tbody>${rows}</tbody></table>
            </div>
            <div id="questionModal" class="modal"><div class="modal-content"><h2 id="modalTitle">ویرایش سوال</h2>
            <form id="questionForm"><input type="hidden" id="questionId">
            <textarea id="questionText" placeholder="متن سوال..." required></textarea>
            <div class="options-builder">
                <div class="options-builder-title">گزینه‌های پاسخ (متن گزینه و امتیازی که با انتخابش گرفته می‌شود):</div>
                <div id="optionsList"></div>
                <button type="button" class="btn-add-option" onclick="addOptionRow()">+ افزودن گزینه</button>
            </div>
            <div style="margin-top:20px; text-align:right;"><button type="submit" class="btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M5 4h11l3 3v13H5V4Z"/><path d="M8 4v5h7V4"/><path d="M8 13h8v7H8z"/></svg> ذخیره</button>
            <button type="button" class="btn btn-back" onclick="closeModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M6 6l12 12M18 6L6 18"/></svg> انصراف</button></div></form></div></div>
            <script>
                let allQuestions = ${safeJson(generalQuestions)};

                function addOptionRow(text, score) {
                    const list = document.getElementById('optionsList');
                    const row = document.createElement('div');
                    row.className = 'option-row';
                    row.innerHTML = '<input type="text" class="opt-text" placeholder="متن گزینه...">' +
                        '<input type="number" class="opt-score-input" placeholder="امتیاز" step="any">' +
                        '<button type="button" class="btn-remove-option" onclick="this.parentElement.remove()">×</button>';
                    list.appendChild(row);
                    row.querySelector('.opt-text').value = text || '';
                    row.querySelector('.opt-score-input').value = (score === undefined || score === null) ? '' : score;
                }
                function resetOptionsBuilder(options) {
                    document.getElementById('optionsList').innerHTML = '';
                    if (options && options.length) {
                        options.forEach(o => addOptionRow(o.text, o.score));
                    } else {
                        addOptionRow('', '');
                        addOptionRow('', '');
                    }
                }
                function collectOptions() {
                    return Array.from(document.querySelectorAll('#optionsList .option-row')).map(row => ({
                        text: row.querySelector('.opt-text').value.trim(),
                        score: parseFloat(row.querySelector('.opt-score-input').value)
                    }));
                }
                function openAddModal() {
                    document.getElementById('modalTitle').textContent = 'افزودن سوال جدید';
                    document.getElementById('questionId').value = '';
                    document.getElementById('questionText').value = '';
                    resetOptionsBuilder(null);
                    document.getElementById('questionModal').style.display = 'flex';
                }
                function closeModal() { document.getElementById('questionModal').style.display = 'none'; }
                function editQuestion(id) {
                    const q = allQuestions.find(q => q.id === id);
                    if (!q) return;
                    document.getElementById('modalTitle').textContent = 'ویرایش سوال';
                    document.getElementById('questionId').value = q.id;
                    document.getElementById('questionText').value = q.question;
                    resetOptionsBuilder(q.options);
                    document.getElementById('questionModal').style.display = 'flex';
                }
                async function deleteQuestion(id) { if(confirm('آیا از حذف این سوال مطمئن هستید؟')) { const res = await fetch('/api/general-question/' + id, { method: 'DELETE' }); const result = await res.json(); if(result.success) { alert('سوال حذف شد'); location.reload(); } else alert('خطا در حذف'); } }
                document.getElementById('questionForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const id = document.getElementById('questionId').value;
                    const question = document.getElementById('questionText').value;
                    const options = collectOptions();
                    if (options.some(o => !o.text || isNaN(o.score))) { alert('متن و امتیاز همه‌ی گزینه‌ها را کامل وارد کنید'); return; }
                    if (options.length < 2) { alert('حداقل دو گزینه‌ی پاسخ لازم است'); return; }
                    const url = id ? '/api/general-question/' + id : '/api/general-question';
                    const method = id ? 'PUT' : 'POST';
                    const res = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: question, options: options }) });
                    const result = await res.json();
                    if (result.success) { alert(id ? 'ویرایش شد' : 'سوال جدید اضافه شد'); location.reload(); } else alert(result.message || 'خطا');
                });
                window.onclick = function(event) { if(event.target === document.getElementById('questionModal')) closeModal(); }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API سوالات عمومی ====================
app.get('/api/general-questions', (req, res) => res.json(db.GeneralQuestions.listWithOptions()));

// هر سوال (عمومی یا تخصصی) باید حداقل دو گزینه‌ی پاسخ معتبر (متن + امتیاز عددی) داشته باشد
function validateQuestionOptions(options) {
    if (!Array.isArray(options) || options.length < 2) {
        return 'باید حداقل دو گزینه‌ی پاسخ برای سوال تعریف شود';
    }
    for (const opt of options) {
        if (!opt || typeof opt.text !== 'string' || !opt.text.trim()) {
            return 'متن همه‌ی گزینه‌ها باید پر شود';
        }
        if (typeof opt.score !== 'number' || !Number.isFinite(opt.score)) {
            return 'امتیاز همه‌ی گزینه‌ها باید یک عدد معتبر باشد';
        }
    }
    return null;
}

app.post('/api/general-question', requireRole('admin', 'management'), (req, res) => {
    const { question, options } = req.body;
    if (!question) {
        return res.json({ success: false, message: 'متن سوال وارد نشده است' });
    }
    const optionsError = validateQuestionOptions(options);
    if (optionsError) {
        return res.json({ success: false, message: optionsError });
    }
    const cleanOptions = options.map(o => ({ text: o.text.trim(), score: o.score }));
    db.GeneralQuestions.add(question, cleanOptions);
    addLog('افزودن سوال عمومی', 'سیستم', 'سوال جدید اضافه شد');
    res.json({ success: true });
});
app.put('/api/general-question/:id', requireRole('admin', 'management'), (req, res) => {
    const id = parseInt(req.params.id);
    const { question, options } = req.body;
    if (!question) {
        return res.json({ success: false, message: 'متن سوال وارد نشده است' });
    }
    const optionsError = validateQuestionOptions(options);
    if (optionsError) {
        return res.json({ success: false, message: optionsError });
    }
    const cleanOptions = options.map(o => ({ text: o.text.trim(), score: o.score }));
    if (db.GeneralQuestions.update(id, question, cleanOptions)) {
        addLog('ویرایش سوال عمومی', 'سیستم', 'سوال شماره ' + id + ' ویرایش شد');
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});
app.delete('/api/general-question/:id', requireRole('admin', 'management'), (req, res) => {
    db.GeneralQuestions.remove(parseInt(req.params.id));
    addLog('حذف سوال عمومی', 'سیستم', 'سوال شماره ' + req.params.id + ' حذف شد');
    res.json({ success: true });
});

// ==================== مدیریت سوالات تخصصی ====================
app.get('/hr/specialized-questions', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const organizationalPositions = db.Positions.list();
    const specializedQuestions = db.SpecializedQuestions.listWithOptions();
    const positionOptions = organizationalPositions.map(p =>
        `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)}</option>`
    ).join('');

    let rows = '';
    for (let i = 0; i < specializedQuestions.length; i++) {
        const q = specializedQuestions[i];
        const optionsPreview = q.options.map(o => escapeHtml(o.text) + ' <span class="opt-score">(' + toPersianDigits(o.score) + ')</span>').join('<br>');
        rows += '<tr>';
        rows += '<td style="text-align:center;">' + toPersianDigits(i+1) + '</td>';
        rows += '<td style="text-align:center;">' + escapeHtml(q.position) + '</td>';
        rows += '<td style="text-align:right;">' + escapeHtml(q.question) + '</td>';
        rows += '<td style="text-align:right; font-size:12px; color:#666;">' + optionsPreview + '</td>';
        rows += '<td style="text-align:center;"><button class="btn btn-edit" onclick="editQuestion(' + q.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg> ویرایش</button> <button class="btn btn-delete" onclick="deleteQuestion(' + q.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg> حذف</button></td>';
        rows += '</tr>';
    }

    if (specializedQuestions.length === 0) {
        rows = '<tr><td colspan="5" style="text-align:center;">هیچ سوالی ثبت نشده است</td></tr>';
    }
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>مدیریت سوالات تخصصی</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1000px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-edit { background: #E8963E; }
                .btn-delete { background: #ff4444; }
                .btn-add { background: #3E9188; font-size: 16px; }
                .inline-add-form { display: none; gap: 10px; margin-top: 14px; align-items: flex-start; background: #f9f9f9; padding: 16px; border-radius: 12px; border: 1px dashed #3E9188; flex-wrap: wrap; }
                .inline-add-panel.open .inline-add-form { display: flex; }
                .inline-add-form textarea { flex: 2 1 220px; margin: 0; min-height: 44px; }
                .inline-add-form select { max-width: 220px; }
                .inline-add-form .select-wrap { flex: 1 1 180px; width: auto; max-width: 220px; }
                .inline-add-form .btn { margin: 0; flex-shrink: 0; align-self: center; }
                .btn-back { background: #666; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
                th, td { padding: 12px 14px; border-bottom: 1px solid #eee; }
                th { background: #3E9188; color: white; text-align: center; padding: 14px 12px; font-weight: 600; letter-spacing: 0.3px; }
                tbody tr { transition: background 0.15s ease; }
                tbody tr:nth-child(even) { background: #FAFBFB; }
                tbody tr:hover { background: #EFF7F6; }
                .stats { background: #E6F2F0; padding: 10px; border-radius: 6px; margin: 15px 0; font-weight: bold; }
                .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; overflow-y: auto; padding: 20px 0; box-sizing: border-box; }
                .modal-content { background: white; padding: 25px; border-radius: 15px; width: 560px; max-width: 90%; max-height: 90vh; overflow-y: auto; }
                .modal-content input, .modal-content textarea, .modal-content select { width: 100%; padding: 8px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
                .modal-content textarea { height: 80px; resize: vertical; }
                .opt-score { color: #999; }
                .options-builder { margin: 14px 0; }
                .options-builder-title { font-weight: 600; font-size: 13px; color: #666; margin-bottom: 8px; }
                .option-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }
                .option-row input[type="text"] { flex: 1; margin: 0; }
                .option-row input[type="number"] { width: 80px; margin: 0; }
                .option-row .btn-remove-option { background: #ff4444; color: white; border: none; border-radius: 5px; width: 32px; height: 32px; cursor: pointer; flex-shrink: 0; }
                .btn-add-option { background: #E6F2F0; color: #3E9188; border: 1px dashed #3E9188; border-radius: 8px; padding: 8px 14px; cursor: pointer; font-weight: 600; font-size: 13px; }
                .filter-box { display: flex; gap: 10px; margin: 15px 0; flex-wrap: wrap; align-items: center; }
                .filter-box select { padding: 8px; border: 1px solid #ddd; border-radius: 5px; min-width: 150px; }
                @media (max-width: 768px) { .container { padding: 15px; } table { font-size: 12px; } th, td { padding: 6px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg></div><h1>مدیریت سوالات ارزیابی تخصصی</h1></div>
                <div class="stats"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل سوالات: ${toPersianDigits(specializedQuestions.length)}</div>
                
                <div class="filter-box">
                    <select id="filterPosition" onchange="filterByPosition()" style="min-width:200px;">
                        <option value="all">همه پست‌ها</option>
                        ${positionOptions}
                    </select>
                    <button class="btn btn-add" onclick="openAddModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M12 5v14M5 12h14"/></svg> افزودن سوال جدید</button>
                </div>
                <div class="table-container" style="max-height:500px; overflow-y:auto; overflow-x:hidden; border:1px solid #eee; border-radius:12px;">
                    <table id="questionsTable">
                        <thead><tr><th>ردیف</th><th>پست سازمانی</th><th>متن سوال</th><th>گزینه‌های پاسخ (امتیاز)</th><th>عملیات</th></tr></thead>
                        <tbody id="tableBody">${rows}</tbody>
                    </table>
                </div>
            </div>

            <div id="questionModal" class="modal">
                <div class="modal-content">
                    <h2 id="modalTitle">ویرایش سوال</h2>
                    <form id="questionForm">
                        <input type="hidden" id="questionId">
                        <label>پست سازمانی:</label>
                        <select id="questionPosition" required>
                            <option value="">-- انتخاب کنید --</option>
                            ${positionOptions}
                        </select>
                        <label>متن سوال:</label>
                        <textarea id="questionText" placeholder="متن سوال..." required></textarea>
                        <div class="options-builder">
                            <div class="options-builder-title">گزینه‌های پاسخ (متن گزینه و امتیازی که با انتخابش گرفته می‌شود):</div>
                            <div id="optionsList"></div>
                            <button type="button" class="btn-add-option" onclick="addOptionRow()">+ افزودن گزینه</button>
                        </div>
                        <div style="margin-top:20px; text-align:right;">
                            <button type="submit" class="btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M5 4h11l3 3v13H5V4Z"/><path d="M8 4v5h7V4"/><path d="M8 13h8v7H8z"/></svg> ذخیره</button>
                            <button type="button" class="btn btn-back" onclick="closeModal()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M6 6l12 12M18 6L6 18"/></svg> انصراف</button>
                        </div>
                    </form>
                </div>
            </div>

            <script>
                let allQuestions = ${safeJson(specializedQuestions)};

                function filterByPosition() {
                    const position = document.getElementById('filterPosition').value;
                    const rows = document.getElementById('tableBody').getElementsByTagName('tr');
                    let visible = 0;
                    for (let i = 0; i < rows.length; i++) {
                        const row = rows[i];
                        const cells = row.getElementsByTagName('td');
                        if (cells.length > 0) {
                            const pos = cells[1]?.innerText || '';
                            if (position === 'all' || pos === position) {
                                row.style.display = '';
                                visible++;
                            } else {
                                row.style.display = 'none';
                            }
                        }
                    }
                }

                function addOptionRow(text, score) {
                    const list = document.getElementById('optionsList');
                    const row = document.createElement('div');
                    row.className = 'option-row';
                    row.innerHTML = '<input type="text" class="opt-text" placeholder="متن گزینه...">' +
                        '<input type="number" class="opt-score-input" placeholder="امتیاز" step="any">' +
                        '<button type="button" class="btn-remove-option" onclick="this.parentElement.remove()">×</button>';
                    list.appendChild(row);
                    row.querySelector('.opt-text').value = text || '';
                    row.querySelector('.opt-score-input').value = (score === undefined || score === null) ? '' : score;
                }
                function resetOptionsBuilder(options) {
                    document.getElementById('optionsList').innerHTML = '';
                    if (options && options.length) {
                        options.forEach(o => addOptionRow(o.text, o.score));
                    } else {
                        addOptionRow('', '');
                        addOptionRow('', '');
                    }
                }
                function collectOptions() {
                    return Array.from(document.querySelectorAll('#optionsList .option-row')).map(row => ({
                        text: row.querySelector('.opt-text').value.trim(),
                        score: parseFloat(row.querySelector('.opt-score-input').value)
                    }));
                }
                function openAddModal() {
                    document.getElementById('modalTitle').textContent = 'افزودن سوال جدید';
                    document.getElementById('questionId').value = '';
                    document.getElementById('questionPosition').value = '';
                    document.getElementById('questionText').value = '';
                    resetOptionsBuilder(null);
                    document.getElementById('questionModal').style.display = 'flex';
                }

                function closeModal() {
                    document.getElementById('questionModal').style.display = 'none';
                }

                function editQuestion(id) {
                    const q = allQuestions.find(q => q.id === id);
                    if (q) {
                        document.getElementById('modalTitle').textContent = 'ویرایش سوال';
                        document.getElementById('questionId').value = q.id;
                        document.getElementById('questionPosition').value = q.position;
                        document.getElementById('questionText').value = q.question;
                        resetOptionsBuilder(q.options);
                        document.getElementById('questionModal').style.display = 'flex';
                    }
                }

                async function deleteQuestion(id) {
                    if (confirm('آیا از حذف این سوال مطمئن هستید؟')) {
                        const res = await fetch('/api/specialized-question/' + id, { method: 'DELETE' });
                        const result = await res.json();
                        if (result.success) {
                            alert('سوال حذف شد');
                            location.reload();
                        } else alert('خطا در حذف');
                    }
                }

                document.getElementById('questionForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const id = document.getElementById('questionId').value;
                    const data = {
                        position: document.getElementById('questionPosition').value,
                        question: document.getElementById('questionText').value,
                        options: collectOptions()
                    };

                    if (!data.position) { alert('لطفاً پست سازمانی را انتخاب کنید'); return; }
                    if (!data.question) { alert('لطفاً متن سوال را وارد کنید'); return; }
                    if (data.options.some(o => !o.text || isNaN(o.score))) { alert('متن و امتیاز همه‌ی گزینه‌ها را کامل وارد کنید'); return; }
                    if (data.options.length < 2) { alert('حداقل دو گزینه‌ی پاسخ لازم است'); return; }

                    const url = id ? '/api/specialized-question/' + id : '/api/specialized-question';
                    const method = id ? 'PUT' : 'POST';
                    const res = await fetch(url, {
                        method: method,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    const result = await res.json();
                    if (result.success) {
                        alert(id ? 'سوال ویرایش شد' : 'سوال جدید اضافه شد');
                        location.reload();
                    } else alert(result.message || 'خطا');
                });

                window.onclick = function(event) {
                    if (event.target === document.getElementById('questionModal')) closeModal();
                }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API سوالات تخصصی ====================
app.get('/api/specialized-questions', (req, res) => res.json(db.SpecializedQuestions.listWithOptions()));
app.get('/api/specialized-questions/:position', (req, res) => {
    res.json(db.SpecializedQuestions.listByPositionWithOptions(req.params.position));
});

app.post('/api/specialized-question', requireRole('admin', 'management'), (req, res) => {
    const { position, question, options } = req.body;
    if (!position || !question) {
        return res.json({ success: false, message: 'اطلاعات ناقص است' });
    }
    const optionsError = validateQuestionOptions(options);
    if (optionsError) {
        return res.json({ success: false, message: optionsError });
    }
    const cleanOptions = options.map(o => ({ text: o.text.trim(), score: o.score }));
    if (db.SpecializedQuestions.add(position, question, cleanOptions)) {
        addLog('افزودن سوال تخصصی', 'سیستم', 'سوال برای پست "' + position + '" اضافه شد');
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'پست سازمانی یافت نشد' });
    }
});

app.put('/api/specialized-question/:id', requireRole('admin', 'management'), (req, res) => {
    const id = parseInt(req.params.id);
    const { position, question, options } = req.body;
    const optionsError = validateQuestionOptions(options);
    if (optionsError) {
        return res.json({ success: false, message: optionsError });
    }
    const cleanOptions = options.map(o => ({ text: o.text.trim(), score: o.score }));
    if (db.SpecializedQuestions.update(id, position, question, cleanOptions)) {
        addLog('ویرایش سوال تخصصی', 'سیستم', 'سوال شماره ' + id + ' ویرایش شد');
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

app.delete('/api/specialized-question/:id', requireRole('admin', 'management'), (req, res) => {
    const id = parseInt(req.params.id);
    const deleted = db.SpecializedQuestions.remove(id);
    if (deleted) {
        addLog('حذف سوال تخصصی', 'سیستم', 'سوال برای پست "' + deleted.position + '" حذف شد');
    }
    res.json({ success: true });
});

// ==================== ارزیابی ۳۶۰ درجه ====================

// صفحه ارزیابی عمومی
app.get('/exam/general', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;

    const user = db.Accounts.findByUsername(username);
    if (!user) return res.redirect('/');

    const generalQuestions = db.GeneralQuestions.listWithOptions();
    if (generalQuestions.length === 0) {
        return res.send(`

            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>ارزیابی عمومی</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon" style="background: rgba(242,185,13,0.15); color: #A67C00;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg></div>
                    <h1>ارزیابی عمومی</h1>
                    <p>هنوز سوالی برای ارزیابی عمومی ثبت نشده است.</p>
                    <button class="btn-back" onclick="location.href='/dashboard?user=${username}&role=${role}'">بازگشت به داشبورد</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }
    
    // این یک سامانه‌ی ارزیابی ۳۶۰ درجه‌ی درون‌بخشی است: هر شخص فقط پرسنل واحد
    // سازمانی خودش را ارزیابی می‌کند (به جز خودش). ادمین/مدیریت واحد ندارند،
    // پس برای آن‌ها این محدودیت اعمال نمی‌شود و می‌توانند هر کسی را انتخاب کنند.
    const userUnit = user.unit || '';
    const isAdminOrManagement = role === 'admin' || role === 'management';
    const personnelList = isAdminOrManagement
        ? db.Personnel.list().filter(p => p.nationalCode !== username)
        : db.Personnel.list().filter(p => p.unit === userUnit && p.nationalCode !== username);
    let personnelOptions = '';
    let hasTargets = false;
    for (const p of personnelList) {
        // بررسی اینکه قبلاً این فرد را ارزیابی کرده یا نه
        const alreadyEvaluated = hasUserEvaluated(username, p.nationalCode, 'general');
        const disabled = alreadyEvaluated ? 'disabled' : '';
        const label = alreadyEvaluated ? p.fullname + ' (ارزیابی شده)' : p.fullname;
        personnelOptions += `<option value="${escapeHtml(p.nationalCode)}" ${disabled}>${escapeHtml(label)}</option>`;
        if (!alreadyEvaluated) hasTargets = true;
    }
    
    if (!hasTargets && personnelList.length > 0) {
        return res.send(`

            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>ارزیابی عمومی</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon" style="background: rgba(62,145,136,0.12); color: #3E9188;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 5-5"/></svg></div>
                    <h1>ارزیابی عمومی</h1>
                    <p>${isAdminOrManagement ? 'شما قبلاً به تمام پرسنل امتیاز داده‌اید.' : 'شما قبلاً به تمام پرسنل واحد خود امتیاز داده‌اید.'}</p>
                    <button class="btn-back" onclick="location.href='/dashboard?user=${username}&role=${role}'">بازگشت به داشبورد</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }
    
    if (personnelList.length === 0) {
        return res.send(`

            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>ارزیابی عمومی</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon" style="background: rgba(242,185,13,0.15); color: #A67C00;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg></div>
                    <h1>ارزیابی عمومی</h1>
                    <p>${isAdminOrManagement ? 'هیچ پرسنلی برای ارزیابی وجود ندارد.' : `هیچ پرسنل دیگری در واحد "${escapeHtml(userUnit || 'نامشخص')}" برای ارزیابی وجود ندارد.`}</p>
                    <button class="btn-back" onclick="location.href='/dashboard?user=${username}&role=${role}'">بازگشت به داشبورد</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }
    
    // ساخت فرم سوالات؛ هر سوال گزینه‌های پاسخ اختصاصی خودش را دارد
    let questionsHtml = '';
    generalQuestions.forEach((q, index) => {
        const optionsHtml = q.options.map(o =>
            `<label><input type="radio" name="q${q.id}" value="${o.score}"> ${escapeHtml(o.text)}</label>`
        ).join('');
        questionsHtml += `
            <div class="question-box">
                <h3>سوال ${toPersianDigits(index + 1)}:</h3>
                <p>${escapeHtml(q.question)}</p>
                <div class="options">
                    ${optionsHtml}
                </div>
            </div>
        `;
    });
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>ارزیابی عمومی</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 11px 22px; border-radius: 10px; cursor: pointer; margin: 5px; font-size: 16px; font-weight: 600; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; }
                .btn-submit { background: #3E9188; font-size: 18px; padding: 12px 40px; }
                .btn-submit:disabled { background: #ccc; cursor: not-allowed; }
                .question-box { background: #f9f9f9; padding: 20px; border-radius: 10px; margin: 20px 0; border-right: 4px solid #3E9188; }
                .question-box h3 { color: #1A1A1A; margin-bottom: 10px; }
                .question-box p { font-size: 16px; color: #555; margin-bottom: 15px; }
                .options { display: flex; flex-direction: column; gap: 10px; }
                .options label { display: flex; align-items: flex-start; gap: 10px; cursor: pointer; width: 100%; box-sizing: border-box; padding: 12px 16px; border-radius: 8px; transition: 0.2s; border: 1px solid #ddd; background: white; line-height: 1.7; }
                .options label:hover { background: #E6F2F0; border-color: #3E9188; }
                .options input[type="radio"] { flex-shrink: 0; margin: 3px 0 0 0; }
                .header { background: rgba(255,255,255,0.95); padding: 15px 20px; border-radius: 10px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
                .personnel-select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; margin-bottom: 20px; box-sizing: border-box; }
                .already-evaluated { color: #999; font-style: italic; }
                @media (max-width: 768px) { .container { padding: 15px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/dashboard?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="header">
                    <div><strong><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/></svg> ${escapeHtml(user.fullname)}</strong> - ${escapeHtml(user.position || 'کاربر')}</div>

                </div>
                <h1><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 10h6M9 13h6M9 16h4"/></svg> ارزیابی عمومی (۳۶۰ درجه)</h1>
                <p style="color:#666; margin-bottom:10px;">لطفاً شخص مورد ارزیابی را انتخاب کنید و به سوالات پاسخ دهید.</p>
                <p style="color:#A67C00; font-size:14px;">توجه: هر شخص فقط یک بار قابل ارزیابی است.</p>
                
                <select class="personnel-select" id="targetPersonnel" required onchange="checkTarget()">
                    <option value="">-- انتخاب شخص مورد ارزیابی --</option>
                    ${personnelOptions}
                </select>
                <div id="targetStatus" style="margin-bottom:15px;"></div>
                
                <form id="examForm" onsubmit="submitGeneralExam(event)">
                    <div id="questionsContainer">
                        ${questionsHtml}
                    </div>
                    <div style="text-align:center; margin-top:30px;">
                        <button type="submit" class="btn btn-submit" id="submitBtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4 20-7Z"/></svg> ثبت ارزیابی</button>
                    </div>
                </form>
                <div id="result" style="margin-top:20px;"></div>
            </div>
            
            <script>
                function checkTarget() {
                    const target = document.getElementById('targetPersonnel').value;
                    const statusDiv = document.getElementById('targetStatus');
                    if (target) {
                        const option = document.getElementById('targetPersonnel').options[document.getElementById('targetPersonnel').selectedIndex];
                        if (option.disabled) {
                            statusDiv.innerHTML = '<span style="color:#A67C00;">این شخص قبلاً توسط شما ارزیابی شده است.</span>';
                            document.getElementById('submitBtn').disabled = true;
                        } else {
                            statusDiv.innerHTML = '<span style="color:#3E9188;">این شخص قابل ارزیابی است.</span>';
                            document.getElementById('submitBtn').disabled = false;
                        }
                    } else {
                        statusDiv.innerHTML = '';
                        document.getElementById('submitBtn').disabled = true;
                    }
                }
                
                function toFa(n) { return String(n).replace(/[0-9]/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]); }
                async function submitGeneralExam(e) {
                    e.preventDefault();
                    const targetPersonnel = document.getElementById('targetPersonnel').value;
                    if (!targetPersonnel) {
                        alert('لطفاً شخص مورد ارزیابی را انتخاب کنید.');
                        return;
                    }

                    const option = document.getElementById('targetPersonnel').options[document.getElementById('targetPersonnel').selectedIndex];
                    if (option.disabled) {
                        alert('این شخص قبلاً توسط شما ارزیابی شده است.');
                        return;
                    }

                    const container = document.getElementById('questionsContainer');
                    const radios = container.querySelectorAll('input[type="radio"]');
                    const names = Array.from(new Set(Array.from(radios).map(r => r.name)));
                    const answers = {};
                    let allAnswered = true;
                    names.forEach(name => {
                        const checked = container.querySelector('input[name="' + name + '"]:checked');
                        const qId = name.slice(1);
                        answers[qId] = checked ? checked.value : null;
                        if (!checked) allAnswered = false;
                    });

                    if (!allAnswered) {
                        alert('لطفاً به تمام سوالات پاسخ دهید.');
                        return;
                    }

                    const res = await fetch('/api/evaluation/general/submit', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            evaluator: '${username}',
                            target: targetPersonnel,
                            answers: answers 
                        })
                    });
                    const result = await res.json();
                    if (result.success) {
                        document.getElementById('result').innerHTML = '<div style="background:#E6F2F0; padding:20px; border-radius:10px; text-align:center;"><h2 style="color:#3E9188;">ارزیابی با موفقیت ثبت شد</h2><p>امتیاز: ' + toFa(result.score) + ' از ' + toFa(result.total) + '</p></div>';
                        document.getElementById('examForm').querySelector('button[type="submit"]').disabled = true;
                        document.getElementById('targetPersonnel').disabled = true;
                    } else {
                        alert('خطا در ثبت ارزیابی: ' + (result.message || 'مشخص نیست'));
                    }
                }
                
                // بررسی اولیه
                checkTarget();
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// صفحه ارزیابی تخصصی
app.get('/exam/specialized', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;

    const user = db.Accounts.findByUsername(username);
    if (!user) return res.redirect('/');

    const userPosition = user.position || '';
    const positionQuestions = db.SpecializedQuestions.listByPositionWithOptions(userPosition);
    // ادمین و مدیریت خودشان پست سازمانی ندارند، پس نمی‌توانند طرف ارزیابیِ
    // «هم‌پست» باشند؛ برای آن‌ها باید بشود هر شخصی را انتخاب کرد و سوالات
    // متناسب با پست همان شخص (نه پست ارزیابی‌کننده) نمایش داده شود.
    const isAdminOrManagement = role === 'admin' || role === 'management';
    const allSpecializedQuestions = db.SpecializedQuestions.listWithOptions();
    const questionsByPosition = {};
    allSpecializedQuestions.forEach(q => {
        if (!questionsByPosition[q.position]) questionsByPosition[q.position] = [];
        questionsByPosition[q.position].push({ id: q.id, question: q.question, options: q.options });
    });

    const noQuestionsAtAll = isAdminOrManagement ? allSpecializedQuestions.length === 0 : positionQuestions.length === 0;
    if (noQuestionsAtAll) {
        return res.send(`

            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>ارزیابی تخصصی</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon" style="background: rgba(242,185,13,0.15); color: #A67C00;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg></div>
                    <h1>ارزیابی تخصصی</h1>
                    <p>برای پست سازمانی شما (${userPosition || 'نامشخص'}) سوالی ثبت نشده است.</p>
                    <button class="btn-back" onclick="location.href='/dashboard?user=${username}&role=${role}'">بازگشت به داشبورد</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }
    
    // ادمین/مدیریت: هر پرسنلی قابل انتخاب است (بدون محدودیت هم‌پست بودن).
    // پرسنل عادی: فقط هم‌پست‌های خودش، طبق منطق ارزیابی همتا به همتا.
    const personnelList = isAdminOrManagement
        ? db.Personnel.list().filter(p => p.nationalCode !== username)
        : db.Personnel.list().filter(p => p.position === userPosition && p.nationalCode !== username);
    let personnelOptions = '';
    let hasTargets = false;
    for (const p of personnelList) {
        const alreadyEvaluated = hasUserEvaluated(username, p.nationalCode, 'specialized');
        const disabled = alreadyEvaluated ? 'disabled' : '';
        const label = alreadyEvaluated ? p.fullname + ' (ارزیابی شده)' : p.fullname;
        personnelOptions += `<option value="${escapeHtml(p.nationalCode)}" data-position="${escapeHtml(p.position || '')}" ${disabled}>${escapeHtml(label)}</option>`;
        if (!alreadyEvaluated) hasTargets = true;
    }

    if (!hasTargets && personnelList.length > 0) {
        return res.send(`

            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>ارزیابی تخصصی</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon" style="background: rgba(62,145,136,0.12); color: #3E9188;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 5-5"/></svg></div>
                    <h1>ارزیابی تخصصی</h1>
                    <p>${isAdminOrManagement ? 'شما قبلاً به تمام پرسنل امتیاز داده‌اید.' : 'شما قبلاً به تمام پرسنل هم‌پست خود امتیاز داده‌اید.'}</p>
                    <button class="btn-back" onclick="location.href='/dashboard?user=${username}&role=${role}'">بازگشت به داشبورد</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }
    
    if (personnelList.length === 0) {
        return res.send(`

            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head><meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet"><title>ارزیابی تخصصی</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif;
                    background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: #1A1A1A;
                    -webkit-font-smoothing: antialiased;
                }
                .status-card {
                    background: white;
                    border-radius: 24px;
                    padding: 48px 40px;
                    max-width: 420px;
                    width: 100%;
                    text-align: center;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                }
                .status-icon {
                    width: 84px;
                    height: 84px;
                    border-radius: 50%;
                    margin: 0 auto 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .status-icon svg { width: 40px; height: 40px; }
                .status-card h1 { font-size: 1.3rem; margin-bottom: 12px; color: #1A1A1A; }
                .status-card p { color: #666; font-size: 0.95rem; line-height: 1.7; margin-bottom: 28px; }
                .btn-back {
                    display: inline-block;
                    background: #3E9188;
                    color: white;
                    border: none;
                    padding: 12px 28px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 4px 12px rgba(62,145,136,0.3);
                }
                .btn-back:hover { background: #337971; transform: translateY(-1px); }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style></head>
            <body>
                <div class="status-card">
                    <div class="status-icon" style="background: rgba(242,185,13,0.15); color: #A67C00;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg></div>
                    <h1>ارزیابی تخصصی</h1>
                    <p>${isAdminOrManagement ? 'هیچ پرسنلی برای ارزیابی وجود ندارد.' : `هیچ پرسنل دیگری با پست "${userPosition}" برای ارزیابی وجود ندارد.`}</p>
                    <button class="btn-back" onclick="location.href='/dashboard?user=${username}&role=${role}'">بازگشت به داشبورد</button>
                </div>
            <script>
            (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
            </html>
        `);
    }
    
    // برای ادمین/مدیریت، سوالات بسته به پستِ شخصِ انتخاب‌شده تغییر می‌کنند
    // (سمت کلاینت، از روی نقشه‌ی questionsByPosition)، پس این‌جا فقط یک پیام
    // راهنما نمایش داده می‌شود؛ برای پرسنل عادی، سوالاتِ پستِ خودش ثابت است.
    let questionsHtml = '';
    if (isAdminOrManagement) {
        questionsHtml = '<p style="color:#999; text-align:center; padding:20px;">ابتدا شخص مورد ارزیابی را انتخاب کنید.</p>';
    }
    positionQuestions.forEach((q, index) => {
        const optionsHtml = q.options.map(o =>
            `<label><input type="radio" name="q${q.id}" value="${o.score}"> ${escapeHtml(o.text)}</label>`
        ).join('');
        questionsHtml += `
            <div class="question-box">
                <h3>سوال ${toPersianDigits(index + 1)}:</h3>
                <p>${escapeHtml(q.question)}</p>
                <div class="options">
                    ${optionsHtml}
                </div>
            </div>
        `;
    });
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>ارزیابی تخصصی</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 11px 22px; border-radius: 10px; cursor: pointer; margin: 5px; font-size: 16px; font-weight: 600; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; }
                .btn-submit { background: #3E9188; font-size: 18px; padding: 12px 40px; }
                .btn-submit:disabled { background: #ccc; cursor: not-allowed; }
                .question-box { background: #f9f9f9; padding: 20px; border-radius: 10px; margin: 20px 0; border-right: 4px solid #E8963E; }
                .question-box h3 { color: #1A1A1A; margin-bottom: 10px; }
                .question-box p { font-size: 16px; color: #555; margin-bottom: 15px; }
                .options { display: flex; flex-direction: column; gap: 10px; }
                .options label { display: flex; align-items: flex-start; gap: 10px; cursor: pointer; width: 100%; box-sizing: border-box; padding: 12px 16px; border-radius: 8px; transition: 0.2s; border: 1px solid #ddd; background: white; line-height: 1.7; }
                .options label:hover { background: #FBE9D3; border-color: #E8963E; }
                .options input[type="radio"] { flex-shrink: 0; margin: 3px 0 0 0; }
                .header { background: rgba(255,255,255,0.95); padding: 15px 20px; border-radius: 10px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
                .position-badge { background: #E8963E; color: white; padding: 5px 15px; border-radius: 20px; font-size: 14px; }
                .personnel-select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; margin-bottom: 20px; box-sizing: border-box; }
                .already-evaluated { color: #999; font-style: italic; }
                @media (max-width: 768px) { .container { padding: 15px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/dashboard?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="header">
                    <div>
                        <strong><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/></svg> ${escapeHtml(user.fullname)}</strong>
                        <span class="position-badge">${escapeHtml(userPosition)}</span>
                    </div>
                    
                </div>
                <h1><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg> ارزیابی تخصصی (۳۶۰ درجه)</h1>
                <p style="color:#666; margin-bottom:10px;">لطفاً شخص مورد ارزیابی را انتخاب کنید و به سوالات تخصصی پاسخ دهید.</p>
                <p style="color:#A67C00; font-size:14px;">توجه: هر شخص فقط یک بار قابل ارزیابی است.</p>
                
                <select class="personnel-select" id="targetPersonnel" required onchange="checkTarget()">
                    <option value="">-- انتخاب شخص مورد ارزیابی --</option>
                    ${personnelOptions}
                </select>
                <div id="targetStatus" style="margin-bottom:15px;"></div>
                
                <form id="examForm" onsubmit="submitSpecializedExam(event)">
                    <div id="questionsContainer">
                        ${questionsHtml}
                    </div>
                    <div style="text-align:center; margin-top:30px;">
                        <button type="submit" class="btn btn-submit" id="submitBtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4 20-7Z"/></svg> ثبت ارزیابی</button>
                    </div>
                </form>
                <div id="result" style="margin-top:20px;"></div>
            </div>
            
            <script>
                var isAdminSpecializedMode = ${isAdminOrManagement ? 'true' : 'false'};
                var questionsByPosition = ${isAdminOrManagement ? safeJson(questionsByPosition) : '{}'};
                function toFa(n) { return String(n).replace(/[0-9]/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]); }
                function escHtmlSpec(s) {
                    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
                }
                function renderQuestionsForPosition(positionName) {
                    const container = document.getElementById('questionsContainer');
                    const qs = questionsByPosition[positionName] || [];
                    if (qs.length === 0) {
                        container.innerHTML = '<p style="color:#999; text-align:center; padding:20px;">سوال تخصصی‌ای برای پست «' + escHtmlSpec(positionName || 'نامشخص') + '» ثبت نشده است.</p>';
                        return;
                    }
                    let html = '';
                    qs.forEach((q, i) => {
                        const optionsHtml = (q.options || []).map(o =>
                            '<label><input type="radio" name="q' + q.id + '" value="' + o.score + '"> ' + escHtmlSpec(o.text) + '</label>'
                        ).join('');
                        html += '<div class="question-box"><h3>سوال ' + toFa(i + 1) + ':</h3><p>' + escHtmlSpec(q.question) + '</p><div class="options">' + optionsHtml + '</div></div>';
                    });
                    container.innerHTML = html;
                }
                function checkTarget() {
                    const select = document.getElementById('targetPersonnel');
                    const target = select.value;
                    const statusDiv = document.getElementById('targetStatus');
                    if (target) {
                        const option = select.options[select.selectedIndex];
                        if (isAdminSpecializedMode) renderQuestionsForPosition(option.dataset.position || '');
                        if (option.disabled) {
                            statusDiv.innerHTML = '<span style="color:#A67C00;">این شخص قبلاً توسط شما ارزیابی شده است.</span>';
                            document.getElementById('submitBtn').disabled = true;
                        } else {
                            statusDiv.innerHTML = '<span style="color:#3E9188;">این شخص قابل ارزیابی است.</span>';
                            document.getElementById('submitBtn').disabled = false;
                        }
                    } else {
                        statusDiv.innerHTML = '';
                        document.getElementById('submitBtn').disabled = true;
                        if (isAdminSpecializedMode) {
                            document.getElementById('questionsContainer').innerHTML = '<p style="color:#999; text-align:center; padding:20px;">ابتدا شخص مورد ارزیابی را انتخاب کنید.</p>';
                        }
                    }
                }

                async function submitSpecializedExam(e) {
                    e.preventDefault();
                    const select = document.getElementById('targetPersonnel');
                    const targetPersonnel = select.value;
                    if (!targetPersonnel) {
                        alert('لطفاً شخص مورد ارزیابی را انتخاب کنید.');
                        return;
                    }

                    const option = select.options[select.selectedIndex];
                    if (option.disabled) {
                        alert('این شخص قبلاً توسط شما ارزیابی شده است.');
                        return;
                    }

                    const container = document.getElementById('questionsContainer');
                    const radios = container.querySelectorAll('input[type="radio"]');
                    const names = Array.from(new Set(Array.from(radios).map(r => r.name)));
                    if (names.length === 0) {
                        alert('سوالی برای پاسخ‌گویی وجود ندارد.');
                        return;
                    }

                    const answers = {};
                    let allAnswered = true;
                    names.forEach(name => {
                        const checked = container.querySelector('input[name="' + name + '"]:checked');
                        const qId = name.slice(1);
                        answers[qId] = checked ? checked.value : null;
                        if (!checked) allAnswered = false;
                    });

                    if (!allAnswered) {
                        alert('لطفاً به تمام سوالات پاسخ دهید.');
                        return;
                    }

                    const res = await fetch('/api/evaluation/specialized/submit', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            evaluator: '${username}',
                            target: targetPersonnel,
                            position: option.dataset.position || '${userPosition}',
                            answers: answers
                        })
                    });
                    const result = await res.json();
                    if (result.success) {
                        document.getElementById('result').innerHTML = '<div style="background:#E6F2F0; padding:20px; border-radius:10px; text-align:center;"><h2 style="color:#3E9188;">ارزیابی با موفقیت ثبت شد</h2><p>امتیاز: ' + toFa(result.score) + ' از ' + toFa(result.total) + '</p></div>';
                        document.getElementById('examForm').querySelector('button[type="submit"]').disabled = true;
                        document.getElementById('targetPersonnel').disabled = true;
                    } else {
                        alert('خطا در ثبت ارزیابی: ' + (result.message || 'مشخص نیست'));
                    }
                }

                checkTarget();
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API ثبت ارزیابی ====================
app.post('/api/evaluation/general/submit', (req, res) => {
    // evaluator همیشه از نشست فعلی خوانده می‌شود، نه از بدنه‌ی درخواست؛
    // در غیر این صورت هر کاربر می‌توانست به‌جای شخص دیگری ارزیابی ثبت کند.
    const evaluator = req.session.user.username;
    const { target, answers } = req.body;
    if (!target || !answers) {
        return res.json({ success: false, message: 'اطلاعات ناقص است' });
    }

    if (evaluator === target) {
        return res.json({ success: false, message: 'شما نمی‌توانید خودتان را ارزیابی کنید' });
    }

    if (!db.Accounts.findByUsername(target)) {
        return res.json({ success: false, message: 'شخص مورد ارزیابی یافت نشد' });
    }

    // بررسی اینکه قبلاً ارزیابی ثبت نشده باشد
    if (hasUserEvaluated(evaluator, target, 'general')) {
        return res.json({ success: false, message: 'شما قبلاً این شخص را ارزیابی کرده‌اید' });
    }

    // هر سوال عمومی گزینه‌های پاسخ اختصاصی با امتیاز دلخواه دارد؛ پاسخ ارسالی
    // باید دقیقاً برابر امتیاز یکی از گزینه‌های همان سوال باشد (نه یک بازه‌ی ثابت ۱ تا ۴).
    const generalQuestions = db.GeneralQuestions.listWithOptions();
    const answersById = new Map();
    for (const [qId, answer] of Object.entries(answers)) {
        const q = generalQuestions.find(q => q.id === parseInt(qId));
        if (!q || !q.options.length) continue;
        const answerValue = parseFloat(answer);
        const matchedOption = q.options.find(o => o.score === answerValue);
        if (!matchedOption) continue;
        const maxScore = Math.max(...q.options.map(o => o.score));
        answersById.set(parseInt(qId), { question: q.question, answer: answerValue, maxScore });
    }

    const result = db.Evaluations.submit({ evaluator, target, type: 'general', answersById });

    addLog('ثبت ارزیابی عمومی', evaluator, 'ارزیابی از ' + target + ' - امتیاز: ' + result.score + ' از ' + result.total);
    res.json({ success: true, score: result.score, total: result.total });
});

app.post('/api/evaluation/specialized/submit', (req, res) => {
    const evaluator = req.session.user.username;
    const { target, position, answers } = req.body;
    if (!target || !answers) {
        return res.json({ success: false, message: 'اطلاعات ناقص است' });
    }

    if (evaluator === target) {
        return res.json({ success: false, message: 'شما نمی‌توانید خودتان را ارزیابی کنید' });
    }

    if (!db.Accounts.findByUsername(target)) {
        return res.json({ success: false, message: 'شخص مورد ارزیابی یافت نشد' });
    }

    if (hasUserEvaluated(evaluator, target, 'specialized')) {
        return res.json({ success: false, message: 'شما قبلاً این شخص را ارزیابی کرده‌اید' });
    }

    // هر سوال تخصصی گزینه‌های پاسخ اختصاصی با امتیاز دلخواه دارد؛ پاسخ ارسالی
    // باید دقیقاً برابر امتیاز یکی از گزینه‌های همان سوال باشد (نه یک بازه‌ی ثابت ۱ تا ۴).
    const specializedQuestions = db.SpecializedQuestions.listWithOptions();
    const answersById = new Map();
    for (const [qId, answer] of Object.entries(answers)) {
        const q = specializedQuestions.find(q => q.id === parseInt(qId));
        if (!q || !q.options.length) continue;
        const answerValue = parseFloat(answer);
        const matchedOption = q.options.find(o => o.score === answerValue);
        if (!matchedOption) continue;
        const maxScore = Math.max(...q.options.map(o => o.score));
        answersById.set(parseInt(qId), { question: q.question, answer: answerValue, maxScore });
    }

    const result = db.Evaluations.submit({ evaluator, target, type: 'specialized', answersById });

    addLog('ثبت ارزیابی تخصصی', evaluator, 'ارزیابی از ' + target + ' - پست: ' + position + ' - امتیاز: ' + result.score + ' از ' + result.total);
    res.json({ success: true, score: result.score, total: result.total });
});

// ==================== کارنامه ارزیابی ====================
app.get('/exam/results', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;

    const user = db.Accounts.findByUsername(username);
    if (!user) return res.redirect('/');

    const isAdmin = role === 'admin' || role === 'management';
    const userResults = db.Evaluations.listForUser(username, isAdmin);

    let rows = '';
    for (const r of userResults) {
        const typeLabel = r.type === 'general' ? 'عمومی' : 'تخصصی';
        const date = new Date(r.date).toLocaleDateString('fa-IR');
        const time = new Date(r.date).toLocaleTimeString('fa-IR');

        const evaluatorAccount = db.Accounts.findByUsername(r.evaluator);
        const targetAccount = db.Accounts.findByUsername(r.target);
        const evaluatorName = evaluatorAccount?.fullname || r.evaluator;
        const targetName = targetAccount?.fullname || r.target;
        const targetPosition = targetAccount?.position || '-';
        
        rows += '<tr>';
        rows += '<td style="text-align:center;">' + toPersianDigits(r.id) + '</td>';
        rows += '<td style="text-align:center;">' + escapeHtml(evaluatorName) + '</td>';
        rows += '<td style="text-align:center;">' + escapeHtml(targetName) + '</td>';
        rows += '<td style="text-align:center;">' + escapeHtml(targetPosition) + '</td>';
        rows += '<td style="text-align:center;">' + typeLabel + '</td>';
        rows += '<td style="text-align:center;">' + toPersianDigits(r.score) + '</td>';
        rows += '<td style="text-align:center;">' + toPersianDigits(r.total) + '</td>';
        rows += '<td style="text-align:center;">' + toPersianDigits(r.percentage) + '%</td>';
        if (isAdmin) {
            rows += '<td style="text-align:center;"><button class="btn-delete" onclick="deleteEvaluation(' + r.id + ')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/></svg> حذف</button></td>';
        }
        rows += '</tr>';
    }
    
    const colCount = isAdmin ? 9 : 8;
    if (userResults.length === 0) {
        rows = '<tr><td colspan="' + colCount + '" style="text-align:center; padding:30px;">هیچ ارزیابی ثبت نشده است</td></tr>';
    }
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>کارنامه ارزیابی</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; }
                .btn-delete { background: #ff4444; color: white; border: none; padding: 6px 12px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 13px; transition: all 0.2s ease; }
                .btn-delete:hover { background: #cc0000; transform: translateY(-1px); }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
                th, td { padding: 12px 14px; border-bottom: 1px solid #eee; }
                th { background: #3E9188; color: white; text-align: center; padding: 14px 12px; font-weight: 600; letter-spacing: 0.3px; }
                tbody tr { transition: background 0.15s ease; }
                tbody tr:nth-child(even) { background: #FAFBFB; }
                tbody tr:hover { background: #EFF7F6; }
                .stats { background: #E6F2F0; padding: 10px; border-radius: 6px; margin: 15px 0; font-weight: bold; }
                .table-container { max-height: 500px; overflow-y: auto; overflow-x: hidden; border: 1px solid #eee; border-radius: 12px; }
                @media (max-width: 768px) { .container { padding: 15px; } table { font-size: 12px; } th, td { padding: 6px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg></div><h1>کارنامه ارزیابی</h1></div>
                <div class="stats"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> تعداد کل ارزیابی‌ها: ${toPersianDigits(userResults.length)}</div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>ارزیاب</th>
                                <th>هدف</th>
                                <th>پست</th>
                                <th>نوع</th>
                                <th>امتیاز</th>
                                <th>مجموع</th>
                                <th>درصد</th>
                                ${isAdmin ? '<th>عملیات</th>' : ''}
                            </tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </div>
            
            <script>
                async function deleteEvaluation(id) {
                    if (!confirm('آیا از حذف این ارزیابی مطمئن هستید؟ این عمل قابل بازگشت نیست.')) return;
                    const res = await fetch('/api/evaluation/' + id, { method: 'DELETE' });
                    const result = await res.json();
                    if (result.success) {
                        alert('ارزیابی با موفقیت حذف شد');
                        location.reload();
                    } else {
                        alert('خطا در حذف ارزیابی: ' + (result.message || 'مشخص نیست'));
                    }
                }
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API حذف ارزیابی ====================
app.delete('/api/evaluation/:id', requireRole('admin', 'management'), (req, res) => {
    const id = parseInt(req.params.id);
    const deleted = db.Evaluations.findById(id);
    if (!deleted) {
        return res.json({ success: false, message: 'ارزیابی یافت نشد' });
    }

    db.Evaluations.remove(id);
    addLog('حذف ارزیابی', 'سیستم', 'ارزیابی شماره ' + id + ' توسط ' + deleted.evaluator + ' برای ' + deleted.target + ' حذف شد');
    res.json({ success: true });
});

// ==================== گزارش‌های کلی ====================
app.get('/exam/reports', (req, res) => {
    const username = req.session.user.username;
    const role = req.session.user.effectiveRole;
    if (role !== 'admin' && role !== 'management') return res.redirect('/');

    const evaluationResults = db.Evaluations.all();
    const totalEvaluations = evaluationResults.length;
    const generalExams = evaluationResults.filter(r => r.type === 'general').length;
    const specializedExams = evaluationResults.filter(r => r.type === 'specialized').length;
    const avgScore = evaluationResults.length > 0 ? Math.round(evaluationResults.reduce((sum, r) => sum + r.percentage, 0) / evaluationResults.length) : 0;

    const best = evaluationResults.length > 0 ? evaluationResults.reduce((a, b) => a.percentage > b.percentage ? a : b) : null;
    const worst = evaluationResults.length > 0 ? evaluationResults.reduce((a, b) => a.percentage < b.percentage ? a : b) : null;

    const targetCount = {};
    for (const r of evaluationResults) {
        targetCount[r.target] = (targetCount[r.target] || 0) + 1;
    }
    let mostEvaluated = null;
    let maxCount = 0;
    for (const [target, count] of Object.entries(targetCount)) {
        if (count > maxCount) {
            maxCount = count;
            mostEvaluated = target;
        }
    }
    const mostEvaluatedName = mostEvaluated ? (db.Accounts.findByUsername(mostEvaluated)?.fullname || mostEvaluated) : '-';
    
    res.send(`
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <link rel="manifest" href="/manifest.json">
            <meta name="theme-color" content="#3E9188">
            <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
            <meta name="csrf-token" content="${req.session.csrfToken}">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
            <title>گزارش‌های کلی</title>
            <style>
                body { font-family: 'Vazirmatn', 'Segoe UI', 'IRANSans', Tahoma, sans-serif; background: linear-gradient(135deg, #1A1A1A 0%, #3E9188 100%); margin: 0; padding: 20px; padding-top: 100px; overflow-x: hidden; color: #1A1A1A; line-height: 1.6; -webkit-font-smoothing: antialiased; }
                .container { max-width: 1000px; margin: 0 auto; background: white; padding: 32px; border-radius: 20px; box-shadow: 0 4px 24px rgba(26,26,26,0.08); border: 1px solid rgba(26,26,26,0.05); }
                .btn { background: #3E9188; color: white; border: none; padding: 9px 18px; border-radius: 10px; cursor: pointer; margin: 5px; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(62,145,136,0.25); transition: all 0.2s ease; }
                .btn:hover { background: #337971; box-shadow: 0 6px 16px rgba(62,145,136,0.35); transform: translateY(-1px); }
                .btn:active { transform: translateY(0); }
                .btn-back { background: #666; }
                .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
                .stat-card { background: #f9f9f9; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #e0e0e0; }
                .stat-card .number { font-size: 2.5rem; font-weight: bold; color: #3E9188; }
                .stat-card .label { font-size: 14px; color: #666; margin-top: 5px; }
                .stat-card.highlight { background: #E6F2F0; border-color: #3E9188; }
                .stat-card.warning { background: #fff3e0; border-color: #F2B90D; }
                .stat-card {
                    opacity: 0;
                    transform: translateY(16px);
                    animation: statCardIn 0.5s ease forwards;
                    transition: transform 0.25s ease, box-shadow 0.25s ease;
                }
                .stat-card:hover { transform: translateY(-4px); box-shadow: 0 10px 24px rgba(0,0,0,0.12); }
                .stats-grid > .stat-card:nth-child(1) { animation-delay: .05s; }
                .stats-grid > .stat-card:nth-child(2) { animation-delay: .12s; }
                .stats-grid > .stat-card:nth-child(3) { animation-delay: .19s; }
                .stats-grid > .stat-card:nth-child(4) { animation-delay: .26s; }
                .stats-grid > .stat-card:nth-child(5) { animation-delay: .33s; }
                .stats-grid > .stat-card:nth-child(6) { animation-delay: .40s; }
                .stats-grid > .stat-card:nth-child(7) { animation-delay: .47s; }
                @keyframes statCardIn { to { opacity: 1; transform: translateY(0); } }
                .mini-bar { height: 6px; background: rgba(62,145,136,0.15); border-radius: 3px; margin-top: 10px; overflow: hidden; }
                .mini-bar-fill { height: 100%; width: 0%; background: #3E9188; border-radius: 3px; transition: width 1s cubic-bezier(.22,1,.36,1); }
                @media (max-width: 768px) { .stats-grid { grid-template-columns: 1fr; } .container { padding: 15px; } }
            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #3E9188;
                box-shadow: 0 0 0 3px rgba(62,145,136,0.15);
            }
            input, select, textarea, button {
                font-family: inherit;
            }
            input, select, textarea {
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
                .page-header {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    text-align: center;
                    gap: 14px;
                    margin: 4px auto 30px;
                    padding-bottom: 24px;
                    border-bottom: 1px solid #eee;
                }
                .page-header-icon {
                    width: 64px;
                    height: 64px;
                    min-width: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, rgba(62,145,136,0.16), rgba(62,145,136,0.06));
                    color: #3E9188;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 14px rgba(62,145,136,0.18);
                }
                .page-header-icon svg { width: 30px; height: 30px; }
                .page-header h1 { margin: 0; font-size: 1.5rem; color: #1A1A1A; font-weight: 700; }
                .page-header::after {
                    content: '';
                    display: block;
                    width: 46px;
                    height: 3px;
                    border-radius: 3px;
                    background: #3E9188;
                    margin-top: 2px;
                }
            select {
                appearance: none;
                -webkit-appearance: none;
                -moz-appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23666666' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                background-size: 15px;
                padding-left: 34px !important;
                cursor: pointer;
            }
            .select-wrap { position: relative; display: inline-block; width: 100%; }
            select.enhanced-select { position: absolute; opacity: 0; width: 100%; height: 100%; top: 0; right: 0; pointer-events: none; }
            .cs-trigger {
                width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid #ddd; border-radius: 8px;
                background: white; cursor: pointer; font-family: inherit; font-size: 14px; text-align: right;
                display: flex; align-items: center; justify-content: space-between; gap: 8px;
                transition: border-color .2s ease, box-shadow .2s ease; color: #1A1A1A; user-select: none;
            }
            .cs-trigger:hover { border-color: #3E9188; }
            .cs-trigger.open, .cs-trigger.cs-focus { border-color: #3E9188; box-shadow: 0 0 0 3px rgba(62,145,136,.15); outline: none; }
            .cs-trigger.disabled { background: #f5f5f5; color: #999; cursor: not-allowed; }
            .cs-trigger .cs-chevron { width: 15px; height: 15px; color: #666; transition: transform .2s ease; flex-shrink: 0; }
            .cs-trigger.open .cs-chevron { transform: rotate(180deg); }
            .cs-menu {
                position: absolute; top: calc(100% + 6px); right: 0; left: 0; background: white; border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,.18); border: 1px solid #eee; max-height: 240px; overflow-y: auto;
                z-index: 2000; padding: 6px; display: none;
            }
            .cs-menu.open { display: block; animation: csFadeIn .15s ease; }
            @keyframes csFadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .cs-option { padding: 9px 12px; border-radius: 7px; cursor: pointer; font-size: 14px; transition: background .12s ease; }
            .cs-option:hover, .cs-option.cs-highlight { background: #F0F7F6; }
            .cs-option.selected { background: #3E9188; color: white; font-weight: 600; }
            .cs-option.disabled { opacity: .5; cursor: not-allowed; }
            .cs-fs-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 5000; display: flex; align-items: flex-end; justify-content: center; animation: csFadeIn .15s ease; }
            .cs-fs-panel { background: white; width: 100%; max-width: 480px; max-height: 80vh; border-radius: 20px 20px 0 0; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 -10px 40px rgba(0,0,0,0.3); }
            @media (min-width: 700px) { .cs-fs-overlay { align-items: center; } .cs-fs-panel { border-radius: 18px; max-height: 70vh; } }
            .cs-fs-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 700; font-size: 15px; flex-shrink: 0; }
            .cs-fs-close { width: 32px; height: 32px; border-radius: 50%; border: none; background: #f5f5f5; color: #1A1A1A; cursor: pointer; display: flex; align-items: center; justify-content: center; }
            .cs-fs-close:hover { background: #eee; }
            .cs-fs-close svg { width: 16px; height: 16px; }
            .cs-fs-list { overflow-y: auto; padding: 10px; }
            .cs-fs-option { padding: 14px 16px; border-radius: 10px; cursor: pointer; font-size: 15px; transition: background .12s ease; }
            .cs-fs-option:hover { background: #F0F7F6; }
            .cs-fs-option.selected { background: #3E9188; color: white; font-weight: 700; }
            .cs-fs-option.disabled { opacity: .5; cursor: not-allowed; }
            .top-bar {
                position: fixed; top: 0; left: 0; right: 0; height: 76px;
                background: rgba(255,255,255,0.95); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); z-index: 1000;
            }
            .top-bar-inner { max-width: 1400px; margin: 0 auto; height: 100%; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; box-sizing: border-box; position: relative; }
            .top-bar-left { display: flex; align-items: center; gap: 10px; }
            .top-bar-right { display: flex; align-items: center; gap: 14px; }
            .top-bar-icon-btn {
                display: flex; align-items: center; justify-content: center;
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; text-decoration: none; border: none; cursor: pointer;
                transition: all .2s ease;
            }
            .top-bar-icon-btn:hover { background: #337971; transform: translateY(-1px); }
            .top-bar-icon-btn svg { width: 18px; height: 18px; }
            .top-bar-logout { background: #ff4444; }
            .top-bar-logout:hover { background: #cc0000; }
            .top-bar-clock { font-size: 12px; color: #1A1A1A; font-weight: 600; white-space: nowrap; }
            .top-bar-title { position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%); font-size: 15px; color: #3E9188; font-weight: 700; white-space: nowrap; }
            .top-bar-brand { display: flex; align-items: center; gap: 10px; }
            .top-bar-brand img { max-height: 38px; }
            .top-bar-orgname { font-weight: 700; color: #3E9188; font-size: 15px; }
            .top-bar-profile { position: relative; }
            .profile-avatar {
                width: 40px; height: 40px; border-radius: 50%;
                background: #3E9188; color: white; display: flex; align-items: center; justify-content: center;
                font-size: 17px; font-weight: bold; cursor: pointer; border: 2px solid #fff;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2); transition: 0.3s;
            }
            .profile-avatar:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
            .profile-dropdown {
                display: none; position: absolute; left: 0; top: 50px;
                background: white; min-width: 220px; border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.2); padding: 10px 0; z-index: 1000;
            }
            .profile-dropdown.show { display: block; }
            .profile-dropdown .user-info { padding: 12px 20px; border-bottom: 1px solid #eee; margin-bottom: 5px; }
            .profile-dropdown .user-info .name { font-weight: bold; color: #1A1A1A; font-size: 14px; }
            .profile-dropdown .user-info .position { color: #666; font-size: 12px; margin-top: 3px; }
            .profile-dropdown .dropdown-item { padding: 10px 20px; color: #1A1A1A; text-decoration: none; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
            .profile-dropdown .dropdown-item:hover { background: #f5f5f5; }
            @media (max-width: 600px) {
                .top-bar { height: 66px; }
                .top-bar-clock { font-size: 10px; }
                .top-bar-orgname { display: none; }
                .top-bar-title { display: none; }
                .top-bar-icon-btn { width: 34px; height: 34px; }
                .profile-avatar { width: 34px; height: 34px; font-size: 14px; }
            }
            </style>
        </head>
        <body>
        ${renderTopBar({ backHref: '/hr?user=' + username + '&role=' + role })}
            <div class="container">
                <div class="page-header"><div class="page-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M15 7h6v6"/></svg></div><h1>گزارش‌های کلی ارزیابی</h1></div>
                
                <div class="stats-grid">
                    <div class="stat-card highlight">
                        <div class="number" data-count="${totalEvaluations}">۰</div>
                        <div class="label">تعداد کل ارزیابی‌ها</div>
                    </div>
                    <div class="stat-card">
                        <div class="number" data-count="${generalExams}">۰</div>
                        <div class="label">ارزیابی‌های عمومی</div>
                    </div>
                    <div class="stat-card">
                        <div class="number" data-count="${specializedExams}">۰</div>
                        <div class="label">ارزیابی‌های تخصصی</div>
                    </div>
                    <div class="stat-card highlight">
                        <div class="number" data-count="${avgScore}" data-suffix="%">۰%</div>
                        <div class="label">میانگین امتیاز</div>
                        <div class="mini-bar"><div class="mini-bar-fill" data-width="${avgScore}"></div></div>
                    </div>
                    ${best ? `<div class="stat-card highlight"><div class="number" data-count="${best.percentage}" data-suffix="%">۰%</div><div class="label">بهترین: ${escapeHtml(db.Accounts.findByUsername(best.target)?.fullname || best.target)}</div></div>` : '<div class="stat-card"><div class="number">-</div><div class="label">بهترین</div></div>'}
                    ${worst ? `<div class="stat-card warning"><div class="number" data-count="${worst.percentage}" data-suffix="%">۰%</div><div class="label">بدترین: ${escapeHtml(db.Accounts.findByUsername(worst.target)?.fullname || worst.target)}</div></div>` : '<div class="stat-card"><div class="number">-</div><div class="label">بدترین</div></div>'}
                    <div class="stat-card">
                        <div class="number" data-count="${maxCount}">۰</div>
                        <div class="label">بیشترین ارزیابی: ${escapeHtml(mostEvaluatedName)}</div>
                    </div>
                </div>
                
                <div style="margin-top:20px; padding:20px; background:#f5f5f5; border-radius:10px;">
                    <h3><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;vertical-align:-3px;display:inline-block;"><path d="M3 3v18h18"/><rect x="7" y="13" width="3" height="5" fill="currentColor" stroke="none"/><rect x="12" y="9" width="3" height="9" fill="currentColor" stroke="none"/><rect x="17" y="6" width="3" height="12" fill="currentColor" stroke="none"/></svg> توزیع ارزیابی‌ها</h3>
                    <div style="display:flex; gap:20px; margin-top:10px; flex-wrap:wrap;">
                        <div style="flex:1; min-width:150px; background:#3E9188; color:white; padding:15px; border-radius:8px; text-align:center;">
                            عمومی: ${toPersianDigits(totalEvaluations > 0 ? Math.round((generalExams / totalEvaluations) * 100) : 0)}%
                        </div>
                        <div style="flex:1; min-width:150px; background:#E8963E; color:white; padding:15px; border-radius:8px; text-align:center;">
                            تخصصی: ${toPersianDigits(totalEvaluations > 0 ? Math.round((specializedExams / totalEvaluations) * 100) : 0)}%
                        </div>
                    </div>
                </div>
            </div>
            <script>
                (function() {
                    function toFaLocal(n) { return String(n).replace(/[0-9]/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]); }
                    document.querySelectorAll('.number[data-count]').forEach(function(el) {
                        var target = parseInt(el.getAttribute('data-count'), 10) || 0;
                        var suffix = el.getAttribute('data-suffix') || '';
                        var duration = 900;
                        var start = null;
                        function step(ts) {
                            if (!start) start = ts;
                            var progress = Math.min((ts - start) / duration, 1);
                            var eased = 1 - Math.pow(1 - progress, 3);
                            var current = Math.round(eased * target);
                            el.textContent = toFaLocal(current) + suffix;
                            if (progress < 1) requestAnimationFrame(step);
                        }
                        requestAnimationFrame(step);
                    });
                    setTimeout(function() {
                        document.querySelectorAll('.mini-bar-fill').forEach(function(el) {
                            el.style.width = (el.getAttribute('data-width') || 0) + '%';
                        });
                    }, 100);
                })();
            </script>
        <script>
        (function() {
            var __csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            var __origFetch = window.fetch;
            window.fetch = function(url, opts) {
                opts = opts || {};
                var method = (opts.method || 'GET').toUpperCase();
                var isRelative = typeof url === 'string' && url.indexOf('://') === -1 && url.indexOf('//') !== 0;
                if (isRelative && method !== 'GET' && method !== 'HEAD') {
                    opts.headers = Object.assign({}, opts.headers, { 'X-CSRF-Token': __csrfToken });
                }
                return __origFetch(url, opts);
            };
            window.doLogout = function() {
                window.fetch('/logout', { method: 'POST' }).then(function() {
                    window.location.href = '/';
                }).catch(function() { window.location.href = '/'; });
            };
            if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                    navigator.serviceWorker.register('/sw.js').catch(function() {});
                });
            }
            function enhance(sel) {
                if (sel.dataset.csEnhanced || sel.closest('.select-wrap')) return;
                sel.dataset.csEnhanced = '1';
                var isFullscreen = !!sel.closest('.table-container');
                var wrap = document.createElement('div');
                wrap.className = 'select-wrap';
                sel.parentNode.insertBefore(wrap, sel);
                wrap.appendChild(sel);
                sel.classList.add('enhanced-select');
                sel.tabIndex = -1;

                var trigger = document.createElement('div');
                trigger.className = 'cs-trigger';
                trigger.tabIndex = 0;
                var label = document.createElement('span');
                label.className = 'cs-label';
                trigger.appendChild(label);
                trigger.insertAdjacentHTML('beforeend', '<svg class="cs-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>');

                var menu = document.createElement('div');
                menu.className = 'cs-menu';
                wrap.appendChild(trigger);
                wrap.appendChild(menu);

                function buildOptionItems(container, onPick) {
                    container.innerHTML = '';
                    Array.prototype.forEach.call(sel.options, function(opt, i) {
                        var item = document.createElement('div');
                        item.className = (container === menu ? 'cs-option' : 'cs-fs-option') + (opt.disabled ? ' disabled' : '') + (i === sel.selectedIndex ? ' selected' : '');
                        item.textContent = opt.textContent;
                        if (!opt.disabled) {
                            item.addEventListener('click', function() {
                                sel.value = opt.value;
                                sel.dispatchEvent(new Event('change', { bubbles: true }));
                                onPick();
                            });
                        }
                        container.appendChild(item);
                    });
                }
                function buildOptions() { buildOptionItems(menu, closeMenu); }
                function syncLabel() {
                    var selectedOpt = sel.options[sel.selectedIndex];
                    label.textContent = selectedOpt ? selectedOpt.textContent : '';
                    trigger.classList.toggle('disabled', sel.disabled);
                }
                function openMenu() {
                    if (sel.disabled) return;
                    document.querySelectorAll('.cs-menu.open').forEach(function(m) {
                        if (m !== menu) { m.classList.remove('open'); m.previousElementSibling.classList.remove('open'); }
                    });
                    buildOptions();
                    menu.classList.add('open');
                    trigger.classList.add('open');
                }
                function closeMenu() {
                    menu.classList.remove('open');
                    trigger.classList.remove('open');
                    syncLabel();
                }
                function openFullscreen() {
                    if (sel.disabled) return;
                    var overlay = document.createElement('div');
                    overlay.className = 'cs-fs-overlay';
                    var panel = document.createElement('div');
                    panel.className = 'cs-fs-panel';
                    var header = document.createElement('div');
                    header.className = 'cs-fs-header';
                    var titleSpan = document.createElement('span');
                    titleSpan.textContent = 'انتخاب کنید';
                    var closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'cs-fs-close';
                    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
                    header.appendChild(titleSpan);
                    header.appendChild(closeBtn);
                    var list = document.createElement('div');
                    list.className = 'cs-fs-list';
                    function remove() { if (overlay.parentNode) document.body.removeChild(overlay); syncLabel(); }
                    buildOptionItems(list, remove);
                    panel.appendChild(header);
                    panel.appendChild(list);
                    overlay.appendChild(panel);
                    overlay.addEventListener('click', function(e) { if (e.target === overlay) remove(); });
                    closeBtn.addEventListener('click', remove);
                    document.body.appendChild(overlay);
                }
                trigger.addEventListener('click', function() {
                    if (isFullscreen) { openFullscreen(); return; }
                    if (menu.classList.contains('open')) closeMenu(); else openMenu();
                });
                trigger.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
                    if (e.key === 'Escape') closeMenu();
                });
                trigger.addEventListener('focus', function() { trigger.classList.add('cs-focus'); });
                trigger.addEventListener('blur', function() { trigger.classList.remove('cs-focus'); });
                document.addEventListener('click', function(e) {
                    if (!wrap.contains(e.target)) closeMenu();
                });
                var observer = new MutationObserver(function() {
                    syncLabel();
                    if (menu.classList.contains('open')) buildOptions();
                });
                observer.observe(sel, { childList: true, subtree: true, attributes: true });
                sel.addEventListener('change', syncLabel);
                buildOptions();
                syncLabel();
            }
            function enhanceAll() {
                document.querySelectorAll('select').forEach(enhance);
            }
            window.csEnhanceAll = enhanceAll;
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', enhanceAll);
            } else {
                enhanceAll();
            }

            function updateTopBarClock() {
                var el = document.getElementById('topBarClock');
                if (!el) return;
                var now = new Date();
                var date = now.toLocaleDateString('fa-IR');
                var time = now.toLocaleTimeString('fa-IR');
                el.textContent = date + ' - ' + time;
            }
            updateTopBarClock();
            setInterval(updateTopBarClock, 1000);
        })();
        </script>
    </body>
        </html>
    `);
});

// ==================== API پرسنل ====================
app.get('/api/personnel', (req, res) => res.json(db.Personnel.list()));

app.post('/api/personnel', requireRole('admin', 'management'), (req, res) => {
    const { fullname, unit, position } = req.body;
    const personnelCode = toEnglishDigits(req.body.personnelCode);
    const nationalCode = toEnglishDigits(req.body.nationalCode);
    if (fullname && personnelCode && unit && position && nationalCode) {
        if (!/^[0-9]{10}$/.test(nationalCode)) {
            return res.json({ success: false, message: 'کد ملی باید دقیقاً 10 رقم باشد' });
        }
        if (db.Personnel.existsCodeOrNationalCode(personnelCode, nationalCode)) {
            return res.json({ success: false, message: 'کد پرسنلی یا کد ملی تکراری است' });
        }
        db.Personnel.add({ fullname, personnelCode, unit, position, nationalCode });
        addLog('افزودن پرسنل جدید', 'سیستم', 'پرسنل "' + fullname + '" با کد پرسنلی ' + personnelCode + ' اضافه شد');
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'اطلاعات ناقص است' });
    }
});

app.put('/api/personnel/:id', requireRole('admin', 'management'), (req, res) => {
    const id = parseInt(req.params.id);
    const { fullname, unit, position } = req.body;
    const personnelCode = toEnglishDigits(req.body.personnelCode);
    const nationalCode = toEnglishDigits(req.body.nationalCode);

    const existing = db.Personnel.findById(id);
    if (!existing) return res.json({ success: false, message: 'پرسنل یافت نشد' });

    if (db.Personnel.existsCodeOrNationalCode(personnelCode, nationalCode, id)) {
        return res.json({ success: false, message: 'کد پرسنلی یا کد ملی تکراری است' });
    }

    db.Personnel.update(id, { fullname, personnelCode, unit, position, nationalCode });
    addLog('ویرایش پرسنل', 'سیستم', 'پرسنل "' + fullname + '" ویرایش شد');
    res.json({ success: true });
});

app.delete('/api/personnel/:id', requireRole('admin', 'management'), (req, res) => {
    const id = parseInt(req.params.id);
    const deletedPersonnel = db.Personnel.findById(id);
    if (deletedPersonnel) {
        db.Personnel.remove(id);
        addLog('حذف پرسنل', 'سیستم', 'پرسنل "' + deletedPersonnel.fullname + '" حذف شد');
    }
    res.json({ success: true });
});

app.post('/api/sync-users', requireRole('admin', 'management'), (req, res) => {
    const count = db.Accounts.listPersonnelAccounts().length;
    addLog('همگام‌سازی کاربران', 'سیستم', count + ' کاربر همگام‌سازی شدند');
    res.json({ success: true, message: count + ' کاربر همگام‌سازی شدند' });
});

// ==================== پردازش فرم‌ها ====================
app.post('/hr/add-unit', requireRole('admin'), (req, res) => {
    const { unitName, username } = req.body;
    if (db.Units.add(unitName)) {
        addLog('افزودن واحد سازمانی', username || 'سیستم', 'واحد "' + unitName + '" اضافه شد');
    }
    res.redirect("/hr/organization?user=" + username + "&role=admin");
});

app.post('/hr/add-position', requireRole('admin'), (req, res) => {
    const { positionName, username } = req.body;
    if (db.Positions.add(positionName)) {
        addLog('افزودن پست سازمانی', username || 'سیستم', 'پست "' + positionName + '" اضافه شد');
    }
    res.redirect("/hr/organization?user=" + username + "&role=admin");
});

app.get('/hr/delete-unit', requireRole('admin'), (req, res) => {
    const { id, username, role } = req.query;
    const unit = db.Units.list().find(u => u.id == id);
    if (unit) {
        db.Units.remove(unit.id);
        addLog('حذف واحد سازمانی', username || 'سیستم', 'واحد "' + unit.name + '" حذف شد');
    }
    res.redirect("/hr/organization?user=" + username + "&role=" + role);
});

app.get('/hr/delete-position', requireRole('admin'), (req, res) => {
    const { id, username, role } = req.query;
    const position = db.Positions.list().find(p => p.id == id);
    if (position) {
        db.Positions.remove(position.id);
        addLog('حذف پست سازمانی', username || 'سیستم', 'پست "' + position.name + '" حذف شد');
    }
    res.redirect("/hr/organization?user=" + username + "&role=" + role);
});

app.post('/hr/add-personnel', requireRole('admin', 'management'), (req, res) => {
    const { fullname, unit, position, username } = req.body;
    const personnelCode = toEnglishDigits(req.body.personnelCode);
    const nationalCode = toEnglishDigits(req.body.nationalCode);
    if (fullname && personnelCode && unit && position && nationalCode && /^[0-9]{10}$/.test(nationalCode)) {
        if (!db.Personnel.existsCodeOrNationalCode(personnelCode, nationalCode)) {
            db.Personnel.add({ fullname, personnelCode, unit, position, nationalCode });
            addLog('افزودن پرسنل جدید', username || 'سیستم', 'پرسنل "' + fullname + '" با کد پرسنلی ' + personnelCode + ' اضافه شد');
        }
    }
    res.redirect("/hr/personnel/list?user=" + username + "&role=admin");
});

// ==================== راه‌اندازی ====================
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log('═══════════════════════════════════════');
    console.log(`سرور اجرا شد: http://localhost:${port}`);
    console.log('ادمین: admin | 123456');
    console.log('═══════════════════════════════════════');
});