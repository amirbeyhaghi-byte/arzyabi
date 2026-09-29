// ==================== لایه دسترسی به دیتابیس (SQLite) ====================
// طراحی رابطه‌ای: هر صفحه/بخش یک جدول مستقل دارد و جداول از طریق کلید خارجی
// (Foreign Key) به هم متصل شده‌اند. مستندسازی روابط:
//
//   units (واحدهای سازمانی) ──┐
//   positions (پست‌های سازمانی) ─┼─< personnel.unit_id / personnel.position_id
//                              │
//   personnel (پرسنل) ─────────┴─< accounts.personnel_id  (۱ به ۱: هر پرسنل یک حساب کاربری،
//                                                          ON DELETE CASCADE)
//
//   positions ──< specialized_questions.position_id  (ON DELETE CASCADE)
//   evaluation_results ──< evaluation_answers.evaluation_id  (ON DELETE CASCADE)
//
//   organization: جدول تک‌ردیفه (singleton) برای اطلاعات سازمان
//
//   عمداً بدون کلید خارجی سخت‌گیرانه:
//   - evaluation_results.evaluator_username / target_username: این‌ها سابقه‌ی
//     حسابرسی (audit trail) هستند و باید حتی پس از حذف پرسنل/حساب مرتبط باقی
//     بمانند؛ یک FK با CASCADE باعث از دست رفتن تاریخچه‌ی ارزیابی می‌شد و یک FK
//     بدون CASCADE مانع حذف پرسنل می‌شد.
//   - system_logs.username: باید تلاش‌های ورود ناموفق با نام کاربری نامعتبر را
//     هم ثبت کند، پس نمی‌تواند به accounts ارجاع سخت داشته باشد.

const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ==================== هش کردن رمز عبور (scrypt، بدون وابستگی خارجی) ====================
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return `scrypt:${salt}:${hash}`;
}
function verifyPassword(password, stored) {
    if (!stored || !stored.startsWith('scrypt:')) return false;
    const parts = stored.split(':');
    if (parts.length !== 3) return false;
    const [, salt, hash] = parts;
    const hashBuffer = Buffer.from(hash, 'hex');
    const suppliedBuffer = crypto.scryptSync(String(password), salt, 64);
    if (hashBuffer.length !== suppliedBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, suppliedBuffer);
}
function hasPassword(stored) {
    return !!stored && stored.startsWith('scrypt:');
}

const DB_PATH = path.join(__dirname, 'data', 'app.db');
if (!fs.existsSync(path.dirname(DB_PATH))) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

db.exec(`
CREATE TABLE IF NOT EXISTS organization (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    logo TEXT
);

CREATE TABLE IF NOT EXISTS units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS positions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS personnel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    personnel_code TEXT NOT NULL UNIQUE,
    national_code TEXT NOT NULL UNIQUE,
    unit_id INTEGER REFERENCES units(id) ON DELETE SET NULL,
    position_id INTEGER REFERENCES positions(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('admin','personnel')),
    access_level TEXT NOT NULL DEFAULT 'normal' CHECK (access_level IN ('normal','management','organizational')),
    fullname TEXT,
    personnel_id INTEGER UNIQUE REFERENCES personnel(id) ON DELETE CASCADE
);

-- ==================== دوره‌های ارزیابی ====================
-- در هر سال ۴ دوره ارزیابی داریم (دوره ۱ تا ۴). سوالات، پاسخ‌ها و نتایج
-- همگی به یک دوره وابسته‌اند تا ارزیابی‌های سال‌ها/دوره‌های مختلف با هم قاطی نشوند.
CREATE TABLE IF NOT EXISTS periods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    year INTEGER NOT NULL,
    period_no INTEGER NOT NULL CHECK (period_no BETWEEN 1 AND 4),
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (year, period_no)
);

CREATE TABLE IF NOT EXISTS general_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    period_id INTEGER REFERENCES periods(id) ON DELETE CASCADE
);

-- هر سوال عمومی می‌تواند گزینه‌های پاسخ اختصاصی خودش را داشته باشد (متن +
-- امتیاز)، چون تعداد و امتیاز گزینه‌ها بین سوالات مختلف یکسان نیست.
CREATE TABLE IF NOT EXISTS general_question_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL REFERENCES general_questions(id) ON DELETE CASCADE,
    option_text TEXT NOT NULL,
    score INTEGER NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS specialized_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    position_id INTEGER NOT NULL REFERENCES positions(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    period_id INTEGER REFERENCES periods(id) ON DELETE CASCADE
);

-- مشابه general_question_options: هر سوال تخصصی هم گزینه‌های پاسخ اختصاصی خودش را دارد
CREATE TABLE IF NOT EXISTS specialized_question_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL REFERENCES specialized_questions(id) ON DELETE CASCADE,
    option_text TEXT NOT NULL,
    score INTEGER NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS evaluation_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- عمداً بدون کلید خارجی به accounts: نتایج ارزیابی سابقه‌ی حسابرسی (audit trail)
    -- هستند و باید حتی پس از حذف حساب/پرسنل مرتبط باقی بمانند.
    evaluator_username TEXT NOT NULL,
    target_username TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('general','specialized')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    percentage INTEGER NOT NULL,
    -- عمداً بدون FK: مثل نام کاربری‌ها، سابقه‌ی ارزیابی باید حتی با حذف دوره باقی بماند
    period_id INTEGER,
    period_year INTEGER,
    period_no INTEGER
);

CREATE TABLE IF NOT EXISTS evaluation_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluation_id INTEGER NOT NULL REFERENCES evaluation_results(id) ON DELETE CASCADE,
    question_id INTEGER,
    question_text TEXT NOT NULL,
    answer INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    event TEXT NOT NULL,
    username TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_personnel_unit ON personnel(unit_id);
CREATE INDEX IF NOT EXISTS idx_personnel_position ON personnel(position_id);
CREATE INDEX IF NOT EXISTS idx_specialized_questions_position ON specialized_questions(position_id);
CREATE INDEX IF NOT EXISTS idx_general_question_options_question ON general_question_options(question_id);
CREATE INDEX IF NOT EXISTS idx_specialized_question_options_question ON specialized_question_options(question_id);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_evaluator ON evaluation_results(evaluator_username);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_target ON evaluation_results(target_username);
CREATE INDEX IF NOT EXISTS idx_evaluation_answers_evaluation ON evaluation_answers(evaluation_id);
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs(created_at);
`);

// ---------- مهاجرت: افزودن «دوره» به دیتابیس‌های قدیمی ----------
// دیتابیس‌هایی که قبل از افزوده‌شدن دوره‌ها ساخته شده‌اند ستون period_id ندارند؛
// CREATE TABLE IF NOT EXISTS آن‌ها را تغییر نمی‌دهد، پس این‌جا دستی اضافه می‌شود.
function columnExists(table, column) {
    return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
}
function addColumnIfMissing(table, column, definition) {
    if (!columnExists(table, column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        return true;
    }
    return false;
}

addColumnIfMissing('general_questions', 'period_id', 'INTEGER REFERENCES periods(id) ON DELETE CASCADE');
addColumnIfMissing('specialized_questions', 'period_id', 'INTEGER REFERENCES periods(id) ON DELETE CASCADE');
addColumnIfMissing('evaluation_results', 'period_id', 'INTEGER');
addColumnIfMissing('evaluation_results', 'period_year', 'INTEGER');
addColumnIfMissing('evaluation_results', 'period_no', 'INTEGER');
// «معیار»: گروه‌بندی اختیاری سوالات در کارنامه (مثل «تنظیم شعائر و انضباط»)
addColumnIfMissing('general_questions', 'category', 'TEXT');
addColumnIfMissing('specialized_questions', 'category', 'TEXT');

db.exec(`
CREATE INDEX IF NOT EXISTS idx_general_questions_period ON general_questions(period_id);
CREATE INDEX IF NOT EXISTS idx_specialized_questions_period ON specialized_questions(period_id);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_period ON evaluation_results(period_id);
`);

// اگر هیچ دوره‌ای تعریف نشده، یک دوره‌ی پیش‌فرض (سال جاری شمسی، دوره ۱) ساخته
// و فعال می‌شود تا داده‌های موجود بی‌صاحب نمانند.
function currentJalaliYear() {
    try {
        const fa = new Intl.DateTimeFormat('fa-IR-u-nu-latn', { year: 'numeric' }).format(new Date());
        const y = parseInt(String(fa).replace(/[^0-9]/g, ''), 10);
        if (y > 1300 && y < 1600) return y;
    } catch (e) {}
    return 1404;
}

const periodSeed = db.prepare('SELECT COUNT(*) AS c FROM periods').get();
if (periodSeed.c === 0) {
    db.prepare('INSERT INTO periods (year, period_no, is_active) VALUES (?, 1, 1)').run(currentJalaliYear());
}

// سوالات و نتایج قدیمی که دوره ندارند به دوره‌ی فعال نسبت داده می‌شوند
const activeRow = db.prepare('SELECT id, year, period_no FROM periods WHERE is_active = 1 ORDER BY id LIMIT 1').get()
    || db.prepare('SELECT id, year, period_no FROM periods ORDER BY id LIMIT 1').get();
if (activeRow) {
    db.prepare('UPDATE general_questions SET period_id = ? WHERE period_id IS NULL').run(activeRow.id);
    db.prepare('UPDATE specialized_questions SET period_id = ? WHERE period_id IS NULL').run(activeRow.id);
    db.prepare('UPDATE evaluation_results SET period_id = ?, period_year = ?, period_no = ? WHERE period_id IS NULL')
        .run(activeRow.id, activeRow.year, activeRow.period_no);
}

// ---------- seed اولیه ----------
const orgSeed = db.prepare('SELECT COUNT(*) AS c FROM organization').get();
if (orgSeed.c === 0) {
    db.prepare('INSERT INTO organization (id, name, logo) VALUES (1, ?, NULL)').run('شرکت ایده پردازان');
}
const adminSeed = db.prepare("SELECT COUNT(*) AS c FROM accounts WHERE username = 'admin'").get();
if (adminSeed.c === 0) {
    const defaultAdminPassword = process.env.ADMIN_PASSWORD || '123456';
    db.prepare("INSERT INTO accounts (username, password, role, access_level, fullname) VALUES ('admin', ?, 'admin', 'management', 'ادمین')").run(hashPassword(defaultAdminPassword));
    if (!process.env.ADMIN_PASSWORD) {
        console.log('حساب ادمین با رمز پیش‌فرض 123456 ساخته شد. لطفاً هرچه زودتر آن را از صفحه‌ی «اطلاعات وضعیت کاربران» تغییر دهید یا با متغیر محیطی ADMIN_PASSWORD رمز دلخواه تنظیم کنید.');
    }
}

// ---------- کمک‌تابع‌ها ----------
function nowFa() {
    const now = new Date();
    return { date: now.toLocaleDateString('fa-IR'), time: now.toLocaleTimeString('fa-IR') };
}

// ==================== Organization ====================
const Organization = {
    get() {
        return db.prepare('SELECT name, logo FROM organization WHERE id = 1').get();
    },
    update({ name, logo }) {
        if (name !== undefined && logo !== undefined) {
            db.prepare('UPDATE organization SET name = ?, logo = ? WHERE id = 1').run(name, logo);
        } else if (name !== undefined) {
            db.prepare('UPDATE organization SET name = ? WHERE id = 1').run(name);
        } else if (logo !== undefined) {
            db.prepare('UPDATE organization SET logo = ? WHERE id = 1').run(logo);
        }
    }
};

// ==================== Units ====================
const Units = {
    list() {
        return db.prepare('SELECT id, name FROM units ORDER BY id').all();
    },
    exists(name) {
        return !!db.prepare('SELECT 1 FROM units WHERE name = ?').get(name);
    },
    add(name) {
        if (!name || Units.exists(name)) return null;
        const info = db.prepare('INSERT INTO units (name) VALUES (?)').run(name);
        return { id: Number(info.lastInsertRowid), name };
    },
    remove(id) {
        const row = db.prepare('SELECT id FROM units WHERE id = ?').get(id);
        if (!row) return false;
        db.prepare('DELETE FROM units WHERE id = ?').run(id);
        return true;
    }
};

// ==================== Positions ====================
const Positions = {
    list() {
        return db.prepare('SELECT id, name FROM positions ORDER BY id').all();
    },
    exists(name) {
        return !!db.prepare('SELECT 1 FROM positions WHERE name = ?').get(name);
    },
    add(name) {
        if (!name || Positions.exists(name)) return null;
        const info = db.prepare('INSERT INTO positions (name) VALUES (?)').run(name);
        return { id: Number(info.lastInsertRowid), name };
    },
    remove(id) {
        const row = db.prepare('SELECT id FROM positions WHERE id = ?').get(id);
        if (!row) return false;
        db.prepare('DELETE FROM positions WHERE id = ?').run(id);
        return true;
    }
};

const PERSONNEL_SELECT = `
    SELECT p.id, p.full_name AS fullname, p.personnel_code AS personnelCode,
           p.national_code AS nationalCode,
           u.id AS unitId, u.name AS unit,
           pos.id AS positionId, pos.name AS position
    FROM personnel p
    LEFT JOIN units u ON u.id = p.unit_id
    LEFT JOIN positions pos ON pos.id = p.position_id
`;

// ==================== Personnel (+ متصل به accounts) ====================
const Personnel = {
    list() {
        return db.prepare(PERSONNEL_SELECT + ' ORDER BY p.id').all();
    },
    findById(id) {
        return db.prepare(PERSONNEL_SELECT + ' WHERE p.id = ?').get(id);
    },
    existsCodeOrNationalCode(personnelCode, nationalCode, excludeId) {
        const row = excludeId
            ? db.prepare('SELECT id FROM personnel WHERE (personnel_code = ? OR national_code = ?) AND id != ?').get(personnelCode, nationalCode, excludeId)
            : db.prepare('SELECT id FROM personnel WHERE personnel_code = ? OR national_code = ?').get(personnelCode, nationalCode);
        return !!row;
    },
    // پرسنل و حساب کاربری متناظرش را در یک تراکنش می‌سازد
    add({ fullname, personnelCode, unit, position, nationalCode }) {
        const unitRow = db.prepare('SELECT id FROM units WHERE name = ?').get(unit);
        const positionRow = db.prepare('SELECT id FROM positions WHERE name = ?').get(position);
        db.exec('BEGIN');
        try {
            const info = db.prepare(
                'INSERT INTO personnel (full_name, personnel_code, national_code, unit_id, position_id) VALUES (?, ?, ?, ?, ?)'
            ).run(fullname, personnelCode, nationalCode, unitRow ? unitRow.id : null, positionRow ? positionRow.id : null);
            const personnelId = Number(info.lastInsertRowid);
            db.prepare(
                "INSERT INTO accounts (username, password, role, access_level, personnel_id) VALUES (?, '', 'personnel', 'normal', ?)"
            ).run(nationalCode, personnelId);
            db.exec('COMMIT');
            return Personnel.findById(personnelId);
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    update(id, { fullname, personnelCode, unit, position, nationalCode }) {
        const existing = db.prepare('SELECT national_code FROM personnel WHERE id = ?').get(id);
        if (!existing) return null;
        const unitRow = db.prepare('SELECT id FROM units WHERE name = ?').get(unit);
        const positionRow = db.prepare('SELECT id FROM positions WHERE name = ?').get(position);
        db.exec('BEGIN');
        try {
            db.prepare(
                'UPDATE personnel SET full_name = ?, personnel_code = ?, national_code = ?, unit_id = ?, position_id = ? WHERE id = ?'
            ).run(fullname, personnelCode, nationalCode, unitRow ? unitRow.id : null, positionRow ? positionRow.id : null, id);
            if (existing.national_code !== nationalCode) {
                db.prepare('UPDATE accounts SET username = ? WHERE personnel_id = ?').run(nationalCode, id);
            }
            db.exec('COMMIT');
            return Personnel.findById(id);
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    remove(id) {
        const row = db.prepare('SELECT id FROM personnel WHERE id = ?').get(id);
        if (!row) return false;
        db.prepare('DELETE FROM personnel WHERE id = ?').run(id);
        return true;
    }
};

// ==================== Accounts (ورود/دسترسی) ====================
const Accounts = {
    findByUsername(username) {
        return db.prepare(`
            SELECT a.id, a.username, a.password, a.role, a.access_level AS accessLevel,
                   COALESCE(a.fullname, p.full_name) AS fullname,
                   p.personnel_code AS personnelCode, u.name AS unit, pos.name AS position
            FROM accounts a
            LEFT JOIN personnel p ON p.id = a.personnel_id
            LEFT JOIN units u ON u.id = p.unit_id
            LEFT JOIN positions pos ON pos.id = p.position_id
            WHERE a.username = ?
        `).get(username);
    },
    // ورود را تایید می‌کند و اطلاعات لازم برای ری‌دایرکت را برمی‌گرداند
    verifyLogin(username, password) {
        const account = Accounts.findByUsername(username);
        if (!account || !verifyPassword(password, account.password)) return null;
        return account;
    },
    listPersonnelAccounts() {
        return db.prepare(`
            SELECT a.username AS nationalCode, a.password, a.access_level AS accessLevel,
                   p.full_name AS fullname, p.personnel_code AS personnelCode,
                   u.name AS unit, pos.name AS position
            FROM accounts a
            JOIN personnel p ON p.id = a.personnel_id
            LEFT JOIN units u ON u.id = p.unit_id
            LEFT JOIN positions pos ON pos.id = p.position_id
            WHERE a.role = 'personnel'
            ORDER BY a.id
        `).all().map(({ password, ...u }) => ({ ...u, hasPassword: hasPassword(password) }));
    },
    setPassword(username, password) {
        const row = db.prepare("SELECT id FROM accounts WHERE username = ? AND role = 'personnel'").get(username);
        if (!row) return false;
        db.prepare('UPDATE accounts SET password = ? WHERE username = ?').run(hashPassword(password), username);
        return true;
    },
    setAccessLevel(username, accessLevel) {
        const row = db.prepare("SELECT id FROM accounts WHERE username = ? AND role = 'personnel'").get(username);
        if (!row) return false;
        db.prepare('UPDATE accounts SET access_level = ? WHERE username = ?').run(accessLevel, username);
        return true;
    },
    setRandomPassword(username) {
        const account = Accounts.findByUsername(username);
        if (!account) return null;
        const newPassword = crypto.randomBytes(6).toString('base64url');
        db.prepare('UPDATE accounts SET password = ? WHERE username = ?').run(hashPassword(newPassword), username);
        return newPassword;
    }
};

// ==================== دوره‌های ارزیابی (سال + دوره ۱..۴) ====================
const Periods = {
    list() {
        return db.prepare('SELECT id, year, period_no AS periodNo, is_active AS isActive FROM periods ORDER BY year DESC, period_no DESC').all();
    },
    findById(id) {
        return db.prepare('SELECT id, year, period_no AS periodNo, is_active AS isActive FROM periods WHERE id = ?').get(id);
    },
    getActive() {
        return db.prepare('SELECT id, year, period_no AS periodNo, is_active AS isActive FROM periods WHERE is_active = 1 ORDER BY id LIMIT 1').get()
            || db.prepare('SELECT id, year, period_no AS periodNo, is_active AS isActive FROM periods ORDER BY year DESC, period_no DESC LIMIT 1').get()
            || null;
    },
    exists(year, periodNo) {
        return !!db.prepare('SELECT 1 FROM periods WHERE year = ? AND period_no = ?').get(year, periodNo);
    },
    add(year, periodNo) {
        if (!Number.isInteger(year) || !Number.isInteger(periodNo)) return null;
        if (periodNo < 1 || periodNo > 4) return null;
        if (Periods.exists(year, periodNo)) return null;
        const info = db.prepare('INSERT INTO periods (year, period_no, is_active) VALUES (?, ?, 0)').run(year, periodNo);
        return Periods.findById(Number(info.lastInsertRowid));
    },
    // فقط یک دوره در هر لحظه می‌تواند فعال باشد
    setActive(id) {
        const row = db.prepare('SELECT id FROM periods WHERE id = ?').get(id);
        if (!row) return false;
        db.exec('BEGIN');
        try {
            db.prepare('UPDATE periods SET is_active = 0').run();
            db.prepare('UPDATE periods SET is_active = 1 WHERE id = ?').run(id);
            db.exec('COMMIT');
            return true;
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    // تعداد سوالات/نتایج وابسته، برای هشدار پیش از حذف
    usage(id) {
        return {
            generalQuestions: db.prepare('SELECT COUNT(*) AS c FROM general_questions WHERE period_id = ?').get(id).c,
            specializedQuestions: db.prepare('SELECT COUNT(*) AS c FROM specialized_questions WHERE period_id = ?').get(id).c,
            evaluations: db.prepare('SELECT COUNT(*) AS c FROM evaluation_results WHERE period_id = ?').get(id).c
        };
    },
    remove(id) {
        const row = Periods.findById(id);
        if (!row) return false;
        // نتایج ارزیابی عمداً پاک نمی‌شوند (سابقه‌ی حسابرسی)؛ فقط سوالات با CASCADE می‌روند
        db.prepare('DELETE FROM periods WHERE id = ?').run(id);
        return true;
    }
};

// ==================== General questions ====================
const GENERAL_OPTIONS_SELECT = 'SELECT id, option_text AS text, score FROM general_question_options WHERE question_id = ? ORDER BY sort_order ASC, id ASC';
const GeneralQuestions = {
    // periodId اگر داده شود فقط سوالات همان دوره برمی‌گردد
    list(periodId) {
        return periodId
            ? db.prepare('SELECT id, question, category, period_id AS periodId FROM general_questions WHERE period_id = ? ORDER BY id').all(periodId)
            : db.prepare('SELECT id, question, category, period_id AS periodId FROM general_questions ORDER BY id').all();
    },
    // نسخه‌ای که برای هر سوال، گزینه‌های پاسخ اختصاصی‌اش (متن + امتیاز) را هم برمی‌گرداند
    listWithOptions(periodId) {
        const questions = GeneralQuestions.list(periodId);
        const getOptions = db.prepare(GENERAL_OPTIONS_SELECT);
        return questions.map(q => ({ ...q, options: getOptions.all(q.id) }));
    },
    findById(id) {
        const q = db.prepare('SELECT id, question, category, period_id AS periodId FROM general_questions WHERE id = ?').get(id);
        if (!q) return null;
        q.options = db.prepare(GENERAL_OPTIONS_SELECT).all(id);
        return q;
    },
    // options: [{ text, score }]
    add(question, options, periodId, category) {
        db.exec('BEGIN');
        try {
            const info = db.prepare('INSERT INTO general_questions (question, period_id, category) VALUES (?, ?, ?)')
                .run(question, periodId || null, category || null);
            const questionId = Number(info.lastInsertRowid);
            const insertOption = db.prepare('INSERT INTO general_question_options (question_id, option_text, score, sort_order) VALUES (?, ?, ?, ?)');
            (options || []).forEach((opt, i) => insertOption.run(questionId, opt.text, opt.score, i));
            db.exec('COMMIT');
            return GeneralQuestions.findById(questionId);
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    // گزینه‌های قبلی حذف و با نسخه‌ی جدید جایگزین می‌شوند (ساده‌ترین راه برای ویرایش یک لیست کامل)
    // category === undefined یعنی «معیار را تغییر نده»
    update(id, question, options, category) {
        const row = db.prepare('SELECT id FROM general_questions WHERE id = ?').get(id);
        if (!row) return false;
        db.exec('BEGIN');
        try {
            db.prepare('UPDATE general_questions SET question = ? WHERE id = ?').run(question, id);
            if (category !== undefined) {
                db.prepare('UPDATE general_questions SET category = ? WHERE id = ?').run(category || null, id);
            }
            db.prepare('DELETE FROM general_question_options WHERE question_id = ?').run(id);
            const insertOption = db.prepare('INSERT INTO general_question_options (question_id, option_text, score, sort_order) VALUES (?, ?, ?, ?)');
            (options || []).forEach((opt, i) => insertOption.run(id, opt.text, opt.score, i));
            db.exec('COMMIT');
            return true;
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    remove(id) {
        db.prepare('DELETE FROM general_questions WHERE id = ?').run(id);
        return true;
    }
};

// ==================== Specialized questions ====================
const SPECIALIZED_SELECT = `
    SELECT sq.id, sq.question, sq.category, sq.period_id AS periodId, pos.name AS position, pos.id AS positionId
    FROM specialized_questions sq
    JOIN positions pos ON pos.id = sq.position_id
`;
const SPECIALIZED_OPTIONS_SELECT = 'SELECT id, option_text AS text, score FROM specialized_question_options WHERE question_id = ? ORDER BY sort_order ASC, id ASC';
const SpecializedQuestions = {
    list(periodId) {
        return periodId
            ? db.prepare(SPECIALIZED_SELECT + ' WHERE sq.period_id = ? ORDER BY sq.id').all(periodId)
            : db.prepare(SPECIALIZED_SELECT + ' ORDER BY sq.id').all();
    },
    // نسخه‌ای که برای هر سوال، گزینه‌های پاسخ اختصاصی‌اش را هم برمی‌گرداند
    listWithOptions(periodId) {
        const questions = SpecializedQuestions.list(periodId);
        const getOptions = db.prepare(SPECIALIZED_OPTIONS_SELECT);
        return questions.map(q => ({ ...q, options: getOptions.all(q.id) }));
    },
    listByPosition(positionName, periodId) {
        return periodId
            ? db.prepare(SPECIALIZED_SELECT + ' WHERE pos.name = ? AND sq.period_id = ? ORDER BY sq.id').all(positionName, periodId)
            : db.prepare(SPECIALIZED_SELECT + ' WHERE pos.name = ? ORDER BY sq.id').all(positionName);
    },
    listByPositionWithOptions(positionName, periodId) {
        const questions = SpecializedQuestions.listByPosition(positionName, periodId);
        const getOptions = db.prepare(SPECIALIZED_OPTIONS_SELECT);
        return questions.map(q => ({ ...q, options: getOptions.all(q.id) }));
    },
    findById(id) {
        const q = db.prepare(SPECIALIZED_SELECT + ' WHERE sq.id = ?').get(id);
        if (!q) return null;
        q.options = db.prepare(SPECIALIZED_OPTIONS_SELECT).all(id);
        return q;
    },
    // options: [{ text, score }] (اختیاری، برای سازگاری با فراخوان‌های قدیمی)
    add(positionName, question, options, periodId, category) {
        const positionRow = db.prepare('SELECT id FROM positions WHERE name = ?').get(positionName);
        if (!positionRow) return null;
        db.exec('BEGIN');
        try {
            const info = db.prepare('INSERT INTO specialized_questions (position_id, question, period_id, category) VALUES (?, ?, ?, ?)')
                .run(positionRow.id, question, periodId || null, category || null);
            const questionId = Number(info.lastInsertRowid);
            const insertOption = db.prepare('INSERT INTO specialized_question_options (question_id, option_text, score, sort_order) VALUES (?, ?, ?, ?)');
            (options || []).forEach((opt, i) => insertOption.run(questionId, opt.text, opt.score, i));
            db.exec('COMMIT');
            return SpecializedQuestions.findById(questionId);
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    update(id, positionName, question, options, category) {
        const positionRow = db.prepare('SELECT id FROM positions WHERE name = ?').get(positionName);
        if (!positionRow) return false;
        const row = db.prepare('SELECT id FROM specialized_questions WHERE id = ?').get(id);
        if (!row) return false;
        db.exec('BEGIN');
        try {
            db.prepare('UPDATE specialized_questions SET position_id = ?, question = ? WHERE id = ?').run(positionRow.id, question, id);
            if (category !== undefined) {
                db.prepare('UPDATE specialized_questions SET category = ? WHERE id = ?').run(category || null, id);
            }
            if (options !== undefined) {
                db.prepare('DELETE FROM specialized_question_options WHERE question_id = ?').run(id);
                const insertOption = db.prepare('INSERT INTO specialized_question_options (question_id, option_text, score, sort_order) VALUES (?, ?, ?, ?)');
                options.forEach((opt, i) => insertOption.run(id, opt.text, opt.score, i));
            }
            db.exec('COMMIT');
            return true;
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    remove(id) {
        const row = SpecializedQuestions.findById(id);
        db.prepare('DELETE FROM specialized_questions WHERE id = ?').run(id);
        return row || null;
    }
};

// ==================== Evaluations ====================
const Evaluations = {
    // «قبلاً ارزیابی شده» فقط داخل همان دوره معنا دارد؛ در دوره‌ی بعدی دوباره باید ارزیابی شود
    hasEvaluated(evaluator, target, type, periodId) {
        const row = periodId
            ? db.prepare('SELECT 1 FROM evaluation_results WHERE evaluator_username = ? AND target_username = ? AND type = ? AND period_id = ?')
                .get(evaluator, target, type, periodId)
            : db.prepare('SELECT 1 FROM evaluation_results WHERE evaluator_username = ? AND target_username = ? AND type = ?')
                .get(evaluator, target, type);
        return !!row;
    },
    submit({ evaluator, target, type, answersById, periodId }) {
        // answersById: Map(questionId -> {question, answer, maxScore})
        // maxScore پیش‌فرض ۴ دارد (مقیاس ضعیف=۱..عالی=۴ سوالات تخصصی)، اما
        // سوالات عمومی چون گزینه‌های اختصاصی با امتیاز دلخواه دارند، حداکثر
        // امتیاز واقعی همان سوال را می‌فرستند.
        let score = 0;
        let totalMax = 0;
        const details = [];
        for (const [qId, entry] of answersById) {
            score += entry.answer;
            totalMax += entry.maxScore || 4;
            details.push({ questionId: qId, question: entry.question, answer: entry.answer });
        }
        const percentage = totalMax > 0 ? Math.round((score / totalMax) * 100) : 0;
        db.exec('BEGIN');
        try {
            const period = periodId ? Periods.findById(periodId) : null;
            const info = db.prepare(
                'INSERT INTO evaluation_results (evaluator_username, target_username, type, score, total, percentage, period_id, period_year, period_no) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            ).run(evaluator, target, type, score, totalMax, percentage,
                period ? period.id : null, period ? period.year : null, period ? period.periodNo : null);
            const evaluationId = Number(info.lastInsertRowid);
            const insertAnswer = db.prepare(
                'INSERT INTO evaluation_answers (evaluation_id, question_id, question_text, answer) VALUES (?, ?, ?, ?)'
            );
            for (const d of details) insertAnswer.run(evaluationId, d.questionId, d.question, d.answer);
            db.exec('COMMIT');
            return { id: evaluationId, score, total: totalMax, percentage };
        } catch (e) {
            db.exec('ROLLBACK');
            throw e;
        }
    },
    listForUser(username, isAdmin) {
        const base = `
            SELECT er.id, er.evaluator_username AS evaluator, er.target_username AS target,
                   er.type, strftime('%Y-%m-%dT%H:%M:%SZ', er.created_at) AS date,
                   er.score, er.total, er.percentage,
                   er.period_id AS periodId, er.period_year AS periodYear, er.period_no AS periodNo
            FROM evaluation_results er
        `;
        const rows = isAdmin
            ? db.prepare(base + ' ORDER BY er.id DESC').all()
            : db.prepare(base + ' WHERE er.evaluator_username = ? OR er.target_username = ? ORDER BY er.id DESC').all(username, username);
        return rows;
    },
    findById(id) {
        return db.prepare('SELECT id, evaluator_username AS evaluator, target_username AS target FROM evaluation_results WHERE id = ?').get(id);
    },
    remove(id) {
        const row = db.prepare('SELECT id FROM evaluation_results WHERE id = ?').get(id);
        if (!row) return false;
        db.prepare('DELETE FROM evaluation_results WHERE id = ?').run(id);
        return true;
    },
    // همه‌ی پاسخ‌هایی که یک نفر (target) در یک دوره از ارزیاب‌ها گرفته است
    answersForTarget(target, type, periodId) {
        return db.prepare(`
            SELECT ea.evaluation_id AS evaluationId, ea.question_id AS questionId, ea.answer
            FROM evaluation_answers ea
            JOIN evaluation_results er ON er.id = ea.evaluation_id
            WHERE er.target_username = ? AND er.type = ? AND er.period_id = ?
        `).all(target, type, periodId);
    },
    countForTarget(target, type, periodId) {
        return db.prepare('SELECT COUNT(*) AS c FROM evaluation_results WHERE target_username = ? AND type = ? AND period_id = ?')
            .get(target, type, periodId).c;
    },
    all(periodId) {
        const base = 'SELECT evaluator_username AS evaluator, target_username AS target, type, score, total, percentage, period_id AS periodId, period_year AS periodYear, period_no AS periodNo FROM evaluation_results';
        return periodId
            ? db.prepare(base + ' WHERE period_id = ?').all(periodId)
            : db.prepare(base).all();
    }
};

// ==================== System logs ====================
const Logs = {
    add(event, user, details = '') {
        db.prepare('INSERT INTO system_logs (event, username, details) VALUES (?, ?, ?)').run(event, user, details);
        const countRow = db.prepare('SELECT COUNT(*) AS c FROM system_logs').get();
        if (countRow.c > 1000) {
            db.prepare(`
                DELETE FROM system_logs WHERE id IN (
                    SELECT id FROM system_logs ORDER BY id ASC LIMIT ?
                )
            `).run(countRow.c - 1000);
        }
    },
    list(limit = 100) {
        const rows = db.prepare('SELECT id, created_at, event, username AS user, details FROM system_logs ORDER BY id DESC LIMIT ?').all(limit);
        return rows.map(r => {
            const d = new Date(r.created_at.replace(' ', 'T') + 'Z');
            return {
                id: r.id,
                date: d.toLocaleDateString('fa-IR'),
                time: d.toLocaleTimeString('fa-IR'),
                event: r.event,
                user: r.user,
                details: r.details
            };
        });
    },
    count() {
        return db.prepare('SELECT COUNT(*) AS c FROM system_logs').get().c;
    },
    clear() {
        db.prepare('DELETE FROM system_logs').run();
    }
};

module.exports = {
    raw: db,
    Organization,
    Periods,
    Units,
    Positions,
    Personnel,
    Accounts,
    GeneralQuestions,
    SpecializedQuestions,
    Evaluations,
    Logs
};
