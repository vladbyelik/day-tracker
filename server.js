const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { MongoClient } = require('mongodb');

const scrypt = promisify(crypto.scrypt);

const app = express();
// Render стоит за прокси — без этого req.secure и req.ip будут неверными
app.set('trust proxy', 1);
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_PATH = path.join(__dirname, 'db.json');
const AUTH_PATH = path.join(__dirname, 'auth.json');
const CONFIG_PATH = path.join(__dirname, 'config.json');
const MONGODB_URI = process.env.MONGODB_URI;

// ===== Конфиг (API-ключ Anthropic): сначала переменная окружения (облако), потом локальный config.json =====
function readLocalConfig() {
  if (!fs.existsSync(CONFIG_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (e) {
    return {};
  }
}

function getAnthropicApiKey() {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY.trim();
  const config = readLocalConfig();
  return (config.anthropicApiKey || '').trim();
}

// ===== Хранилище: MongoDB Atlas, если задан MONGODB_URI, иначе локальный db.json =====
let mongoClientPromise = null;
let mongoConnected = false;

async function getMongoCollection() {
  if (!MONGODB_URI) return null;
  if (!mongoClientPromise) {
    mongoClientPromise = (async () => {
      const client = new MongoClient(MONGODB_URI);
      await client.connect();
      mongoConnected = true;
      console.log('Подключено к MongoDB Atlas — данные хранятся в облаке, переживают перезапуски');
      return client;
    })().catch((e) => {
      mongoConnected = false;
      console.error('Не удалось подключиться к MongoDB, запускаюсь с локальным файлом:', e.message);
      return null;
    });
  }
  const client = await mongoClientPromise;
  if (!client) return null;
  return client.db('daytracker').collection('store');
}

function readLocalDB() {
  if (!fs.existsSync(DB_PATH)) return { days: {}, jobs: [] };
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) {
    console.error('Ошибка чтения db.json, создаю новую базу', e);
    return { days: {}, jobs: [] };
  }
}

function writeLocalDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

async function readDB() {
  const col = await getMongoCollection();
  if (col) {
    const doc = await col.findOne({ _id: 'main' });
    return (doc && doc.data) || { days: {}, jobs: [] };
  }
  return readLocalDB();
}

async function writeDB(db) {
  const col = await getMongoCollection();
  if (col) {
    await col.updateOne({ _id: 'main' }, { $set: { data: db } }, { upsert: true });
    return;
  }
  writeLocalDB(db);
}

// =====================================================================
// ===== Авторизация: один пользователь, логин+пароль, код восстановления =====
// =====================================================================
// Данные входа хранятся ОТДЕЛЬНО от основных данных: в MongoDB документ _id: "auth",
// локально — файл auth.json. Пароль и код восстановления хранятся только в виде хэшей (scrypt).
// Сессия — случайный токен в HttpOnly-cookie; в базе лежит только его sha256.

const SESSION_COOKIE = 'dt_session';
const SESSION_MAX_AGE_SEC = 400 * 24 * 60 * 60; // ~13 месяцев (максимум, который разрешает Chrome), продлевается при каждом заходе
const MAX_SESSIONS = 20;
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // без 0/O, 1/I — чтобы код было легко переписать

let authCache; // undefined — ещё не загружали; null — вход ещё не настроен

async function readAuth() {
  if (authCache !== undefined) return authCache;
  const col = await getMongoCollection();
  if (col) {
    const doc = await col.findOne({ _id: 'auth' });
    authCache = (doc && doc.auth) || null;
  } else {
    // Если MongoDB задана, но недоступна — НЕ откатываемся на пустой локальный файл,
    // иначе на Render появился бы экран «создать аккаунт» и кто угодно мог бы его занять.
    if (MONGODB_URI) {
      const err = new Error('storage_unavailable');
      err.storageUnavailable = true;
      throw err;
    }
    authCache = fs.existsSync(AUTH_PATH) ? JSON.parse(fs.readFileSync(AUTH_PATH, 'utf8')) : null;
  }
  return authCache;
}

async function writeAuth(auth) {
  const col = await getMongoCollection();
  if (col) {
    await col.updateOne({ _id: 'auth' }, { $set: { auth } }, { upsert: true });
  } else {
    if (MONGODB_URI) {
      const err = new Error('storage_unavailable');
      err.storageUnavailable = true;
      throw err;
    }
    fs.writeFileSync(AUTH_PATH, JSON.stringify(auth, null, 2), 'utf8');
  }
  authCache = auth;
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

async function hashSecret(secret, salt) {
  const buf = await scrypt(String(secret), salt, 64);
  return buf.toString('hex');
}

async function verifySecret(secret, salt, expectedHex) {
  if (!salt || !expectedHex) return false;
  const actual = Buffer.from(await hashSecret(secret, salt), 'hex');
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function safeEqualStrings(a, b) {
  const ha = Buffer.from(sha256(a), 'hex');
  const hb = Buffer.from(sha256(b), 'hex');
  return crypto.timingSafeEqual(ha, hb);
}

function normalizeLogin(login) {
  return String(login || '').trim().toLowerCase();
}

function normalizeRecoveryCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function generateRecoveryCode() {
  const bytes = crypto.randomBytes(16);
  let s = '';
  for (let i = 0; i < 16; i++) s += RECOVERY_ALPHABET[bytes[i] % RECOVERY_ALPHABET.length];
  return s.match(/.{4}/g).join('-'); // например K7QM-2XPA-9HWR-D3TF
}

function validateCredentials(login, password) {
  const l = String(login || '').trim();
  if (l.length < 3 || l.length > 40) return 'bad_login';
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return 'weak_password';
  return null;
}

// Собирает новый объект auth с новыми хэшами пароля и кода восстановления
async function buildAuth(login, password, createdAt) {
  const recoveryCode = generateRecoveryCode();
  const passSalt = newSalt();
  const recSalt = newSalt();
  const auth = {
    login: String(login).trim(),
    passSalt,
    passHash: await hashSecret(password, passSalt),
    recSalt,
    recHash: await hashSecret(normalizeRecoveryCode(recoveryCode), recSalt),
    createdAt: createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    sessions: [],
  };
  return { auth, recoveryCode };
}

// ----- cookie -----
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch (e) {
      out[k] = v;
    }
  });
  return out;
}

function sessionCookie(req, value, maxAgeSec) {
  const parts = [
    SESSION_COOKIE + '=' + encodeURIComponent(value),
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + maxAgeSec,
  ];
  if (req.secure) parts.push('Secure');
  return parts.join('; ');
}

function setSessionCookie(req, res, token) {
  res.setHeader('Set-Cookie', sessionCookie(req, token, SESSION_MAX_AGE_SEC));
}

function clearSessionCookie(req, res) {
  res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
}

// ----- сессии -----
async function createSession(req, res, auth) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date().toISOString();
  auth.sessions = auth.sessions || [];
  auth.sessions.unshift({
    id: sha256(token),
    createdAt: now,
    lastSeenAt: now,
    device: String(req.headers['user-agent'] || '').slice(0, 160),
  });
  auth.sessions = auth.sessions.slice(0, MAX_SESSIONS);
  await writeAuth(auth);
  setSessionCookie(req, res, token);
}

async function getSession(req) {
  const auth = await readAuth();
  if (!auth) return null;
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const id = sha256(token);
  const session = (auth.sessions || []).find((s) => s.id === id);
  return session ? { auth, session, token } : null;
}

// ----- защита от перебора: 8 неудачных попыток за 15 минут с одного IP -----
const failedAttempts = new Map();
const MAX_FAILS = 8;
const FAIL_WINDOW_MS = 15 * 60 * 1000;

function isRateLimited(ip) {
  const e = failedAttempts.get(ip);
  if (!e) return false;
  if (Date.now() - e.first > FAIL_WINDOW_MS) {
    failedAttempts.delete(ip);
    return false;
  }
  return e.count >= MAX_FAILS;
}

function registerFail(ip) {
  const e = failedAttempts.get(ip);
  if (!e || Date.now() - e.first > FAIL_WINDOW_MS) failedAttempts.set(ip, { count: 1, first: Date.now() });
  else e.count++;
}

function authError(res, e) {
  if (e && e.storageUnavailable) return res.status(503).json({ error: 'storage_unavailable' });
  console.error('Ошибка авторизации', e);
  return res.status(500).json({ error: 'auth_failed' });
}

// Состояние входа: настроен ли аккаунт и вошёл ли этот браузер
app.get('/api/auth/status', async (req, res) => {
  try {
    const auth = await readAuth();
    if (!auth) return res.json({ configured: false, loggedIn: false });
    const s = await getSession(req);
    if (!s) return res.json({ configured: true, loggedIn: false });
    // Продлеваем cookie при каждом заходе, а время последнего визита пишем не чаще раза в 12 часов
    setSessionCookie(req, res, s.token);
    if (Date.now() - Date.parse(s.session.lastSeenAt || 0) > 12 * 60 * 60 * 1000) {
      s.session.lastSeenAt = new Date().toISOString();
      await writeAuth(s.auth);
    }
    res.json({ configured: true, loggedIn: true, login: s.auth.login, sessions: (s.auth.sessions || []).length });
  } catch (e) {
    authError(res, e);
  }
});

// Первый вход: придумать логин и пароль. Работает только пока аккаунт не создан.
app.post('/api/auth/setup', async (req, res) => {
  try {
    if (await readAuth()) return res.status(409).json({ error: 'already_configured' });
    const { login, password } = req.body || {};
    const bad = validateCredentials(login, password);
    if (bad) return res.status(400).json({ error: bad });
    const { auth, recoveryCode } = await buildAuth(login, password);
    await createSession(req, res, auth);
    console.log('Аккаунт создан для логина:', auth.login);
    res.json({ ok: true, recoveryCode });
  } catch (e) {
    authError(res, e);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    if (isRateLimited(req.ip)) return res.status(429).json({ error: 'too_many_attempts' });
    const auth = await readAuth();
    if (!auth) return res.status(409).json({ error: 'not_configured' });
    const { login, password } = req.body || {};
    // Пароль проверяем всегда, даже при неверном логине — чтобы по времени ответа нельзя было угадать логин
    const passOk = await verifySecret(String(password || ''), auth.passSalt, auth.passHash);
    const loginOk = normalizeLogin(login) === normalizeLogin(auth.login);
    if (!passOk || !loginOk) {
      registerFail(req.ip);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    failedAttempts.delete(req.ip);
    await createSession(req, res, auth);
    res.json({ ok: true });
  } catch (e) {
    authError(res, e);
  }
});

// Выход: с этого устройства или со всех сразу ({ all: true })
app.post('/api/auth/logout', async (req, res) => {
  try {
    const s = await getSession(req);
    if (s) {
      if (req.body && req.body.all) s.auth.sessions = [];
      else s.auth.sessions = (s.auth.sessions || []).filter((x) => x.id !== s.session.id);
      await writeAuth(s.auth);
    }
    clearSessionCookie(req, res);
    res.json({ ok: true });
  } catch (e) {
    authError(res, e);
  }
});

// Восстановление доступа по коду: задаёт новый логин и пароль, выкидывает все старые сессии,
// выдаёт НОВЫЙ код восстановления (старый перестаёт работать).
// Запасной вариант: код из переменной окружения AUTH_RESET_CODE на Render.
app.post('/api/auth/recover', async (req, res) => {
  try {
    if (isRateLimited(req.ip)) return res.status(429).json({ error: 'too_many_attempts' });
    const { recoveryCode, login, password } = req.body || {};
    const code = normalizeRecoveryCode(recoveryCode);
    const current = await readAuth();

    let codeOk = false;
    if (code && current) codeOk = await verifySecret(code, current.recSalt, current.recHash);
    const envCode = normalizeRecoveryCode(process.env.AUTH_RESET_CODE);
    if (!codeOk && code && envCode.length >= 8 && safeEqualStrings(code, envCode)) codeOk = true;

    if (!codeOk) {
      registerFail(req.ip);
      return res.status(401).json({ error: 'invalid_code' });
    }
    const bad = validateCredentials(login, password);
    if (bad) return res.status(400).json({ error: bad });

    failedAttempts.delete(req.ip);
    const { auth, recoveryCode: newCode } = await buildAuth(login, password, current && current.createdAt);
    await createSession(req, res, auth);
    console.log('Доступ восстановлен, логин:', auth.login);
    res.json({ ok: true, recoveryCode: newCode });
  } catch (e) {
    authError(res, e);
  }
});

// Выпустить новый код восстановления (нужен текущий пароль). Старый код перестаёт работать.
app.post('/api/auth/recovery-code', async (req, res) => {
  try {
    if (isRateLimited(req.ip)) return res.status(429).json({ error: 'too_many_attempts' });
    const s = await getSession(req);
    if (!s) return res.status(401).json({ error: 'unauthorized' });
    const passOk = await verifySecret(String((req.body && req.body.password) || ''), s.auth.passSalt, s.auth.passHash);
    if (!passOk) {
      registerFail(req.ip);
      return res.status(401).json({ error: 'invalid_password' });
    }
    const recoveryCode = generateRecoveryCode();
    s.auth.recSalt = newSalt();
    s.auth.recHash = await hashSecret(normalizeRecoveryCode(recoveryCode), s.auth.recSalt);
    s.auth.updatedAt = new Date().toISOString();
    await writeAuth(s.auth);
    res.json({ ok: true, recoveryCode });
  } catch (e) {
    authError(res, e);
  }
});

// Все остальные /api/* — только для вошедшего пользователя. Открыты: /api/auth/* и /api/ping (для пинг-сервиса).
app.use('/api', async (req, res, next) => {
  if (req.path.startsWith('/auth/') || req.path === '/ping') return next();
  try {
    const s = await getSession(req);
    if (!s) return res.status(401).json({ error: 'unauthorized' });
    next();
  } catch (e) {
    authError(res, e);
  }
});

// Получить запись за конкретный день
app.get('/api/day/:date', async (req, res) => {
  const db = await readDB();
  res.json(db.days[req.params.date] || null);
});

// Сохранить/обновить часть записи за день (слияние с уже сохранёнными разделами)
app.post('/api/day/:date', async (req, res) => {
  const db = await readDB();
  db.days = db.days || {};
  const existing = db.days[req.params.date] || {};
  db.days[req.params.date] = { ...existing, ...req.body, date: req.params.date };
  await writeDB(db);
  res.json({ ok: true });
});

// Последние N дней (по умолчанию 14), отсортированы от новых к старым
app.get('/api/days', async (req, res) => {
  const db = await readDB();
  const limit = parseInt(req.query.limit) || 14;
  const days = db.days || {};
  const dates = Object.keys(days).sort().reverse().slice(0, limit);
  res.json(dates.map((d) => days[d]));
});

// Список откликов на вакансии
app.get('/api/jobs', async (req, res) => {
  const db = await readDB();
  res.json(db.jobs || []);
});

// Добавить отклик
app.post('/api/jobs', async (req, res) => {
  const db = await readDB();
  db.jobs = db.jobs || [];
  db.jobs.unshift(req.body);
  await writeDB(db);
  res.json({ ok: true });
});

// Дата последнего дня, когда были указаны реальные (ненулевые) юниты алкоголя — считается по всем сохранённым дням
app.get('/api/sobriety', async (req, res) => {
  const db = await readDB();
  const days = db.days || {};
  const dates = Object.keys(days)
    .filter((d) => Number(days[d].alcohol) > 0)
    .sort();
  const lastDrinkDate = dates.length ? dates[dates.length - 1] : null;
  res.json({ lastDrinkDate });
});

const VALID_LEVELS = ['A1', 'A2', 'B1', 'B2'];

const LEVEL_GUIDANCE = {
  A1: 'уровня A1: только самые простые слова и конструкции, короткие простые предложения в настоящем времени, минимум связок',
  A2: 'уровня A2: простая лексика и грамматика (présent, passé composé, futur proche), короткие предложения, повседневные слова',
  B1: 'уровня B1: чуть более сложная лексика, разные времена (présent, passé composé, imparfait, futur simple), сложноподчинённые предложения, немного разговорных оборотов',
  B2: 'уровня B2: богатая лексика, разнообразные грамматические конструкции (subjonctif, conditionnel, сложные времена), связная аргументация, идиоматические выражения',
};

// Получить последний сохранённый текст для уровня (без обращения к AI — экономия)
app.get('/api/french-text/:level', async (req, res) => {
  const level = req.params.level;
  if (!VALID_LEVELS.includes(level)) return res.status(400).json({ error: 'bad_level' });
  const db = await readDB();
  res.json((db.frenchTexts && db.frenchTexts[level]) || null);
});

// Собственный текст пользователя (вкладка "Свой текст") — хранится отдельно от сгенерированных
app.get('/api/french-custom-text', async (req, res) => {
  const db = await readDB();
  res.json(db.customFrenchText || null);
});

app.post('/api/french-custom-text', async (req, res) => {
  const text = (req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'no_text' });
  const db = await readDB();
  db.customFrenchText = { text, savedAt: new Date().toISOString() };
  await writeDB(db);
  res.json({ ok: true });
});

// Список ранее использованных тем
app.get('/api/topics', async (req, res) => {
  const db = await readDB();
  res.json(db.topics || []);
});

app.post('/api/topics', async (req, res) => {
  const topic = (req.body.topic || '').trim();
  if (!topic) return res.status(400).json({ error: 'no_topic' });
  const db = await readDB();
  db.topics = db.topics || [];
  if (!db.topics.includes(topic)) db.topics.push(topic);
  await writeDB(db);
  res.json(db.topics);
});

app.delete('/api/topics', async (req, res) => {
  const topic = (req.body.topic || '').trim();
  const db = await readDB();
  db.topics = (db.topics || []).filter((t) => t !== topic);
  await writeDB(db);
  res.json(db.topics);
});

// Личный словарь слов/выражений, сохранённых из разбора
app.get('/api/dictionary', async (req, res) => {
  const db = await readDB();
  res.json(db.dictionary || []);
});

app.post('/api/dictionary', async (req, res) => {
  const db = await readDB();
  db.dictionary = db.dictionary || [];
  const word = (req.body.word || '').trim();
  const norm = word.toLowerCase();
  const exists = db.dictionary.some((e) => (e.word || '').trim().toLowerCase() === norm);
  if (exists) {
    return res.json({ ok: true, duplicate: true });
  }
  db.dictionary.unshift({ ...req.body, word, addedAt: new Date().toISOString() });
  await writeDB(db);
  res.json({ ok: true, duplicate: false });
});

app.delete('/api/dictionary', async (req, res) => {
  const addedAt = req.body.addedAt;
  const db = await readDB();
  db.dictionary = (db.dictionary || []).filter((e) => e.addedAt !== addedAt);
  await writeDB(db);
  res.json({ ok: true });
});

// Генерация текста на французском по теме — раздел "Французский"
async function callClaude(apiKey, content, maxTokens) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-5',
      max_tokens: maxTokens,
      messages: [{ role: 'user', content }],
    }),
  });
  const data = await r.json();
  if (!r.ok) {
    const err = new Error(data.error?.message || 'api_error');
    err.isApiError = true;
    throw err;
  }
  return (data.content || [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
}

app.post('/api/generate-text', async (req, res) => {
  const topic = (req.body.topic || '').trim();
  const level = VALID_LEVELS.includes(req.body.level) ? req.body.level : 'A2';
  if (!topic) return res.status(400).json({ error: 'no_topic' });

  const apiKey = getAnthropicApiKey();
  if (!apiKey || apiKey === 'PASTE_YOUR_KEY_HERE') {
    return res.status(500).json({ error: 'no_api_key' });
  }

  try {
    const text = await callClaude(
      apiKey,
      'Напиши текст на французском языке ' +
        LEVEL_GUIDANCE[level] +
        '. Объём — примерно 500 слов. Тема: "' +
        topic +
        '". Не добавляй заголовок, перевод или пояснения — выведи только сам текст на французском языке.',
      1300
    );

    const db = await readDB();
    db.frenchTexts = db.frenchTexts || {};
    db.frenchTexts[level] = { text, topic, level, generatedAt: new Date().toISOString() };
    db.topics = db.topics || [];
    if (!db.topics.includes(topic)) db.topics.push(topic);
    await writeDB(db);

    res.json({ text, topic, level });
  } catch (e) {
    console.error('Ошибка генерации текста', e);
    res.status(500).json({ error: e.isApiError ? 'api_error' : 'generation_failed', details: e.message });
  }
});

// Разбор слова/выражения из французского текста по клику
app.post('/api/word-info', async (req, res) => {
  const word = (req.body.word || '').trim();
  const sentence = (req.body.sentence || '').trim();
  if (!word) return res.status(400).json({ error: 'no_word' });

  const norm = word.toLowerCase();
  const db0 = await readDB();
  if (db0.wordCache && db0.wordCache[norm]) {
    return res.json({ ...db0.wordCache[norm], fromCache: true });
  }

  const apiKey = getAnthropicApiKey();
  if (!apiKey || apiKey === 'PASTE_YOUR_KEY_HERE') {
    return res.status(500).json({ error: 'no_api_key' });
  }

  const prompt =
    'Ты помогаешь изучающему французский язык на уровне A2 разобрать слово из текста.\n' +
    'Слово/выражение: "' + word + '"\n' +
    'Предложение-контекст: "' + sentence + '"\n\n' +
    'Ответь СТРОГО валидным JSON без markdown-обрамления (без ```), по такой схеме:\n' +
    '{\n' +
    '  "word": "слово как в тексте",\n' +
    '  "translation": "перевод на русский именно в этом контексте",\n' +
    '  "transcription": "упрощённая русская транскрипция произношения",\n' +
    '  "partOfSpeech": "часть речи по-русски (глагол/существительное/прилагательное/наречие/предлог/местоимение/другое)",\n' +
    '  "gender": "род для существительных: мужской/женский, или null если неприменимо",\n' +
    '  "notes": "краткое объяснение употребления именно в этом контексте, 1-2 предложения по-русски",\n' +
    '  "verb": null или объект (только если это глагол или его форма):\n' +
    '    {\n' +
    '      "infinitive": "инфинитив",\n' +
    '      "group": "группа спряжения, например \'1-я группа (-er)\' / \'2-я группа (-ir)\' / \'3-я группа (неправильные)\'",\n' +
    '      "present": {"je":"...","tu":"...","il/elle/on":"...","nous":"...","vous":"...","ils/elles":"..."},\n' +
    '      "passeCompose": {"je":"...","tu":"...","il/elle/on":"...","nous":"...","vous":"...","ils/elles":"..."},\n' +
    '      "futurSimple": {"je":"...","tu":"...","il/elle/on":"...","nous":"...","vous":"...","ils/elles":"..."}\n' +
    '    }\n' +
    '}\n' +
    'Если слово — часть устойчивого выражения (например, предлог + существительное), учти это в notes. Никакого текста вне JSON.';

  try {
    const raw = await callClaude(apiKey, prompt, 1000);
    const cleaned = raw.replace(/^```json\s*|^```\s*|```$/gm, '').trim();
    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (parseErr) {
      return res.json({ word, translation: null, raw: cleaned });
    }
    const db = await readDB();
    db.wordCache = db.wordCache || {};
    db.wordCache[norm] = parsed;
    await writeDB(db);
    res.json(parsed);
  } catch (e) {
    console.error('Ошибка разбора слова', e);
    res.status(500).json({ error: e.isApiError ? 'api_error' : 'generation_failed', details: e.message });
  }
});

// Простая проверка, что сервер жив (и на каком хранилище сейчас работает — удобно для диагностики)
// Распознавание французского текста с фотографии (скан камерой телефона)
app.post('/api/ocr-text', async (req, res) => {
  const imageBase64 = req.body.imageBase64;
  const mediaType = req.body.mediaType || 'image/jpeg';
  if (!imageBase64) return res.status(400).json({ error: 'no_image' });

  const apiKey = getAnthropicApiKey();
  if (!apiKey || apiKey === 'PASTE_YOUR_KEY_HERE') {
    return res.status(500).json({ error: 'no_api_key' });
  }

  try {
    const text = await callClaude(
      apiKey,
      [
        { type: 'image', source: { type: 'base64', media_type: mediaType, data: imageBase64 } },
        {
          type: 'text',
          text:
            'Распознай весь французский текст на этом изображении и выведи его дословно, в том же порядке, сохраняя знаки препинания. ' +
            'Не добавляй перевод, заголовок или пояснения — выведи только сам распознанный текст на французском. ' +
            'Если текста на изображении нет или он нечитаем, ответь ровно: НЕТ_ТЕКСТА',
        },
      ],
      1500
    );
    if (text.trim() === 'НЕТ_ТЕКСТА') {
      return res.status(422).json({ error: 'no_text_found' });
    }
    res.json({ text: text.trim() });
  } catch (e) {
    console.error('Ошибка распознавания фото', e);
    res.status(500).json({ error: e.isApiError ? 'api_error' : 'generation_failed', details: e.message });
  }
});

app.get('/api/ping', async (req, res) => {
  await getMongoCollection().catch(() => null);
  res.json({ ok: true, time: new Date().toISOString(), storage: mongoConnected ? 'mongodb' : 'local-file' });
});

const PORT = process.env.PORT || 4177;
app.listen(PORT, '0.0.0.0', () => {
  console.log('Трекер запущен: http://localhost:' + PORT);
});