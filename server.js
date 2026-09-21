const express = require('express');
const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const DB_PATH = path.join(__dirname, 'db.json');
const CONFIG_PATH = path.join(__dirname, 'config.json');

// ---------- Конфиг (API-ключ) ----------
function readConfig() {
  if (process.env.ANTHROPIC_API_KEY) {
    return { anthropicApiKey: process.env.ANTHROPIC_API_KEY };
  }
  if (!fs.existsSync(CONFIG_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (e) {
    return {};
  }
}

// ---------- База данных: MongoDB (если задан MONGODB_URI) либо локальный db.json ----------
const MONGO_URI = process.env.MONGODB_URI;
let mongoCollection = null;

async function initMongo() {
  if (!MONGO_URI) {
    console.log('MONGODB_URI не задан — работаю с локальным файлом db.json');
    return;
  }
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db('daytracker');
  mongoCollection = db.collection('store');
  console.log('Подключено к MongoDB Atlas — данные хранятся в облаке, переживают перезапуски');
}

function readLocalDB() {
  if (!fs.existsSync(DB_PATH)) {
    return { days: {}, jobs: [] };
  }
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
  if (mongoCollection) {
    const doc = await mongoCollection.findOne({ _id: 'main' });
    return (doc && doc.data) || { days: {}, jobs: [] };
  }
  return readLocalDB();
}

async function writeDB(db) {
  if (mongoCollection) {
    await mongoCollection.updateOne({ _id: 'main' }, { $set: { data: db } }, { upsert: true });
    return;
  }
  writeLocalDB(db);
}

// ---------- Роуты ----------

// Получить запись за конкретный день
app.get('/api/day/:date', async (req, res) => {
  const db = await readDB();
  res.json(db.days[req.params.date] || null);
});

// Сохранить/обновить часть записи за день (слияние с уже сохранёнными разделами)
app.post('/api/day/:date', async (req, res) => {
  const db = await readDB();
  const existing = db.days[req.params.date] || {};
  db.days[req.params.date] = { ...existing, ...req.body, date: req.params.date };
  await writeDB(db);
  res.json({ ok: true });
});

// Последние N дней (по умолчанию 14), отсортированы от новых к старым
app.get('/api/days', async (req, res) => {
  const db = await readDB();
  const limit = parseInt(req.query.limit) || 14;
  const dates = Object.keys(db.days).sort().reverse().slice(0, limit);
  res.json(dates.map((d) => db.days[d]));
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

// Дата последнего дня, когда были указаны реальные (ненулевые) юниты алкоголя
app.get('/api/sobriety', async (req, res) => {
  const db = await readDB();
  const dates = Object.keys(db.days)
    .filter((d) => Number(db.days[d].alcohol) > 0)
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

// Генерация текста на французском (A2) по теме — раздел "Французский"
async function callClaude(apiKey, userText, maxTokens) {
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
      messages: [{ role: 'user', content: userText }],
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

  const config = readConfig();
  const apiKey = (config.anthropicApiKey || '').trim();
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

  const config = readConfig();
  const apiKey = (config.anthropicApiKey || '').trim();
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

// Простая проверка, что сервер жив (удобно для диагностики с телефона)
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString(), storage: mongoCollection ? 'mongodb' : 'local-file' });
});

const PORT = process.env.PORT || 4177;

initMongo()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log('Трекер запущен: http://localhost:' + PORT);
      console.log('С телефона через Tailscale: http://<имя-компьютера>:' + PORT);
    });
  })
  .catch((e) => {
    console.error('Не удалось подключиться к MongoDB, запускаюсь с локальным файлом:', e.message);
    app.listen(PORT, '0.0.0.0', () => {
      console.log('Трекер запущен: http://localhost:' + PORT);
    });
  });
