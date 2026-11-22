require('dotenv').config();

const express = require('express');
const multer = require('multer');
const { rateLimit } = require('express-rate-limit');
const yauzl = require('yauzl');
const plist = require('plist');
const bplist = require('bplist-parser');
const { execFile } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { Transform, pipeline } = require('node:stream');
const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');

// ---------------------------------------------------------------------------
// Configurazione (da .env)
// ---------------------------------------------------------------------------
const MB = 1024 * 1024;

function envNumber(name, def, allowZero = false) {
  const v = Number(process.env[name] ?? def);
  if (!Number.isFinite(v) || v < 0 || (v === 0 && !allowZero)) {
    throw new Error(`Variabile ${name} non valida`);
  }
  return v;
}

if (!process.env.DOMAIN) throw new Error('Variabile DOMAIN mancante (es. sign.example.com)');

const PORT = envNumber('PORT', 3000);
const BASE_URL = (/^https?:\/\//i.test(process.env.DOMAIN) ? process.env.DOMAIN : `https://${process.env.DOMAIN}`).replace(/\/+$/, '');
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const ZSIGN_PATH = process.env.ZSIGN_PATH || 'zsign';
const CLEANUP_MS = envNumber('CLEANUP_MINUTES', 60) * 60 * 1000;

// Numero di proxy davanti all'app (serve per leggere l'IP reale del client). 0 = nessuno.
const TRUST_PROXY = envNumber('TRUST_PROXY', 1, true);

// Rate limiting su /sign. Un valore MAX uguale a 0 disattiva quel limite.
const RATE = {
  ipMax: envNumber('RATE_LIMIT_IP_MAX', 10, true),
  ipWindowMs: envNumber('RATE_LIMIT_IP_WINDOW_MINUTES', 60) * 60 * 1000,
  globalMax: envNumber('RATE_LIMIT_GLOBAL_MAX', 100, true),
  globalWindowMs: envNumber('RATE_LIMIT_GLOBAL_WINDOW_MINUTES', 60) * 60 * 1000,
};

const LIMITS = {
  ipa: envNumber('MAX_IPA_MB', 500) * MB,
  mobileprovision: envNumber('MAX_MOBILEPROVISION_MB', 1) * MB,
  p12: envNumber('MAX_P12_MB', 1) * MB,
};

const FILENAMES = {
  ipa: 'input.ipa',
  mobileprovision: 'profile.mobileprovision',
  p12: 'cert.p12',
};

const EXTENSIONS = {
  ipa: '.ipa',
  mobileprovision: '.mobileprovision',
  p12: '.p12',
};

const ID_RE = /^[0-9a-f-]{36}$/;

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

const jobDirOf = (id) => path.join(DATA_DIR, id);
const removeJob = (id) => fsp.rm(jobDirOf(id), { recursive: true, force: true }).catch(() => {});

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ---------------------------------------------------------------------------
// Storage di multer con limite di dimensione per ogni campo
// ---------------------------------------------------------------------------
class LimitedDiskStorage {
  _handleFile(req, file, cb) {
    const limit = LIMITS[file.fieldname];
    if (!limit) return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname));

    const dest = path.join(req.jobDir, FILENAMES[file.fieldname]);
    let size = 0;

    const counter = new Transform({
      transform(chunk, _enc, done) {
        size += chunk.length;
        if (size > limit) {
          return done(
            httpError(413, `Il file "${file.fieldname}" supera il limite di ${Math.round(limit / MB)} MB`)
          );
        }
        done(null, chunk);
      },
    });

    pipeline(file.stream, counter, fs.createWriteStream(dest), (err) => {
      if (err) return cb(err);
      cb(null, { path: dest, size });
    });
  }

  _removeFile(_req, file, cb) {
    fsp.rm(file.path, { force: true }).then(() => cb(null), cb);
  }
}

const upload = multer({
  storage: new LimitedDiskStorage(),
  limits: { files: 3, fields: 5, fieldSize: 64 * 1024 },
}).fields([
  { name: 'ipa', maxCount: 1 },
  { name: 'mobileprovision', maxCount: 1 },
  { name: 'p12', maxCount: 1 },
]);

// ---------------------------------------------------------------------------
// Firma con zsign
// ---------------------------------------------------------------------------
function runZsign({ input, p12, password, mobileprovision, output }) {
  const args = ['-k', p12];
  if (password) args.push('-p', password);
  args.push('-m', mobileprovision, '-o', output, input);

  return new Promise((resolve, reject) => {
    execFile(ZSIGN_PATH, args, { timeout: 5 * 60 * 1000, maxBuffer: 10 * MB }, (err, stdout, stderr) => {
      if (err) {
        const details = `${stdout || ''}\n${stderr || ''}`.trim().slice(-1000);
        return reject(httpError(422, `Firma fallita${details ? `: ${details}` : ''}`));
      }
      resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Verifica del p12 (password corretta, cifrari legacy) prima di firmare
// ---------------------------------------------------------------------------
// La password viene passata a openssl via variabile d'ambiente, non come argomento.
function openssl(args, password) {
  return new Promise((resolve) => {
    execFile(
      'openssl',
      args,
      { env: { ...process.env, P12_PASS: password }, timeout: 30 * 1000, maxBuffer: MB },
      (err, _stdout, stderr) => resolve({ ok: !err, missing: err?.code === 'ENOENT', stderr: String(stderr || '') })
    );
  });
}

const WRONG_PASSWORD = 'Password del p12 errata (oppure file p12 corrotto)';
const isMacFailure = (stderr) => /mac verify failure/i.test(stderr);

// Ritorna il percorso del p12 da usare per la firma (originale o convertito in formato moderno).
async function checkP12(p12Path, password, jobDir) {
  const base = ['pkcs12', '-in', p12Path, '-nokeys', '-noout', '-passin', 'env:P12_PASS'];

  let r = await openssl(base, password);
  if (r.missing) return p12Path; // openssl non installato: lascio decidere a zsign
  if (r.ok) return p12Path;
  if (isMacFailure(r.stderr)) throw httpError(400, WRONG_PASSWORD);

  // Probabile p12 con cifrari vecchi (RC2/3DES) non supportati da OpenSSL 3: riprovo in modalità legacy
  r = await openssl([...base, '-legacy'], password);
  if (!r.ok) {
    if (isMacFailure(r.stderr)) throw httpError(400, WRONG_PASSWORD);
    throw httpError(400, `File p12 non leggibile: ${r.stderr.trim().slice(-300)}`);
  }

  // Lo converto in un p12 moderno, che zsign riesce a leggere
  const pem = path.join(jobDir, 'tmp.pem');
  const modern = path.join(jobDir, 'cert-modern.p12');
  try {
    const a = await openssl(
      ['pkcs12', '-in', p12Path, '-legacy', '-nodes', '-passin', 'env:P12_PASS', '-out', pem],
      password
    );
    if (!a.ok) throw httpError(400, `Conversione del p12 fallita: ${a.stderr.trim().slice(-300)}`);

    const b = await openssl(
      ['pkcs12', '-export', '-in', pem, '-out', modern, '-passout', 'env:P12_PASS'],
      password
    );
    if (!b.ok) throw httpError(400, `Conversione del p12 fallita: ${b.stderr.trim().slice(-300)}`);
  } finally {
    await fsp.rm(pem, { force: true }); // contiene la chiave privata in chiaro
  }
  return modern;
}

// ---------------------------------------------------------------------------
// Lettura Info.plist dall'IPA firmato (serve per il manifest)
// ---------------------------------------------------------------------------
function parsePlist(buf) {
  if (buf.subarray(0, 6).toString('latin1') === 'bplist') {
    return bplist.parseBuffer(buf)[0];
  }
  return plist.parse(buf.toString('utf8'));
}

function readInfoPlist(ipaPath) {
  return new Promise((resolve, reject) => {
    yauzl.open(ipaPath, { lazyEntries: true }, (err, zip) => {
      if (err) return reject(httpError(400, 'IPA non valido (non è un archivio zip)'));

      const re = /^Payload\/[^/]+\.app\/Info\.plist$/;
      let found = false;

      zip.on('entry', (entry) => {
        if (!re.test(entry.fileName)) return zip.readEntry();
        found = true;
        zip.openReadStream(entry, (err, stream) => {
          if (err) {
            zip.close();
            return reject(err);
          }
          const chunks = [];
          stream.on('data', (c) => chunks.push(c));
          stream.on('error', (e) => {
            zip.close();
            reject(e);
          });
          stream.on('end', () => {
            zip.close();
            try {
              resolve(parsePlist(Buffer.concat(chunks)));
            } catch (e) {
              reject(e);
            }
          });
        });
      });
      zip.on('end', () => {
        if (!found) reject(httpError(400, 'Info.plist non trovato nell\'IPA'));
      });
      zip.on('error', reject);
      zip.readEntry();
    });
  });
}

function buildManifest({ ipaUrl, bundleId, version, title }) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>${xmlEscape(ipaUrl)}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>${xmlEscape(bundleId)}</string>
        <key>bundle-version</key>
        <string>${xmlEscape(version)}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>${xmlEscape(title)}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
async function sweep() {
  let entries;
  try {
    entries = await fsp.readdir(DATA_DIR);
  } catch {
    return;
  }
  const now = Date.now();
  for (const id of entries) {
    if (!ID_RE.test(id)) continue;
    const dir = jobDirOf(id);
    try {
      let createdAt;
      try {
        createdAt = JSON.parse(await fsp.readFile(path.join(dir, 'meta.json'), 'utf8')).createdAt;
      } catch {
        createdAt = (await fsp.stat(dir)).mtimeMs; // job incompleto/orfano
      }
      if (now - createdAt >= CLEANUP_MS) {
        await removeJob(id);
        console.log(`[cleanup] rimosso ${id}`);
      }
    } catch {
      /* ignora */
    }
  }
}

function scheduleCleanup(id) {
  setTimeout(() => {
    removeJob(id).then(() => console.log(`[cleanup] rimosso ${id}`));
  }, CLEANUP_MS).unref();
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_PROXY);

const noLimit = (_req, _res, next) => next();
const tooMany = (message) => (_req, res) => res.status(429).json({ error: message });

// Limite per singolo IP
const ipLimiter =
  RATE.ipMax > 0
    ? rateLimit({
        windowMs: RATE.ipWindowMs,
        limit: RATE.ipMax,
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        handler: tooMany('Troppe richieste da questo IP, riprova più tardi'),
      })
    : noLimit;

// Limite globale (tutti gli utenti insieme)
const globalLimiter =
  RATE.globalMax > 0
    ? rateLimit({
        windowMs: RATE.globalWindowMs,
        limit: RATE.globalMax,
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        keyGenerator: () => 'global',
        handler: tooMany('Servizio al momento troppo carico, riprova più tardi'),
      })
    : noLimit;

app.get('/health', (_req, res) => res.json({ ok: true }));

async function prepareJob(req, _res, next) {
  try {
    req.jobId = randomUUID();
    req.jobDir = jobDirOf(req.jobId);
    await fsp.mkdir(req.jobDir, { recursive: true });
    next();
  } catch (e) {
    next(e);
  }
}

app.post('/sign', ipLimiter, globalLimiter, prepareJob, upload, async (req, res, next) => {
  const { jobId, jobDir } = req;
  try {
    const files = req.files || {};
    for (const field of Object.keys(EXTENSIONS)) {
      const f = files[field]?.[0];
      if (!f) throw httpError(400, `Campo mancante: ${field}`);
      if (!f.originalname.toLowerCase().endsWith(EXTENSIONS[field])) {
        throw httpError(400, `Il file "${field}" deve avere estensione ${EXTENSIONS[field]}`);
      }
    }

    const password = req.body?.password ?? '';
    const p12Path = await checkP12(path.join(jobDir, FILENAMES.p12), password, jobDir);

    const signedPath = path.join(jobDir, 'signed.ipa');
    await runZsign({
      input: path.join(jobDir, FILENAMES.ipa),
      p12: p12Path,
      mobileprovision: path.join(jobDir, FILENAMES.mobileprovision),
      password,
      output: signedPath,
    });

    const info = await readInfoPlist(signedPath);
    const bundleId = info.CFBundleIdentifier;
    if (!bundleId) throw httpError(422, 'CFBundleIdentifier mancante nell\'IPA firmato');

    const ipaUrl = `${BASE_URL}/files/${jobId}/signed.ipa`;
    const manifestUrl = `${BASE_URL}/manifest/${jobId}.plist`;

    await fsp.writeFile(
      path.join(jobDir, 'manifest.plist'),
      buildManifest({
        ipaUrl,
        bundleId,
        version: info.CFBundleShortVersionString || info.CFBundleVersion || '1.0',
        title: info.CFBundleDisplayName || info.CFBundleName || bundleId,
      })
    );

    const createdAt = Date.now();
    await fsp.writeFile(path.join(jobDir, 'meta.json'), JSON.stringify({ createdAt }));
    scheduleCleanup(jobId);
    req.jobDone = true;

    res.json({
      id: jobId,
      installUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`,
      installPage: `${BASE_URL}/install/${jobId}`,
      manifestUrl,
      ipaUrl,
      expiresAt: new Date(createdAt + CLEANUP_MS).toISOString(),
    });
  } catch (e) {
    next(e);
  }
});

// Carica un job solo se esiste e non è scaduto
async function requireJob(req, res, next) {
  const id = req.params.id;
  if (!ID_RE.test(id)) return res.status(404).send('Not found');
  try {
    const meta = JSON.parse(await fsp.readFile(path.join(jobDirOf(id), 'meta.json'), 'utf8'));
    if (Date.now() - meta.createdAt >= CLEANUP_MS) {
      removeJob(id);
      return res.status(404).send('Link scaduto');
    }
    req.jobId = id;
    next();
  } catch {
    res.status(404).send('Not found');
  }
}

app.get('/manifest/:id.plist', requireJob, (req, res) => {
  res.type('text/xml').sendFile(path.join(jobDirOf(req.jobId), 'manifest.plist'));
});

app.get('/files/:id/signed.ipa', requireJob, (req, res) => {
  res
    .type('application/octet-stream')
    .sendFile(path.join(jobDirOf(req.jobId), 'signed.ipa'));
});

// Pagina con il pulsante di installazione (da aprire con Safari su iPhone/iPad)
app.get('/install/:id', requireJob, (req, res) => {
  const manifestUrl = `${BASE_URL}/manifest/${req.jobId}.plist`;
  const link = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
  res.type('html').send(`<!doctype html>
<html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Installa app</title>
<style>
  body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f5f5f7}
  a{background:#0071e3;color:#fff;padding:16px 32px;border-radius:14px;text-decoration:none;font-size:18px}
</style></head>
<body><a href="${xmlEscape(link)}">Installa</a></body></html>`);
});

// Gestione errori
// eslint-disable-next-line no-unused-vars
app.use(async (err, req, res, _next) => {
  if (req.jobId && !req.jobDone) await removeJob(req.jobId);

  let status = err.status || 500;
  let message = err.message || 'Errore interno';
  if (err instanceof multer.MulterError) {
    status = 400;
    message = `Errore upload: ${err.message}`;
  }
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Errore interno' : message });
});

(async () => {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await sweep();
  setInterval(sweep, 5 * 60 * 1000).unref();
  app.listen(PORT, () => {
    console.log(`IPA signer in ascolto su :${PORT} - dominio: ${BASE_URL}`);
  });
})();
