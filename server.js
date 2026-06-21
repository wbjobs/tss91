const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const ipaddr = require('ipaddr.js');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL, isoUint8Array } = require('@simplewebauthn/server/helpers');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

const RP_NAME = 'Internal Tool Portal';
const RP_ID = process.env.RP_ID || 'localhost';
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || `http://localhost:${PORT}`;

const INTERNAL_NETWORKS = [
  { cidr: '10.0.0.0/8' },
  { cidr: '172.16.0.0/12' },
  { cidr: '192.168.0.0/16' },
  { cidr: '127.0.0.1/32' },
  { cidr: '::1/128' },
];

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8,
  },
}));

const db = new Database('./data.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_name TEXT,
    user_agent TEXT,
    user_handle TEXT,
    transports TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT,
    device_name TEXT,
    user_agent TEXT,
    ip_address TEXT,
    success INTEGER NOT NULL,
    error_message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS temp_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    generated_by TEXT NOT NULL,
    note TEXT,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    used_by_ip TEXT,
    used_by_ua TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

function isInternalIp(req) {
  const candidates = [
    req.ip,
    req.connection?.remoteAddress,
    req.socket?.remoteAddress,
    req.connection?.socket?.remoteAddress,
  ].filter(Boolean);

  for (const rawIp of candidates) {
    try {
      let addr = ipaddr.parse(rawIp);
      if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress?.()) {
        addr = addr.toIPv4Address();
      }
      const isMatch = INTERNAL_NETWORKS.some(net => {
        try {
          return addr.match(ipaddr.parseCIDR(net.cidr));
        } catch {
          return false;
        }
      });
      if (isMatch) return true;
    } catch (e) {}
  }
  return false;
}

function requireInternalIp(req, res, next) {
  if (!isInternalIp(req)) {
    return res.status(403).send('Access restricted to internal network only.');
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function getDeviceInfo(req) {
  return {
    userAgent: req.headers['user-agent'] || '',
    ip: req.ip || req.connection.remoteAddress || '',
  };
}

app.use(requireInternalIp);

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/session', (req, res) => {
  if (req.session.userId) {
    res.json({ authenticated: true });
  } else {
    res.json({ authenticated: false });
  }
});

app.get('/api/setup/status', (req, res) => {
  const credentials = db.prepare('SELECT COUNT(*) AS c FROM credentials').get().c;
  res.json({ hasAnyCredentials: credentials > 0, totalCredentials: credentials });
});

app.get('/api/register/options', async (req, res) => {
  const credentialCount = db.prepare('SELECT COUNT(*) as c FROM credentials').get().c;
  const isFirstBootstrap = credentialCount === 0;

  if (!isFirstBootstrap && !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const userId = req.session.userId || crypto.randomBytes(16).toString('hex');
  if (!req.session.userId) {
    req.session.userId = userId;
  }

  const credentials = db.prepare('SELECT credential_id, device_name FROM credentials').all();

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: userId,
    userName: `user-${userId.slice(0, 8)}`,
    attestationType: 'none',
    excludeCredentials: credentials.map(c => ({
      id: c.credential_id,
      type: 'public-key',
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  req.session.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const credentialCount = db.prepare('SELECT COUNT(*) as c FROM credentials').get().c;
  const isFirstBootstrap = credentialCount === 0;

  if (!isFirstBootstrap && !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { body } = req;
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'No registration in progress' });
  }

  const info = getDeviceInfo(req);
  const deviceName = body.deviceName || 'Unnamed Device';

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });
  } catch (error) {
    db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                VALUES (?, ?, ?, ?, 0, ?)`).run(null, deviceName, info.userAgent, info.ip, error.message);
    return res.status(400).json({ error: error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    const credentialIdB64 = isoBase64URL.fromBuffer(credentialID);

    const stmt = db.prepare(`
      INSERT INTO credentials (credential_id, public_key, counter, device_name, user_agent, transports, created_at, last_used_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT(credential_id) DO UPDATE SET
        public_key = excluded.public_key,
        counter = MAX(counter, excluded.counter),
        device_name = COALESCE(NULLIF(excluded.device_name, 'Unnamed Device'), credentials.device_name),
        user_agent = excluded.user_agent,
        transports = excluded.transports,
        last_used_at = CURRENT_TIMESTAMP
    `);
    stmt.run(
      credentialIdB64,
      Buffer.from(credentialPublicKey),
      counter,
      deviceName,
      info.userAgent,
      JSON.stringify(body.response?.transports || [])
    );

    db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success)
                VALUES (?, ?, ?, ?, 1)`).run(credentialIdB64, deviceName, info.userAgent, info.ip);

    req.session.currentChallenge = undefined;
    return res.json({ verified: true });
  }

  db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
              VALUES (?, ?, ?, ?, 0, ?)`).run(null, deviceName, info.userAgent, info.ip, 'Registration verification failed');
  res.json({ verified: false });
});

app.get('/api/auth/options', async (req, res) => {
  const credentials = db.prepare('SELECT credential_id FROM credentials').all();

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: credentials.map(c => ({
      id: c.credential_id,
      type: 'public-key',
    })),
    userVerification: 'preferred',
  });

  req.session.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/api/auth/verify', async (req, res) => {
  const { body } = req;
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'No authentication in progress' });
  }

  const info = getDeviceInfo(req);

  const credentialRow = db.prepare('SELECT * FROM credentials WHERE credential_id = ?').get(body.id);
  if (!credentialRow) {
    db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                VALUES (?, ?, ?, ?, 0, ?)`).run(body.id, 'Unknown', info.userAgent, info.ip, 'Credential not registered');
    return res.status(400).json({ error: 'Credential not registered' });
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialPublicKey: new Uint8Array(credentialRow.public_key),
        credentialID: isoBase64URL.toBuffer(credentialRow.credential_id),
        counter: credentialRow.counter,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        transports: JSON.parse(credentialRow.transports || '[]'),
      },
      requireUserVerification: false,
    });
  } catch (error) {
    db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                VALUES (?, ?, ?, ?, 0, ?)`).run(body.id, credentialRow.device_name, info.userAgent, info.ip, error.message);
    return res.status(400).json({ error: error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    const newCounter = authenticationInfo.newCounter;
    const oldCounter = credentialRow.counter;

    const tx = db.transaction((credId, nc, oc, devName, ua, ip) => {
      const result = db.prepare(`
        UPDATE credentials
        SET counter = ?, last_used_at = CURRENT_TIMESTAMP
        WHERE credential_id = ? AND counter <= ?
      `).run(nc, credId, oc);

      if (result.changes === 0) {
        const latest = db.prepare('SELECT counter FROM credentials WHERE credential_id = ?').get(credId);
        db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                    VALUES (?, ?, ?, ?, 0, ?)`).run(
          credId, devName, ua, ip,
          `Counter collision: expected <= ${oc}, received ${nc}, DB latest ${latest?.counter ?? '?'}`
        );
        return { ok: false, reason: 'counter_collision' };
      }

      db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success)
                  VALUES (?, ?, ?, ?, 1)`).run(credId, devName, ua, ip);
      return { ok: true };
    });

    const txResult = tx(body.id, newCounter, oldCounter, credentialRow.device_name, info.userAgent, info.ip);

    if (!txResult.ok) {
      return res.status(409).json({
        verified: false,
        error: 'Concurrent authentication rejected (counter rollback detected). Please retry.',
      });
    }

    if (!req.session.userId) {
      req.session.userId = crypto.randomBytes(16).toString('hex');
    }

    req.session.currentChallenge = undefined;
    return res.json({ verified: true });
  }

  db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
              VALUES (?, ?, ?, ?, 0, ?)`).run(body.id, credentialRow.device_name, info.userAgent, info.ip, 'Authentication failed');
  res.json({ verified: false });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/devices', requireAuth, (req, res) => {
  const devices = db.prepare(`SELECT id, credential_id, device_name, counter, created_at, last_used_at
                              FROM credentials ORDER BY created_at DESC`).all();
  res.json(devices);
});

app.delete('/api/devices/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });

  const cred = db.prepare('SELECT credential_id FROM credentials WHERE id = ?').get(id);
  if (!cred) return res.status(404).json({ error: 'Device not found' });

  db.prepare('DELETE FROM credentials WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.get('/api/logs', requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const logs = db.prepare(`SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT ?`).all(limit);
  res.json(logs);
});

const TEMP_CODE_TTL_MS = 5 * 60 * 1000;

function generateTempCode() {
  return String(Math.floor(100000 + crypto.randomInt(0, 900000)));
}

app.get('/api/temp-codes', requireAuth, (req, res) => {
  const codes = db.prepare(`
    SELECT id, code, note, expires_at, used_at, used_by_ip, revoked, created_at
    FROM temp_codes
    ORDER BY created_at DESC
    LIMIT 100
  `).all();
  res.json(codes);
});

app.post('/api/temp-codes/generate', requireAuth, (req, res) => {
  const note = (req.body?.note || '').toString().slice(0, 120);
  const expiresAt = new Date(Date.now() + TEMP_CODE_TTL_MS).toISOString();

  let code;
  let attempts = 0;
  while (attempts < 5) {
    code = generateTempCode();
    const existing = db.prepare('SELECT id FROM temp_codes WHERE code = ?').get(code);
    if (!existing) break;
    attempts++;
  }
  if (attempts >= 5) {
    return res.status(500).json({ error: 'Failed to generate unique code' });
  }

  const info = getDeviceInfo(req);
  const result = db.prepare(`
    INSERT INTO temp_codes (code, generated_by, note, expires_at, created_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
  `).run(code, info.ip + (info.userAgent ? '|' + info.userAgent.slice(0, 60) : ''), note, expiresAt);

  const row = db.prepare('SELECT * FROM temp_codes WHERE id = ?').get(result.lastInsertRowid);
  res.json({ ok: true, code: row });
});

app.post('/api/temp-codes/:id/revoke', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });

  const row = db.prepare('SELECT id FROM temp_codes WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE temp_codes SET revoked = 1 WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/temp-codes/login', (req, res) => {
  const code = (req.body?.code || '').toString().trim().replace(/\D/g, '').slice(0, 6);
  const deviceName = (req.body?.deviceName || 'Temporary Code Login').toString().slice(0, 100);

  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ verified: false, error: '请输入 6 位数字授权码' });
  }

  const info = getDeviceInfo(req);

  const tx = db.transaction(() => {
    const row = db.prepare(`SELECT * FROM temp_codes WHERE code = ?`).get(code);

    if (!row) {
      db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                  VALUES (?, ?, ?, ?, 0, ?)`).run('temp-code-' + code, deviceName, info.userAgent, info.ip, '授权码不存在');
      return { status: 400, body: { verified: false, error: '授权码无效' } };
    }

    if (row.revoked) {
      db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                  VALUES (?, ?, ?, ?, 0, ?)`).run('temp-code-' + code, deviceName, info.userAgent, info.ip, '授权码已撤销');
      return { status: 400, body: { verified: false, error: '该授权码已被撤销' } };
    }

    if (row.used_at) {
      db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                  VALUES (?, ?, ?, ?, 0, ?)`).run('temp-code-' + code, deviceName, info.userAgent, info.ip, '授权码已被使用');
      return { status: 400, body: { verified: false, error: '该授权码已被使用，一次性码不能重复使用' } };
    }

    if (new Date(row.expires_at).getTime() < Date.now()) {
      db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success, error_message)
                  VALUES (?, ?, ?, ?, 0, ?)`).run('temp-code-' + code, deviceName, info.userAgent, info.ip, '授权码已过期');
      return { status: 400, body: { verified: false, error: '该授权码已过期（有效期 5 分钟）' } };
    }

    const upd = db.prepare(`
      UPDATE temp_codes
      SET used_at = CURRENT_TIMESTAMP, used_by_ip = ?, used_by_ua = ?
      WHERE id = ? AND used_at IS NULL AND revoked = 0
    `).run(info.ip, info.userAgent, row.id);

    if (upd.changes === 0) {
      return { status: 409, body: { verified: false, error: '授权码正在被使用，请稍后重试' } };
    }

    db.prepare(`INSERT INTO auth_logs (credential_id, device_name, user_agent, ip_address, success)
                VALUES (?, ?, ?, ?, 1)`).run('temp-code-' + code, deviceName, info.userAgent, info.ip);

    if (!req.session.userId) {
      req.session.userId = crypto.randomBytes(16).toString('hex');
    }
    req.session.tempCodeLogin = true;

    return { status: 200, body: { verified: true } };
  });

  const out = tx();
  res.status(out.status).json(out.body);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/manage', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'manage.html'));
});

app.listen(PORT, () => {
  console.log(`WebAuthn Internal Auth listening on ${EXPECTED_ORIGIN}`);
  console.log(`Allowed internal networks: ${INTERNAL_NETWORKS.map(n => n.cidr).join(', ')}`);
});
