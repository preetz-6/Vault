'use strict';

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const { nanoid } = require('nanoid');
const { encrypt, decrypt, hashSecret, generatePassword } = require('./crypto');
const { syncUpsert, syncDelete, syncAuthConfig } = require('./sync');

const app = express();
app.use(express.json());

// Serve frontend static files
app.use(express.static(path.join(__dirname, 'public')));

// Config paths (same as vault.js)
const CONFIG_DIR = path.join(require('os').homedir(), '.vault-cli');
const AUTH_FILE = path.join(CONFIG_DIR, 'auth.json');
const VAULT_FILE = path.join(CONFIG_DIR, 'vault.json');

if (!fs.existsSync(CONFIG_DIR)) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Helpers
function loadAuth() {
  return fs.existsSync(AUTH_FILE) ? JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')) : null;
}

function loadVault() {
  return fs.existsSync(VAULT_FILE) ? JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8')) : [];
}

function saveVault(entries) {
  fs.writeFileSync(VAULT_FILE, JSON.stringify(entries, null, 2), 'utf8');
}

function decryptEntry(entry, masterKey) {
  try {
    return JSON.parse(decrypt(entry.encrypted, masterKey));
  } catch (e) {
    return null;
  }
}

// In-memory master key storage for the active session
let sessionMasterKey = null;

// Middleware to check if unlocked
function requireAuth(req, res, next) {
  if (!sessionMasterKey) {
    return res.status(401).json({ error: 'Vault is locked. Please log in.' });
  }
  next();
}

// ── AUTH ENDPOINTS ──────────────────────────────────────────────────────────

// Check setup status
app.get('/api/auth/status', (req, res) => {
  const auth = loadAuth();
  res.json({
    setupRequired: !auth,
    unlocked: !!sessionMasterKey,
    question: auth ? auth.question : null
  });
});

// Setup master password
app.post('/api/auth/setup', async (req, res) => {
  const { masterPw, question, answer } = req.body;
  if (!masterPw || !question || !answer) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (masterPw.length < 8) {
    return res.status(400).json({ error: 'Master password must be at least 8 characters' });
  }

  const questionHash = hashSecret(answer.trim());
  const auth = {
    masterHash:   hashSecret(masterPw),
    questionHash,
    question:     question.trim()
  };

  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), 'utf8');

  // Sync security question to Supabase so vault-web can verify it
  try {
    await syncAuthConfig(auth.question, questionHash);
  } catch (err) {
    console.error('Supabase config sync error:', err.message);
  }

  res.json({ success: true });
});

// Verify master password (login step 1)
app.post('/api/auth/verify-password', (req, res) => {
  const auth = loadAuth();
  if (!auth) {
    return res.status(400).json({ error: 'Vault is not set up' });
  }

  const { masterPw } = req.body;
  if (!masterPw) {
    return res.status(400).json({ error: 'Password is required' });
  }

  if (hashSecret(masterPw) !== auth.masterHash) {
    return res.status(401).json({ error: 'Incorrect master password' });
  }

  res.json({ success: true, question: auth.question });
});

// Login / Unlock
app.post('/api/auth/login', (req, res) => {
  const auth = loadAuth();
  if (!auth) {
    return res.status(400).json({ error: 'Vault is not set up' });
  }

  const { masterPw, answer } = req.body;
  if (!masterPw || !answer) {
    return res.status(400).json({ error: 'Password and answer are required' });
  }

  if (hashSecret(masterPw) !== auth.masterHash) {
    return res.status(401).json({ error: 'Incorrect master password' });
  }

  if (hashSecret(answer.trim()) !== auth.questionHash) {
    return res.status(401).json({ error: 'Incorrect answer to secret question' });
  }

  sessionMasterKey = masterPw;
  res.json({ success: true, question: auth.question });
});

// Logout / Lock
app.post('/api/auth/logout', (req, res) => {
  sessionMasterKey = null;
  res.json({ success: true });
});

// ── VAULT CRUD ENDPOINTS ──────────────────────────────────────────────────────

// Get all decrypted entries
app.get('/api/entries', requireAuth, (req, res) => {
  const entries = loadVault();
  const decrypted = entries
    .map(e => {
      const d = decryptEntry(e, sessionMasterKey);
      if (!d) return null;
      return {
        id: e.id,
        category: e.category,
        name: d.name,
        username: d.username || '',
        password: d.password || '',
        pin: d.pin || '',
        url: d.url || '',
        notes: d.notes || '',
        extra: d.extra || '',
        device: d.device || '',
        favourite: !!d.favourite,
        hasSecretGuard: !!d.hasSecretGuard,
        secretQuestion: d.secretQuestion || '',
        secretAnswerHash: d.secretAnswerHash || '',
        created: d.created || new Date().toISOString(),
        updated: d.updated
      };
    })
    .filter(Boolean);

  res.json(decrypted);
});

// Add a new entry
app.post('/api/entries', requireAuth, async (req, res) => {
  const { category, name, username, password, url, notes, extra,
          pin, device, favourite, hasSecretGuard, secretQuestion, secretAnswerHash } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }

  const data = {
    name: (name || '').trim(),
    username: (username || '').trim(),
    password: password || '',
    pin: (pin || '').trim(),
    url: (url || '').trim(),
    notes: (notes || '').trim(),
    extra: (extra || '').trim(),
    device: (device || '').trim(),
    favourite: !!favourite,
    hasSecretGuard: !!hasSecretGuard,
    secretQuestion: (secretQuestion || '').trim(),
    secretAnswerHash: secretAnswerHash || '',
    created: new Date().toISOString()
  };

  const newId = nanoid();
  const entry = {
    id: newId,
    category: category || 'other',
    encrypted: encrypt(JSON.stringify(data), sessionMasterKey)
  };

  const entries = loadVault();
  entries.unshift(entry);
  saveVault(entries);

  // Sync to Supabase in the background
  try {
    await syncUpsert(entry);
  } catch (err) {
    console.error('Supabase sync error:', err.message);
  }

  res.json({
    success: true,
    entry: {
      id: newId,
      category: entry.category,
      ...data
    }
  });
});

// Edit an entry
app.put('/api/entries/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { category, name, username, password, url, notes, extra, created,
          pin, device, favourite, hasSecretGuard, secretQuestion, secretAnswerHash } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }

  const entries = loadVault();
  const index = entries.findIndex(e => e.id === id);
  if (index === -1) {
    return res.status(404).json({ error: 'Entry not found' });
  }

  const updatedData = {
    name: (name || '').trim(),
    username: (username || '').trim(),
    password: password || '',
    pin: (pin || '').trim(),
    url: (url || '').trim(),
    notes: (notes || '').trim(),
    extra: (extra || '').trim(),
    device: (device || '').trim(),
    favourite: !!favourite,
    hasSecretGuard: !!hasSecretGuard,
    secretQuestion: (secretQuestion || '').trim(),
    secretAnswerHash: secretAnswerHash || '',
    created: created || new Date().toISOString(),
    updated: new Date().toISOString()
  };

  const entry = {
    id,
    category: category || 'other',
    encrypted: encrypt(JSON.stringify(updatedData), sessionMasterKey)
  };

  entries[index] = entry;
  saveVault(entries);

  // Sync in the background
  try {
    await syncUpsert(entry);
  } catch (err) {
    console.error('Supabase sync error:', err.message);
  }

  res.json({ success: true });
});

// Delete an entry
app.delete('/api/entries/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const entries = loadVault();
  const index = entries.findIndex(e => e.id === id);
  if (index === -1) {
    return res.status(404).json({ error: 'Entry not found' });
  }

  entries.splice(index, 1);
  saveVault(entries);

  // Sync in the background
  try {
    await syncDelete(id);
  } catch (err) {
    console.error('Supabase sync error:', err.message);
  }

  res.json({ success: true });
});

// Generate password
app.post('/api/generate-password', (req, res) => {
  const opts = req.body;
  try {
    const pw = generatePassword(opts);
    res.json({ password: pw });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Graceful exit
app.post('/api/exit', (req, res) => {
  res.json({ success: true });
  setTimeout(() => {
    process.exit(0);
  }, 500);
});

// Port configuration
const PORT = process.env.PORT || 5005;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Vault backend running on http://localhost:${PORT}`);
});
