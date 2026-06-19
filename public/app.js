'use strict';

// ── CATEGORY CONFIG ──────────────────────────────────────────────────────────
const CATEGORIES = {
  'app-lock': {
    label: 'App Lock',
    fields: [
      { id: 'form-name',     label: 'App Name',            type: 'text',     placeholder: '', required: true },
      { id: 'form-password', label: 'Lock Password / PIN', type: 'password', placeholder: '', hasGenerator: false },
      { id: 'form-device',   label: 'Device',              type: 'text',     placeholder: '' },
    ]
  },
  'login': {
    label: 'Login',
    fields: [
      { id: 'form-name',     label: 'Account Name',     type: 'text',     placeholder: '', required: true },
      { id: 'form-url',      label: 'URL',              type: 'text',     placeholder: '' },
      { id: 'form-username', label: 'Email / Username', type: 'text',     placeholder: '' },
      { id: 'form-password', label: 'Password',         type: 'password', placeholder: '', hasGenerator: false },
      { id: 'form-device',   label: 'Device / Context', type: 'text',     placeholder: '' },
    ]
  },
  'bank': {
    label: 'Bank / Financial',
    fields: [
      { id: 'form-name',   label: 'Account / Card Name', type: 'text',     placeholder: '', required: true },
      { id: 'form-pin',    label: 'PIN / UPI PIN',        type: 'password', placeholder: '', maxlength: 6 },
      { id: 'form-device', label: 'Bank / App',           type: 'text',     placeholder: '' },
    ]
  },
  'wifi-other': {
    label: 'Wi-Fi & Other',
    fields: [
      { id: 'form-name',     label: 'Name',             type: 'text',     placeholder: '', required: true },
      { id: 'form-password', label: 'Password / Key',   type: 'password', placeholder: '', hasGenerator: false },
      { id: 'form-notes',    label: 'Notes',            type: 'textarea', placeholder: '' },
      { id: 'form-device',   label: 'Device / Context', type: 'text',     placeholder: '' },
    ]
  }
};

// ── STATE ────────────────────────────────────────────────────────────────────
const state = {
  setupRequired: false,
  unlocked: false,
  question: '',
  activeTab: 'passwords',
  entries: [],
  currentCategory: 'all',
  searchQuery: '',
  selectedEntry: null,
  tempPassword: '',
  formCategory: 'app-lock'
};

// ── DOM REFS ─────────────────────────────────────────────────────────────────
const setupScreen           = document.getElementById('setup-screen');
const loginScreen           = document.getElementById('login-screen');
const appLayout             = document.getElementById('app-layout');
const tabViews              = { passwords: document.getElementById('view-passwords') };
const navItems              = document.querySelectorAll('.nav-item');
const setupForm             = document.getElementById('setup-form');
const loginForm             = document.getElementById('login-form');
const entryForm             = document.getElementById('entry-form');
const loginStep1            = document.getElementById('login-step-1');
const loginStep2            = document.getElementById('login-step-2');
const btnLoginNext          = document.getElementById('btn-login-next');
const btnLoginBack          = document.getElementById('btn-login-back');
const securityQuestionLabel = document.getElementById('security-question-label');
const setupError            = document.getElementById('setup-error');
const loginError            = document.getElementById('login-error');
const entriesGrid           = document.getElementById('entries-grid');
const emptyState            = document.getElementById('empty-state');
const searchInput           = document.getElementById('search-input');
const categoryButtons       = document.querySelectorAll('.cat-pill');
const statusDot             = document.querySelector('.status-dot');
const btnAddEntry           = document.getElementById('btn-add-entry');
const btnEmptyAdd           = document.getElementById('btn-empty-add');
const btnLock               = document.getElementById('btn-lock');
const modalViewEntry        = document.getElementById('modal-view-entry');
const modalEditEntry        = document.getElementById('modal-edit-entry');
const viewTitle             = document.getElementById('view-title');
const viewCategoryBadge     = document.getElementById('view-category-badge');
const viewModalBody         = document.getElementById('view-modal-body');
const btnEditEntryFromView  = document.getElementById('btn-edit-entry-from-view');
const btnDeleteEntryFromView= document.getElementById('btn-delete-entry-from-view');
const formModalTitle        = document.getElementById('form-modal-title');
const entryIdField          = document.getElementById('entry-id-field');
const formDynamicFields     = document.getElementById('form-dynamic-fields');
const formSecretGuard       = document.getElementById('form-secret-guard');
const formSecretGuardFields = document.getElementById('form-secret-guard-fields');
const genOutput             = document.getElementById('gen-output');
const btnGenCopy            = document.getElementById('btn-gen-copy');
const btnGenRefresh         = document.getElementById('btn-gen-refresh');
const genLength             = document.getElementById('gen-length');
const lenVal                = document.getElementById('len-val');
const genUpper              = document.getElementById('gen-upper');
const genLower              = document.getElementById('gen-lower');
const genNumbers            = document.getElementById('gen-numbers');
const genSymbols            = document.getElementById('gen-symbols');
const genCustom             = document.getElementById('gen-custom');
const strengthText          = document.getElementById('strength-text');
const strengthFill          = document.getElementById('strength-fill');
const toast                 = document.getElementById('toast');

// ── TOAST ─────────────────────────────────────────────────────────────────────
function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('show'), 2800);
}

// ── CLIPBOARD + AUTO-CLEAR (30s) ──────────────────────────────────────────────
let clipboardClearTimer = null;
function copyToClipboard(text, fieldName = 'Text') {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    showToast(`${fieldName} copied — clears in 30s`);
    clipboardClearTimer = setTimeout(() => {
      navigator.clipboard.writeText('').catch(() => {});
      showToast('Clipboard cleared');
    }, 30000);
  }).catch(err => console.error('Copy failed:', err));
}

// ── SECRET ANSWER HASHING (SHA-256 via WebCrypto) ────────────────────────────
async function hashAnswer(answer) {
  const buf = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode('sq::' + answer.trim().toLowerCase()));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── STRENGTH METER ─────────────────────────────────────────────────────────────
function evaluateStrength(password) {
  if (!password) return { label: 'Weak', class: 'strength-weak', fillClass: 'strength-fill-weak', percent: 10 };
  let s = 0;
  if (password.length >= 8)  s++;
  if (password.length >= 16) s++;
  if (/[A-Z]/.test(password)) s++;
  if (/[a-z]/.test(password)) s++;
  if (/[0-9]/.test(password)) s++;
  if (/[^A-Za-z0-9]/.test(password)) s++;
  if (s <= 2) return { label: 'Weak',     class: 'strength-weak',   fillClass: 'strength-fill-weak',   percent: 30 };
  if (s <= 4) return { label: 'Moderate', class: 'strength-medium', fillClass: 'strength-fill-medium', percent: 60 };
  return               { label: 'Strong',   class: 'strength-good',   fillClass: 'strength-fill-good',   percent: 100 };
}

// ── API ────────────────────────────────────────────────────────────────────────
async function apiRequest(url, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── SCREENS ────────────────────────────────────────────────────────────────────
function showScreen(screen) {
  [setupScreen, loginScreen, appLayout].forEach(el => el.classList.add('hidden'));
  if (screen === 'setup') setupScreen.classList.remove('hidden');
  else if (screen === 'login') loginScreen.classList.remove('hidden');
  else if (screen === 'app') appLayout.classList.remove('hidden');
}

async function checkAuthStatus() {
  try {
    const data = await apiRequest('/api/auth/status');
    state.setupRequired = data.setupRequired;
    state.unlocked = data.unlocked;
    state.question = data.question;
    if (state.setupRequired) {
      showScreen('setup');
    } else if (!state.unlocked) {
      showScreen('login');
      loginStep1.classList.remove('hidden');
      loginStep2.classList.add('hidden');
      state.tempPassword = '';
    } else {
      showScreen('app');
      loadVaultEntries();
    }
  } catch {
    showToast('Failed to connect to backend server.');
  }
}

// ── AUTH ───────────────────────────────────────────────────────────────────────
setupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  setupError.classList.add('hidden');
  const masterPw  = document.getElementById('setup-password').value;
  const confirmPw = document.getElementById('setup-confirm').value;
  const question  = document.getElementById('setup-question').value;
  const answer    = document.getElementById('setup-answer').value;
  if (masterPw !== confirmPw) {
    setupError.textContent = 'Passwords do not match.';
    setupError.classList.remove('hidden');
    return;
  }
  try {
    await apiRequest('/api/auth/setup', 'POST', { masterPw, question, answer });
    showToast('Vault initialized!');
    checkAuthStatus();
  } catch (err) {
    setupError.textContent = err.message;
    setupError.classList.remove('hidden');
  }
});

btnLoginNext.addEventListener('click', async () => {
  loginError.classList.add('hidden');
  const masterPw = document.getElementById('login-password').value;
  if (!masterPw) { loginError.textContent = 'Enter your master password.'; loginError.classList.remove('hidden'); return; }
  try {
    const data = await apiRequest('/api/auth/verify-password', 'POST', { masterPw });
    state.tempPassword = masterPw;
    securityQuestionLabel.textContent = `Security Question: ${data.question}`;
    loginStep1.classList.add('hidden');
    loginStep2.classList.remove('hidden');
    document.getElementById('login-answer').value = '';
    document.getElementById('login-answer').focus();
  } catch (err) {
    loginError.textContent = err.message;
    loginError.classList.remove('hidden');
  }
});

btnLoginBack.addEventListener('click', () => {
  state.tempPassword = '';
  loginStep2.classList.add('hidden');
  loginStep1.classList.remove('hidden');
  loginError.classList.add('hidden');
  document.getElementById('login-password').focus();
});

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.classList.add('hidden');
  const answer = document.getElementById('login-answer').value;
  if (!state.tempPassword) {
    loginError.textContent = 'Session expired. Re-enter password.';
    loginError.classList.remove('hidden');
    loginStep2.classList.add('hidden');
    loginStep1.classList.remove('hidden');
    return;
  }
  try {
    await apiRequest('/api/auth/login', 'POST', { masterPw: state.tempPassword, answer });
    showToast('Vault Unlocked');
    state.tempPassword = '';
    loginForm.reset();
    checkAuthStatus();
  } catch (err) {
    loginError.textContent = err.message;
    loginError.classList.remove('hidden');
  }
});

btnLock.addEventListener('click', async () => {
  try {
    await apiRequest('/api/auth/logout', 'POST');
    state.unlocked = false;
    state.entries = [];
    showScreen('login');
    apiRequest('/api/exit', 'POST').catch(() => {});
    showToast('Vault closed. Server shutting down...');
    setTimeout(() => window.close(), 1000);
  } catch {
    showScreen('login');
  }
});

// ── VAULT LOADING ──────────────────────────────────────────────────────────────
async function loadVaultEntries() {
  setSyncStatus(true);
  try {
    state.entries = await apiRequest('/api/entries');
    renderEntries();
    setSyncStatus(false);
  } catch {
    showToast('Error loading passwords.');
    setSyncStatus(false);
  }
}

function setSyncStatus(isSyncing) {
  statusDot.className = isSyncing ? 'status-dot syncing' : 'status-dot';
  statusDot.title = isSyncing ? 'Syncing...' : 'Synced';
}

// ── RENDER ENTRIES ─────────────────────────────────────────────────────────────
function renderEntries() {
  entriesGrid.innerHTML = '';
  const q = state.searchQuery.toLowerCase();

  const filtered = state.entries
    .filter(e => {
      const matchCat = state.currentCategory === 'all' || e.category === state.currentCategory;
      const matchSearch = !q || [e.name, e.username, e.url, e.notes, e.device, e.category]
        .some(v => (v || '').toLowerCase().includes(q));
      return matchCat && matchSearch;
    })
    // Favourites first
    .sort((a, b) => (b.favourite ? 1 : 0) - (a.favourite ? 1 : 0));

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
    entriesGrid.classList.add('hidden');
    return;
  }
  emptyState.classList.add('hidden');
  entriesGrid.classList.remove('hidden');

  filtered.forEach(e => {
    const cat = CATEGORIES[e.category] || { icon: '📦', label: e.category };
    const card = document.createElement('div');
    card.className = 'entry-card';

    // Subtitle under name
    let subtitle = '';
    if (e.category === 'bank') {
      subtitle = `<span class="entry-field-value pin-masked">PIN ●●●●</span>`;
    } else if (e.username) {
      subtitle = `<span class="entry-field-value">${escapeHtml(e.username)}</span>`;
    } else if (e.url) {
      subtitle = `<span class="entry-field-value">${escapeHtml(e.url)}</span>`;
    } else if (e.device) {
      subtitle = `<span class="entry-field-value">${escapeHtml(e.device)}</span>`;
    }

    // What to quick-copy
    const secretVal   = e.category === 'bank' ? e.pin : e.password;
    const secretLabel = e.category === 'bank' ? 'PIN' : 'Password';

    const guardBadge = e.hasSecretGuard
      ? `<span class="guard-badge" title="Protected by secret question">&#x1F512;</span>` : '';

    card.innerHTML = `
      <div class="entry-card-header">
        <div class="entry-name-group">
          <span class="entry-name">${escapeHtml(e.name)}</span>
          ${subtitle}
        </div>
        <div class="entry-card-meta">
          ${guardBadge}
          <span class="badge badge-${e.category}">${cat.label}</span>
        </div>
      </div>
      <div class="entry-card-actions">
        ${e.category === 'login' && e.username ? `
          <button class="btn btn-icon btn-copy-username" title="Copy Username">
            <svg viewBox="0 0 24 24" class="icon-s"><path fill="currentColor" d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
          </button>` : ''}
        ${secretVal ? `
          <button class="btn btn-icon btn-copy-secret" title="Copy ${secretLabel}">
            <svg viewBox="0 0 24 24" class="icon-s"><path fill="currentColor" d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
          </button>` : ''}
      </div>`;

    card.addEventListener('click', ev => {
      if (ev.target.closest('.btn-icon')) return;
      openViewModal(e);
    });

    const copyUser = card.querySelector('.btn-copy-username');
    if (copyUser) copyUser.addEventListener('click', ev => {
      ev.stopPropagation(); copyToClipboard(e.username, 'Username');
    });

    const copySecret = card.querySelector('.btn-copy-secret');
    if (copySecret) copySecret.addEventListener('click', async ev => {
      ev.stopPropagation();
      if (e.hasSecretGuard) { showToast('Entry is guarded. Open it to reveal.'); return; }
      copyToClipboard(secretVal, secretLabel);
    });

    entriesGrid.appendChild(card);
  });
}



function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// ── SEARCH & FILTER ────────────────────────────────────────────────────────────
searchInput.addEventListener('input', e => { state.searchQuery = e.target.value; renderEntries(); });

categoryButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    categoryButtons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.currentCategory = btn.getAttribute('data-cat');
    renderEntries();
  });
});

// ── SVG HELPERS ────────────────────────────────────────────────────────────────
const eyeIcon    = () => `<svg viewBox="0 0 24 24" class="icon-s"><path fill="currentColor" d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>`;
const eyeOffIcon = () => `<svg viewBox="0 0 24 24" class="icon-s"><path fill="currentColor" d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/></svg>`;
const copyIcon   = () => `<svg viewBox="0 0 24 24" class="icon-s"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;

// ── VIEW MODAL ─────────────────────────────────────────────────────────────────
function openViewModal(entry) {
  state.selectedEntry = entry;
  viewTitle.textContent = entry.name;
  const cat = CATEGORIES[entry.category] || { label: entry.category, icon: '📦' };
  viewCategoryBadge.textContent = cat.label;
  viewCategoryBadge.className = `badge badge-${entry.category}`;

  viewModalBody.innerHTML = '';

  // Helper: plain text row with copy
  const addRow = (label, value) => {
    if (!value) return;
    const row = document.createElement('div');
    row.className = 'detail-row';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-icon'; copyBtn.innerHTML = copyIcon();
    copyBtn.addEventListener('click', () => copyToClipboard(value, label));
    row.innerHTML = `<span class="detail-label">${escapeHtml(label)}</span>`;
    const wrapper = document.createElement('div');
    wrapper.className = 'detail-value-wrapper';
    const span = document.createElement('span');
    span.className = 'detail-value'; span.textContent = value;
    wrapper.appendChild(span); wrapper.appendChild(copyBtn);
    row.appendChild(wrapper); viewModalBody.appendChild(row);
  };

  // Helper: password row (masked, with show/hide + copy)
  const addPasswordRow = (label, value) => {
    if (!value) return;
    const row = document.createElement('div');
    row.className = 'detail-row';
    row.innerHTML = `<span class="detail-label">${escapeHtml(label)}</span>`;
    const wrapper = document.createElement('div');
    wrapper.className = 'detail-value-wrapper';
    const inp = document.createElement('input');
    inp.type = 'password'; inp.className = 'detail-value-input'; inp.value = value; inp.readOnly = true;
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'btn btn-icon'; toggleBtn.innerHTML = eyeIcon();
    toggleBtn.addEventListener('click', () => {
      inp.type = inp.type === 'password' ? 'text' : 'password';
      toggleBtn.innerHTML = inp.type === 'password' ? eyeIcon() : eyeOffIcon();
    });
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-icon'; copyBtn.innerHTML = copyIcon();
    copyBtn.addEventListener('click', () => copyToClipboard(value, label));
    wrapper.appendChild(inp); wrapper.appendChild(toggleBtn); wrapper.appendChild(copyBtn);
    row.appendChild(wrapper); viewModalBody.appendChild(row);
  };

  // Helper: guarded secret row
  const addGuardedRow = (label, value, question, answerHash) => {
    const row = document.createElement('div');
    row.className = 'detail-row';
    row.innerHTML = `<span class="detail-label">${escapeHtml(label)}</span>`;

    const container = document.createElement('div');
    container.className = 'guard-container';

    // Banner
    const banner = document.createElement('div');
    banner.className = 'guard-banner';
    banner.innerHTML = `<span>Protected by secret question</span><button type="button" class="btn btn-secondary btn-sm">Reveal</button>`;

    // Input section
    const inputSection = document.createElement('div');
    inputSection.className = 'guard-input-section hidden';
    inputSection.innerHTML = `
      <p class="guard-question">${escapeHtml(question)}</p>
      <div class="password-input-wrapper">
        <input type="password" class="sg-answer" placeholder="Your answer...">
      </div>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button type="button" class="btn btn-primary btn-sm sg-confirm">Confirm</button>
        <button type="button" class="btn btn-secondary btn-sm sg-cancel">Cancel</button>
      </div>
      <p class="error-msg hidden sg-error" style="margin-top:6px">Incorrect answer. Try again.</p>`;

    // Revealed section
    const revealSection = document.createElement('div');
    revealSection.className = 'hidden';
    const revealWrapper = document.createElement('div');
    revealWrapper.className = 'detail-value-wrapper';
    const inp = document.createElement('input');
    inp.type = 'password'; inp.className = 'detail-value-input'; inp.value = value; inp.readOnly = true;
    const tBtn = document.createElement('button');
    tBtn.className = 'btn btn-icon'; tBtn.innerHTML = eyeIcon();
    tBtn.addEventListener('click', () => { inp.type = inp.type === 'password' ? 'text' : 'password'; tBtn.innerHTML = inp.type === 'password' ? eyeIcon() : eyeOffIcon(); });
    const cBtn = document.createElement('button');
    cBtn.className = 'btn btn-icon'; cBtn.innerHTML = copyIcon();
    cBtn.addEventListener('click', () => copyToClipboard(value, label));
    revealWrapper.appendChild(inp); revealWrapper.appendChild(tBtn); revealWrapper.appendChild(cBtn);
    revealSection.appendChild(revealWrapper);

    container.appendChild(banner);
    container.appendChild(inputSection);
    container.appendChild(revealSection);
    row.appendChild(container);
    viewModalBody.appendChild(row);

    // Events
    banner.querySelector('button').addEventListener('click', () => {
      banner.classList.add('hidden');
      inputSection.classList.remove('hidden');
      inputSection.querySelector('.sg-answer').focus();
    });
    inputSection.querySelector('.sg-cancel').addEventListener('click', () => {
      inputSection.classList.add('hidden');
      banner.classList.remove('hidden');
      inputSection.querySelector('.sg-answer').value = '';
    });
    inputSection.querySelector('.sg-confirm').addEventListener('click', async () => {
      const ans = inputSection.querySelector('.sg-answer').value;
      const errEl = inputSection.querySelector('.sg-error');
      if (!ans) return;
      const hash = await hashAnswer(ans);
      if (hash === answerHash) {
        inputSection.classList.add('hidden');
        revealSection.classList.remove('hidden');
        errEl.classList.add('hidden');
      } else {
        errEl.classList.remove('hidden');
        inputSection.querySelector('.sg-answer').value = '';
        inputSection.querySelector('.sg-answer').focus();
      }
    });
    inputSection.querySelector('.sg-answer').addEventListener('keydown', ev => {
      if (ev.key === 'Enter') inputSection.querySelector('.sg-confirm').click();
    });
  };

  // Shorthand to use guarded or plain based on entry.hasSecretGuard
  const addSecret = (label, value) => {
    if (!value) return;
    if (entry.hasSecretGuard) {
      addGuardedRow(label, value, entry.secretQuestion, entry.secretAnswerHash);
    } else {
      addPasswordRow(label, value);
    }
  };

  // Per-category field layout
  if (entry.category === 'app-lock') {
    addRow('App Name', entry.name);
    addRow('Device', entry.device);
    addSecret('Lock Password / PIN', entry.password);
  } else if (entry.category === 'login') {
    addRow('Account Name', entry.name);
    addRow('URL', entry.url);
    addRow('Email / Username', entry.username);
    addSecret('Password', entry.password);
    addRow('Device / Context', entry.device);
  } else if (entry.category === 'bank') {
    addRow('Account / Card Name', entry.name);
    addSecret('PIN / UPI PIN', entry.pin);
    addRow('Bank / App', entry.device);
  } else if (entry.category === 'wifi-other') {
    addRow('Name', entry.name);
    addSecret('Password / Key', entry.password);
    addRow('Notes', entry.notes);
    addRow('Device / Context', entry.device);
  }

  // Favourite indicator — removed

  // Timestamps
  const tsRow = document.createElement('div');
  tsRow.className = 'timestamps';
  tsRow.textContent = `Created: ${new Date(entry.created).toLocaleString()} | Updated: ${entry.updated ? new Date(entry.updated).toLocaleString() : 'Never'}`;
  viewModalBody.appendChild(tsRow);

  modalViewEntry.classList.remove('hidden');
}

// ── ADD/EDIT FORM ──────────────────────────────────────────────────────────────
function renderCategorySelector(selected) {
  const grid = document.getElementById('cat-selector-grid');
  grid.innerHTML = '';
  Object.entries(CATEGORIES).forEach(([key, cat]) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cat-select-btn' + (key === selected ? ' active' : '');
    btn.dataset.cat = key;
    btn.innerHTML = `<span>${cat.label}</span>`;
    btn.addEventListener('click', () => {
      document.querySelectorAll('.cat-select-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.formCategory = key;
      renderFormFields(key);
    });
    grid.appendChild(btn);
  });
}

function renderFormFields(category) {
  const config = CATEGORIES[category];
  if (!config) return;
  formDynamicFields.innerHTML = '';

  config.fields.forEach(field => {
    const group = document.createElement('div');
    group.className = 'form-group';
    const label = document.createElement('label');
    label.setAttribute('for', field.id);
    label.textContent = field.label + (field.required ? ' *' : '');
    group.appendChild(label);

    if (field.type === 'textarea') {
      const el = document.createElement('textarea');
      el.id = field.id; el.placeholder = field.placeholder || '';
      group.appendChild(el);
    } else if (field.hasGenerator) {
      const wrap = document.createElement('div');
      wrap.className = 'password-input-wrapper';
      const el = document.createElement('input');
      el.type = field.type; el.id = field.id;
      el.placeholder = field.placeholder || '';
      if (field.required) el.required = true;
      const genBtn = document.createElement('button');
      genBtn.type = 'button';
      genBtn.className = 'btn btn-secondary btn-small-action';
      genBtn.textContent = 'Generate';
      genBtn.addEventListener('click', async () => {
        const data = await apiRequest('/api/generate-password', 'POST', { length: 20 });
        el.value = data.password;
        el.type = 'text';
        setTimeout(() => { el.type = 'password'; }, 2000);
        showToast('Password generated!');
      });
      wrap.appendChild(el); wrap.appendChild(genBtn);
      group.appendChild(wrap);
    } else {
      const el = document.createElement('input');
      el.type = field.type; el.id = field.id;
      el.placeholder = field.placeholder || '';
      if (field.required) el.required = true;
      if (field.maxlength) el.maxLength = field.maxlength;
      group.appendChild(el);
    }
    formDynamicFields.appendChild(group);
  });
}

const getVal = id => { const el = document.getElementById(id); return el ? el.value : ''; };
const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };

function resetForm() {
  formSecretGuard.checked = false;
  formSecretGuardFields.classList.add('hidden');
  setVal('form-sq-question', '');
  setVal('form-sq-answer', '');
}

function openAddModal() {
  formModalTitle.textContent = 'New Entry';
  entryIdField.value = '';
  state.formCategory = 'app-lock';
  renderCategorySelector('app-lock');
  renderFormFields('app-lock');
  resetForm();
  modalEditEntry.classList.remove('hidden');
}

function openEditModal(entry) {
  formModalTitle.textContent = 'Edit Entry';
  entryIdField.value = entry.id;
  state.formCategory = entry.category || 'app-lock';
  renderCategorySelector(state.formCategory);
  renderFormFields(state.formCategory);
  // Populate existing values
  setVal('form-name', entry.name);
  setVal('form-username', entry.username);
  setVal('form-password', entry.password);
  setVal('form-pin', entry.pin);
  setVal('form-url', entry.url);
  setVal('form-notes', entry.notes);
  setVal('form-device', entry.device);
  formSecretGuard.checked = !!entry.hasSecretGuard;
  if (entry.hasSecretGuard) {
    formSecretGuardFields.classList.remove('hidden');
    setVal('form-sq-question', entry.secretQuestion);
    // Don't pre-fill answer — it's hashed
  } else {
    formSecretGuardFields.classList.add('hidden');
  }
  modalViewEntry.classList.add('hidden');
  modalEditEntry.classList.remove('hidden');
}

btnAddEntry.addEventListener('click', openAddModal);
btnEmptyAdd.addEventListener('click', openAddModal);
btnEditEntryFromView.addEventListener('click', () => { if (state.selectedEntry) openEditModal(state.selectedEntry); });

btnDeleteEntryFromView.addEventListener('click', async () => {
  if (!state.selectedEntry) return;
  const name = state.selectedEntry.name;
  if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
  setSyncStatus(true);
  try {
    await apiRequest(`/api/entries/${state.selectedEntry.id}`, 'DELETE');
    showToast(`Deleted "${name}"`);
    modalViewEntry.classList.add('hidden');
    loadVaultEntries();
  } catch {
    showToast('Error deleting entry.');
    setSyncStatus(false);
  }
});

formSecretGuard.addEventListener('change', () => {
  formSecretGuardFields.classList.toggle('hidden', !formSecretGuard.checked);
});

entryForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = entryIdField.value;
  const hasSecretGuard = formSecretGuard.checked;

  let secretAnswerHash = '';
  if (hasSecretGuard) {
    const rawAnswer = getVal('form-sq-answer').trim();
    if (!rawAnswer && !id) {
      showToast('Please provide a secret answer.');
      return;
    }
    if (rawAnswer) {
      secretAnswerHash = await hashAnswer(rawAnswer);
    } else {
      // editing — keep old hash
      secretAnswerHash = state.selectedEntry?.secretAnswerHash || '';
    }
  }

  const entryData = {
    category:        state.formCategory,
    name:            getVal('form-name'),
    username:        getVal('form-username'),
    password:        getVal('form-password'),
    pin:             getVal('form-pin'),
    url:             getVal('form-url'),
    notes:           getVal('form-notes'),
    device:          getVal('form-device'),
    favourite:       false,
    hasSecretGuard,
    secretQuestion:  hasSecretGuard ? getVal('form-sq-question').trim() : '',
    secretAnswerHash
  };

  setSyncStatus(true);
  try {
    if (id) {
      await apiRequest(`/api/entries/${id}`, 'PUT', { id, ...entryData, created: state.selectedEntry?.created });
      showToast('Entry updated.');
    } else {
      await apiRequest('/api/entries', 'POST', entryData);
      showToast('Entry added.');
    }
    modalEditEntry.classList.add('hidden');
    loadVaultEntries();
  } catch (err) {
    showToast(err.message);
    setSyncStatus(false);
  }
});

// Close modals
document.querySelectorAll('.modal-close-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    modalViewEntry.classList.add('hidden');
    modalEditEntry.classList.add('hidden');
  });
});
window.addEventListener('click', e => {
  if (e.target === modalViewEntry) modalViewEntry.classList.add('hidden');
  if (e.target === modalEditEntry) modalEditEntry.classList.add('hidden');
});

// ── PASSWORD GENERATOR ─────────────────────────────────────────────────────────
async function triggerPasswordGeneration() {
  try {
    const data = await apiRequest('/api/generate-password', 'POST', {
      length:  parseInt(genLength.value),
      upper:   genUpper.checked,
      lower:   genLower.checked,
      numbers: genNumbers.checked,
      symbols: genSymbols.checked,
      custom:  genCustom.value.trim()
    });
    genOutput.textContent = data.password;
    const s = evaluateStrength(data.password);
    strengthText.textContent = s.label;
    strengthText.className = `strength-text ${s.class}`;
    strengthFill.style.width = `${s.percent}%`;
    strengthFill.className = `strength-fill ${s.fillClass}`;
  } catch {
    genOutput.textContent = 'Error generating';
  }
}

genLength.addEventListener('input', e => { lenVal.textContent = e.target.value; triggerPasswordGeneration(); });
[genUpper, genLower, genNumbers, genSymbols].forEach(cb => cb.addEventListener('change', triggerPasswordGeneration));
genCustom.addEventListener('input', triggerPasswordGeneration);
btnGenRefresh.addEventListener('click', triggerPasswordGeneration);
btnGenCopy.addEventListener('click', () => {
  const pw = genOutput.textContent;
  if (pw && pw !== 'Generating...') copyToClipboard(pw, 'Password');
});

// ── NAVIGATION ─────────────────────────────────────────────────────────────────
function switchTab(tabName) {
  state.activeTab = tabName;
  navItems.forEach(item => item.classList.toggle('active', item.getAttribute('data-tab') === tabName));
  Object.entries(tabViews).forEach(([name, view]) => view.classList.toggle('hidden', name !== tabName));
}

navItems.forEach(item => {
  item.addEventListener('click', e => { e.preventDefault(); switchTab(item.getAttribute('data-tab')); });
});

// ── INIT ───────────────────────────────────────────────────────────────────────
checkAuthStatus();
