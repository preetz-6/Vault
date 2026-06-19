#!/usr/bin/env node
'use strict';

require('dotenv').config();
const fs        = require('fs');
const path      = require('path');
const inquirer  = require('inquirer');
const chalk     = require('chalk');
const Table     = require('cli-table3');
const { nanoid } = require('nanoid');
const { encrypt, decrypt, hashSecret, generatePassword } = require('./crypto');
const { syncUpsert, syncDelete, syncAuthConfig } = require('./sync');

// ── Config paths ──────────────────────────────────────────────────────────────
const CONFIG_DIR  = path.join(require('os').homedir(), '.vault-cli');
const AUTH_FILE   = path.join(CONFIG_DIR, 'auth.json');
const VAULT_FILE  = path.join(CONFIG_DIR, 'vault.json');

if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });

// ── Helpers ───────────────────────────────────────────────────────────────────
const CATS = ['app-password', 'app-lock', 'service', 'info', 'other'];

function loadAuth()  { return fs.existsSync(AUTH_FILE)  ? JSON.parse(fs.readFileSync(AUTH_FILE,  'utf8')) : null; }
function loadVault() { return fs.existsSync(VAULT_FILE) ? JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8')) : []; }
function saveVault(entries) { fs.writeFileSync(VAULT_FILE, JSON.stringify(entries, null, 2), 'utf8'); }

function banner() {
  console.clear();
  console.log(chalk.blue.bold('\n  ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗'));
  console.log(chalk.blue.bold('  ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝'));
  console.log(chalk.blue.bold('  ██║   ██║███████║██║   ██║██║     ██║   '));
  console.log(chalk.blue.bold('  ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   '));
  console.log(chalk.blue.bold('   ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   '));
  console.log(chalk.blue.bold('    ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   '));
  console.log(chalk.gray('  Personal Password Manager\n'));
}

function decryptEntry(entry, masterKey) {
  try {
    return JSON.parse(decrypt(entry.encrypted, masterKey));
  } catch (e) {
    return null;
  }
}

function printTable(entries, masterKey) {
  if (entries.length === 0) {
    console.log(chalk.gray('  No entries found.\n'));
    return;
  }
  const t = new Table({
    head: [
      chalk.cyan('#'),
      chalk.cyan('Name'),
      chalk.cyan('Category'),
      chalk.cyan('Username / ID'),
      chalk.cyan('Notes preview')
    ],
    colWidths: [4, 24, 14, 24, 28],
    style: { head: [], border: ['gray'] }
  });
  entries.forEach((e, i) => {
    const d = decryptEntry(e, masterKey);
    if (!d) return;
    t.push([
      chalk.gray(i + 1),
      chalk.white.bold(d.name),
      chalk.yellow(e.category),
      chalk.gray(d.username || d.identifier || '—'),
      chalk.gray((d.notes || '').slice(0, 25) || '—')
    ]);
  });
  console.log(t.toString());
}

// ── SETUP (first run) ─────────────────────────────────────────────────────────
async function setup() {
  console.log(chalk.yellow.bold('\n  First time setup\n'));

  const { masterPw } = await inquirer.prompt([{
    type: 'password', name: 'masterPw', mask: '*',
    message: 'Set your master password:',
    validate: v => v.length >= 8 ? true : 'At least 8 characters'
  }]);
  const { confirmPw } = await inquirer.prompt([{
    type: 'password', name: 'confirmPw', mask: '*',
    message: 'Confirm master password:'
  }]);
  if (masterPw !== confirmPw) {
    console.log(chalk.red('  Passwords do not match. Restart and try again.')); process.exit(1);
  }

  console.log(chalk.gray('\n  Now set your secret question. This is asked every login.\n'));
  const { question } = await inquirer.prompt([{
    type: 'input', name: 'question',
    message: 'Your bizarre secret question:',
    validate: v => v.trim().length > 5 ? true : 'Make it more interesting'
  }]);
  const { answer } = await inquirer.prompt([{
    type: 'password', name: 'answer', mask: '*',
    message: 'Your answer (case-sensitive):'
  }]);

  const auth = {
    masterHash:   hashSecret(masterPw),
    questionHash: hashSecret(answer.trim()),
    question:     question.trim()
  };
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), 'utf8');

  // Sync security question to Supabase so vault-web can ask it
  process.stdout.write(chalk.gray('  Syncing security question to cloud...'));
  try {
    await syncAuthConfig(auth.question, auth.questionHash);
    console.log(chalk.green(' done'));
  } catch (err) {
    console.log(chalk.yellow(' skipped (no Supabase configured)'));
  }

  console.log(chalk.green('\n  ✓ Vault set up! Run `node vault.js` again to log in.\n'));
  process.exit(0);
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
async function authenticate() {
  const auth = loadAuth();
  if (!auth) await setup();

  const { masterPw } = await inquirer.prompt([{
    type: 'password', name: 'masterPw', mask: '*',
    message: chalk.blue('  Master password:')
  }]);

  if (hashSecret(masterPw) !== auth.masterHash) {
    console.log(chalk.red('\n  ✗ Wrong master password.\n')); process.exit(1);
  }

  console.log(chalk.gray('\n  ' + auth.question));
  const { answer } = await inquirer.prompt([{
    type: 'password', name: 'answer', mask: '*',
    message: chalk.blue('  Your answer:')
  }]);

  if (hashSecret(answer.trim()) !== auth.questionHash) {
    console.log(chalk.red('\n  ✗ Wrong answer.\n')); process.exit(1);
  }

  console.log(chalk.green('\n  ✓ Unlocked\n'));
  return masterPw;
}

// ── MAIN MENU ─────────────────────────────────────────────────────────────────
async function mainMenu(masterKey) {
  const entries = loadVault();

  const { action } = await inquirer.prompt([{
    type: 'list', name: 'action',
    message: chalk.white('What do you want to do?'),
    choices: [
      { name: `📋  View all entries  (${entries.length})`, value: 'view' },
      { name: '🔍  Search entries',                        value: 'search' },
      { name: '➕  Add new entry',                         value: 'add' },
      { name: '✏️   Edit an entry',                         value: 'edit' },
      { name: '🗑️   Delete an entry',                       value: 'delete' },
      { name: '🔑  Generate strong password',               value: 'generate' },
      { name: '─────────────────────',                     value: 'sep', disabled: true },
      { name: '🚪  Lock & exit',                           value: 'exit' }
    ]
  }]);

  switch (action) {
    case 'view':     await viewEntries(masterKey, entries);  break;
    case 'search':   await searchEntries(masterKey, entries); break;
    case 'add':      await addEntry(masterKey);               break;
    case 'edit':     await editEntry(masterKey, entries);     break;
    case 'delete':   await deleteEntry(masterKey, entries);   break;
    case 'generate': await genPassword();                     break;
    case 'exit':
      console.log(chalk.gray('\n  🔒 Vault locked. Bye!\n')); process.exit(0);
  }
}

// ── VIEW ──────────────────────────────────────────────────────────────────────
async function viewEntries(masterKey, entries) {
  console.log('');
  printTable(entries, masterKey);

  const { pick } = await inquirer.prompt([{
    type: 'list', name: 'pick',
    message: 'View full details of an entry?',
    choices: [
      ...entries.map((e, i) => {
        const d = decryptEntry(e, masterKey);
        return { name: `${i+1}. ${d?.name || '?'} [${e.category}]`, value: i };
      }),
      { name: '← Back', value: -1 }
    ]
  }]);

  if (pick === -1) return;
  await showEntry(masterKey, entries[pick]);
}

async function showEntry(masterKey, entry) {
  const d = decryptEntry(entry, masterKey);
  if (!d) { console.log(chalk.red('  Could not decrypt.')); return; }

  console.log(chalk.gray('\n  ─────────────────────────────────────────'));
  console.log(chalk.white.bold(`  ${d.name}`) + chalk.gray(` [${entry.category}]`));
  console.log(chalk.gray('  ─────────────────────────────────────────'));

  const fields = [
    ['Username / ID',  d.username],
    ['Password / PIN', d.password],
    ['URL / App',      d.url],
    ['Notes / Data',   d.notes],
    ['Extra field',    d.extra]
  ];

  fields.forEach(([label, val]) => {
    if (val) console.log(`  ${chalk.cyan(label.padEnd(15))}  ${chalk.white(val)}`);
  });

  console.log(chalk.gray('  ─────────────────────────────────────────\n'));
  await inquirer.prompt([{ type: 'input', name: '_', message: chalk.gray('Press enter to go back') }]);
}

// ── SEARCH ────────────────────────────────────────────────────────────────────
async function searchEntries(masterKey, entries) {
  const { q } = await inquirer.prompt([{
    type: 'input', name: 'q', message: '  Search:'
  }]);
  const term = q.toLowerCase();
  const results = entries.filter(e => {
    const d = decryptEntry(e, masterKey);
    if (!d) return false;
    return [d.name, d.username, d.url, d.notes, d.extra, e.category]
      .some(v => (v||'').toLowerCase().includes(term));
  });

  console.log('');
  if (!results.length) {
    console.log(chalk.gray('  No matches found.\n'));
    return;
  }
  printTable(results, masterKey);

  const { pick } = await inquirer.prompt([{
    type: 'list', name: 'pick',
    message: 'Open an entry?',
    choices: [
      ...results.map((e, i) => {
        const d = decryptEntry(e, masterKey);
        return { name: `${i+1}. ${d?.name} [${e.category}]`, value: i };
      }),
      { name: '← Back', value: -1 }
    ]
  }]);
  if (pick !== -1) await showEntry(masterKey, results[pick]);
}

// ── ADD ───────────────────────────────────────────────────────────────────────
async function addEntry(masterKey) {
  console.log(chalk.yellow('\n  New entry\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list', name: 'category', message: 'Category:',
      choices: ['app-password', 'app-lock', 'service', 'info', 'other']
    },
    { type: 'input',    name: 'name',     message: 'Name (e.g. Gmail, Netflix):',       validate: v => v.trim() ? true : 'Required' },
    { type: 'input',    name: 'username', message: 'Username / email / ID (optional):' },
    { type: 'password', name: 'password', message: 'Password / PIN / secret (optional):', mask: '*' },
    { type: 'input',    name: 'url',      message: 'URL / app name (optional):' },
    { type: 'editor',   name: 'notes',    message: 'Notes / extra data (opens editor, optional) — save & close to continue:' },
    { type: 'input',    name: 'extra',    message: 'Any other field (optional):' }
  ]);

  // Option to auto-generate password if left blank
  let finalPassword = answers.password;
  if (!finalPassword) {
    const { gen } = await inquirer.prompt([{
      type: 'confirm', name: 'gen', message: 'No password entered. Generate one?', default: true
    }]);
    if (gen) {
      finalPassword = await genPassword(true);
    }
  }

  const data = {
    name:     answers.name.trim(),
    username: answers.username.trim(),
    password: finalPassword,
    url:      answers.url.trim(),
    notes:    answers.notes.trim(),
    extra:    answers.extra.trim(),
    created:  new Date().toISOString()
  };

  const entry = {
    id:        nanoid(),
    category:  answers.category,
    encrypted: encrypt(JSON.stringify(data), masterKey)
  };

  const entries = loadVault();
  entries.unshift(entry);
  saveVault(entries);

  console.log(chalk.green('\n  ✓ Entry saved locally.'));
  process.stdout.write(chalk.gray('  Syncing to cloud...'));
  await syncUpsert(entry);
  console.log(chalk.green(' done\n'));
}

// ── EDIT ──────────────────────────────────────────────────────────────────────
async function editEntry(masterKey, entries) {
  if (!entries.length) { console.log(chalk.gray('\n  No entries.\n')); return; }

  const { pick } = await inquirer.prompt([{
    type: 'list', name: 'pick',
    message: 'Which entry to edit?',
    choices: [
      ...entries.map((e, i) => {
        const d = decryptEntry(e, masterKey);
        return { name: `${i+1}. ${d?.name || '?'} [${e.category}]`, value: i };
      }),
      { name: '← Back', value: -1 }
    ]
  }]);
  if (pick === -1) return;

  const entry = entries[pick];
  const old   = decryptEntry(entry, masterKey);

  console.log(chalk.gray('\n  Leave blank to keep current value.\n'));

  const answers = await inquirer.prompt([
    { type: 'list',    name: 'category', message: `Category [${entry.category}]:`, choices: CATS, default: CATS.indexOf(entry.category) },
    { type: 'input',   name: 'name',     message: `Name [${old.name}]:` },
    { type: 'input',   name: 'username', message: `Username [${old.username || '—'}]:` },
    { type: 'password',name: 'password', message: `Password [keep/change]:`, mask: '*' },
    { type: 'input',   name: 'url',      message: `URL [${old.url || '—'}]:` },
    { type: 'input',   name: 'extra',    message: `Extra field [${old.extra || '—'}]:` }
  ]);

  const { editNotes } = await inquirer.prompt([{
    type: 'confirm', name: 'editNotes', message: 'Edit notes?', default: false
  }]);
  let notes = old.notes;
  if (editNotes) {
    const { n } = await inquirer.prompt([{ type: 'editor', name: 'n', message: 'Notes:', default: old.notes }]);
    notes = n.trim();
  }

  const updated = {
    name:     answers.name.trim()     || old.name,
    username: answers.username.trim() || old.username,
    password: answers.password        || old.password,
    url:      answers.url.trim()      || old.url,
    notes,
    extra:    answers.extra.trim()    || old.extra,
    created:  old.created,
    updated:  new Date().toISOString()
  };

  entry.category  = answers.category;
  entry.encrypted = encrypt(JSON.stringify(updated), masterKey);
  entries[pick]   = entry;
  saveVault(entries);

  console.log(chalk.green('\n  ✓ Entry updated locally.'));
  process.stdout.write(chalk.gray('  Syncing to cloud...'));
  await syncUpsert(entry);
  console.log(chalk.green(' done\n'));
}

// ── DELETE ────────────────────────────────────────────────────────────────────
async function deleteEntry(masterKey, entries) {
  if (!entries.length) { console.log(chalk.gray('\n  No entries.\n')); return; }

  const { pick } = await inquirer.prompt([{
    type: 'list', name: 'pick',
    message: 'Which entry to delete?',
    choices: [
      ...entries.map((e, i) => {
        const d = decryptEntry(e, masterKey);
        return { name: `${i+1}. ${d?.name || '?'} [${e.category}]`, value: i };
      }),
      { name: '← Back', value: -1 }
    ]
  }]);
  if (pick === -1) return;

  const d = decryptEntry(entries[pick], masterKey);
  const { confirm } = await inquirer.prompt([{
    type: 'confirm', name: 'confirm',
    message: chalk.red(`Delete "${d?.name}"? This cannot be undone.`),
    default: false
  }]);
  if (!confirm) return;

  const id = entries[pick].id;
  entries.splice(pick, 1);
  saveVault(entries);

  console.log(chalk.green('\n  ✓ Deleted locally.'));
  process.stdout.write(chalk.gray('  Syncing to cloud...'));
  await syncDelete(id);
  console.log(chalk.green(' done\n'));
}

// ── GENERATE PASSWORD ─────────────────────────────────────────────────────────
async function genPassword(returnOnly = false) {
  const opts = await inquirer.prompt([
    { type: 'number',  name: 'length',  message: 'Length:', default: 24, validate: v => v >= 4 ? true : 'Minimum 4' },
    { type: 'confirm', name: 'upper',   message: 'Include uppercase (A-Z)?',  default: true },
    { type: 'confirm', name: 'lower',   message: 'Include lowercase (a-z)?',  default: true },
    { type: 'confirm', name: 'numbers', message: 'Include numbers (0-9)?',    default: true },
    { type: 'confirm', name: 'symbols', message: 'Include symbols (!@#...)?', default: true },
    { type: 'input',   name: 'custom',  message: 'Custom charset (leave blank for above):' }
  ]);

  const pw = generatePassword(opts);
  console.log(chalk.green(`\n  Generated: `) + chalk.white.bold(pw) + '\n');

  if (returnOnly) return pw;

  const { copy } = await inquirer.prompt([{
    type: 'confirm', name: 'copy', message: 'Use this password for a new entry?', default: false
  }]);
  if (copy) {
    // Pre-fill in add flow isn't trivial in CLI — just show it and let user paste
    console.log(chalk.gray('  Copy the password above, then use "Add new entry" to save it.\n'));
  }
  return pw;
}

// ── ENTRY POINT ───────────────────────────────────────────────────────────────
(async () => {
  const runCli = process.argv.includes('--cli');

  if (runCli) {
    banner();
    const masterKey = await authenticate();

    // Loop the menu
    while (true) {
      banner();
      await mainMenu(masterKey);
    }
  } else {
    banner();
    const { exec } = require('child_process');
    const port = process.env.PORT || 5005;
    const url = `http://localhost:${port}`;

    console.log(chalk.blue('  Starting Vault Desktop UI...'));
    
    // Require server.js to start express listener
    require('./server');

    console.log(chalk.green(`  ✓ Server running on ${url}`));
    console.log(chalk.gray('  Opening MS Edge in App Mode...'));

    exec(`start msedge --app=${url}`, (err) => {
      if (err) {
        console.log(chalk.red('  Failed to open MS Edge. Trying default browser...'));
        exec(`start ${url}`);
      }
    });

    console.log(chalk.yellow('\n  Keep this terminal window open. Close the app window to exit.\n'));
  }
})();
