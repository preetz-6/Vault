#!/usr/bin/env node
'use strict';
/**
 * One-time script: syncs your existing security question + hash to Supabase
 * so vault-web can ask it during login.
 *
 * Run from vault-cli directory:
 *   node sync-auth.js
 */
require('dotenv').config();
const fs   = require('fs');
const path = require('path');
const { syncAuthConfig } = require('./sync');

const AUTH_FILE = path.join(require('os').homedir(), '.vault-cli', 'auth.json');

if (!fs.existsSync(AUTH_FILE)) {
  console.error('ERROR: auth.json not found. Run vault setup first.');
  process.exit(1);
}

const auth = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));

if (!auth.question || !auth.questionHash) {
  console.error('ERROR: auth.json missing question or questionHash fields.');
  process.exit(1);
}

console.log('Security question:', auth.question);
console.log('Syncing to Supabase...');

syncAuthConfig(auth.question, auth.questionHash)
  .then(() => {
    console.log('Done! Your vault-web will now ask the security question on login.');
    process.exit(0);
  })
  .catch(err => {
    console.error('Sync failed:', err.message);
    process.exit(1);
  });
