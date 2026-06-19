const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const PBKDF2_ITER = 200000;
const SALT_LEN = 32;
const IV_LEN = 16;
const TAG_LEN = 16;

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITER, 32, 'sha256');
}

function encrypt(plaintext, masterKey) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv   = crypto.randomBytes(IV_LEN);
  const key  = deriveKey(masterKey, salt);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag  = cipher.getAuthTag();
  // layout: salt(32) | iv(16) | tag(16) | ciphertext
  return Buffer.concat([salt, iv, tag, enc]).toString('base64');
}

function decrypt(b64, masterKey) {
  const buf  = Buffer.from(b64, 'base64');
  const salt = buf.slice(0, SALT_LEN);
  const iv   = buf.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const tag  = buf.slice(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const enc  = buf.slice(SALT_LEN + IV_LEN + TAG_LEN);
  const key  = deriveKey(masterKey, salt);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc) + decipher.final('utf8');
}

function hashSecret(value) {
  return crypto.createHash('sha256').update('v::' + value).digest('hex');
}

function generatePassword(opts = {}) {
  const {
    length = 20,
    upper = true,
    lower = true,
    numbers = true,
    symbols = true,
    custom = ''
  } = opts;

  let chars = custom;
  if (!custom) {
    if (lower)   chars += 'abcdefghijklmnopqrstuvwxyz';
    if (upper)   chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) chars += '0123456789';
    if (symbols) chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  }
  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  const bytes = crypto.randomBytes(length * 4);
  let result = '';
  for (let i = 0; i < bytes.length && result.length < length; i++) {
    const idx = bytes[i] % chars.length;
    result += chars[idx];
  }
  return result;
}

module.exports = { encrypt, decrypt, hashSecret, generatePassword };
