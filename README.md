# Vault

A personal password manager that runs entirely on your machine. It stores your credentials locally (encrypted with AES-256-GCM), and optionally syncs the encrypted blobs to Supabase so you can access them from a companion web app.

It has two modes — a **CLI** for terminal lovers and a **desktop UI** that opens in an Edge app window.

---

## Why I made this

I wanted something simple that I actually control. No cloud-only lock-in, no subscription, no trusting a random company with my passwords. Everything is encrypted locally with your master password before it ever leaves your machine. The Supabase sync is optional and only pushes encrypted data — the server never sees plaintext.

---

## How it works

- You set a **master password** + a **secret question** on first run
- Both are needed to unlock the vault each time
- Every entry is encrypted individually using AES-256-GCM with PBKDF2 key derivation (200k iterations, random salt per entry)
- Data is stored as JSON in `~/.vault-cli/`
- If Supabase creds are configured, encrypted entries sync to the cloud automatically

---

## Features

- **View, search, add, edit, delete** entries — the usual CRUD stuff
- **Categories** — organize entries as `app-password`, `app-lock`, `service`, `info`, or `other`
- **Password generator** — configurable length, character sets (upper, lower, numbers, symbols, or custom charset)
- **Desktop UI** — launches a local Express server and opens it in Edge's app mode, so it feels like a native app
- **CLI mode** — run with `--cli` flag if you prefer the terminal
- **Cloud sync** — encrypted entries sync to Supabase (optional, needs `.env` setup)
- **Secret Guard** — individual entries can have their own secret question for extra protection
- **Favourites** — mark entries you access often

---

## Getting started

### Prerequisites

- Node.js (v16 or later)
- npm
- Microsoft Edge (for the desktop UI mode — falls back to default browser if Edge isn't found)

### Install

```bash
git clone <your-repo-url>
cd vault-cli
npm install
```

### Run

**Desktop UI** (default):
```bash
node vault.js
```
This starts the Express server on `localhost:5005` and opens it in Edge app mode.

**CLI mode**:
```bash
node vault.js --cli
```

On first run, you'll be asked to set up your master password and secret question. After that, you need both to unlock the vault.

---

## Cloud sync (optional)

If you want your encrypted entries synced to Supabase (for use with the companion `vault-web` project), create a `.env` file:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-role-key
```

> **⚠️ The service key is powerful.** It bypasses Row Level Security. Never expose it in browser code. It's only used server-side in this CLI app.

You'll need two tables in your Supabase project:

- `vault_entries` — columns: `id` (text, PK), `encrypted` (text), `category` (text), `updated_at` (timestamptz)
- `vault_config` — columns: `key` (text, PK), `value` (text)

If you already have an auth setup locally and need to sync the security question to Supabase for `vault-web`, run:

```bash
node sync-auth.js
```

---

## Project structure

```
vault-cli/
├── vault.js          # Main entry — CLI mode + desktop launcher
├── server.js         # Express API backend for the desktop UI
├── crypto.js         # AES-256-GCM encryption, PBKDF2, password generator
├── sync.js           # Supabase sync logic (upsert, delete, full sync)
├── sync-auth.js      # One-time script to push auth config to Supabase
├── public/
│   ├── index.html    # Desktop UI markup
│   ├── style.css     # Styles
│   └── app.js        # Frontend logic
├── .env              # Supabase credentials (not committed)
├── .gitignore
└── package.json
```

---

## Security notes

- Encryption: AES-256-GCM with per-entry random salt (32 bytes) and IV (16 bytes)
- Key derivation: PBKDF2 with SHA-256, 200,000 iterations
- Master password hash: SHA-256 (used only for login verification, not for encryption key)
- Your actual master password is used as input to PBKDF2 to derive encryption keys — it's never stored
- Cloud sync only pushes the encrypted blob. Supabase never has your plaintext data.

---

## Tech stack

- **Node.js** — runtime
- **Express** — local API server for the desktop UI
- **Inquirer** — interactive CLI prompts
- **Chalk** — terminal colors
- **cli-table3** — formatted tables in the CLI
- **nanoid** — unique entry IDs
- **@supabase/supabase-js** — cloud sync client
- **dotenv** — environment variable loading

---

## License

This is a personal project. Do whatever you want with it.
