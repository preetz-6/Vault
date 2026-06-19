const { createClient } = require('@supabase/supabase-js');

let supabase = null;

function getClient() {
  if (supabase) return supabase;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY; // service role key — bypasses RLS for writes
  if (!url || !key) return null;
  supabase = createClient(url, key);
  return supabase;
}

async function syncUpsert(entry) {
  const sb = getClient();
  if (!sb) return;
  const { error } = await sb.from('vault_entries').upsert({
    id:         entry.id,
    encrypted:  entry.encrypted,
    category:   entry.category,
    updated_at: new Date().toISOString()
  }, { onConflict: 'id' });
  if (error) console.error('  [sync] upsert error:', error.message);
}

async function syncDelete(id) {
  const sb = getClient();
  if (!sb) return;
  const { error } = await sb.from('vault_entries').delete().eq('id', id);
  if (error) console.error('  [sync] delete error:', error.message);
}

async function syncAll(entries) {
  const sb = getClient();
  if (!sb) return;
  // Full replace: delete all, re-insert
  await sb.from('vault_entries').delete().neq('id', '__none__');
  if (entries.length === 0) return;
  const rows = entries.map(e => ({
    id:         e.id,
    encrypted:  e.encrypted,
    category:   e.category,
    updated_at: new Date().toISOString()
  }));
  const { error } = await sb.from('vault_entries').insert(rows);
  if (error) console.error('  [sync] full sync error:', error.message);
}

/**
 * Sync auth config (security question text + hash) to Supabase.
 * Called after setup or whenever auth changes.
 * We sync the hash so vault-web can verify the answer without
 * storing the raw answer anywhere.
 * @param {string} question  - The security question text
 * @param {string} hash      - The hashed answer (from hashSecret)
 */
async function syncAuthConfig(question, hash) {
  const sb = getClient();
  if (!sb) return;
  const rows = [
    { key: 'security_question',      value: question },
    { key: 'security_question_hash', value: hash }
  ];
  const { error } = await sb.from('vault_config').upsert(rows, { onConflict: 'key' });
  if (error) console.error('  [sync] config sync error:', error.message);
  else console.log('  [sync] auth config synced to Supabase');
}

module.exports = { syncUpsert, syncDelete, syncAll, syncAuthConfig };
