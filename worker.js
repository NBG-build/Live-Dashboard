/**
 * Live Dashboard — Cloudflare Worker (secure proxy for Lark Base)
 * ---------------------------------------------------------------
 * Deploy on Cloudflare Workers (free). Set these environment variables
 * (Worker → Settings → Variables). Secrets should be added as "Encrypted".
 *
 *   LARK_APP_ID          Lark custom-app App ID
 *   LARK_APP_SECRET      Lark custom-app App Secret        (encrypted)
 *   LARK_BASE_TOKEN      Bitable app_token of the Base holding all tables
 *   REGISTRY_TABLE_ID    _Registry table id
 *   USERS_TABLE_ID       _Users table id
 *   GOALS_TABLE_ID       _Goals table id
 *   REPORTS_TABLE_ID     _Reports table id
 *   LARK_GROUP_CHAT_ID   Lark chat_id of the department group (for one-click report send)
 *   ALLOWED_DOMAIN       nb-agency.live
 *   ADMIN_EMAILS         comma list, e.g. belle.guo@nb-agency.live
 *   JWT_SECRET           long random string                (encrypted)
 *   ALLOW_ORIGIN         https://<your-github-pages-url>
 *
 * Lark region: international → https://open.larksuite.com (set below).
 */

const LARK = 'https://open.larksuite.com';
const JWT_TTL = 12 * 3600; // seconds

/* ---------------- tiny helpers ---------------- */
const te = new TextEncoder();
const json = (obj, status = 200, origin = '*') =>
  new Response(JSON.stringify(obj), { status, headers: cors(origin, { 'Content-Type': 'application/json' }) });
function cors(origin, extra = {}) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    'Access-Control-Max-Age': '86400',
    ...extra,
  };
}
function b64url(bufOrStr) {
  let bin;
  if (typeof bufOrStr === 'string') bin = unescape(encodeURIComponent(bufOrStr));
  else bin = String.fromCharCode(...new Uint8Array(bufOrStr));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  return decodeURIComponent(escape(atob(s)));
}
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', key, te.encode(data));
}
async function signJWT(payload, secret) {
  const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64url(JSON.stringify(payload));
  const sig = b64url(await hmac(secret, `${h}.${p}`));
  return `${h}.${p}.${sig}`;
}
async function verifyJWT(token, secret) {
  if (!token) return null;
  const [h, p, s] = token.split('.');
  if (!s) return null;
  const expected = b64url(await hmac(secret, `${h}.${p}`));
  if (expected !== s) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(p)); } catch (e) { return null; }
  if (payload.exp && Date.now() / 1000 > payload.exp) return null;
  return payload;
}

/* ---------------- Lark token cache ---------------- */
let _tenant = { v: null, exp: 0 };
async function tenantToken(env) {
  if (_tenant.v && Date.now() < _tenant.exp) return _tenant.v;
  const r = await fetch(`${LARK}/open-apis/auth/v3/tenant_access_token/internal`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_id: env.LARK_APP_ID, app_secret: env.LARK_APP_SECRET }),
  });
  const j = await r.json();
  if (j.code !== 0) throw new Error('tenant_access_token: ' + JSON.stringify(j));
  _tenant = { v: j.tenant_access_token, exp: Date.now() + (j.expire - 120) * 1000 };
  return _tenant.v;
}
async function appToken(env) {
  const r = await fetch(`${LARK}/open-apis/auth/v3/app_access_token/internal`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_id: env.LARK_APP_ID, app_secret: env.LARK_APP_SECRET }),
  });
  const j = await r.json();
  if (j.code !== 0) throw new Error('app_access_token: ' + JSON.stringify(j));
  return j.app_access_token;
}

/* ---------------- Lark login (OIDC) ---------------- */
async function larkLogin(env, code) {
  const aat = await appToken(env);
  const r = await fetch(`${LARK}/open-apis/authen/v1/oidc/access_token`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + aat },
    body: JSON.stringify({ grant_type: 'authorization_code', code }),
  });
  const j = await r.json();
  if (j.code !== 0) throw new Error('login exchange: ' + JSON.stringify(j));
  const uat = j.data.access_token;
  const ur = await fetch(`${LARK}/open-apis/authen/v1/user_info`, { headers: { Authorization: 'Bearer ' + uat } });
  const uj = await ur.json();
  if (uj.code !== 0) throw new Error('user_info: ' + JSON.stringify(uj));
  return uj.data; // { name, email, enterprise_email, open_id, ... }
}

/* ---------------- Bitable helpers ---------------- */
async function bt(env, path, opts = {}) {
  const tok = await tenantToken(env);
  const r = await fetch(`${LARK}/open-apis/bitable/v1/apps/${env.LARK_BASE_TOKEN}${path}`, {
    ...opts, headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const j = await r.json();
  if (j.code !== 0) throw new Error(`bitable ${path}: ` + JSON.stringify(j));
  return j.data;
}
async function listAll(env, tableId, filter) {
  let items = [], pageToken = '';
  do {
    const qs = `page_size=500${pageToken ? '&page_token=' + encodeURIComponent(pageToken) : ''}`;
    const d = await bt(env, `/tables/${tableId}/records/search?${qs}`, {
      method: 'POST', body: JSON.stringify(filter ? { filter } : {}),
    });
    items = items.concat(d.items || []);
    pageToken = d.has_more ? d.page_token : '';
  } while (pageToken);
  return items;
}
async function findByField(env, tableId, field, value) {
  const d = await bt(env, `/tables/${tableId}/records/search?page_size=1`, {
    method: 'POST',
    body: JSON.stringify({ filter: { conjunction: 'and', conditions: [{ field_name: field, operator: 'is', value: [String(value)] }] } }),
  });
  return (d.items && d.items[0]) || null;
}
async function createRecord(env, tableId, fields) {
  return bt(env, `/tables/${tableId}/records`, { method: 'POST', body: JSON.stringify({ fields }) });
}
async function updateRecord(env, tableId, recordId, fields) {
  return bt(env, `/tables/${tableId}/records/${recordId}`, { method: 'PUT', body: JSON.stringify({ fields }) });
}
async function upsert(env, tableId, keyField, keyVal, fields) {
  const ex = await findByField(env, tableId, keyField, keyVal);
  if (ex) return updateRecord(env, tableId, ex.record_id, fields);
  return createRecord(env, tableId, fields);
}

/* session table schema (created on demand) */
const NUM = 2, TXT = 1;
const SESSION_FIELDS = [
  ['roomId', TXT], ['date', TXT], ['creator', TXT], ['shop', TXT], ['durationSec', NUM], ['slices', NUM],
  ['gmv', NUM], ['orders', NUM], ['items', NUM], ['customers', NUM], ['viewers', NUM], ['totalViewers', NUM],
  ['views', NUM], ['impression', NUM], ['prodImp', NUM], ['prodClk', NUM], ['likes', NUM], ['comments', NUM],
  ['shares', NUM], ['newFollowers', NUM], ['adSpend', TXT], ['avgViewDur', TXT],
  ['ratesJson', TXT], ['productsJson', TXT], ['sourceJson', TXT], ['profileJson', TXT], ['hostsJson', TXT], ['startTime', TXT], ['endTime', TXT], ['ingestedBy', TXT], ['ingestedAt', TXT],
  /* --- added: POC, live-hours waiver, campaign tagging (see /ingest + dashboard pending-card UI) --- */
  ['poc', TXT], ['hoursWaived', NUM], ['campaign', TXT],
  /* --- added: per-product auction-round detail (Starting bid / Sale price / Bidders / Duration),
     parsed client-side from the companion "..._auction.xlsx" export and merged in at upload time --- */
  ['auctionJson', TXT],
];
/* _Registry columns for per-project pricing (flat fee / commission, simple or tiered) + contract archive.
   Auto-created the same way USER_FIELDS is, so nobody has to add Bitable columns by hand. */
const REGISTRY_FIELDS = [
  ['pricingJson', TXT], ['pricingUpdatedBy', TXT], ['pricingUpdatedAt', TXT],
  ['contractFileToken', TXT], ['contractFileName', TXT], ['contractUploadedBy', TXT], ['contractUploadedAt', TXT],
];
/* _Users columns needed by the request/approval model. Auto-created so Belle never has to
   add columns by hand (writing to a non-existent Bitable field throws "field not found"). */
const USER_FIELDS = [
  ['email', TXT], ['name', TXT], ['openId', TXT], ['role', TXT], ['status', TXT],
  ['viewProjects', TXT], ['uploadProjects', TXT], ['note', TXT], ['requestedAt', TXT], ['updatedAt', TXT],
];
async function ensureFieldsList(env, tableId, list) {
  const d = await bt(env, `/tables/${tableId}/fields?page_size=200`, { method: 'GET' });
  const have = new Set((d.items || []).map(f => f.field_name));
  for (const [field_name, type] of list) {
    if (!have.has(field_name)) {
      await bt(env, `/tables/${tableId}/fields`, { method: 'POST', body: JSON.stringify({ field_name, type }) });
    }
  }
}
let _usersEnsured = false;
async function ensureUserFields(env) {
  if (_usersEnsured) return;
  await ensureFieldsList(env, env.USERS_TABLE_ID, USER_FIELDS);
  _usersEnsured = true;
}
let _registryEnsured = false;
async function ensureRegistryFields(env) {
  if (_registryEnsured) return;
  await ensureFieldsList(env, env.REGISTRY_TABLE_ID, REGISTRY_FIELDS);
  _registryEnsured = true;
}
/* Add any columns the table is missing (handles tables created with an older schema) */
async function ensureFields(env, tableId) {
  await ensureFieldsList(env, tableId, SESSION_FIELDS);
}
/* Add any missing SESSION_FIELDS columns to an existing project table.
   Fixes older tables created before newer fields (comments / customers / viewers / …)
   existed — otherwise createRecord fails with "field not found" and returns 500. Safe:
   only ADDS columns that are missing, never touches existing data. */
async function reconcileTable(env, tableId) {
  let have = new Set();
  try {
    const d = await bt(env, `/tables/${tableId}/fields?page_size=200`);
    have = new Set((d.items || []).map(f => f.field_name));
  } catch (e) { return; }
  for (const [field_name, type] of SESSION_FIELDS) {
    if (!have.has(field_name)) {
      try { await bt(env, `/tables/${tableId}/fields`, { method: 'POST', body: JSON.stringify({ field_name, type }) }); } catch (e) {}
    }
  }
}
async function ensureProjectTable(env, projectId, name) {
  const reg = await findByField(env, env.REGISTRY_TABLE_ID, 'projectId', projectId);
  if (reg && reg.fields.tableId) {
    const tid = textVal(reg.fields.tableId);
    await ensureFields(env, tid);   // backfill any missing columns before writing
    return tid;
  }
  const tableName = `P__${(name || projectId).slice(0, 40)}`;
  // Adopt an existing table with the same name instead of re-creating it. A prior failed
  // attempt (or the same creator previously uploaded under a different projectId key, e.g.
  // with vs. without Shop ID) can leave an orphan table that _Registry doesn't point to.
  // Re-creating it hits Lark 1254013 "TableNameDuplicated"; adopting it fixes that.
  let tableId = null;
  try {
    let pageToken = '';
    do {
      const qs = `page_size=100${pageToken ? '&page_token=' + encodeURIComponent(pageToken) : ''}`;
      const d = await bt(env, `/tables?${qs}`, { method: 'GET' });
      const hit = (d.items || []).find(t => t.name === tableName);
      if (hit) { tableId = hit.table_id; break; }
      pageToken = d.has_more ? d.page_token : '';
    } while (pageToken);
  } catch (e) { /* fall through to create */ }
  if (tableId) {
    await ensureFields(env, tableId); // make sure the adopted table has every column
  } else {
    const d = await bt(env, `/tables`, {
      method: 'POST',
      body: JSON.stringify({ table: { name: tableName, fields: SESSION_FIELDS.map(([field_name, type]) => ({ field_name, type })) } }),
    });
    tableId = d.table_id;
  }
  // create/refresh the _Registry pointer for this projectId
  if (reg) await updateRecord(env, env.REGISTRY_TABLE_ID, reg.record_id, { projectId, name: name || projectId, tableId, createdAt: new Date().toISOString() });
  else await createRecord(env, env.REGISTRY_TABLE_ID, { projectId, name: name || projectId, tableId, createdAt: new Date().toISOString() });
  return tableId;
}

/* Lark text fields may come back as [{text}] arrays or plain strings */
function textVal(v) {
  if (v == null) return '';
  if (Array.isArray(v)) return v.map(x => (x && x.text != null ? x.text : x)).join('');
  if (typeof v === 'object' && v.text != null) return v.text;
  return String(v);
}
function numVal(v) { const n = Number(textVal(v)); return isNaN(n) ? 0 : n; }

/* ---------------- host pay (biweekly, Friday payday) ----------------
   Anchor: the last COMPLETED payday before this feature was built was Friday 2026-08-28
   (the message that requested this said "9.28", which isn't a Friday in any nearby year —
   2026-08-28 is the closest date that is both a Friday and already in the past, so that's
   the anchor used below). Every 14 days from that Friday, forward and back, is a payday.
   If the real anchor is different, change PAY_ANCHOR below — everything else derives from it. */
const PAY_ANCHOR = '2026-08-28';
const PAY_TIERS = [ { max: 10, rate: 35 }, { max: 20, rate: 45 }, { max: null, rate: 60 } ]; // <10h, 10–20h, 20h+ (whole-bucket rate, not marginal)
function hostRate(hours) {
  for (const t of PAY_TIERS) { if (t.max == null || hours < t.max) return t.rate; }
  return PAY_TIERS[PAY_TIERS.length - 1].rate;
}
function hhmmToMinutes(t) {
  const m = String(t || '').match(/^(\d{1,2}):(\d{2})/);
  if (!m) return null;
  return (+m[1]) * 60 + (+m[2]);
}
function hostSegmentHours(h) {
  const s = hhmmToMinutes(h && h.start), e = hhmmToMinutes(h && h.end);
  if (s == null || e == null) return 0;
  let mins = e - s;
  if (mins <= 0) mins += 24 * 60; // overnight session
  return mins / 60;
}
/* Which biweekly [start,end] pay period (paid on `payDate`, a Friday) a session date falls in.
   Period = the 14 days ending on the payDate itself (i.e. hours are paid the Friday they land in). */
function payPeriodForDate(dateStr) {
  const anchor = Date.UTC(...PAY_ANCHOR.split('-').map((x, i) => i === 1 ? +x - 1 : +x));
  const [y, m, d] = dateStr.split('-').map(Number);
  const day = Date.UTC(y, m - 1, d);
  const diffDays = Math.round((day - anchor) / 86400000);
  const period = Math.floor(diffDays / 14);
  const periodEndMs = anchor + period * 14 * 86400000;
  const periodStartMs = periodEndMs - 13 * 86400000;
  const iso = ms => new Date(ms).toISOString().slice(0, 10);
  return { start: iso(periodStartMs), end: iso(periodEndMs), payDate: iso(periodEndMs) };
}

/* ---------------- session <-> record ---------------- */
function sessionToFields(s, email) {
  return {
    roomId: s.room, date: s.date, creator: s.creator, shop: s.shop, durationSec: s.dur || 0, slices: s.nslice || 0,
    gmv: s['Attributed GMV'] || 0, orders: s.orders || 0, items: s['Attributed items sold'] || 0,
    customers: s['Customers'] || 0, viewers: s['Viewers'] || 0, totalViewers: s['Total {country} viewers'] || 0,
    views: s['Views'] || 0, impression: s['LIVE impression'] || 0, prodImp: s['Product Impressions'] || 0,
    prodClk: s['Product Clicks'] || 0, likes: s['Likes'] || 0, comments: s['Comments'] || 0, shares: s['Shares'] || 0,
    newFollowers: s['New followers'] || 0,
    adSpend: s.adSpend == null ? '' : String(s.adSpend), avgViewDur: s.avgViewDur == null ? '' : String(s.avgViewDur),
    ratesJson: JSON.stringify({ err: s['L_Enter room rate'] || [], ctr: s['L_CTR'] || [], ctor: s['L_CTOR (SKU orders)'] || [], gpm: s['L_GPM'] || [], viewers: s['L_Viewers'] || [], views: s['L_Views'] || [] }),
    productsJson: JSON.stringify(s.products || []), sourceJson: JSON.stringify(s.source || {}), profileJson: JSON.stringify(s.profile || {}),
    hostsJson: JSON.stringify(s.hosts || []), startTime: s.startTime || '', endTime: s.endTime || '',
    poc: s.poc || '', hoursWaived: Number(s.hoursWaived) || 0, campaign: s.campaign || '',
    auctionJson: JSON.stringify(s.auction || {}),
    ingestedBy: email || '', ingestedAt: new Date().toISOString(),
  };
}
function recordToSession(f) {
  let rates = {}, products = [], source = {}, profile = {}, hosts = [], auction = {};
  try { rates = JSON.parse(textVal(f.ratesJson) || '{}'); } catch (e) {}
  try { products = JSON.parse(textVal(f.productsJson) || '[]'); } catch (e) {}
  try { source = JSON.parse(textVal(f.sourceJson) || '{}'); } catch (e) {}
  try { profile = JSON.parse(textVal(f.profileJson) || '{}'); } catch (e) {}
  try { hosts = JSON.parse(textVal(f.hostsJson) || '[]'); } catch (e) {}
  try { auction = JSON.parse(textVal(f.auctionJson) || '{}'); } catch (e) {}
  const adRaw = textVal(f.adSpend).trim(), vdRaw = textVal(f.avgViewDur).trim();
  return {
    room: textVal(f.roomId), creator: textVal(f.creator), shop: textVal(f.shop), date: textVal(f.date),
    dur: numVal(f.durationSec), nslice: numVal(f.slices),
    'Attributed GMV': numVal(f.gmv), 'Attributed items sold': numVal(f.items), 'Total {country} viewers': numVal(f.totalViewers),
    'LIVE impression': numVal(f.impression), 'Views': numVal(f.views), 'Product Impressions': numVal(f.prodImp),
    'Product Clicks': numVal(f.prodClk), 'Likes': numVal(f.likes), 'Shares': numVal(f.shares), 'Comments': numVal(f.comments),
    'New followers': numVal(f.newFollowers), 'Viewers': numVal(f.viewers), 'Customers': numVal(f.customers),
    orders: numVal(f.orders),
    'L_Enter room rate': rates.err || [], 'L_CTR': rates.ctr || [], 'L_CTOR (SKU orders)': rates.ctor || [],
    'L_GPM': rates.gpm || [], 'L_Viewers': rates.viewers || [], 'L_Views': rates.views || [],
    products, source, profile, hosts, startTime: textVal(f.startTime), endTime: textVal(f.endTime),
    adSpend: adRaw === '' ? null : Number(adRaw),
    avgViewDur: vdRaw === '' ? null : Number(vdRaw),
    poc: textVal(f.poc), hoursWaived: numVal(f.hoursWaived), campaign: textVal(f.campaign),
    auction,
  };
}

/* ---------------- permissions ---------------- */
function parseList(v) { const s = textVal(v).trim(); if (s === '*') return '*'; return s ? s.split(',').map(x => x.trim()).filter(Boolean) : []; }
function can(list, projectId) { return list === '*' || (Array.isArray(list) && list.includes(projectId)); }
function isAdmin(env, email, openId) {
  const emails = (env.ADMIN_EMAILS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  const ids = (env.ADMIN_OPEN_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
  return (email && emails.includes(String(email).toLowerCase())) || (openId && ids.includes(openId));
}

/* IDENTITY MODEL (request + approval)
   - Authentication = Lark. Any member of the company's Lark org can obtain an auth code; the
     app trusts that as proof of employment. There is NO email-domain gate anymore, so staff
     whose Lark is registered with a personal email are no longer locked out.
   - Authorization = this app. Identity is keyed on Lark open_id (stable, unique per user).
     Each user has a status: 'active' (approved), 'pending' (awaiting admin approval), or
     'disabled' (revoked). Admins are always active with '*' access.
   - Legacy migration: users already in _Users (keyed by email from the old model) are matched
     by email on first open_id login, their openId is backfilled, and — because they were
     already using the app — they are marked 'active' so nobody currently working gets locked out.
   loadUser is idempotent and self-healing; it also ensures the _Users columns exist. */
async function loadUser(env, ident) {
  await ensureUserFields(env);
  const openId = ident.openId || '';
  const email = (ident.email || '').toLowerCase();
  const name = ident.name || '';
  const admin = isAdmin(env, email, openId);

  let rec = openId ? await findByField(env, env.USERS_TABLE_ID, 'openId', openId) : null;

  // legacy record matched by email → adopt it and backfill openId (+ activate)
  if (!rec && email) {
    const legacy = await findByField(env, env.USERS_TABLE_ID, 'email', email);
    if (legacy) {
      const patch = { openId, updatedAt: new Date().toISOString() };
      if (!textVal(legacy.fields.status)) patch.status = 'active'; // pre-existing = already trusted
      if (name && !textVal(legacy.fields.name)) patch.name = name;
      await updateRecord(env, env.USERS_TABLE_ID, legacy.record_id, patch);
      rec = await findByField(env, env.USERS_TABLE_ID, 'openId', openId) || legacy;
    }
  }

  if (admin) {
    // NOTE: this runs on every authenticated request, not just /auth/login — `name` is only ever
    // non-empty on the login call, so a blind overwrite here wiped the admin's stored name back to
    // blank on their very next API call. Only touch fields that actually need to change.
    if (!rec) {
      await createRecord(env, env.USERS_TABLE_ID, { openId, email, name, role: 'admin', status: 'active', viewProjects: '*', uploadProjects: '*', updatedAt: new Date().toISOString() });
    } else {
      const f = rec.fields, fresh = {};
      if (openId && !textVal(f.openId)) fresh.openId = openId;
      if (name && !textVal(f.name)) fresh.name = name;
      if (email && !textVal(f.email)) fresh.email = email;
      if (textVal(f.role) !== 'admin') fresh.role = 'admin';
      if (textVal(f.status) !== 'active') fresh.status = 'active';
      if (textVal(f.viewProjects) !== '*') fresh.viewProjects = '*';
      if (textVal(f.uploadProjects) !== '*') fresh.uploadProjects = '*';
      if (Object.keys(fresh).length) { fresh.updatedAt = new Date().toISOString(); await updateRecord(env, env.USERS_TABLE_ID, rec.record_id, fresh); }
    }
    return { openId, email, name: (rec && textVal(rec.fields.name)) || name, role: 'admin', status: 'active', view: '*', upload: '*' };
  }

  if (!rec) {
    // brand-new org member → pending, no project access until an admin approves
    await createRecord(env, env.USERS_TABLE_ID, { openId, email, name, role: 'member', status: 'pending', viewProjects: '', uploadProjects: '', requestedAt: '', updatedAt: new Date().toISOString() });
    return { openId, email, name, role: 'member', status: 'pending', view: [], upload: [] };
  }

  const f = rec.fields;
  // keep display fields fresh, but NEVER silently overwrite an already-set name: Lang/Lark's
  // user_info can return a slightly different string for the same person on a later login
  // (locale, en_name vs name, whitespace), and this used to rename them on every login — which
  // made their POC chip "disappear" (it re-appeared under the new string) each time they
  // refreshed/re-logged in. Only backfill name/email when the stored value is still empty.
  const fresh = {}; if (openId && !textVal(f.openId)) fresh.openId = openId; if (name && !textVal(f.name)) fresh.name = name; if (email && !textVal(f.email)) fresh.email = email;
  if (Object.keys(fresh).length) await updateRecord(env, env.USERS_TABLE_ID, rec.record_id, fresh);
  return {
    openId: textVal(f.openId) || openId, email: textVal(f.email) || email, name: textVal(f.name) || name,
    role: textVal(f.role) || 'member', status: textVal(f.status) || 'pending',
    view: parseList(f.viewProjects), upload: parseList(f.uploadProjects), recordId: rec.record_id,
  };
}

/* Notify admins (dedicated admin chat if set, else the department group) when someone requests access. Best-effort. */
async function notifyAccessRequest(env, me, note) {
  const chat = env.LARK_ADMIN_CHAT_ID || env.LARK_GROUP_CHAT_ID;
  if (!chat) return;
  try {
    const tok = await tenantToken(env);
    const text = `🔐 Live Dashboard — new access request\nName: ${me.name || '—'}\nEmail: ${me.email || '—'}\nopen_id: ${me.openId}\n${note ? ('Note: ' + note + '\n') : ''}Open the app → Admin panel to approve and assign projects.`;
    await fetch(`${LARK}/open-apis/im/v1/messages?receive_id_type=chat_id`, {
      method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
      body: JSON.stringify({ receive_id: chat, msg_type: 'text', content: JSON.stringify({ text }) }),
    });
  } catch (e) { /* never fail the request because the notification failed */ }
}

/* ---------------- router ---------------- */
export default {
  async fetch(request, env) {
    const origin = env.ALLOW_ORIGIN || '*';
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors(origin) });
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '');
    try {
      if (path === '/health') return json({ ok: true, version: 'access-request-v6-2026-07-27' }, 200, origin);

      /* ----- login (no JWT) -----
         No email-domain gate: a valid Lark auth code proves org membership. Identity = open_id. */
      if (path === '/auth/login' && request.method === 'POST') {
        const { code } = await request.json();
        if (!code) return json({ error: 'missing code' }, 400, origin);
        const info = await larkLogin(env, code);
        const openId = info.open_id || info.union_id || '';
        if (!openId) return json({ error: 'no Lark identity (open_id) on this account' }, 403, origin);
        const email = (info.enterprise_email || info.email || '').toLowerCase();
        const me = await loadUser(env, { openId, email, name: info.name || '' });
        const token = await signJWT({ openId, email: me.email, role: me.role, exp: Math.floor(Date.now() / 1000) + JWT_TTL }, env.JWT_SECRET);
        return json({
          token, openId, email: me.email, name: me.name, role: me.role, status: me.status,
          viewProjects: me.view, uploadProjects: me.upload,
        }, 200, origin);
      }

      /* ----- everything below requires a valid JWT ----- */
      const auth = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      const claim = await verifyJWT(auth, env.JWT_SECRET);
      if (!claim) return json({ error: 'unauthorized' }, 401, origin);
      const me = await loadUser(env, { openId: claim.openId, email: claim.email }); // re-read perms fresh each call

      /* who am I (debug + frontend status refresh) */
      if (path === '/whoami' && request.method === 'GET') {
        return json({ openId: me.openId, email: me.email, name: me.name, role: me.role, status: me.status, viewProjects: me.view, uploadProjects: me.upload }, 200, origin);
      }

      /* file / refresh an access request — available to pending users (before the active gate) */
      if (path === '/access/request' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const rec = me.recordId ? { record_id: me.recordId } : await findByField(env, env.USERS_TABLE_ID, 'openId', me.openId);
        if (rec) await updateRecord(env, env.USERS_TABLE_ID, rec.record_id, { requestedAt: new Date().toISOString(), note: (body.note || '').slice(0, 300), updatedAt: new Date().toISOString() });
        await notifyAccessRequest(env, me, body.note || '');
        return json({ ok: true, status: me.status }, 200, origin);
      }

      /* ACCESS GATE: only approved (active) users may reach data/admin endpoints */
      if (me.status !== 'active') {
        if (me.role === 'admin') { /* admins are always active; fall through */ }
        else return json({ error: 'access_' + me.status, status: me.status }, 403, origin);
      }

      /* ----- team names, for the POC picker at daily upload (any active user — not admin-only,
         and deliberately returns just names, not emails/roles/permissions) ----- */
      if (path === '/team' && request.method === 'GET') {
        await ensureUserFields(env);
        const rows = await listAll(env, env.USERS_TABLE_ID);
        const names = [...new Set(rows.map(r => textVal(r.fields.name).trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
        return json({ names }, 200, origin);
      }

      /* ----- projects visible to me ----- */
      if (path === '/projects' && request.method === 'GET') {
        const regs = await listAll(env, env.REGISTRY_TABLE_ID);
        const list = regs.map(r => ({ projectId: textVal(r.fields.projectId), name: textVal(r.fields.name), tableId: textVal(r.fields.tableId) }))
          .filter(p => can(me.view, p.projectId));
        return json({ projects: list.map(({ tableId, ...p }) => p) }, 200, origin);
      }

      /* ----- records for a project ----- */
      if (path === '/records' && request.method === 'GET') {
        const projectId = url.searchParams.get('project');
        if (!projectId) return json({ error: 'missing project' }, 400, origin);
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        const reg = await findByField(env, env.REGISTRY_TABLE_ID, 'projectId', projectId);
        if (!reg) return json({ sessions: [] }, 200, origin);
        const rows = await listAll(env, textVal(reg.fields.tableId));
        return json({ sessions: rows.map(r => recordToSession(r.fields)) }, 200, origin);
      }

      /* ----- ingest one session ----- */
      if (path === '/ingest' && request.method === 'POST') {
        const { session } = await request.json();
        // shop can be empty on some exports; projectId falls back to creator, so only require room + (shop OR creator).
        if (!session || !session.room || !(session.shop || session.creator)) return json({ error: 'bad session (need room + shop or creator)' }, 400, origin);
        const projectId = session.shop || session.creator;
        if (!can(me.upload, projectId)) return json({ error: 'no upload permission for this project' }, 403, origin);
        const tableId = await ensureProjectTable(env, projectId, session.creator);
        const existing = await findByField(env, tableId, 'roomId', session.room);
        // UPSERT, not reject-on-duplicate: re-uploading the same Room ID used to be silently
        // dropped ("duplicate, skipped"), which meant editing POC / hours-waived / campaign /
        // ad spend / auction-detail after the first commit had no effect — the dashboard kept
        // showing the original values because the edit never reached Bitable. Same Room ID always
        // means the same live session, so overwriting is safe (no legitimate case produces two
        // different metric sets for one Room ID) and lets edits actually take effect.
        const fields = sessionToFields(session, me.email);
        try {
          if (existing) await updateRecord(env, tableId, existing.record_id, fields);
          else await createRecord(env, tableId, fields);
        } catch (e) {
          // Most likely the project table is missing newer columns. Repair schema and retry once.
          await reconcileTable(env, tableId);
          if (existing) await updateRecord(env, tableId, existing.record_id, fields);
          else await createRecord(env, tableId, fields);
        }
        return json({ ok: true, duplicate: false, updated: !!existing }, 200, origin);
      }

      /* ----- project settings: pricing (flat fee / commission, simple or tiered) + contract archive ----- */
      if (path === '/project/settings' && request.method === 'GET') {
        const projectId = url.searchParams.get('project');
        if (!projectId) return json({ error: 'missing project' }, 400, origin);
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        await ensureRegistryFields(env);
        const reg = await findByField(env, env.REGISTRY_TABLE_ID, 'projectId', projectId);
        if (!reg) return json({ pricing: null, contract: null }, 200, origin);
        let pricing = null;
        try { pricing = JSON.parse(textVal(reg.fields.pricingJson) || 'null'); } catch (e) {}
        const contract = textVal(reg.fields.contractFileToken) ? {
          fileName: textVal(reg.fields.contractFileName),
          uploadedBy: textVal(reg.fields.contractUploadedBy),
          uploadedAt: textVal(reg.fields.contractUploadedAt),
        } : null;
        return json({ pricing, contract }, 200, origin);
      }
      if (path === '/project/settings' && request.method === 'POST') {
        const { projectId, pricing } = await request.json();
        if (!projectId) return json({ error: 'missing projectId' }, 400, origin);
        if (!can(me.upload, projectId) && me.role !== 'admin') return json({ error: 'forbidden' }, 403, origin);
        await ensureRegistryFields(env);
        const reg = await findByField(env, env.REGISTRY_TABLE_ID, 'projectId', projectId);
        if (!reg) return json({ error: 'project not found — upload at least one session first so the project exists' }, 404, origin);
        await updateRecord(env, env.REGISTRY_TABLE_ID, reg.record_id, {
          pricingJson: JSON.stringify(pricing || {}), pricingUpdatedBy: me.email, pricingUpdatedAt: new Date().toISOString(),
        });
        return json({ ok: true }, 200, origin);
      }
      if (path === '/project/contract' && request.method === 'POST') {
        const { projectId, fileName, dataBase64 } = await request.json();
        if (!projectId || !fileName || !dataBase64) return json({ error: 'missing fields' }, 400, origin);
        if (!can(me.upload, projectId) && me.role !== 'admin') return json({ error: 'forbidden' }, 403, origin);
        await ensureRegistryFields(env);
        const reg = await findByField(env, env.REGISTRY_TABLE_ID, 'projectId', projectId);
        if (!reg) return json({ error: 'project not found — upload at least one session first so the project exists' }, 404, origin);
        const b64 = String(dataBase64).split(',').pop();
        const bin = Uint8Array.from(atob(b64), ch => ch.charCodeAt(0));
        const tok = await tenantToken(env);
        const fd = new FormData();
        fd.append('file_name', fileName);
        fd.append('parent_type', 'bitable_file');
        fd.append('parent_node', env.LARK_BASE_TOKEN);
        fd.append('size', String(bin.length));
        fd.append('file', new Blob([bin]), fileName);
        const ur = await fetch(`${LARK}/open-apis/drive/v1/medias/upload_all`, { method: 'POST', headers: { Authorization: 'Bearer ' + tok }, body: fd });
        const uj = await ur.json();
        if (uj.code !== 0) return json({ error: 'lark upload: ' + JSON.stringify(uj) }, 502, origin);
        await updateRecord(env, env.REGISTRY_TABLE_ID, reg.record_id, {
          contractFileToken: uj.data.file_token, contractFileName: fileName,
          contractUploadedBy: me.email, contractUploadedAt: new Date().toISOString(),
        });
        return json({ ok: true, fileName }, 200, origin);
      }
      if (path === '/project/contract/download' && request.method === 'GET') {
        const projectId = url.searchParams.get('project');
        if (!projectId) return json({ error: 'missing project' }, 400, origin);
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        const reg = await findByField(env, env.REGISTRY_TABLE_ID, 'projectId', projectId);
        const tokenv = reg ? textVal(reg.fields.contractFileToken) : '';
        if (!tokenv) return json({ error: 'no contract on file for this project' }, 404, origin);
        const tok = await tenantToken(env);
        const fr = await fetch(`${LARK}/open-apis/drive/v1/medias/${tokenv}/download`, { headers: { Authorization: 'Bearer ' + tok } });
        if (!fr.ok) return json({ error: 'download failed (' + fr.status + ')' }, 502, origin);
        const buf = await fr.arrayBuffer();
        const fname = (textVal(reg.fields.contractFileName) || 'contract').replace(/"/g, '');
        return new Response(buf, { status: 200, headers: cors(origin, { 'Content-Type': fr.headers.get('content-type') || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${fname}"` }) });
      }

      /* ----- project cost (host/mod pay attributable to ONE project) -----
         Visible to anyone with VIEW access to this project (same as GMV/hours elsewhere in the
         dashboard) — not admin-gated, since it only returns an aggregate $ total for the project
         (no host names/individual amounts), so it doesn't expose anyone's personal payroll. The
         all-projects, per-host Host Pay breakdown (/hostpay) stays admin-only.
         Rate bracket is still based on each host's FULL biweekly hours across all projects —
         only the $ SLICE for hours worked on this project within [start,end] is summed. */
      if (path === '/project/cost' && request.method === 'GET') {
        const projectId = url.searchParams.get('project');
        const start = url.searchParams.get('start'), end = url.searchParams.get('end');
        if (!projectId || !start || !end) return json({ error: 'missing project/start/end' }, 400, origin);
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        const regs = await listAll(env, env.REGISTRY_TABLE_ID);
        const periodMap = {}; // periodKey -> { hostName: { totalHours, inRangeThisProject } }
        for (const r of regs) {
          const pid = textVal(r.fields.projectId), tid = textVal(r.fields.tableId);
          if (!tid) continue;
          const rows = await listAll(env, tid);
          rows.forEach(row => {
            const f = row.fields, date = textVal(f.date);
            if (!date) return;
            let hosts = [];
            try { hosts = JSON.parse(textVal(f.hostsJson) || '[]'); } catch (e) {}
            if (!hosts.length) return;
            const per = payPeriodForDate(date), key = per.start + '|' + per.end;
            if (!periodMap[key]) periodMap[key] = {};
            hosts.forEach(h => {
              const name = String(h.name || '').trim().toUpperCase();
              if (!name) return;
              const hrs = hostSegmentHours(h);
              if (!periodMap[key][name]) periodMap[key][name] = { totalHours: 0, inRangeThisProject: 0 };
              periodMap[key][name].totalHours += hrs;
              if (pid === projectId && date >= start && date <= end) periodMap[key][name].inRangeThisProject += hrs;
            });
          });
        }
        let cost = 0, hostsInvolved = 0;
        Object.values(periodMap).forEach(hosts => {
          Object.values(hosts).forEach(h => {
            if (h.inRangeThisProject > 0) { cost += h.inRangeThisProject * hostRate(h.totalHours); hostsInvolved++; }
          });
        });
        return json({ cost: Math.round(cost * 100) / 100, hostsInvolved }, 200, origin);
      }

      /* ----- host pay: auto-computed from each session's Hosts & time, biweekly, Friday payday -----
         Admin-only — this is payroll. See PAY_ANCHOR / PAY_TIERS above for the assumptions used. */
      if (path === '/hostpay' && request.method === 'GET') {
        if (me.role !== 'admin') return json({ error: 'admin only' }, 403, origin);
        const nPeriods = Number(url.searchParams.get('periods') || 8);
        const regs = await listAll(env, env.REGISTRY_TABLE_ID);
        const periodMap = {};
        for (const r of regs) {
          const pid = textVal(r.fields.projectId), tid = textVal(r.fields.tableId);
          if (!tid) continue;
          const rows = await listAll(env, tid);
          rows.forEach(row => {
            const f = row.fields, date = textVal(f.date);
            if (!date) return;
            let hosts = [];
            try { hosts = JSON.parse(textVal(f.hostsJson) || '[]'); } catch (e) {}
            if (!hosts.length) return;
            const per = payPeriodForDate(date);
            const key = per.start + '|' + per.end;
            if (!periodMap[key]) periodMap[key] = { start: per.start, end: per.end, payDate: per.payDate, hosts: {} };
            hosts.forEach(h => {
              const name = String(h.name || '').trim().toUpperCase();
              if (!name) return;
              const hrs = hostSegmentHours(h);
              if (!periodMap[key].hosts[name]) periodMap[key].hosts[name] = { hours: 0, byProject: {} };
              periodMap[key].hosts[name].hours += hrs;
              periodMap[key].hosts[name].byProject[pid] = (periodMap[key].hosts[name].byProject[pid] || 0) + hrs;
            });
          });
        }
        let periods = Object.values(periodMap).sort((a, b) => a.start.localeCompare(b.start));
        periods = periods.map(p => ({
          start: p.start, end: p.end, payDate: p.payDate,
          hosts: Object.entries(p.hosts).map(([name, v]) => {
            const hours = Math.round(v.hours * 100) / 100, rate = hostRate(hours), pay = Math.round(hours * rate * 100) / 100;
            return { name, hours, rate, pay, byProject: v.byProject };
          }).sort((a, b) => a.name.localeCompare(b.name)),
        }));
        if (nPeriods) periods = periods.slice(-nPeriods);
        return json({ periods, anchor: PAY_ANCHOR, tiers: PAY_TIERS }, 200, origin);
      }

      /* ----- goals ----- */
      if (path === '/goals' && request.method === 'GET') {
        const projectId = url.searchParams.get('project');
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        const month = url.searchParams.get('month') || new Date().toISOString().slice(0, 7);
        const rec = await findByField(env, env.GOALS_TABLE_ID, 'key', `${projectId}|${month}`);
        if (!rec) return json({ goal: null }, 200, origin);
        return json({ goal: { gmvGoal: numVal(rec.fields.gmvGoal), hoursGoal: numVal(rec.fields.hoursGoal), locked: textVal(rec.fields.locked) === 'true' } }, 200, origin);
      }
      if (path === '/goals' && request.method === 'POST') {
        const { projectId, gmvGoal, hoursGoal, month } = await request.json();
        const m = month || new Date().toISOString().slice(0, 7);
        const key = `${projectId}|${m}`;
        const existing = await findByField(env, env.GOALS_TABLE_ID, 'key', key);
        const locked = existing && textVal(existing.fields.locked) === 'true';
        if (locked && me.role !== 'admin') return json({ error: 'goal locked; admin only' }, 403, origin);
        if (!can(me.upload, projectId) && me.role !== 'admin') return json({ error: 'forbidden' }, 403, origin);
        const fields = { key, projectId, month: m, gmvGoal: Number(gmvGoal) || 0, hoursGoal: Number(hoursGoal) || 0, locked: 'true', setBy: me.email, setAt: new Date().toISOString() };
        await upsert(env, env.GOALS_TABLE_ID, 'key', key, fields);
        return json({ ok: true }, 200, origin);
      }

      /* ----- management roll-up (any authenticated user) ----- */
      if (path === '/management' && request.method === 'GET') {
        const regs = await listAll(env, env.REGISTRY_TABLE_ID);
        const goalRows = await listAll(env, env.GOALS_TABLE_ID);
        const goalPerProj = {}; // pid -> { month -> {gmv,hours} }
        goalRows.forEach(g => { const pid = textVal(g.fields.projectId), m = textVal(g.fields.month); (goalPerProj[pid] = goalPerProj[pid] || {})[m] = { gmv: numVal(g.fields.gmvGoal), hours: numVal(g.fields.hoursGoal) }; });
        const projects = [];
        for (const r of regs) {
          const pid = textVal(r.fields.projectId), tid = textVal(r.fields.tableId);
          if (!tid) continue;
          const rows = await listAll(env, tid);
          const sessions = rows.map(x => ({ date: textVal(x.fields.date), gmv: numVal(x.fields.gmv), imp: numVal(x.fields.impression), views: numVal(x.fields.views), prodClk: numVal(x.fields.prodClk), orders: numVal(x.fields.orders), dur: numVal(x.fields.durationSec), adSpend: textVal(x.fields.adSpend).trim() === '' ? null : numVal(x.fields.adSpend) }));
          projects.push({ projectId: pid, name: textVal(r.fields.name), sessions, goals: goalPerProj[pid] || {} });
        }
        return json({ projects }, 200, origin);
      }

      /* ----- daily reports ----- */
      if (path === '/reports' && request.method === 'GET') {
        const projectId = url.searchParams.get('project');
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        const month = url.searchParams.get('month') || '';
        const rows = await listAll(env, env.REPORTS_TABLE_ID, { conjunction: 'and', conditions: [{ field_name: 'projectId', operator: 'is', value: [String(projectId)] }] });
        const reports = rows.map(r => { let inc = [], ins = {}; try { inc = JSON.parse(textVal(r.fields.includedJson) || '[]'); } catch (e) {} try { ins = JSON.parse(textVal(r.fields.insightsJson) || '{}'); } catch (e) {}
          return { date: textVal(r.fields.date), included: inc, insights: ins, sentAt: textVal(r.fields.sentAt) }; }).filter(x => !month || (x.date || '').startsWith(month));
        return json({ reports }, 200, origin);
      }
      if (path === '/report' && request.method === 'POST') {
        const { projectId, date, included, insights } = await request.json();
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        if (!projectId || !date) return json({ error: 'missing fields' }, 400, origin);
        const key = `${projectId}|${date}`;
        await upsert(env, env.REPORTS_TABLE_ID, 'key', key, { key, projectId, date, includedJson: JSON.stringify(included || []), insightsJson: JSON.stringify(insights || {}), by: me.email, updatedAt: new Date().toISOString() });
        return json({ ok: true }, 200, origin);
      }
      if (path === '/report/send' && request.method === 'POST') {
        const { projectId, date, text, card, image } = await request.json();
        if (!can(me.view, projectId)) return json({ error: 'forbidden' }, 403, origin);
        if (!env.LARK_GROUP_CHAT_ID) return json({ error: 'LARK_GROUP_CHAT_ID not configured' }, 400, origin);
        const tok = await tenantToken(env);
        let msg;
        if (image) {
          const b64 = String(image).split(',').pop();
          const bin = Uint8Array.from(atob(b64), ch => ch.charCodeAt(0));
          const fd = new FormData();
          fd.append('image_type', 'message');
          fd.append('image', new Blob([bin], { type: 'image/png' }), 'report.png');
          const ur = await fetch(`${LARK}/open-apis/im/v1/images`, { method: 'POST', headers: { Authorization: 'Bearer ' + tok }, body: fd });
          const uj = await ur.json();
          if (uj.code !== 0) return json({ error: 'lark image upload: ' + JSON.stringify(uj) }, 502, origin);
          msg = { msg_type: 'image', content: JSON.stringify({ image_key: uj.data.image_key }) };
        } else if (card) {
          msg = { msg_type: 'interactive', content: JSON.stringify(card) };
        } else {
          msg = { msg_type: 'text', content: JSON.stringify({ text: text || '' }) };
        }
        const r = await fetch(`${LARK}/open-apis/im/v1/messages?receive_id_type=chat_id`, {
          method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
          body: JSON.stringify({ receive_id: env.LARK_GROUP_CHAT_ID, ...msg }),
        });
        const j = await r.json();
        if (j.code !== 0) return json({ error: 'lark send: ' + JSON.stringify(j) }, 502, origin);
        const key = `${projectId}|${date}`;
        const ex = await findByField(env, env.REPORTS_TABLE_ID, 'key', key);
        if (ex) await updateRecord(env, env.REPORTS_TABLE_ID, ex.record_id, { sentAt: new Date().toISOString() });
        return json({ ok: true }, 200, origin);
      }

      /* ----- admin ----- */
      if (path.startsWith('/admin/')) {
        if (me.role !== 'admin') return json({ error: 'admin only' }, 403, origin);
        if (path === '/admin/users' && request.method === 'GET') {
          await ensureUserFields(env);
          const rows = await listAll(env, env.USERS_TABLE_ID);
          const users = rows.map(r => ({
            openId: textVal(r.fields.openId), email: textVal(r.fields.email), name: textVal(r.fields.name),
            role: textVal(r.fields.role) || 'member', status: textVal(r.fields.status) || 'pending',
            viewProjects: textVal(r.fields.viewProjects), uploadProjects: textVal(r.fields.uploadProjects),
            note: textVal(r.fields.note), requestedAt: textVal(r.fields.requestedAt),
          }));
          // pending first, then by requestedAt desc
          users.sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1) || (b.requestedAt || '').localeCompare(a.requestedAt || ''));
          return json({ users }, 200, origin);
        }
        if (path === '/admin/projects' && request.method === 'GET') {
          const regs = await listAll(env, env.REGISTRY_TABLE_ID);
          return json({ projects: regs.map(r => ({ projectId: textVal(r.fields.projectId), name: textVal(r.fields.name) })) }, 200, origin);
        }
        if (path === '/admin/user' && request.method === 'POST') {
          // approve / disable / edit permissions. Keyed by openId when known, else email
          // (so an admin can pre-authorise someone by email before their first login).
          const { openId, email, role, status, viewProjects, uploadProjects } = await request.json();
          if (!openId && !email) return json({ error: 'missing openId/email' }, 400, origin);
          const keyField = openId ? 'openId' : 'email';
          const keyVal = openId || email.toLowerCase();
          const rec = await findByField(env, env.USERS_TABLE_ID, keyField, keyVal);
          const fields = {
            role: role || 'member', status: status || 'active',
            viewProjects: Array.isArray(viewProjects) ? viewProjects.join(',') : (viewProjects || ''),
            uploadProjects: Array.isArray(uploadProjects) ? uploadProjects.join(',') : (uploadProjects || ''),
            updatedAt: new Date().toISOString(),
          };
          if (email) fields.email = email.toLowerCase();
          if (openId) fields.openId = openId;
          if (rec) await updateRecord(env, env.USERS_TABLE_ID, rec.record_id, fields);
          else await createRecord(env, env.USERS_TABLE_ID, fields);
          return json({ ok: true }, 200, origin);
        }
      }

      return json({ error: 'not found' }, 404, origin);
    } catch (e) {
      // DIAGNOSTIC: surface the real error (incl. full Lark Base response) in Cloudflare
      // Observability logs, so a 500 tells us exactly why instead of just "500".
      console.error('WORKER 500 on ' + (path || url.pathname) + ' -> ' + String(e && e.stack || e && e.message || e));
      return json({ error: String(e && e.message || e) }, 500, origin);
    }
  },
};
