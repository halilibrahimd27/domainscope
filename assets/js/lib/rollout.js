/**
 * lib/rollout.js — the Rollout board of a new certificate (the SSL Targets Rollout tab,
 * ui/rollout-panel.js): one row per server that needs it (per server and certificate set when a
 * renewal has several), a checklist of three steps the user ticks — installed, reloaded,
 * verified — kept in the workspace, progress counts, the rows the Verify tab confirmed, and a CSV.
 *
 * A board belongs to the certificate(s) it rolls out: its id is their leaf SHA-256 fingerprints
 * ({@link boardId}), so loading the same certificate again (another day, another scan) brings the
 * same ticks back, and a renewal of several certificates has one board whatever the file order (a
 * set's rows are keyed by the set's own fingerprints, not its letter).
 *
 * Steps are ordered: ticking one ticks the earlier ones, unticking one unticks the later ones. The
 * Verify tab marks a row verified when every check it made on that server (and set) saw the new
 * certificate, and only with a check newer than the user's last change of the row, so a row the
 * user unticked stays unticked until a new check confirms it. A row Verify marked is unmarked again
 * when a newer check sees an old certificate there; a row the user ticked is never changed.
 *
 * The workspace part 'rollout' (lib/workspace.js) holds the boards as JSON text written by
 * {@link serializeRollout} and read by {@link parseRollout}, which checks every field: the text
 * may come from another tab or an imported workspace file.
 *
 * DOM-free and i18n-free (codes only).
 */

/** The steps of a row, in order. */
export const ROLLOUT_STEPS = Object.freeze(['installed', 'reloaded', 'verified']);
/** Where a row stands: no step, or its last step ticked (`ro.stage.<stage>`). */
export const ROLLOUT_STAGES = Object.freeze(['todo', 'installed', 'reloaded', 'verified']);
/** What the Verify tab says about a row (`ro.vfy.<status>`). */
export const ROLLOUT_VERIFY = Object.freeze(['confirmed', 'old', 'mixed', 'other', 'unchecked']);
/**
 * Bounds: boards kept per workspace (most recently changed first), rows per board, stored characters
 * (lib/workspace.js sanitizePart keeps a 'rollout' text of at most `chars`, whole or not at all).
 */
export const ROLLOUT_LIMITS = Object.freeze({ boards: 20, rows: 2000, label: 200, name: 255, chars: 262144 });
/** The CSV columns (lib/export.js toCsv). */
export const ROLLOUT_CSV_COLUMNS = Object.freeze([
  { key: 'server', header: 'Server' },
  { key: 'address', header: 'Address outside the inventory' },
  { key: 'set', header: 'Certificate set' },
  { key: 'targets', header: 'Addresses' },
  { key: 'names', header: 'Names' },
  { key: 'stage', header: 'Stage' },
  { key: 'installed', header: 'Installed' },
  { key: 'reloaded', header: 'Reloaded' },
  { key: 'verified', header: 'Verified' },
  { key: 'verifiedBy', header: 'Verified by' },
  { key: 'verify', header: 'Verify tab' }
]);

const HEX64_RE = /^[0-9a-f]{64}$/;
const DEFAULT_PORT = 443;

/**
 * The id of the board of these certificates: their SHA-256 fingerprints, lowercase, sorted, unique.
 * @param {string[]} fingerprints
 * @returns {string|null} null without a valid fingerprint
 */
export function boardId(fingerprints) {
  const list = [...new Set((Array.isArray(fingerprints) ? fingerprints : [])
    .map((f) => (typeof f === 'string' ? f.replace(/[:\s]/g, '').toLowerCase() : ''))
    .filter((f) => HEX64_RE.test(f)))].sort();
  return list.length ? list.join(',') : null;
}

/**
 * The stable key of a certificate set: the first 16 hex digits of each of its leaves'
 * fingerprints, sorted.
 * @param {string[]} fingerprints
 * @returns {string|null}
 */
export function setKey(fingerprints) {
  const id = boardId(fingerprints);
  return id ? id.split(',').map((f) => f.slice(0, 16)).join('+') : null;
}

/**
 * @typedef {object} RolloutRow
 * @property {string} key 's:<server id>' or 'ip:<address>', plus '#<set key>' with several sets
 * @property {{ id: string, name: string, ips: string[] }|null} server null for an address outside the inventory
 * @property {string|null} ip that address
 * @property {boolean} private the address is private
 * @property {string|null} set the set's letter (several certificates)
 * @property {string[]} names the names it serves that the certificate (the set) covers
 * @property {Array<{ ip: string, port: number }>} targets the addresses and ports to deploy to and check
 */

/** The TLS ports of one address of an inventory server (`ports=` / `ip:port`), 443 by default. */
function portsOf(server, ip) {
  const own = server && server.ports && Array.isArray(server.ports[ip]) ? server.ports[ip].filter((p) => Number.isInteger(p)) : [];
  if (own.length) return own;
  const tls = server && Array.isArray(server.tlsPorts) ? server.tlsPorts.filter((p) => Number.isInteger(p)) : [];
  return tls.length ? tls : [DEFAULT_PORT];
}

function addTarget(list, ip, port) {
  if (ip && !list.some((t) => t.ip === ip && t.port === port)) list.push({ ip, port });
}

const uniq = (list) => [...new Set(list)];
const serverOf = (s) => ({ id: String(s.id ?? s.name ?? ''), name: String(s.name ?? s.id ?? ''), ips: [...(s.ips || [])] });

/**
 * The board's rows from a finished scan: with one certificate, the inventory servers that need it
 * (a DNS, zone-file or remembered origin name it covers lands there; origin hints alone do not, nor
 * does a server whose TLS ends elsewhere, `terminates_tls=no`) and the addresses outside the
 * inventory that serve a covered name; with several, one row per server (address) and set of the
 * renewal plan (lib/certsets.js planRenewal), origin hints left out.
 * @param {object} result lib/scanner ScanResult
 * @param {{ plan?: object|null, setKeys?: Map<string, string>|null }} [opts] plan: the renewal plan;
 *   setKeys: set letter → {@link setKey}
 * @returns {RolloutRow[]}
 */
export function rolloutRows(result, { plan = null, setKeys = null } = {}) {
  const r = result && typeof result === 'object' ? result : {};
  const rows = [];
  if (plan && Array.isArray(plan.rows) && Array.isArray(plan.sets)) {
    for (const pr of plan.rows) {
      if (!pr || !pr.needsCert || (pr.server && pr.server.terminatesTls === false)) continue;
      for (const s of plan.sets) {
        const entries = ((pr.cells && pr.cells[s.id]) || []).filter((e) => e && e.via !== 'hint');
        if (!entries.length) continue;
        const targets = [];
        for (const e of entries) {
          for (const ip of e.ips || []) for (const port of pr.server ? portsOf(pr.server, ip) : [DEFAULT_PORT]) addTarget(targets, ip, port);
        }
        const key = (setKeys && setKeys.get(s.id)) || s.id;
        rows.push({
          key: `${pr.key}#${key}`, server: pr.server ? serverOf(pr.server) : null, ip: pr.server ? null : pr.ip,
          private: !!pr.private, set: s.id, names: uniq(entries.map((e) => e.name)), targets
        });
      }
    }
    return rows;
  }
  for (const g of Array.isArray(r.servers) ? r.servers : []) {
    const s = g && g.server;
    if (!s || !g.needsCert || s.terminatesTls === false) continue;
    const hosts = (g.hosts || []).filter((x) => x && x.covered && x.via !== 'hint');
    const targets = [];
    for (const x of hosts) {
      if (x.port) addTarget(targets, x.ip, x.port);
      else for (const port of portsOf(s, x.ip)) addTarget(targets, x.ip, port);
    }
    rows.push({ key: `s:${serverOf(s).id}`, server: serverOf(s), ip: null, private: false, set: null, names: uniq(hosts.map((x) => x.name)), targets });
  }
  const byName = new Map((Array.isArray(r.hosts) ? r.hosts : []).map((x) => [x.name, x]));
  for (const u of Array.isArray(r.unmatchedIps) ? r.unmatchedIps : []) {
    const names = (u.hosts || []).filter((n) => {
      const host = byName.get(n);
      return host && host.cert && host.cert.covered && !host.wildcardSuspect;
    });
    if (!names.length) continue;
    rows.push({ key: `ip:${u.ip}`, server: null, ip: u.ip, private: !!u.private, set: null, names: uniq(names), targets: [{ ip: u.ip, port: DEFAULT_PORT }] });
  }
  return rows;
}

/* ------------------------------------------------------------------------ */
/* The stored boards                                                         */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} SavedRow
 * @property {string} k row key
 * @property {string} n what the row is called (the server name or the address)
 * @property {string|null} s the set's letter when it was saved
 * @property {string|null} i installed at (ISO 8601)
 * @property {string|null} r reloaded at
 * @property {string|null} v verified at
 * @property {'verify'|null} a 'verify': the Verify tab marked it verified
 * @property {string|null} m the user's last change of the row
 *
 * @typedef {{ id: string, label: string, created: string, updated: string, rows: SavedRow[] }} Board
 * @typedef {{ v: 1, boards: Board[] }} RolloutState
 */

const iso = (v) => {
  if (typeof v !== 'string' || v.length > 40) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
};
const ms = (v) => (v ? Date.parse(v) : 0) || 0;
const text = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').trim().slice(0, max) : '');

/** An empty state. */
export function emptyRollout() {
  return { v: 1, boards: [] };
}

function sanitizeRow(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const k = text(raw.k, 600);
  if (!k) return null;
  return {
    k, n: text(raw.n, ROLLOUT_LIMITS.name), s: text(raw.s, 8) || null,
    i: iso(raw.i), r: iso(raw.r), v: iso(raw.v), a: raw.a === 'verify' && iso(raw.v) ? 'verify' : null, m: iso(raw.m)
  };
}

function sanitizeBoard(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = typeof raw.id === 'string' && raw.id.length <= 65 * 64 ? boardId(raw.id.split(',')) : null;
  if (!id || id !== raw.id.toLowerCase()) return null;
  const rows = [];
  const seen = new Set();
  for (const r of Array.isArray(raw.rows) ? raw.rows.slice(0, ROLLOUT_LIMITS.rows * 2) : []) {
    const row = sanitizeRow(r);
    if (!row || seen.has(row.k) || rows.length >= ROLLOUT_LIMITS.rows) continue;
    seen.add(row.k);
    rows.push(row);
  }
  const created = iso(raw.created) || iso(raw.updated) || new Date(0).toISOString();
  return { id, label: text(raw.label, ROLLOUT_LIMITS.label), created, updated: iso(raw.updated) || created, rows };
}

/**
 * The stored text read back, every field checked; anything unreadable is left out.
 * @param {unknown} value the workspace part (JSON text), or an already parsed object
 * @returns {RolloutState}
 */
export function parseRollout(value) {
  let src = value;
  if (typeof value === 'string') {
    if (!value.trim()) return emptyRollout();
    try {
      src = JSON.parse(value);
    } catch {
      return emptyRollout();
    }
  }
  if (!src || typeof src !== 'object' || src.v !== 1 || !Array.isArray(src.boards)) return emptyRollout();
  const boards = [];
  for (const b of src.boards.slice(0, ROLLOUT_LIMITS.boards * 2)) {
    const board = sanitizeBoard(b);
    if (board && !boards.some((x) => x.id === board.id)) boards.push(board);
  }
  boards.sort((a, b) => ms(b.updated) - ms(a.updated));
  return { v: 1, boards: boards.slice(0, ROLLOUT_LIMITS.boards) };
}

/**
 * The state as the workspace part stores it: JSON text of at most ROLLOUT_LIMITS.chars characters
 * (the boards changed longest ago are dropped first, then the last rows of the only board left);
 * '' when there is no board (an empty part is not stored).
 * @param {RolloutState} state
 * @returns {string}
 */
export function serializeRollout(state) {
  const s = parseRollout(state);
  const boards = s.boards.filter((b) => b.rows.length);
  if (!boards.length) return '';
  let out = JSON.stringify({ v: 1, boards });
  while (out.length > ROLLOUT_LIMITS.chars && boards.length > 1) {
    boards.pop();
    out = JSON.stringify({ v: 1, boards });
  }
  while (out.length > ROLLOUT_LIMITS.chars && boards[0].rows.length) {
    const cut = Math.max(1, Math.ceil(boards[0].rows.length * (1 - ROLLOUT_LIMITS.chars / out.length)));
    boards[0] = { ...boards[0], rows: boards[0].rows.slice(0, -cut) };
    out = JSON.stringify({ v: 1, boards });
  }
  return boards[0].rows.length ? out : '';
}

/**
 * One board of the state, or null.
 * @param {RolloutState} state
 * @param {string} id
 * @returns {Board|null}
 */
export function findBoard(state, id) {
  return (state && Array.isArray(state.boards) ? state.boards : []).find((b) => b.id === id) || null;
}

/** The state with this board replaced (or added), as the most recently changed one. */
function putBoard(state, board) {
  const others = (state.boards || []).filter((b) => b.id !== board.id);
  return { v: 1, boards: [board, ...others].slice(0, ROLLOUT_LIMITS.boards) };
}

const rowName = (row) => (row.server ? row.server.name : row.ip) || row.key;

/**
 * A step of one row ticked or unticked by the user: the earlier steps follow a tick, the later ones
 * an untick. The board is created on its first tick.
 * @param {RolloutState} state
 * @param {{ id: string, label?: string }} board
 * @param {RolloutRow|{ key: string, name?: string }} row
 * @param {string} step one of {@link ROLLOUT_STEPS}
 * @param {boolean} on
 * @param {{ now?: () => number }} [opts]
 * @returns {RolloutState}
 */
export function setStep(state, board, row, step, on, { now = Date.now } = {}) {
  const s = parseRollout(state);
  const idx = ROLLOUT_STEPS.indexOf(step);
  const id = board && boardId(String(board.id || '').split(','));
  if (idx < 0 || !id || !row || !row.key) return s;
  const at = new Date(now()).toISOString();
  const prev = findBoard(s, id);
  const b = prev ? { ...prev, rows: [...prev.rows] } : { id, label: text(board.label, ROLLOUT_LIMITS.label), created: at, updated: at, rows: [] };
  let i = b.rows.findIndex((r) => r.k === row.key);
  if (i < 0) {
    if (!on || b.rows.length >= ROLLOUT_LIMITS.rows) return s;
    b.rows.push({ k: row.key, n: text(row.name || rowName(row), ROLLOUT_LIMITS.name), s: row.set || null, i: null, r: null, v: null, a: null, m: null });
    i = b.rows.length - 1;
  }
  const r = { ...b.rows[i], m: at };
  const fields = ['i', 'r', 'v'];
  if (on) {
    for (let j = 0; j <= idx; j++) if (!r[fields[j]]) r[fields[j]] = at;
    if (idx === 2 && !b.rows[i].v) r.a = null;
  } else {
    for (let j = idx; j < fields.length; j++) r[fields[j]] = null;
    if (!r.v) r.a = null;
  }
  b.rows[i] = r;
  b.updated = at;
  return putBoard(s, b);
}

/**
 * The board without any tick (removed from the state).
 * @param {RolloutState} state
 * @param {string} id
 * @returns {RolloutState}
 */
export function resetBoard(state, id) {
  const s = parseRollout(state);
  return { v: 1, boards: s.boards.filter((b) => b.id !== id) };
}

/* ------------------------------------------------------------------------ */
/* What the Verify tab saw                                                   */
/* ------------------------------------------------------------------------ */

/**
 * What the Verify tab's checks say about each row: 'confirmed' (every check on that server — and
 * set — saw the new certificate), 'old' (only old or other certificates), 'mixed' (some did),
 * 'other' (no verdict about the certificate: not hosted, closed, a TLS error…) or 'unchecked'.
 * @param {object[]} verifyRows lib/verify.js VerifyRow[] (`run.verify.rows`)
 * @param {RolloutRow[]} rows
 * @returns {Map<string, { status: string, at: string|null, updated: number, checked: number }>}
 */
export function verifyStatus(verifyRows, rows) {
  const out = new Map();
  const done = (Array.isArray(verifyRows) ? verifyRows : []).filter((v) => v && v.state === 'done' && v.status);
  for (const row of Array.isArray(rows) ? rows : []) {
    const mine = done.filter((v) => {
      if (row.set && v.setId && v.setId !== row.set) return false;
      if (row.server) return (v.server && v.server.id === row.server.id) || (v.alsoServers || []).some((x) => x && x.id === row.server.id);
      return !v.server && v.ip === row.ip;
    });
    const updated = mine.filter((v) => v.status === 'UPDATED').length;
    const old = mine.filter((v) => v.status === 'NEEDS_UPDATE').length;
    let status = 'unchecked';
    if (mine.length) {
      if (updated === mine.length) status = 'confirmed';
      else if (updated) status = 'mixed';
      else status = old ? 'old' : 'other';
    }
    const times = mine.map((v) => (v.checkedAt instanceof Date ? v.checkedAt.getTime() : ms(v.checkedAt))).filter((t) => t > 0);
    out.set(row.key, { status, at: times.length ? new Date(Math.max(...times)).toISOString() : null, updated, checked: mine.length });
  }
  return out;
}

/**
 * The rows the Verify tab confirmed, marked verified (with the earlier steps) when its check is
 * newer than the user's last change of the row; a row it marked before, unmarked when a newer
 * check saw an old certificate. Rows the user ticked are never changed.
 * @param {RolloutState} state
 * @param {{ id: string, label?: string }} board
 * @param {RolloutRow[]} rows
 * @param {Map<string, { status: string, at: string|null }>} statuses {@link verifyStatus}
 * @returns {{ state: RolloutState, marked: string[], unmarked: string[] }}
 */
export function applyVerify(state, board, rows, statuses) {
  const s = parseRollout(state);
  const id = board && boardId(String(board.id || '').split(','));
  const marked = [];
  const unmarked = [];
  if (!id || !(statuses instanceof Map)) return { state: s, marked, unmarked };
  const prev = findBoard(s, id);
  const b = prev ? { ...prev, rows: [...prev.rows] } : null;
  let changed = false;
  let next = b;
  let latest = null;
  for (const row of Array.isArray(rows) ? rows : []) {
    const st = statuses.get(row.key);
    if (!st || !st.at) continue;
    const at = st.at;
    const i = next ? next.rows.findIndex((r) => r.k === row.key) : -1;
    const saved = i >= 0 ? next.rows[i] : null;
    if (st.status === 'confirmed') {
      if (saved && (saved.v || ms(saved.m) >= ms(at))) continue;
      if (!next) next = { id, label: text(board.label, ROLLOUT_LIMITS.label), created: at, updated: at, rows: [] };
      if (!saved && next.rows.length >= ROLLOUT_LIMITS.rows) continue;
      const r = saved ? { ...saved } : { k: row.key, n: text(rowName(row), ROLLOUT_LIMITS.name), s: row.set || null, i: null, r: null, v: null, a: null, m: null };
      r.i = r.i || at;
      r.r = r.r || at;
      r.v = at;
      r.a = 'verify';
      if (saved) next.rows[i] = r;
      else next.rows.push(r);
      marked.push(row.key);
      changed = true;
    } else if ((st.status === 'old' || st.status === 'mixed') && saved && saved.a === 'verify' && ms(at) > ms(saved.v)) {
      next.rows[i] = { ...saved, v: null, a: null };
      unmarked.push(row.key);
      changed = true;
    } else continue;
    if (!latest || ms(at) > ms(latest)) latest = at;
  }
  if (!changed) return { state: s, marked, unmarked };
  next.updated = latest && ms(latest) > ms(next.updated) ? latest : next.updated;
  return { state: putBoard(s, next), marked, unmarked };
}

/* ------------------------------------------------------------------------ */
/* The board as shown                                                        */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {RolloutRow & { name: string, installed: string|null, reloaded: string|null, verified: string|null,
 *   verifiedBy: 'verify'|'manual'|null, stage: string, saved: boolean, verify: { status: string, at: string|null }|null }} BoardRow
 *   `saved`: a row of the stored board that this scan did not find (kept with its ticks)
 */

/**
 * The rows of the scan with their ticks, then the stored rows the scan did not find.
 * @param {RolloutState} state
 * @param {string|null} id the board id
 * @param {RolloutRow[]} rows
 * @param {Map<string, object>} [statuses] {@link verifyStatus}
 * @returns {BoardRow[]}
 */
export function boardRows(state, id, rows, statuses = new Map()) {
  const board = id ? findBoard(parseRollout(state), id) : null;
  const saved = new Map((board ? board.rows : []).map((r) => [r.k, r]));
  const out = [];
  const withTicks = (row, r) => ({
    ...row, name: rowName(row) || (r && r.n) || row.key,
    installed: r ? r.i : null, reloaded: r ? r.r : null, verified: r ? r.v : null,
    verifiedBy: r && r.v ? (r.a === 'verify' ? 'verify' : 'manual') : null,
    stage: !r ? 'todo' : r.v ? 'verified' : r.r ? 'reloaded' : r.i ? 'installed' : 'todo',
    verify: statuses.get(row.key) || null
  });
  for (const row of Array.isArray(rows) ? rows : []) out.push({ ...withTicks(row, saved.get(row.key)), saved: false });
  const seen = new Set(out.map((r) => r.key));
  for (const r of saved.values()) {
    if (seen.has(r.k) || (!r.i && !r.r && !r.v)) continue;
    const ip = r.k.startsWith('ip:') ? r.k.slice(3).split('#')[0] : null;
    out.push({
      ...withTicks({ key: r.k, server: ip ? null : { id: r.k.slice(2).split('#')[0], name: r.n, ips: [] }, ip, private: false, set: r.s, names: [], targets: [] }, r),
      name: r.n || r.k, saved: true
    });
  }
  return out;
}

/**
 * Progress counts of the board's rows.
 * @param {BoardRow[]} rows
 * @returns {{ total: number, installed: number, reloaded: number, verified: number, auto: number, todo: number }}
 */
export function rolloutProgress(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const count = (pred) => list.filter(pred).length;
  return {
    total: list.length,
    installed: count((r) => !!r.installed),
    reloaded: count((r) => !!r.reloaded),
    verified: count((r) => !!r.verified),
    auto: count((r) => r.verifiedBy === 'verify'),
    todo: count((r) => r.stage === 'todo')
  };
}

/**
 * The board as CSV rows for {@link ROLLOUT_CSV_COLUMNS}.
 * @param {BoardRow[]} rows
 * @returns {object[]}
 */
export function rolloutCsvRows(rows) {
  return (Array.isArray(rows) ? rows : []).map((r) => ({
    server: r.server ? r.server.name : '',
    address: r.server ? '' : r.ip || '',
    set: r.set || '',
    targets: (r.targets || []).map((t) => (t.ip.includes(':') ? `[${t.ip}]:${t.port}` : `${t.ip}:${t.port}`)),
    names: r.names || [],
    stage: r.stage,
    installed: r.installed || '',
    reloaded: r.reloaded || '',
    verified: r.verified || '',
    verifiedBy: r.verifiedBy || '',
    verify: r.verify ? r.verify.status : ''
  }));
}
