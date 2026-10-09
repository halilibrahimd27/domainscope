/**
 * regstatus.js — a domain's registry statuses read for risk (RFC 8056 / EPP / RFC 9083): the flags
 * with their kind, the critical ones, the depth of its lock and the risk. The Domain portfolio,
 * Domain overview and Home share these rules, so none has a copy of its own; lib/portfolio.js and
 * lib/passport.js re-export them (split out of them like lib/ip.js out of lib/netinfo.js, so Home
 * reads registrations without the portfolio's lookups).
 *
 * Pure: no DOM, network, clock or i18n.
 */

import { uniq } from './util.js';

/**
 * Registry statuses that put the domain at risk now (RFC 8056 / EPP, matched case-free with or
 * without spaces): a hold takes it out of DNS, redemption and pending delete mean it is being lost.
 */
export const CRITICAL_STATUSES = Object.freeze(['serverHold', 'clientHold', 'redemptionPeriod', 'pendingDelete']);

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const squash = (s) => canon(s).replace(/[\s_-]+/g, '');

/**
 * The RDAP status values (RFC 8056's mapping of the EPP statuses, RFC 9083's own): a registry that
 * writes EPP's spelling ('clientTransferProhibited', lower-cased by lib/rdap.js) is said in this one.
 */
const RDAP_STATUS_NAMES = new Map([
  'active', 'inactive', 'associated', 'validated', 'locked', 'proxy', 'private', 'removed', 'obscured',
  'add period', 'auto renew period', 'renew period', 'transfer period', 'redemption period',
  'pending create', 'pending delete', 'pending renew', 'pending restore', 'pending transfer', 'pending update',
  'client delete prohibited', 'client hold', 'client renew prohibited', 'client transfer prohibited', 'client update prohibited',
  'server delete prohibited', 'server hold', 'server renew prohibited', 'server transfer prohibited', 'server update prohibited',
  'delete prohibited', 'renew prohibited', 'transfer prohibited', 'update prohibited'
].map((name) => [name.replace(/ /g, ''), name]));

/**
 * A status in its RDAP spelling when it is a known one (any case or spacing), else as written.
 * @param {string} status
 * @returns {string}
 */
export function statusName(status) {
  return RDAP_STATUS_NAMES.get(squash(status)) || status;
}

/**
 * Registry status → what it means for the domain ('lock': a *Prohibited flag, 'hold', 'pending',
 * 'ok', 'other'), in RFC 8056 wording ('client hold') or EPP's ('clientHold') alike.
 */
function statusKind(status) {
  const s = canon(status);
  if (/prohibited/.test(s)) return 'lock';
  if (/hold\b/.test(s)) return 'hold';
  if (/pending|redemption/.test(s)) return 'pending';
  if (s === 'ok' || s === 'active' || s === 'associated') return 'ok';
  return 'other';
}

/**
 * RDAP status values with their kind: holds and pending deletes first, then locks. `code` is
 * spelled as the registry sent it (RFC 8056's 'client transfer prohibited' or EPP's
 * 'clientTransferProhibited'); a value repeated in another case counts once.
 * @param {string[]} statuses
 * @returns {Array<{ code: string, kind: 'lock'|'hold'|'pending'|'ok'|'other' }>}
 */
export function rdapStatusFlags(statuses) {
  const order = { hold: 0, pending: 1, lock: 2, ok: 3, other: 4 };
  const seen = new Set();
  const flags = [];
  for (const status of statuses || []) {
    const code = String(status ?? '').trim();
    const key = canon(code);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    flags.push({ code, kind: statusKind(key) });
  }
  return flags.sort((a, b) => order[a.kind] - order[b.kind] || canon(a.code).localeCompare(canon(b.code), 'en'));
}

/** How deeply a domain can be locked ({@link lockLevel}), weakest first: what lib/policy.js `lock.level` orders. */
export const LOCK_LEVELS = Object.freeze(['none', 'registrar-transfer', 'registrar-full', 'registry-partial', 'registry']);
/** The three prohibitions a lock is made of, in the order a status list says them. */
const LOCK_OPS = Object.freeze(['transfer', 'update', 'delete']);

/**
 * How deeply a domain is locked, from its registry statuses (RFC 8056's spelling with spaces,
 * "client transfer prohibited", or EPP's camelCase, "clientTransferProhibited"; any case):
 * - 'registry': server transfer, update and delete prohibited — a registry lock: the registry
 *   itself refuses transfers, changes and deletion (RFC 5731) until the registrar's out-of-band
 *   request lifts it, so a hijacked registrar account cannot;
 * - 'registry-partial': some of those, not all three. serverTransferProhibited alone is also what
 *   a registry sets during a dispute or for the 60-day lock after a transfer: no registry lock;
 * - 'registrar-full': client transfer, update and delete prohibited (the registrar's lock);
 * - 'registrar-transfer': client transfer prohibited, without both update and delete;
 * - 'none': transfers are not prohibited at all — whatever else is set (a server delete
 *   prohibition alone), anyone with the transfer code can move the domain to another registrar.
 * RFC 9083's plain prohibitions ("transfer prohibited", neither client nor server) count as the
 * registrar's: who set them is not said, and only a server status is the registry's.
 * @param {string[]} statuses as RDAP lists them
 * @returns {'none'|'registrar-transfer'|'registrar-full'|'registry-partial'|'registry'}
 */
export function lockLevel(statuses) {
  const keys = new Set((Array.isArray(statuses) ? statuses : []).map(squash));
  const server = LOCK_OPS.filter((op) => keys.has(`server${op}prohibited`));
  const client = LOCK_OPS.filter((op) => keys.has(`client${op}prohibited`) || keys.has(`${op}prohibited`));
  if (!server.includes('transfer') && !client.includes('transfer')) return 'none';
  if (server.length === LOCK_OPS.length) return 'registry';
  if (server.length) return 'registry-partial';
  return client.length === LOCK_OPS.length ? 'registrar-full' : 'registrar-transfer';
}

/**
 * The registry statuses read for risk: the flags as {@link rdapStatusFlags} orders them, the
 * critical ones ({@link CRITICAL_STATUSES}), whether transfers are prohibited —
 * clientTransferProhibited (the registrar's lock), serverTransferProhibited (the registry's: RFC 5731
 * says transfer requests MUST be rejected) or RFC 9083's plain "transfer prohibited", as Domain
 * overview and Domain Health read it (null when the registry reports no status at all) —, the
 * statuses that say so (in their RDAP spelling, as every status here), the lock's depth
 * ({@link lockLevel}), the registry lock — server transfer, update and delete prohibited, all three —
 * with the server prohibitions that are set, and the risk: 'critical' (a critical status), 'hijack'
 * (no transfer prohibition at all: anyone with the transfer code can move the domain to another
 * registrar), 'ok', or null without statuses; 'pending-transfer' (a transfer under way: a hijack in
 * progress if nobody here asked for it) comes right after 'critical'.
 * @param {string[]} statuses as RDAP lists them ('client transfer prohibited' or 'clientTransferProhibited')
 * @returns {{ flags: Array<{ code: string, kind: string }>, critical: string[], transferLock: boolean|null,
 *   registryLock: boolean|null, lockLevel: string|null, serverLocks: string[], transferCodes: string[],
 *   risk: 'critical'|'pending-transfer'|'hijack'|'ok'|null }} `serverLocks`: 'server transfer prohibited',
 *   'server update prohibited', 'server delete prohibited' as far as they are set
 */
export function statusRisk(statuses) {
  // each status once, in its RDAP spelling: EPP's clientTransferProhibited arrives lower-cased from lib/rdap.js
  const list = uniq((Array.isArray(statuses) ? statuses : []).map((s) => statusName(String(s ?? '').trim())).filter(Boolean));
  const keys = new Set(list.map(squash));
  const critical = CRITICAL_STATUSES.filter((c) => keys.has(c.toLowerCase()));
  const known = list.length > 0;
  const transferCodes = list.filter((s) => squash(s).includes('transferprohibited'));
  const transferLock = known ? transferCodes.length > 0 : null;
  const serverLocks = LOCK_OPS.filter((op) => keys.has(`server${op}prohibited`)).map((op) => `server ${op} prohibited`);
  // A registry lock is all three server prohibitions: serverTransferProhibited alone is also set
  // during a dispute or the 60-day lock after a transfer.
  const registryLock = known ? serverLocks.length === LOCK_OPS.length : null;
  let risk = null;
  if (critical.length) risk = 'critical';
  // a transfer under way: a hijack in progress if nobody here asked for it
  else if (keys.has('pendingtransfer')) risk = 'pending-transfer';
  else if (known) risk = transferLock ? 'ok' : 'hijack';
  return {
    flags: rdapStatusFlags(list), critical, transferLock, registryLock, lockLevel: known ? lockLevel(list) : null, serverLocks, transferCodes, risk
  };
}
