/**
 * portfolio.js — "Domain portfolio": many domains, one row each (ROADMAP P2.6). Per domain:
 * registration (RDAP: expiry with the days left, the status flags read for risk — no transfer
 * prohibition at all (client, server or RFC 9083's plain one) is a hijack risk, serverHold /
 * clientHold / redemptionPeriod / pendingDelete are critical —, the registrar), DNSSEC (DS at the parent, validated by the
 * resolver), the name servers' own registrable domains with THEIR expiry (a name server domain that
 * lapses is a classic takeover: whoever registers it answers for the zone), CAA, and the mail
 * posture: SPF (valid, within 10 lookups), DMARC, DKIM at a few common selectors, MTA-STS and
 * TLS-RPT, and for a domain that takes no mail the parked lock-down (null MX, `-all`, `p=reject`).
 *
 * - Lookups ({@link PORTFOLIO_LOOKUPS}) go through the page's DohClient (each question once per
 *   domain, lib/passport.js passportDns) and lib/rdap.js: straight to the registry's server from
 *   the IANA bootstrap, rdap.org only as its paced fallback. RDAP is asked once per distinct domain
 *   of the run — a portfolio domain and a name server domain alike — with at most
 *   {@link RDAP_CONCURRENCY} requests in flight; {@link PORTFOLIO_CONCURRENCY} domains run at once.
 * - {@link createPortfolio} runs them, reports each lookup as it lands (rows fill progressively),
 *   stops with its signal, and asks one row's failed lookups (or one name server domain's RDAP)
 *   again past the DNS cache.
 * - {@link portfolioFacts} turns one row's results into facts: codes and values, never text (the
 *   view and lib/policy.js word them); a lookup that failed is a lib/sourcestatus.js status on
 *   its part, never "none".
 * - {@link expiryEvents}: the dates for the calendar file (lib/ics.js), one per domain.
 *
 * DOM-free; runs in browsers and Node 22 (the headless runner's `audit`, tools/ds). Every network
 * call takes the injected `dns` client or `fetchImpl` and the caller's signal; only an abort rejects.
 */

import { errorKind, throwIfAborted, uniq, createLimiter, randomLabel } from './util.js';
import { isSubdomainOf } from './domain.js';
import { rdapDomain, registryDomain } from './rdap.js';
import { spfLookupCount, parseDkim, SPF_LOOKUP_LIMIT } from './health.js';
import { passportDomain, passportDns, runLookup, mailCard, certsCard, rdapStatusFlags, registryWhois, lookupStatus } from './passport.js';

/** At most this many domains in one run (the rest are said and left out). */
export const PORTFOLIO_MAX_DOMAINS = 300;
/** Domains looked up at once (each one's DNS questions go through the DohClient's own limit). */
export const PORTFOLIO_CONCURRENCY = 4;
/** RDAP requests in flight at once (registry servers; rdap.org is paced by lib/rdap.js). */
export const RDAP_CONCURRENCY = 4;
/** DKIM selectors asked when the DKIM option is on: the most common ones only (one TXT query each). */
export const PORTFOLIO_DKIM_SELECTORS = Object.freeze(['google', 'selector1', 'selector2', 'default', 'k1', 's1', 'dkim', 'mail']);

/** Every lookup of a row. `spf` counts the SPF record's DNS lookups (after `txt`). */
export const PORTFOLIO_LOOKUPS = Object.freeze(['rdap', 'ns', 'ds', 'dnskey', 'caa', 'mx', 'txt', 'dmarc', 'spf', 'dkim', 'mtaSts', 'tlsRpt']);
/** Which service each lookup asks (a Retry button names it). */
export const LOOKUP_SOURCES = Object.freeze(Object.fromEntries(PORTFOLIO_LOOKUPS.map((id) => [id, id === 'rdap' ? 'rdap' : 'doh'])));

/** The columns of a row, in table order. */
export const PORTFOLIO_CELLS = Object.freeze(['expiry', 'status', 'registrar', 'dnssec', 'ns', 'caa', 'spf', 'dmarc', 'dkim', 'mtaSts', 'parked']);
/** The lookups each column is built from; a column's Retry asks only its failed ones. */
export const CELL_LOOKUPS = Object.freeze({
  expiry: Object.freeze(['rdap']),
  status: Object.freeze(['rdap']),
  registrar: Object.freeze(['rdap']),
  dnssec: Object.freeze(['ds', 'dnskey']),
  ns: Object.freeze(['ns']),
  caa: Object.freeze(['caa']),
  spf: Object.freeze(['txt', 'spf']),
  dmarc: Object.freeze(['dmarc']),
  dkim: Object.freeze(['dkim']),
  mtaSts: Object.freeze(['mtaSts', 'tlsRpt']),
  parked: Object.freeze(['mx', 'txt', 'dmarc'])
});

/**
 * Registry statuses that put the domain at risk now (RFC 8056 / EPP, matched case-free with or
 * without spaces): a hold takes it out of DNS, redemption and pending delete mean it is being lost.
 */
export const CRITICAL_STATUSES = Object.freeze(['serverHold', 'clientHold', 'redemptionPeriod', 'pendingDelete']);

const DAY_MS = 86400000;
const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const squash = (s) => canon(s).replace(/[\s_-]+/g, '');
const clock = (now) => (now instanceof Date ? now : new Date(Number.isFinite(now) ? now : Date.now()));
const isAbort = (err) => errorKind(err) === 'abort';

/* ------------------------------------------------------------------------ */
/* Input                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The domains of a pasted list: one or more per line (spaces, commas or semicolons between them,
 * `#` comments), each reduced to its registrable domain (a host name or URL names its domain),
 * de-duplicated in input order, at most `max`.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {{ domains: string[], reduced: Array<{ input: string, domain: string }>, invalid: string[], capped: number }}
 *   `capped`: how many valid domains were left out past `max`
 */
export function parsePortfolioInput(text, { max = PORTFOLIO_MAX_DOMAINS } = {}) {
  const tokens = String(text ?? '').split(/\r?\n/).map((line) => line.replace(/#.*$/, ''))
    .flatMap((line) => line.split(/[\s,;]+/)).map((s) => s.trim()).filter(Boolean);
  const domains = [];
  const reduced = [];
  const invalid = [];
  const left = new Set();
  for (const token of tokens) {
    const p = passportDomain(token);
    if (!p) {
      if (!invalid.includes(token)) invalid.push(token);
      continue;
    }
    if (domains.includes(p.domain)) continue;
    if (domains.length >= max) {
      left.add(p.domain);
      continue;
    }
    domains.push(p.domain);
    if (p.host) reduced.push({ input: p.host, domain: p.domain });
  }
  return { domains, reduced, invalid, capped: left.size };
}

/* ------------------------------------------------------------------------ */
/* Registry statuses                                                        */
/* ------------------------------------------------------------------------ */

/**
 * The registry statuses read for risk: the flags as lib/passport.js orders them, the critical ones
 * ({@link CRITICAL_STATUSES}), whether transfers are prohibited — clientTransferProhibited (the
 * registrar's lock), serverTransferProhibited (the registry's: RFC 5731 says transfer requests MUST
 * be rejected) or RFC 9083's plain "transfer prohibited", as Domain overview and Domain Health read
 * it (null when the registry reports no status at all) —, the statuses that say so, the registry
 * lock alone, and the risk: 'critical' (a critical status), 'hijack' (no transfer prohibition at
 * all: anyone with the transfer code can move the domain to another registrar), 'ok', or null
 * without statuses; 'pending-transfer' (a transfer under way: a hijack in progress if nobody here
 * asked for it) comes right after 'critical'.
 * @param {string[]} statuses as RDAP lists them ('client transfer prohibited' or 'clientTransferProhibited')
 * @returns {{ flags: Array<{ code: string, kind: string }>, critical: string[], transferLock: boolean|null,
 *   registryLock: boolean|null, transferCodes: string[], risk: 'critical'|'pending-transfer'|'hijack'|'ok'|null }}
 */
export function statusRisk(statuses) {
  const list = (Array.isArray(statuses) ? statuses : []).map((s) => String(s ?? '').trim()).filter(Boolean);
  const keys = new Set(list.map(squash));
  const critical = CRITICAL_STATUSES.filter((c) => keys.has(c.toLowerCase()));
  const known = list.length > 0;
  const transferCodes = list.filter((s) => squash(s).includes('transferprohibited'));
  const transferLock = known ? transferCodes.length > 0 : null;
  const registryLock = known ? keys.has('servertransferprohibited') : null;
  let risk = null;
  if (critical.length) risk = 'critical';
  // a transfer under way: a hijack in progress if nobody here asked for it
  else if (keys.has('pendingtransfer')) risk = 'pending-transfer';
  else if (known) risk = transferLock ? 'ok' : 'hijack';
  return { flags: rdapStatusFlags(list), critical, transferLock, registryLock, transferCodes, risk };
}

/**
 * The registrable domains of a zone's name servers, each once, with the hosts under it; `own`
 * when it is the domain itself (in-bailiwick name servers: their expiry is the domain's own).
 * @param {string[]} hosts name server host names
 * @param {string} domain the zone's domain
 * @returns {Array<{ domain: string, hosts: string[], own: boolean }>} sorted, own first
 */
export function nsDomainsOf(hosts, domain) {
  const own = canon(domain);
  const by = new Map();
  for (const h of hosts || []) {
    const host = canon(h);
    if (!host) continue;
    const d = registryDomain(host) || (isSubdomainOf(host, own) ? own : null);
    if (!d) continue;
    if (!by.has(d)) by.set(d, []);
    if (!by.get(d).includes(host)) by.get(d).push(host);
  }
  return [...by].map(([d, list]) => ({ domain: d, hosts: list.sort(), own: d === own }))
    .sort((a, b) => Number(b.own) - Number(a.own) || a.domain.localeCompare(b.domain, 'en'));
}

/* ------------------------------------------------------------------------ */
/* Lookups                                                                  */
/* ------------------------------------------------------------------------ */

/** A lookup that threw (anything but an abort): kept as its status, never as "no data". */
function thrownResult(err, source = 'doh') {
  return { failed: true, source, error: err && err.message ? String(err.message) : String(err), errorKind: errorKind(err) };
}

function txtText(data) {
  return Array.isArray(data) ? data.map(String).join('') : String(data ?? '');
}

/** Did a DNS lookup get an answer (NOERROR or NXDOMAIN)? */
function answered(res) {
  return !!res && res.ok !== false && !res.failed && (res.rcode === 'NOERROR' || res.rcode === 'NXDOMAIN');
}

/** The TXT strings of an answer at `name` (a CNAME's target counts). */
function txtRecords(res) {
  return (res && Array.isArray(res.answers) ? res.answers : []).filter((rr) => rr && rr.type === 'TXT').map((rr) => txtText(rr.data).trim());
}

/** The single SPF record of a TXT answer, or why there is none to count. */
function spfRecordOf(txt) {
  if (!answered(txt)) return { skip: 'txt' };
  const records = txtRecords(txt).filter((s) => /^v=spf1(?:\s|$)/i.test(s));
  if (!records.length) return { skip: 'none' };
  if (records.length > 1) return { skip: 'many' };
  return { record: records[0] };
}

/**
 * DKIM keys at the common selectors, and a random selector first: a `*._domainkey` wildcard (often
 * the "v=DKIM1; p=" of a domain that sends nothing) answers every selector, so its record is no key.
 */
async function lookupDkim(dns, domain, { selectors = PORTFOLIO_DKIM_SELECTORS, signal } = {}) {
  const ask = async (sel) => {
    const res = await dns.query(`${sel}._domainkey.${domain}`, 'TXT', { signal });
    if (!answered(res)) return { selector: sel, failed: true, res };
    const rec = txtRecords(res).find((s) => /(?:^|;)\s*p\s*=/i.test(s) || /^\s*v\s*=\s*DKIM1/i.test(s)) || null;
    return { selector: sel, record: rec };
  };
  const [probe, ...results] = await Promise.all([ask(`x${randomLabel(12)}`), ...selectors.map(ask)]);
  const wildcard = probe.record || null;
  const found = results.filter((r) => r.record && r.record !== wildcard);
  // No selector answered: the first failed answer says why (lib/passport.js lookupStatus reads it).
  if (results.length && results.every((r) => r.failed)) return { ...results[0].res, dkimFailed: true, asked: selectors.length };
  return {
    asked: selectors.length,
    selectors: found.filter((r) => !parseDkim(r.record).revoked).map((r) => r.selector),
    revoked: found.filter((r) => parseDkim(r.record).revoked).map((r) => r.selector),
    wildcard: !!wildcard,
    failedSelectors: results.filter((r) => r.failed).map((r) => r.selector)
  };
}

/**
 * Run one lookup of a row. DNS lookups resolve to a DnsResponse (`caa`: lib/health.js findCaa),
 * `rdap` to an rdapDomain() result (through `rdapFor`, shared by the run), `spf` to
 * `{ count, voidCount, errors }` or `{ skipped }` (it reads `raw.txt`), `dkim` to the selectors
 * found (or `{ off: true }`). Only an abort rejects.
 * @param {string} id one of {@link PORTFOLIO_LOOKUPS}
 * @param {string} domain
 * @param {{ dns: object, fetchImpl?: typeof fetch, signal?: AbortSignal, raw?: object, rdapFor: Function,
 *   dkim?: boolean, noCache?: boolean }} opts `dns`: a lib/passport.js passportDns client
 * @returns {Promise<object>}
 */
export async function runPortfolioLookup(id, domain, { dns, fetchImpl = globalThis.fetch, signal, raw = {}, rdapFor, dkim = true, noCache = false } = {}) {
  throwIfAborted(signal);
  const name = canon(domain);
  try {
    switch (id) {
      case 'rdap': return await rdapFor(name, { signal, noCache });
      case 'ns': case 'ds': case 'dnskey': case 'mx': case 'txt': case 'dmarc': case 'caa':
        return await runLookup(id, name, { dns, fetchImpl, signal });
      case 'mtaSts': return await dns.query(`_mta-sts.${name}`, 'TXT', { signal });
      case 'tlsRpt': return await dns.query(`_smtp._tls.${name}`, 'TXT', { signal });
      case 'spf': {
        const spf = spfRecordOf(raw.txt);
        if (!spf.record) return { skipped: spf.skip };
        const r = await spfLookupCount(name, { dns, signal, record: spf.record });
        return { count: r.count, voidCount: r.voidCount || 0, errors: (r.errors || []).map((e) => ({ code: e.code, domain: e.domain || null, target: e.target || null })) };
      }
      case 'dkim': return dkim ? await lookupDkim(dns, name, { signal }) : { off: true };
      default: throw new RangeError(`portfolio: unknown lookup "${id}"`);
    }
  } catch (err) {
    if (isAbort(err) || err instanceof RangeError) throw err;
    return thrownResult(err, id === 'rdap' ? 'rdap' : 'doh');
  }
}

/* ------------------------------------------------------------------------ */
/* The run                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * A portfolio run: rows in input order, RDAP shared by every domain the run meets.
 *
 *   const run = createPortfolio({ domains, dns, onEvent: (e) => redraw(e.domain) });
 *   await run.start({ signal });            // rejects with AbortError on a stop: what landed stays
 *   run.facts('example.com');               // portfolioFacts() of a row, now
 *   await run.retry('example.com', ['ns']); // its failed lookups again, past the DNS cache
 *   await run.retryRdap('example.net');     // a name server domain's RDAP again (every row reading it)
 *
 * Events (`onEvent`): `{ type: 'lookup', domain, lookup }` (a row's result landed),
 * `{ type: 'rdap', domain }` (an RDAP result landed: the row of that domain and every row whose name
 * servers are under it), `{ type: 'row', domain, state }` ('running' | 'done' | 'stopped').
 * @param {{ domains: string[], dns: object, fetchImpl?: typeof fetch, dkim?: boolean, concurrency?: number,
 *   rdapConcurrency?: number, rdapOptions?: object, onEvent?: Function }} opts `dns`: a DohClient;
 *   `rdapOptions`: passed to rdapDomain (tests: the registries' and rdap.org's pacing)
 * @returns {object}
 */
export function createPortfolio({
  domains, dns, fetchImpl = globalThis.fetch, dkim = true, concurrency = PORTFOLIO_CONCURRENCY,
  rdapConcurrency = RDAP_CONCURRENCY, rdapOptions = {}, onEvent = null
}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('A DNS client with query(name, type, opts) is required');
  const order = uniq((domains || []).map(canon).filter(Boolean));
  const rows = new Map(order.map((d, index) => [d, { domain: d, index, raw: { domain: d }, state: 'queued', retrying: new Set() }]));
  /** domain → { promise } of its RDAP lookup (portfolio and name server domains alike). */
  const memo = new Map();
  /** domain → rdapDomain() result, as each lands. */
  const rdap = new Map();
  /** name server domain → the portfolio domains whose zones it serves. */
  const nsUsers = new Map();
  const rdapLimiter = createLimiter(rdapConcurrency);
  const run = { status: 'idle', startedAt: null, finishedAt: null, dkim };

  const emit = (e) => {
    if (typeof onEvent !== 'function') return;
    try {
      onEvent(e);
    } catch {
      // observer errors are ignored
    }
  };

  function rdapFor(domain, { signal, noCache = false } = {}) {
    const d = canon(domain);
    const hit = memo.get(d);
    if (hit && !noCache) return hit.promise;
    const entry = {};
    entry.promise = rdapLimiter.run(() => rdapDomain(d, { fetchImpl, signal, ...rdapOptions }), { signal }).then((result) => {
      if (memo.get(d) === entry) rdap.set(d, result);
      emit({ type: 'rdap', domain: d });
      return result;
    }, (err) => {
      if (memo.get(d) === entry) memo.delete(d);
      throw err;
    });
    memo.set(d, entry);
    return entry.promise;
  }

  /** The name server domains of a row once its NS lookup landed, each asked once for the run. */
  async function nsDomains(row, { signal, noCache = false }) {
    const res = row.raw.ns;
    if (!answered(res)) return;
    const hosts = (res.answers || []).filter((rr) => rr.type === 'NS').map((rr) => canon(rr.data)).filter(Boolean);
    const list = nsDomainsOf(hosts, row.domain);
    for (const d of list) {
      if (!nsUsers.has(d.domain)) nsUsers.set(d.domain, new Set());
      nsUsers.get(d.domain).add(row.domain);
    }
    // Once per run whatever asks: a Retry of the NS answer does not ask a known domain's RDAP again
    // (retryRdap does, for one whose RDAP failed).
    await Promise.all(list.filter((d) => !d.own).map((d) => rdapFor(d.domain, { signal }).catch((err) => {
      if (isAbort(err)) throw err;
    })));
  }

  async function runRow(row, { signal, lookups = PORTFOLIO_LOOKUPS, noCache = false }) {
    const client = passportDns(dns, { signal, noCache });
    const land = (id, result) => {
      row.raw[id] = result;
      emit({ type: 'lookup', domain: row.domain, lookup: id });
    };
    const one = async (id) => {
      const result = await runPortfolioLookup(id, row.domain, { dns: client, fetchImpl, signal, raw: row.raw, rdapFor, dkim, noCache });
      throwIfAborted(signal);
      land(id, result);
      if (id === 'ns') await nsDomains(row, { signal });
      return result;
    };
    const wantSpf = lookups.includes('spf');
    await Promise.all([
      ...lookups.filter((id) => id !== 'spf' && id !== 'txt').map(one),
      // SPF's lookup count reads the TXT answer: after it (or on the one already there).
      (async () => {
        if (lookups.includes('txt')) await one('txt');
        if (wantSpf) await one('spf');
      })()
    ]);
  }

  /**
   * Run every row (bounded: `concurrency` domains at once). Rejects with an AbortError when
   * `signal` aborts; the rows not finished are 'stopped'.
   * @param {{ signal?: AbortSignal }} [opts]
   */
  run.start = async ({ signal } = {}) => {
    run.status = 'running';
    run.startedAt = new Date();
    const limiter = createLimiter(concurrency);
    try {
      await Promise.all(order.map((d) => limiter.run(async () => {
        const row = rows.get(d);
        row.state = 'running';
        emit({ type: 'row', domain: d, state: 'running' });
        await runRow(row, { signal });
        row.state = 'done';
        emit({ type: 'row', domain: d, state: 'done' });
      }, { signal })));
      run.status = 'done';
    } catch (err) {
      if (!isAbort(err)) throw err;
      run.status = 'stopped';
      for (const row of rows.values()) {
        if (row.state !== 'done') {
          row.state = 'stopped';
          emit({ type: 'row', domain: row.domain, state: 'stopped' });
        }
      }
      throw err;
    } finally {
      run.finishedAt = new Date();
    }
  };

  /**
   * One row's lookups again, past the DNS cache (a column's Retry: its failed lookups; after a stop:
   * the ones never run). RDAP is asked again too when listed. Only an abort rejects.
   * @param {string} domain
   * @param {string[]} lookups
   * @param {{ signal?: AbortSignal }} [opts]
   */
  run.retry = async (domain, lookups, { signal } = {}) => {
    const row = rows.get(canon(domain));
    if (!row) throw new RangeError(`portfolio: not in this run: ${domain}`);
    const list = PORTFOLIO_LOOKUPS.filter((id) => lookups.includes(id));
    for (const id of list) row.retrying.add(id);
    try {
      await runRow(row, { signal, lookups: list, noCache: true });
      if (!list.length || PORTFOLIO_LOOKUPS.every((id) => row.raw[id] !== undefined)) {
        row.state = 'done';
        emit({ type: 'row', domain: row.domain, state: 'done' });
      }
    } finally {
      for (const id of list) row.retrying.delete(id);
    }
  };

  /**
   * A domain's RDAP again (a name server domain's, or a row's own): every row that reads it is
   * told (`rdap` event). Only an abort rejects.
   * @param {string} domain
   * @param {{ signal?: AbortSignal }} [opts]
   */
  run.retryRdap = async (domain, { signal } = {}) => {
    const d = canon(domain);
    const row = rows.get(d);
    if (row) {
      row.retrying.add('rdap');
      try {
        const result = await rdapFor(d, { signal, noCache: true });
        row.raw.rdap = result;
        emit({ type: 'lookup', domain: d, lookup: 'rdap' });
      } finally {
        row.retrying.delete('rdap');
      }
      return;
    }
    await rdapFor(d, { signal, noCache: true });
  };

  run.domains = () => [...order];
  run.row = (domain) => rows.get(canon(domain)) || null;
  /** The rows that read `domain`'s RDAP (an `rdap` event redraws them): its own and those whose name servers are under it. */
  run.affectedBy = (domain) => uniq([...(rows.has(canon(domain)) ? [canon(domain)] : []), ...(nsUsers.get(canon(domain)) || [])]);
  run.facts = (domain, { now } = {}) => {
    const row = rows.get(canon(domain));
    return row ? portfolioFacts(row.raw, { now, rdap, dkim }) : null;
  };
  run.allFacts = ({ now } = {}) => order.map((d) => run.facts(d, { now }));
  /** Lookups of a row still to land (none for a finished row). */
  run.pending = (domain) => {
    const row = rows.get(canon(domain));
    return row ? PORTFOLIO_LOOKUPS.filter((id) => row.raw[id] === undefined) : [];
  };
  return run;
}

/* ------------------------------------------------------------------------ */
/* Facts                                                                    */
/* ------------------------------------------------------------------------ */

function daysUntil(date, now) {
  return Math.floor((date.getTime() - now.getTime()) / DAY_MS);
}

/** 'expired' | 'error' (< 30 days) | 'warn' (< 60) | 'ok': Domain Health's bands. */
export function expiryBand(daysLeft) {
  if (!Number.isFinite(daysLeft)) return null;
  return daysLeft < 0 ? 'expired' : daysLeft < 30 ? 'error' : daysLeft < 60 ? 'warn' : 'ok';
}

const asDate = (v) => (v instanceof Date ? v : v ? new Date(v) : null);

/** One RDAP result as the facts keep it. */
function registrationFacts(r, now) {
  if (r === undefined) return { state: 'pending', failure: null };
  if (r.failed) return { state: 'failed', failure: lookupStatus(r, { now: now.getTime() }) };
  const base = { tld: r.tld || null, registryDomain: r.domain || null };
  if (r.unsupportedTld) return { ...base, state: 'unsupported', failure: null, whois: registryWhois(r.tld, r.domain) };
  if (r.notFound) return { ...base, state: 'not-found', failure: null };
  if (r.errorKind === 'invalid') return { ...base, state: 'invalid', failure: null };
  if (!r.ok) return { ...base, state: 'failed', failure: lookupStatus(r, { now: now.getTime() }) };
  const expires = asDate(r.expires);
  const valid = expires && !Number.isNaN(expires.getTime());
  const daysLeft = valid ? daysUntil(expires, now) : null;
  const risk = statusRisk(r.status);
  return {
    ...base,
    state: 'ok',
    failure: null,
    registrar: r.registrar || null,
    ianaId: r.registrarIanaId || null,
    registrarUrl: r.registrarUrl || null,
    expires: valid ? expires : null,
    daysLeft,
    expiry: expiryBand(daysLeft),
    statuses: Array.isArray(r.status) ? [...r.status] : [],
    ...risk,
    delegationSigned: typeof r.dnssecSigned === 'boolean' ? r.dnssecSigned : null,
    server: r.rdapServer || null
  };
}

/** The TXT policy record of MTA-STS (`v=STSv1` with an id) or TLS-RPT (`v=TLSRPTv1` with rua). */
function policyRecord(res, kind, now) {
  if (res === undefined) return { state: null, failure: null, pending: true };
  if (!answered(res)) return { state: null, failure: lookupStatus(res, { now: now.getTime() }) };
  const re = kind === 'mtaSts' ? /^v=STSv1\b/i : /^v=TLSRPTv1\b/i;
  const records = txtRecords(res).filter((s) => re.test(s));
  if (!records.length) return { state: 'none', failure: null };
  if (records.length > 1) return { state: 'invalid', failure: null };
  const ok = kind === 'mtaSts' ? /(?:^|;)\s*id\s*=\s*[A-Za-z0-9]{1,32}\s*(?:;|$)/.test(records[0]) : /(?:^|;)\s*rua\s*=\s*\S/.test(records[0]);
  return { state: ok ? 'present' : 'invalid', failure: null, record: records[0] };
}

/** The DNSSEC state of the DS and DNSKEY answers (lib/passport.js dnsCard's reading). */
function dnssecFacts(raw, now) {
  const failure = (id) => lookupStatus(raw[id], { now: now.getTime() });
  if (raw.ds === undefined) return { state: null, failure: null, pending: true };
  if (!answered(raw.ds)) return { state: null, failure: failure('ds') };
  const ds = (raw.ds.answers || []).filter((rr) => rr.type === 'DS');
  if (!ds.length) return { state: 'unsigned', failure: null, dsCount: 0 };
  let state = 'signed';
  let dnskeyFailure = null;
  if (raw.dnskey !== undefined) {
    if (!answered(raw.dnskey)) {
      // An answer with an error rcode (SERVFAIL) next to a DS: validation fails. No answer at all: not known.
      state = raw.dnskey && raw.dnskey.ok !== false && !raw.dnskey.failed ? 'failing' : 'signed';
      dnskeyFailure = failure('dnskey');
    } else if (raw.dnskey.flags && raw.dnskey.flags.ad) state = 'validated';
  }
  return { state, failure: null, dnskeyFailure, dsCount: ds.length, pending: raw.dnskey === undefined };
}

/** The name servers and their domains' expiry. */
function nsFacts(raw, own, rdap, now) {
  const res = raw.ns;
  if (res === undefined) return { state: 'pending', failure: null, hosts: [], domains: [], minDaysLeft: null };
  if (!answered(res)) return { state: 'failed', failure: lookupStatus(res, { now: now.getTime() }), hosts: [], domains: [], minDaysLeft: null };
  if (res.rcode === 'NXDOMAIN') return { state: 'nxdomain', failure: null, hosts: [], domains: [], minDaysLeft: null };
  const hosts = uniq((res.answers || []).filter((rr) => rr.type === 'NS').map((rr) => canon(rr.data)).filter(Boolean)).sort();
  if (!hosts.length) return { state: 'none', failure: null, hosts, domains: [], minDaysLeft: null };
  const domains = nsDomainsOf(hosts, raw.domain).map((d) => {
    const reg = d.own ? own : registrationFacts(rdap.get(d.domain), now);
    return {
      domain: d.domain, hosts: d.hosts, own: d.own, state: reg.state,
      expires: reg.expires || null, daysLeft: Number.isFinite(reg.daysLeft) ? reg.daysLeft : null, expiry: reg.expiry || null,
      registrar: reg.registrar || null, failure: reg.failure || null, whois: reg.whois || null, critical: reg.critical || []
    };
  });
  const days = domains.filter((d) => Number.isFinite(d.daysLeft)).map((d) => d.daysLeft);
  return { state: 'ok', failure: null, hosts, domains, minDaysLeft: days.length ? Math.min(...days) : null };
}

/**
 * One row's facts: what lib/policy.js evaluates, the table draws and the exports write. Every part
 * has a `state` (null when not known: `failure` then says why, or `pending` that it has not landed)
 * and its values. Pure.
 * @param {object} raw the row's lookup results by id, plus `domain`
 * @param {{ now?: Date|number, rdap?: Map<string, object>, dkim?: boolean }} [opts] `rdap`: the run's
 *   RDAP results of the name server domains
 * @returns {object}
 */
export function portfolioFacts(raw, { now, rdap = new Map(), dkim = true } = {}) {
  const t = clock(now);
  const r = raw || {};
  const failure = (id) => lookupStatus(r[id], { now: t.getTime() });
  const registration = registrationFacts(r.rdap, t);
  const ns = nsFacts(r, registration, rdap, t);
  const exists = ns.state !== 'nxdomain';

  const certs = certsCard({ caa: r.caa }, { now: t });
  let caa;
  if (r.caa === undefined) caa = { state: null, failure: null, pending: true };
  else if (certs.caa) {
    caa = {
      state: certs.caa.state, failure: null, foundAt: certs.caa.foundAt,
      issuers: certs.caa.issue.map((e) => e.issuer), wildIssuers: certs.caa.issuewild.map((e) => e.issuer),
      restricted: [...certs.caa.issue, ...certs.caa.issuewild].some((e) => e.restricted), criticalTags: certs.caa.criticalTags
    };
  } else caa = { state: null, failure: certs.failures[0] || null };

  const mail = mailCard({ domain: r.domain, mx: r.mx, txt: r.txt, dmarc: r.dmarc }, { now: t });
  let mx;
  if (r.mx === undefined) mx = { state: null, failure: null, pending: true };
  else if (mail.mx) mx = { state: mail.mx.state, failure: null, hosts: mail.mx.hosts.map((m) => m.exchange), platforms: mail.mx.platforms.map((p) => p.name) };
  else mx = { state: null, failure: failure('mx') };

  let spf;
  if (r.txt === undefined) spf = { state: null, failure: null, pending: true };
  else if (mail.spf) {
    const s = mail.spf;
    spf = { state: s.state, failure: null, record: s.record || null, all: s.all || null, redirect: s.redirect || null, count: s.count || null, lookups: null, lookupsState: null };
    const l = r.spf;
    if (s.state === 'ok') {
      if (l === undefined) spf.lookupsState = 'pending';
      else if (l.failed) {
        spf.lookupsState = 'failed';
        spf.lookupsFailure = lookupStatus(l, { now: t.getTime() });
      } else if (Number.isFinite(l.count)) {
        spf.lookups = l.count;
        spf.voidLookups = l.voidCount || 0;
        spf.lookupsState = (l.errors || []).some((e) => e.code === 'dns-error') ? 'partial' : 'ok';
        spf.over = l.count > SPF_LOOKUP_LIMIT;
      }
    }
  } else spf = { state: null, failure: failure('txt') };

  let dmarc;
  if (r.dmarc === undefined) dmarc = { state: null, failure: null, pending: true };
  else if (mail.dmarc) dmarc = { state: mail.dmarc.state, failure: null, policy: mail.dmarc.policy || null, pct: mail.dmarc.pct ?? null, record: mail.dmarc.record || null, count: mail.dmarc.count || null };
  else dmarc = { state: null, failure: failure('dmarc') };

  let dkimFacts;
  const k = r.dkim;
  if (k === undefined) dkimFacts = { state: null, failure: null, pending: true };
  else if (k.off || !dkim) dkimFacts = { state: 'off', failure: null };
  else if (k.failed || k.dkimFailed) dkimFacts = { state: 'failed', failure: lookupStatus(k, { now: t.getTime() }) };
  else dkimFacts = { state: k.selectors.length ? 'found' : 'none', failure: null, selectors: [...k.selectors], revoked: [...(k.revoked || [])], wildcard: !!k.wildcard, asked: k.asked };

  const mtaSts = policyRecord(r.mtaSts, 'mtaSts', t);
  const tlsRpt = policyRecord(r.tlsRpt, 'tlsRpt', t);

  // A domain that takes no mail (null MX, or no MX at all): its lock-down against spoofing.
  let parked;
  if (!mx.state) parked = { parked: null, nullMx: null, spfFail: null, dmarcReject: null, complete: null };
  else {
    const takesNoMail = mx.state === 'null' || mx.state === 'none';
    const spfFail = spf.state ? spf.state === 'ok' && spf.all === '-' : null;
    const dmarcReject = dmarc.state ? dmarc.state === 'ok' && dmarc.policy === 'reject' : null;
    const nullMx = mx.state === 'null';
    let complete = null;
    if (takesNoMail) {
      if (!nullMx || spfFail === false || dmarcReject === false) complete = false;
      else if (spfFail === null || dmarcReject === null) complete = null;
      else complete = true;
    }
    parked = { parked: takesNoMail, nullMx, spfFail, dmarcReject, complete };
  }

  return {
    domain: r.domain || null,
    exists,
    registration,
    ns,
    dnssec: dnssecFacts(r, t),
    caa,
    mx,
    spf,
    dmarc,
    dkim: dkimFacts,
    mtaSts,
    tlsRpt,
    parked
  };
}

/**
 * The failures behind a column of a row (what its "⚠ n/a" says and what its Retry asks), from the
 * facts: `{ lookup, status }` per failed lookup of the column. The name servers column also lists
 * its name server domains whose RDAP failed (`nsDomain`: their Retry asks that domain's RDAP).
 * @param {object} facts {@link portfolioFacts}
 * @param {string} column one of {@link PORTFOLIO_CELLS}
 * @returns {Array<{ lookup: string, status: object, nsDomain?: string }>}
 */
export function cellFailures(facts, column) {
  const f = facts || {};
  const out = [];
  const add = (lookup, status) => {
    if (status) out.push({ lookup, status });
  };
  switch (column) {
    case 'expiry': case 'status': case 'registrar':
      if (f.registration && f.registration.state === 'failed') add('rdap', f.registration.failure);
      break;
    case 'dnssec':
      add('ds', f.dnssec && f.dnssec.failure);
      if (f.dnssec && f.dnssec.dnskeyFailure && f.dnssec.state !== 'failing') add('dnskey', f.dnssec.dnskeyFailure);
      break;
    case 'ns':
      add('ns', f.ns && f.ns.failure);
      for (const d of (f.ns && f.ns.domains) || []) if (!d.own && d.state === 'failed' && d.failure) out.push({ lookup: 'rdap', status: d.failure, nsDomain: d.domain });
      break;
    case 'caa': add('caa', f.caa && f.caa.failure); break;
    case 'spf':
      add('txt', f.spf && f.spf.failure);
      if (f.spf && f.spf.lookupsState === 'failed') add('spf', f.spf.lookupsFailure);
      break;
    case 'dmarc': add('dmarc', f.dmarc && f.dmarc.failure); break;
    case 'dkim': add('dkim', f.dkim && f.dkim.failure); break;
    case 'mtaSts':
      add('mtaSts', f.mtaSts && f.mtaSts.failure);
      add('tlsRpt', f.tlsRpt && f.tlsRpt.failure);
      break;
    case 'parked':
      add('mx', f.mx && f.mx.failure);
      add('txt', f.spf && f.spf.failure);
      add('dmarc', f.dmarc && f.dmarc.failure);
      break;
    default:
      break;
  }
  return out;
}

/**
 * The name server domains of a row the registry says are not registered (RDAP 404): anyone can
 * register one and answer DNS for the zone — the classic name server takeover.
 * @param {object} facts {@link portfolioFacts}
 * @returns {string[]}
 */
export function unregisteredNsDomains(facts) {
  return facts && facts.ns && Array.isArray(facts.ns.domains)
    ? facts.ns.domains.filter((d) => !d.own && d.state === 'not-found').map((d) => d.domain)
    : [];
}

/**
 * The headline risk of a row, worst first: 'critical' (a critical registry status),
 * 'ns-unregistered' (a name server domain nobody has registered: as urgent), 'pending-transfer'
 * (a transfer under way), 'expired', 'expiring'
 * (< 30 days), 'ns-expiring' (a name server domain < 30 days), 'hijack' (no transfer lock), 'warn'
 * (< 60 days), 'ok', or null while nothing is known.
 * @param {object} facts
 * @returns {string|null}
 */
export function rowRisk(facts) {
  const reg = facts && facts.registration;
  const nsMin = facts && facts.ns ? facts.ns.domains.filter((d) => !d.own && Number.isFinite(d.daysLeft)).map((d) => d.daysLeft) : [];
  if (reg && reg.risk === 'critical') return 'critical';
  if (unregisteredNsDomains(facts).length) return 'ns-unregistered';
  if (reg && reg.risk === 'pending-transfer') return 'pending-transfer';
  if (reg && reg.expiry === 'expired') return 'expired';
  if (reg && reg.expiry === 'error') return 'expiring';
  if (nsMin.length && Math.min(...nsMin) < 30) return 'ns-expiring';
  if (reg && reg.risk === 'hijack') return 'hijack';
  if (reg && reg.expiry === 'warn') return 'warn';
  if (reg && reg.state === 'ok') return 'ok';
  return null;
}

/* ------------------------------------------------------------------------ */
/* Calendar and exports                                                     */
/* ------------------------------------------------------------------------ */

/**
 * The expiry dates of a portfolio for the calendar: one per domain — each portfolio domain whose
 * registry gives a date, and each name server domain of theirs (a domain that is both is one
 * entry) — soonest first. `nsOf`: the portfolio domains whose name servers are under it.
 * @param {object[]} factsList {@link portfolioFacts} per row
 * @returns {Array<{ domain: string, expires: Date, daysLeft: number, registrar: string|null, portfolio: boolean, nsOf: string[] }>}
 */
export function expiryEvents(factsList) {
  const by = new Map();
  const entry = (domain) => {
    if (!by.has(domain)) by.set(domain, { domain, expires: null, daysLeft: null, registrar: null, portfolio: false, nsOf: [] });
    return by.get(domain);
  };
  for (const f of factsList || []) {
    if (!f || !f.domain) continue;
    const reg = f.registration;
    const e = entry(f.domain);
    e.portfolio = true;
    if (reg && reg.state === 'ok' && reg.expires) {
      e.expires = reg.expires;
      e.daysLeft = reg.daysLeft;
      e.registrar = reg.registrar || null;
    }
    for (const d of (f.ns && f.ns.domains) || []) {
      if (d.own) continue;
      const n = entry(d.domain);
      if (!n.nsOf.includes(f.domain)) n.nsOf.push(f.domain);
      if (!n.expires && d.state === 'ok' && d.expires) {
        n.expires = d.expires;
        n.daysLeft = d.daysLeft;
        n.registrar = d.registrar || null;
      }
    }
  }
  return [...by.values()].filter((e) => e.expires)
    .sort((a, b) => a.expires - b.expires || a.domain.localeCompare(b.domain, 'en'));
}

/** The stable UID of a domain's expiry event: importing a newer file updates it, never adds a second. */
export function expiryUid(domain) {
  return `expiry-${canon(domain)}@domainscope`;
}

/**
 * One row as a flat export record (CSV / JSON): language-neutral codes and values.
 * @param {object} f {@link portfolioFacts}
 * @returns {object}
 */
export function exportRow(f) {
  const reg = f.registration || {};
  const iso = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : null);
  const failed = PORTFOLIO_CELLS.flatMap((c) => cellFailures(f, c).map((x) => x.nsDomain ? `rdap:${x.nsDomain}` : x.lookup));
  return {
    domain: f.domain,
    registration: reg.state || null,
    registrar: reg.registrar || null,
    expires: iso(reg.expires),
    daysLeft: Number.isFinite(reg.daysLeft) ? reg.daysLeft : null,
    risk: rowRisk(f),
    statuses: (reg.statuses || []).join(' '),
    transferLock: reg.transferLock ?? null,
    critical: (reg.critical || []).join(' '),
    dnssec: f.dnssec ? f.dnssec.state : null,
    delegationSigned: reg.delegationSigned ?? null,
    nameServers: (f.ns && f.ns.hosts ? f.ns.hosts : []).join(' '),
    nsDomains: (f.ns && f.ns.domains ? f.ns.domains : []).map((d) => `${d.domain}${d.own ? '' : `:${Number.isFinite(d.daysLeft) ? d.daysLeft : d.state}`}`).join(' '),
    nsMinDaysLeft: f.ns && Number.isFinite(f.ns.minDaysLeft) ? f.ns.minDaysLeft : null,
    caa: f.caa ? f.caa.state : null,
    caaIssuers: f.caa && f.caa.issuers ? [...new Set([...f.caa.issuers, ...(f.caa.wildIssuers || [])])].join(' ') : null,
    mx: f.mx ? f.mx.state : null,
    spf: f.spf ? f.spf.state : null,
    spfAll: f.spf && f.spf.all ? `${f.spf.all}all` : null,
    spfLookups: f.spf && Number.isFinite(f.spf.lookups) ? f.spf.lookups : null,
    // p=none and no record at all never read alike: 'p=none' / 'missing' (or 'many', 'invalid')
    dmarc: f.dmarc ? (f.dmarc.state === 'ok' ? (f.dmarc.policy ? `p=${f.dmarc.policy}` : 'invalid') : f.dmarc.state === 'none' ? 'missing' : f.dmarc.state) : null,
    dkim: f.dkim ? (f.dkim.state === 'found' ? f.dkim.selectors.join(' ') : f.dkim.state) : null,
    mtaSts: f.mtaSts ? f.mtaSts.state : null,
    tlsRpt: f.tlsRpt ? f.tlsRpt.state : null,
    parked: f.parked && f.parked.parked ? (f.parked.complete ? 'locked' : f.parked.complete === false ? 'open' : 'unknown') : f.parked && f.parked.parked === false ? 'receives-mail' : null,
    failed: uniq(failed).join(' ')
  };
}

/** The keys of {@link exportRow}, in CSV column order. */
export const EXPORT_COLUMNS = Object.freeze(['domain', 'registration', 'registrar', 'expires', 'daysLeft', 'risk', 'statuses', 'transferLock', 'critical',
  'dnssec', 'delegationSigned', 'nameServers', 'nsDomains', 'nsMinDaysLeft', 'caa', 'caaIssuers', 'mx', 'spf', 'spfAll', 'spfLookups', 'dmarc', 'dkim',
  'mtaSts', 'tlsRpt', 'parked', 'failed']);

/**
 * What lib/portfoliosummary.js writes for "Copy summary": counts and the domains that need a look,
 * never a record value.
 * @param {object[]} factsList
 * @param {{ at?: Date|null, stopped?: boolean, notLooked?: number, audit?: object|null }} [opts] `audit`: lib/policy.js auditPortfolio
 * @returns {object}
 */
export function portfolioSummaryFacts(factsList, { at = null, stopped = false, notLooked = 0, audit = null } = {}) {
  const list = factsList || [];
  const reg = (f) => f.registration || {};
  const byDays = (a, b) => a.daysLeft - b.daysLeft || a.domain.localeCompare(b.domain, 'en');
  const expiring = list.filter((f) => reg(f).state === 'ok' && Number.isFinite(reg(f).daysLeft) && reg(f).daysLeft < 30)
    .map((f) => ({ domain: f.domain, daysLeft: reg(f).daysLeft })).sort(byDays);
  const nsExpiring = expiryEvents(list).filter((e) => !e.portfolio && e.daysLeft < 30).map((e) => ({ domain: e.domain, daysLeft: e.daysLeft, of: e.nsOf })).sort(byDays);
  const gone = new Map();
  for (const f of list) {
    for (const d of unregisteredNsDomains(f)) {
      if (!gone.has(d)) gone.set(d, []);
      gone.get(d).push(f.domain);
    }
  }
  const count = (fn) => list.filter(fn).length;
  const failedLookups = list.reduce((n, f) => n + PORTFOLIO_CELLS.reduce((m, c) => m + cellFailures(f, c).length, 0), 0);
  return {
    domains: list.length,
    at,
    stopped,
    notLooked,
    expiring,
    critical: list.filter((f) => (reg(f).critical || []).length).map((f) => ({ domain: f.domain, codes: reg(f).critical })),
    pendingTransfer: list.filter((f) => (reg(f).statuses || []).some((s) => squash(s) === 'pendingtransfer')).map((f) => f.domain),
    unlocked: list.filter((f) => reg(f).state === 'ok' && reg(f).transferLock === false).map((f) => f.domain),
    noRdap: count((f) => reg(f).state === 'unsupported'),
    notRegistered: list.filter((f) => reg(f).state === 'not-found').map((f) => f.domain),
    nsExpiring,
    nsUnregistered: [...gone].map(([domain, of]) => ({ domain, of })).sort((a, b) => a.domain.localeCompare(b.domain, 'en')),
    dnssec: {
      validated: count((f) => f.dnssec && f.dnssec.state === 'validated'),
      signed: count((f) => f.dnssec && f.dnssec.state === 'signed'),
      // DS published, the keys not validated: Domain Health's dnssec.broken
      broken: count((f) => f.dnssec && f.dnssec.state === 'failing'),
      unsigned: count((f) => f.dnssec && f.dnssec.state === 'unsigned')
    },
    caaNone: count((f) => f.caa && (f.caa.state === 'none' || f.caa.state === 'unrestricted')),
    spfOver: list.filter((f) => f.spf && f.spf.over).map((f) => f.domain),
    spfBad: list.filter((f) => f.spf && f.spf.state && f.spf.state !== 'ok').map((f) => f.domain),
    dmarcWeak: list.filter((f) => f.dmarc && f.dmarc.state && !(f.dmarc.state === 'ok' && f.dmarc.policy && f.dmarc.policy !== 'none')).map((f) => f.domain),
    parkedOpen: list.filter((f) => f.parked && f.parked.parked && f.parked.complete === false).map((f) => f.domain),
    failedLookups,
    policy: audit ? { name: audit.name, counts: audit.counts, failing: audit.rows.filter((r) => r.fail > 0).map((r) => ({ domain: r.domain, rules: r.cells.filter((c) => c.status === 'fail').map((c) => c.id) })) } : null
  };
}
