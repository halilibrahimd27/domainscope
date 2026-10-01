/**
 * policy.js — a domain policy and its audit: which rules every domain of a portfolio must meet,
 * and a pass / fail matrix (domain × rule) with the evidence of each cell.
 *
 * A policy is JSON: a name and a map of rules, each keyed by a rule id of {@link POLICY_RULES}
 * (named after Domain Health's check ids — `dmarc.policy` reads what `dmarc.policy-*` reads,
 * `spf.lookups` what `spf.lookups-*` reads …). A flat map is accepted too:
 *
 *   { "name": "baseline", "rules": { "expiryDays": ">= 30", "transferLock": true, "dmarc.policy": ">= quarantine" } }
 *   { "dmarc.policy": ">= quarantine", "dnssec": "signed", "caa": "present", "transferLock": true, "expiryDays": ">= 30" }
 *
 * Values by rule kind: a number rule takes a number (compared with its natural operator, `>=` for
 * days left, `<=` for SPF lookups) or "OP N"; an ordered rule ("dnssec", "spf.all", "dmarc.policy")
 * takes a level, meaning "at least" it, or "OP level"; a yes / no rule takes true or false; an
 * enum rule ("caa", "spf") one of its values (true for its first); a list rule ("registrar",
 * "caa.issuers") a string or a list of them. OP is one of {@link POLICY_OPS}.
 *
 * {@link evaluatePolicy} reads the facts lib/portfolio.js portfolioFacts() derives from one
 * domain's lookups; {@link auditPortfolio} makes the matrix. A rule whose facts could not be read
 * (a lookup that failed, a TLD without RDAP, a check not run) is 'unknown', never a pass or a
 * fail: the evidence says why. Texts are keys of {@link POLICY_I18N} (English and Turkish), so the
 * view and the headless runner (tools/ds.mjs audit) word the same evidence.
 *
 * Pure: no DOM, network, storage or clock beyond what the facts carry. Runs in browsers and Node 22.
 */

import { toCsv } from './export.js';

/** Version of the exported policy file. */
export const POLICY_VERSION = 1;
/** Longest policy text read (JSON characters). */
export const POLICY_MAX_CHARS = 16384;
/** Most rules one policy may hold. */
export const POLICY_MAX_RULES = 40;
/** Comparison operators of number and ordered rules. */
export const POLICY_OPS = Object.freeze(['>=', '<=', '>', '<', '==', '!=']);
/** Keys of a flat policy that are not rules. */
const RESERVED_KEYS = new Set(['name', 'version', 'description', '$schema', 'rules']);
/** A cell's outcome. */
export const POLICY_STATUSES = Object.freeze(['pass', 'fail', 'unknown']);
/** Why a policy text was refused or a rule left out ({@link parsePolicy}). */
export const POLICY_ERRORS = Object.freeze(['not-json', 'not-object', 'too-large', 'too-many', 'unknown-rule', 'bad-value', 'empty']);

const rule = (id, kind, extra = {}) => Object.freeze({ id, kind, ...extra, ...(extra.levels ? { levels: Object.freeze([...extra.levels]) } : {}),
  ...(extra.values ? { values: Object.freeze([...extra.values]) } : {}), health: Object.freeze([...(extra.health || [])]) });

/**
 * Every rule a policy can hold, in the matrix's column order. `kind`: 'number' (with its natural
 * `op` and `min` / `max`), 'ordered' (`levels`, lowest first), 'bool', 'enum' (`values`) or 'list';
 * `area`: the part of the facts it reads; `health`: the Domain Health check ids it corresponds to;
 * `example`: a value the editor offers.
 */
export const POLICY_RULES = Object.freeze([
  rule('expiryDays', 'number', { op: '>=', min: 0, max: 3650, area: 'registration', example: '>= 30',
    health: ['rdap.expiry-ok', 'rdap.expiring-soon', 'rdap.expiring', 'rdap.expired'] }),
  rule('transferLock', 'bool', { area: 'registration', example: true, health: ['rdap.transfer-unlocked'] }),
  rule('status.critical', 'bool', { area: 'registration', example: false, health: ['rdap.hold', 'rdap.pending-delete'] }),
  rule('registrar', 'list', { area: 'registration', example: ['Example Registrar, Inc.'] }),
  rule('nsExpiryDays', 'number', { op: '>=', min: 0, max: 3650, area: 'ns', example: '>= 30' }),
  rule('dnssec', 'ordered', { op: '>=', levels: ['unsigned', 'signed', 'validated'], area: 'dnssec', example: 'signed',
    health: ['dnssec.ok', 'dnssec.unsigned', 'dnssec.no-ds', 'dnssec.not-validated', 'dnssec.broken'] }),
  rule('caa', 'enum', { values: ['present', 'deny-all'], area: 'caa', example: 'present', health: ['caa.present', 'caa.missing', 'caa.deny-all'] }),
  rule('caa.issuers', 'list', { area: 'caa', example: ['letsencrypt.org'] }),
  rule('spf', 'enum', { values: ['valid'], area: 'spf', example: 'valid', health: ['spf.present', 'spf.missing', 'spf.multiple', 'spf.syntax'] }),
  rule('spf.lookups', 'number', { op: '<=', min: 0, max: 100, area: 'spf', example: '<= 10',
    health: ['spf.lookups-ok', 'spf.lookups-high', 'spf.lookups-exceeded'] }),
  rule('spf.all', 'ordered', { op: '>=', levels: ['+all', '?all', '~all', '-all'], area: 'spf', example: '>= ~all',
    health: ['spf.all-fail', 'spf.all-softfail', 'spf.all-neutral', 'spf.all-pass', 'spf.all-missing'] }),
  rule('dmarc.policy', 'ordered', { op: '>=', levels: ['none', 'quarantine', 'reject'], area: 'dmarc', example: '>= quarantine',
    health: ['dmarc.policy-none', 'dmarc.policy-quarantine', 'dmarc.policy-reject', 'dmarc.missing'] }),
  rule('dkim', 'bool', { area: 'dkim', example: true, health: ['dkim.found', 'dkim.none'] }),
  rule('mtaSts', 'bool', { area: 'mtaSts', example: true, health: ['mta-sts.present', 'mta-sts.missing'] }),
  rule('tlsRpt', 'bool', { area: 'tlsRpt', example: true, health: ['tls-rpt.present', 'tls-rpt.missing'] }),
  rule('mx.null', 'bool', { area: 'mx', example: true, health: ['mx.null'] })
]);

const RULE_BY_ID = new Map(POLICY_RULES.map((r) => [r.id, r]));

/**
 * A rule by id.
 * @param {string} id
 * @returns {object|null}
 */
export function policyRule(id) {
  return RULE_BY_ID.get(id) || null;
}

/**
 * The presets the editor offers: a baseline for every domain, strict mail for domains that send
 * mail, and the lock-down of a parked domain (the DNS change request's "Lock down a parked domain"
 * template: null MX, `v=spf1 -all`, DMARC `p=reject`, CAA `issue ";"`).
 */
export const POLICY_PRESETS = Object.freeze({
  baseline: Object.freeze({
    name: 'baseline',
    rules: Object.freeze({
      expiryDays: '>= 30', transferLock: true, 'status.critical': false, nsExpiryDays: '>= 30',
      spf: 'valid', 'spf.lookups': '<= 10', 'dmarc.policy': '>= none'
    })
  }),
  'strict-mail': Object.freeze({
    name: 'strict mail',
    rules: Object.freeze({
      spf: 'valid', 'spf.lookups': '<= 10', 'spf.all': '>= ~all', 'dmarc.policy': '>= quarantine', dkim: true, mtaSts: true, tlsRpt: true
    })
  }),
  parked: Object.freeze({
    name: 'parked domain',
    rules: Object.freeze({
      expiryDays: '>= 30', transferLock: true, 'mx.null': true, 'spf.all': '== -all', 'dmarc.policy': '== reject', caa: 'deny-all'
    })
  })
});
/** Preset ids, in the editor's order. */
export const POLICY_PRESET_IDS = Object.freeze(Object.keys(POLICY_PRESETS));

/* ------------------------------------------------------------------------ */
/* Parsing                                                                  */
/* ------------------------------------------------------------------------ */

const OP_RE = /^\s*(>=|<=|==|!=|>|<|=)?\s*(.+?)\s*$/;

/** A value of one rule → `{ op, value }`, or null when it is not one the rule takes. */
function parseRuleValue(r, raw) {
  switch (r.kind) {
    case 'number': {
      if (typeof raw === 'number') return Number.isFinite(raw) && raw >= r.min && raw <= r.max ? { op: r.op, value: raw } : null;
      if (typeof raw !== 'string') return null;
      const m = OP_RE.exec(raw);
      if (!m || !/^-?\d+$/.test(m[2])) return null;
      const n = Number(m[2]);
      if (!Number.isSafeInteger(n) || n < r.min || n > r.max) return null;
      return { op: m[1] === '=' ? '==' : m[1] || r.op, value: n };
    }
    case 'ordered': {
      if (typeof raw !== 'string') return null;
      const m = OP_RE.exec(raw.toLowerCase());
      if (!m) return null;
      let level = m[2];
      // "-all" may be written "-" or "all" alone never: the qualifier is what is compared.
      if (r.id === 'spf.all' && /^[-~?+]$/.test(level)) level = `${level}all`;
      if (r.id === 'dmarc.policy') level = level.replace(/^p\s*=\s*/, '');
      if (!r.levels.includes(level)) return null;
      return { op: m[1] === '=' ? '==' : m[1] || r.op, value: level };
    }
    case 'bool': {
      if (typeof raw === 'boolean') return { op: '==', value: raw };
      if (typeof raw === 'string' && /^(true|false)$/i.test(raw.trim())) return { op: '==', value: raw.trim().toLowerCase() === 'true' };
      return null;
    }
    case 'enum': {
      if (raw === true) return { op: '==', value: r.values[0] };
      if (typeof raw !== 'string') return null;
      const v = raw.trim().toLowerCase();
      return r.values.includes(v) ? { op: '==', value: v } : null;
    }
    case 'list': {
      const list = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : null;
      if (!list || !list.length || list.length > 30) return null;
      const out = [];
      for (const x of list) {
        if (typeof x !== 'string' || !x.trim() || x.length > 120) return null;
        const v = x.trim().replace(/\s+/g, ' ');
        if (!out.some((y) => y.toLowerCase() === v.toLowerCase())) out.push(v);
      }
      return { op: 'in', value: out };
    }
    default:
      return null;
  }
}

/**
 * The value of a parsed rule as a policy file writes it: "OP N" / "OP level" (the operator always
 * written out), a boolean, an enum value, a list.
 * @param {{ id: string, op: string, value: any }} entry
 * @returns {string|boolean|string[]}
 */
export function ruleValueText(entry) {
  const r = policyRule(entry.id);
  if (!r) return entry.value;
  if (r.kind === 'number' || r.kind === 'ordered') return `${entry.op} ${entry.value}`;
  if (r.kind === 'list') return [...entry.value];
  return entry.value;
}

/**
 * Read a policy: JSON text or an object, flat or `{ name, rules }`. Rules are kept in
 * {@link POLICY_RULES} order; an unknown rule or a value its rule does not take is an error (the
 * rule is left out), so a typo never passes silently.
 * @param {string|object} input
 * @returns {{ policy: { name: string|null, rules: Array<{ id: string, kind: string, op: string, value: any }> }|null,
 *   errors: Array<{ code: string, rule?: string, value?: string, detail?: string, example?: string }> }}
 *   `policy` null when nothing could be read (not JSON, not an object, too large)
 */
export function parsePolicy(input) {
  const errors = [];
  let obj = input;
  if (typeof input === 'string') {
    if (input.length > POLICY_MAX_CHARS) return { policy: null, errors: [{ code: 'too-large', value: String(POLICY_MAX_CHARS) }] };
    try {
      obj = JSON.parse(input);
    } catch (err) {
      return { policy: null, errors: [{ code: 'not-json', detail: String((err && err.message) || err).slice(0, 120) }] };
    }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { policy: null, errors: [{ code: 'not-object' }] };
  const nested = obj.rules && typeof obj.rules === 'object' && !Array.isArray(obj.rules);
  if ('rules' in obj && !nested) return { policy: null, errors: [{ code: 'not-object' }] };
  const map = nested ? obj.rules : Object.fromEntries(Object.entries(obj).filter(([k]) => !RESERVED_KEYS.has(k)));
  const name = typeof obj.name === 'string' && obj.name.trim() ? obj.name.trim().replace(/\s+/g, ' ').slice(0, 60) : null;
  const keys = Object.keys(map);
  if (keys.length > POLICY_MAX_RULES) return { policy: null, errors: [{ code: 'too-many', value: String(POLICY_MAX_RULES) }] };
  const parsed = new Map();
  for (const key of keys) {
    const r = policyRule(key);
    if (!r) {
      errors.push({ code: 'unknown-rule', rule: key.slice(0, 60) });
      continue;
    }
    const v = parseRuleValue(r, map[key]);
    if (!v) {
      errors.push({ code: 'bad-value', rule: key, value: JSON.stringify(map[key] ?? null).slice(0, 60), example: JSON.stringify(r.example) });
      continue;
    }
    parsed.set(key, { id: key, kind: r.kind, ...v });
  }
  const rules = POLICY_RULES.filter((r) => parsed.has(r.id)).map((r) => parsed.get(r.id));
  if (!rules.length && !errors.length) errors.push({ code: 'empty' });
  return { policy: { name, rules }, errors };
}

/**
 * The policy as its file: `{ name, version, rules }`, every value written out ({@link ruleValueText}).
 * @param {{ name: string|null, rules: object[] }} policy
 * @returns {{ name: string|null, version: number, rules: Record<string, any> }}
 */
export function policyObject(policy) {
  return {
    name: policy && policy.name ? policy.name : null,
    version: POLICY_VERSION,
    rules: Object.fromEntries(((policy && policy.rules) || []).map((e) => [e.id, ruleValueText(e)]))
  };
}

/**
 * The policy file's text (indented JSON, a trailing newline).
 * @param {{ name: string|null, rules: object[] }} policy
 * @returns {string}
 */
export function policyText(policy) {
  return `${JSON.stringify(policyObject(policy), null, 2)}\n`;
}

/**
 * A preset as a parsed policy.
 * @param {string} id one of {@link POLICY_PRESET_IDS}
 * @returns {{ name: string, rules: object[] }}
 */
export function presetPolicy(id) {
  const p = POLICY_PRESETS[id];
  if (!p) throw new RangeError(`policy: unknown preset "${id}"`);
  return parsePolicy({ name: p.name, rules: p.rules }).policy;
}

/** The requirement of a rule as a short code text (">= 30", "true", "letsencrypt.org, sectigo.com"). */
export function requirementText(entry) {
  const v = ruleValueText(entry);
  return Array.isArray(v) ? v.join(', ') : String(v);
}

/* ------------------------------------------------------------------------ */
/* Evaluation                                                               */
/* ------------------------------------------------------------------------ */

function compare(op, a, b) {
  switch (op) {
    case '>=': return a >= b;
    case '<=': return a <= b;
    case '>': return a > b;
    case '<': return a < b;
    case '==': return a === b;
    case '!=': return a !== b;
    default: return false;
  }
}

const ev = (key, params = {}) => ({ key, params });
/** 'YYYY-MM-DD' of a Date or an ISO string (a report read back), '' for none. */
function isoDay(v) {
  if (!v) return '';
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}
const cell = (entry, status, actual, evidence) => ({ id: entry.id, status, actual: actual === undefined ? null : actual, evidence, required: requirementText(entry) });

/** Why a part of the facts is not known: its lookup failed, was not run, or never answered. */
function unknownWhy(part, what) {
  if (!part || part.state === 'pending' || part.state === undefined) return ev('pol.ev.pending');
  if (part.state === 'off') return ev('pol.ev.off');
  return ev('pol.ev.failed', { what });
}

/** A number rule: the actual number against the requirement. */
function numberCell(entry, n, evidence) {
  return cell(entry, compare(entry.op, n, entry.value) ? 'pass' : 'fail', n, evidence);
}

/** An ordered rule: the actual level's rank against the required level's. */
function orderedCell(entry, level, evidence) {
  const r = policyRule(entry.id);
  return cell(entry, compare(entry.op, r.levels.indexOf(level), r.levels.indexOf(entry.value)) ? 'pass' : 'fail', level, evidence);
}

/** A yes / no rule. */
function boolCell(entry, value, evidence) {
  return cell(entry, value === entry.value ? 'pass' : 'fail', value, evidence);
}

function registrationUnknown(reg) {
  if (!reg || reg.state === 'pending' || reg.state === undefined) return ev('pol.ev.pending');
  if (reg.state === 'unsupported') return ev('pol.ev.noRdap', { tld: reg.tld || '' });
  if (reg.state === 'invalid') return ev('pol.ev.invalid');
  return ev('pol.ev.failed', { what: 'RDAP' });
}

const RULE_EVAL = {
  expiryDays(entry, f) {
    const reg = f.registration;
    if (reg && reg.state === 'not-found') return cell(entry, 'fail', null, ev('pol.ev.notRegistered'));
    if (!reg || reg.state !== 'ok') return cell(entry, 'unknown', null, registrationUnknown(reg));
    if (!Number.isFinite(reg.daysLeft)) return cell(entry, 'unknown', null, ev('pol.ev.noExpiry'));
    const date = isoDay(reg.expires);
    return numberCell(entry, reg.daysLeft, reg.daysLeft < 0 ? ev('pol.ev.expired', { count: -reg.daysLeft, date }) : ev('pol.ev.daysLeft', { count: reg.daysLeft, date }));
  },
  transferLock(entry, f) {
    const reg = f.registration;
    if (!reg || reg.state !== 'ok') return cell(entry, 'unknown', null, registrationUnknown(reg));
    if (reg.transferLock === null || reg.transferLock === undefined) return cell(entry, 'unknown', null, ev('pol.ev.noStatus'));
    return boolCell(entry, reg.transferLock, ev(reg.transferLock ? 'pol.ev.lockOn' : 'pol.ev.lockOff'));
  },
  'status.critical'(entry, f) {
    const reg = f.registration;
    if (!reg || reg.state !== 'ok') return cell(entry, 'unknown', null, registrationUnknown(reg));
    const critical = reg.critical || [];
    return boolCell(entry, critical.length > 0, critical.length ? ev('pol.ev.critical', { codes: critical.join(', ') }) : ev('pol.ev.noCritical'));
  },
  registrar(entry, f) {
    const reg = f.registration;
    if (!reg || reg.state !== 'ok') return cell(entry, 'unknown', null, registrationUnknown(reg));
    if (!reg.registrar) return cell(entry, 'unknown', null, ev('pol.ev.noRegistrar'));
    const name = String(reg.registrar).toLowerCase();
    const hit = entry.value.some((x) => name.includes(x.toLowerCase()));
    return cell(entry, hit ? 'pass' : 'fail', reg.registrar, ev('pol.ev.registrar', { name: reg.registrar }));
  },
  nsExpiryDays(entry, f) {
    const ns = f.ns;
    if (!ns || ns.state === 'failed' || ns.state === 'pending' || ns.state === undefined) return cell(entry, 'unknown', null, unknownWhy(ns, 'NS'));
    if (ns.state === 'nxdomain') return cell(entry, 'fail', null, ev('pol.ev.nxdomain'));
    if (!ns.domains || !ns.domains.length) return cell(entry, 'unknown', null, ev('pol.ev.noNs'));
    const known = ns.domains.filter((d) => d.state === 'ok' && Number.isFinite(d.daysLeft));
    const failing = known.filter((d) => !compare(entry.op, d.daysLeft, entry.value)).sort((a, b) => a.daysLeft - b.daysLeft);
    const soonest = [...known].sort((a, b) => a.daysLeft - b.daysLeft)[0] || null;
    const evidenceOf = (d) => (d.daysLeft < 0 ? ev('pol.ev.nsExpired', { domain: d.domain, count: -d.daysLeft })
      : ev('pol.ev.nsDays', { domain: d.domain, count: d.daysLeft }));
    if (failing.length) return cell(entry, 'fail', failing[0].daysLeft, evidenceOf(failing[0]));
    const notKnown = ns.domains.find((d) => !(d.state === 'ok' && Number.isFinite(d.daysLeft)));
    if (notKnown) return cell(entry, 'unknown', soonest ? soonest.daysLeft : null, ev('pol.ev.nsUnknown', { domain: notKnown.domain }));
    return cell(entry, 'pass', soonest.daysLeft, evidenceOf(soonest));
  },
  dnssec(entry, f) {
    const d = f.dnssec;
    if (!d || !d.state) return cell(entry, 'unknown', null, unknownWhy(d, 'DS'));
    // DS at the parent but the DNSKEY lookup failed: signed, whether it validates is not known.
    if (d.state === 'failing') {
      const want = policyRule('dnssec').levels.indexOf(entry.value);
      const asSigned = compare(entry.op, 1, want);
      const asValidated = compare(entry.op, 2, want);
      const status = asSigned && asValidated ? 'pass' : !asSigned && !asValidated ? 'fail' : 'unknown';
      return cell(entry, status, 'signed', ev('pol.ev.dnssec.failing'));
    }
    return orderedCell(entry, d.state, ev(`pol.ev.dnssec.${d.state}`));
  },
  caa(entry, f) {
    const c = f.caa;
    if (!c || !c.state) return cell(entry, 'unknown', null, unknownWhy(c, 'CAA'));
    const evidence = caaEvidence(c);
    if (entry.value === 'deny-all') return cell(entry, c.state === 'deny-all' ? 'pass' : 'fail', c.state, evidence);
    return cell(entry, c.state === 'present' || c.state === 'deny-all' ? 'pass' : 'fail', c.state, evidence);
  },
  'caa.issuers'(entry, f) {
    const c = f.caa;
    if (!c || !c.state) return cell(entry, 'unknown', null, unknownWhy(c, 'CAA'));
    if (c.state === 'deny-all' || c.state === 'critical') return cell(entry, 'pass', [], caaEvidence(c));
    if (c.state !== 'present') return cell(entry, 'fail', null, caaEvidence(c));
    const allowed = entry.value.map((x) => x.toLowerCase());
    const issuers = [...new Set([...(c.issuers || []), ...(c.wildIssuers || [])])];
    const extra = issuers.filter((x) => !allowed.includes(String(x).toLowerCase()));
    return cell(entry, extra.length ? 'fail' : 'pass', issuers, extra.length ? ev('pol.ev.caaExtra', { list: extra.join(', ') }) : caaEvidence(c));
  },
  spf(entry, f) {
    const s = f.spf;
    if (!s || !s.state) return cell(entry, 'unknown', null, unknownWhy(s, 'TXT'));
    return cell(entry, s.state === 'ok' ? 'pass' : 'fail', s.state, ev(`pol.ev.spf.${s.state}`, { count: s.count || 0 }));
  },
  'spf.lookups'(entry, f) {
    const s = f.spf;
    if (!s || !s.state) return cell(entry, 'unknown', null, unknownWhy(s, 'TXT'));
    if (s.state !== 'ok') return cell(entry, 'fail', null, ev(`pol.ev.spf.${s.state}`, { count: s.count || 0 }));
    if (!Number.isFinite(s.lookups)) return cell(entry, 'unknown', null, unknownWhy({ state: s.lookupsState }, 'SPF'));
    if (s.lookupsState === 'partial') {
      // A lookup in the tree failed: the count is a floor. Over the limit already is a fail.
      const over = !compare(entry.op, s.lookups, entry.value) && (entry.op === '<=' || entry.op === '<');
      return cell(entry, over ? 'fail' : 'unknown', s.lookups, ev('pol.ev.spfLookupsPartial', { count: s.lookups }));
    }
    return numberCell(entry, s.lookups, ev('pol.ev.spfLookups', { count: s.lookups }));
  },
  'spf.all'(entry, f) {
    const s = f.spf;
    if (!s || !s.state) return cell(entry, 'unknown', null, unknownWhy(s, 'TXT'));
    if (s.state !== 'ok') return cell(entry, 'fail', null, ev(`pol.ev.spf.${s.state}`, { count: s.count || 0 }));
    if (!s.all && s.redirect) return cell(entry, 'unknown', null, ev('pol.ev.spfRedirect', { domain: s.redirect }));
    // No "all": unlisted senders are neutral, as with ?all.
    const level = s.all ? `${s.all}all` : '?all';
    return orderedCell(entry, level, s.all ? ev('pol.ev.spfAll', { all: level }) : ev('pol.ev.spfNoAll'));
  },
  'dmarc.policy'(entry, f) {
    const d = f.dmarc;
    if (!d || !d.state) return cell(entry, 'unknown', null, unknownWhy(d, 'DMARC'));
    if (d.state !== 'ok' || !d.policy) return cell(entry, 'fail', null, ev(`pol.ev.dmarc.${d.state === 'ok' ? 'invalid' : d.state}`, { count: d.count || 0 }));
    return orderedCell(entry, d.policy, ev('pol.ev.dmarc', { policy: `p=${d.policy}` }));
  },
  dkim(entry, f) {
    const d = f.dkim;
    if (!d || !d.state || d.state === 'failed' || d.state === 'off') return cell(entry, 'unknown', null, unknownWhy(d, 'DKIM'));
    const found = d.state === 'found';
    return boolCell(entry, found, found ? ev('pol.ev.dkimFound', { list: (d.selectors || []).join(', ') }) : ev('pol.ev.dkimNone', { count: d.asked || 0 }));
  },
  mtaSts(entry, f) {
    return presenceCell(entry, f.mtaSts, '_mta-sts');
  },
  tlsRpt(entry, f) {
    return presenceCell(entry, f.tlsRpt, '_smtp._tls');
  },
  'mx.null'(entry, f) {
    const m = f.mx;
    if (!m || !m.state) return cell(entry, 'unknown', null, unknownWhy(m, 'MX'));
    return boolCell(entry, m.state === 'null', ev(`pol.ev.mx.${m.state}`, { count: (m.hosts || []).length }));
  }
};

function presenceCell(entry, part, what) {
  if (!part || !part.state) return cell(entry, 'unknown', null, unknownWhy(part, what));
  // A record that is not valid is not there for senders.
  return boolCell(entry, part.state === 'present', ev(part.state === 'invalid' ? 'pol.ev.invalidRecord' : `pol.ev.${part.state}`));
}

function caaEvidence(c) {
  if (c.state === 'present') {
    const list = [...new Set([...(c.issuers || []), ...(c.wildIssuers || [])])];
    return ev('pol.ev.caa.present', { list: list.join(', ') || '—' });
  }
  return ev(`pol.ev.caa.${c.state}`);
}

/**
 * Evaluate one domain's facts against a policy.
 * @param {{ rules: Array<{ id: string, op: string, value: any }> }} policy a {@link parsePolicy} policy
 * @param {object} facts lib/portfolio.js portfolioFacts()
 * @returns {Array<{ id: string, status: 'pass'|'fail'|'unknown', actual: any, evidence: { key: string, params: object }, required: string }>}
 */
export function evaluatePolicy(policy, facts) {
  const f = facts || {};
  // A domain that does not exist in DNS: its DNS rules say so, never "not known".
  return ((policy && policy.rules) || []).map((entry) => {
    const fn = RULE_EVAL[entry.id];
    if (!fn) return cell(entry, 'unknown', null, ev('pol.ev.pending'));
    const c = fn(entry, f);
    if (c.status !== 'pass' && f.exists === false && ['dnssec', 'caa', 'caa.issuers', 'spf', 'spf.lookups', 'spf.all', 'dmarc.policy', 'dkim', 'mtaSts', 'tlsRpt', 'mx.null'].includes(entry.id)) {
      return { ...c, status: 'fail', evidence: ev('pol.ev.nxdomain') };
    }
    return c;
  });
}

/**
 * The pass / fail matrix of a portfolio: one row per domain (in the given order), one cell per
 * rule, with counts per row and in all.
 * @param {{ name: string|null, rules: object[] }} policy
 * @param {object[]} factsList lib/portfolio.js portfolioFacts() per domain
 * @returns {{ name: string|null, rules: Array<{ id: string, required: string }>, rows: Array<{ domain: string,
 *   cells: object[], pass: number, fail: number, unknown: number }>, counts: { domains: number, failing: number,
 *   passing: number, unknown: number, pass: number, fail: number, cells: number } }}
 *   `failing`: domains with at least one failed rule; `passing`: every rule passed; `unknown`: the rest
 */
export function auditPortfolio(policy, factsList) {
  const rules = ((policy && policy.rules) || []).map((e) => ({ id: e.id, required: requirementText(e) }));
  const rows = (factsList || []).map((facts) => {
    const cells = evaluatePolicy(policy, facts);
    const count = (s) => cells.filter((c) => c.status === s).length;
    return { domain: facts.domain, cells, pass: count('pass'), fail: count('fail'), unknown: count('unknown') };
  });
  const counts = {
    domains: rows.length,
    failing: rows.filter((r) => r.fail > 0).length,
    passing: rows.filter((r) => r.fail === 0 && r.unknown === 0).length,
    unknown: rows.filter((r) => r.fail === 0 && r.unknown > 0).length,
    pass: rows.reduce((n, r) => n + r.pass, 0),
    fail: rows.reduce((n, r) => n + r.fail, 0),
    cells: rows.reduce((n, r) => n + r.cells.length, 0)
  };
  return { name: policy ? policy.name : null, rules, rows, counts };
}

/**
 * A cell's evidence as text in the language `t` speaks.
 * @param {{ evidence: { key: string, params: object } }} c
 * @param {Function} t i18n.js t
 * @returns {string}
 */
export function evidenceText(c, t) {
  return c && c.evidence ? String(t(c.evidence.key, c.evidence.params)) : '';
}

/**
 * The matrix as CSV: one row per domain, its counts, then one column per rule — "PASS", "FAIL" or
 * "UNKNOWN" with the evidence (`FAIL · 12 days left (2026-10-14)`). Formula-looking cells are
 * defused by lib/export.js toCsv.
 * @param {ReturnType<typeof auditPortfolio>} audit
 * @param {{ t: Function }} opts
 * @returns {string}
 */
export function auditCsv(audit, { t }) {
  const columns = [
    { key: 'domain', header: t('pol.csv.domain') },
    { key: 'fail', header: t('pol.csv.fail') },
    { key: 'unknown', header: t('pol.csv.unknown') },
    { key: 'pass', header: t('pol.csv.pass') },
    ...audit.rules.map((r, i) => ({
      key: r.id,
      header: `${r.id} (${r.required})`,
      get: (row) => {
        const c = row.cells[i];
        return c ? `${c.status.toUpperCase()} · ${evidenceText(c, t)}` : '';
      }
    }))
  ];
  return toCsv(audit.rows, columns);
}

/**
 * The matrix as JSON-ready data: the policy, the counts and every cell with its evidence worded
 * (`text`) and as its key and params.
 * @param {ReturnType<typeof auditPortfolio>} audit
 * @param {{ t: Function, policy: object, app?: string, version?: string, at?: Date }} opts
 * @returns {object}
 */
export function auditJson(audit, { t, policy, app = 'DomainScope', version = '', at = new Date() }) {
  return {
    format: 'domainscope-policy-audit',
    v: 1,
    app,
    version,
    at: at instanceof Date ? at.toISOString() : at,
    policy: policyObject(policy),
    counts: audit.counts,
    rows: audit.rows.map((r) => ({
      domain: r.domain,
      pass: r.pass,
      fail: r.fail,
      unknown: r.unknown,
      rules: r.cells.map((c) => ({ id: c.id, status: c.status, required: c.required, actual: c.actual, evidence: evidenceText(c, t), key: c.evidence.key, params: c.evidence.params }))
    }))
  };
}

/* ------------------------------------------------------------------------ */
/* Texts                                                                    */
/* ------------------------------------------------------------------------ */

const STRINGS = [
  ['pol.rule.expiryDays', ['Days until expiry', 'Bitişe kalan gün']],
  ['pol.rule.transferLock', ['Transfer lock (clientTransferProhibited)', 'Transfer kilidi (clientTransferProhibited)']],
  ['pol.rule.status.critical', ['Critical registry status (hold, redemption, pending delete)', 'Kritik kayıt durumu (askı, geri alma, silinme bekliyor)']],
  ['pol.rule.registrar', ['Registrar', 'Kayıt firması']],
  ['pol.rule.nsExpiryDays', ['Days until the name servers’ domains expire', 'Ad sunucusu alan adlarının bitişine kalan gün']],
  ['pol.rule.dnssec', ['DNSSEC', 'DNSSEC']],
  ['pol.rule.caa', ['CAA', 'CAA']],
  ['pol.rule.caa.issuers', ['The only CAs CAA may allow', 'CAA’nın izin verebileceği CA’lar (yalnızca)']],
  ['pol.rule.spf', ['SPF record', 'SPF kaydı']],
  ['pol.rule.spf.lookups', ['SPF DNS lookups', 'SPF DNS sorguları']],
  ['pol.rule.spf.all', ['SPF “all” qualifier', 'SPF “all” niteleyicisi']],
  ['pol.rule.dmarc.policy', ['DMARC policy', 'DMARC politikası']],
  ['pol.rule.dkim', ['DKIM key published', 'Yayımlanmış DKIM anahtarı']],
  ['pol.rule.mtaSts', ['MTA-STS record', 'MTA-STS kaydı']],
  ['pol.rule.tlsRpt', ['TLS-RPT record', 'TLS-RPT kaydı']],
  ['pol.rule.mx.null', ['Null MX (accepts no mail)', 'Null MX (e-posta kabul etmez)']],

  ['pol.st.pass', ['Pass', 'Geçti']],
  ['pol.st.fail', ['Fail', 'Kaldı']],
  ['pol.st.unknown', ['Not known', 'Bilinmiyor']],

  ['pol.preset.baseline', ['Baseline', 'Temel']],
  ['pol.preset.strict-mail', ['Strict mail', 'Sıkı e-posta']],
  ['pol.preset.parked', ['Parked domain', 'Park edilmiş alan adı']],

  ['pol.err.not-json', ['Not valid JSON: {detail}', 'Geçerli bir JSON değil: {detail}']],
  ['pol.err.not-object', ['A policy is a JSON object of rules, such as { "expiryDays": ">= 30" }.', 'Politika, { "expiryDays": ">= 30" } gibi kurallardan oluşan bir JSON nesnesidir.']],
  ['pol.err.too-large', ['The policy is too long (at most {value} characters).', 'Politika çok uzun (en fazla {value} karakter).']],
  ['pol.err.too-many', ['Too many rules (at most {value}).', 'Çok fazla kural var (en fazla {value}).']],
  ['pol.err.unknown-rule', ['Unknown rule “{rule}”: it is left out.', 'Bilinmeyen kural: “{rule}”. Dikkate alınmadı.']],
  ['pol.err.bad-value', ['“{rule}” does not take {value} (for example {example}): it is left out.', '“{rule}” kuralı {value} değerini almaz (örneğin {example}). Dikkate alınmadı.']],
  ['pol.err.empty', ['The policy has no rules yet.', 'Politikada henüz kural yok.']],

  ['pol.ev.pending', ['not looked up', 'sorgulanmadı']],
  ['pol.ev.off', ['not checked (turned off)', 'kontrol edilmedi (kapalı)']],
  ['pol.ev.failed', ['{what} lookup failed', '{what} sorgusu başarısız']],
  ['pol.ev.invalid', ['not a domain a registry holds', 'bir kayıt kuruluşunun tuttuğu bir alan adı değil']],
  ['pol.ev.noRdap', ['the .{tld} registry publishes no RDAP: see its WHOIS', '.{tld} kayıt kuruluşu RDAP sunmuyor: WHOIS hizmetine bakın']],
  ['pol.ev.notRegistered', ['not registered: the registry has no record of it', 'kayıtlı değil: kayıt kuruluşunda kaydı yok']],
  ['pol.ev.noExpiry', ['the registry gives no expiry date', 'kayıt kuruluşu bitiş tarihi vermiyor']],
  ['pol.ev.daysLeft', [{ zero: 'expires today ({date})', one: '{count} day left ({date})', other: '{count} days left ({date})' }, { zero: 'bugün sona eriyor ({date})', other: '{count} gün kaldı ({date})' }]],
  ['pol.ev.expired', [{ one: 'expired {count} day ago ({date})', other: 'expired {count} days ago ({date})' }, '{count} gün önce sona erdi ({date})']],
  ['pol.ev.lockOn', ['clientTransferProhibited is set', 'clientTransferProhibited var']],
  ['pol.ev.lockOff', ['clientTransferProhibited is missing: the domain can be transferred away', 'clientTransferProhibited yok: alan adı başka yere transfer edilebilir']],
  ['pol.ev.noStatus', ['the registry reports no status', 'kayıt kuruluşu durum bildirmiyor']],
  ['pol.ev.critical', ['critical status: {codes}', 'kritik durum: {codes}']],
  ['pol.ev.noCritical', ['no hold, redemption or pending delete', 'askı, geri alma ya da silinme durumu yok']],
  ['pol.ev.registrar', ['registrar: {name}', 'kayıt firması: {name}']],
  ['pol.ev.noRegistrar', ['the registry names no registrar', 'kayıt kuruluşu bir kayıt firması belirtmiyor']],
  ['pol.ev.nsDays', [{ zero: 'name server domain {domain} expires today', one: 'name server domain {domain}: {count} day left', other: 'name server domain {domain}: {count} days left' },
    { zero: 'ad sunucusu alan adı {domain} bugün sona eriyor', other: 'ad sunucusu alan adı {domain}: {count} gün kaldı' }]],
  ['pol.ev.nsExpired', [{ one: 'name server domain {domain} expired {count} day ago', other: 'name server domain {domain} expired {count} days ago' },
    'ad sunucusu alan adı {domain} {count} gün önce sona erdi']],
  ['pol.ev.nsUnknown', ['the expiry of name server domain {domain} is not known', 'ad sunucusu alan adı {domain} için bitiş tarihi bilinmiyor']],
  ['pol.ev.noNs', ['no name servers to check', 'kontrol edilecek ad sunucusu yok']],
  ['pol.ev.nxdomain', ['the domain does not exist in DNS (NXDOMAIN)', 'alan adı DNS’te yok (NXDOMAIN)']],
  ['pol.ev.dnssec.validated', ['signed (DS) and validated', 'imzalı (DS) ve doğrulanıyor']],
  ['pol.ev.dnssec.signed', ['signed (DS), not validated by the resolver', 'imzalı (DS), çözümleyici doğrulamıyor']],
  ['pol.ev.dnssec.failing', ['signed (DS), but the keys could not be read', 'imzalı (DS), ama anahtarlar okunamadı']],
  ['pol.ev.dnssec.unsigned', ['not signed: no DS record', 'imzasız: DS kaydı yok']],
  ['pol.ev.caa.present', ['CAA allows {list}', 'CAA şunlara izin veriyor: {list}']],
  ['pol.ev.caa.none', ['no CAA record: any CA may issue', 'CAA kaydı yok: her CA sertifika verebilir']],
  ['pol.ev.caa.unrestricted', ['CAA has no issue property: any CA may issue', 'CAA’da issue özelliği yok: her CA sertifika verebilir']],
  ['pol.ev.caa.deny-all', ['CAA allows no CA', 'CAA hiçbir CA’ya izin vermiyor']],
  ['pol.ev.caa.critical', ['CAA has an unknown tag marked critical: no CA may issue', 'CAA’da kritik işaretli bilinmeyen bir etiket var: hiçbir CA sertifika veremez']],
  ['pol.ev.caaExtra', ['CAA also allows {list}', 'CAA şunlara da izin veriyor: {list}']],
  ['pol.ev.spf.ok', ['one valid SPF record', 'geçerli tek bir SPF kaydı']],
  ['pol.ev.spf.none', ['no SPF record', 'SPF kaydı yok']],
  ['pol.ev.spf.many', ['{count} SPF records (receivers treat that as an error)', '{count} SPF kaydı (alıcılar bunu hata sayar)']],
  ['pol.ev.spf.invalid', ['the SPF record is not valid', 'SPF kaydı geçerli değil']],
  ['pol.ev.spfLookups', [{ one: '{count} DNS lookup', other: '{count} DNS lookups' }, '{count} DNS sorgusu']],
  ['pol.ev.spfLookupsPartial', ['at least {count} DNS lookups (a lookup in its tree failed)', 'en az {count} DNS sorgusu (ağacındaki bir sorgu başarısız)']],
  ['pol.ev.spfAll', ['ends with {all}', 'sonu {all}']],
  ['pol.ev.spfNoAll', ['no “all” term: unlisted senders are neutral', '“all” terimi yok: listede olmayan göndericiler nötr sayılır']],
  ['pol.ev.spfRedirect', ['redirected to {domain}', '{domain} adresine yönlendiriliyor']],
  ['pol.ev.dmarc', ['DMARC {policy}', 'DMARC {policy}']],
  ['pol.ev.dmarc.none', ['no DMARC record', 'DMARC kaydı yok']],
  ['pol.ev.dmarc.many', ['{count} DMARC records (receivers ignore them all)', '{count} DMARC kaydı (alıcılar hepsini yok sayar)']],
  ['pol.ev.dmarc.invalid', ['the DMARC record is not valid', 'DMARC kaydı geçerli değil']],
  ['pol.ev.dkimFound', ['DKIM selectors {list}', 'DKIM seçicileri: {list}']],
  ['pol.ev.dkimNone', ['none of the {count} common selectors has a key', 'yaygın {count} seçicinin hiçbirinde anahtar yok']],
  ['pol.ev.present', ['record published', 'kayıt yayımlanmış']],
  ['pol.ev.none', ['no record', 'kayıt yok']],
  ['pol.ev.invalidRecord', ['the record is not valid', 'kayıt geçerli değil']],
  ['pol.ev.mx.null', ['null MX: accepts no mail', 'null MX: e-posta kabul etmiyor']],
  ['pol.ev.mx.some', [{ one: 'receives mail ({count} MX host)', other: 'receives mail ({count} MX hosts)' }, 'e-posta alıyor ({count} MX sunucusu)']],
  ['pol.ev.mx.none', ['no MX record (senders fall back to the domain’s address)', 'MX kaydı yok (gönderenler alan adının adresine yönelir)']],

  ['pol.csv.domain', ['Domain', 'Alan adı']],
  ['pol.csv.fail', ['Failed', 'Kalan']],
  ['pol.csv.unknown', ['Not known', 'Bilinmeyen']],
  ['pol.csv.pass', ['Passed', 'Geçen']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of every `pol.*` key: rule names, statuses, presets, parse errors and
 * the evidence of a cell. Placeholders `{param}`; a text with a count is a plural object.
 * @type {{ en: Record<string, string|object>, tr: Record<string, string|object> }}
 */
export const POLICY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
