/**
 * tlsrpt.js — SMTP TLS reports (TLS-RPT, RFC 8460): the JSON a sending organisation mails to the
 * `rua` of a domain's `_smtp._tls` record, read into plain objects and summed per policy domain —
 * how many TLS sessions succeeded, and every failure by type, receiving MX host and sender.
 * DOM-free and network-free; runs in browsers and Node 22.
 *
 * - {@link parseTlsReport}: one report (text or an already parsed object) → a {@link TlsReport}, or
 *   the reason it is none (`not-json`, `not-tlsrpt`, `incomplete`).
 * - {@link summarizeTls}: every report of a policy domain together ({@link TlsSummary}), the
 *   failures grouped by {@link TLS_RESULT_TYPES} and by MX host.
 * - {@link tlsAdvice}: what a failure type points at (the certificate, STARTTLS, DANE or the
 *   MTA-STS policy) and which tool checks it; the view words the advice.
 * - {@link tlsCsvRows}: the failure details for a spreadsheet ({@link TLS_CSV_COLUMNS}).
 *
 * Field names follow RFC 8460 §4.4. Reporters differ in small ways, all read: `mx-host` or the
 * draft's `mx-host-pattern`, a count sent as a string, result types in capitals.
 */

import { normalizeHostname } from './domain.js';
import { normalizeIP } from './netinfo.js';

/**
 * Failure result types of RFC 8460 §4.3, in its order: negotiation failures (§4.3.1), then the
 * DANE (§4.3.2.1) and MTA-STS (§4.3.2.2) policy failures. A type outside the list is kept as
 * written and grouped as `other`.
 */
export const TLS_RESULT_TYPES = Object.freeze([
  'starttls-not-supported', 'certificate-host-mismatch', 'certificate-expired', 'certificate-not-trusted', 'validation-failure',
  'tlsa-invalid', 'dnssec-invalid', 'dane-required',
  'sts-policy-fetch-error', 'sts-policy-invalid', 'sts-webpki-invalid'
]);
/** Policy types of RFC 8460 §4.4 (`policy-type`). */
export const TLS_POLICY_TYPES = Object.freeze(['sts', 'tlsa', 'no-policy-found']);
/** Why a file is no TLS report (`rpt.tls.err.<code>` in the view). */
export const TLS_REPORT_ERRORS = Object.freeze(['not-json', 'not-tlsrpt', 'incomplete']);
/** Columns of {@link tlsCsvRows} (language-neutral; the view writes the same headers). */
export const TLS_CSV_COLUMNS = Object.freeze([
  'policy_domain', 'organization', 'report_id', 'begin', 'end', 'policy_type', 'result_type', 'receiving_mx', 'receiving_ip',
  'sending_mta_ip', 'failed_sessions', 'failure_reason_code', 'additional_information'
]);

/**
 * Where each failure type points, for the advice: `area` (what to fix: `starttls`, `certificate`,
 * `dane`, `sts-policy`) and `tools` (the checks that go deeper: `health` — Domain Health's MTA-STS
 * card and its policy check, `tlsa` — the TLSA records in DNS Lookup, `cert` — the MX host's
 * certificate and its DANE / TLSA tab in the Certificate view).
 */
const ADVICE = Object.freeze({
  'starttls-not-supported': { area: 'starttls', tools: ['health'] },
  'certificate-host-mismatch': { area: 'certificate', tools: ['cert', 'health'] },
  'certificate-expired': { area: 'certificate', tools: ['cert'] },
  'certificate-not-trusted': { area: 'certificate', tools: ['cert'] },
  'validation-failure': { area: 'certificate', tools: ['cert'] },
  'tlsa-invalid': { area: 'dane', tools: ['tlsa', 'cert'] },
  'dnssec-invalid': { area: 'dane', tools: ['tlsa'] },
  'dane-required': { area: 'dane', tools: ['tlsa', 'cert'] },
  'sts-policy-fetch-error': { area: 'sts-policy', tools: ['health'] },
  'sts-policy-invalid': { area: 'sts-policy', tools: ['health'] },
  'sts-webpki-invalid': { area: 'sts-policy', tools: ['health', 'cert'] },
  other: { area: 'other', tools: [] }
});

/** Advice areas ({@link tlsAdvice}), `rpt.tls.area.<id>` in the view. */
export const TLS_ADVICE_AREAS = Object.freeze(['starttls', 'certificate', 'dane', 'sts-policy', 'other']);

/**
 * @typedef {object} TlsFailure
 * @property {string} type a {@link TLS_RESULT_TYPES} value, or the reporter's own string lowercased
 * @property {boolean} known whether `type` is one of RFC 8460's
 * @property {string|null} sendingIp `sending-mta-ip`
 * @property {string|null} mx `receiving-mx-hostname`
 * @property {string|null} helo `receiving-mx-helo`
 * @property {string|null} receivingIp
 * @property {number} sessions `failed-session-count`
 * @property {string|null} reason `failure-reason-code` (free text, e.g. an OpenSSL error name)
 * @property {string|null} info `additional-information` (a URI of the reporter)
 */

/**
 * @typedef {object} TlsPolicy
 * @property {'sts'|'tlsa'|'no-policy-found'|string} type
 * @property {string} domain `policy-domain`
 * @property {string[]} strings `policy-string` (the MTA-STS policy's lines, the TLSA records)
 * @property {string|null} mode an MTA-STS policy's `mode:` line (`enforce`, `testing`, `none`)
 * @property {string[]} mx `mx-host`
 * @property {number} success
 * @property {number} failure
 * @property {TlsFailure[]} failures
 */

/**
 * @typedef {object} TlsReport
 * @property {'tlsrpt'} kind
 * @property {string} key the organisation and report id: one report dropped twice counts once
 * @property {string} file where it came from
 * @property {string} org `organization-name`
 * @property {string|null} contact `contact-info`
 * @property {string} reportId
 * @property {Date|null} begin
 * @property {Date|null} end
 * @property {TlsPolicy[]} policies
 * @property {number} success every policy together
 * @property {number} failure
 */

const str = (v) => (typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '');
const count = (v) => {
  const n = typeof v === 'number' ? v : /^\s*\d+\s*$/.test(String(v ?? '')) ? Number(v) : NaN;
  return Number.isSafeInteger(n) && n >= 0 ? n : 0;
};
const date = (v) => {
  const t = Date.parse(str(v));
  return Number.isFinite(t) ? new Date(t) : null;
};
const list = (v) => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const host = (v) => {
  const s = str(v).replace(/\.$/, '');
  return s ? normalizeHostname(s, { allowWildcard: true }) || s.toLowerCase() : null;
};

/** Does a parsed JSON value look like a TLS report (an organisation and a policies array)? */
function isTlsShape(obj) {
  return !!obj && typeof obj === 'object' && !Array.isArray(obj) && Array.isArray(obj.policies)
    && ('organization-name' in obj || 'report-id' in obj || 'date-range' in obj);
}

/**
 * Read one TLS report.
 * @param {string|object} input the JSON text, or the object JSON.parse gave
 * @param {{ file?: string }} [opts]
 * @returns {{ ok: true, report: TlsReport } | { ok: false, code: string, detail: string }} `code`: one of {@link TLS_REPORT_ERRORS}
 */
export function parseTlsReport(input, { file = '' } = {}) {
  let obj = input;
  if (typeof input === 'string') {
    try {
      obj = JSON.parse(input.replace(/^﻿/, ''));
    } catch (err) {
      return { ok: false, code: 'not-json', detail: String((err && err.message) || err).slice(0, 200) };
    }
  }
  if (!isTlsShape(obj)) return { ok: false, code: 'not-tlsrpt', detail: '' };
  const range = obj['date-range'] || {};
  const org = str(obj['organization-name']);
  const reportId = str(obj['report-id']);
  const policies = [];
  for (const p of obj.policies) {
    if (!p || typeof p !== 'object') continue;
    const pol = p.policy || {};
    const strings = list(pol['policy-string']).map(str).filter(Boolean);
    const modeLine = strings.find((s) => /^mode\s*:/i.test(s));
    const summary = p.summary || {};
    policies.push({
      type: str(pol['policy-type']).toLowerCase() || 'no-policy-found',
      domain: host(pol['policy-domain']) || '',
      strings,
      mode: modeLine ? modeLine.split(':').slice(1).join(':').trim().toLowerCase() || null : null,
      mx: list(pol['mx-host'] ?? pol['mx-host-pattern']).map(host).filter(Boolean),
      success: count(summary['total-successful-session-count']),
      failure: count(summary['total-failure-session-count']),
      failures: list(p['failure-details']).filter((f) => f && typeof f === 'object').map((f) => {
        const type = str(f['result-type']).toLowerCase() || 'unknown';
        return {
          type,
          known: TLS_RESULT_TYPES.includes(type),
          sendingIp: normalizeIP(str(f['sending-mta-ip'])) || str(f['sending-mta-ip']) || null,
          mx: host(f['receiving-mx-hostname']),
          helo: host(f['receiving-mx-helo']),
          receivingIp: normalizeIP(str(f['receiving-ip'])) || str(f['receiving-ip']) || null,
          sessions: count(f['failed-session-count']),
          reason: str(f['failure-reason-code']) || null,
          info: str(f['additional-information']) || null
        };
      })
    });
  }
  const domains = policies.map((p) => p.domain).filter(Boolean);
  if (!org || !policies.length || !domains.length) {
    return { ok: false, code: 'incomplete', detail: !org ? 'organization-name' : 'policies' };
  }
  const begin = date(range['start-datetime']);
  const end = date(range['end-datetime']);
  return {
    ok: true,
    report: {
      kind: 'tlsrpt',
      key: `${org.toLowerCase()}|${reportId || `${domains[0]}|${begin ? begin.getTime() : ''}`}`,
      file,
      org,
      contact: str(obj['contact-info']) || null,
      reportId,
      begin,
      end,
      policies,
      success: policies.reduce((n, p) => n + p.success, 0),
      failure: policies.reduce((n, p) => n + p.failure, 0)
    }
  };
}

/**
 * What a failure type points at and which checks go deeper (the view words it).
 * @param {string} type
 * @returns {{ type: string, area: string, tools: string[] }}
 */
export function tlsAdvice(type) {
  const known = TLS_RESULT_TYPES.includes(type);
  const a = ADVICE[known ? type : 'other'];
  return { type: known ? type : 'other', area: a.area, tools: [...a.tools] };
}

/**
 * @typedef {object} TlsSummary
 * @property {string} domain the policy domain
 * @property {number} reports
 * @property {Date|null} begin
 * @property {Date|null} end
 * @property {number} success
 * @property {number} failure
 * @property {number|null} rate success / every session, null without sessions
 * @property {Array<{ org: string, reports: number, success: number, failure: number }>} orgs most sessions first
 * @property {Array<{ type: string, mode: string|null, success: number, failure: number, mx: string[] }>} policies
 *   by policy type (and MTA-STS mode), as the senders found them
 * @property {Array<{ type: string, known: boolean, sessions: number, mx: string[], orgs: string[], receivingIps: string[],
 *   reasons: string[] }>} byType most failed sessions first
 * @property {Array<{ mx: string, sessions: number, types: string[] }>} byMx most failed sessions first
 * @property {Array<object>} failures one row per failure detail ({@link tlsCsvRows} fields)
 */

const bump = (map, key, make) => {
  if (!map.has(key)) map.set(key, make());
  return map.get(key);
};
/** What each list addUnique fills holds: a report with many distinct values stays linear. */
const listIndex = new WeakMap();
const addUnique = (arr, v) => {
  if (!listIndex.has(arr)) listIndex.set(arr, new Set());
  const seen = listIndex.get(arr);
  if (v && !seen.has(v)) {
    seen.add(v);
    arr.push(v);
  }
};
const earliest = (a, b) => (!a ? b : !b ? a : a < b ? a : b);
const latest = (a, b) => (!a ? b : !b ? a : a > b ? a : b);

/**
 * Every report of each policy domain together. A report dropped twice (the same organisation and
 * report id) counts once. Domains with the most sessions first.
 * @param {TlsReport[]} reports
 * @returns {{ domains: TlsSummary[], duplicates: number }}
 */
export function summarizeTls(reports) {
  const seen = new Set();
  let duplicates = 0;
  const byDomain = new Map();
  for (const r of reports || []) {
    if (!r || r.kind !== 'tlsrpt') continue;
    if (seen.has(r.key)) {
      duplicates += 1;
      continue;
    }
    seen.add(r.key);
    for (const p of r.policies) {
      const d = bump(byDomain, p.domain, () => ({
        domain: p.domain, reportKeys: new Set(), begin: null, end: null, success: 0, failure: 0,
        orgs: new Map(), policies: new Map(), types: new Map(), mxs: new Map(), failures: []
      }));
      d.reportKeys.add(r.key);
      d.begin = earliest(d.begin, r.begin);
      d.end = latest(d.end, r.end);
      d.success += p.success;
      d.failure += p.failure;
      const o = bump(d.orgs, r.org, () => ({ org: r.org, reports: new Set(), success: 0, failure: 0 }));
      o.reports.add(r.key);
      o.success += p.success;
      o.failure += p.failure;
      const pk = `${p.type}|${p.mode || ''}`;
      const pol = bump(d.policies, pk, () => ({ type: p.type, mode: p.mode, success: 0, failure: 0, mx: [] }));
      pol.success += p.success;
      pol.failure += p.failure;
      for (const m of p.mx) addUnique(pol.mx, m);
      for (const f of p.failures) {
        const ty = bump(d.types, f.type, () => ({ type: f.type, known: f.known, sessions: 0, mx: [], orgs: [], receivingIps: [], reasons: [] }));
        ty.sessions += f.sessions;
        addUnique(ty.mx, f.mx);
        addUnique(ty.orgs, r.org);
        addUnique(ty.receivingIps, f.receivingIp);
        addUnique(ty.reasons, f.reason);
        const mxKey = f.mx || f.receivingIp || '';
        if (mxKey) {
          const m = bump(d.mxs, mxKey, () => ({ mx: mxKey, sessions: 0, types: [] }));
          m.sessions += f.sessions;
          addUnique(m.types, f.type);
        }
        d.failures.push(failureRow(r, p, f));
      }
    }
  }
  const byCount = (key) => (a, b) => b[key] - a[key];
  const domains = [...byDomain.values()].map((d) => ({
    domain: d.domain,
    reports: d.reportKeys.size,
    begin: d.begin,
    end: d.end,
    success: d.success,
    failure: d.failure,
    rate: d.success + d.failure ? d.success / (d.success + d.failure) : null,
    orgs: [...d.orgs.values()].map((o) => ({ org: o.org, reports: o.reports.size, success: o.success, failure: o.failure }))
      .sort((a, b) => (b.success + b.failure) - (a.success + a.failure) || a.org.localeCompare(b.org)),
    policies: [...d.policies.values()].sort((a, b) => (b.success + b.failure) - (a.success + a.failure)),
    byType: [...d.types.values()].sort(byCount('sessions')),
    byMx: [...d.mxs.values()].sort(byCount('sessions')),
    failures: d.failures.sort((a, b) => b.failed_sessions - a.failed_sessions)
  })).sort((a, b) => (b.success + b.failure) - (a.success + a.failure) || a.domain.localeCompare(b.domain));
  return { domains, duplicates };
}

function failureRow(r, p, f) {
  return {
    policy_domain: p.domain,
    organization: r.org,
    report_id: r.reportId,
    begin: r.begin ? r.begin.toISOString() : '',
    end: r.end ? r.end.toISOString() : '',
    policy_type: p.type,
    result_type: f.type,
    receiving_mx: f.mx || '',
    receiving_ip: f.receivingIp || '',
    sending_mta_ip: f.sendingIp || '',
    failed_sessions: f.sessions,
    failure_reason_code: f.reason || '',
    additional_information: f.info || ''
  };
}

/**
 * The failure details of a summary, one CSV row each ({@link TLS_CSV_COLUMNS}).
 * @param {TlsSummary} summary
 * @returns {object[]}
 */
export function tlsCsvRows(summary) {
  return (summary && summary.failures ? summary.failures : []).map((row) => ({ ...row }));
}
