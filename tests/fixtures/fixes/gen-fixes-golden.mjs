#!/usr/bin/env node
/**
 * Goldens of assets/js/lib/fixes.js and changecheck.js — every change-request template (and the
 * fixes of Domain Health and Zone File) in every format, the admin's instructions in English and
 * Turkish, and the check link.
 *
 *   node tests/fixtures/fixes/gen-fixes-golden.mjs            # compare, print the first difference, exit 1 on change
 *   node tests/fixtures/fixes/gen-fixes-golden.mjs --write    # rewrite expected/<case>.golden.txt
 *
 * One file per case, sections `## <part>`: problems and notes (key + params), the check link's
 * query, then each format with its notes, then the instructions. The Domain Health fixes are built
 * from small reports made with lib/health.js's own parsers. Names are example.com / .net / .org,
 * addresses documentation space; provider names (smtp.google.com …) are what the templates publish.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  buildChange, changeRequest, renderFix, formatNotes, changeInstructions, validateChange, hasErrors, healthFix, FIX_FORMATS
} from '../../../assets/js/lib/fixes.js';
import { checkFromRequest, encodeCheck } from '../../../assets/js/lib/changecheck.js';
import { parseCaa, checkCaaAllows, parseDmarc } from '../../../assets/js/lib/health.js';

export const FIXES_DIR = dirname(fileURLToPath(import.meta.url));
const EXPECTED = join(FIXES_DIR, 'expected');
const CHECK_BASE = 'https://example.github.io/domainscope/#/change/check?';

const TXT = (...v) => v.map((s) => [s]);
const ok = (values, ttl = 3600) => ({ status: 'ok', values, ttl, cname: null });
const none = { status: 'nodata', values: [], ttl: null, cname: null };

/** What a live read found for the "read" cases (lib/fixes.js readCurrent shape). */
export const CURRENT = Object.freeze({
  'example.com|TXT': ok(TXT('v=spf1 include:spf.protection.outlook.com ~all', 'google-site-verification=abc123')),
  'example.com|MX': ok([{ preference: 10, exchange: 'mail.example.com' }]),
  'example.com|CAA': ok([{ flags: 0, tag: 'issue', value: 'pki.goog' }]),
  'example.com|CNAME': none,
  '_dmarc.example.com|TXT': ok(TXT('v=DMARC1; p=none; rua=mailto:dmarc@example.com')),
  '_dmarc.example.com|CNAME': none,
  'autodiscover.example.com|CNAME': none,
  'autodiscover.example.com|A': none,
  'www.example.com|A': ok(['198.51.100.5'], 2911),
  'www.example.com|CNAME': none,
  'shop.example.com|A': ok(['203.0.113.7']),
  'shop.example.com|CNAME': none,
  'mail.example.com|TXT': ok(TXT('v=spf1 a -all')),
  'mail.example.com|CNAME': none,
  '_acme-challenge.example.net|CNAME': ok(['d7c1f3a2.auth.example.org']),
  '_acme-challenge.example.net|TXT': none
});

/**
 * A Domain Health report (lib/health.js domainHealth shape) with what the fixes read: the records,
 * the SPF / DMARC / CAA findings of the parsers, and the CAA check of the current certificate.
 */
export function healthReport({ domain = 'example.com', zone = 'example.com', txt = [], mx = [], caa = [], caaAt = null, issuerDN = null,
  dmarc = null, dmarcAt = null } = {}) {
  const parsedCaa = parseCaa(caa);
  const inherited = !!dmarc && !!dmarcAt && dmarcAt !== domain;
  return {
    domain, zone, records: { txt, mx, caa },
    spf: { record: null, parsed: null, lookups: null },
    dmarc: { record: dmarc, parsed: dmarc ? parseDmarc(dmarc) : null, foundAt: dmarc ? dmarcAt || domain : null, inherited },
    caa: { name: domain, foundAt: caa.length ? caaAt || domain : null, records: caa.map((data) => ({ type: 'CAA', data })), parsed: parsedCaa },
    caaCert: issuerDN ? checkCaaAllows(parsedCaa, issuerDN) : null,
    failedLookups: [], checks: []
  };
}

const LE = "CN=R11,O=Let's Encrypt,C=US";
const healthCase = (id, report) => () => healthFix({ id, params: { issuer: "Let's Encrypt" } }, report).request;

const TOKEN_A = 'gfj9Xq3Wr1Bm5zQXxZrW1zFeI6nY6cRgO0sIkWQfVbk';
const TOKEN_B = 'LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0';

/** Every case: a template with its form (and whether the live read above is applied). */
export const CASES = Object.freeze([
  { id: 'acme-txt-wildcard', template: 'acme-txt', input: { name: '*.example.com', tokens: `${TOKEN_A}\n${TOKEN_B}` } },
  { id: 'acme-txt-delegated', template: 'acme-txt', input: { name: 'example.net', tokens: TOKEN_A }, read: true },
  // The record name an ACME client prints, pasted as the certificate name: the label is not doubled.
  { id: 'acme-txt-pasted', template: 'acme-txt', input: { name: '_acme-challenge.example.com', tokens: TOKEN_A } },
  { id: 'acme-cname', template: 'acme-cname', input: { name: 'www.example.com', target: 'd7c1f3a2.auth.example.org' } },
  { id: 'm365', template: 'm365', input: { domain: 'example.com', tenant: 'example.onmicrosoft.com', rua: 'dmarc@example.com' } },
  { id: 'm365-read', template: 'm365', input: { domain: 'example.com', tenant: 'example.onmicrosoft.com' }, read: true },
  { id: 'google-read', template: 'google', input: { domain: 'example.com', dkimKey: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAexampleexampleexample' }, read: true },
  { id: 'caa', template: 'caa', input: { domain: 'example.com', cas: ['letsencrypt', 'google'], wild: 'none', methods: ['dns-01'], iodef: 'security@example.com' }, read: true },
  { id: 'caa-account', template: 'caa', input: { domain: 'example.org', cas: ['letsencrypt'], accountUri: 'https://acme-v02.api.letsencrypt.org/acme/acct/123456' } },
  { id: 'spf-add', template: 'spf', input: { domain: 'example.com', spfAction: 'add', includes: '_spf.google.com', all: '-all' }, read: true },
  { id: 'spf-remove', template: 'spf', input: { domain: 'example.com', spfAction: 'remove', includes: 'spf.protection.outlook.com' }, read: true },
  { id: 'spf-unread', template: 'spf', input: { domain: 'example.com', spfAction: 'add', includes: 'mailgun.org' } },
  // An include cannot be removed from a record that was not read: no output at all.
  { id: 'spf-remove-unread', template: 'spf', input: { domain: 'example.com', spfAction: 'remove', includes: 'mailgun.org' } },
  { id: 'dmarc-step', template: 'dmarc', input: { domain: 'example.com', policy: 'quarantine', pct: '25' }, read: true },
  // Not read: the instructions say which tags the value leaves out, and name no policy it comes from.
  { id: 'dmarc-unread', template: 'dmarc', input: { domain: 'example.com', policy: 'reject' } },
  { id: 'ttl', template: 'ttl', input: { domain: 'example.com', records: 'www A\n@ MX', ttl: '300' }, read: true },
  { id: 'ttl-unread', template: 'ttl', input: { domain: 'example.com', records: 'www A' } },
  { id: 'record-a', template: 'record', input: { name: 'www', zone: 'example.com', type: 'A', values: '192.0.2.10\n192.0.2.11', ttl: '600' }, read: true },
  { id: 'record-cname-conflict', template: 'record', input: { name: 'shop.example.com', type: 'CNAME', values: 'shops.example.net' }, read: true },
  { id: 'record-txt-long', template: 'record', input: { name: 'long.example.com', type: 'TXT', values: `v=DKIM1; k=rsa; p=${'A'.repeat(300)}` } },
  { id: 'record-mx-delete', template: 'record', input: { name: 'example.com', type: 'MX', action: 'delete' }, read: true },
  // Every TXT record of a name where the read found only an SPF record: the link says so (TXT:*).
  { id: 'record-txt-delete-all', template: 'record', input: { name: 'mail.example.com', type: 'TXT', action: 'delete' }, read: true },
  { id: 'record-txt-escapes', template: 'record', input: { name: 'quote.example.com', type: 'TXT', values: 'a "quoted" \\ back|slash ^ caret; semi \'single\' café' } },
  { id: 'parked', template: 'parked', input: { domain: 'example.org', dkim: true } },
  { id: 'parked-mail-only', template: 'parked', input: { domain: 'example.com', caa: false }, read: true },
  // Domain Health fixes: the CA of the current certificate added where the CAA set of a subdomain lives (the parent).
  { id: 'health-caa-cert-denied', request: healthCase('caa.cert-denied', healthReport({ domain: 'www.example.com', caa: [{ flags: 0, tag: 'issue', value: 'pki.goog' }, { flags: 0, tag: 'iodef', value: 'mailto:security@example.com' }], caaAt: 'example.com', issuerDN: LE })) },
  { id: 'health-caa-critical', request: healthCase('caa.critical-unknown', healthReport({ caa: [{ flags: 128, tag: 'tbs', value: 'unknown' }, { flags: 0, tag: 'issue', value: 'letsencrypt.org' }] })) },
  // A subdomain that inherits "p=reject; sp=none": the organizational domain's record is the one that changes.
  { id: 'health-dmarc-inherited-sp', request: healthCase('dmarc.policy-none', healthReport({ domain: 'shop.example.com', dmarc: 'v=DMARC1; p=reject; sp=none; pct=50', dmarcAt: 'example.com' })) },
  { id: 'health-dmarc-inherited-rua', request: healthCase('dmarc.rua-missing', healthReport({ domain: 'shop.example.com', dmarc: 'v=DMARC1; p=reject; sp=none', dmarcAt: 'example.com' })) },
  { id: 'lint-ttl', request: () => changeRequest({ zone: 'example.com', rrsets: [{ name: 'api.example.com', type: 'A', ttl: 300, mode: 'is', values: ['192.0.2.20'], before: ['192.0.2.20'], beforeTtl: 5 }] }) }
]);

/** The request of a case. */
export function caseRequest(c) {
  if (c.request) return c.request();
  return buildChange(c.template, c.input, { current: c.read ? CURRENT : null });
}

const line = (p) => `${p.severity ? `${p.severity} ` : ''}${p.key} ${JSON.stringify(p.params || {})}`;

/** The golden text of one case. */
export function caseGolden(c) {
  const req = caseRequest(c);
  const out = [`# case: ${c.id}`];
  const problems = validateChange(req, { current: c.read ? CURRENT : null });
  out.push('## problems', ...problems.map(line));
  out.push('## notes', ...req.notes.map(line));
  if (hasErrors({ problems })) return `${out.join('\n')}\n`;
  const link = encodeCheck(checkFromRequest(req));
  out.push('## check', link.ok ? link.query : `(no link: ${link.reason})`);
  for (const f of FIX_FORMATS) {
    out.push(`## ${f}`, renderFix(req, f).replace(/\n$/, ''));
    const notes = formatNotes(req, f);
    if (notes.length) out.push(`## ${f} notes`, ...notes.map(line));
  }
  const checkUrl = link.ok ? `${CHECK_BASE}${link.query}` : null;
  out.push('## en', changeInstructions(req, { lang: 'en', checkUrl }).replace(/\n$/, ''));
  out.push('## tr', changeInstructions(req, { lang: 'tr', checkUrl }).replace(/\n$/, ''));
  return `${out.join('\n')}\n`;
}

export const goldenPath = (id) => join(EXPECTED, `${id}.golden.txt`);

function main() {
  const write = process.argv.includes('--write');
  if (write) mkdirSync(EXPECTED, { recursive: true });
  let changed = 0;
  for (const c of CASES) {
    const text = caseGolden(c);
    const path = goldenPath(c.id);
    const old = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (old === text) continue;
    changed += 1;
    if (write) {
      writeFileSync(path, text);
      process.stdout.write(`wrote ${c.id}\n`);
    } else {
      const a = (old || '').split('\n');
      const b = text.split('\n');
      const i = b.findIndex((l, n) => l !== a[n]);
      process.stdout.write(`${c.id}: line ${i + 1}\n- ${a[i] ?? '(none)'}\n+ ${b[i] ?? '(none)'}\n`);
    }
  }
  if (!write && changed) process.exitCode = 1;
  process.stdout.write(`${CASES.length} cases, ${changed} ${write ? 'written' : 'different'}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
