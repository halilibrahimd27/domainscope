/**
 * A nightly repository's results folder, made up (documentation names and addresses only) for the
 * Monitoring view's tests: tests/js/monitor.test.js, tests/js/monitor-view.test.js and the offline
 * E2E suite tests/e2e/monitor.e2e.mjs, which writes it to a temporary folder.
 *
 * results/: health.json, ct.json, tls.json, takeover.json and audit.json as the runner writes them
 * (tools/ds.mjs, with --baseline: their `changes`), a Markdown summary next to each, and
 * history/2026-08.jsonl … 2026-10.jsonl, one line per target and check a night from 2026-08-20
 * (lib/monitor.js historyLines, as `--history results/history` writes them; the last night is the
 * reports' own run). The story, as of {@link MONITOR_NOW} (2026-10-09 08:00 UTC):
 * - example.com: health B (82) after a DMARC policy got worse on 2026-10-05; its CT certificate
 *   expires in 15 days and Google Trust Services is a new issuer tonight; a takeover risk (high:
 *   mx.example.org pending deletion) since 2026-10-03; the takeover check last ran 2026-10-07 —
 *   two nights ago — so it did not complete since; the audit fails one rule (dnssec), security 5/8;
 * - example.org: health fell to E (58) tonight with a TXT lookup that failed: not completed;
 * - example.net: health A (95), nothing changed;
 * - www.example.com (tls): renewed on 2026-09-10, 53 days left;
 * - mail.example.net (tls): its certificate expired on 2026-10-05 (EXPIRED since).
 * One line of 2026-10.jsonl is not JSON and one is a newer format (v 2): both skipped.
 */

export const MONITOR_NOW = Date.parse('2026-10-09T08:00:00Z');
const DAY = 86400000;
const iso = (ms) => new Date(ms).toISOString();
const day = (s) => Date.parse(`${s}T00:00:00Z`);
const daysLeft = (notAfter, at) => Math.floor((Date.parse(notAfter) - at) / DAY);
const gradeFor = (score) => (score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : score >= 50 ? 'E' : 'F');

/** Each check's time of night (a run ends at that minute). */
const AT = Object.freeze({ health: '03:20', ct: '03:25', tls: '03:30', takeover: '03:35', audit: '03:40' });
const at = (dayIso, command) => Date.parse(`${dayIso}T${AT[command]}:00Z`);
const TONIGHT = '2026-10-09';
/** The takeover check stopped running after this night. */
const TAKEOVER_LAST = '2026-10-07';

const envelope = (command, finishedAt, targets, changes) => ({
  tool: 'domainscope-ds', version: '1.0.0', command,
  startedAt: iso(finishedAt - 60000), finishedAt: iso(finishedAt),
  options: { resolvers: ['cloudflare', 'google', 'dnssb'] },
  targets,
  baseline: { file: `${command}.json`, missing: false, version: '1.0.0', startedAt: iso(finishedAt - DAY - 60000), finishedAt: iso(finishedAt - DAY) },
  changes
});
const change = (tag, tone, target, item, text, extra = {}) => ({
  tag, tone, counts: tone === 'bad' || tone === 'good', target, item, kind: extra.kind || 'changed', before: extra.before ?? null, after: extra.after ?? null, text
});

/* --- the story, night by night ------------------------------------------- */

const healthScore = (target, d) => {
  if (target === 'example.com') return d >= day('2026-10-05') ? 82 : 90;
  if (target === 'example.org') return d >= day(TONIGHT) ? 58 : 70;
  return 95;
};
const tlsCert = (target, d) => {
  if (target === 'www.example.com') return d >= day('2026-09-10') ? '2026-12-01T12:00:00.000Z' : '2026-09-30T12:00:00.000Z';
  return '2026-10-05T12:00:00.000Z';
};
const ctNotAfter = '2026-10-24T12:00:00.000Z';

/** The changes of a night's line per command and target: [tag, tone, item]. */
function nightChanges(command, target, dIso) {
  if (command === 'health' && target === 'example.com' && dIso === '2026-10-05') return [['WORSE', 'bad', 'dmarc.policy'], ['SCORE', 'info', null]];
  if (command === 'health' && target === 'example.org' && dIso === TONIGHT) return [['NEW', 'bad', 'spf.error'], ['SCORE', 'quiet', null]];
  if (command === 'tls' && target === 'www.example.com' && dIso === '2026-09-10') return [['CERT', 'info', '192.0.2.10|443']];
  if (command === 'tls' && target === 'mail.example.net' && dIso === '2026-10-05') return [['WORSE', 'bad', '198.51.100.25|443']];
  if (command === 'takeover' && target === 'example.com' && dIso === '2026-10-03') return [['RISK', 'bad', 'mx|example.com|mx.example.org']];
  if (command === 'ct' && target === 'example.com' && dIso === TONIGHT) return [['ISSUER', 'bad', 'Google Trust Services']];
  return [];
}

const COMMAND_TARGETS = Object.freeze({
  health: ['example.com', 'example.org', 'example.net'],
  ct: ['example.com', 'example.org'],
  tls: ['www.example.com', 'mail.example.net'],
  takeover: ['example.com'],
  audit: ['example.com']
});

/** One history line as lib/monitor.js historyLines writes it. */
function line(command, target, dIso) {
  const t = at(dIso, command);
  const changes = nightChanges(command, target, dIso);
  const bad = changes.filter(([, tone]) => tone === 'bad').length;
  const out = { v: 1, at: iso(t), command, target, ok: !(command === 'health' && target === 'example.org' && dIso === TONIGHT) };
  if (command === 'health') {
    out.score = healthScore(target, t);
    out.grade = gradeFor(out.score);
  }
  if (command === 'tls') out.minDaysLeft = daysLeft(tlsCert(target, t), t);
  if (command === 'ct') out.minDaysLeft = target === 'example.com' ? daysLeft(ctNotAfter, t) : daysLeft('2026-12-30T12:00:00.000Z', t);
  out.counts = { bad, info: changes.length - bad };
  out.changes = changes.map(([tag, tone, item]) => ({ tag, tone, item }));
  out.run = `https://github.com/example-org/nightly/actions/runs/${4000 + Math.round((t - day('2026-08-01')) / DAY)}`;
  return out;
}

/** Every night's lines from 2026-08-20 to tonight, by month file. */
function historyFiles() {
  const months = new Map();
  for (let d = day('2026-08-20'); d <= day(TONIGHT); d += DAY) {
    const dIso = iso(d).slice(0, 10);
    for (const [command, targets] of Object.entries(COMMAND_TARGETS)) {
      if (command === 'takeover' && d > day(TAKEOVER_LAST)) continue;
      if (command === 'audit' && d < day('2026-10-01')) continue;
      for (const target of targets) {
        const name = `${dIso.slice(0, 7)}.jsonl`;
        if (!months.has(name)) months.set(name, []);
        months.get(name).push(JSON.stringify(line(command, target, dIso)));
      }
    }
  }
  const oct = months.get('2026-10.jsonl');
  oct.splice(3, 0, '{"v":1,"at":"2026-10-01T03:20:00.000Z","command":"health"', '{"v":2,"at":"2026-10-01T03:20:00.000Z","command":"health","target":"example.com"}');
  return [...months].map(([name, rows]) => ({ name, text: `${rows.join('\n')}\n` }));
}

/* --- tonight's reports ------------------------------------------------------ */

function healthReport() {
  const t = at(TONIGHT, 'health');
  const target = (domain, checks, extra = {}) => {
    const score = healthScore(domain, t);
    return {
      target: domain, checkedAt: iso(t - 30000), score, grade: gradeFor(score), light: checks.some((c) => c.severity === 'error') ? 'error' : checks.length ? 'warn' : 'ok',
      summary: { ok: 20, info: 2, warn: checks.filter((c) => c.severity === 'warn').length, error: checks.filter((c) => c.severity === 'error').length },
      failedLookups: [], checks, ...extra
    };
  };
  return envelope('health', t, [
    target('example.com', [{ id: 'dmarc.policy', severity: 'warn', titleKey: 'health.dmarc.policy', params: {}, title: 'DMARC policy is none' }]),
    target('example.org', [{ id: 'spf.error', severity: 'error', titleKey: 'health.spf.error', params: {}, title: 'SPF record has an error' },
      { id: 'mx.lookup-error', severity: 'error', titleKey: 'health.mx.lookup', params: {}, title: 'MX lookup failed' }], { failedLookups: ['txt'] }),
    target('example.net', [])
  ], [
    change('NEW', 'bad', 'example.org', 'spf.error', 'example.org: error spf.error — SPF record has an error', { kind: 'appeared', after: 'error' }),
    change('SCORE', 'quiet', 'example.org', null, 'example.org: health score 70 → 58 (a lookup failed this run)', { before: 70, after: 58 })
  ]);
}

function ctReport() {
  const t = at(TONIGHT, 'ct');
  const cert = (id, names, ca, notBefore, notAfter, current) => ({
    id, ca, intermediate: ca === 'Google Trust Services' ? 'WR1' : 'R11', issuer: `C=US, O=${ca}, CN=${ca === 'Google Trust Services' ? 'WR1' : 'R11'}`,
    notBefore, notAfter, names, sha256: null, serialHex: null, sources: ['crtsh'], revoked: null, precert: null,
    wildcard: false, daysLeft: daysLeft(notAfter, t), current, isNew: false, unexpected: null, flags: []
  });
  const target = (domain, certificates) => ({
    target: domain, days: 30, readAt: iso(t - 50000),
    sources: [{ source: 'crtsh', state: 'ok', ok: true, truncated: false, errorKind: null, error: null }],
    complete: true, answered: true, recent: 1,
    issuers: [...new Set(certificates.map((c) => c.ca))].map((name) => ({ name, count: 1, intermediates: [], newest: certificates[0].notBefore })),
    names: [...new Set(certificates.flatMap((c) => c.names))].sort(), certificates,
    watch: { radar: [30, 14, 7], expected: [], comparedWith: iso(t - DAY), counts: { current: certificates.filter((c) => c.current).length, expiring: 1, new: 0, unexpected: 0, wildcard: 0, precert: 0, revoked: 0 } }
  });
  return envelope('ct', t, [
    target('example.com', [
      cert('ct-com-1', ['example.com', 'www.example.com'], 'Let\'s Encrypt', '2026-07-26T12:00:00.000Z', ctNotAfter, true),
      cert('ct-com-2', ['api.example.com'], 'Google Trust Services', '2026-10-08T12:00:00.000Z', '2027-01-06T12:00:00.000Z', true)
    ]),
    target('example.org', [cert('ct-org-1', ['example.org'], 'Let\'s Encrypt', '2026-10-01T12:00:00.000Z', '2026-12-30T12:00:00.000Z', true)])
  ], [change('ISSUER', 'bad', 'example.com', 'Google Trust Services', 'example.com: new issuer Google Trust Services (1 certificate)', { kind: 'appeared' })]);
}

function tlsReport() {
  const t = at(TONIGHT, 'tls');
  const cert = (sha, subject, notAfter) => ({
    sha256: sha, serialHex: '0a1b2c', subject, issuer: 'C=US, O=Let\'s Encrypt, CN=R11', ca: 'Let\'s Encrypt', caId: 'letsencrypt', names: [subject],
    notBefore: '2026-07-01T12:00:00.000Z', notAfter, daysLeft: daysLeft(notAfter, t), keyType: 'EC', keyBits: 256, curve: 'P-256', authorityKeyId: null, crlUrls: []
  });
  return envelope('tls', t, [
    {
      target: 'www.example.com', host: 'www.example.com', port: 443, checkedAt: iso(t - 20000),
      dns: { status: 'NOERROR', ipv4: ['192.0.2.10'], ipv6: ['2001:db8::10'], cnames: [], error: null },
      endpoints: [
        { address: '192.0.2.10', family: 4, port: 443, status: 'OK', error: null, protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', trusted: true, trustError: null, nameMatch: true, chainLength: 2, cert: cert('a1'.repeat(32), 'www.example.com', '2026-12-01T12:00:00.000Z') },
        { address: '2001:db8::10', family: 6, port: 443, status: 'SKIPPED', error: 'no-ipv6-route', protocol: null, cipher: null, trusted: null, trustError: null, nameMatch: null, chainLength: 0 }
      ]
    },
    {
      target: 'mail.example.net', host: 'mail.example.net', port: 443, checkedAt: iso(t - 10000),
      dns: { status: 'NOERROR', ipv4: ['198.51.100.25'], ipv6: [], cnames: [], error: null },
      endpoints: [{ address: '198.51.100.25', family: 4, port: 443, status: 'EXPIRED', error: null, protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', trusted: false, trustError: 'CERT_HAS_EXPIRED', nameMatch: true, chainLength: 2, cert: cert('b2'.repeat(32), 'mail.example.net', '2026-10-05T12:00:00.000Z') }]
    }
  ], []);
}

function takeoverReport() {
  const t = at(TAKEOVER_LAST, 'takeover');
  return envelope('takeover', t, [{
    target: 'example.com', checkedAt: iso(t - 5000), references: 12, checked: 4, hosts: 0, spfMacros: [],
    domains: [{ domain: 'example.org', verdict: 'pending-delete', expires: null }],
    risks: [{
      key: 'mx|example.com|mx.example.org', kind: 'mx', host: 'example.com', target: 'mx.example.org', chain: [], term: null, severity: 'high',
      reason: 'pending-delete', reasons: [{ code: 'pending-delete', severity: 'high', domain: 'example.org' }], domain: 'example.org', expires: null,
      service: null, evidence: 'example.org is pending deletion', fix: 'Remove the MX record or renew example.org'
    }],
    failures: []
  }], []);
}

function auditReport() {
  const t = at(TONIGHT, 'audit');
  return envelope('audit', t, [{
    target: 'example.com', checkedAt: iso(t - 4000), pass: 4, fail: 1, unknown: 0,
    rules: [
      { id: 'expiryDays', status: 'pass', required: '>= 30', actual: '120', evidence: 'expires in 120 days', key: 'pol.ev.expiry', params: {} },
      { id: 'dnssec', status: 'fail', required: 'signed', actual: 'unsigned', evidence: 'no DS record at the parent', key: 'pol.ev.dnssec', params: {} },
      { id: 'caa', status: 'pass', required: 'present', actual: 'present', evidence: 'CAA names letsencrypt.org', key: 'pol.ev.caa', params: {} },
      { id: 'spf', status: 'pass', required: 'present', actual: 'present', evidence: 'v=spf1 -all', key: 'pol.ev.spf', params: {} },
      { id: 'dmarc', status: 'pass', required: 'present', actual: 'p=none', evidence: 'p=none', key: 'pol.ev.dmarc', params: {} }
    ],
    row: {},
    security: { score: 5, max: 8, unknown: 0, measures: {} }
  }], []);
}

/**
 * The results folder as the view's file drop gets it: `{ name, text }` per file, reports first,
 * then the Markdown summaries (left alone by the view), then the history months.
 * @returns {{ files: Array<{ name: string, text: string }>, reports: Record<string, object>, history: Array<{ name: string, text: string }> }}
 */
export function monitorFixture() {
  const reports = { 'audit.json': auditReport(), 'ct.json': ctReport(), 'health.json': healthReport(), 'takeover.json': takeoverReport(), 'tls.json': tlsReport() };
  const history = historyFiles();
  const files = [
    ...Object.entries(reports).map(([name, doc]) => ({ name, text: `${JSON.stringify(doc, null, 2)}\n` })),
    ...Object.keys(reports).map((name) => ({ name: name.replace(/\.json$/, '.md'), text: `**${name}**\n` })),
    ...history
  ];
  return { files, reports, history };
}
