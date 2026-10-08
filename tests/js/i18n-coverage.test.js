/**
 * i18n coverage: every translation key the UI can ask for exists in English AND Turkish.
 *
 * - key sets of both languages are identical once the shell and every view are loaded, and
 *   each key uses the same {placeholders} in both;
 * - every literal key passed to t() in assets/js (shell, ui, views) exists;
 * - every key a library can emit (netinfo reasonKeys, health check ids, CAA reasons, source
 *   notes, error kinds, scanner stages/warnings, x509 and inventory warning codes, …) exists;
 * - each view, loaded alone next to the shell (as the lazy router does in the browser), finds
 *   all of its own literal keys — no view silently depends on strings another view registers.
 *
 * Pure Node: the views are DOM-free at import time.
 */
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const JS = join(ROOT, 'assets', 'js');
const imp = (rel) => import(pathToFileURL(join(ROOT, rel)).href);
const walk = (d) => readdirSync(d).flatMap((f) => {
  const p = join(d, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});
const VIEW_IDS = readdirSync(join(JS, 'views')).filter((f) => f.endsWith('.js')).map((f) => f.slice(0, -3)).sort();
const KEY_RE = /^[a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9_-]+)+$/;

/** Literal keys passed to t('…') / t(`…`) (no interpolation) in a source file (comment lines skipped). */
function literalKeys(source) {
  const src = source.split('\n').filter((line) => !/^\s*(?:\/\*|\*|\/\/)/.test(line)).join('\n');
  const keys = new Set();
  for (const re of [/\bt\(\s*'([^'\n]+)'/g, /\bt\(\s*"([^"\n]+)"/g, /\bt\(\s*`([^`$\n]+)`/g]) {
    for (const m of src.matchAll(re)) if (KEY_RE.test(m[1])) keys.add(m[1]);
  }
  return keys;
}

/** Sorted placeholder names of a string (or of a plural object's 'other' form). */
function placeholders(value) {
  const s = typeof value === 'string' ? value : '';
  return [...new Set([...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]))].sort().join(',');
}

let i18n;
let en;
let tr;
let views;
let subRun;

before(async () => {
  i18n = await imp('assets/js/i18n.js');
  await imp('assets/js/app.js');
  // The Workspaces dialog: the shell loads it on first use, not with a view.
  await imp('assets/js/ui/workspace-panel.js');
  // Subdomains › Sources › Related domains: loaded with a run that reads Certificate Transparency.
  await imp('assets/js/ui/related-domains.js');
  // Subdomains: a scan's progress and results, loaded with the first scan.
  subRun = await imp('assets/js/ui/subdomains-run.js');
  // Subdomains › Overview › Takeover risks: loaded with the results.
  await imp('assets/js/ui/takeover-panel.js');
  // Zone File › Compare and Convert: loaded on the first of those tabs.
  await imp('assets/js/ui/zone-tools.js');
  // IP Intel › a row's routing, RPKI and abuse contact panel: loaded when a row's details first open.
  await imp('assets/js/ui/ip-enrich-panel.js');
  // IP Intel › Domains on this IP: loaded on the first "Find domains".
  await imp('assets/js/ui/reverse-ip-panel.js');
  // IP Intel › a row's details › Blocklists: loaded when a row's details first open.
  await imp('assets/js/ui/dnsbl-panel.js');
  // Domain Health › Delegation: loaded on the first "Check the delegation".
  await imp('assets/js/ui/delegation-panel.js');
  // DNS Lookup › DNSSEC chain: loaded on the first click of its button.
  await imp('assets/js/ui/dnssec-panel.js');
  // DNS Lookup › Explain: loaded on the first click of its button.
  await imp('assets/js/ui/explain-panel.js');
  // Domain overview › Lookalike domains: loaded on the first click of Find lookalikes.
  await imp('assets/js/ui/lookalike-panel.js');
  // The customer report panel (Domain overview and Domain Health › Report): loaded on its first click.
  await imp('assets/js/ui/report.js');
  // Domain portfolio › Certificates (CT): loaded on the tab's first use.
  await imp('assets/js/ui/ctwatch-panel.js');
  // Domain portfolio › Domain security: loaded on the tab's first use.
  await imp('assets/js/ui/secscore-panel.js');
  // Renewal readiness › Plan: loaded on the panel's first open.
  await imp('assets/js/ui/renewal-planner.js');
  // DNS change request › the check page's cutover assistant: loaded with that page.
  await imp('assets/js/ui/cutover.js');
  // Global DNS › ISP resolvers: loaded on the first click of "Ask ISP resolvers…".
  await imp('assets/js/ui/isp-resolvers.js');
  // Global DNS › Expected value › the zone's name server: loaded on the first click of its button.
  await imp('assets/js/ui/soa-probe.js');
  // Domain Health v2 (problems first, the Web card): loaded with the first report.
  await imp('assets/js/ui/health-v2.js');
  // SSL Targets › Rollout: loaded on the tab's first show.
  await imp('assets/js/ui/rollout-panel.js');
  // Certificate › Compare: loaded on the tab's first use.
  await imp('assets/js/ui/cert-diff-panel.js');
  // The command palette: the shell loads it on the first Ctrl/Cmd+K.
  await imp('assets/js/ui/palette.js');
  views = {};
  for (const id of VIEW_IDS) views[id] = await imp(`assets/js/views/${id}.js`);
  en = new Set(i18n.listKeys('en'));
  tr = new Set(i18n.listKeys('tr'));
});

function missingIn(keys) {
  const out = [];
  for (const k of keys) {
    const langs = [!en.has(k) && 'en', !tr.has(k) && 'tr'].filter(Boolean);
    if (langs.length) out.push(`${k} [${langs.join('+')}]`);
  }
  return out;
}

describe('i18n coverage', () => {
  test('English and Turkish have exactly the same keys', () => {
    assert.deepEqual([...en].filter((k) => !tr.has(k)), [], 'keys only in English');
    assert.deepEqual([...tr].filter((k) => !en.has(k)), [], 'keys only in Turkish');
    assert.ok(en.size > 1000, `expected the full dictionary, got ${en.size} keys`);
  });

  test('every key uses the same {placeholders} in both languages and is never empty', () => {
    const bad = [];
    const prev = i18n.getLang();
    try {
      for (const k of en) {
        i18n.setLang('en');
        const e = i18n.t(k);
        i18n.setLang('tr');
        const t = i18n.t(k);
        if (!String(e).trim() || !String(t).trim()) bad.push(`${k}: empty`);
        else if (placeholders(e) !== placeholders(t)) bad.push(`${k}: en{${placeholders(e)}} tr{${placeholders(t)}}`);
      }
    } finally {
      i18n.setLang(prev);
    }
    assert.deepEqual(bad, []);
  });

  test('every literal t() key in the shell, ui and views exists', () => {
    const files = walk(JS).filter((f) => f.endsWith('.js') && !f.includes(`${join('js', 'lib')}`));
    const bad = [];
    for (const f of files) {
      for (const m of missingIn(literalKeys(readFileSync(f, 'utf8')))) bad.push(`${relative(ROOT, f)}: ${m}`);
    }
    assert.deepEqual(bad, []);
  });

  test('every key the libraries and view constants can produce exists', async () => {
    const [netinfo, sources, health, scanner, resolvers, app] = await Promise.all([
      imp('assets/js/lib/netinfo.js'), imp('assets/js/lib/sources.js'), imp('assets/js/lib/health.js'),
      imp('assets/js/lib/scanner.js'), imp('assets/js/lib/resolvers.js'), imp('assets/js/app.js')
    ]);
    const keys = new Set();
    const add = (k) => keys.add(k);
    for (const v of app.VIEWS) { add(`nav.${v.id}`); add(`nav.${v.id}.desc`); }
    for (const id of VIEW_IDS) {
      const m = views[id].default?.mount ? views[id].default : views[id];
      add(m.titleKey);
    }
    // netinfo: every reasonKey literal, plus what classifyResolution returns for real inputs.
    const netSrc = readFileSync(join(JS, 'lib', 'netinfo.js'), 'utf8');
    for (const m of netSrc.matchAll(/'(class\.[a-z.-]+)'/g)) add(m[1]);
    for (const p of netinfo.PROVIDERS) {
      add(`category.${p.category}`);
      if (p.cnameSuffixes[0]) add(netinfo.classifyResolution({ status: 'NOERROR', cnames: [`x.${p.cnameSuffixes[0]}`] }).reasonKey);
      const v4 = p.cidrs.find((c) => !c.includes(':'));
      if (v4) add(netinfo.classifyResolution({ status: 'NOERROR', ipv4: [v4.split('/')[0].replace(/\.0$/, '.1')] }).reasonKey);
    }
    for (const input of [
      { status: 'NXDOMAIN' }, { status: 'NXDOMAIN', cnames: ['a.example'] }, { status: 'NOERROR', cnames: ['a.example'] },
      { status: 'SERVFAIL', cnames: ['a.example'] }, { status: 'NOERROR' }, { status: 'SERVFAIL' }, { status: 'ERROR' },
      { status: 'NOERROR', ipv4: ['10.0.0.1'] }, { status: 'NOERROR', ipv4: ['8.8.8.8'] }
    ]) add(netinfo.classifyResolution(input).reasonKey);
    for (const k of ['cloudflare', 'cdn', 'platform', 'direct', 'private', 'unresolved', 'nxdomain', 'dangling']) add(`kind.${k}`);
    for (const s of ['ok', 'info', 'warn', 'error']) add(`severity.${s}`);
    for (const k of ['abort', 'timeout', 'rate-limit', 'http', 'network', 'parse', 'unknown']) add(`error.kind.${k}`);
    for (const r of resolvers.RESOLVERS) if (r.filtering) add(`settings.filter.${r.filtering}`);
    for (const s of sources.SOURCES) add(s.noteKey);
    for (const id of health.HEALTH_CHECK_IDS) { add(`health.${id}.title`); add(`health.${id}.detail`); }
    for (const g of ['dns', 'email', 'security', 'registration']) add(`health.group.${g}`);
    for (const r of health.CAA_REASONS) add(`health.caa.reason.${r}`);
    for (const p of health.CAA_PROBLEMS) add(`health.caa.problem.${p}`);
    for (const n of health.CAA_NOTES) add(`health.caa.note.${n}`);
    // Domain Health › MTA-STS policy (lib/mtasts.js): every finding and headline.
    const mtasts = await imp('assets/js/lib/mtasts.js');
    for (const id of mtasts.MTA_STS_FINDINGS) { add(`mtasts.${id}.title`); add(`mtasts.${id}.detail`); }
    for (const k of mtasts.MTA_STS_HEADLINES) add(`mtasts.head.${k}`);
    for (const s of ['records', 'ns', 'mx', 'spf', 'dmarc', 'dkim', 'caa', 'dnssec', 'wildcard', 'rdap']) add(`hlt.step.${s}`);
    // Reverse DNS (lib/ptrsweep.js): every FCrDNS status in Domain Health's mail card and in the
    // Reverse DNS view, every target issue and results filter, the PTR-based operator reasons.
    const ptrsweep = await imp('assets/js/lib/ptrsweep.js');
    for (const s of ptrsweep.FCRDNS_STATUSES) { add(`hlt.fcrdns.st.${s}`); add(`ptr.st.${s}`); add(`ptr.st.${s}.title`); }
    for (const s of ptrsweep.FORWARD_STATES) add(`ptr.fwd.${s}`);
    for (const c of ptrsweep.TARGET_ISSUES) add(`ptr.issue.${c}`);
    for (const f of ptrsweep.SWEEP_FILTERS) add(`ptr.filter.${f}`);
    for (const k of ['embedded', 'generic']) add(`ptr.pattern.${k}`);
    for (const p of netinfo.PROVIDERS) add(`ptr.op.${p.id === 'cloudflare' ? 'cloudflare' : p.category}`);
    // Retire an IP (lib/retire.js): every severity and verification (with its tooltip), every
    // address-box issue, every reason an SPF term cannot be told, every passive service, and
    // every "what to change" text views/retire.changeText can pick.
    const retire = await imp('assets/js/lib/retire.js');
    for (const s of retire.SEVERITIES) { add(`retire.sev.${s}`); add(`retire.sevTitle.${s}`); }
    for (const v of retire.VERIFIED_STATES) { add(`retire.ver.${v}`); add(`retire.verTitle.${v}`); }
    for (const c of retire.TARGET_ISSUES) add(`retire.issue.${c}`);
    for (const r of retire.UNKNOWN_REASONS) add(`retire.act.check.${r}`);
    for (const p of retire.PASSIVE_SOURCES) add(`retire.passive.src.${p}`);
    for (const s of retire.HOST_SOURCES) add(`retire.hosts.${s}`);
    for (const s of views.retire.EVIDENCE_SOURCES) add(`retire.ev.src.${s}`);
    for (const r of ['mx', 'ns', 'spf']) add(`retire.ev.roles.${r}`);
    for (const s of ['scan', 'zone', 'target']) add(`retire.filled.${s}`);
    for (const k of ['remove.a', 'remove.https', 'remove.spf', 'remove.spfStale', 'narrow', 'narrow.cidr', 'narrow.cidrHost', 'follow.spf', 'follow.cname',
      'repoint.mx', 'repoint.ns', 'repoint.other', 'glue', 'provider', 'origin', 'keep.shield', 'keep.range', 'shadowed', 'check.passive',
      'check.record-failed']) add(`retire.act.${k}`);
    for (const w of retire.FAILURE_KINDS) add(`retire.fail.${w}`);
    for (const a of retire.CHANGE_ACTIONS) assert.ok([...keys].some((k) => k.startsWith(`retire.act.${a}`)), `retire.act.${a}*`);
    // The missing intermediate and the root-store warnings (lib/chainfix.js, ui/chain-repair.js):
    // every store name and every warning a chain can get.
    const chainfix = await imp('assets/js/lib/chainfix.js');
    for (const s of chainfix.STORES) add(`chainfix.store.${s}`);
    for (const c of chainfix.LIFECYCLE_CODES) add(`chainfix.life.${c}`);
    // Subdomains: the zone chip and the Reverse DNS names chip (one key per mode), the result banners.
    for (const m of views.subdomains.ZONE_MODES) {
      for (const k of ['zone', 'handoff']) { add(`sub.${k}.mode.${m}`); add(`sub.${k}.mode.${m}Title`); add(`sub.${k}.note.${m}`); }
    }
    for (const m of ['exact', 'discover']) { add(`sub.zone.${m}`); add(`sub.handoff.${m}`); }
    for (const s of scanner.SCAN_STAGES) { add(`scan.stage.${s}`); add(`scan.progress.${s}`); }
    // Every warning code runScan can emit (read from its source, so a new code cannot slip
    // through) plus the views' own list: both views render them as <view>.warn.<code>.
    const scannerCodes = [...readFileSync(join(JS, 'lib', 'scanner.js'), 'utf8').matchAll(/code: '([A-Z_]+)'/g)].map((m) => m[1]);
    assert.ok(scannerCodes.includes('WILDCARD_PARENTS_TRUNCATED'), 'scanner warning codes found');
    const warningCodes = new Set([...scannerCodes, ...views.subdomains.WARNING_CODES]);
    for (const c of warningCodes) { add(`scan.warn.${c}`); add(`sub.warn.${c}`); }
    for (const k of views.scan.KIND_FILTERS) add(`scan.filter.${k}`);
    for (const k of views.scan.HINT_KINDS) { add(`scan.hint.${k}`); add(`scan.hint.${k}.title`); }
    for (const k of ['spf', 'mx', 'direct-sibling', 'history', 'resolver-leak']) { add(`scan.hint.${k}`); add(`scan.hint.${k}.title`); }
    for (const m of views.scan.BRUTEFORCE_MODES) {
      add(`scan.summary.bf.${m}`);
      if (m !== 'off') { add(`scan.opt.bf.${m}`); add(`scan.opt.bf.${m}Hint`); }
    }
    for (const o of ['input', 'cert', 'bruteforce', 'wordlist', 'permutation', 'recursive', 'dnsmine', 'zone']) add(`scan.origin.${o}`);
    // Subdomains view: every stage pill / progress label, wordlist level, origin id and hint kind.
    const sub = { ...views.subdomains, ...subRun };
    for (const s of sub.SHOWN_STAGES) { add(`sub.stage.${s}`); add(`sub.progress.${s}`); }
    for (const m of sub.BRUTEFORCE_MODES) {
      add(`sub.sum.bf.${m}`);
      add(`sub.opt.bf.${m}`);
      add(`sub.opt.bf.${m}Hint`);
      if (m !== 'off') add(`sub.bf.${m}`);
    }
    for (const o of ['input', 'cert', 'bruteforce', 'wordlist', 'permutation', 'recursive', 'dnsmine', 'zone', 'zoneTitle']) add(`sub.origin.${o}`);
    for (const k of sub.HINT_KINDS) { add(`sub.hint.${k}`); add(`sub.hint.${k}.title`); }
    for (const f of sub.SEGMENT_FILTERS) add(`sub.filter.${f}`);
    for (const k of ['mine', 'wordlist', 'permutation', 'recursive', 'zone']) add(`sub.tech.${k}`);
    for (const k of ['sub.tech.dnsOnly', 'sub.tech.dnsOnlyIncomplete']) add(k); // dnsOnlyNoteKey()
    // Source health: every state and every quota hint key a SourceResult can carry.
    for (const s of sources.SOURCE_HEALTH_STATES) add(`source.state.${s}`);
    for (const k of ['source.quota.day', 'source.quota.hour', 'source.quota.minutes', 'source.quota.later', 'source.fallback', 'error.kind.unavailable']) add(k);
    for (const c of ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE', 'PKCS12_UNSUPPORTED', 'PKCS12_BAD_PASSWORD', 'PKCS12_DAMAGED', 'CSR_NOT_CERT', 'PARSE_ERROR', 'EXPIRED', 'NOT_YET_VALID']) add(`cert.warn.${c}.title`);
    // A PKCS#12 bundle (ui/pfx-import.js, views/cert.js): the encryption strengths lib/pkcs12.js
    // reports, and the unsupported details the Certificate view words on their own.
    for (const s of ['weak', 'legacy']) { add(`pfx.strength.${s}`); add(`pfx.strength.${s}Title`); }
    for (const d of views.cert.PKCS12_WORDED) add(`cert.warn.PKCS12_UNSUPPORTED.${d}`);
    for (const l of ['EV', 'OV', 'IV', 'DV']) add(`cert.level.${l}`);
    for (const r of ['leaf', 'intermediate', 'root', 'unrelated']) add(`cert.role.${r}`);
    for (const c of ['NO_IP', 'INVALID_IP', 'DUPLICATE_IP', 'PARSE', 'TOPOLOGY', 'INVALID_IP.port', 'INVALID_IP.zone', 'PARSE.hostPort', 'PARSE.sshPort']) add(`inv.warn.${c}`);
    // The topology keys (lib/inventory.js TOPOLOGY_REASONS): every cause the Servers view words.
    const inventory = await imp('assets/js/lib/inventory.js');
    for (const r of inventory.TOPOLOGY_REASONS) add(`inv.warn.TOPOLOGY.${r}`);
    for (const s of ['plain', 'passthrough']) add(`topo.status.${s}`);
    for (const k of [...views.bulk.BULK_FILTERS, ...views.bulk.IP_FILTERS]) add(`bulk.filter.${k}`);
    for (const k of Object.keys(views.lookup.TYPE_PRESETS)) add(`lkp.preset.${k}`);
    // Global DNS: every verdict finding the summary renders as glb.find.<code>.
    const propagation = await imp('assets/js/lib/propagation.js');
    for (const f of propagation.VERDICT_FINDINGS) add(`glb.find.${f}`);
    for (const g of views.health.HEALTH_GROUPS) add(`health.group.${g}`);
    // Verify tab (ui/verify-panel.js): every status, reason, error, warning (+ tooltip), state,
    // skip / not-run reason, exposure (+ tooltip), headline and not-checkable part lib/verify.js
    // can produce; the panel builds these keys from the codes.
    const vf = await imp('assets/js/lib/verify.js');
    for (const s of vf.VERIFY_STATUSES) add(`vfy.st.${s}`);
    for (const k of ['vfy.st.NEEDS_UPDATE.other', 'vfy.st.NEEDS_UPDATE.nocert', 'vfy.st.TIMEOUT.origin']) add(k);
    for (const k of ['vfy.empty', 'vfy.empty.none', 'vfy.empty.noCli']) add(k); // emptyKey()
    for (const r of vf.VERIFY_REASONS) add(`vfy.reason.${r}`);
    for (const e of vf.VERIFY_ERRORS) add(`vfy.err.${e}`);
    for (const w of vf.VERIFY_WARNINGS) { add(`vfy.warn.${w}`); add(`vfy.warn.${w}.title`); }
    for (const s of vf.VERIFY_STATES.filter((x) => x !== 'done' && x !== 'skipped')) add(`vfy.state.${s}`);
    for (const s of vf.SKIP_REASONS) { add(`vfy.skip.${s}`); add(`vfy.notHere.${s}`); }
    add('vfy.skip.cdn-edge.title');
    for (const k of ['proxied', 'managed']) add(`vfy.notHere.${k}`);
    for (const k of vf.NOT_HERE_KEYS || []) add(`vfy.notHere.${k}`);
    for (const n of vf.NOT_RUN_REASONS) add(`vfy.notRun.${n}`);
    for (const x of vf.EXPOSURES) { add(`vfy.exp.${x}`); add(`vfy.exp.${x}.title`); }
    for (const hk of vf.HEADLINE_KEYS) add(`vfy.head.${hk}`);
    for (const v of ['dns', 'hint', 'zone', 'known']) add(`vfy.via.${v}`);
    for (const k of ['datacenter', 'eyeball']) add(`vfy.det.kind.${k}`);
    for (const k of ['on', 'off']) add(`vfy.planOrigins.${k}`);
    for (const sh of views.subdomains.SHELLS) { add(`scan.cdn.shell.${sh}`); add(`scan.cdn.shellTitle.${sh}`); }
    // DANE / TLSA panel (ui/dane-panel.js): every status (+ its explanation), note, record issue
    // and headline lib/dane.js can produce, and the explanation keys whyKey() builds.
    const dn = await imp('assets/js/lib/dane.js');
    const dp = await imp('assets/js/ui/dane-panel.js');
    for (const s of dn.DANE_STATUSES) {
      add(`dane.st.${s}`);
      for (const service of ['smtp', 'https']) add(dp.whyKey({ status: s, service, notes: [] }));
    }
    add(dp.whyKey({ status: 'insecure', service: 'smtp', notes: [{ code: 'mx-insecure' }] }));
    for (const n of dn.DANE_NOTES) add(`dane.note.${n}`);
    for (const i of dn.TLSA_ISSUES) add(`dane.issue.${i}`);
    for (const hk of dn.DANE_HEADLINES) add(`dane.head.${hk}`);
    for (const r of [{ usable: true, matches: true, matchedBy: 'leaf' }, { usable: true, matches: true, matchedBy: 'chain' },
      { usable: true, matches: false }, { usable: true, matches: null }]) add(dp.recordStateKey(r));
    for (const svc of Object.keys(dn.DANE_PORTS)) add(`dane.svc.${svc}`);
    for (const k of ['d', 'h', 'min', 's']) add(`dane.dur.${k}`);
    // Shell navigation (lib/shellnav.js): group headings, start-page jobs, shortcut descriptions.
    const shellnav = await imp('assets/js/lib/shellnav.js');
    for (const g of [...shellnav.NAV_GROUPS, shellnav.OTHER_GROUP]) add(g.labelKey);
    for (const g of shellnav.groupViews(app.VIEWS)) add(g.labelKey);
    for (const task of shellnav.START_TASKS) add(`start.task.${task.id}`);
    for (const s of shellnav.SHORTCUTS) add(`keys.${s.id}`);
    // Copy summary (lib/summary.js): every sum.* text, registered with the views by ui/summary-button.js.
    const summary = await imp('assets/js/lib/summary.js');
    for (const k of Object.keys(summary.SUMMARY_I18N.en)) add(k);
    // DMARC & TLS reports: its summary texts, registered by views/reports.js (lib/reportsummary.js).
    const reportsummary = await imp('assets/js/lib/reportsummary.js');
    for (const k of Object.keys(reportsummary.REPORTS_SUMMARY_I18N.en)) add(k);
    for (const kind of summary.SUMMARY_KINDS) add(`nav.${kind}`);
    // No silent dashes (lib/sourcestatus.js through ui/source-status.js): every reason, source and
    // chip state; IP Intel's folded zero counts (lib/density.js).
    const ss = await imp('assets/js/lib/sourcestatus.js');
    for (const r of ss.STATUS_REASONS) add(`srcst.reason.${r}`);
    for (const s of [...Object.keys(ss.STATUS_SOURCES), ...Object.keys(ss.IP_SOURCE_GROUPS)]) add(`srcst.source.${s}`);
    for (const st of ['ok', 'idle', 'pending', 'failed']) add(`srcst.chip.${st}`);
    for (const id of ['cdn', 'mine', 'priv']) add(`ipi.zero.${id}`);
    // Workspaces: the dialog's refusals and a storage error's reason, worded from their codes.
    const [panel, wsUi] = await Promise.all([imp('assets/js/ui/workspace-panel.js'), imp('assets/js/ui/workspace-ui.js')]);
    for (const code of [...panel.IMPORT_ERRORS, ...panel.NAME_ERRORS, ...panel.PASSWORD_PROBLEMS]) add(`ws.err.${code}`);
    for (const reason of wsUi.STORAGE_REASONS) add(`ws.why.${reason}`);
    // Domain overview (lib/passport.js through views/domain.js): every card title and the tool its
    // link opens, SPF qualifier, DMARC policy, DNSSEC state, health light and count, and the kind
    // of a mail platform the view builds a key from.
    const passport = await imp('assets/js/lib/passport.js');
    for (const c of passport.PASSPORT_CARDS) { add(`dov.card.${c}`); add(`nav.${views.domain.cardLink(c, 'example.com').view}`); }
    for (const q of ['-', '~', '?', '+', 'redirect', 'noAll', 'none', 'many', 'invalid']) add(`dov.mail.spf.${q}`);
    for (const p of ['reject', 'quarantine', 'none', 'many', 'invalid', 'missing']) add(`dov.mail.dmarc.${p}`);
    for (const d of ['validated', 'signed', 'failing', 'unsigned']) add(`dov.dns.dnssec.${d}`);
    for (const l of ['ok', 'warn', 'error']) add(`dov.health.light.${l}`);
    for (const k of ['error', 'warn', 'info']) add(`dov.health.count.${k}`);
    for (const p of passport.MAIL_PLATFORMS) if (p.kind !== 'mailbox') add(`dov.mail.kind.${p.kind}`);
    // Certificate estate (lib/estate.js through views/estate.js): every filter, flag, kind, expiry
    // bucket, weak reason, tab and why a file is not a report.
    const estate = await imp('assets/js/lib/estate.js');
    for (const f of estate.ESTATE_FILTERS) add(`estate.filter.${f}`);
    for (const f of estate.ESTATE_FLAGS) { add(`estate.flag.${f}`); add(`estate.flagTitle.${f}`); }
    for (const k of estate.ESTATE_KINDS) add(`estate.kind.${k}`);
    for (const b of estate.ESTATE_BUCKETS) add(`estate.bucket.${b}`);
    for (const w of estate.ESTATE_WEAK_REASONS) { add(`estate.weak.${w}`); add(`estate.weakShort.${w}`); }
    for (const e of estate.REPORT_ERRORS) add(`estate.error.${e}`);
    for (const tab of views.estate.ESTATE_TABS) add(`estate.tab.${tab}`);
    // Certificate › PEM & OpenSSL › Does this CSR match?: why a pasted text is not a CSR.
    const x509 = await imp('assets/js/lib/x509.js');
    for (const e of x509.CSR_ERRORS) add(`cert.csr.err.${e}`);
    // DNS change request › the check page (lib/changecheck.js through views/change.js): every
    // headline, every stop the page words (the user's too), verdict, reason not done yet and error kind.
    const cc = await imp('assets/js/lib/changecheck.js');
    for (const hk of cc.CHECK_HEADLINES) add(`chg.check.head.${hk}`);
    for (const s of [...cc.CHECK_STOPS.filter((x) => x !== 'done'), 'user']) add(`chg.check.stop.${s}`);
    for (const v of [...cc.CHECK_VERDICTS.filter((x) => x !== 'pending'), 'waiting', 'noAnswer']) add(`chg.check.v.${v}`);
    for (const r of cc.PENDING_REASONS) add(`chg.check.p.${r}`);
    for (const k of views.change.CHECK_ERROR_KINDS) add(`chg.check.err.${k}`);
    for (const m of ['is', 'has', 'none']) add(`chg.check.mode.${m}`);
    for (const e of ['too-long', 'too-many', 'version', 'zone', 'empty', 'set']) add(`chg.check.bad.${e}`);
    // … and its cutover assistant (ui/cutover.js, lib/cutover.js): every countdown, plan step, note,
    // error and checklist line.
    const cut = await imp('assets/js/lib/cutover.js');
    for (const k of cut.CACHE_KINDS) add(`chg.cut.cd.${k}`);
    for (const st of cut.PLAN_STEPS) { add(`chg.cut.plan.step.${st}`); add(`chg.cut.plan.when.${st}`); }
    for (const n of cut.PLAN_NOTES) add(`chg.cut.plan.note.${n}`);
    for (const e of cut.PLAN_ERRORS) add(`chg.cut.plan.err.${e}`);
    for (const k of Object.keys(cut.CUTOVER_I18N.en)) add(k);
    // Zone File › New name servers (ui/parity-panel.js, lib/nsparity.js) and Retire an IP › the old
    // and the new server (ui/origin-compare.js, lib/origincompare.js): every status, reason, server
    // state, runbook step, field, note and verdict the panels word from a library code.
    const [pp, oc, zd] = await Promise.all([imp('assets/js/ui/parity-panel.js'), imp('assets/js/ui/origin-compare.js'), imp('assets/js/lib/zonedrift.js')]);
    for (const k of [...pp.generatedKeys(), ...oc.generatedKeys()]) add(k);
    for (const r of zd.DRIFT_REASONS) add(pp.reasonKey(r));
    // Domain Health › Delegation (ui/delegation-panel.js over lib/delegation.js): every server, NS-set,
    // recursion, parent and glue state, finding, stop, plan failure, takeover risk, reference and verdict.
    for (const k of (await imp('assets/js/ui/delegation-panel.js')).generatedKeys()) add(k);
    // Zone File › Compare and Convert (ui/zone-tools.js over lib/zonediff.js and lib/zoneconvert.js):
    // every status, reason, note and option of a comparison, every target and every pitfall text
    // a conversion can raise for it (a code worded per target, or once for all).
    const [zt, zc] = await Promise.all([imp('assets/js/ui/zone-tools.js'), imp('assets/js/lib/zoneconvert.js')]);
    for (const k of zt.generatedKeys()) add(k);
    for (const code of zc.PITFALL_CODES) for (const target of Object.keys(zc.PITFALL_SEVERITY[code])) add(zc.pitfallKey(code, target));
    // The command palette (ui/palette.js over lib/palette.js): every action and entry type.
    for (const k of (await imp('assets/js/ui/palette.js')).generatedKeys()) add(k);
    // About › What this page sent (ui/egress-panel.js over lib/egress.js): every data kind, service
    // role and never-sent item the ledger words from the registry.
    const egress = await imp('assets/js/lib/egress.js');
    for (const k of egress.DATA_KINDS) add(`egress.kind.${k}`);
    for (const r of egress.EGRESS_ROLES) add(`egress.role.${r}`);
    for (const svc of egress.EGRESS_SERVICES) assert.ok(egress.EGRESS_ROLES.includes(svc.role), `${svc.id}: role ${svc.role}`);
    for (const n of egress.NEVER_SENT) add(`egress.never.${n}`);
    // Subdomains › Related domains (ui/related-domains.js): every Certificate Transparency state it words.
    for (const st of ['waiting', 'failed', 'none', 'sharedOnlyNone']) add(`rel.${st}`);
    // Certificate › Key continuity (ui/key-continuity.js): the consequences of a reused or a new key,
    // a leaf's and a CA certificate's.
    for (const w of ['reused', 'single']) for (const suffix of ['', 'Ca']) { add(`key.tlsa.${w}${suffix}`); add(`key.pin.${w}${suffix}`); }
    // Certificate › Compare (ui/cert-diff-panel.js over lib/certdiff.js): every change, severity, verdict and area it words.
    for (const k of (await imp('assets/js/ui/cert-diff-panel.js')).generatedKeys()) add(k);
    // DMARC & TLS reports (lib/dmarcreport.js, lib/tlsrpt.js, lib/health.js spfEvaluate through
    // views/reports.js): every source class (tile, badge, tooltip), reason, fix, verdict and note,
    // why a file could not be used, the SPF line's states and verdicts (a permerror's reason too), every TLS-RPT result type
    // with its advice, policy type and the tools its advice links.
    const [dmarcreport, tlsrpt] = await Promise.all([imp('assets/js/lib/dmarcreport.js'), imp('assets/js/lib/tlsrpt.js')]);
    for (const c of dmarcreport.SOURCE_CLASSES) { add(`rpt.cls.${c}`); add(`rpt.clsOne.${c}`); add(`rpt.clsDesc.${c}`); }
    for (const r of dmarcreport.CLASS_REASONS) add(`rpt.why.${r}`);
    for (const f of dmarcreport.FIX_CODES) add(`rpt.fix.${f}`);
    for (const v of [...dmarcreport.DMARC_VERDICTS, ...views.reports.VERDICT_EXTRA_KEYS]) { add(`rpt.verdict.${v}.title`); add(`rpt.verdict.${v}.body`); }
    for (const n of dmarcreport.DMARC_NOTES) add(`rpt.note.${n}`);
    for (const p of dmarcreport.REPORT_PROBLEMS) add(`rpt.problem.${p}`);
    for (const r of health.SPF_EVAL_RESULTS) add(`rpt.spfNow.${r}`);
    for (const r of health.SPF_UNKNOWN_REASONS) add(`rpt.spfUnknown.${r}`);
    for (const r of health.SPF_PERMERROR_REASONS) add(`rpt.spfError.${r}`);
    for (const s of views.reports.SPF_LINE_STATES) add(`rpt.spf.${s}`);
    for (const ty of [...tlsrpt.TLS_RESULT_TYPES, 'other']) { add(`rpt.tls.type.${ty}`); add(`rpt.tls.advice.${ty}`); }
    for (const p of tlsrpt.TLS_POLICY_TYPES) add(`rpt.tls.policy.${p}`);
    for (const tool of views.reports.TLS_TOOLS) add(`rpt.tls.tool.${tool}`);
    for (const k of ['rpt.domainOption', 'rpt.tls.domainOption', 'rpt.kept']) add(k);
    // Domain portfolio (lib/portfolio.js, lib/policy.js through views/portfolio.js): every column,
    // filter, tile and risk, every state a cell words from the facts, every rule, status, preset,
    // parse error and evidence of the policy, and the summary's texts (lib/portfoliosummary.js).
    const [portfolio, policy, pfsum] = await Promise.all([imp('assets/js/lib/portfolio.js'), imp('assets/js/lib/policy.js'), imp('assets/js/lib/portfoliosummary.js')]);
    const pf = views.portfolio;
    for (const c of portfolio.PORTFOLIO_CELLS) add(`pf.col.${c}`);
    for (const k of ['domain', 'policy']) add(`pf.col.${k}`);
    for (const f of pf.PORTFOLIO_FILTERS) add(`pf.filter.${f}`);
    for (const k of ['domains', ...pf.PORTFOLIO_TILES]) add(`pf.tile.${k}`);
    for (const r of pf.RISK_BADGES) add(`pf.risk.${r}`);
    for (const tab of pf.PORTFOLIO_TABS) add(`pf.tab.${tab}`);
    // Its Certificates (CT) tab (ui/ctwatch-panel.js over lib/ctwatch.js): every flag, filter, note,
    // tile and source a row or a domain's read words from a library code.
    for (const k of (await imp('assets/js/ui/ctwatch-panel.js')).generatedKeys()) add(k);
    // Its Domain security tab (ui/secscore-panel.js over lib/secscore.js): every measure's name and
    // what it asks, every status a cell and the legend word, the CSV's headers.
    for (const k of (await imp('assets/js/ui/secscore-panel.js')).generatedKeys()) add(k);
    for (const k of Object.keys((await imp('assets/js/lib/secscore.js')).SECURITY_I18N.en)) add(k);
    for (const d of ['validated', 'signed', 'failing', 'unsigned']) add(`pf.dnssec.${d}`);
    for (const c of ['none', 'unrestricted', 'deny-all', 'critical']) add(`pf.caa.${c}`);
    for (const s of ['none', 'many', 'invalid']) { add(`pf.spf.${s}`); add(`pf.dmarc.${s}`); }
    for (const s of ['present', 'none', 'invalid']) add(`pf.rec.${s}`);
    for (const r of policy.POLICY_RULES) add(`pol.rule.${r.id}`);
    for (const s of policy.POLICY_STATUSES) add(`pol.st.${s}`);
    for (const p of policy.POLICY_PRESET_IDS) add(`pol.preset.${p}`);
    for (const e of policy.POLICY_ERRORS) add(`pol.err.${e}`);
    for (const k of Object.keys(policy.POLICY_I18N.en)) add(k);
    for (const k of Object.keys(pfsum.PORTFOLIO_SUMMARY_I18N.en)) add(k);
    // The origin map (ui/origin-map.js, ui/origin-map-panel.js over lib/originmap.js and lib/originfill.js):
    // every source and stale reason, why the form refuses an entry, why a CLI report could not be read.
    const [om, omp] = await Promise.all([imp('assets/js/ui/origin-map.js'), imp('assets/js/ui/origin-map-panel.js')]);
    for (const k of om.generatedKeys()) add(k);
    // IP Intel › Check routing (ui/ip-enrich-panel.js): RPKI statuses, routing flags, PeeringDB types, sources.
    for (const k of (await imp('assets/js/ui/ip-enrich-panel.js')).generatedKeys()) add(k);
    // IP Intel › Domains on this IP (ui/reverse-ip-panel.js over lib/reverseip.js): every status and source.
    for (const k of (await imp('assets/js/ui/reverse-ip-panel.js')).generatedKeys()) add(k);
    // The DNSSEC chain (ui/dnssec-panel.js over lib/dnssec.js): every status, reason, fix and signature result.
    for (const k of (await imp('assets/js/ui/dnssec-panel.js')).generatedKeys()) add(k);
    // Explain (ui/explain-panel.js over lib/records.js, lib/spfexplain.js and the SPF check of lib/health.js):
    // every SPF result, step kind and state, permerror and unknown reason, flatten note, DMARC meaning and
    // issue, CAA property, ECH error, HTTPS / SVCB note and hint status; the CAA problems it words.
    for (const k of (await imp('assets/js/ui/explain-panel.js')).generatedKeys()) add(k);
    // Renewal readiness › Plan (ui/renewal-planner.js over lib/renewalplan.js): states, groupings, notes, environments, key types.
    for (const k of (await imp('assets/js/ui/renewal-planner.js')).generatedKeys()) add(k);
    // The Rollout tab (ui/rollout-panel.js): steps, stages, Verify verdicts, platforms, options, sections, notes, warnings.
    for (const k of (await imp('assets/js/ui/rollout-panel.js')).generatedKeys()) add(k);
    for (const e of omp.FORM_ERRORS) add(`omp.err.${e}`);
    for (const e of estate.REPORT_ERRORS) add(`omp.file.${e}`);
    // Domain overview › Lookalike domains (ui/lookalike-panel.js): every technique, level and reason.
    for (const k of (await imp('assets/js/ui/lookalike-panel.js')).generatedKeys()) add(k);
    for (const v of ['known']) { add(`scan.srv.via.${v}`); add(`scan.hint.${v}`); add(`sub.hint.${v}`); }
    // IP Intel › Blocklists (ui/dnsbl-panel.js over lib/dnsbl.js): every status, refusal, error, skip and meaning.
    for (const k of (await imp('assets/js/ui/dnsbl-panel.js')).generatedKeys()) add(k);
    // Subdomains › Takeover risks (ui/takeover-panel.js over lib/takeover.js): every code it words.
    const [tko, tkp] = await Promise.all([imp('assets/js/lib/takeover.js'), imp('assets/js/ui/takeover-panel.js')]);
    for (const k of tkp.generatedKeys()) add(k);
    for (const s of tko.TAKEOVER_SEVERITIES) add(`tko.sev.${s}`);
    for (const k of tko.TAKEOVER_REF_KINDS) add(`tko.kind.${k}`);
    for (const s of tko.TAKEOVER_STATUSES) add(`tko.status.${s}`);
    for (const r of tko.TAKEOVER_REASONS) add(`tko.reason.${r}`);
    for (const o of tko.HTTP_CHECK_OUTCOMES.filter((x) => x !== 'in-use')) add(`tko.http.outcome.${o}`);
    // Global DNS › ISP resolvers (ui/isp-resolvers.js over lib/ispdns.js): why a plan is refused, what the public sources say.
    const isp = await imp('assets/js/lib/ispdns.js');
    for (const e of isp.ISP_PLAN_ERRORS) add(`isp.err.${e}`);
    for (const s of ['agree', 'by-design', 'geo']) add(`isp.sum.ref.${s}`);
    // Domain Health v2 (ui/health-v2.js over lib/healthweb.js and lib/healthadvice.js): skip reasons, caps, every Web check and advice.
    const hv2 = await imp('assets/js/ui/health-v2.js');
    const [hweb, hadv] = await Promise.all([imp('assets/js/lib/healthweb.js'), imp('assets/js/lib/healthadvice.js')]);
    for (const k of [...hv2.generatedKeys(), ...Object.keys(hweb.HEALTH_WEB_I18N.en), ...Object.keys(hadv.HEALTH_ADVICE_I18N.en)]) add(k);
    // The origin exposure audit (ui/exposure-panel.js over lib/exposure.js, Servers › Exposure):
    // every finding kind, severity, reachability result, advice and skip reason it words from a code.
    const exp = await imp('assets/js/ui/exposure-panel.js');
    for (const k of exp.generatedKeys()) add(k);
    assert.deepEqual(missingIn(keys), []);
  });

  test('each view finds its own keys when loaded alone next to the shell', () => {
    const script = `
      const [root, id] = process.argv.slice(1);
      const u = (p) => new URL(p, root).href;
      const i18n = await import(u('assets/js/i18n.js'));
      await import(u('assets/js/app.js'));
      await import(u('assets/js/views/' + id + '.js'));
      console.log(JSON.stringify({ en: i18n.listKeys('en'), tr: i18n.listKeys('tr') }));`;
    const rootUrl = `${pathToFileURL(ROOT).href}/`;
    const bad = [];
    for (const id of VIEW_IDS) {
      const out = execFileSync(process.execPath, ['--input-type=module', '-e', script, rootUrl, id], { encoding: 'utf8' });
      const { en: e, tr: t } = JSON.parse(out.trim().split('\n').pop());
      const have = { en: new Set(e), tr: new Set(t) };
      for (const k of literalKeys(readFileSync(join(JS, 'views', `${id}.js`), 'utf8'))) {
        if (!have.en.has(k) || !have.tr.has(k)) bad.push(`${id}: ${k}`);
      }
    }
    assert.deepEqual(bad, []);
  });
});
