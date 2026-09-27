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

before(async () => {
  i18n = await imp('assets/js/i18n.js');
  await imp('assets/js/app.js');
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
    const sub = views.subdomains;
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
    for (const c of ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE', 'PKCS12_UNSUPPORTED', 'CSR_NOT_CERT', 'PARSE_ERROR', 'EXPIRED', 'NOT_YET_VALID']) add(`cert.warn.${c}.title`);
    for (const l of ['EV', 'OV', 'IV', 'DV']) add(`cert.level.${l}`);
    for (const r of ['leaf', 'intermediate', 'root', 'unrelated']) add(`cert.role.${r}`);
    for (const c of ['NO_IP', 'INVALID_IP', 'DUPLICATE_IP', 'PARSE', 'INVALID_IP.port', 'INVALID_IP.zone', 'PARSE.hostPort', 'PARSE.sshPort']) add(`inv.warn.${c}`);
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
    for (const v of ['dns', 'hint', 'zone']) add(`vfy.via.${v}`);
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
