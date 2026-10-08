/**
 * ui/exposure-panel.js — Servers › Exposure audit: how exposed are the real origins of this
 * workspace's CDN-proxied names (lib/exposure.js, ROADMAP P0.2)? It sits next to the Origin map
 * because it reads the same workspace data — the origin map's active entries, an imported zone's
 * proxied origins, the inventory's server labels — and asks two questions of each origin:
 *
 * 1. DNS leaks (always, over the configured DoH resolvers, nothing typed leaves beyond a lookup):
 *    the records of the domain that point straight at the origin address, defeating the CDN before
 *    a request is made.
 * 2. Direct reachability (opt-in, through the Globalping consent gate): does the origin serve the
 *    site when asked directly, with the proxied name as SNI / Host, bypassing the CDN? Private and
 *    reserved origins are never sent — they are audited for DNS leaks only.
 *
 * Every finding carries a severity and the fixes it calls for (firewall the CDN's ranges,
 * Authenticated Origin Pulls / mTLS, a Cloudflare Tunnel, move the service, rotate the address).
 * CSV export and Copy summary. Every string is rendered through h() / text nodes; names and
 * server names come from the workspace.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, DataTable, Disclosure, EmptyState, ErrorBanner, Spinner, StatCard, announce
} from './components.js';
import { t, registerStrings, formatNumber } from '../i18n.js';
import { state } from '../state.js';
import { errorKind } from '../lib/util.js';
import { registerRunning } from './jobs.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from './globalping-gate.js';
import { registrableDomain, normalizeHostname } from '../lib/domain.js';
import {
  exposureTargets, targetKey, runLeakScan, exposureProbes, readExposureSides, reachabilityFinding, exposureSummary,
  sortFindings, cdnOf, daysAgo, EXPOSURE_FINDINGS, EXPOSURE_SEVERITIES, REACH_RESULTS, EXPOSURE_ADVICE, SKIP_REASONS,
  FINDING_ADVICE, EXPOSURE_PROBES
} from '../lib/exposure.js';

/** The Globalping consent purpose of the direct origin probe (its own privacy text and consent). */
export const EXPOSURE_PURPOSE = 'origin-exposure';
/** Above this many probes a run asks again even after consent (a large origin map). */
const CONFIRM_ABOVE = 20;

/** A severity → the Badge variant that colours it. */
const SEV_VARIANT = Object.freeze({ critical: 'error', high: 'warn', medium: 'accent', low: 'neutral', info: 'info' });

registerStrings('en', {
  'exp.privacy': 'The DNS lookups go to the resolvers you chose; the origin map and the server names stay in this browser. The direct probe is opt-in and goes to Globalping — its result is public by measurement ID — and a private or reserved origin is never sent.',
  'exp.lead': 'How exposed are the real origins behind your CDN-proxied names? This reads the workspace origin map, an imported zone and your inventory, finds the DNS records that reveal an origin address, and — only when you ask — checks whether the origin answers the site directly, bypassing the CDN.',
  'exp.empty': 'No known origins to audit yet. Remember a zone file’s origins, import a CLI report, or add an origin in the Origin map tab — then come back here.',
  'exp.openMap': 'Open the Origin map',
  'exp.stat.targets': 'Origins',
  'exp.stat.probeable': 'Probeable',
  'exp.stat.findings': 'Findings',
  'exp.stat.worst': 'Worst',
  'exp.none': 'No origins',
  'exp.targetsTitle': 'Proxied origins',
  'exp.targetsSubtitle': 'The (name, origin) pairs this audit covers',
  'exp.col.name': 'Name',
  'exp.col.origin': 'Origin',
  'exp.col.server': 'Server',
  'exp.col.source': 'Known from',
  'exp.col.status': 'Probe',
  'exp.col.finding': 'Finding',
  'exp.col.severity': 'Severity',
  'exp.col.where': 'Where',
  'exp.col.advice': 'Fixes',
  'exp.toAudit': 'To audit',
  'exp.auditLeaks': 'Audit DNS leaks',
  'exp.reAudit': 'Audit again',
  'exp.probe': { one: 'Probe {count} origin directly', other: 'Probe {count} origins directly' },
  'exp.probeHint': 'Opt-in: an HTTPS GET of each origin address with the name as Host, through Globalping ({count} probes).',
  'exp.running.leaks': 'Checking DNS for origin leaks…',
  'exp.running.probe': 'Probing the origins…',
  'exp.progress': '{done} of {total}',
  'exp.ranNone': 'No origin leaks found in DNS. Run a direct probe to see whether an origin answers the site itself.',
  'exp.ranClean': 'No exposure found: no DNS record points at an origin, and no probed origin served the site directly.',
  'exp.findingsTitle': 'Findings',
  'exp.findingsSubtitle': { one: '{count} finding, worst first', other: '{count} findings, worst first' },
  'exp.copySummary': 'Copy summary',
  'exp.summaryTitle': 'Origin exposure audit',
  'exp.summaryWorst': 'Worst: {sev} · {count} findings · {ips} origin addresses leaked',
  'exp.summaryClean': 'No origin exposure found across {count} proxied origins.',
  'exp.names': { one: '{first}', other: '{first} +{count}' },
  'exp.reachLine': 'Direct probe: {exposed} exposed, {filtered} filtered, {closed} closed, {other} other.',
  'exp.reach.status': 'Origin {name}: {result}',
  'exp.measurement': 'measurement',
  'exp.quota': 'Globalping’s hourly quota is used up — it resets {when}. The DNS findings are still shown.',
  'exp.leakError': 'The DNS audit could not finish.',
  'exp.failures': { one: '{count} lookup failed — the result may be incomplete.', other: '{count} lookups failed — the result may be incomplete.' },
  'exp.retry': 'Retry',
  // generated: finding kinds
  'exp.finding.reachable': 'Origin reachable directly',
  'exp.finding.dns-a': 'A / AAAA record at the origin',
  'exp.finding.https-hint': 'HTTPS record hint at the origin',
  'exp.finding.dns-mx': 'Mail host at the origin',
  'exp.finding.spf': 'SPF authorises the origin',
  'exp.finding.txt-ip': 'TXT record names the origin',
  'exp.finding.dns-ns': 'Name server at the origin',
  // generated: severities
  'exp.sev.critical': 'Critical',
  'exp.sev.high': 'High',
  'exp.sev.medium': 'Medium',
  'exp.sev.low': 'Low',
  'exp.sev.info': 'Info',
  // generated: reachability results
  'exp.reach.exposed': 'exposed (served the site directly)',
  'exp.reach.other-content': 'answered, but not this site',
  'exp.reach.filtered': 'filtered (no answer — good)',
  'exp.reach.closed': 'closed (refused — good)',
  'exp.reach.unreachable': 'unreachable',
  'exp.reach.incomplete': 'could not compare',
  // generated: advice
  'exp.advice.firewall': 'Allow only your CDN’s published IP ranges to reach the origin at the firewall.',
  'exp.advice.aop': 'Require Authenticated Origin Pulls (mTLS) so the origin answers only the CDN.',
  'exp.advice.tunnel': 'Put the origin behind a Cloudflare Tunnel (or equivalent) so it needs no public inbound address.',
  'exp.advice.move': 'Move the leaked service (mail, name server) off the origin address.',
  'exp.advice.rotate': 'Rotate the origin address once the leak is closed — the old one is already known.',
  // generated: skip reasons
  'exp.skip.private': 'private address — DNS leaks only',
  'exp.skip.reserved': 'reserved address — DNS leaks only',
  'exp.skip.wildcard': 'wildcard name — DNS leaks only',
  'exp.skip.bad-name': 'not a probeable name — DNS leaks only',
  'exp.skip.bad-port': 'port not probeable — DNS leaks only'
});

registerStrings('tr', {
  'exp.privacy': 'DNS sorguları seçtiğiniz çözümleyicilere gider; origin haritası ve sunucu adları bu tarayıcıda kalır. Doğrudan ölçüm isteğe bağlıdır ve Globalping’e gider — sonucu ölçüm kimliğiyle herkese açıktır — özel ya da ayrılmış bir origin asla gönderilmez.',
  'exp.lead': 'CDN’in arkasındaki proxy’li adlarınızın gerçek origin’leri ne kadar açıkta? Bu araç çalışma alanının origin haritasını, içe aktarılan zone’u ve sunucu envanterinizi okur, bir origin adresini açığa çıkaran DNS kayıtlarını bulur ve — yalnızca istediğinizde — origin’in CDN’i atlayarak siteyi doğrudan sunup sunmadığını kontrol eder.',
  'exp.empty': 'Denetlenecek bilinen origin yok. Bir zone dosyasının origin’lerini hatırlayın, bir CLI raporu içe aktarın ya da Origin haritası sekmesinden bir origin ekleyin — sonra buraya dönün.',
  'exp.openMap': 'Origin haritasını aç',
  'exp.stat.targets': 'Origin’ler',
  'exp.stat.probeable': 'Ölçülebilir',
  'exp.stat.findings': 'Bulgular',
  'exp.stat.worst': 'En kötü',
  'exp.none': 'Origin yok',
  'exp.targetsTitle': 'Proxy’li origin’ler',
  'exp.targetsSubtitle': 'Bu denetimin kapsadığı (ad, origin) çiftleri',
  'exp.col.name': 'Ad',
  'exp.col.origin': 'Origin',
  'exp.col.server': 'Sunucu',
  'exp.col.source': 'Kaynak',
  'exp.col.status': 'Ölçüm',
  'exp.col.finding': 'Bulgu',
  'exp.col.severity': 'Önem',
  'exp.col.where': 'Nerede',
  'exp.col.advice': 'Çözümler',
  'exp.toAudit': 'Denetlenecek',
  'exp.auditLeaks': 'DNS sızıntılarını denetle',
  'exp.reAudit': 'Yeniden denetle',
  'exp.probe': { other: '{count} origin’i doğrudan ölç' },
  'exp.probeHint': 'İsteğe bağlı: her origin adresine, ad Host olarak verilerek Globalping üzerinden bir HTTPS GET ({count} ölçüm).',
  'exp.running.leaks': 'Origin sızıntıları için DNS kontrol ediliyor…',
  'exp.running.probe': 'Origin’ler ölçülüyor…',
  'exp.progress': '{total} işlemden {done} tanesi',
  'exp.ranNone': 'DNS’te origin sızıntısı bulunamadı. Bir origin’in siteyi kendisinin sunup sunmadığını görmek için doğrudan ölçüm çalıştırın.',
  'exp.ranClean': 'Açıkta kalan bir şey bulunamadı: hiçbir DNS kaydı bir origin’i göstermiyor ve ölçülen hiçbir origin siteyi doğrudan sunmadı.',
  'exp.findingsTitle': 'Bulgular',
  'exp.findingsSubtitle': { other: 'En kötüsü önce olmak üzere {count} bulgu' },
  'exp.copySummary': 'Özeti kopyala',
  'exp.summaryTitle': 'Origin açığa çıkma denetimi',
  'exp.summaryWorst': 'En kötü: {sev} · {count} bulgu · {ips} origin adresi sızdırıldı',
  'exp.summaryClean': '{count} proxy’li origin genelinde açığa çıkma bulunamadı.',
  'exp.names': { other: '{first} +{count}' },
  'exp.reachLine': 'Doğrudan ölçüm: {exposed} açıkta, {filtered} filtrelenmiş, {closed} kapalı, {other} diğer.',
  'exp.reach.status': '{name} origin’i: {result}',
  'exp.measurement': 'ölçüm',
  'exp.quota': 'Globalping’in saatlik kotası doldu — {when} sıfırlanır. DNS bulguları yine de gösteriliyor.',
  'exp.leakError': 'DNS denetimi tamamlanamadı.',
  'exp.failures': { other: '{count} sorgu başarısız oldu — sonuç eksik olabilir.' },
  'exp.retry': 'Yeniden dene',
  'exp.finding.reachable': 'Origin’e doğrudan erişilebiliyor',
  'exp.finding.dns-a': 'Origin’i gösteren A / AAAA kaydı',
  'exp.finding.https-hint': 'Origin’i gösteren HTTPS kaydı ipucu',
  'exp.finding.dns-mx': 'Origin üzerindeki posta sunucusu',
  'exp.finding.spf': 'SPF origin’i yetkilendiriyor',
  'exp.finding.txt-ip': 'TXT kaydı origin’i içeriyor',
  'exp.finding.dns-ns': 'Origin üzerindeki ad sunucusu',
  'exp.sev.critical': 'Kritik',
  'exp.sev.high': 'Yüksek',
  'exp.sev.medium': 'Orta',
  'exp.sev.low': 'Düşük',
  'exp.sev.info': 'Bilgi',
  'exp.reach.exposed': 'açıkta (siteyi doğrudan sundu)',
  'exp.reach.other-content': 'yanıt verdi ama bu site değil',
  'exp.reach.filtered': 'filtrelenmiş (yanıt yok — iyi)',
  'exp.reach.closed': 'kapalı (reddetti — iyi)',
  'exp.reach.unreachable': 'erişilemez',
  'exp.reach.incomplete': 'karşılaştırılamadı',
  'exp.advice.firewall': 'Güvenlik duvarında origin’e yalnızca CDN’inizin yayımladığı IP aralıklarının erişmesine izin verin.',
  'exp.advice.aop': 'Origin yalnızca CDN’e yanıt versin diye Authenticated Origin Pulls (mTLS) zorunlu kılın.',
  'exp.advice.tunnel': 'Origin’i bir Cloudflare Tunnel’ın (ya da eşdeğerinin) arkasına alın; böylece genel bir gelen adrese ihtiyacı kalmaz.',
  'exp.advice.move': 'Sızdıran servisi (posta, ad sunucusu) origin adresinden taşıyın.',
  'exp.advice.rotate': 'Sızıntı kapatıldıktan sonra origin adresini değiştirin — eskisi zaten biliniyor.',
  'exp.skip.private': 'özel adres — yalnızca DNS sızıntıları',
  'exp.skip.reserved': 'ayrılmış adres — yalnızca DNS sızıntıları',
  'exp.skip.wildcard': 'wildcard ad — yalnızca DNS sızıntıları',
  'exp.skip.bad-name': 'ölçülebilir ad değil — yalnızca DNS sızıntıları',
  'exp.skip.bad-port': 'port ölçülemez — yalnızca DNS sızıntıları'
});

/** The code-built i18n keys, for the coverage test (as ui/origin-map.js does). */
export function generatedKeys() {
  const keys = [];
  for (const k of EXPOSURE_FINDINGS) keys.push(`exp.finding.${k}`);
  for (const s of EXPOSURE_SEVERITIES) keys.push(`exp.sev.${s}`);
  for (const r of REACH_RESULTS) keys.push(`exp.reach.${r}`);
  for (const a of EXPOSURE_ADVICE) keys.push(`exp.advice.${a}`);
  for (const r of SKIP_REASONS) keys.push(`exp.skip.${r}`);
  return keys;
}

// A switch to another workspace naming a running audit (ui/jobs.js registerRunning).
let anyRunning = false;
registerRunning('exp.running.leaks', () => anyRunning);

/** The known host names of the page session grouped by domain, to widen the DNS-leak scan. */
function sessionHostsByDomain(domains) {
  const want = new Set(domains);
  const out = new Map();
  const add = (raw) => {
    const n = normalizeHostname(String(raw ?? ''));
    const d = n ? registrableDomain(n) : null;
    if (!n || !d || !want.has(d)) return;
    if (!out.has(d)) out.set(d, new Set());
    out.get(d).add(n);
  };
  const scan = state.getSession('scanHosts');
  for (const n of scan && Array.isArray(scan.names) ? scan.names : []) add(n);
  const zone = state.getSession('zone');
  for (const n of zone && Array.isArray(zone.names) ? zone.names : []) add(n);
  return new Map([...out].map(([d, set]) => [d, [...set]]));
}

/**
 * The Exposure audit tab of the Servers view.
 * @param {{ ctx: import('../app.js').ViewContext }} opts
 * @returns {{ el: HTMLElement, destroy(): void }}
 */
export function ExposurePanel({ ctx }) {
  const el = h('div', { class: 'stack exp-panel', dataset: { role: 'exposure' } });
  const S = {
    targets: [], capped: false, running: null, controller: null, progress: null,
    ran: false, leaks: [], probeFindings: [], reach: new Map(), leakFailures: [], leakError: null, quotaResetAt: null
  };

  function loadTargets() {
    const map = state.workspaceData('origins');
    const zone = state.getSession('zone');
    const index = ctx.getInventoryIndex();
    const res = exposureTargets({ map, zone, index });
    S.targets = res.targets;
    S.capped = res.capped;
  }

  const allFindings = () => sortFindings([...S.leaks, ...S.probeFindings]);

  function stop() {
    if (S.controller) S.controller.abort();
    S.controller = null;
    S.running = null;
    anyRunning = false;
  }

  /* --- the DNS-leak audit --------------------------------------------- */
  async function auditLeaks({ retry = false } = {}) {
    if (S.running || !S.targets.length || !ctx.requireOnline()) return;
    const ac = new AbortController();
    Object.assign(S, { running: 'leaks', controller: ac, progress: { done: 0, total: 0 }, leakError: null });
    if (retry) S.leaks = [];
    anyRunning = true;
    ctx.setBusy(true);
    render();
    try {
      const dns = await ctx.getDns();
      const hosts = sessionHostsByDomain([...new Set(S.targets.map((x) => x.domain).filter(Boolean))]);
      const res = await runLeakScan({
        targets: S.targets, dns, signal: ac.signal, hosts,
        onProgress: (done, total) => { S.progress = { done, total }; updateProgress(); }
      });
      if (S.controller !== ac) return;
      Object.assign(S, { leaks: res.findings, leakFailures: res.failures, ran: true });
      announce(summaryText());
    } catch (err) {
      if (S.controller !== ac) return;
      if (errorKind(err) === 'abort' || ac.signal.aborted) return;
      S.leakError = err;
    } finally {
      if (S.controller === ac) {
        S.controller = null;
        S.running = null;
        anyRunning = false;
        ctx.setBusy(false);
      }
      if (el.isConnected || !ac.signal.aborted) render();
    }
  }

  /* --- the opt-in direct probe ---------------------------------------- */
  async function probeOrigins() {
    const probeable = S.targets.filter((x) => x.probeable);
    if (S.running || !probeable.length || !ctx.requireOnline()) return;
    const ac = new AbortController();
    Object.assign(S, { running: 'probe', controller: ac, progress: { done: 0, total: probeable.length }, quotaResetAt: null });
    anyRunning = true;
    ctx.setBusy(true);
    render();
    try {
      const gate = await gateProbes(ctx, {
        purpose: EXPOSURE_PURPOSE, probes: probeable.length * EXPOSURE_PROBES, signal: ac.signal, className: 'exp-confirm',
        confirmAbove: CONFIRM_ABOVE, privacy: probePrivacy(probeable)
      });
      if (S.controller !== ac) return;
      if (gate.status === 'cancelled') return;
      if (gate.status === 'quota') {
        S.quotaResetAt = gate.resetAt;
        announce(t('exp.quota', { when: whenText(gate.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') throw gate.error;
      const client = gate.client;
      for (let i = 0; i < probeable.length; i += 1) {
        if (ac.signal.aborted) break;
        const target = probeable[i];
        try {
          const { proxied } = exposureProbes({ name: target.name, ip: target.ip, port: target.port });
          const first = await client.measure(proxied, { signal: ac.signal });
          const { origin } = exposureProbes({ name: target.name, ip: target.ip, port: target.port, locations: first.id });
          const second = await client.measure(origin, { signal: ac.signal });
          noteQuota(client.quota);
          const sides = readExposureSides({ proxiedMeasurement: first.measurement, originMeasurement: second.measurement, name: target.name, ip: target.ip, now: Date.now() });
          const r = reachabilityFinding(sides, { name: target.name, ip: target.ip, port: target.port, server: target.server });
          S.reach.set(targetKey(target), { result: r.result, ids: [first.id, second.id] });
          if (r.finding) S.probeFindings.push(r.finding);
        } catch (err) {
          if (errorKind(err) === 'abort' || ac.signal.aborted) break;
          if (err && err.quota) noteQuota(err.quota);
          S.reach.set(targetKey(target), { result: 'error', error: err });
          if (err && (err.code === 'rate-limit' || err.code === 'insufficient-credits')) {
            S.quotaResetAt = err.resetAt || null;
            break;
          }
        }
        S.progress = { done: i + 1, total: probeable.length };
        updateProgress();
      }
      S.ran = true;
      announce(summaryText());
    } catch (err) {
      if (S.controller !== ac) return;
      if (errorKind(err) === 'abort' || ac.signal.aborted) return;
      S.leakError = err;
    } finally {
      if (S.controller === ac) {
        S.controller = null;
        S.running = null;
        anyRunning = false;
        ctx.setBusy(false);
      }
      if (el.isConnected || !ac.signal.aborted) render();
    }
  }

  function probePrivacy(probeable) {
    const names = probeable.slice(0, 3).map((x) => x.name).join(', ');
    return h('span', null, t('exp.probeHint', { count: probeable.length * EXPOSURE_PROBES }), ' ',
      h('code', null, names), probeable.length > 3 ? ` +${probeable.length - 3}` : '');
  }

  /* --- summary text (Copy summary and announcements) ------------------- */
  function summaryText() {
    const findings = allFindings();
    const s = exposureSummary(findings);
    const lines = [t('exp.summaryTitle')];
    if (!findings.length) {
      lines.push(s.total === 0 && S.ran ? t('exp.summaryClean', { count: S.targets.length }) : t('exp.ranNone'));
      return lines.join('\n');
    }
    lines.push(t('exp.summaryWorst', { sev: t(`exp.sev.${s.worst}`), count: formatNumber(s.total), ips: formatNumber(s.leakedIps) }));
    for (const f of findings.slice(0, 10)) {
      lines.push(`- [${t(`exp.sev.${f.severity}`)}] ${t(`exp.finding.${f.kind}`)}: \`${f.names.join(', ')}\` ← \`${f.record}\` → ${f.target}`);
    }
    if (findings.length > 10) lines.push(t('common.moreCount', { count: formatNumber(findings.length - 10) }));
    return lines.join('\n');
  }

  /* --- rendering ------------------------------------------------------- */
  const progressEl = h('div', { class: 'exp-progress', dataset: { role: 'exp-progress' }, attrs: { 'aria-live': 'polite' } });
  function updateProgress() {
    clear(progressEl);
    if (!S.running) return;
    const label = t(`exp.running.${S.running}`);
    const pct = S.progress && S.progress.total ? ` · ${t('exp.progress', { done: formatNumber(S.progress.done), total: formatNumber(S.progress.total) })}` : '';
    progressEl.append(h('span', { class: 'cluster' }, Spinner({ size: 14 }), h('span', { class: 'muted text-sm' }, `${label}${pct}`)));
  }

  function namesCell(f) {
    return f.names.length > 1 ? t('exp.names', { first: f.names[0], count: f.names.length - 1 }) : (f.names[0] || '');
  }

  function adviceCell(f) {
    return h('ul', { class: 'exp-advice' }, f.advice.map((a) => h('li', { title: t(`exp.advice.${a}`) }, t(`exp.advice.${a}`))));
  }

  function findingsCard() {
    const findings = allFindings();
    const table = DataTable({
      caption: t('exp.findingsTitle'),
      rows: findings,
      rowKey: (f) => `${f.kind}|${f.recordType}|${f.record}|${f.ip}|${f.port}`,
      dense: true,
      search: findings.length > 8,
      pageSize: 200,
      empty: t('exp.ranClean'),
      className: 'exp-table',
      rowClass: (f) => `exp-row-${f.severity}`,
      export: { filename: 'origin-exposure' },
      columns: [
        {
          key: 'severity', label: t('exp.col.severity'), sortable: true, sortValue: (f) => EXPOSURE_SEVERITIES.indexOf(f.severity),
          exportValue: (f) => f.severity, render: (f) => Badge(t(`exp.sev.${f.severity}`), { variant: SEV_VARIANT[f.severity] || 'neutral' })
        },
        { key: 'finding', label: t('exp.col.finding'), sortable: true, exportValue: (f) => f.kind, sortValue: (f) => EXPOSURE_FINDINGS.indexOf(f.kind), render: (f) => t(`exp.finding.${f.kind}`) },
        { key: 'name', label: t('exp.col.name'), mono: true, exportValue: (f) => f.names.join(' '), searchValue: (f) => f.names.join(' '), render: (f) => namesCell(f) },
        { key: 'origin', label: t('exp.col.origin'), mono: true, sortable: true, exportValue: (f) => f.target, render: (f) => f.target },
        { key: 'where', label: t('exp.col.where'), mono: true, searchValue: (f) => f.record, exportValue: (f) => [f.recordType, f.record, f.detail].filter(Boolean).join(' '), render: (f) => whereCell(f) },
        { key: 'advice', label: t('exp.col.advice'), export: false, wrap: true, render: adviceCell }
      ]
    });
    const copy = CopyButton(() => summaryText(), { label: t('exp.copySummary'), size: 'sm' });
    return Card({
      title: t('exp.findingsTitle'),
      subtitle: t('exp.findingsSubtitle', { count: findings.length }),
      icon: 'alert',
      className: 'exp-findings',
      actions: copy,
      children: table.el
    });
  }

  function whereCell(f) {
    return h('span', { class: 'exp-where' },
      f.recordType ? Badge(f.recordType, { variant: 'neutral', className: 'exp-rt' }) : null,
      h('code', null, f.record),
      f.detail ? h('span', { class: 'muted text-sm exp-detail' }, f.detail) : null);
  }

  function reachLine() {
    if (!S.reach.size) return null;
    const vals = [...S.reach.values()].map((r) => r.result);
    const count = (x) => vals.filter((v) => v === x).length;
    const other = vals.length - count('exposed') - count('filtered') - count('closed');
    return h('p', { class: 'muted text-sm', dataset: { role: 'exp-reach' } },
      t('exp.reachLine', { exposed: formatNumber(count('exposed')), filtered: formatNumber(count('filtered')), closed: formatNumber(count('closed')), other: formatNumber(other) }));
  }

  function statusCell(target) {
    const key = targetKey(target);
    const r = S.reach.get(key);
    if (r) {
      const variant = r.result === 'exposed' ? 'error' : r.result === 'error' ? 'warn' : r.result === 'filtered' || r.result === 'closed' ? 'ok' : 'info';
      const text = r.result === 'error' ? t('exp.reach.unreachable') : t(`exp.reach.${r.result}`);
      const link = r.ids && measurementUrl(r.ids[r.ids.length - 1]);
      const badge = Badge(text, { variant });
      return link ? h('span', { class: 'cluster' }, badge, h('a', { class: 'link text-sm', href: link, attrs: { target: '_blank', rel: 'noopener noreferrer' } }, t('exp.measurement'))) : badge;
    }
    if (target.skip) return Badge(t(`exp.skip.${target.skip}`), { variant: 'neutral' });
    return h('span', { class: 'muted text-sm' }, t('exp.toAudit'));
  }

  function targetsCard() {
    const table = DataTable({
      caption: t('exp.targetsTitle'),
      rows: S.targets,
      rowKey: targetKey,
      dense: true,
      search: S.targets.length > 10,
      pageSize: 200,
      className: 'exp-targets-table',
      columns: [
        { key: 'name', label: t('exp.col.name'), mono: true, sortable: true, render: (x) => x.name },
        { key: 'origin', label: t('exp.col.origin'), mono: true, sortable: true, exportValue: (x) => x.target, render: (x) => x.target },
        { key: 'server', label: t('exp.col.server'), sortable: true, render: (x) => x.server || '' },
        { key: 'source', label: t('exp.col.source'), sortable: true, render: (x) => x.source },
        { key: 'status', label: t('exp.col.status'), export: false, render: statusCell }
      ]
    });
    return Card({ title: t('exp.targetsTitle'), subtitle: t('exp.targetsSubtitle'), icon: 'server', className: 'exp-targets', children: table.el });
  }

  function controls() {
    const probeable = S.targets.filter((x) => x.probeable);
    const leaksBtn = Button({
      label: S.ran ? t('exp.reAudit') : t('exp.auditLeaks'), icon: 'search', variant: 'primary',
      disabled: !!S.running, dataset: { action: 'exp-audit' }, onClick: () => auditLeaks({ retry: S.ran })
    });
    const probeBtn = probeable.length
      ? Button({
        label: t('exp.probe', { count: probeable.length }), icon: 'globe', variant: 'secondary',
        disabled: !!S.running, dataset: { action: 'exp-probe' }, onClick: () => probeOrigins()
      })
      : null;
    return h('div', { class: 'cluster exp-controls' }, leaksBtn, probeBtn, progressEl);
  }

  function statsRow() {
    const findings = allFindings();
    const s = exposureSummary(findings);
    const probeable = S.targets.filter((x) => x.probeable).length;
    return h('div', { class: 'stat-grid exp-stats' },
      StatCard({ label: t('exp.stat.targets'), value: formatNumber(S.targets.length), icon: 'server', variant: 'accent' }),
      StatCard({ label: t('exp.stat.probeable'), value: formatNumber(probeable), icon: 'globe' }),
      StatCard({ label: t('exp.stat.findings'), value: formatNumber(s.total), icon: 'alert', variant: s.total ? 'warn' : 'default' }),
      StatCard({ label: t('exp.stat.worst'), value: s.worst ? t(`exp.sev.${s.worst}`) : t('exp.none'), icon: 'shield', variant: s.worst === 'critical' || s.worst === 'high' ? 'warn' : 'default' }));
  }

  function render() {
    clear(el);
    el.append(Alert({ variant: 'ok', icon: 'lock', compact: true, message: t('exp.privacy') }));
    if (!S.targets.length) {
      el.append(Card({
        icon: 'shield', className: 'exp-lead',
        children: h('div', { class: 'stack-sm' }, h('p', null, t('exp.lead')),
          EmptyState({ icon: 'map-pin', message: t('exp.empty'), action: Button({ label: t('exp.openMap'), icon: 'map-pin', size: 'sm', onClick: () => ctx.setParams({ tab: 'origins' }) }) }))
      }));
      updateProgress();
      return;
    }
    el.append(
      Card({ icon: 'shield', className: 'exp-lead', children: h('div', { class: 'stack-sm' }, h('p', null, t('exp.lead')), statsRow(), controls()) }));
    if (S.leakError) {
      el.append(ErrorBanner(S.leakError, { title: t('exp.leakError'), compact: true, onRetry: () => auditLeaks({ retry: true }) }));
    }
    if (S.quotaResetAt) el.append(Alert({ variant: 'warn', icon: 'clock', compact: true, message: t('exp.quota', { when: whenText(S.quotaResetAt) }) }));
    if (S.leakFailures.length) {
      el.append(Alert({
        variant: 'warn', icon: 'alert', compact: true,
        message: h('span', null, t('exp.failures', { count: S.leakFailures.length }), ' ',
          Button({ label: t('exp.retry'), icon: 'refresh', size: 'sm', variant: 'ghost', onClick: () => auditLeaks({ retry: true }) }))
      }));
    }
    if (S.ran && !allFindings().length) el.append(Alert({ variant: 'ok', icon: 'check', compact: true, message: exposureSummary(allFindings()).total === 0 && S.reach.size ? t('exp.ranClean') : t('exp.ranNone') }));
    if (allFindings().length) el.append(findingsCard());
    const rl = reachLine();
    if (rl) el.append(rl);
    el.append(targetsCard());
    el.append(adviceLegend());
    updateProgress();
  }

  function adviceLegend() {
    return Disclosure({
      summary: t('exp.col.advice'),
      className: 'exp-advice-legend',
      children: h('ul', { class: 'stack-sm' }, EXPOSURE_ADVICE.map((a) => h('li', null, h('strong', null, t(`exp.advice.${a}`)))))
    });
  }

  // Another tab wrote the origin map, or a workspace switch: reload the targets and redraw.
  const off = state.subscribe(({ key, value }) => {
    if (key === 'cleared' || key === 'workspace') {
      stop();
      Object.assign(S, { ran: false, leaks: [], probeFindings: [], reach: new Map(), leakFailures: [], leakError: null, quotaResetAt: null });
      loadTargets();
      render();
    } else if (key === 'workspaceData' && value && Array.isArray(value.parts) && value.parts.includes('origins')) {
      loadTargets();
      render();
    }
  });

  loadTargets();
  render();
  return {
    el,
    destroy() {
      stop();
      off();
    }
  };
}
