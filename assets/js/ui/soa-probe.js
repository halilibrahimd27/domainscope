/**
 * ui/soa-probe.js — Global DNS › Expected value › "Ask the zone's name server": one Globalping DNS
 * measurement (lib/soaprobe.js) that asks the zone's own name server for the SOA of the name, for
 * the worst-case wait the card gives. Loaded on its first click (views/global.js), which also sends
 * it: the zone and its name servers over DoH (free), then the consent and quota gate
 * (ui/globalping-gate.js, purpose `soa-probe`; its privacy text names the name and the server),
 * then one probe.
 *
 * The answer, from the source: whether the server answers for the zone with authority (else a lame
 * delegation), the zone's serial and primary, whether the name exists there (a record the change
 * should add that the name server does not have has not reached the zone), and the negative-cache
 * time — which the card's worst case then takes instead of the one read from cached answers.
 *
 * Statuses, never blanks: looking up the name servers, reading the quota, asking the server, done,
 * nothing sent (an internal name, no zone of its own, no name server Globalping can ask), the quota
 * used up (when it resets), Globalping unreachable, no probe available, a failed measurement (with
 * its link). A new check resets it, leaving the view aborts it; a language re-mount keeps its answer
 * (`snapshot()`), with nothing sent again.
 *
 * Every string is rendered through h() / text nodes.
 */

import { h, clear } from './dom.js';
import { Alert, Button, announce, setButtonBusy } from './components.js';
import { t, registerStrings, formatNumber, formatRegion } from '../i18n.js';
import { registerRunning } from './jobs.js';
import { gateProbes, noteQuota, whenText, measurementUrl } from './globalping-gate.js';
import { SOA_PROBE_COST, SOA_PROBE_PURPOSE, planSoaProbe, runSoaProbe } from '../lib/soaprobe.js';
import { errorKind, mergeSignals } from '../lib/util.js';

registerStrings('en', {
  'soa.running': 'The zone’s name server (Global DNS)',
  'soa.run': 'Ask the zone’s name server (1 Globalping probe)',
  'soa.again': 'Ask again (1 Globalping probe)',
  'soa.status.plan': 'Looking up the zone and its name servers…',
  'soa.status.gate': 'Reading the Globalping quota…',
  'soa.status.running': 'Asking {ns} for the SOA of {name}…',
  'soa.status.quota': 'The Globalping quota for this hour is used up (resets {when}). Nothing was sent.',
  'soa.status.unreachable': 'Globalping could not be reached. Nothing was sent.',
  'soa.status.noProbes': 'Globalping has no probe free right now. Nothing was sent: try again in a minute.',
  'soa.status.failed': 'The measurement failed: {error}',
  'soa.err.name': 'Globalping cannot ask for this name. Nothing was sent.',
  'soa.err.internal': 'An internal name ({name}) is never sent to Globalping.',
  'soa.err.lookup': 'The zone’s name servers could not be looked up. Nothing was sent.',
  'soa.err.no-zone': '{name} belongs to no zone of its own — only a public suffix answers for it, so it is most likely not registered. Nothing was sent.',
  'soa.err.no-ns': 'The zone {zone} has no name servers in DNS. Nothing was sent.',
  'soa.err.not-probeable': 'Globalping cannot ask any of the name servers of {zone}. Nothing was sent.',
  'soa.privacy': 'Globalping (jsDelivr) receives the name {name} and the zone’s name server {ns}; one probe asks that server for the SOA of the name. The result is public by its measurement ID. Nothing else is sent.',
  'soa.measurement': 'Measurement {id}',
  'soa.from': 'Asked from {place}.',
  'soa.res.ok': '{ns} answers for the zone {zone} with authority.',
  'soa.res.serial': 'SOA serial {serial}, primary {mname}.',
  'soa.res.exists': '{name} exists there.',
  'soa.res.missing': '{name} does not exist there.',
  'soa.res.missingExpected': 'The change has not reached the zone yet — or it went to another zone or DNS provider: no resolver can serve what the name server does not have.',
  'soa.res.alias': '{name} is an alias of {target} there.',
  'soa.res.negative': 'Negative-cache time: {ttl} s — the lower of the SOA’s TTL ({soaTtl} s) and its minimum ({minimum} s).',
  'soa.state.not-authoritative': '{ns} answered without authority for {zone}: a lame delegation — that server does not serve the zone.',
  'soa.state.refused': '{ns} refused the question: it does not serve the zone {zone} (a lame delegation).',
  'soa.state.servfail': '{ns} answered SERVFAIL: it could not answer for the zone {zone}.',
  'soa.state.timeout': '{ns} did not answer in time.',
  'soa.state.unreachable': '{ns} could not be reached.',
  'soa.state.failed': 'The probe got no answer from {ns}: {error}'
});

registerStrings('tr', {
  'soa.running': 'Bölgenin ad sunucusu (Global DNS)',
  'soa.run': 'Bölgenin ad sunucusuna sor (1 Globalping ölçümü)',
  'soa.again': 'Yeniden sor (1 Globalping ölçümü)',
  'soa.status.plan': 'Bölge ve ad sunucuları aranıyor…',
  'soa.status.gate': 'Globalping kotası okunuyor…',
  'soa.status.running': '{ns} sunucusuna {name} adının SOA kaydı soruluyor…',
  'soa.status.quota': 'Bu saatin Globalping kotası doldu ({when} sıfırlanır). Hiçbir şey gönderilmedi.',
  'soa.status.unreachable': 'Globalping’e ulaşılamadı. Hiçbir şey gönderilmedi.',
  'soa.status.noProbes': 'Globalping’in şu anda boşta ölçüm noktası yok. Hiçbir şey gönderilmedi: bir dakika sonra yeniden deneyin.',
  'soa.status.failed': 'Ölçüm başarısız oldu: {error}',
  'soa.err.name': 'Globalping bu adı soramaz. Hiçbir şey gönderilmedi.',
  'soa.err.internal': 'İç ağ adları ({name}) Globalping’e asla gönderilmez.',
  'soa.err.lookup': 'Bölgenin ad sunucuları bulunamadı. Hiçbir şey gönderilmedi.',
  'soa.err.no-zone': '{name} kendine ait bir bölgeye bağlı değil — onun için yalnızca bir genel sonek (public suffix) yanıt veriyor; büyük olasılıkla kayıtlı değil. Hiçbir şey gönderilmedi.',
  'soa.err.no-ns': '{zone} bölgesinin DNS’te ad sunucusu yok. Hiçbir şey gönderilmedi.',
  'soa.err.not-probeable': 'Globalping, {zone} bölgesinin ad sunucularının hiçbirine soramaz. Hiçbir şey gönderilmedi.',
  'soa.privacy': 'Globalping (jsDelivr) {name} adını ve bölgenin ad sunucusu {ns} bilgisini alır; tek bir ölçüm noktası bu sunucuya adın SOA kaydını sorar. Sonuç, ölçüm kimliğini bilen herkese açıktır. Başka hiçbir şey gönderilmez.',
  'soa.measurement': 'Ölçüm {id}',
  'soa.from': 'Sorulduğu yer: {place}.',
  'soa.res.ok': '{ns}, {zone} bölgesi için yetkili olarak yanıt veriyor.',
  'soa.res.serial': 'SOA seri numarası {serial}, birincil sunucu {mname}.',
  'soa.res.exists': '{name} orada var.',
  'soa.res.missing': '{name} orada yok.',
  'soa.res.missingExpected': 'Değişiklik henüz bölgeye ulaşmamış — ya da başka bir bölgeye veya DNS sağlayıcısına yapılmış: ad sunucusunda olmayanı hiçbir çözümleyici döndüremez.',
  'soa.res.alias': '{name} orada {target} adının takma adı (CNAME).',
  'soa.res.negative': 'Negatif önbellek süresi: {ttl} sn — SOA kaydının TTL değeri ({soaTtl} sn) ile minimum değerinden ({minimum} sn) küçük olanı.',
  'soa.state.not-authoritative': '{ns}, {zone} için yetkisiz yanıt verdi: hatalı yetkilendirme (lame delegation) — bu sunucu bölgeyi sunmuyor.',
  'soa.state.refused': '{ns} soruyu reddetti: {zone} bölgesini sunmuyor (hatalı yetkilendirme).',
  'soa.state.servfail': '{ns} SERVFAIL döndürdü: {zone} bölgesi için yanıt veremedi.',
  'soa.state.timeout': '{ns} zamanında yanıt vermedi.',
  'soa.state.unreachable': '{ns} sunucusuna ulaşılamadı.',
  'soa.state.failed': 'Ölçüm noktası {ns} sunucusundan yanıt alamadı: {error}'
});

/** Panels with a probe going (a workspace switch names it). */
const runningPanels = new Set();
registerRunning('soa.running', () => runningPanels.size > 0);

/** Where a probe asked from: "Frankfurt, Germany (Example Networks)". */
function placeOf(probe) {
  if (!probe) return null;
  const where = [probe.city, probe.country ? formatRegion(probe.country) : null].filter(Boolean).join(', ');
  return [where, probe.network ? `(${probe.network})` : null].filter(Boolean).join(' ') || null;
}

/**
 * Mount the probe panel.
 * @param {HTMLElement} el
 * @param {{ ctx: object, check: () => ({ name: string, type: string, busy: boolean }|null),
 *   expected: () => (object|null), onResult: (result: object|null) => void }} host
 *   `check`: the check on screen; `expected`: its parsed expected value (lib/expected.js); `onResult`:
 *   the name server's answer (lib/soaprobe.js SoaProbe), for the card's worst case
 * @param {{ restored?: { result: object|null, id: string|null }|null }} [opts]
 * @returns {{ run: () => Promise<void>, reset: () => void, refresh: () => void, busy: () => boolean,
 *   snapshot: () => object|null, teardown: () => void }}
 */
export function mountSoaProbe(el, host, { restored = null } = {}) {
  const { ctx } = host;
  /** The panel's state: `status` idle | plan | gate | running | done | plan-<error> | quota | unreachable | no-probes | failed. */
  const P = { status: 'idle', controller: null, result: null, id: null, error: null, plan: null, resetAt: null, name: null };
  if (restored && restored.result) Object.assign(P, { status: 'done', result: restored.result, id: restored.id || null, name: restored.result.name });

  const statusEl = h('div', { class: 'glb-soa-status', dataset: { role: 'soa-status' }, attrs: { 'aria-live': 'polite' } });
  const resultEl = h('div', { class: 'glb-soa-result', dataset: { role: 'soa-result' } });
  const runBtn = Button({ label: t('soa.run'), icon: 'server', size: 'sm', variant: 'secondary', dataset: { action: 'soa-run' }, onClick: () => run() });
  el.append(h('div', { class: 'stack-sm glb-soa', dataset: { role: 'soa-panel' } }, statusEl, resultEl, h('div', { class: 'cluster' }, runBtn)));

  const errorText = (err) => (err && typeof err.message === 'string' && err.message ? err.message : t(`error.kind.${errorKind(err) || 'unknown'}`));
  const link = (id) => (id && measurementUrl(id)
    ? h('a', { href: measurementUrl(id), target: '_blank', rel: 'noopener noreferrer', class: 'text-sm', dataset: { role: 'soa-measurement' } }, t('soa.measurement', { id }))
    : null);

  /** The name server's answer, as one alert: authority, the serial, the name there, the negative-cache time. */
  function resultAlert(r) {
    const lines = [];
    let variant = 'info';
    if (r.state === 'ok') {
      lines.push(t('soa.res.ok', { ns: r.ns, zone: r.zone }));
      if (r.soa) lines.push(t('soa.res.serial', { serial: String(r.soa.serial), mname: r.soa.mname }));
      if (r.alias) lines.push(t('soa.res.alias', { name: r.name, target: r.alias }));
      else if (r.exists === true) lines.push(t('soa.res.exists', { name: r.name }));
      else if (r.exists === false) {
        lines.push(t('soa.res.missing', { name: r.name }));
        const exp = host.expected();
        if (exp && exp.special !== 'NXDOMAIN') {
          lines.push(t('soa.res.missingExpected'));
          variant = 'warn';
        }
      }
      if (r.soa && r.negativeTtl !== null) {
        lines.push(t('soa.res.negative', { ttl: formatNumber(r.negativeTtl), soaTtl: formatNumber(r.soa.ttl ?? r.soa.minimum), minimum: formatNumber(r.soa.minimum) }));
      }
    } else {
      lines.push(t(`soa.state.${r.state}`, { ns: r.ns, zone: r.zone, error: r.error || r.rcode || '' }));
      variant = r.state === 'timeout' || r.state === 'unreachable' || r.state === 'failed' ? 'error' : 'warn';
    }
    const place = placeOf(r.probe);
    const node = Alert({
      variant, compact: true, icon: 'server', message: lines.join(' '),
      children: h('div', { class: 'cluster text-sm glb-soa-meta' }, place ? h('span', { class: 'muted' }, t('soa.from', { place })) : null, link(r.measurementId || P.id))
    });
    Object.assign(node.dataset, { soaState: r.state, soaExists: r.exists === null ? '' : String(r.exists) });
    return node;
  }

  function render() {
    clear(statusEl);
    clear(resultEl);
    const chk = host.check();
    const running = !!P.controller;
    runBtn.hidden = running;
    runBtn.disabled = !chk || chk.busy;
    runBtn.querySelector('.btn-label').textContent = P.result ? t('soa.again') : t('soa.run');
    setButtonBusy(runBtn, false);
    const name = (P.plan && P.plan.name) || P.name || (chk && chk.name) || '';
    let node = null;
    if (P.status === 'plan') node = Alert({ variant: 'info', compact: true, message: t('soa.status.plan') });
    else if (P.status === 'gate') node = Alert({ variant: 'info', compact: true, message: t('soa.status.gate') });
    else if (P.status === 'running') node = Alert({ variant: 'info', icon: 'activity', compact: true, message: t('soa.status.running', { ns: P.plan.ns, name }) });
    else if (P.status.startsWith('plan-')) {
      node = Alert({ variant: 'warn', compact: true, message: t(`soa.err.${P.status.slice(5)}`, { name, zone: (P.plan && P.plan.zone) || '' }) });
    } else if (P.status === 'quota') node = Alert({ variant: 'warn', compact: true, message: t('soa.status.quota', { when: whenText(P.resetAt) }) });
    else if (P.status === 'unreachable') node = Alert({ variant: 'error', compact: true, message: t('soa.status.unreachable') });
    else if (P.status === 'no-probes') node = Alert({ variant: 'warn', compact: true, message: t('soa.status.noProbes') });
    else if (P.status === 'failed') node = Alert({ variant: 'error', compact: true, message: t('soa.status.failed', { error: errorText(P.error) }), children: link(P.id) });
    if (node) {
      node.dataset.soaStatus = P.status;
      statusEl.append(node);
    }
    if (P.result) resultEl.append(resultAlert(P.result));
  }

  /** Plan, gate and send the probe for the check on screen; its answer goes to the card. */
  async function run() {
    const chk = host.check();
    if (!chk || chk.busy || P.controller || !ctx.requireOnline()) return;
    const ac = new AbortController();
    const signal = mergeSignals(ctx.signal, ac.signal);
    Object.assign(P, { controller: ac, status: 'plan', error: null, plan: null, name: chk.name });
    runningPanels.add(P);
    render();
    const before = P.result ? 'done' : 'idle';
    try {
      const plan = await planSoaProbe(chk.name, { dns: await ctx.getDns(), signal });
      if (P.controller !== ac) return;
      if (!plan.ok) {
        P.plan = plan.zone ? { zone: plan.zone, name: chk.name } : null;
        P.status = `plan-${plan.error}`;
        announce(t(`soa.err.${plan.error}`, { name: chk.name, zone: plan.zone || '' }));
        return;
      }
      P.plan = plan;
      P.status = 'gate';
      render();
      const gate = await gateProbes(ctx, {
        purpose: SOA_PROBE_PURPOSE, probes: SOA_PROBE_COST, signal, className: 'soa-confirm',
        privacy: t('soa.privacy', { name: plan.name, ns: plan.ns })
      });
      if (P.controller !== ac) return;
      if (gate.status === 'cancelled') {
        P.status = before;
        return;
      }
      if (gate.status === 'quota') {
        Object.assign(P, { status: 'quota', resetAt: gate.resetAt });
        announce(t('soa.status.quota', { when: whenText(gate.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') {
        Object.assign(P, { status: 'unreachable', error: gate.error });
        return;
      }
      P.status = 'running';
      render();
      const out = await runSoaProbe(plan, { client: gate.client, signal });
      noteQuota(out.quota);
      if (P.controller !== ac) return;
      Object.assign(P, { status: 'done', result: out.result, id: out.id });
      announce(resultAlert(out.result).textContent);
    } catch (err) {
      if (P.controller !== ac) return;
      if (err && err.quota) noteQuota(err.quota);
      if (errorKind(err) === 'abort' || ac.signal.aborted) P.status = before;
      else if (err && (err.code === 'rate-limit' || err.code === 'insufficient-credits')) Object.assign(P, { status: 'quota', resetAt: err.resetAt || null });
      else if (err && err.code === 'no-probes') P.status = 'no-probes';
      else Object.assign(P, { status: 'failed', error: err, id: (err && err.measurementId) || null });
    } finally {
      if (P.controller === ac) {
        P.controller = null;
        runningPanels.delete(P);
        if (!ctx.signal.aborted) {
          render();
          host.onResult(P.result);
        }
      }
    }
  }

  const api = {
    run,
    /** A new check: whatever runs stops, the last answer goes (it was about the last check's name). */
    reset() {
      if (P.controller) P.controller.abort();
      P.controller = null;
      runningPanels.delete(P);
      Object.assign(P, { status: 'idle', result: null, id: null, error: null, plan: null, resetAt: null, name: null });
      render();
    },
    refresh: render,
    busy: () => !!P.controller,
    /** What a language re-mount shows again (the answer and its measurement), or null. */
    snapshot: () => (P.result ? { result: P.result, id: P.id } : null),
    teardown() {
      if (P.controller) P.controller.abort();
      runningPanels.delete(P);
    }
  };
  render();
  if (P.result) host.onResult(P.result);
  return api;
}
