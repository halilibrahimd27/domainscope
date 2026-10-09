/**
 * ui/isp-resolvers.js — Global DNS › ISP resolvers: what the resolvers of real ISPs answer for the
 * check on screen, asked through Globalping probes (lib/ispdns.js). Loaded on first use.
 *
 * - The form: how many probes (10 over the continents by default, up to 50), the countries / AS
 *   numbers / places to take them from, and whether only consumer (eyeball) networks count.
 *   Every send goes through ui/globalping-gate.js (consent, the quota shown before and after).
 * - The probes' answers become rows of the check (kind 'isp', a row group of their own: their
 *   table here), so the answer groups, the IP table and the verdict (lib/propagation.js: by design,
 *   propagating, or stale at these ISPs) take them in; each row shows the probe's country, city,
 *   ASN / network, the resolver it asked and the TTL its cache has left, i.e. when an old answer
 *   there expires.
 * - Failures are statuses: the quota, Globalping unreachable, no probes in those places, a probe
 *   that timed out (its row); Stop and leaving the view abort the run.
 *
 * Every string is rendered through h() / text nodes.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, DataTable, announce, checkbox, select, setButtonBusy, textInput } from './components.js';
import { t, registerStrings, formatNumber, formatRegion, formatDate } from '../i18n.js';
import { Flag } from './flag.js';
import { registerRunning } from './jobs.js';
import { PrivacyNote } from './template.js';
import { gateProbes, noteQuota, sharedQuota, liveQuota, whenText, measurementUrl } from './globalping-gate.js';
import {
  ISP_PURPOSE, ISP_PROBE_CHOICES, ISP_DEFAULT_PROBES, ISP_MAX_PICKS, parsePicks, planIspMeasurement, mapIspResults, pendingIspRows, longestTtl
} from '../lib/ispdns.js';
import { GP_LIMITS } from '../lib/globalping.js';
import { errorKind, mergeSignals } from '../lib/util.js';
import { splitChain } from '../lib/propagation.js';

/** A batch of more probes than this asks again, even after this page session's consent. */
export const ISP_CONFIRM_ABOVE = 20;

registerStrings('en', {
  'isp.running': 'ISP resolvers (Global DNS)',
  'isp.intro': 'Each Globalping probe asks its own default resolver — the resolver of the ISP it sits in — so you see what users there get, and how long each ISP still keeps its answer cached.',
  'isp.probes': 'Probes',
  'isp.probeCount': { one: '{count} probe', other: '{count} probes' },
  'isp.places': 'Countries or networks (optional)',
  'isp.placesPlaceholder': 'TR, DE, AS3320, Comcast, Istanbul',
  'isp.placesHint': 'Two-letter country codes, AS numbers, or a city, region or network name, separated by commas. Empty: spread over the continents.',
  'isp.eyeball': 'ISP (home and mobile) networks only',
  'isp.eyeballHint': 'A probe in a data centre asks its host’s resolver, not an ISP’s.',
  'isp.run': 'Ask ISP resolvers',
  'isp.quota': 'Globalping: {remaining} of {limit} probes left this hour (resets {when}).',
  'isp.noCheck': 'Run a check first: the ISP resolvers are asked the same name and record type.',
  'isp.waitCheck': 'The ISP resolvers can be asked once the check has finished.',
  'isp.status.gate': 'Reading the Globalping quota…',
  'isp.status.running': { one: 'Asking {count} probe…', other: 'Asking {count} probes…' },
  'isp.status.done': '{answered} of {count} probes answered.',
  'isp.status.stopped': 'Stopped — {answered} of {count} probes had answered.',
  'isp.status.partial': 'Globalping gave no final result in time — showing the {answered} probes that answered.',
  'isp.status.quota': 'The Globalping quota for this hour is used up (resets {when}). Nothing was sent.',
  'isp.status.unreachable': 'Globalping could not be reached. Nothing was sent.',
  'isp.status.failed': 'The measurement failed: {error}',
  'isp.status.noProbes': 'Globalping has no probe in these places right now. Pick other countries or networks, or allow data-centre probes.',
  'isp.err.name': 'Globalping cannot ask for this name.',
  'isp.err.internal': 'An internal name ({name}) is never sent to Globalping.',
  'isp.err.type': 'Globalping cannot ask for {type} records: pick another record type and check again.',
  'isp.err.picks': 'Not a country code, AS number or place name: {entry}',
  'isp.err.picksMany': 'Pick at most {max} places, and no more places than probes.',
  'isp.err.probes': 'Pick 1–50 probes.',
  'isp.privacy': 'Globalping (jsDelivr) receives the name {name}, the record type and the places you picked; each probe asks its own resolver, so those ISPs’ resolvers receive the question too. Nothing else is sent.',
  'isp.measurement': 'Measurement {id}',
  'isp.title': 'ISP resolvers',
  'isp.col.location': 'Location',
  'isp.col.isp': 'ISP / network',
  'isp.col.resolver': 'Resolver',
  'isp.col.ttl': 'TTL left',
  'isp.resolver.private': 'ISP-internal',
  'isp.resolver.privateTitle': 'A private address: the ISP’s own resolver or the home router in front of it (Globalping does not show private addresses).',
  'isp.resolver.public': 'Public resolver, not the ISP’s',
  'isp.resolver.unknown': 'Not reported',
  'isp.datacenter': 'data centre',
  'isp.pendingProbe': 'Waiting for the probe',
  'isp.ttl.until': 'until {time}',
  'isp.ttl.title': 'This resolver keeps its answer cached for {human} more (until {time}); a newer answer reaches its users after that.',
  'isp.sum.staleTitle': { one: 'Stale at {count} ISP resolver', other: 'Stale at {count} ISP resolvers' },
  'isp.sum.ref.agree': 'The public resolvers and locations agree.',
  'isp.sum.ref.by-design': 'The public resolvers and locations differ only by design (CDN / GeoDNS edges).',
  'isp.sum.ref.geo': 'The public resolvers agree; the locations differ only by GeoDNS.',
  'isp.sum.staleWhy': 'These ISP resolvers still give an answer none of them gives: most likely an older answer in their cache, which expires by itself. If it stays after that, the ISP rewrites the name on purpose (some block names with an address of their own).',
  'isp.sum.line': '{isps}: {answer} — expires within {ttl} (by {time}).',
  'isp.sum.lineNoTtl': '{isps}: {answer}.',
  'isp.sum.unsure': '{isps}: an answer no public resolver or location gives — GeoDNS for their region, or an older answer still in their cache (it would expire within {ttl}).',
  'isp.sum.lingering': '{isps}: an answer no public resolver or location gives, most likely an older answer still in their cache (it expires within {ttl}).',
  'isp.sum.nxdomain': 'NXDOMAIN (cached: the name did not exist)',
  'isp.sum.nodata': 'no {type} records (cached empty answer)',
  'isp.ttlNone': 'no TTL'
});

registerStrings('tr', {
  'isp.running': 'İSS çözümleyicileri (Global DNS)',
  'isp.intro': 'Her Globalping ölçüm noktası kendi varsayılan çözümleyicisini — bulunduğu İSS’nin (internet servis sağlayıcısı) çözümleyicisini — sorar; böylece oradaki kullanıcıların ne aldığını ve her İSS’nin yanıtı daha ne kadar önbellekte tutacağını görürsünüz.',
  'isp.probes': 'Ölçüm sayısı',
  'isp.probeCount': '{count} ölçüm',
  'isp.places': 'Ülkeler veya ağlar (isteğe bağlı)',
  'isp.placesPlaceholder': 'TR, DE, AS9121, Turkcell, İstanbul',
  'isp.placesHint': 'İki harfli ülke kodları, AS numaraları ya da bir şehir, bölge veya ağ adı; virgülle ayırın. Boş bırakılırsa ölçümler kıtalara dağıtılır.',
  'isp.eyeball': 'Yalnızca İSS (ev ve mobil) ağları',
  'isp.eyeballHint': 'Veri merkezindeki bir ölçüm noktası İSS’nin değil, barındırma firmasının çözümleyicisini sorar.',
  'isp.run': 'İSS çözümleyicilerine sor',
  'isp.quota': 'Globalping: bu saat {limit} ölçümden {remaining} tanesi kaldı ({when} sıfırlanır).',
  'isp.noCheck': 'Önce bir kontrol çalıştırın: İSS çözümleyicilerine aynı ad ve kayıt türü sorulur.',
  'isp.waitCheck': 'İSS çözümleyicileri kontrol bittikten sonra sorulabilir.',
  'isp.status.gate': 'Globalping kotası okunuyor…',
  'isp.status.running': '{count} ölçüm soruluyor…',
  'isp.status.done': '{count} ölçümden {answered} tanesi yanıt verdi.',
  'isp.status.stopped': 'Durduruldu — {count} ölçümden {answered} tanesi yanıt vermişti.',
  'isp.status.partial': 'Globalping zamanında son sonucu vermedi — yanıt veren {answered} ölçüm gösteriliyor.',
  'isp.status.quota': 'Bu saatin Globalping kotası doldu ({when} sıfırlanır). Hiçbir şey gönderilmedi.',
  'isp.status.unreachable': 'Globalping’e ulaşılamadı. Hiçbir şey gönderilmedi.',
  'isp.status.failed': 'Ölçüm başarısız oldu: {error}',
  'isp.status.noProbes': 'Globalping’in şu anda bu yerlerde ölçüm noktası yok. Başka ülkeler veya ağlar seçin ya da veri merkezi ölçüm noktalarına izin verin.',
  'isp.err.name': 'Globalping bu adı soramaz.',
  'isp.err.internal': 'İç ağ adları ({name}) Globalping’e asla gönderilmez.',
  'isp.err.type': 'Globalping {type} kayıtlarını soramaz: başka bir kayıt türü seçip yeniden kontrol edin.',
  'isp.err.picks': 'Ülke kodu, AS numarası ya da yer adı değil: {entry}',
  'isp.err.picksMany': 'En fazla {max} yer seçin; yer sayısı ölçüm sayısını geçmesin.',
  'isp.err.probes': '1–50 ölçüm seçin.',
  'isp.privacy': 'Globalping (jsDelivr) {name} adını, kayıt türünü ve seçtiğiniz yerleri alır; her ölçüm noktası kendi çözümleyicisini sorduğundan bu İSS’lerin çözümleyicileri de soruyu alır. Başka hiçbir şey gönderilmez.',
  'isp.measurement': 'Ölçüm {id}',
  'isp.title': 'İSS çözümleyicileri',
  'isp.col.location': 'Konum',
  'isp.col.isp': 'İSS / ağ',
  'isp.col.resolver': 'Çözümleyici',
  'isp.col.ttl': 'Kalan TTL',
  'isp.resolver.private': 'İSS iç ağı',
  'isp.resolver.privateTitle': 'Özel adres: İSS’nin kendi çözümleyicisi ya da önündeki ev yönlendiricisi (Globalping özel adresleri göstermez).',
  'isp.resolver.public': 'Genel çözümleyici, İSS’ninki değil',
  'isp.resolver.unknown': 'Bildirilmedi',
  'isp.datacenter': 'veri merkezi',
  'isp.pendingProbe': 'Ölçüm noktası bekleniyor',
  'isp.ttl.until': '{time} saatine kadar',
  'isp.ttl.title': 'Bu çözümleyici yanıtı {human} daha önbellekte tutar ({time} saatine kadar); daha yeni bir yanıt kullanıcılarına bundan sonra ulaşır.',
  'isp.sum.staleTitle': '{count} İSS çözümleyicisinde eskimiş yanıt',
  'isp.sum.ref.agree': 'Genel çözümleyiciler ve konumlar aynı yanıtı veriyor.',
  'isp.sum.ref.by-design': 'Genel çözümleyiciler ve konumlar yalnızca tasarım gereği farklı (CDN / GeoDNS uç sunucuları).',
  'isp.sum.ref.geo': 'Genel çözümleyiciler aynı; konumlar yalnızca GeoDNS yüzünden farklı.',
  'isp.sum.staleWhy': 'Bu İSS çözümleyicileri hiçbirinin vermediği bir yanıtı hâlâ veriyor: büyük olasılıkla önbellekte kalmış, süresi dolunca kendiliğinden kaybolacak eski bir yanıt. Sonra da sürerse İSS adı bilerek değiştiriyordur (bazıları adları kendi adresleriyle engeller).',
  'isp.sum.line': '{isps}: {answer} — {ttl} içinde sona erer ({time} saatine kadar).',
  'isp.sum.lineNoTtl': '{isps}: {answer}.',
  'isp.sum.unsure': '{isps}: hiçbir genel çözümleyicinin ya da konumun vermediği bir yanıt — bölgelerine özgü GeoDNS ya da önbellekte kalmış eski bir yanıt (öyleyse {ttl} içinde sona erer).',
  'isp.sum.lingering': '{isps}: hiçbir genel çözümleyicinin ya da konumun vermediği bir yanıt; büyük olasılıkla önbellekte kalmış eski bir yanıt ({ttl} içinde sona erer).',
  'isp.sum.nxdomain': 'NXDOMAIN (önbellekte: ad yoktu)',
  'isp.sum.nodata': '{type} kaydı yok (önbellekteki boş yanıt)',
  'isp.ttlNone': 'TTL yok'
});

/** Panels with a run going (the workspace switch names it). */
const runningPanels = new Set();
registerRunning('isp.running', () => runningPanels.size > 0);

/** "25 min" / "2 h" for a TTL in seconds (as the Global DNS tables word it). */
export function humanTtl(s) {
  if (!Number.isFinite(s)) return t('isp.ttlNone');
  if (s < 120) return t('time.s', { n: formatNumber(s) });
  if (s < 7200) return `${formatNumber(Math.round(s / 60))} min`;
  if (s < 172800) return `${formatNumber(Math.round(s / 3600))} h`;
  return `${formatNumber(Math.round(s / 86400))} d`;
}

const clock = (iso) => formatDate(iso, { hour: '2-digit', minute: '2-digit' });

/**
 * The name of an ISP row's source: its network, then its city and country code.
 * @param {{ isp?: object|null, key: string }} row
 * @returns {string}
 */
export function ispLabel(row) {
  const p = (row && row.isp) || {};
  const net = p.network || (p.asn ? `AS${p.asn}` : null);
  const where = [p.city, p.country].filter(Boolean).join(', ');
  return net ? (where ? `${net} (${where})` : net) : (where || String(row && row.key));
}

/**
 * Mount the ISP resolvers panel into `el` (the host view's section body).
 * @param {HTMLElement} el
 * @param {{ ctx: object, check: () => ({ name: string, type: string, busy: boolean }|null), rows: () => object[],
 *   setRows: (rows: object[]) => void, apply: (item: object) => void,
 *   cells: { group: Function, answer: Function, status: Function, ad: Function, latency: Function, rowClass: Function,
 *   groupSort: Function, answerText: Function } }} host
 * @returns {{ refresh: () => void, setFilter: (fn: Function|null) => void, reset: () => void, label: (row: object) => string,
 *   staleSummary: (verdict: object, opts: object) => { title: string, body: string[], lines: string[] },
 *   note: (verdict: object, opts: object) => string|null, snapshot: () => object, teardown: () => void }}
 *   `staleSummary`: the words of the 'stale' state for the host's result header (its title and what it
 *   rests on) and its findings list (one line per ISP answer that looks cached)
 */
export function mountIspPanel(el, host, { restored = null } = {}) {
  const { ctx } = host;
  const P = {
    status: restored && restored.status ? restored.status : 'idle', // idle | gate | running | done | stopped | partial | quota | unreachable | failed | no-probes
    error: null, resetAt: null, controller: null, run: restored && Number.isInteger(restored.run) ? restored.run : 0,
    id: restored && restored.id ? restored.id : null, probes: restored && restored.probes ? restored.probes : 0
  };

  const probesField = select({
    label: t('isp.probes'),
    options: ISP_PROBE_CHOICES.map((n) => ({ value: String(n), label: t('isp.probeCount', { count: n }) })),
    value: String(restored && restored.choice ? restored.choice : ISP_DEFAULT_PROBES),
    className: 'glb-isp-probes'
  });
  probesField.input.dataset.role = 'isp-probes';
  const placesField = textInput({
    label: t('isp.places'), value: restored && restored.places ? restored.places : '', placeholder: t('isp.placesPlaceholder'), hint: t('isp.placesHint'),
    className: 'glb-isp-places', attrs: { 'data-role': 'isp-places' }, onEnter: () => start()
  });
  const eyeballField = checkbox({ label: t('isp.eyeball'), hint: t('isp.eyeballHint'), checked: restored ? restored.eyeball !== false : true });
  eyeballField.input.dataset.role = 'isp-eyeball';
  const runBtn = Button({ label: t('isp.run'), icon: 'globe', variant: 'primary', dataset: { action: 'isp-run' }, onClick: () => start() });
  const stopBtn = Button({ label: t('common.stop'), icon: 'stop', variant: 'secondary', dataset: { action: 'isp-stop' }, onClick: () => stop() });
  stopBtn.hidden = true;
  const quotaEl = h('p', { class: 'muted text-sm glb-isp-quota', dataset: { role: 'isp-quota' } });
  const statusEl = h('div', { class: 'glb-isp-status', attrs: { 'aria-live': 'polite' }, dataset: { role: 'isp-status' } });

  const ttlCell = (r) => {
    if (r.pending || !Number.isInteger(r.ttl)) return null;
    const time = r.expiresAt ? clock(r.expiresAt) : null;
    return h('div', { class: 'glb-isp-ttl', title: time ? t('isp.ttl.title', { human: humanTtl(r.ttl), time }) : null },
      h('span', { class: 'num' }, formatNumber(r.ttl)),
      time ? h('span', { class: 'muted text-xs' }, t('isp.ttl.until', { time })) : null);
  };
  const resolverCell = (r) => {
    const res = (r.isp && r.isp.resolver) || {};
    if (r.pending && !res.address && !res.private) return null;
    if (res.private && !res.address) return Badge(t('isp.resolver.private'), { variant: 'neutral', icon: 'network', title: t('isp.resolver.privateTitle') });
    if (res.address) {
      return h('div', { class: 'glb-isp-res' }, h('span', { class: 'mono' }, res.address),
        res.publicName ? h('span', { class: 'muted text-xs', title: t('isp.resolver.public') }, `${res.publicName} · ${t('isp.resolver.public')}`) : null);
    }
    return h('span', { class: 'muted text-xs' }, t('isp.resolver.unknown'));
  };
  const table = DataTable({
    caption: t('isp.title'),
    rowKey: (r) => r.key,
    rowClass: host.cells.rowClass,
    dense: true,
    maxHeight: null,
    export: { filename: 'global-dns-isp-resolvers', subject: '' },
    columns: [
      { key: 'group', label: t('glb.col.group'), sortable: true, sortValue: host.cells.groupSort, width: '4rem', render: host.cells.group },
      {
        key: 'location', label: t('isp.col.location'), sortable: true,
        sortValue: (r) => `${r.isp?.country || '~'} ${r.isp?.city || ''}`,
        exportValue: (r) => [r.isp?.city, r.isp?.country].filter(Boolean).join(', '),
        render: (r) => (r.isp && r.isp.country
          ? h('span', { class: 'glb-loc-geo' }, Flag(r.isp.country, { className: 'glb-flag', title: formatRegion(r.isp.country) }), ' ',
            [r.isp.city, formatRegion(r.isp.country)].filter(Boolean).join(', '))
          : h('span', { class: 'muted text-xs' }, t('isp.pendingProbe')))
      },
      {
        key: 'isp', label: t('isp.col.isp'), sortable: true, sortValue: (r) => r.isp?.network || '',
        exportValue: (r) => [r.isp?.network, r.isp?.asn ? `AS${r.isp.asn}` : null].filter(Boolean).join(' '),
        render: (r) => (r.isp && (r.isp.network || r.isp.asn) ? h('div', { class: 'glb-isp' },
          h('span', null, r.isp.network || ''),
          h('span', { class: 'cluster text-xs' }, r.isp.asn ? h('span', { class: 'muted mono' }, `AS${r.isp.asn}`) : null,
            r.isp.kind === 'datacenter' ? Badge(t('isp.datacenter'), { variant: 'neutral', title: t('isp.eyeballHint') }) : null)) : null)
      },
      {
        key: 'resolver', label: t('isp.col.resolver'), sortable: true, render: resolverCell,
        sortValue: (r) => r.isp?.resolver?.address || (r.isp?.resolver?.private ? '~private' : ''),
        exportValue: (r) => r.isp?.resolver?.address || (r.isp?.resolver?.private ? 'private' : '')
      },
      { key: 'ttl', label: t('isp.col.ttl'), sortable: true, align: 'end', sortValue: (r) => (r.pending ? null : r.ttl), exportValue: (r) => r.ttl ?? '', render: ttlCell },
      { key: 'status', label: t('glb.col.status'), sortable: true, sortValue: (r) => (r.pending ? null : r.response?.rcode || 'ERROR'), render: host.cells.status, exportValue: (r) => (r.pending ? '' : r.response?.rcode || 'ERROR') },
      { key: 'ad', label: t('glb.col.dnssec'), sortable: true, sortValue: (r) => (r.pending || !r.response?.ok ? null : r.response.ad), render: host.cells.ad, exportValue: (r) => (r.response?.ad ? 'AD' : '') },
      { key: 'latency', label: t('glb.col.latency'), sortable: true, align: 'end', render: host.cells.latency, exportValue: (r) => r.response?.elapsedMs ?? '' },
      { key: 'answer', label: t('glb.col.answer'), render: host.cells.answer, searchValue: host.cells.answerText, exportValue: host.cells.answerText }
    ]
  });
  const tableWrap = h('div', { class: 'glb-isp-table', hidden: true }, table.el || table);

  // The tab's own run (docs/DESIGN.md §5.5: a panel that sends something has its run row and its
  // privacy note): what Globalping and the ISPs' resolvers receive, next to Ask.
  const privacyText = h('span', { class: 'glb-isp-privacy-text' });
  el.append(h('div', { class: 'stack glb-isp-panel', dataset: { role: 'isp-panel', shortcutScope: 'isp' } },
    h('p', { class: 'section-desc' }, t('isp.intro')),
    h('div', { class: 'glb-isp-form' }, probesField.el, placesField.el, h('div', { class: 'glb-buttons' }, runBtn, stopBtn)),
    eyeballField.el,
    PrivacyNote({ text: privacyText, className: 'glb-isp-privacy' }),
    quotaEl,
    statusEl,
    tableWrap));

  const running = () => !!P.controller;
  const answered = () => host.rows().filter((r) => !r.pending && !(r.values && r.values.length === 1 && r.values[0] === 'ERROR')).length;

  function renderQuota() {
    const q = liveQuota(sharedQuota());
    quotaEl.textContent = q && Number.isFinite(q.remaining)
      ? t('isp.quota', { remaining: formatNumber(Math.max(0, q.remaining)), limit: formatNumber(q.limit ?? GP_LIMITS.anonymousPerHour), when: whenText(q.resetAt) })
      : t('gp.quotaUnknown', { limit: formatNumber(GP_LIMITS.anonymousPerHour) });
  }

  function renderStatus() {
    clear(statusEl);
    const chk = host.check();
    privacyText.textContent = t('isp.privacy', { name: chk ? chk.name : '—' });
    runBtn.hidden = running();
    stopBtn.hidden = !running();
    setButtonBusy(runBtn, P.status === 'gate');
    runBtn.disabled = !chk || chk.busy;
    probesField.input.disabled = running();
    placesField.input.readOnly = running();
    eyeballField.input.disabled = running();
    const total = host.rows().length || P.probes;
    let node = null;
    const link = P.id && measurementUrl(P.id)
      ? h('a', { href: measurementUrl(P.id), target: '_blank', rel: 'noopener noreferrer', class: 'text-sm', dataset: { role: 'isp-measurement' } }, t('isp.measurement', { id: P.id }))
      : null;
    const retry = Button({ label: t('common.retry'), icon: 'refresh', size: 'sm', dataset: { action: 'isp-retry' }, onClick: () => start() });
    if (!chk) node = h('p', { class: 'muted text-sm' }, t('isp.noCheck'));
    else if (chk.busy && !running()) node = h('p', { class: 'muted text-sm' }, t('isp.waitCheck'));
    else if (P.status === 'gate') node = Alert({ variant: 'info', compact: true, message: t('isp.status.gate') });
    else if (P.status === 'running') node = Alert({ variant: 'info', icon: 'activity', compact: true, message: t('isp.status.running', { count: total }) });
    else if (P.status === 'done') node = Alert({ variant: 'ok', compact: true, message: t('isp.status.done', { answered: formatNumber(answered()), count: formatNumber(total) }), children: link });
    else if (P.status === 'stopped') node = Alert({ variant: 'info', compact: true, message: t('isp.status.stopped', { answered: formatNumber(answered()), count: formatNumber(P.probes) }), children: link });
    else if (P.status === 'partial') node = Alert({ variant: 'warn', compact: true, message: t('isp.status.partial', { answered: formatNumber(answered()) }), children: link, actions: [retry] });
    else if (P.status === 'quota') node = Alert({ variant: 'warn', compact: true, message: t('isp.status.quota', { when: whenText(P.resetAt) }) });
    else if (P.status === 'unreachable') node = Alert({ variant: 'error', compact: true, message: t('isp.status.unreachable'), actions: [retry] });
    else if (P.status === 'no-probes') node = Alert({ variant: 'warn', compact: true, message: t('isp.status.noProbes') });
    else if (P.status === 'failed') node = Alert({ variant: 'error', compact: true, message: t('isp.status.failed', { error: errorText(P.error) }), children: link, actions: [retry] });
    if (node) {
      node.dataset.ispStatus = P.status;
      statusEl.append(node);
    }
    renderQuota();
  }

  function errorText(err) {
    const kind = errorKind(err);
    if (err && typeof err.message === 'string' && err.message) return err.message;
    return kind ? t(`error.kind.${kind}`) : String(err);
  }

  /** Refuse a plan with the reason at the field (nothing is sent). */
  function planError(plan, chk) {
    const msg = plan.error === 'picks' ? (plan.detail ? t('isp.err.picks', { entry: plan.detail }) : t('isp.err.picksMany', { max: ISP_MAX_PICKS }))
      : plan.error === 'internal' ? t('isp.err.internal', { name: chk.name })
        : plan.error === 'type' ? t('isp.err.type', { type: chk.type })
          : t(`isp.err.${plan.error}`);
    if (plan.error === 'picks') {
      placesField.setError(msg);
      placesField.focus();
    } else {
      clear(statusEl);
      const node = Alert({ variant: 'warn', compact: true, message: msg });
      node.dataset.ispStatus = `plan-${plan.error}`;
      statusEl.append(node);
    }
    announce(msg);
  }

  /** Fold a (partial) measurement into the rows: probe details, then each answer once. */
  function applyMeasurement(m, run, chk) {
    const { rows } = mapIspResults(m, { name: chk.name, type: chk.type, run });
    if (rows.length && rows.length !== host.rows().length) setRows(pendingIspRows(rows.length, run));
    const byKey = new Map(host.rows().map((r) => [r.key, r]));
    for (const r of rows) {
      const row = byKey.get(r.key);
      if (!row) continue;
      row.isp = r.isp;
      row.status = r.status;
      if (!r.pending && row.pending) {
        row.ttl = r.ttl;
        row.expiresAt = r.expiresAt;
        host.apply({ key: r.key, response: r.response, values: r.values, filtered: false, addresses: r.addresses, scopePrefix: null });
      }
    }
    table.refresh();
  }

  function setRows(rows) {
    host.setRows(rows);
    table.setRows(host.rows());
    tableWrap.hidden = !rows.length;
  }

  /** Drop the probes that never answered (a stopped or timed-out run): their rows would spin forever. */
  function dropPending() {
    const left = host.rows().filter((r) => !r.pending);
    if (left.length !== host.rows().length) setRows(left);
  }

  async function start() {
    const chk = host.check();
    if (!chk || chk.busy || running() || !ctx.requireOnline()) return;
    placesField.setError(null);
    const { picks, invalid } = parsePicks(placesField.value);
    const choice = Number(probesField.value) || ISP_DEFAULT_PROBES;
    const plan = planIspMeasurement({ name: chk.name, type: chk.type, probes: choice, picks, invalid, eyeball: eyeballField.checked });
    if (!plan.ok) {
      planError(plan, chk);
      return;
    }
    const ac = new AbortController();
    const signal = mergeSignals(ctx.signal, ac.signal);
    const prev = { status: P.status, id: P.id, probes: P.probes };
    Object.assign(P, { controller: ac, status: 'gate', error: null });
    runningPanels.add(P);
    renderStatus();
    let created = null;
    try {
      const gate = await gateProbes(ctx, {
        purpose: ISP_PURPOSE, probes: plan.probes, signal, confirmAbove: ISP_CONFIRM_ABOVE, className: 'isp-confirm',
        privacy: t('isp.privacy', { name: chk.name })
      });
      if (P.controller !== ac) return;
      if (gate.status === 'cancelled') {
        Object.assign(P, prev);
        return;
      }
      if (gate.status === 'quota') {
        Object.assign(P, { status: 'quota', resetAt: gate.resetAt });
        announce(t('isp.status.quota', { when: whenText(gate.resetAt) }));
        return;
      }
      if (gate.status === 'unreachable') {
        Object.assign(P, { status: 'unreachable', error: gate.error });
        return;
      }
      P.run += 1;
      const run = P.run;
      Object.assign(P, { status: 'running', id: null, probes: plan.probes });
      setRows(pendingIspRows(plan.probes, run));
      renderStatus();
      created = await gate.client.create(plan.body, { signal });
      noteQuota(created.quota);
      P.id = created.id;
      if (Number.isInteger(created.probesCount) && created.probesCount > 0 && created.probesCount !== plan.probes) {
        P.probes = created.probesCount;
        setRows(pendingIspRows(created.probesCount, run));
      }
      renderStatus();
      const deadlineAt = Date.now() + ((plan.body.timeout || GP_LIMITS.maxTimeoutS) + GP_LIMITS.clientSlackS) * 1000;
      const final = await gate.client.poll(created.id, {
        signal, deadlineAt, onUpdate: (m) => { if (P.controller === ac) applyMeasurement(m, run, chk); }
      });
      if (P.controller !== ac) return;
      applyMeasurement(final, run, chk);
      dropPending();
      P.status = 'done';
      announce(t('isp.status.done', { answered: formatNumber(answered()), count: formatNumber(host.rows().length) }));
    } catch (err) {
      if (P.controller !== ac) return;
      if (errorKind(err) === 'abort' || ac.signal.aborted) {
        dropPending();
        P.status = created ? 'stopped' : prev.status;
      } else if (err && err.code === 'deadline') {
        dropPending();
        P.status = 'partial';
      } else {
        dropPending();
        P.status = err && err.code === 'no-probes' ? 'no-probes' : 'failed';
        P.error = err;
      }
    } finally {
      if (P.controller === ac) {
        P.controller = null;
        runningPanels.delete(P);
        if (!ctx.signal.aborted) renderStatus();
      }
    }
  }

  function stop() {
    if (P.controller) P.controller.abort();
  }

  /** Who gave a verdict's ISP-only answer, and what it is: "a (x), b (y): 192.0.2.10". */
  function staleParts(entries, verdict, shortList) {
    const rows = host.rows();
    return entries.map((s) => {
      const members = rows.filter((r) => s.members.includes(r.key));
      const { plain } = splitChain(s.key.split('\n'));
      const answer = s.status === 'nxdomain' ? t('isp.sum.nxdomain') : s.status === 'nodata' ? t('isp.sum.nodata', { type: verdict.type })
        : shortList(plain.length ? plain : s.key.split('\n'));
      const { ttl, expiresAt } = longestTtl(members);
      return { isps: shortList(members.map(ispLabel), 3, '; '), answer, ttl, expiresAt };
    });
  }

  const api = {
    refresh() {
      table.refresh();
      renderStatus();
    },
    setFilter(fn) {
      table.setFilter(fn);
    },
    /** A new check: the ISP rows belonged to the one before (the host dropped them). */
    reset() {
      if (P.controller) P.controller.abort();
      P.controller = null;
      runningPanels.delete(P);
      Object.assign(P, { status: 'idle', error: null, id: null, probes: 0 });
      table.setRows([]);
      tableWrap.hidden = true;
      renderStatus();
    },
    label: ispLabel,
    /**
     * The summary of the 'stale' state: what the public sources say, the ISP answers that look
     * cached, with the longest TTL each still has.
     */
    staleSummary(verdict, { shortList }) {
      const parts = staleParts(verdict.isp.stale, verdict, shortList);
      const count = verdict.isp.stale.reduce((n, s) => n + s.members.length, 0);
      const ref = ['agree', 'by-design', 'geo'].includes(verdict.isp.reference) ? t(`isp.sum.ref.${verdict.isp.reference}`) : null;
      return {
        title: t('isp.sum.staleTitle', { count }),
        body: [ref, t('isp.sum.staleWhy')].filter(Boolean),
        lines: parts.map((p) => (p.ttl === null ? t('isp.sum.lineNoTtl', p)
          : t('isp.sum.line', { ...p, ttl: humanTtl(p.ttl), time: p.expiresAt ? clock(p.expiresAt) : '—' })))
      };
    },
    /** A sentence for the other states: ISP-only answers that are GeoDNS or cached (unsure), or cached next to a fault. */
    note(verdict, { shortList }) {
      const isp = verdict && verdict.isp;
      if (!isp || !isp.stale.length || verdict.state === 'stale') return null;
      return staleParts(isp.stale, verdict, shortList)
        .map((p) => t(isp.unsure ? 'isp.sum.unsure' : 'isp.sum.lingering', { isps: p.isps, ttl: humanTtl(p.ttl) })).join(' ');
    },
    snapshot() {
      return { status: running() ? 'stopped' : P.status, run: P.run, id: P.id, probes: P.probes, choice: Number(probesField.value), places: placesField.value, eyeball: eyeballField.checked };
    },
    teardown() {
      if (P.controller) P.controller.abort();
      runningPanels.delete(P);
    }
  };
  if (host.rows().length) {
    table.setRows(host.rows());
    tableWrap.hidden = false;
  }
  renderStatus();
  return api;
}
