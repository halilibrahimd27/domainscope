/**
 * ui/ip-enrich-panel.js — IP Intel's "Routing, RPKI and abuse contact" panel in a row's details
 * (lib/ipenrich.js): the announced prefix and origin AS, the RPKI validity with the ROAs, routing
 * sanity flags, the abuse contact, the origin's PeeringDB record, and a clickable CIDR breadcrumb
 * (/8 › /16 › /24 › announced prefix › address) listing the user's servers inside each level.
 *
 * Loaded on first use by views/ip.js (a row's details opened). Nothing is sent before "Check
 * routing" is pressed, nor ever for an address that is not globally routable; the breadcrumb and
 * the server matching are local. A failed source says "⚠ n/a" with the reason, and Retry asks
 * only the failed sources again. The answers of a page's run are kept per address while the view
 * is mounted (the details re-render whenever their row does).
 */

import { h, clear, append } from './dom.js';
import { Badge, Button, CopyButton, ExternalLink, KeyValueList, TruncatedList, announce, setButtonBusy } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import {
  createIpEnrich, cidrLevels, serversInLevels, knownFromInfo, peeringdbTypeCode, ENRICH_SOURCES, PEERINGDB_TYPE_CODES,
  RPKI_STATUSES, ROUTING_FLAGS
} from '../lib/ipenrich.js';
import { isGloballyRoutable, normalizeIP } from '../lib/ip.js';
import { sourceStatus } from '../lib/sourcestatus.js';
import { NaMark, RetryButton, setRetryBusy } from './source-status.js';

registerStrings('en', {
  'ipe.title': 'Routing, RPKI and abuse contact',
  'ipe.check': 'Check routing',
  'ipe.checkTitle': 'Ask RIPEstat for the route, its RPKI validity and the abuse contact, and PeeringDB for the network',
  'ipe.checkFor': 'Check routing of {ip}',
  'ipe.privacy': 'Sends this address, its announced prefix and origin AS to RIPEstat, and the AS number to PeeringDB. Your server list never leaves the browser.',
  'ipe.notSent': 'Nothing has been sent yet.',
  'ipe.checking': 'Checking…',
  'ipe.done': 'Routing of {ip} checked.',
  'ipe.notRoutable': 'Not a globally routable address (private, reserved or documentation space): nothing is looked up or sent for it.',
  'ipe.prefix': 'Announced prefix',
  'ipe.originAs': 'Origin AS',
  'ipe.notAnnounced': 'Not announced — no route on the Internet covers this address.',
  'ipe.rpki': 'RPKI (route origin)',
  'ipe.rpki.valid': 'Valid',
  'ipe.rpki.invalid-asn': 'Invalid: wrong origin',
  'ipe.rpki.invalid-length': 'Invalid: prefix too long',
  'ipe.rpki.not-found': 'Not found',
  'ipe.rpkiDesc.valid': 'A ROA allows AS{asn} to announce {prefix}.',
  'ipe.rpkiDesc.invalid-asn': 'The ROAs covering {prefix} name other origin ASes than AS{asn}: networks that validate RPKI drop this route.',
  'ipe.rpkiDesc.invalid-length': 'A ROA allows AS{asn}, but not a prefix as long as {prefix}: networks that validate RPKI drop this route.',
  'ipe.rpkiDesc.not-found': 'No ROA covers {prefix}: the route is accepted, but nothing protects it against a hijack. The address holder can create a ROA at its RIR.',
  'ipe.roa': 'ROA {prefix} · max length /{max} · AS{asn}',
  'ipe.roaNoMax': 'ROA {prefix} · AS{asn}',
  'ipe.routing': 'Routing',
  'ipe.routingOk': 'One origin, seen by {seeing} of {total} RIS peers',
  'ipe.routingOne': 'One origin',
  'ipe.routingSeen': 'Seen by {seeing} of {total} RIS peers',
  'ipe.flag.not-announced': 'Not announced',
  'ipe.flag.moas': 'Several origin ASes',
  'ipe.flag.more-specifics': 'More-specific routes',
  'ipe.flag.low-visibility': 'Low visibility',
  'ipe.flagDesc.not-announced': 'RIS sees no origin for this prefix today.',
  'ipe.flagDesc.moas': 'Announced by {list} (MOAS): anycast or a network with several upstreams — or a hijack.',
  'ipe.flagDesc.more-specifics': {
    one: '{count} longer prefix inside it is announced too, and traffic to its addresses follows that route: traffic engineering, DDoS protection — or a hijack.',
    other: '{count} longer prefixes inside it are announced too, and traffic to their addresses follows those routes: traffic engineering, DDoS protection — or a hijack.'
  },
  'ipe.flagDesc.low-visibility': 'Only {seeing} of {total} RIS peers see it: parts of the Internet may not reach it.',
  'ipe.firstSeen': 'first seen {date}',
  'ipe.abuse': 'Abuse contact',
  'ipe.abuseNone': 'No abuse contact is registered for this address.',
  'ipe.abuseRir': 'registered at {rir}',
  'ipe.pdb': 'PeeringDB',
  'ipe.pdbNone': 'AS{asn}: no PeeringDB record',
  'ipe.pdbOpen': 'PeeringDB record of AS{asn}',
  'ipe.pdbPolicy': 'peering: {policy}',
  'ipe.pdbScope': 'scope: {scope}',
  'ipe.pdbType.nsp': 'NSP (transit)',
  'ipe.pdbType.content': 'Content',
  'ipe.pdbType.isp': 'Cable/DSL/ISP',
  'ipe.pdbType.enterprise': 'Enterprise',
  'ipe.pdbType.education': 'Educational/Research',
  'ipe.pdbType.non-profit': 'Non-profit',
  'ipe.pdbType.route-server': 'Route server',
  'ipe.pdbType.network-services': 'Network services',
  'ipe.pdbType.route-collector': 'Route collector',
  'ipe.pdbType.government': 'Government',
  'ipe.pdbType.not-disclosed': 'Not disclosed',
  'ipe.website': 'Website',
  'ipe.crumbs': 'Address ranges',
  'ipe.crumbCount': '{cidr}: {count} of your servers',
  'ipe.crumbAnnounced': 'announced prefix',
  'ipe.serversIn': 'Your servers in {cidr}',
  'ipe.serversNone': 'None of your servers is in {cidr}.',
  'ipe.serversNoInventory': 'No server list in this workspace: save one under Servers to see which of your servers share these ranges.',
  'ipe.serversHere': 'this address'
});

registerStrings('tr', {
  'ipe.title': 'Yönlendirme, RPKI ve abuse iletişimi',
  'ipe.check': 'Yönlendirmeyi kontrol et',
  'ipe.checkTitle': 'Rota, RPKI geçerliliği ve abuse iletişim adresi RIPEstat’a, ağ bilgisi PeeringDB’ye sorulur',
  'ipe.checkFor': 'Yönlendirmeyi kontrol et: {ip}',
  'ipe.privacy': 'Bu adres, duyurulan öneki ve kaynak AS’i RIPEstat’a, AS numarası PeeringDB’ye gönderilir. Sunucu listeniz tarayıcıdan çıkmaz.',
  'ipe.notSent': 'Henüz hiçbir şey gönderilmedi.',
  'ipe.checking': 'Kontrol ediliyor…',
  'ipe.done': '{ip} adresinin yönlendirmesi kontrol edildi.',
  'ipe.notRoutable': 'İnternet’te yönlendirilebilen bir adres değil (özel, ayrılmış ya da dokümantasyon alanı): bu adres için hiçbir sorgu yapılmaz, hiçbir şey gönderilmez.',
  'ipe.prefix': 'Duyurulan önek',
  'ipe.originAs': 'Kaynak AS',
  'ipe.notAnnounced': 'Duyurulmuyor — İnternet’te bu adresi kapsayan bir rota yok.',
  'ipe.rpki': 'RPKI (rota kaynağı)',
  'ipe.rpki.valid': 'Geçerli',
  'ipe.rpki.invalid-asn': 'Geçersiz: yanlış kaynak',
  'ipe.rpki.invalid-length': 'Geçersiz: önek fazla uzun',
  'ipe.rpki.not-found': 'Bulunamadı',
  'ipe.rpkiDesc.valid': 'Bir ROA, {prefix} önekini duyurma iznini AS{asn} numaralı ağa veriyor.',
  'ipe.rpkiDesc.invalid-asn': '{prefix} önekini kapsayan ROA’lar AS{asn} dışındaki kaynak AS’leri gösteriyor: RPKI doğrulaması yapan ağlar bu rotayı düşürür.',
  'ipe.rpkiDesc.invalid-length': 'Bir ROA, AS{asn} numaralı ağa izin veriyor, ancak {prefix} kadar uzun bir öneke değil: RPKI doğrulaması yapan ağlar bu rotayı düşürür.',
  'ipe.rpkiDesc.not-found': '{prefix} önekini kapsayan bir ROA yok: rota kabul edilir, ancak ele geçirilmeye (hijack) karşı korunmaz. Adres sahibi, bağlı olduğu RIR’de bir ROA oluşturabilir.',
  'ipe.roa': 'ROA {prefix} · en fazla /{max} · AS{asn}',
  'ipe.roaNoMax': 'ROA {prefix} · AS{asn}',
  'ipe.routing': 'Yönlendirme',
  'ipe.routingOk': 'Tek kaynak; {total} RIS eşinden {seeing} tanesi görüyor',
  'ipe.routingOne': 'Tek kaynak',
  'ipe.routingSeen': '{total} RIS eşinden {seeing} tanesi görüyor',
  'ipe.flag.not-announced': 'Duyurulmuyor',
  'ipe.flag.moas': 'Birden fazla kaynak AS',
  'ipe.flag.more-specifics': 'Daha özel rotalar',
  'ipe.flag.low-visibility': 'Düşük görünürlük',
  'ipe.flagDesc.not-announced': 'RIS bugün bu önek için hiçbir kaynak görmüyor.',
  'ipe.flagDesc.moas': 'Duyuran ağlar: {list} (MOAS) — anycast ya da birden fazla üst bağlantısı olan bir ağ; ya da bir ele geçirme (hijack).',
  'ipe.flagDesc.more-specifics': '{count} daha uzun önek de duyuruluyor ve bu adreslere giden trafik o rotaları izliyor: trafik mühendisliği, DDoS koruması — ya da bir ele geçirme (hijack).',
  'ipe.flagDesc.low-visibility': '{total} RIS eşinden yalnızca {seeing} tanesi görüyor: İnternet’in bazı kısımları bu öneke ulaşamayabilir.',
  'ipe.firstSeen': 'ilk görülme: {date}',
  'ipe.abuse': 'Abuse iletişimi',
  'ipe.abuseNone': 'Bu adres için kayıtlı bir abuse iletişim adresi yok.',
  'ipe.abuseRir': 'kayıt: {rir}',
  'ipe.pdb': 'PeeringDB',
  'ipe.pdbNone': 'AS{asn}: PeeringDB kaydı yok',
  'ipe.pdbOpen': 'AS{asn} PeeringDB kaydı',
  'ipe.pdbPolicy': 'eşleşme (peering): {policy}',
  'ipe.pdbScope': 'kapsam: {scope}',
  'ipe.pdbType.nsp': 'NSP (transit)',
  'ipe.pdbType.content': 'İçerik',
  'ipe.pdbType.isp': 'Kablo/DSL/İSS',
  'ipe.pdbType.enterprise': 'Kurumsal',
  'ipe.pdbType.education': 'Eğitim/Araştırma',
  'ipe.pdbType.non-profit': 'Kâr amacı gütmeyen',
  'ipe.pdbType.route-server': 'Route server',
  'ipe.pdbType.network-services': 'Ağ hizmetleri',
  'ipe.pdbType.route-collector': 'Route collector',
  'ipe.pdbType.government': 'Kamu',
  'ipe.pdbType.not-disclosed': 'Belirtilmemiş',
  'ipe.website': 'Web sitesi',
  'ipe.crumbs': 'Adres aralıkları',
  'ipe.crumbCount': '{cidr}: sunucularınızdan {count} tanesi',
  'ipe.crumbAnnounced': 'duyurulan önek',
  'ipe.serversIn': '{cidr} içindeki sunucularınız',
  'ipe.serversNone': 'Sunucularınızdan hiçbiri {cidr} içinde değil.',
  'ipe.serversNoInventory': 'Bu çalışma alanında sunucu listesi yok: hangi sunucularınızın bu aralıkları paylaştığını görmek için Sunucular’da bir liste kaydedin.',
  'ipe.serversHere': 'bu adres'
});

/**
 * Every key this module builds from a code (for the i18n coverage test).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...RPKI_STATUSES.flatMap((s) => [`ipe.rpki.${s}`, `ipe.rpkiDesc.${s}`]),
    ...ROUTING_FLAGS.flatMap((f) => [`ipe.flag.${f}`, `ipe.flagDesc.${f}`]),
    ...PEERINGDB_TYPE_CODES.map((c) => `ipe.pdbType.${c}`),
    ...ENRICH_SOURCES.map((s) => `srcst.source.${s}`)
  ];
}

/** Badge variants of the RPKI statuses. */
const RPKI_VARIANTS = Object.freeze({ valid: 'ok', 'invalid-asn': 'error', 'invalid-length': 'error', 'not-found': 'warn' });
const RPKI_ICONS = Object.freeze({ valid: 'check-circle', 'invalid-asn': 'x-circle', 'invalid-length': 'x-circle', 'not-found': 'alert' });
/** Servers listed per breadcrumb level before "+N more". */
const MAX_SERVERS = 50;

/** The service (its caches outlive a mount, as IP Intel's own lookups do). */
let service = null;
const getService = () => service || (service = createIpEnrich());

/** Per view mount (its ctx): the panel state of each address. */
const mounts = new WeakMap();

function stateOf(ctx, ip) {
  let map = mounts.get(ctx);
  if (!map) {
    map = new Map();
    mounts.set(ctx, map);
  }
  let st = map.get(ip);
  if (!st) {
    // A result kept from an earlier look (another mount, a language switch) is shown at once.
    const kept = isGloballyRoutable(ip) ? getService().peek(ip) : null;
    st = { status: kept ? 'done' : 'idle', result: kept, level: null, slot: null, row: null };
    map.set(ip, st);
  }
  return st;
}

/**
 * Fill a row's details slot with the panel of its address. The slot may be replaced whenever the
 * row re-renders: the latest one gets the answers.
 * @param {HTMLElement} slot
 * @param {{ ip: string, info?: object|null }} row an IP Intel row
 * @param {import('../app.js').ViewContext} ctx
 */
export function mountIpEnrich(slot, row, ctx) {
  const ip = normalizeIP(row.ip);
  if (!ip) return;
  const st = stateOf(ctx, ip);
  st.slot = slot;
  st.row = row;
  render(st, ctx);
}

/** The sources whose failure the result records. */
const failedSources = (r) => [...new Set(r.errors.map((e) => e.source))];

/** "⚠ n/a" for the failures of `sources` (the failure that kept a section empty). */
function naOf(r, sources) {
  const statuses = r.errors.filter((e) => sources.includes(e.source)).map((e) => sourceStatus(e));
  return statuses.length ? NaMark(statuses, { className: 'ipe-na' }) : null;
}

async function check(st, ctx, { sources = null } = {}) {
  if (st.status === 'loading' || !ctx.requireOnline()) return;
  const ip = normalizeIP(st.row.ip);
  const prev = st.result;
  st.status = 'loading';
  render(st, ctx);
  try {
    const svc = getService();
    st.result = prev && sources
      ? await svc.retry(prev, { sources, signal: ctx.signal })
      : await svc.enrich(ip, { known: knownFromInfo(st.row.info), signal: ctx.signal, noCache: !!prev });
    st.status = 'done';
    announce(t('ipe.done', { ip }));
  } catch (err) {
    // Only an abort rejects: the view went away (or the page is leaving).
    st.status = prev ? 'done' : 'idle';
    st.result = prev;
    if (!(err && err.name === 'AbortError')) ctx.toast(`${t('error.title')}: ${err && err.message ? err.message : String(err)}`, { type: 'error' });
  }
  if (!ctx.signal.aborted) render(st, ctx);
}

function render(st, ctx) {
  const slot = st.slot;
  if (!slot) return;
  const ip = normalizeIP(st.row.ip);
  const routable = isGloballyRoutable(ip);
  const r = st.result;
  // Keyboard focus inside the panel moves to its new action (or its title) instead of dropping to the page.
  const doc = globalThis.document;
  const hadFocus = !!(doc && doc.activeElement && doc.activeElement !== slot && slot.contains(doc.activeElement));
  clear(slot);
  slot.dataset.state = routable ? st.status : 'not-routable';
  slot.dataset.ip = ip;

  let action = null;
  if (routable && !r) {
    action = Button({
      label: t('ipe.check'), icon: 'search', size: 'sm', variant: 'secondary', title: t('ipe.checkTitle'),
      ariaLabel: t('ipe.checkFor', { ip }), dataset: { action: 'enrich' }, onClick: () => check(st, ctx)
    });
    if (st.status === 'loading') setButtonBusy(action, true);
  } else if (r && r.errors.length) {
    action = RetryButton({ sources: failedSources(r), target: ip, onClick: () => check(st, ctx, { sources: failedSources(r) }), dataset: { enrichRetry: ip } });
    if (st.status === 'loading') setRetryBusy(action);
  }

  const body = [];
  if (!routable) body.push(h('p', { class: 'muted text-sm ipe-note' }, t('ipe.notRoutable')));
  else if (!r) body.push(h('p', { class: 'muted text-xs ipe-note' }, `${t('ipe.privacy')} ${st.status === 'loading' ? t('ipe.checking') : t('ipe.notSent')}`));
  else body.push(KeyValueList(resultItems(r), { className: 'ipe-facts' }));

  const prefix = r ? r.prefix : (knownFromInfo(st.row.info) || {}).prefix || null;
  const title = h('h4', { class: 'ipe-title', attrs: { tabindex: '-1' } }, t('ipe.title'));
  append(slot,
    h('div', { class: 'ipe-head' }, title, action),
    body,
    breadcrumb(st, ctx, ip, prefix));
  if (hadFocus) (action || title).focus({ preventScroll: true });
}

/** The facts of a result: prefix and origin, RPKI, routing, abuse contact, PeeringDB. */
function resultItems(r) {
  const items = [];
  const asLink = (asn) => ExternalLink(`https://stat.ripe.net/AS${asn}`, `AS${asn}`, { className: 'mono', icon: false });
  const join = (nodes) => nodes.flatMap((n, i) => (i ? [', ', n] : [n]));
  const networkNa = naOf(r, ['ripestat-network']);

  // Prefix and origin.
  if (r.prefix) {
    items.push({ key: t('ipe.prefix'), value: h('span', { class: 'ipe-prefix', dataset: { from: r.prefixFrom || '' } },
      ExternalLink(`https://stat.ripe.net/${r.prefix}`, r.prefix, { className: 'mono', icon: false }),
      r.origins.length ? h('span', { class: 'muted' }, ` · ${t('ipe.originAs')} `) : null,
      ...join(r.origins.map(asLink))) });
  } else if (networkNa) {
    items.push({ key: t('ipe.prefix'), value: networkNa });
  } else if (r.announced === false) {
    items.push({ key: t('ipe.prefix'), value: Badge(t('ipe.notAnnounced'), { variant: 'warn', icon: 'alert', className: 'ipe-unannounced' }) });
  }

  // The sources that need a prefix: n/a with the prefix's failure while it is missing.
  const needsPrefix = (sources) => naOf(r, sources) || (!r.prefix ? networkNa : null);

  // RPKI.
  if (r.rpki && r.rpki.length) {
    items.push({
      key: t('ipe.rpki'),
      value: h('div', { class: 'stack-sm ipe-rpki' }, r.rpki.map((x) => h('div', { class: 'ipe-rpki-row', dataset: { asn: x.asn, status: x.status } },
        h('div', { class: 'cluster' },
          Badge(t(`ipe.rpki.${x.status}`), { variant: RPKI_VARIANTS[x.status] || 'neutral', icon: RPKI_ICONS[x.status] || null }),
          r.rpki.length > 1 ? h('span', { class: 'mono text-xs' }, `AS${x.asn}`) : null),
        h('span', { class: 'muted text-xs' }, t(`ipe.rpkiDesc.${x.status}`, { asn: x.asn, prefix: r.prefix })),
        x.roas.length ? h('ul', { class: 'ipe-roas mono text-xs' }, x.roas.slice(0, 6).map((o) => h('li', null,
          o.maxLength !== null
            ? t('ipe.roa', { prefix: o.prefix || '?', max: o.maxLength, asn: o.origin ?? '?' })
            : t('ipe.roaNoMax', { prefix: o.prefix || '?', asn: o.origin ?? '?' })))) : null)),
      naOf(r, ['ripestat-rpki']))
    });
  } else if (needsPrefix(['ripestat-rpki'])) {
    items.push({ key: t('ipe.rpki'), value: needsPrefix(['ripestat-rpki']) });
  }

  // Routing.
  if (r.routing) {
    const g = r.routing;
    const seen = g.visibility ? { seeing: formatNumber(g.visibility.seeing), total: formatNumber(g.visibility.total) } : null;
    const clean = !g.flags.length;
    items.push({
      key: t('ipe.routing'),
      value: h('div', { class: 'stack-sm ipe-routing', dataset: { flags: g.flags.join(' ') } },
        clean
          ? h('span', null, Badge(seen ? t('ipe.routingOk', seen) : t('ipe.routingOne'), { variant: 'ok', icon: 'check-circle' }))
          : h('div', { class: 'cluster' }, g.flags.map((f) => Badge(t(`ipe.flag.${f}`), {
            variant: f === 'more-specifics' ? 'info' : 'warn', icon: 'alert', title: flagText(f, g), className: 'ipe-flag'
          }))),
        ...g.flags.map((f) => h('span', { class: 'muted text-xs ipe-flag-desc', dataset: { flag: f } }, flagText(f, g))),
        g.moreSpecifics.length ? TruncatedList(g.moreSpecifics.map((m) => (m.origin ? `${m.prefix} (AS${m.origin})` : m.prefix)), { max: 4 }) : null,
        h('span', { class: 'muted text-xs' }, [!clean && seen ? t('ipe.routingSeen', seen) : null,
          g.firstSeen ? t('ipe.firstSeen', { date: formatDate(utcDate(g.firstSeen)) }) : null].filter(Boolean).join(' · ')))
    });
  } else if (needsPrefix(['ripestat-routing'])) {
    items.push({ key: t('ipe.routing'), value: needsPrefix(['ripestat-routing']) });
  }

  // Abuse contact.
  if (r.abuse) {
    items.push({
      key: t('ipe.abuse'),
      value: r.abuse.contacts.length
        ? h('div', { class: 'cluster ipe-abuse' },
          ...r.abuse.contacts.map((c) => h('a', { class: 'mono', href: `mailto:${c}` }, c)),
          CopyButton(() => r.abuse.contacts.join(', '), { iconOnly: true }),
          r.abuse.rir ? h('span', { class: 'muted text-xs' }, t('ipe.abuseRir', { rir: r.abuse.rir })) : null)
        : h('span', { class: 'muted ipe-abuse' }, t('ipe.abuseNone'))
    });
  } else if (naOf(r, ['ripestat-abuse'])) {
    items.push({ key: t('ipe.abuse'), value: naOf(r, ['ripestat-abuse']) });
  }

  // PeeringDB.
  if (r.peeringdb && (r.peeringdb.length || naOf(r, ['peeringdb']))) {
    items.push({
      key: t('ipe.pdb'),
      value: h('div', { class: 'stack-sm ipe-pdb' }, r.peeringdb.map(({ asn, net }) => (net
        ? h('div', { class: 'ipe-pdb-net', dataset: { asn } },
          h('div', { class: 'cluster' },
            ExternalLink(`https://www.peeringdb.com/net/${net.id}`, net.name, { title: t('ipe.pdbOpen', { asn }) }),
            ...net.types.map((label) => Badge(peeringdbTypeCode(label) ? t(`ipe.pdbType.${peeringdbTypeCode(label)}`) : label, { variant: 'info' }))),
          h('span', { class: 'muted text-xs' }, [net.aka, net.policy ? t('ipe.pdbPolicy', { policy: net.policy }) : null,
            net.scope ? t('ipe.pdbScope', { scope: net.scope }) : null].filter(Boolean).join(' · ')),
          net.website ? ExternalLink(net.website, net.website.replace(/^https?:\/\//, '').replace(/\/$/, ''), { className: 'text-xs', title: t('ipe.website') }) : null)
        : h('span', { class: 'muted ipe-pdb-none', dataset: { asn } }, t('ipe.pdbNone', { asn })))),
      naOf(r, ['peeringdb']))
    });
  } else if (needsPrefix(['peeringdb'])) {
    items.push({ key: t('ipe.pdb'), value: needsPrefix(['peeringdb']) });
  }
  return items;
}

/** RIPEstat's times are UTC without a zone. */
function utcDate(s) {
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`);
}

function flagText(flag, g) {
  if (flag === 'moas') return t('ipe.flagDesc.moas', { list: g.origins.map((a) => `AS${a}`).join(', ') });
  if (flag === 'more-specifics') return t('ipe.flagDesc.more-specifics', { count: g.moreSpecificCount });
  if (flag === 'low-visibility' && g.visibility) return t('ipe.flagDesc.low-visibility', { seeing: formatNumber(g.visibility.seeing), total: formatNumber(g.visibility.total) });
  return t(`ipe.flagDesc.${flag}`);
}

/**
 * The CIDR breadcrumb: a button per level with the number of the user's servers inside it, and
 * the servers of the chosen level (by default the narrowest range that holds another server).
 */
function breadcrumb(st, ctx, ip, prefix) {
  const index = ctx.getInventoryIndex();
  const levels = serversInLevels(cidrLevels(ip, prefix), index, ip);
  if (!levels.length) return null;
  const blocks = levels.filter((l) => !l.address);
  const others = (l) => l.servers.some((s) => !s.here);
  const fallback = [...blocks].reverse().find(others) || blocks.find((l) => l.announced) || blocks[blocks.length - 1];
  const chosen = levels.find((l) => l.cidr === st.level) || fallback;
  const list = h('div', { class: 'ipe-servers', attrs: { 'aria-live': 'polite' } });
  const crumbs = [];
  const pick = (level) => {
    st.level = level.cidr;
    for (const b of crumbs) if (b.dataset.cidr) b.setAttribute('aria-pressed', String(b.dataset.cidr === level.cidr));
    showServers(list, level, index.size > 0);
  };
  levels.forEach((l, i) => {
    if (i) crumbs.push(h('span', { class: 'ipe-sep', attrs: { 'aria-hidden': 'true' } }, '›'));
    const btn = h('button', {
      type: 'button',
      class: ['ipe-crumb', { 'is-announced': l.announced, 'is-address': l.address }],
      attrs: { 'aria-pressed': String(l === chosen), 'aria-label': t('ipe.crumbCount', { cidr: l.address ? ip : l.cidr, count: l.servers.length }) },
      title: l.announced ? t('ipe.crumbAnnounced') : null,
      dataset: { cidr: l.cidr, count: l.servers.length },
      on: { click: () => pick(l) }
    }, h('span', { class: 'mono' }, l.address ? ip : l.cidr), h('span', { class: ['ipe-crumb-count', { 'is-zero': !l.servers.length }] }, formatNumber(l.servers.length)));
    crumbs.push(btn);
  });
  showServers(list, chosen, index.size > 0);
  return h('div', { class: 'ipe-crumbs-wrap' },
    h('nav', { class: 'ipe-crumbs', attrs: { 'aria-label': t('ipe.crumbs') } }, crumbs),
    list);
}

function showServers(list, level, haveInventory) {
  clear(list);
  list.dataset.cidr = level.cidr;
  if (!haveInventory) {
    list.append(h('p', { class: 'muted text-xs' }, t('ipe.serversNoInventory')));
    return;
  }
  const cidr = level.address ? level.cidr.replace(/\/\d+$/, '') : level.cidr;
  if (!level.servers.length) {
    list.append(h('p', { class: 'muted text-xs' }, t('ipe.serversNone', { cidr })));
    return;
  }
  append(list,
    h('p', { class: 'text-xs ipe-servers-title' }, t('ipe.serversIn', { cidr })),
    h('ul', { class: 'ipe-server-list' }, level.servers.slice(0, MAX_SERVERS).map((s) => h('li', { dataset: { server: s.id } },
      h('span', { class: 'ipe-server-name' }, s.name), ' ',
      h('span', { class: 'mono muted text-xs' }, s.ips.join(', ')),
      s.here ? [' ', Badge(t('ipe.serversHere'), { variant: 'direct', className: 'ipe-here' })] : null))),
    level.servers.length > MAX_SERVERS ? h('p', { class: 'muted text-xs' }, `+${formatNumber(level.servers.length - MAX_SERVERS)}`) : null);
}
