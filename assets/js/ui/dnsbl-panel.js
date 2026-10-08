/**
 * ui/dnsbl-panel.js — the "Blocklists" panel of an IP Intel row (views/ip.js loads it when a
 * row's details first open; lib/dnsbl.js does the asking).
 *
 * Nothing is sent before "Check blocklists": then the IP blocklists are asked about the address,
 * and the domain lists about the registrable domains of the host names it came from, through the
 * DoH resolver, a few lists at a time (lib/dnsbl.js `createDnsblChecker`, one per DNS client, so
 * every row shares its limit and its test-point verdicts). Stop, or leaving the view, aborts.
 *
 * Per list: listed (the decoded code, the delist page), not listed, cannot be checked here (a
 * refusal code, or a test point that did not come back listed: never "not listed"; the list's own
 * page and a `dig` command for a resolver of your own), failed (why, with Retry of the failed
 * lists) or not asked (an IPv4-only list and an IPv6 address). Private, reserved and documentation
 * addresses and internal names are never sent: the panel says so.
 *
 * The same element serves the same row object across the details row's re-renders; a finished
 * check is kept on the row (`row.dnsbl`), so a language re-mount shows it again.
 */

import { h, clear } from './dom.js';
import { Badge, Button, CopyButton, ExternalLink, announce } from './components.js';
import { t, registerStrings, formatNumber, formatDateTime } from '../i18n.js';
import {
  createDnsblChecker, dnsblCounts, dnsblTarget, listsFor, DNSBL_ERRORS, DNSBL_MEANINGS, DNSBL_REFUSALS, DNSBL_SKIPS, DNSBL_STATUSES
} from '../lib/dnsbl.js';
import { mergeSignals } from '../lib/util.js';

/** At most this many registrable domains of a row's host names are checked. */
export const MAX_DOMAINS = 3;

registerStrings('en', {
  'dnsbl.intro': { one: 'Asks {count} IP blocklist through your DoH resolver whether {ip} is listed.', other: 'Asks {count} IP blocklists through your DoH resolver whether {ip} is listed.' },
  'dnsbl.introDomains': 'Domain lists ({lists}): {names}.',
  'dnsbl.nothingSent': 'Nothing has been sent yet.',
  'dnsbl.privacy': 'The address goes to your DoH resolver reversed, as a DNS name, and the resolver asks each list’s name servers. A list is trusted only when its own test address comes back listed through the same resolver.',
  'dnsbl.check': 'Check blocklists',
  'dnsbl.again': 'Check again',
  'dnsbl.stop': 'Stop',
  'dnsbl.retryFailed': 'Retry failed lists',
  'dnsbl.checking': 'Checking blocklists… {done} of {total}',
  'dnsbl.stopped': 'Stopped — lists without a result were not asked.',
  'dnsbl.failedStart': 'The check could not start: {error}',
  'dnsbl.never.private': 'Private addresses are never sent to a blocklist.',
  'dnsbl.never.reserved': 'Reserved and documentation addresses are never sent to a blocklist.',
  'dnsbl.never.none': 'Nothing here can be checked.',
  'dnsbl.target.ip': 'Address {value}',
  'dnsbl.target.domain': 'Domain {value}',
  'dnsbl.col.list': 'List',
  'dnsbl.col.result': 'Result',
  'dnsbl.col.details': 'Details',
  'dnsbl.pending': 'Asking…',
  'dnsbl.status.listed': 'Listed',
  'dnsbl.status.not-listed': 'Not listed',
  'dnsbl.status.refused': 'Cannot check here',
  'dnsbl.status.error': 'Failed',
  'dnsbl.status.skipped': 'Not asked',
  'dnsbl.sum.listed': { zero: 'Not listed on any list that could be checked', one: 'Listed on {count} list', other: 'Listed on {count} lists' },
  'dnsbl.sum.clean': '{count} not listed',
  'dnsbl.sum.refused': '{count} cannot be checked from a public resolver',
  'dnsbl.sum.error': '{count} failed',
  'dnsbl.sum.skipped': '{count} take IPv4 only',
  'dnsbl.at': 'checked {time}',
  'dnsbl.refused.public-resolver': 'Refuses queries from public resolvers (answer {code}).',
  'dnsbl.refused.rate-limited': 'Says this resolver sent too many queries (answer {code}).',
  'dnsbl.refused.bad-query': 'Did not accept the query from this resolver (answer {code}).',
  'dnsbl.refused.query-refused': 'Refuses queries from public resolvers and high-volume senders (answer {code}).',
  'dnsbl.refused.test-point': 'Its own test address did not come back listed through this resolver, so a “not listed” here would mean nothing.',
  'dnsbl.refused.rcode': 'The resolver answered REFUSED.',
  'dnsbl.refusedHelp': 'Cannot be checked from a public resolver: use a local resolver or the command line, for example',
  'dnsbl.err.servfail': 'No answer from the list’s name servers through this resolver (SERVFAIL); some lists do not answer public resolvers.',
  'dnsbl.err.rcode': 'The resolver answered {rcode}.',
  'dnsbl.err.bad-answer': 'Answered {codes}, outside 127.0.0.0/8: the resolver may rewrite missing names, so the answer is not used.',
  'dnsbl.err.timeout': 'No answer in time.',
  'dnsbl.err.network': 'The resolver could not be reached.',
  'dnsbl.err.http': 'The resolver answered with an HTTP error.',
  'dnsbl.err.rate-limit': 'The resolver is rate limiting — try again in a minute.',
  'dnsbl.err.parse': 'The resolver’s answer could not be read.',
  'dnsbl.err.unknown': 'The query failed.',
  'dnsbl.skip.ipv4-only': 'Checks IPv4 addresses only.',
  'dnsbl.delist': 'Delist',
  'dnsbl.lookup': 'Check on its site',
  'dnsbl.code': 'answer {code}',
  'dnsbl.m.listed': 'listed',
  'dnsbl.m.sbl': 'SBL: a spam source or spam operation',
  'dnsbl.m.css': 'SBL CSS: snowshoe spam',
  'dnsbl.m.xbl': 'XBL: an infected or exploited machine',
  'dnsbl.m.drop': 'DROP: a hijacked or criminal network',
  'dnsbl.m.pbl': 'PBL: an end-user range that should not send mail directly (a policy, not abuse)',
  'dnsbl.m.rep-worst': 'worst reputation',
  'dnsbl.m.rep-very-bad': 'very bad reputation',
  'dnsbl.m.rep-bad': 'bad reputation',
  'dnsbl.m.rep-suspicious': 'suspicious behaviour',
  'dnsbl.m.reputation': 'reputation only (neutral to good), not a listing',
  'dnsbl.m.uce-1': 'this address sent mail to their spam traps',
  'dnsbl.m.uce-2': 'the provider’s network (allocation) is listed because of other addresses in it',
  'dnsbl.m.uce-3': 'the provider’s whole AS is listed',
  'dnsbl.m.test': 'test listing',
  'dnsbl.m.drone': 'a bot or drone (spam, IRC)',
  'dnsbl.m.ddos': 'a DDoS drone',
  'dnsbl.m.proxy': 'an open proxy',
  'dnsbl.m.open-dns': 'an open DNS resolver',
  'dnsbl.m.brute-force': 'brute-force attacks',
  'dnsbl.m.router': 'a compromised router or gateway',
  'dnsbl.m.vpn': 'an abused VPN service',
  'dnsbl.m.attacks': 'attacks reported to blocklist.de (SSH, mail, web …)',
  'dnsbl.m.backscatter': 'backscatter (bounces to forged senders)',
  'dnsbl.m.dbl-spam': 'a spam domain',
  'dnsbl.m.dbl-phish': 'a phishing domain',
  'dnsbl.m.dbl-malware': 'a malware domain',
  'dnsbl.m.dbl-botnet': 'a botnet command-and-control domain',
  'dnsbl.m.dbl-abused': 'a legitimate domain that is being abused',
  'dnsbl.m.young': 'first seen {hours} hours ago (a newly observed domain)',
  'dnsbl.m.phishing': 'phishing',
  'dnsbl.m.malware': 'malware',
  'dnsbl.m.abuse': 'spam and other abuse',
  'dnsbl.m.cracked': 'a cracked (compromised) site',
  'dnsbl.m.uribl-black': 'black: a spam domain',
  'dnsbl.m.uribl-grey': 'grey: a bulk-mail domain',
  'dnsbl.m.uribl-red': 'red: newly seen in spam'
});

registerStrings('tr', {
  'dnsbl.intro': '{ip} adresinin listede olup olmadığı DoH çözümleyiciniz üzerinden {count} IP kara listesine sorulur.',
  'dnsbl.introDomains': 'Alan adı listeleri ({lists}): {names}.',
  'dnsbl.nothingSent': 'Henüz hiçbir şey gönderilmedi.',
  'dnsbl.privacy': 'Adres, DoH çözümleyicinize ters çevrilmiş bir DNS adı olarak gider; çözümleyici her listenin ad sunucularına sorar. Bir listeye yalnızca kendi test adresi aynı çözümleyici üzerinden listede göründüğünde güvenilir.',
  'dnsbl.check': 'Kara listeleri kontrol et',
  'dnsbl.again': 'Yeniden kontrol et',
  'dnsbl.stop': 'Durdur',
  'dnsbl.retryFailed': 'Başarısız listeleri yeniden dene',
  'dnsbl.checking': 'Kara listeler kontrol ediliyor… {done} / {total}',
  'dnsbl.stopped': 'Durduruldu — sonucu olmayan listelere sorulmadı.',
  'dnsbl.failedStart': 'Kontrol başlatılamadı: {error}',
  'dnsbl.never.private': 'Özel (private) adresler hiçbir kara listeye gönderilmez.',
  'dnsbl.never.reserved': 'Ayrılmış ve dokümantasyon adresleri hiçbir kara listeye gönderilmez.',
  'dnsbl.never.none': 'Burada kontrol edilebilecek bir şey yok.',
  'dnsbl.target.ip': 'Adres {value}',
  'dnsbl.target.domain': 'Alan adı {value}',
  'dnsbl.col.list': 'Liste',
  'dnsbl.col.result': 'Sonuç',
  'dnsbl.col.details': 'Ayrıntılar',
  'dnsbl.pending': 'Soruluyor…',
  'dnsbl.status.listed': 'Listede',
  'dnsbl.status.not-listed': 'Listede değil',
  'dnsbl.status.refused': 'Buradan kontrol edilemez',
  'dnsbl.status.error': 'Başarısız',
  'dnsbl.status.skipped': 'Sorulmadı',
  'dnsbl.sum.listed': { zero: 'Kontrol edilebilen hiçbir listede yer almıyor', other: '{count} listede yer alıyor' },
  'dnsbl.sum.clean': '{count} listede yok',
  'dnsbl.sum.refused': '{count} liste genel bir çözümleyiciden kontrol edilemez',
  'dnsbl.sum.error': '{count} liste başarısız',
  'dnsbl.sum.skipped': '{count} liste yalnızca IPv4 alır',
  'dnsbl.at': 'kontrol: {time}',
  'dnsbl.refused.public-resolver': 'Genel çözümleyicilerden gelen sorguları reddediyor (yanıt {code}).',
  'dnsbl.refused.rate-limited': 'Bu çözümleyicinin çok fazla sorgu gönderdiğini söylüyor (yanıt {code}).',
  'dnsbl.refused.bad-query': 'Bu çözümleyiciden gelen sorguyu kabul etmedi (yanıt {code}).',
  'dnsbl.refused.query-refused': 'Genel çözümleyicilerden ve çok sorgu gönderenlerden gelen sorguları reddediyor (yanıt {code}).',
  'dnsbl.refused.test-point': 'Kendi test adresi bu çözümleyici üzerinden listede görünmedi; bu yüzden buradaki bir “listede değil” yanıtı hiçbir şey ifade etmez.',
  'dnsbl.refused.rcode': 'Çözümleyici REFUSED yanıtı verdi.',
  'dnsbl.refusedHelp': 'Genel bir çözümleyiciden kontrol edilemez: yerel bir çözümleyici ya da komut satırı kullanın, örneğin',
  'dnsbl.err.servfail': 'Bu çözümleyici üzerinden listenin ad sunucularından yanıt alınamadı (SERVFAIL); bazı listeler genel çözümleyicilere yanıt vermez.',
  'dnsbl.err.rcode': 'Çözümleyici {rcode} yanıtı verdi.',
  'dnsbl.err.bad-answer': '127.0.0.0/8 dışında bir yanıt verdi ({codes}): çözümleyici olmayan adların yanıtını değiştiriyor olabilir; bu yüzden yanıt kullanılmadı.',
  'dnsbl.err.timeout': 'Zamanında yanıt gelmedi.',
  'dnsbl.err.network': 'Çözümleyiciye ulaşılamadı.',
  'dnsbl.err.http': 'Çözümleyici bir HTTP hatasıyla yanıt verdi.',
  'dnsbl.err.rate-limit': 'Çözümleyici hız sınırı uyguluyor — bir dakika sonra yeniden deneyin.',
  'dnsbl.err.parse': 'Çözümleyicinin yanıtı okunamadı.',
  'dnsbl.err.unknown': 'Sorgu başarısız oldu.',
  'dnsbl.skip.ipv4-only': 'Yalnızca IPv4 adreslerini kontrol eder.',
  'dnsbl.delist': 'Listeden çıkarma',
  'dnsbl.lookup': 'Sitesinde kontrol et',
  'dnsbl.code': 'yanıt {code}',
  'dnsbl.m.listed': 'listede',
  'dnsbl.m.sbl': 'SBL: bir spam kaynağı ya da spam operasyonu',
  'dnsbl.m.css': 'SBL CSS: snowshoe spam',
  'dnsbl.m.xbl': 'XBL: virüslü ya da ele geçirilmiş bir makine',
  'dnsbl.m.drop': 'DROP: ele geçirilmiş ya da suç amaçlı bir ağ',
  'dnsbl.m.pbl': 'PBL: doğrudan e-posta göndermemesi gereken bir son kullanıcı aralığı (kötüye kullanım değil, bir politika)',
  'dnsbl.m.rep-worst': 'en kötü itibar',
  'dnsbl.m.rep-very-bad': 'çok kötü itibar',
  'dnsbl.m.rep-bad': 'kötü itibar',
  'dnsbl.m.rep-suspicious': 'şüpheli davranış',
  'dnsbl.m.reputation': 'yalnızca itibar bilgisi (nötrden iyiye), listeleme değil',
  'dnsbl.m.uce-1': 'bu adres spam tuzaklarına e-posta gönderdi',
  'dnsbl.m.uce-2': 'sağlayıcının ağı (tahsisi), içindeki başka adresler yüzünden listede',
  'dnsbl.m.uce-3': 'sağlayıcının tüm AS’i listede',
  'dnsbl.m.test': 'test kaydı',
  'dnsbl.m.drone': 'bir bot ya da drone (spam, IRC)',
  'dnsbl.m.ddos': 'bir DDoS drone’u',
  'dnsbl.m.proxy': 'açık bir proxy',
  'dnsbl.m.open-dns': 'açık bir DNS çözümleyicisi',
  'dnsbl.m.brute-force': 'kaba kuvvet (brute-force) saldırıları',
  'dnsbl.m.router': 'ele geçirilmiş bir yönlendirici ya da ağ geçidi',
  'dnsbl.m.vpn': 'kötüye kullanılan bir VPN hizmeti',
  'dnsbl.m.attacks': 'blocklist.de’ye bildirilen saldırılar (SSH, e-posta, web …)',
  'dnsbl.m.backscatter': 'backscatter (sahte göndericilere giden geri dönüşler)',
  'dnsbl.m.dbl-spam': 'bir spam alan adı',
  'dnsbl.m.dbl-phish': 'bir oltalama (phishing) alan adı',
  'dnsbl.m.dbl-malware': 'bir zararlı yazılım alan adı',
  'dnsbl.m.dbl-botnet': 'bir botnet komuta-kontrol alan adı',
  'dnsbl.m.dbl-abused': 'kötüye kullanılan meşru bir alan adı',
  'dnsbl.m.young': 'ilk kez {hours} saat önce görüldü (yeni gözlenen bir alan adı)',
  'dnsbl.m.phishing': 'oltalama (phishing)',
  'dnsbl.m.malware': 'zararlı yazılım',
  'dnsbl.m.abuse': 'spam ve diğer kötüye kullanım',
  'dnsbl.m.cracked': 'ele geçirilmiş bir site',
  'dnsbl.m.uribl-black': 'black: bir spam alan adı',
  'dnsbl.m.uribl-grey': 'grey: bir toplu e-posta alan adı',
  'dnsbl.m.uribl-red': 'red: spam’de yeni görülen'
});

/** Every key the panel builds from a library code (statuses, reasons, meanings), for the i18n coverage. */
export function generatedKeys() {
  return [
    ...DNSBL_STATUSES.map((s) => `dnsbl.status.${s}`),
    ...DNSBL_REFUSALS.map((r) => `dnsbl.refused.${r}`),
    ...DNSBL_ERRORS.map((e) => `dnsbl.err.${e}`),
    ...DNSBL_SKIPS.map((s) => `dnsbl.skip.${s}`),
    ...DNSBL_MEANINGS.map((m) => `dnsbl.m.${m}`),
    'dnsbl.never.private', 'dnsbl.never.reserved'
  ];
}

const STATUS_BADGE = {
  listed: { variant: 'error', icon: 'alert' },
  'not-listed': { variant: 'ok', icon: 'check-circle' },
  refused: { variant: 'warn', icon: 'minus-circle' },
  error: { variant: 'warn', icon: 'x-circle' },
  skipped: { variant: 'neutral', icon: 'minus' }
};

let checker = null;
let checkerDns = null;

/** The shared checker of a DNS client (one limiter and one test-point cache for every row). */
function getChecker(dns) {
  if (!checker || checkerDns !== dns) {
    checker = createDnsblChecker({ dns });
    checkerDns = dns;
  }
  return checker;
}

/** Row object → its panel element (the details row is rebuilt on every table update). */
const panels = new WeakMap();

/**
 * The Blocklists panel of an IP Intel row: the same element for the same row object.
 * @param {{ ip: string, hosts?: string[], dnsbl?: object }} row
 * @param {{ getDns: () => Promise<object>, requireOnline: (o?: object) => boolean, signal: AbortSignal }} ctx
 * @returns {HTMLElement}
 */
export function dnsblPanel(row, ctx) {
  let el = panels.get(row);
  if (!el) {
    el = buildPanel(row, ctx);
    panels.set(row, el);
  }
  return el;
}

/** Text of one decoded code ("SBL: a spam source … · 127.0.0.2"). */
function meaningText(c) {
  return t(`dnsbl.m.${c.meaning}`, { hours: formatNumber(c.hours ?? 0) });
}

/** The details cell of a result. */
function detailsOf(r) {
  const parts = [];
  if (r.status === 'listed' || (r.status === 'not-listed' && r.codes.length)) {
    for (const c of r.codes) parts.push(h('span', { class: 'ipi-bl-code' }, meaningText(c), ' ', h('span', { class: 'mono muted text-xs' }, c.code)));
  } else if (r.status === 'refused') {
    const code = r.codes.length ? r.codes[0].code : '';
    parts.push(h('span', null, t(`dnsbl.refused.${r.reason}`, { code })));
    const dig = `dig +short ${r.query} A`;
    parts.push(h('span', { class: 'ipi-bl-dig' }, h('span', { class: 'muted text-xs' }, t('dnsbl.refusedHelp')), ' ',
      h('code', { class: 'mono text-xs' }, dig), CopyButton(dig, { iconOnly: true, size: 'sm' })));
  } else if (r.status === 'error') {
    parts.push(h('span', null, t(`dnsbl.err.${r.reason}`, { rcode: r.rcode || '', codes: r.codes.map((c) => c.code).join(', ') })));
    if (r.error) parts.push(h('span', { class: 'mono muted text-xs' }, r.error));
  } else if (r.status === 'skipped') {
    parts.push(h('span', { class: 'muted' }, t(`dnsbl.skip.${r.reason}`)));
  }
  if (r.status === 'listed') parts.push(ExternalLink(r.delist, t('dnsbl.delist'), { className: 'ipi-bl-link' }));
  else if (r.status === 'refused' || r.status === 'error') parts.push(ExternalLink(r.delist, t('dnsbl.lookup'), { className: 'ipi-bl-link' }));
  return h('div', { class: 'ipi-bl-details' }, parts);
}

function resultRow(l, r) {
  const status = r ? r.status : 'pending';
  const badge = r
    ? Badge(t(`dnsbl.status.${r.status}`), STATUS_BADGE[r.status])
    : h('span', { class: 'ipi-pending' }, h('span', { class: 'spinner spinner-inline', attrs: { 'aria-hidden': 'true' } }), t('dnsbl.pending'));
  return h('tr', { class: 'ipi-bl-row', dataset: { list: l.id, status } },
    h('th', { attrs: { scope: 'row' } }, h('span', { class: 'ipi-bl-name' }, l.name), h('span', { class: 'mono muted text-xs ipi-bl-zone' }, r && r.zone ? r.zone : l.zone)),
    h('td', { class: 'ipi-bl-result' }, badge),
    h('td', null, r ? detailsOf(r) : null));
}

/** One summary line over every target's results. */
function summaryText(sections) {
  const counts = dnsblCounts(sections.flatMap((s) => s.results.filter(Boolean)));
  const parts = [t('dnsbl.sum.listed', { count: counts.listed })];
  if (counts['not-listed']) parts.push(t('dnsbl.sum.clean', { count: counts['not-listed'] }));
  if (counts.refused) parts.push(t('dnsbl.sum.refused', { count: counts.refused }));
  if (counts.error) parts.push(t('dnsbl.sum.error', { count: counts.error }));
  if (counts.skipped) parts.push(t('dnsbl.sum.skipped', { count: counts.skipped }));
  return { text: parts.join(' · '), counts };
}

function buildPanel(row, ctx) {
  const ip = dnsblTarget(row.ip);
  const domains = [];
  for (const host of row.hosts || []) {
    const d = dnsblTarget(host);
    if (d.ok && d.kind === 'domain' && !domains.some((x) => x.value === d.value)) domains.push(d);
  }
  const targets = [...(ip.ok ? [ip] : []), ...domains.slice(0, MAX_DOMAINS)];
  const root = h('div', { class: 'stack-sm ipi-bl', dataset: { ip: row.ip } });

  const never = !ip.ok && ip.reason ? h('p', { class: 'muted text-sm ipi-bl-never' }, t(`dnsbl.never.${ip.reason === 'private' ? 'private' : 'reserved'}`)) : null;
  if (!targets.length) {
    root.append(never || h('p', { class: 'muted text-sm ipi-bl-never' }, t('dnsbl.never.none')));
    return root;
  }

  const intro = h('p', { class: 'text-sm ipi-bl-intro' },
    ip.ok ? t('dnsbl.intro', { count: listsFor('ip').length, ip: ip.value }) : null,
    domains.length ? ` ${t('dnsbl.introDomains', { lists: listsFor('domain').map((l) => l.name).join(', '), names: domains.slice(0, MAX_DOMAINS).map((d) => d.value).join(', ') })}` : null);
  const sentNote = h('p', { class: 'muted text-xs ipi-bl-sent' }, t('dnsbl.nothingSent'));
  const privacy = h('p', { class: 'muted text-xs ipi-bl-privacy' }, t('dnsbl.privacy'));
  const checkBtn = Button({ label: t('dnsbl.check'), icon: 'shield', size: 'sm', variant: 'secondary', dataset: { action: 'dnsbl-check' }, onClick: () => run() });
  const stopBtn = Button({ label: t('dnsbl.stop'), icon: 'stop', size: 'sm', variant: 'ghost', dataset: { action: 'dnsbl-stop' }, onClick: () => stop() });
  const retryBtn = Button({ label: t('dnsbl.retryFailed'), icon: 'refresh', size: 'sm', variant: 'ghost', dataset: { action: 'dnsbl-retry' }, onClick: () => run({ retry: true }) });
  const statusEl = h('p', { class: 'text-sm ipi-bl-status', attrs: { 'aria-live': 'polite' } });
  const sectionsEl = h('div', { class: 'stack-sm ipi-bl-sections' });
  for (const el of [intro, never, h('div', { class: 'cluster ipi-bl-actions' }, checkBtn, stopBtn, retryBtn, statusEl), sentNote, privacy, sectionsEl]) {
    if (el) root.appendChild(el);
  }

  /** The check on screen: { sections: [{ target, results: (DnsblResult|null)[] }], at, stopped }. */
  let shown = row.dnsbl && Array.isArray(row.dnsbl.sections) ? row.dnsbl : null;
  let controller = null;
  let stoppedByUser = false;
  /** Why the last check could not start (no DNS client), shown until the next one. */
  let startError = null;

  function renderSections() {
    clear(sectionsEl);
    if (!shown) return;
    for (const s of shown.sections) {
      const lists = listsFor(s.target.kind);
      sectionsEl.append(h('div', { class: 'ipi-bl-section', dataset: { target: s.target.value, kind: s.target.kind } },
        h('h4', { class: 'ipi-bl-target' }, t(`dnsbl.target.${s.target.kind}`, { value: s.target.value })),
        h('div', { class: 'ipi-bl-scroll' },
          h('table', { class: 'ipi-bl-table' },
            h('thead', null, h('tr', null,
              h('th', { attrs: { scope: 'col' } }, t('dnsbl.col.list')),
              h('th', { attrs: { scope: 'col' } }, t('dnsbl.col.result')),
              h('th', { attrs: { scope: 'col' } }, t('dnsbl.col.details')))),
            h('tbody', null, lists.map((l, i) => resultRow(l, s.results[i])))))));
    }
  }

  function renderState({ done = 0, total = 0 } = {}) {
    const running = !!controller;
    checkBtn.hidden = running;
    stopBtn.hidden = !running;
    sentNote.hidden = !!shown;
    const failed = shown && !running ? shown.sections.some((s) => s.results.some((r) => r && r.status === 'error')) : false;
    retryBtn.hidden = !failed;
    const label = checkBtn.querySelector('.btn-label');
    if (label) label.textContent = shown && !running ? t('dnsbl.again') : t('dnsbl.check');
    if (running) statusEl.textContent = t('dnsbl.checking', { done: formatNumber(done), total: formatNumber(total) });
    else if (startError) statusEl.textContent = t('dnsbl.failedStart', { error: startError });
    else if (shown && shown.stopped) statusEl.textContent = t('dnsbl.stopped');
    else if (shown) statusEl.textContent = `${summaryText(shown.sections).text} · ${t('dnsbl.at', { time: formatDateTime(new Date(shown.at)) })}`;
    else statusEl.textContent = '';
    statusEl.dataset.state = running ? 'running' : startError ? 'failed' : shown ? (shown.stopped ? 'stopped' : 'done') : 'idle';
  }

  function stop() {
    if (controller) {
      stoppedByUser = true;
      controller.abort();
    }
  }

  /** Ask every list (or, `retry`, only the lists that failed) for every target. */
  async function run({ retry = false } = {}) {
    if (controller) return;
    if (!ctx.requireOnline()) return;
    const prev = retry && shown && !shown.stopped ? shown : null;
    const sections = targets.map((target) => {
      const old = prev ? prev.sections.find((s) => s.target.value === target.value) : null;
      return { target, results: old ? old.results.map((r) => (r && r.status === 'error' ? null : r)) : listsFor(target.kind).map(() => null) };
    });
    const total = sections.reduce((n, s) => n + s.results.filter((r) => !r).length, 0);
    let done = 0;
    controller = new AbortController();
    stoppedByUser = false;
    startError = null;
    const signal = mergeSignals(ctx.signal, controller.signal);
    shown = { sections, at: Date.now(), stopped: false };
    renderSections();
    renderState({ done, total });
    try {
      const dns = await ctx.getDns();
      const c = getChecker(dns);
      await Promise.all(sections.map(async (s) => {
        const lists = listsFor(s.target.kind);
        const ids = lists.filter((l, i) => !s.results[i]).map((l) => l.id);
        if (!ids.length) return;
        await c.check(s.target, {
          signal, lists: ids, noCache: retry,
          onResult: (r) => {
            if (signal.aborted) return;
            const i = lists.findIndex((l) => l.id === r.list);
            s.results[i] = r;
            done += 1;
            const body = sectionsEl.querySelector(`.ipi-bl-section[data-target="${CSS.escape(s.target.value)}"] tbody`);
            if (body && body.children[i]) body.children[i].replaceWith(resultRow(lists[i], r));
            renderState({ done, total });
          }
        });
      }));
      shown.at = Date.now();
      row.dnsbl = { sections, at: shown.at };
      announce(summaryText(sections).text);
    } catch (err) {
      if (err && err.name === 'AbortError') {
        if (stoppedByUser) shown.stopped = true;
        else shown = row.dnsbl || null;
      } else {
        shown = row.dnsbl || null;
        startError = err && err.message ? err.message : String(err);
      }
    } finally {
      controller = null;
      if (!ctx.signal.aborted) {
        renderSections();
        renderState();
      }
    }
  }

  renderSections();
  renderState();
  return root;
}
