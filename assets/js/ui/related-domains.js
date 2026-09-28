/**
 * ui/related-domains.js — Subdomains › Sources › "Related domains in the same certificates".
 *
 * Other registrable domains named in the certificates of the scanned hosts, from the Certificate
 * Transparency results the scan already has (lib/ctrelated.js; nothing is sent again): each with
 * how many certificates it shares, its host names there, the certificates themselves (issuer,
 * validity, the scanned names they carry, a crt.sh link) and "Scan too", which starts a new scan
 * of the scanned domains together with it. Domains seen only in certificates that name more than
 * {@link SHARED_CERT_DOMAINS} registrable domains fold into one list at the end, worded as what
 * such a certificate usually is (a CDN's or a host's, for many customers: nothing about who owns
 * a domain) and can be (one company's, for its many brands), each with "Scan too" as well.
 *
 * Loaded by views/subdomains.js with a run that asks crt.sh or Cert Spotter. The card is drawn
 * again only when the run's Certificate Transparency results change (not on every source event),
 * keeps the disclosures the user opened, and only turns its buttons on or off when a scan starts
 * or ends.
 */

import { h, clear, uid } from './dom.js';
import { Alert, Badge, Button, Disclosure, ExternalLink, TruncatedList } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { relatedDomains, SHARED_CERT_DOMAINS } from '../lib/ctrelated.js';

registerStrings('en', {
  'rel.title': 'Related domains in the same certificates',
  'rel.hint': 'Other registrable domains named in the certificates of these hosts, read from the Certificate Transparency data this scan already fetched — nothing is sent again. A forgotten brand or campaign domain often shows up here.',
  'rel.scanHint': '“Scan too” starts a new scan of {domains} together with that domain; it asks the passive sources again for each (Cert Spotter allows about 10 domain searches an hour).',
  'rel.waiting': 'Waiting for Certificate Transparency…',
  'rel.failed': 'Certificate Transparency did not answer, so there are no certificates to read.',
  'rel.none': { one: 'No other registrable domain shares a certificate with these hosts ({count} certificate read).', other: 'No other registrable domain shares a certificate with these hosts ({count} certificates read).' },
  'rel.sharedOnlyNone': {
    one: 'Other domains appear only in certificates that name more than {max} registrable domains ({count} certificate read).',
    other: 'Other domains appear only in certificates that name more than {max} registrable domains ({count} certificates read).'
  },
  'rel.found': {
    one: '{count} other domain shares certificates with these hosts ({certs}).',
    other: '{count} other domains share certificates with these hosts ({certs}).'
  },
  'rel.certsRead': { one: '{count} certificate read', other: '{count} certificates read' },
  'rel.partial': {
    one: 'crt.sh returns only the names that matched the search and a certificate’s common name: {count} certificate only crt.sh reported may name more domains.',
    other: 'crt.sh returns only the names that matched the search and a certificate’s common name: {count} certificates only crt.sh reported may name more domains.'
  },
  'rel.more': { one: '{count} more domain is not listed.', other: '{count} more domains are not listed.' },
  'rel.certs': { one: '{count} certificate', other: '{count} certificates' },
  'rel.current': 'Current',
  'rel.currentTitle': 'A certificate naming this domain is valid today',
  'rel.expired': 'Expired',
  'rel.expiredTitle': 'Every certificate naming it has expired',
  'rel.platform': 'Platform: {name}',
  'rel.platformTitle': 'A hosting or CDN platform’s domain, not a brand of these hosts',
  'rel.scan': 'Scan too',
  'rel.scanLabel': 'Scan too: {domain}',
  'rel.scanTitle': 'Scan {domains} together with {domain}',
  'rel.scanBusy': 'Available when this scan has ended',
  'rel.certList': 'The certificates',
  'rel.cert.valid': '{from} – {to}',
  'rel.cert.with': 'Scanned names',
  'rel.cert.shared': '{count} registrable domains',
  'rel.cert.sharedTitle': 'More than {max} registrable domains in one certificate: usually a CDN’s or a host’s certificate for many customers, sometimes one company’s for its many brands',
  'rel.cert.partial': 'crt.sh only: names may be missing',
  'rel.cert.open': 'crt.sh',
  'rel.moreNames': { one: '+{count} name', other: '+{count} names' },
  'rel.sharedOnly': {
    one: '{count} domain appears only in certificates that name more than {max} registrable domains',
    other: '{count} domains appear only in certificates that name more than {max} registrable domains'
  },
  'rel.sharedHint': 'Such a certificate is usually a CDN’s or a host’s for many customers, and says nothing about who owns a domain in it. It can also be one company’s certificate for its many brands, so “Scan too” is here as well.'
});

registerStrings('tr', {
  'rel.title': 'Aynı sertifikalardaki ilişkili alan adları',
  'rel.hint': 'Bu host’ların sertifikalarında geçen diğer kayıtlı alan adları; bu taramanın zaten aldığı Certificate Transparency verisinden okunur, yeniden hiçbir şey gönderilmez. Unutulmuş bir marka ya da kampanya alan adı çoğu zaman burada çıkar.',
  'rel.scanHint': '“Bunu da tara”, {domains} ile o alan adını birlikte tarayan yeni bir tarama başlatır; pasif kaynaklara her biri için yeniden sorulur (Cert Spotter saatte yaklaşık 10 alan adı aramasına izin verir).',
  'rel.waiting': 'Certificate Transparency bekleniyor…',
  'rel.failed': 'Certificate Transparency yanıt vermedi; okunacak sertifika yok.',
  'rel.none': { other: 'Başka hiçbir kayıtlı alan adı bu host’larla sertifika paylaşmıyor ({count} sertifika okundu).' },
  'rel.sharedOnlyNone': { other: 'Diğer alan adları yalnızca {max} taneden fazla kayıtlı alan adı içeren sertifikalarda geçiyor ({count} sertifika okundu).' },
  'rel.found': { other: '{count} başka alan adı bu host’larla sertifika paylaşıyor ({certs}).' },
  'rel.certsRead': { other: '{count} sertifika okundu' },
  'rel.partial': { other: 'crt.sh yalnızca aramayla eşleşen adları ve sertifikanın ortak adını (CN) döndürür: yalnızca crt.sh’in bildirdiği {count} sertifikada başka alan adları da olabilir.' },
  'rel.more': { other: '{count} alan adı daha listelenmedi.' },
  'rel.certs': { other: '{count} sertifika' },
  'rel.current': 'Geçerli',
  'rel.currentTitle': 'Bu alan adını içeren bir sertifika bugün geçerli',
  'rel.expired': 'Süresi dolmuş',
  'rel.expiredTitle': 'Onu içeren her sertifikanın süresi dolmuş',
  'rel.platform': 'Platform: {name}',
  'rel.platformTitle': 'Bu host’ların bir markası değil, bir barındırma ya da CDN platformunun alan adı',
  'rel.scan': 'Bunu da tara',
  'rel.scanLabel': 'Bunu da tara: {domain}',
  'rel.scanTitle': '{domains} ile {domain} alan adını birlikte tara',
  'rel.scanBusy': 'Bu tarama bitince kullanılabilir',
  'rel.certList': 'Sertifikalar',
  'rel.cert.valid': '{from} – {to}',
  'rel.cert.with': 'Taranan adlar',
  'rel.cert.shared': '{count} kayıtlı alan adı',
  'rel.cert.sharedTitle': 'Tek sertifikada {max} taneden fazla kayıtlı alan adı: çoğunlukla bir CDN’in ya da barındırma firmasının birçok müşteri için aldığı sertifika, bazen de tek bir şirketin birçok markası için aldığı sertifika',
  'rel.cert.partial': 'yalnızca crt.sh: adlar eksik olabilir',
  'rel.cert.open': 'crt.sh',
  'rel.moreNames': { other: '+{count} ad' },
  'rel.sharedOnly': { other: '{count} alan adı yalnızca {max} taneden fazla kayıtlı alan adı içeren sertifikalarda geçiyor' },
  'rel.sharedHint': 'Böyle bir sertifika çoğunlukla bir CDN’in ya da barındırma firmasının birçok müşteri için aldığı sertifikadır ve içindeki bir alan adının sahibi hakkında bir şey söylemez. Tek bir şirketin birçok markası için aldığı sertifika da olabilir; bu yüzden “Bunu da tara” burada da var.'
});

/** Passive sources that read Certificate Transparency. */
const CT_SOURCES = Object.freeze(['crtsh', 'certspotter']);

/**
 * Where the scan's Certificate Transparency stands: 'off' (not among its sources — the view does
 * not load the card for such a run), 'waiting' (none answered yet while the scan runs), 'failed'
 * (none answered and none will) or 'ready'.
 * @param {{ status: string, config: { sources?: string[] }, sourceResults: object[] }} run
 * @returns {'off'|'waiting'|'failed'|'ready'}
 */
export function ctState(run) {
  const asked = (run.config.sources || []).filter((s) => CT_SOURCES.includes(s));
  if (!asked.length) return 'off';
  const results = run.sourceResults.filter((r) => r && CT_SOURCES.includes(r.source));
  if (results.some((r) => r.ok || (Array.isArray(r.certs) && r.certs.length))) return 'ready';
  return run.status === 'running' ? 'waiting' : 'failed';
}

/**
 * The card.
 * @param {{ onScanWith: (domains: string[]) => void }} opts onScanWith: start a new scan of these domains
 * @returns {{ el: HTMLElement, update: (run: object, opts: { busy: boolean }) => void }}
 */
export function RelatedDomains({ onScanWith }) {
  const headingId = uid('sub-rel');
  const body = h('div', { class: 'stack-sm sub-rel-body' });
  const el = h('section', { class: 'sub-src-section card sub-rel', dataset: { part: 'related' }, attrs: { 'aria-labelledby': headingId } },
    h('h3', { class: 'sub-src-heading', id: headingId }, t('rel.title')),
    h('p', { class: 'sub-src-hint' }, t('rel.hint')),
    body);
  /** What the drawn card was made from (the CT results and the domains), and its scan buttons. */
  let drawn = null;
  let scanButtons = [];

  function certLine(c) {
    return h('li', { class: 'sub-rel-cert', dataset: { cert: c.key } },
      h('div', { class: 'sub-rel-cert-head' },
        h('span', { class: 'sub-rel-issuer' }, c.issuer || '—'),
        h('span', { class: 'sub-rel-valid num' }, t('rel.cert.valid', { from: formatDate(c.notBefore), to: formatDate(c.notAfter) })),
        c.url ? ExternalLink(c.url, t('rel.cert.open'), { className: 'sub-rel-link' }) : null),
      h('div', { class: 'sub-rel-with' }, h('span', { class: 'muted' }, `${t('rel.cert.with')}: `),
        TruncatedList(c.ownNames, { max: 3, inline: true })),
      c.shared || c.partial ? h('div', { class: 'sub-rel-flags' },
        c.shared ? Badge(t('rel.cert.shared', { count: c.domains }), { variant: 'neutral', title: t('rel.cert.sharedTitle', { max: SHARED_CERT_DOMAINS }) }) : null,
        c.partial ? Badge(t('rel.cert.partial'), { variant: 'neutral' }) : null) : null);
  }

  /** Turn a "Scan too" button on or off (a scan running blocks a new one). */
  function setBusy(btn, busy, domains) {
    btn.disabled = busy;
    btn.title = busy ? t('rel.scanBusy') : t('rel.scanTitle', { domains: domains.join(', '), domain: btn.dataset.domain });
  }

  /** "Scan too" for a domain, or null for a platform's domain (never a brand of these hosts). */
  function scanButton(d, run, busy) {
    if (d.platform) return null;
    const domains = run.config.domains;
    const scan = Button({
      label: t('rel.scan'),
      icon: 'search',
      size: 'sm',
      variant: 'secondary',
      // Every button reads "Scan too": its accessible name says which domain.
      ariaLabel: t('rel.scanLabel', { domain: d.domain }),
      dataset: { action: 'rel-scan', domain: d.domain },
      onClick: () => onScanWith([...domains, d.domain])
    });
    setBusy(scan, busy, domains);
    scanButtons.push(scan);
    return scan;
  }

  function domainItem(d, run, busy, open) {
    return h('li', { class: 'sub-rel-item', dataset: { domain: d.domain, certs: String(d.certs) } },
      h('div', { class: 'sub-rel-head' },
        h('span', { class: 'sub-rel-domain mono' }, d.domain),
        h('span', { class: 'sub-rel-badges' },
          Badge(t('rel.certs', { count: d.certs }), { variant: 'accent', icon: 'certificate' }),
          d.current ? Badge(t('rel.current'), { variant: 'ok', title: t('rel.currentTitle') })
            : Badge(t('rel.expired'), { variant: 'neutral', title: t('rel.expiredTitle') }),
          d.platform ? Badge(t('rel.platform', { name: d.platform }), { variant: 'info', title: t('rel.platformTitle') }) : null),
        scanButton(d, run, busy)),
      h('div', { class: 'sub-rel-names' },
        TruncatedList(d.names, { max: 4, inline: true }),
        d.moreNames ? h('span', { class: 'muted text-sm' }, ` ${t('rel.moreNames', { count: d.moreNames })}`) : null),
      Disclosure({
        summary: `${t('rel.certList')} (${formatNumber(d.certs)})`,
        className: 'sub-rel-certs',
        open,
        children: h('ul', { class: 'sub-rel-cert-list' }, d.certificates.map(certLine))
      }));
  }

  /** The disclosures open now: each domain's certificate list, and the shared-only list. */
  function openState() {
    return {
      domains: new Set([...body.querySelectorAll('.sub-rel-item')].filter((li) => li.querySelector('.sub-rel-certs[open]')).map((li) => li.dataset.domain)),
      shared: !!body.querySelector('.sub-rel-shared[open]')
    };
  }

  function draw(run, state, ctResults, busy) {
    const open = openState();
    clear(body);
    scanButtons = [];
    el.hidden = state === 'off';
    el.dataset.state = state;
    if (state !== 'ready') {
      if (state !== 'off') body.append(h('p', { class: 'sub-src-none' }, t(`rel.${state}`)));
      return;
    }
    const out = relatedDomains(ctResults.flatMap((r) => r.certs || []), { domains: run.config.domains });
    el.dataset.related = String(out.related.length);
    const brands = out.related.filter((d) => !d.sharedOnly);
    const sharedOnly = out.related.filter((d) => d.sharedOnly);
    // The brands a scan can go on with; the shared-only domains say so in their own list below.
    body.append(h('p', { class: 'sub-rel-summary', dataset: { role: 'rel-summary' } }, brands.length
      ? t('rel.found', { count: brands.length, certs: t('rel.certsRead', { count: out.certs }) })
      : t(sharedOnly.length ? 'rel.sharedOnlyNone' : 'rel.none', { count: out.certs, max: SHARED_CERT_DOMAINS })));
    if (brands.length) {
      body.append(h('ul', { class: 'sub-rel-list' }, brands.map((d) => domainItem(d, run, busy, open.domains.has(d.domain)))));
    }
    if (sharedOnly.length) {
      // Usually a CDN's or a host's customers, but a company's many brands look the same: hedged, and scannable.
      body.append(Disclosure({
        summary: t('rel.sharedOnly', { count: sharedOnly.length, max: SHARED_CERT_DOMAINS }),
        className: 'sub-rel-shared',
        open: open.shared,
        children: h('div', { class: 'stack-sm' },
          h('p', { class: 'sub-src-hint' }, t('rel.sharedHint')),
          h('ul', { class: 'sub-rel-shared-list' }, sharedOnly.map((d) => h('li', { class: 'sub-rel-shared-item', dataset: { domain: d.domain } },
            h('span', { class: 'sub-rel-shared-name' },
              h('span', { class: 'mono sub-rel-shared-domain' }, d.domain), ' ', h('span', { class: 'muted sub-rel-shared-count' }, t('rel.certs', { count: d.certs }))),
            scanButton(d, run, busy)))))
      }));
    }
    if (scanButtons.length) body.append(h('p', { class: 'sub-src-hint' }, t('rel.scanHint', { domains: run.config.domains.join(', ') })));
    if (out.more) body.append(h('p', { class: 'muted text-sm' }, t('rel.more', { count: out.more })));
    if (out.partial) body.append(Alert({ variant: 'info', compact: true, message: t('rel.partial', { count: out.partial }) }));
  }

  /**
   * Follow a run (on each source result and when it ends): the card is drawn again only when its
   * Certificate Transparency results changed; a scan starting or ending only turns the buttons on or off.
   * @param {object} run a Subdomains run (views/subdomains.js createRun)
   * @param {{ busy?: boolean }} [opts] busy: a scan is running (no new one can start)
   */
  function update(run, { busy = false } = {}) {
    const state = ctState(run);
    const ctResults = run.sourceResults.filter((r) => r && CT_SOURCES.includes(r.source));
    const inputs = { run, state, domains: run.config.domains.join(','), results: ctResults.map((r) => [r, r.certs, (r.certs || []).length]) };
    const same = drawn && drawn.run === inputs.run && drawn.state === inputs.state && drawn.domains === inputs.domains
      && drawn.results.length === inputs.results.length
      && drawn.results.every((x, i) => x.every((v, j) => v === inputs.results[i][j]));
    if (!same) {
      draw(run, state, ctResults, busy);
      drawn = inputs;
      return;
    }
    for (const btn of scanButtons) setBusy(btn, busy, run.config.domains);
  }

  return { el, update };
}
