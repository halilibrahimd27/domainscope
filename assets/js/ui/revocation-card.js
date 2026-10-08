/**
 * ui/revocation-card.js — Certificate › CT logs › "Is it revoked?" (lib/revocation.js): on a
 * click, one exact-name request to Cert Spotter, the answer matched to the certificate by its
 * SHA-256 computed here; the certificate itself is never sent. Revoked: when, why, and the CA's
 * problem-reporting contact (ui/revocation.js).
 *
 * Loaded by the Certificate view with its CT logs tab, never on the start route. Nothing is sent
 * before the button is pressed, and nothing at all for an expired certificate or one without a
 * name (Cert Spotter lists unexpired certificates by name). A lookup runs on a controller of its
 * own, kept with its result in the cache the view passes in, so a language switch or another tab
 * does not lose it; the view aborts them when the workspace changes.
 */

import { h, clear } from './dom.js';
import { Alert, Button, Card, ErrorBanner, Spinner } from './components.js';
import { t, registerStrings, formatDateTime, formatRelative } from '../i18n.js';
import { checkRevocation, revocationName, REVOCATION_MAX_PAGES } from '../lib/revocation.js';
import { errorKind } from '../lib/util.js';
import { ProblemReporting, reasonLabel } from './revocation.js';

registerStrings('en', {
  'revc.title': 'Is it revoked?',
  'revc.intro': 'Cert Spotter reads the revocation lists public CAs publish. One request asks it about the name below; the certificate itself is never sent: Cert Spotter’s answer is matched to it here by its SHA-256.',
  'revc.nameLabel': 'Name sent',
  'revc.run': 'Ask Cert Spotter',
  'revc.rerun': 'Ask again',
  'revc.cost': 'Uses one of the 100 single-name searches Cert Spotter allows your IP address an hour (up to three for a name with many certificates).',
  'revc.checking': 'Asking Cert Spotter…',
  'revc.good.title': 'Not revoked',
  'revc.good.body': 'Cert Spotter last read the CA’s revocation list {time}.',
  'revc.good.bodyNoTime': 'Cert Spotter does not say when it last read the CA’s revocation list.',
  'revc.revoked.title': 'Revoked on {date}',
  'revc.revoked.titleNoDate': 'Revoked',
  'revc.revoked.body': 'Reason: {reason}. Clients that check revocation refuse this certificate: replace it on every server that serves it.',
  'revc.byIssuance': 'Cert Spotter knows this issuance by its precertificate: it was matched by the public key and the exact validity period.',
  'revc.notFound.title': 'Cert Spotter does not list this certificate',
  'revc.notFound.body': 'Cert Spotter lists the unexpired certificates public CAs logged in Certificate Transparency. A certificate from a private CA or a self-signed one is never there, and one issued in the last few hours may not be there yet.',
  'revc.notFound.truncated': 'Cert Spotter lists more certificates for {name} than the {count} pages read.',
  'revc.expired': 'This certificate has expired, and Cert Spotter lists unexpired certificates only. Nothing is sent.',
  'revc.noName': 'This certificate has no DNS name to look it up by. Nothing is sent.',
  'revc.limited': 'Cert Spotter’s hourly limit for your IP address is used up until about {time}.',
  'revc.limitedNoTime': 'Cert Spotter’s hourly limit for your IP address is used up. Try again in an hour.',
  'revc.failed': 'Cert Spotter did not answer'
});

registerStrings('tr', {
  'revc.title': 'İptal edilmiş mi?',
  'revc.intro': 'Cert Spotter, herkese açık CA’ların yayımladığı iptal listelerini okur. Tek bir istekle ona aşağıdaki ad sorulur; sertifikanın kendisi hiç gönderilmez, Cert Spotter’ın yanıtı burada sertifikanın SHA-256 özetiyle eşleştirilir.',
  'revc.nameLabel': 'Gönderilen ad',
  'revc.run': 'Cert Spotter’a sor',
  'revc.rerun': 'Yeniden sor',
  'revc.cost': 'Cert Spotter’ın IP adresinize saatte tanıdığı 100 tek ad sorgusundan birini kullanır (çok sertifikası olan bir ad için en fazla üç).',
  'revc.checking': 'Cert Spotter’a soruluyor…',
  'revc.good.title': 'İptal edilmemiş',
  'revc.good.body': 'Cert Spotter, CA’nın iptal listesini en son {time} okudu.',
  'revc.good.bodyNoTime': 'Cert Spotter, CA’nın iptal listesini en son ne zaman okuduğunu belirtmiyor.',
  'revc.revoked.title': '{date} tarihinde iptal edilmiş',
  'revc.revoked.titleNoDate': 'İptal edilmiş',
  'revc.revoked.body': 'Gerekçe: {reason}. İptal denetimi yapan istemciler bu sertifikayı reddeder: onu sunan her sunucuda değiştirin.',
  'revc.byIssuance': 'Cert Spotter bu sertifikayı ön sertifikasıyla tanıyor: açık anahtarı ve tam geçerlilik süresiyle eşleştirildi.',
  'revc.notFound.title': 'Cert Spotter bu sertifikayı listelemiyor',
  'revc.notFound.body': 'Cert Spotter, herkese açık CA’ların Certificate Transparency’ye kaydettiği ve süresi dolmamış sertifikaları listeler. Özel bir CA’dan alınmış ya da kendinden imzalı bir sertifika orada hiç olmaz; son birkaç saatte verilmiş bir sertifika da henüz görünmeyebilir.',
  'revc.notFound.truncated': 'Cert Spotter {name} için okunan {count} sayfadan daha fazla sertifika listeliyor.',
  'revc.expired': 'Bu sertifikanın süresi dolmuş; Cert Spotter yalnızca süresi dolmamış sertifikaları listeler. Hiçbir şey gönderilmez.',
  'revc.noName': 'Bu sertifikada aranabilecek bir DNS adı yok. Hiçbir şey gönderilmez.',
  'revc.limited': 'Cert Spotter’ın IP adresiniz için saatlik sınırı yaklaşık {time} saatine kadar doldu.',
  'revc.limitedNoTime': 'Cert Spotter’ın IP adresiniz için saatlik sınırı doldu. Bir saat sonra yeniden deneyin.',
  'revc.failed': 'Cert Spotter yanıt vermedi'
});

/**
 * The "Is it revoked?" card of one certificate (a server certificate: the view leaves it out for a
 * CA certificate).
 * @param {{ cert: object, ctx: import('../app.js').ViewContext, cache: Map<string, object>, cacheKey: string, now?: () => number }} opts
 *   cert: a lib/x509.js Certificate; cache / cacheKey: where its lookup is kept
 * @returns {HTMLElement}
 */
export function RevocationCard({ cert, ctx, cache, cacheKey, now = () => Date.now() }) {
  const name = revocationName(cert);
  const expired = cert.notAfter instanceof Date && cert.notAfter.getTime() < now();
  const body = h('div', { class: 'stack-sm rev-body', attrs: { 'aria-live': 'polite' } });
  const runBtn = Button({ label: t('revc.run'), icon: 'search', size: 'sm', dataset: { action: 'rev-run' }, onClick: () => run() });
  const canAsk = !!name && !expired;
  const card = Card({
    title: t('revc.title'),
    icon: 'shield',
    className: 'rev-card',
    children: h('div', { class: 'stack-sm' },
      h('p', { class: 'muted text-sm' }, t('revc.intro')),
      canAsk ? h('div', { class: 'rev-name' }, h('span', { class: 'field-label' }, t('revc.nameLabel')), h('code', { class: 'mono', dataset: { role: 'rev-name' } }, name)) : null,
      canAsk ? h('div', { class: 'cluster rev-actions' }, runBtn, h('span', { class: 'muted text-xs' }, t('revc.cost'))) : null,
      body)
  });
  card.dataset.role = 'rev-card';

  const refresh = (entry) => {
    if (card.isConnected) show(entry);
  };

  function show(entry) {
    clear(body);
    card.dataset.state = entry ? entry.status : 'idle';
    delete card.dataset.status;
    if (!canAsk) {
      card.dataset.status = expired ? 'expired' : 'no-name';
      body.append(Alert({ variant: 'info', compact: true, message: t(expired ? 'revc.expired' : 'revc.noName') }));
      return;
    }
    runBtn.querySelector('.btn-label').textContent = entry && entry.status !== 'running' ? t('revc.rerun') : t('revc.run');
    runBtn.disabled = !!entry && entry.status === 'running';
    if (!entry) return;
    if (entry.status === 'running') {
      entry.watchers.add(refresh);
      body.append(Spinner({ label: t('revc.checking'), showLabel: true }));
      return;
    }
    if (entry.status === 'error') {
      body.append(ErrorBanner(entry.error, { title: t('revc.failed'), compact: true }));
      return;
    }
    body.append(...resultNodes(entry.result));
  }

  function resultNodes(r) {
    card.dataset.status = r.status;
    const nodes = [];
    if (r.status === 'good') {
      const checked = r.revocation && r.revocation.checkedAt;
      nodes.push(Alert({ variant: 'ok', title: t('revc.good.title'), message: checked ? t('revc.good.body', { time: formatRelative(checked, now()) }) : t('revc.good.bodyNoTime') }));
    } else if (r.status === 'revoked') {
      const when = r.revocation && r.revocation.time;
      nodes.push(Alert({
        variant: 'error',
        title: when ? t('revc.revoked.title', { date: formatDateTime(when, { utc: true }) }) : t('revc.revoked.titleNoDate'),
        message: t('revc.revoked.body', { reason: reasonLabel(r.revocation && r.revocation.reason) })
      }));
      if (r.problemReporting) nodes.push(ProblemReporting(r.problemReporting));
    } else if (r.status === 'not-found') {
      nodes.push(Alert({ variant: 'info', title: t('revc.notFound.title'), message: t('revc.notFound.body') }));
      if (r.truncated) nodes.push(h('p', { class: 'muted text-sm' }, t('revc.notFound.truncated', { name: r.name, count: REVOCATION_MAX_PAGES })));
    } else if (r.status === 'rate-limited') {
      const reset = r.quota && r.quota.resetAt;
      nodes.push(Alert({ variant: 'warn', compact: true, message: reset ? t('revc.limited', { time: formatDateTime(reset) }) : t('revc.limitedNoTime') }));
    } else if (r.status === 'expired' || r.status === 'no-name') {
      nodes.push(Alert({ variant: 'info', compact: true, message: t(r.status === 'expired' ? 'revc.expired' : 'revc.noName') }));
    } else {
      nodes.push(ErrorBanner({ message: r.error || '', kind: r.errorKind }, { title: t('revc.failed'), compact: true }));
    }
    if (r.matchedBy === 'issuance') nodes.push(h('p', { class: 'muted text-sm', dataset: { note: 'by-issuance' } }, t('revc.byIssuance')));
    return nodes;
  }

  function run() {
    const prev = cache.get(cacheKey);
    if (prev && prev.status === 'running') {
      show(prev);
      return;
    }
    if (!ctx.requireOnline()) return;
    // Its own controller, not the view's signal: a re-mount (language, another tab) keeps it running.
    const entry = { status: 'running', watchers: new Set(), controller: new AbortController() };
    cache.set(cacheKey, entry);
    show(entry);
    checkRevocation(cert, { signal: entry.controller.signal, now: now() }).then((result) => {
      Object.assign(entry, { status: 'done', result });
    }, (err) => {
      if (errorKind(err) === 'abort') {
        if (cache.get(cacheKey) === entry) cache.delete(cacheKey);
        entry.status = 'aborted';
      } else {
        Object.assign(entry, { status: 'error', error: err });
      }
    }).then(() => {
      const watchers = [...entry.watchers];
      entry.watchers.clear();
      for (const w of watchers) w(entry.status === 'aborted' ? null : entry);
    });
  }

  show(canAsk ? cache.get(cacheKey) || null : null);
  return card;
}
