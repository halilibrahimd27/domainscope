/**
 * ui/key-continuity.js — Certificate › CT logs › "Key continuity": was this certificate's key
 * carried over renewals, or is it new with this certificate? (lib/keycontinuity.js)
 *
 * The public key's SHA-256 is computed in the browser and shown at once; crt.sh is asked for the
 * other certificates with that key only when the user presses the button (only the hash is sent).
 * The answer is worded as what crt.sh has, since its coverage is incomplete: the key reused and
 * for how long, no earlier certificate with it on crt.sh, or none at all — "not indexed yet" when
 * the certificate carries SCTs or comes from a public CA —, with what a reused or a changing key
 * means for TLSA `3 1 1` records (a button opens the DANE / TLSA tab) and for HPKP-style pins.
 *
 * The lookup runs on a controller of its own, kept with the result in the cache the view passes
 * in (page session only): leaving the view — to watch the request in About › What this page sent
 * — or switching the language does not stop it, and the card that is mounted when it ends shows
 * the answer. Loading another certificate stops it ({@link cancelKeyLookups}).
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, Card, CopyButton, DataTable, ErrorBanner, ExternalLink, Spinner } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { lookupKeyContinuity, spkiSha256, KEY_MAX_ROWS } from '../lib/keycontinuity.js';
import { errorKind } from '../lib/util.js';

registerStrings('en', {
  'key.title': 'Key continuity',
  'key.intro': 'Is this certificate’s public key in other certificates crt.sh has indexed? A key carried over renewals keeps TLSA 3 1 1 records and key pins matching; a new key breaks them at the renewal.',
  'key.spki': 'Public key SHA-256',
  'key.computing': 'Computing…',
  'key.run': 'Look this key up in CT',
  'key.rerun': 'Look up again',
  'key.sends': 'Sends only this hash to crt.sh.',
  'key.searching': 'Searching crt.sh for certificates with this key… this can take up to a minute.',
  'key.failed': 'crt.sh did not answer',
  'key.failedHint': 'crt.sh is often busy; try again in a minute.',
  'key.reused.title': 'Key reused across renewals',
  'key.reused.body': {
    one: 'crt.sh lists this key in {count} other certificate: in use since at least {since} ({days}), {before} issued before this one and {after} after it.',
    other: 'crt.sh lists this key in {count} other certificates: in use since at least {since} ({days}), {before} issued before this one and {after} after it.'
  },
  'key.single.title': 'No earlier certificate with this key on crt.sh',
  'key.single.body': 'crt.sh lists no other certificate with this key. The key may be new with this certificate (changed at the renewal, or its first certificate), or crt.sh lacks the earlier ones: its coverage is incomplete.',
  'key.notIndexed.title': 'Logged, but not on crt.sh yet',
  'key.notIndexed.scts': {
    one: 'This certificate carries {count} SCT, a log’s promise to publish it, so it was logged; crt.sh has no certificate with this key. crt.sh’s coverage is incomplete and can lag by days or weeks: look again later.',
    other: 'This certificate carries {count} SCTs, logs’ promises to publish it, so it was logged; crt.sh has no certificate with this key. crt.sh’s coverage is incomplete and can lag by days or weeks: look again later.'
  },
  'key.notIndexed.public': 'Its issuer is a public CA, which logs what it issues; crt.sh has no certificate with this key. crt.sh’s coverage is incomplete and can lag by days or weeks: look again later.',
  'key.notFound.title': 'crt.sh has no certificate with this key',
  'key.notFound.body': 'The certificate carries no SCTs and its issuer is not a known public CA: certificates of a private CA are never logged. A public certificate can be missing from crt.sh too, since its coverage is incomplete.',
  'key.notThis': 'crt.sh does not list this certificate itself: its coverage is incomplete and can lag by days or weeks.',
  'key.days': { one: '{count} day', other: '{count} days' },
  'key.tlsa.reused': 'TLSA 3 1 1: a record for this key keeps matching as long as the next certificate reuses the key. A renewal with a new key breaks it unless the new record is published 2 × TTL before the new certificate is installed.',
  'key.tlsa.single': 'TLSA 3 1 1: if the key did change with this certificate, expect the next renewal to change it too — publish the next key’s record 2 × TTL before installing it, or pin the issuing CA (2 1 1) instead.',
  'key.pin.reused': 'Key pinning (HPKP-style, e.g. in a mobile app): a pin of this key survives renewals only while the key is reused; rotating it later breaks the pin unless the app also pins a backup key or the CA. A key that never changes stays useful to anyone who copied it for as long as it is in use.',
  'key.pin.single': 'Key pinning (HPKP-style, e.g. in a mobile app): if the leaf key changes at renewals, a pin of it breaks at each one; pin a backup key or the issuing CA instead.',
  'key.openDane': 'Open the DANE / TLSA tab',
  'key.truncated': { one: 'crt.sh listed more than {count} entry; the first {count} were read.', other: 'crt.sh listed more than {count} entries; the first {count} were read.' },
  'key.col.id': 'crt.sh ID',
  'key.col.issuer': 'Issuer',
  'key.col.from': 'Valid from',
  'key.col.to': 'Valid until',
  'key.this': 'This certificate'
});

registerStrings('tr', {
  'key.title': 'Anahtar sürekliliği',
  'key.intro': 'Bu sertifikanın açık anahtarı crt.sh’in dizine eklediği başka sertifikalarda da var mı? Yenilemelerde korunan bir anahtar TLSA 3 1 1 kayıtlarını ve anahtar sabitlemelerini (pin) eşleşir tutar; yeni bir anahtar ise yenilemede bunları bozar.',
  'key.spki': 'Açık anahtar SHA-256',
  'key.computing': 'Hesaplanıyor…',
  'key.run': 'Bu anahtarı CT’de ara',
  'key.rerun': 'Yeniden ara',
  'key.sends': 'crt.sh’e yalnızca bu özet gönderilir.',
  'key.searching': 'crt.sh’te bu anahtarı taşıyan sertifikalar aranıyor… bir dakikayı bulabilir.',
  'key.failed': 'crt.sh yanıt vermedi',
  'key.failedHint': 'crt.sh çoğu zaman yoğundur; bir dakika sonra yeniden deneyin.',
  'key.reused.title': 'Anahtar yenilemelerde yeniden kullanılmış',
  'key.reused.body': { other: 'crt.sh bu anahtarı {count} başka sertifikada daha listeliyor: en az {since} tarihinden beri kullanılıyor ({days}); {before} tanesi bundan önce, {after} tanesi sonra verilmiş.' },
  'key.single.title': 'crt.sh’te bu anahtarla daha eski bir sertifika yok',
  'key.single.body': 'crt.sh bu anahtarı başka hiçbir sertifikada listelemiyor. Anahtar bu sertifikayla gelmiş olabilir (yenilemede değiştirilmiş ya da ilk sertifikası bu) ya da önceki sertifikalar crt.sh’te eksiktir: crt.sh’in kapsamı tam değildir.',
  'key.notIndexed.title': 'Kayda geçmiş, ama henüz crt.sh’te yok',
  'key.notIndexed.scts': { other: 'Bu sertifika {count} SCT taşıyor (bir kaydın onu yayımlama sözü), yani kayda geçmiş; crt.sh’te ise bu anahtarı taşıyan hiçbir sertifika yok. crt.sh’in kapsamı tam değildir ve günler, hatta haftalar geriden gelebilir: daha sonra yeniden bakın.' },
  'key.notIndexed.public': 'Sertifikayı veren, verdiklerini kayda geçiren genel bir CA; crt.sh’te ise bu anahtarı taşıyan hiçbir sertifika yok. crt.sh’in kapsamı tam değildir ve günler, hatta haftalar geriden gelebilir: daha sonra yeniden bakın.',
  'key.notFound.title': 'crt.sh’te bu anahtarı taşıyan sertifika yok',
  'key.notFound.body': 'Sertifika SCT taşımıyor ve vereni bilinen bir genel CA değil: özel bir CA’nın sertifikaları hiçbir zaman kayda geçmez. Kapsamı tam olmadığı için genel bir sertifika da crt.sh’te eksik olabilir.',
  'key.notThis': 'crt.sh bu sertifikanın kendisini listelemiyor: kapsamı tam değildir ve günler, hatta haftalar geriden gelebilir.',
  'key.days': { other: '{count} gün' },
  'key.tlsa.reused': 'TLSA 3 1 1: bu anahtarın kaydı, sonraki sertifika da aynı anahtarı kullandıkça eşleşmeye devam eder. Anahtarı değişen bir yenileme, yeni kayıt sertifikadan en az 2 × TTL önce yayımlanmadıysa onu bozar.',
  'key.tlsa.single': 'TLSA 3 1 1: anahtar bu sertifikayla gerçekten değiştiyse sonraki yenilemede de değişmesini bekleyin — sonraki anahtarın kaydını kurulumdan 2 × TTL önce yayımlayın ya da bunun yerine sertifikayı veren CA’yı sabitleyin (2 1 1).',
  'key.pin.reused': 'Anahtar sabitleme (HPKP tarzı, ör. bir mobil uygulamada): bu anahtarın sabitlemesi, anahtar yeniden kullanıldıkça yenilemelerden sağ çıkar; anahtar sonradan değişirse uygulama yedek bir anahtarı ya da CA’yı da sabitlemediyse bozulur. Hiç değişmeyen bir anahtar, onu kopyalayan biri için kullanımda kaldığı sürece işe yarar.',
  'key.pin.single': 'Anahtar sabitleme (HPKP tarzı, ör. bir mobil uygulamada): uç sertifika anahtarı yenilemelerde değişiyorsa onun sabitlemesi her değişimde bozulur; bunun yerine yedek bir anahtarı ya da sertifikayı veren CA’yı sabitleyin.',
  'key.openDane': 'DANE / TLSA sekmesini aç',
  'key.truncated': { other: 'crt.sh {count} kayıttan fazlasını listeledi; ilk {count} tanesi okundu.' },
  'key.col.id': 'crt.sh kimliği',
  'key.col.issuer': 'Veren',
  'key.col.from': 'Geçerlilik başlangıcı',
  'key.col.to': 'Geçerlilik sonu',
  'key.this': 'Bu sertifika'
});

/**
 * Stop every lookup of a cache that is still running (the view loads another certificate).
 * @param {Map<string, object>} cache the view's key continuity cache
 */
export function cancelKeyLookups(cache) {
  for (const entry of cache.values()) if (entry.status === 'running' && entry.controller) entry.controller.abort();
}

/**
 * The key continuity card of one certificate.
 * @param {{ cert: object, ctx: import('../app.js').ViewContext, cache: Map<string, object>, cacheKey: string,
 *   publicCa?: boolean, onOpenDane?: (() => void)|null }} opts cert: a lib/x509.js Certificate; cache / cacheKey:
 *   where the lookup of this certificate is kept (`{ status: 'running'|'done'|'error', controller, result?, error?,
 *   watchers }`); publicCa: its issuer is a known public CA (a certificate crt.sh lacks was still logged)
 * @returns {HTMLElement}
 */
export function KeyContinuityCard({ cert, ctx, cache, cacheKey, publicCa = false, onOpenDane = null }) {
  const spkiOut = h('code', { class: 'mono cert-key-spki-value', dataset: { role: 'key-spki' } }, t('key.computing'));
  spkiSha256(cert).then((hex) => { spkiOut.textContent = hex; }, () => { spkiOut.textContent = '—'; });
  const body = h('div', { class: 'stack-sm cert-key-body' });
  const runBtn = Button({ label: t('key.run'), icon: 'search', size: 'sm', dataset: { action: 'key-run' }, onClick: () => run() });
  const card = Card({
    title: t('key.title'),
    icon: 'key',
    className: 'cert-key-card',
    children: h('div', { class: 'stack-sm' },
      h('p', { class: 'muted text-sm' }, t('key.intro')),
      h('div', { class: 'cert-key-spki' }, h('span', { class: 'field-label' }, t('key.spki')), spkiOut,
        CopyButton(() => spkiOut.textContent, { iconOnly: true })),
      h('div', { class: 'cluster' }, runBtn, h('span', { class: 'muted text-sm' }, t('key.sends'))),
      body)
  });
  card.dataset.state = 'idle';

  const refresh = (entry) => {
    if (card.isConnected) show(entry);
  };

  function show(entry) {
    clear(body);
    card.dataset.state = entry ? entry.status : 'idle';
    runBtn.querySelector('.btn-label').textContent = entry && entry.status !== 'running' ? t('key.rerun') : t('key.run');
    runBtn.disabled = !!entry && entry.status === 'running';
    if (!entry) return;
    if (entry.status === 'running') {
      entry.watchers.add(refresh);
      body.append(Spinner({ label: t('key.searching'), showLabel: true }));
      return;
    }
    if (entry.status === 'error') {
      body.append(ErrorBanner(entry.error, { title: t('key.failed'), onRetry: () => run() }),
        h('p', { class: 'muted text-sm' }, t('key.failedHint')));
      return;
    }
    body.append(...resultNodes(entry.result));
  }

  /** The headline of a result: what crt.sh has, never more. */
  function headline(r) {
    if (r.status === 'reused') {
      return Alert({
        variant: 'info',
        icon: 'refresh',
        title: t('key.reused.title'),
        message: t('key.reused.body', {
          count: r.others, since: formatDate(r.firstSeen), days: t('key.days', { count: r.days ?? 0 }),
          before: formatNumber(r.before), after: formatNumber(r.after)
        })
      });
    }
    if (r.status === 'single') return Alert({ variant: 'info', icon: 'key', title: t('key.single.title'), message: t('key.single.body') });
    if (r.status === 'not-indexed') {
      return Alert({
        variant: 'info',
        title: t('key.notIndexed.title'),
        message: r.sctCount ? t('key.notIndexed.scts', { count: r.sctCount }) : t('key.notIndexed.public')
      });
    }
    return Alert({ variant: 'info', title: t('key.notFound.title'), message: t('key.notFound.body') });
  }

  function resultNodes(r) {
    card.dataset.status = r.status;
    const alert = headline(r);
    alert.dataset.keyStatus = r.status;
    const nodes = [alert];
    if (r.status === 'reused' || r.status === 'single') {
      if (!r.thisLogged) nodes.push(h('p', { class: 'muted text-sm' }, t('key.notThis')));
      nodes.push(h('ul', { class: 'cert-key-effects' },
        h('li', { dataset: { effect: 'tlsa' } }, t(`key.tlsa.${r.status}`)),
        h('li', { dataset: { effect: 'pin' } }, t(`key.pin.${r.status}`))));
      if (onOpenDane) {
        nodes.push(h('div', null, Button({ label: t('key.openDane'), icon: 'key', size: 'sm', variant: 'secondary', dataset: { action: 'key-dane' }, onClick: onOpenDane })));
      }
      nodes.push(DataTable({
        caption: t('key.title'),
        rows: r.certs,
        dense: true,
        cellLabels: true,
        rowKey: (c) => c.ids.join(',') || c.serialHex || '',
        className: 'cert-key-table',
        rowClass: (c) => (c.isThis ? 'cert-key-row-this' : null),
        columns: [
          {
            key: 'id', label: t('key.col.id'),
            render: (c) => h('span', { class: 'cluster cert-key-id' },
              c.ids.length ? ExternalLink(c.url, c.ids[0], { className: 'mono' }) : '—',
              c.isThis ? Badge(t('key.this'), { variant: 'accent' }) : null)
          },
          { key: 'issuer', label: t('key.col.issuer'), wrap: true },
          { key: 'notBefore', label: t('key.col.from'), sortable: true, render: (c) => formatDate(c.notBefore) },
          { key: 'notAfter', label: t('key.col.to'), sortable: true, render: (c) => formatDate(c.notAfter) }
        ]
      }).el);
    }
    if (r.truncated) nodes.push(h('p', { class: 'muted text-sm' }, t('key.truncated', { count: KEY_MAX_ROWS })));
    return nodes;
  }

  function run() {
    const prev = cache.get(cacheKey);
    if (prev && prev.status === 'running') {
      show(prev);
      return;
    }
    if (!ctx.requireOnline()) return;
    // Its own controller, not the view's signal: a re-mount (language, navigation) keeps it running.
    const entry = { status: 'running', watchers: new Set(), controller: new AbortController() };
    cache.set(cacheKey, entry);
    show(entry);
    lookupKeyContinuity(cert, { signal: entry.controller.signal, publicCa }).then((result) => {
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

  show(cache.get(cacheKey) || null);
  return card;
}
