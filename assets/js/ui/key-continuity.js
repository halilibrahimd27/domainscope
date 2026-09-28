/**
 * ui/key-continuity.js — Certificate › CT logs › "Key continuity": was this certificate's key
 * carried over renewals, or is it new with this certificate? (lib/keycontinuity.js)
 *
 * The public key's SHA-256 is computed in the browser and shown at once; crt.sh is asked for the
 * other certificates with that key only when the user presses the button (only the hash is sent).
 * The answer says whether the key was reused and for how long, or rotated, and what that means
 * for TLSA `3 1 1` records (a button opens the DANE / TLSA tab) and for HPKP-style pins. The
 * result is kept per certificate in the cache the view passes in, for the page session only.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, Card, CopyButton, DataTable, ErrorBanner, ExternalLink, Spinner } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { lookupKeyContinuity, spkiSha256, KEY_MAX_ROWS } from '../lib/keycontinuity.js';
import { errorKind } from '../lib/util.js';

registerStrings('en', {
  'key.title': 'Key continuity',
  'key.intro': 'Is this certificate’s public key in other logged certificates? A key carried over renewals keeps TLSA 3 1 1 records and key pins matching; a new key breaks them at the renewal.',
  'key.spki': 'Public key SHA-256',
  'key.computing': 'Computing…',
  'key.run': 'Look this key up in CT',
  'key.rerun': 'Look up again',
  'key.sends': 'Sends only this hash to crt.sh.',
  'key.searching': 'Searching crt.sh for certificates with this key… this can take up to a minute.',
  'key.failed': 'crt.sh did not answer',
  'key.failedHint': 'crt.sh is often busy; try again in a minute.',
  'key.offline': 'You are offline: nothing was sent.',
  'key.reused.title': 'Key reused across renewals',
  'key.reused.body': { one: 'This key is in {count} other logged certificate: in use since {since} ({days}), {before} issued before this one and {after} after it.', other: 'This key is in {count} other logged certificates: in use since {since} ({days}), {before} issued before this one and {after} after it.' },
  'key.single.title': 'New key with this certificate',
  'key.single.body': 'No other logged certificate has this key: it was rotated when this certificate was issued (or this is the first certificate for it).',
  'key.notLogged.title': 'No logged certificate has this key',
  'key.notLogged.body': 'Certificates of a private CA are never logged, and a new public certificate can take a few hours to appear on crt.sh.',
  'key.notThis': 'This certificate itself is not among them yet (logs can lag a few hours).',
  'key.days': { one: '{count} day', other: '{count} days' },
  'key.tlsa.reused': 'TLSA 3 1 1: a record for this key keeps matching as long as the next certificate reuses the key. A renewal with a new key breaks it unless the new record is published 2 × TTL before the new certificate is installed.',
  'key.tlsa.single': 'TLSA 3 1 1: the key changes with each renewal like this one, so the record must change too — publish the next key’s record 2 × TTL before installing, or pin the issuing CA (2 1 1) instead.',
  'key.pin.reused': 'Key pinning (HPKP-style, e.g. in a mobile app): a pin of this key survives renewals only while the key is reused; rotating it later breaks the pin unless the app also pins a backup key or the CA. A key that never changes stays useful to anyone who copied it for as long as it is in use.',
  'key.pin.single': 'Key pinning (HPKP-style, e.g. in a mobile app): a pin of the leaf key breaks at each rotation like this one; pin a backup key or the issuing CA instead.',
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
  'key.intro': 'Bu sertifikanın açık anahtarı kayıtlı başka sertifikalarda da var mı? Yenilemelerde korunan bir anahtar TLSA 3 1 1 kayıtlarını ve anahtar sabitlemelerini (pin) eşleşir tutar; yeni bir anahtar ise yenilemede bunları bozar.',
  'key.spki': 'Açık anahtar SHA-256',
  'key.computing': 'Hesaplanıyor…',
  'key.run': 'Bu anahtarı CT’de ara',
  'key.rerun': 'Yeniden ara',
  'key.sends': 'crt.sh’e yalnızca bu özet gönderilir.',
  'key.searching': 'crt.sh’te bu anahtarı taşıyan sertifikalar aranıyor… bir dakikayı bulabilir.',
  'key.failed': 'crt.sh yanıt vermedi',
  'key.failedHint': 'crt.sh çoğu zaman yoğundur; bir dakika sonra yeniden deneyin.',
  'key.offline': 'Çevrimdışısınız: hiçbir şey gönderilmedi.',
  'key.reused.title': 'Anahtar yenilemelerde yeniden kullanılmış',
  'key.reused.body': { other: 'Bu anahtar kayıtlı {count} başka sertifikada daha var: {since} tarihinden beri kullanılıyor ({days}); {before} tanesi bundan önce, {after} tanesi sonra verilmiş.' },
  'key.single.title': 'Bu sertifikayla gelen yeni anahtar',
  'key.single.body': 'Bu anahtar kayıtlı başka hiçbir sertifikada yok: bu sertifika verilirken anahtar değiştirilmiş (ya da bu, anahtarın ilk sertifikası).',
  'key.notLogged.title': 'Bu anahtarı taşıyan kayıtlı sertifika yok',
  'key.notLogged.body': 'Özel bir CA’nın sertifikaları hiçbir zaman kayda geçmez; yeni bir genel sertifikanın crt.sh’te görünmesi de birkaç saat sürebilir.',
  'key.notThis': 'Bu sertifikanın kendisi henüz aralarında değil (kayıtlar birkaç saat geriden gelebilir).',
  'key.days': { other: '{count} gün' },
  'key.tlsa.reused': 'TLSA 3 1 1: bu anahtarın kaydı, sonraki sertifika da aynı anahtarı kullandıkça eşleşmeye devam eder. Yeni anahtarlı bir yenileme, yeni kayıt yeni sertifika kurulmadan 2 × TTL önce yayımlanmadıysa onu bozar.',
  'key.tlsa.single': 'TLSA 3 1 1: bunun gibi her yenilemede anahtar değişir, kayıt da onunla değişmelidir — sonraki anahtarın kaydını kurulumdan 2 × TTL önce yayımlayın ya da bunun yerine sertifikayı veren CA’yı sabitleyin (2 1 1).',
  'key.pin.reused': 'Anahtar sabitleme (HPKP tarzı, ör. bir mobil uygulamada): bu anahtarın sabitlemesi, anahtar yeniden kullanıldıkça yenilemelerden sağ çıkar; anahtar sonradan değişirse uygulama yedek bir anahtarı ya da CA’yı da sabitlemediyse bozulur. Hiç değişmeyen bir anahtar, onu kopyalayan biri için kullanımda kaldığı sürece işe yarar.',
  'key.pin.single': 'Anahtar sabitleme (HPKP tarzı, ör. bir mobil uygulamada): uç sertifika anahtarının sabitlemesi bunun gibi her değişimde bozulur; bunun yerine yedek bir anahtarı ya da sertifikayı veren CA’yı sabitleyin.',
  'key.openDane': 'DANE / TLSA sekmesini aç',
  'key.truncated': { other: 'crt.sh {count} kayıttan fazlasını listeledi; ilk {count} tanesi okundu.' },
  'key.col.id': 'crt.sh kimliği',
  'key.col.issuer': 'Veren',
  'key.col.from': 'Geçerlilik başlangıcı',
  'key.col.to': 'Geçerlilik sonu',
  'key.this': 'Bu sertifika'
});

/**
 * The key continuity card of one certificate.
 * @param {{ cert: object, ctx: import('../app.js').ViewContext, cache: Map<string, object>, cacheKey: string,
 *   onOpenDane?: (() => void)|null }} opts cert: a lib/x509.js Certificate; cache / cacheKey: where the
 *   lookup of this certificate is kept (`{ status: 'running'|'done'|'error', result?, error?, watchers }`)
 * @returns {HTMLElement}
 */
export function KeyContinuityCard({ cert, ctx, cache, cacheKey, onOpenDane = null }) {
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

  function resultNodes(r) {
    card.dataset.status = r.status;
    const nodes = [];
    if (r.status === 'reused') {
      nodes.push(Alert({
        variant: 'info',
        icon: 'refresh',
        title: t('key.reused.title'),
        message: t('key.reused.body', {
          count: r.others, since: formatDate(r.firstSeen), days: t('key.days', { count: r.days ?? 0 }),
          before: formatNumber(r.before), after: formatNumber(r.after)
        })
      }));
    } else if (r.status === 'single') {
      nodes.push(Alert({ variant: 'info', icon: 'key', title: t('key.single.title'), message: t('key.single.body') }));
    } else {
      nodes.push(Alert({ variant: 'info', title: t('key.notLogged.title'), message: t('key.notLogged.body') }));
    }
    const alert = nodes[0];
    alert.dataset.keyStatus = r.status;
    if (r.status !== 'not-logged') {
      if (!r.thisLogged) nodes.push(h('p', { class: 'muted text-sm' }, t('key.notThis')));
      const which = r.status === 'reused' ? 'reused' : 'single';
      nodes.push(h('ul', { class: 'cert-key-effects' },
        h('li', { dataset: { effect: 'tlsa' } }, t(`key.tlsa.${which}`)),
        h('li', { dataset: { effect: 'pin' } }, t(`key.pin.${which}`))));
      if (onOpenDane) {
        nodes.push(h('div', null, Button({ label: t('key.openDane'), icon: 'key', size: 'sm', variant: 'secondary', dataset: { action: 'key-dane' }, onClick: onOpenDane })));
      }
      nodes.push(DataTable({
        caption: t('key.title'),
        rows: r.certs,
        dense: true,
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
    const entry = { status: 'running', watchers: new Set() };
    cache.set(cacheKey, entry);
    show(entry);
    lookupKeyContinuity(cert, { signal: ctx.signal }).then((result) => {
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
