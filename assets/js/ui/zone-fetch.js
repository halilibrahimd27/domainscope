/**
 * ui/zone-fetch.js — Zone File › "Fetch from deSEC or DigitalOcean": read the zone from the DNS
 * provider's API with an API token the user pastes (lib/zonefetch.js), then hand the provider's JSON
 * to the importer like a pasted listing (lib/zoneparse.js formats `desec-api` / `digitalocean-api`).
 *
 * The token: a password field read once when Fetch is pressed and emptied at that moment; the value
 * then lives only in the running fetch (lib/zonefetch.js), which sends it to the provider's API host
 * in the Authorization header and drops it when it ends. It is never put in this module's memory,
 * the DOM, a URL, browser storage, a workspace, a log or a message. What this module remembers for
 * the page session: the provider picked and the zone typed (never the token), and the running job
 * (to show its progress again after the importer is drawn anew, and to stop it).
 *
 * Nothing is sent before the click. One fetch at a time; Forget, another workspace, "Delete all
 * local data" and leaving the view stop it ({@link stopZoneFetch}).
 */

import { h, clear } from './dom.js';
import { Alert, Button, Disclosure, ExternalLink, SegmentedControl, Spinner, announce, textInput } from './components.js';
import { registerStrings, t, formatNumber } from '../i18n.js';
import { ZONE_PROVIDERS, getZoneProvider, fetchZone, zoneName, cleanToken } from '../lib/zonefetch.js';

registerStrings('en', {
  'zone.fetch.summary': 'Fetch from deSEC or DigitalOcean',
  'zone.fetch.intro': 'Read the zone straight from your DNS provider’s API with an API token. A read-only token is enough: this page only reads.',
  'zone.fetch.provider': 'Provider',
  'zone.fetch.domain': 'Zone',
  'zone.fetch.token': 'API token',
  'zone.fetch.privacy': 'Your token is sent only to {host}, in a request header, for this one fetch. It stays in this tab’s memory for that request only: it is never saved (not in the browser, not in a workspace), never logged, and this field is emptied as soon as you press Fetch zone.',
  'zone.fetch.how.desec': 'Create a token under Token management at deSEC. deSEC tokens can always read; to make one read-only, give it a default policy without write permission and leave “manage tokens”, “create domains” and “delete domains” off. An expiry (max age) of a day is enough.',
  'zone.fetch.how.digitalocean': 'Create a token under API › Tokens at DigitalOcean with Custom scopes and only domain: read (a Read Only token works too). An expiry of a day is enough.',
  'zone.fetch.link.desec.token': 'deSEC token management',
  'zone.fetch.link.desec.docs': 'Token policies',
  'zone.fetch.link.digitalocean.token': 'DigitalOcean API tokens',
  'zone.fetch.link.digitalocean.docs': 'Token scopes',
  'zone.fetch.go': 'Fetch zone',
  'zone.fetch.stop': 'Stop',
  'zone.fetch.running': 'Reading the zone from {provider}…',
  'zone.fetch.progress.desec': { one: '{records} record sets read · {count} request', other: '{records} record sets read · {count} requests' },
  'zone.fetch.progress.digitalocean': { one: '{records} records read · {count} request', other: '{records} records read · {count} requests' },
  'zone.fetch.waiting': '{provider} asks to slow down: waiting {seconds} s before the next request.',
  'zone.fetch.done': { one: '{count} record set read from {provider}.', other: '{count} record sets read from {provider}.' },
  'zone.fetch.doneRecords': { one: '{count} record read from {provider}.', other: '{count} records read from {provider}.' },
  'zone.fetch.file': '{provider} API · {domain}',
  'zone.fetch.stopped': 'Stopped. Nothing was imported.',
  'zone.fetch.err.title': 'The zone could not be fetched',
  'zone.fetch.err.provider': 'Choose a provider.',
  'zone.fetch.err.domain': 'Enter the zone name, for example example.com.',
  'zone.fetch.err.token': 'Paste the API token: one line without spaces, 16 to 512 characters.',
  'zone.fetch.err.auth.desec': '{provider} did not accept the token (HTTP 401): it is wrong, expired or revoked, or limited to other IP networks. Create a new one and paste it again.',
  'zone.fetch.err.auth.digitalocean': '{provider} did not accept the token (HTTP 401): it is wrong, expired or revoked. Create a new one and paste it again.',
  'zone.fetch.err.forbidden.desec': 'deSEC refused the token (HTTP 403). A login token of the web interface needs multi-factor authentication: create an API token instead.',
  'zone.fetch.err.forbidden.digitalocean': 'DigitalOcean refused the token (HTTP 403): it does not have the domain: read scope. Create a token with Custom scopes › domain › read.',
  'zone.fetch.err.not-found': '{provider} has no zone {domain} in the account of this token (HTTP 404). Check the spelling and that the domain is in this account.',
  'zone.fetch.err.rate-limited': '{provider} is limiting this token’s requests (HTTP 429). Try again in {seconds} s.',
  'zone.fetch.err.http': '{provider} answered HTTP {status}.',
  'zone.fetch.err.network': '{provider} could not be reached. The network, a firewall or a browser extension may be blocking {host}.',
  'zone.fetch.err.timeout': '{provider} did not answer in time. Try again.',
  'zone.fetch.err.response': '{provider} sent something that is not a record listing.',
  'zone.fetch.err.detail': '{provider} said: “{detail}”',
  'zone.fetch.err.again': 'The token field was emptied: paste the token again to retry.'
});

registerStrings('tr', {
  'zone.fetch.summary': 'deSEC ya da DigitalOcean’dan getir',
  'zone.fetch.intro': 'Zone’u bir API anahtarıyla doğrudan DNS sağlayıcınızın API’sinden okuyun. Salt okunur bir anahtar yeterli: bu sayfa yalnızca okur.',
  'zone.fetch.provider': 'Sağlayıcı',
  'zone.fetch.domain': 'Zone',
  'zone.fetch.token': 'API anahtarı',
  'zone.fetch.privacy': 'Anahtarınız bir istek başlığında, bu tek okuma için yalnızca {host} adresine gönderilir. Okuma sürdükçe bu sekmenin belleğinde durur: hiçbir yere kaydedilmez (ne tarayıcıya ne bir çalışma alanına), günlüğe yazılmaz ve Zone’u getir’e bastığınız anda bu alan boşaltılır.',
  'zone.fetch.how.desec': 'Anahtarı deSEC’te Token management bölümünde oluşturun. deSEC anahtarları her zaman okuyabilir; birini salt okunur yapmak için ona yazma izni olmayan bir varsayılan politika verin ve “manage tokens”, “create domains”, “delete domains” izinlerini kapalı bırakın. Bir günlük geçerlilik süresi (max age) yeterli.',
  'zone.fetch.how.digitalocean': 'Anahtarı DigitalOcean’da API › Tokens bölümünde Custom scopes seçip yalnızca domain: read izniyle oluşturun (Read Only bir anahtar da olur). Bir günlük geçerlilik süresi yeterli.',
  'zone.fetch.link.desec.token': 'deSEC anahtar yönetimi',
  'zone.fetch.link.desec.docs': 'Anahtar politikaları',
  'zone.fetch.link.digitalocean.token': 'DigitalOcean API anahtarları',
  'zone.fetch.link.digitalocean.docs': 'Anahtar izinleri',
  'zone.fetch.go': 'Zone’u getir',
  'zone.fetch.stop': 'Durdur',
  'zone.fetch.running': 'Zone {provider} üzerinden okunuyor…',
  'zone.fetch.progress.desec': { other: '{records} kayıt kümesi okundu · {count} istek' },
  'zone.fetch.progress.digitalocean': { other: '{records} kayıt okundu · {count} istek' },
  'zone.fetch.waiting': '{provider} yavaşlamamızı istiyor: sonraki istekten önce {seconds} sn bekleniyor.',
  'zone.fetch.done': { other: '{provider} üzerinden {count} kayıt kümesi okundu.' },
  'zone.fetch.doneRecords': { other: '{provider} üzerinden {count} kayıt okundu.' },
  'zone.fetch.file': '{provider} API · {domain}',
  'zone.fetch.stopped': 'Durduruldu. Hiçbir şey içe aktarılmadı.',
  'zone.fetch.err.title': 'Zone getirilemedi',
  'zone.fetch.err.provider': 'Bir sağlayıcı seçin.',
  'zone.fetch.err.domain': 'Zone adını girin, örneğin example.com.',
  'zone.fetch.err.token': 'API anahtarını yapıştırın: boşluksuz tek satır, 16 ile 512 karakter arası.',
  'zone.fetch.err.auth.desec': '{provider} anahtarı kabul etmedi (HTTP 401): anahtar yanlış, süresi dolmuş, iptal edilmiş ya da başka IP ağlarıyla sınırlanmış. Yeni bir anahtar oluşturup yeniden yapıştırın.',
  'zone.fetch.err.auth.digitalocean': '{provider} anahtarı kabul etmedi (HTTP 401): anahtar yanlış, süresi dolmuş ya da iptal edilmiş. Yeni bir anahtar oluşturup yeniden yapıştırın.',
  'zone.fetch.err.forbidden.desec': 'deSEC anahtarı reddetti (HTTP 403). Web arayüzünün oturum anahtarı çok adımlı doğrulama ister: bunun yerine bir API anahtarı oluşturun.',
  'zone.fetch.err.forbidden.digitalocean': 'DigitalOcean anahtarı reddetti (HTTP 403): anahtarda domain: read izni yok. Custom scopes › domain › read ile bir anahtar oluşturun.',
  'zone.fetch.err.not-found': '{provider}, bu anahtarın hesabında {domain} adlı bir zone bulamadı (HTTP 404). Yazımı ve alan adının bu hesapta olduğunu kontrol edin.',
  'zone.fetch.err.rate-limited': '{provider} bu anahtarın isteklerini sınırlıyor (HTTP 429). {seconds} sn sonra yeniden deneyin.',
  'zone.fetch.err.http': '{provider} HTTP {status} ile yanıt verdi.',
  'zone.fetch.err.network': '{provider} sunucusuna ulaşılamadı. Ağ, bir güvenlik duvarı ya da bir tarayıcı eklentisi {host} adresini engelliyor olabilir.',
  'zone.fetch.err.timeout': '{provider} zamanında yanıt vermedi. Yeniden deneyin.',
  'zone.fetch.err.response': '{provider} kayıt listesi olmayan bir yanıt gönderdi.',
  'zone.fetch.err.detail': '{provider} yanıtı: “{detail}”',
  'zone.fetch.err.again': 'Anahtar alanı boşaltıldı: tekrar denemek için anahtarı yeniden yapıştırın.'
});

/** Error codes whose text depends on the provider (`zone.fetch.err.<code>.<provider>`). */
const PER_PROVIDER = new Set(['auth', 'forbidden']);

/**
 * The i18n key of a fetch error.
 * @param {string} code lib/zonefetch.js ZONE_FETCH_ERRORS
 * @param {string} provider
 * @returns {string}
 */
export function fetchErrorKey(code, provider) {
  return PER_PROVIDER.has(code) ? `zone.fetch.err.${code}.${provider}` : `zone.fetch.err.${code}`;
}

/** Every i18n key this module can build from a library code (for the coverage test). */
export function generatedKeys() {
  const keys = [];
  for (const p of ZONE_PROVIDERS) {
    keys.push(`zone.fetch.how.${p.id}`, `zone.fetch.link.${p.id}.token`, `zone.fetch.link.${p.id}.docs`, `zone.fetch.progress.${p.id}`);
    for (const code of ['provider', 'domain', 'token', 'auth', 'forbidden', 'not-found', 'rate-limited', 'http', 'network', 'timeout', 'response']) {
      keys.push(fetchErrorKey(code, p.id));
    }
  }
  return [...new Set(keys)];
}

/** Host name of an API base. */
const hostOf = (url) => new URL(url).host;

/**
 * Page-session memory: the provider picked and the zone typed (never the token), the running job and
 * the last outcome. `paint` redraws the panel that is on the page now.
 */
const memo = { provider: ZONE_PROVIDERS[0].id, domain: '', job: null, error: null, notice: null, paint: null, status: null };

/** Stop a running fetch (Forget, another workspace, "Delete all local data", leaving the view). */
export function stopZoneFetch() {
  if (memo.job) memo.job.controller.abort();
  memo.job = null;
  memo.error = null;
  memo.notice = null;
}

/** Is a fetch running? */
export function zoneFetchRunning() {
  return !!memo.job;
}

/**
 * The fetch panel of the Zone File importer.
 * @param {{ domainHint?: string, open?: boolean, onZone: (z: { name: string, text: string, origin: string, provider: string }) => void }} opts
 *   onZone: called with the provider's listing when a fetch succeeds
 * @returns {HTMLElement}
 */
export function ZoneFetchPanel({ domainHint = '', open = false, onZone }) {
  if (!memo.domain && domainHint) memo.domain = domainHint;
  const body = h('div', { class: 'stack-sm zone-fetch-body', dataset: { shortcutScope: 'zone-fetch' } });
  const panel = Disclosure({
    summary: t('zone.fetch.summary'),
    className: 'zone-fetch',
    open: open || !!memo.job || !!memo.error,
    children: body
  });

  /** The control that has the keyboard focus in the panel, as a selector that finds it again after a repaint. */
  const focusKey = () => {
    const el = document.activeElement;
    if (!el || !body.contains(el)) return null;
    if (el.dataset.role) return `[data-role="${el.dataset.role}"]`;
    if (el.dataset.action) return `[data-action="${el.dataset.action}"]`;
    if (el.classList.contains('seg-btn') && el.dataset.value) return `.seg-btn[data-value="${el.dataset.value}"]`;
    return null;
  };
  /** Is the focus in the panel, or nowhere (a click on a button that is gone)? Then the panel may move it. */
  const focusHere = () => !document.activeElement || document.activeElement === document.body || body.contains(document.activeElement);
  let statusEl = null;

  /**
   * Rebuild the panel. The keyboard focus goes back to the control that had it (the provider, a
   * field, a button) or to `focus` (a selector); Stop, gone once a fetch ends, hands it to Fetch zone.
   */
  function paint({ focus = null } = {}) {
    const keep = focus || focusKey();
    clear(body);
    const provider = getZoneProvider(memo.provider) || ZONE_PROVIDERS[0];
    const running = !!memo.job;
    const providerControl = SegmentedControl({
      label: t('zone.fetch.provider'),
      size: 'sm',
      value: provider.id,
      options: ZONE_PROVIDERS.map((p) => ({ value: p.id, label: p.name })),
      onChange: (v) => {
        if (memo.job) return;
        memo.provider = v;
        memo.error = null;
        paint();
      }
    });
    const domainField = textInput({
      label: t('zone.fetch.domain'),
      value: memo.domain,
      placeholder: 'example.com',
      mono: true,
      attrs: { 'data-role': 'zone-fetch-domain', inputmode: 'url' },
      onInput: (v) => {
        memo.domain = String(v || '');
      },
      onEnter: () => start()
    });
    // A password field: never echoed, never autofilled or offered for saving; read once on Fetch.
    const tokenField = textInput({
      label: t('zone.fetch.token'),
      type: 'password',
      mono: true,
      autocomplete: 'off',
      attrs: { 'data-role': 'zone-fetch-token', 'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-form-type': 'other' },
      onEnter: () => start()
    });
    const go = Button({
      label: t('zone.fetch.go'),
      icon: 'download',
      variant: 'primary',
      size: 'sm',
      disabled: running,
      dataset: { action: 'zone-fetch', shortcut: 'submit' },
      onClick: () => start()
    });
    const stop = running ? Button({
      label: t('zone.fetch.stop'),
      icon: 'x',
      size: 'sm',
      dataset: { action: 'zone-fetch-stop', shortcut: 'cancel' },
      onClick: () => {
        stopZoneFetch();
        memo.notice = t('zone.fetch.stopped');
        paint({ focus: '[data-action="zone-fetch"]' });
      }
    }) : null;

    /** Read the fields, empty the token field at once, and run one fetch. */
    function start() {
      if (memo.job) return;
      const raw = tokenField.value;
      tokenField.value = '';
      // `cleared`: a token had been pasted, and is gone now: the error says to paste it again.
      const cleared = raw.length > 0;
      memo.domain = domainField.value.trim();
      memo.error = null;
      memo.notice = null;
      const zone = zoneName(memo.domain);
      if (!zone) {
        memo.error = { code: 'domain', provider: provider.id, params: {}, cleared };
        paint({ focus: '[data-role="zone-fetch-domain"]' });
        return;
      }
      if (!cleanToken(raw)) {
        memo.error = { code: 'token', provider: provider.id, params: {}, cleared };
        paint({ focus: '[data-role="zone-fetch-token"]' });
        return;
      }
      const controller = new AbortController();
      const job = { controller, provider: provider.id, domain: zone, progress: null };
      memo.job = job;
      paint({ focus: '[data-action="zone-fetch-stop"]' });
      announce(t('zone.fetch.running', { provider: provider.name }));
      fetchZone(provider.id, zone, raw, {
        signal: controller.signal,
        onProgress: (p) => {
          job.progress = p;
          // Only the status line: a rebuild would take the focus from Stop.
          if (memo.job === job && memo.status) memo.status();
        }
      }).then((out) => {
        if (memo.job !== job) return;
        memo.job = null;
        memo.notice = t(out.provider === 'desec' ? 'zone.fetch.done' : 'zone.fetch.doneRecords', { count: out.records, provider: provider.name });
        announce(memo.notice);
        onZone({ name: t('zone.fetch.file', { provider: provider.name, domain: out.domain }), text: out.text, origin: out.domain, provider: out.provider });
      }, (err) => {
        if (memo.job !== job) return;
        memo.job = null;
        if (err && err.name === 'AbortError') return;
        memo.error = { code: err && err.code ? err.code : 'network', provider: provider.id, domain: zone, params: (err && err.params) || {}, cleared: true };
        if (memo.paint) memo.paint(focusHere() ? { focus: '[data-role="zone-fetch-token"]' } : {});
        announce(t('zone.fetch.err.title'));
      });
    }

    const links = h('div', { class: 'cluster zone-fetch-links' },
      ExternalLink(provider.tokenUrl, t(`zone.fetch.link.${provider.id}.token`)),
      ExternalLink(provider.docsUrl, t(`zone.fetch.link.${provider.id}.docs`)));
    body.append(
      h('p', { class: 'text-sm' }, t('zone.fetch.intro')),
      h('div', { class: 'cluster zone-fetch-provider' }, h('span', { class: 'text-sm muted' }, t('zone.fetch.provider')), providerControl.el),
      h('div', { class: 'zone-fetch-fields' }, domainField.el, tokenField.el),
      h('p', { class: 'text-sm muted zone-fetch-how' }, t(`zone.fetch.how.${provider.id}`)),
      links,
      h('div', { class: 'zone-fetch-privacy' },
        Alert({ variant: 'info', icon: 'lock', compact: true, message: t('zone.fetch.privacy', { host: hostOf(provider.api) }) })),
      h('div', { class: 'cluster' }, go, stop),
      statusEl = h('div', { class: 'zone-fetch-status' }));
    fillStatus(provider);
    if (running) domainField.input.disabled = true;
    if (running) tokenField.input.disabled = true;
    const again = keep ? body.querySelector(keep) : null;
    if (again && !again.disabled) again.focus();
  }

  /** Progress, the last error or notice, in the status element (filled in place). */
  function fillStatus(provider) {
    const el = statusEl;
    clear(el);
    el.className = 'zone-fetch-status';
    el.hidden = false;
    delete el.dataset.code;
    const job = memo.job;
    if (job) {
      const p = job.progress;
      const lines = [h('span', null, t('zone.fetch.running', { provider: provider.name }))];
      if (p && p.phase === 'wait') {
        lines.push(h('span', { class: 'muted' }, t('zone.fetch.waiting', { provider: provider.name, seconds: formatNumber(Math.ceil(p.waitMs / 1000)) })));
      } else if (p) {
        const records = p.total !== null && p.total !== undefined ? `${formatNumber(p.records)} / ${formatNumber(p.total)}` : formatNumber(p.records);
        lines.push(h('span', { class: 'muted' }, t(`zone.fetch.progress.${provider.id}`, { records, count: p.requests })));
      }
      el.dataset.state = 'running';
      el.append(Spinner({ label: t('zone.fetch.running', { provider: provider.name }) }), h('div', { class: 'stack-xs' }, lines));
      return;
    }
    if (memo.error) {
      const e = memo.error;
      const name = (getZoneProvider(e.provider) || provider).name;
      const host = hostOf((getZoneProvider(e.provider) || provider).api);
      const params = { provider: name, host, domain: e.domain || memo.domain, status: e.params.status ?? '', seconds: formatNumber(e.params.retryAfterS ?? 60) };
      const extra = [];
      if (e.params.detail) extra.push(h('p', { class: 'text-sm' }, t('zone.fetch.err.detail', { provider: name, detail: e.params.detail })));
      if (e.cleared) extra.push(h('p', { class: 'text-sm muted' }, t('zone.fetch.err.again')));
      el.dataset.state = 'error';
      el.dataset.code = e.code;
      el.append(Alert({
        variant: 'error',
        title: t('zone.fetch.err.title'),
        message: t(fetchErrorKey(e.code, e.provider), params),
        children: extra.length ? h('div', { class: 'stack-xs' }, extra) : null
      }));
      return;
    }
    if (memo.notice) {
      el.dataset.state = 'notice';
      el.classList.add('muted', 'text-sm');
      el.append(memo.notice);
      return;
    }
    el.dataset.state = '';
    el.hidden = true;
  }

  memo.paint = (opts) => {
    if (body.isConnected) paint(opts);
  };
  memo.status = () => {
    if (body.isConnected && statusEl) fillStatus(getZoneProvider(memo.provider) || ZONE_PROVIDERS[0]);
  };
  paint();
  return panel;
}
