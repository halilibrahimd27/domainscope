/**
 * ui/origin-map-panel.js — Servers › Origin map: the workspace's origin map (lib/originmap.js),
 * "which server and port really serves this proxied name".
 *
 * It sits next to the inventory (a tab of the Servers view) because both describe the
 * customer's own servers, belong to the workspace, work offline and feed the same tools: the
 * inventory says which addresses are yours, the map which of them serves a name a CDN hides.
 *
 * - The switch "Remember origins in this workspace" (off by default). While it is off nothing is
 *   written — not by Zone File, Verify, Retire an IP, a CLI report or the form here — and the
 *   panel says so; deleting entries always works.
 * - The entries: name, origin (address, with its port when not 443), server, source, when it was
 *   first seen and last confirmed, and whether it is stale (with why). Edit, delete, remove the
 *   stale ones, forget them all.
 * - Add or change one by hand.
 * - Import the CLI's `--json` reports (lib/originfill.js readCliReports, the Certificate estate's
 *   reader): a server answering UPDATED, NEEDS_UPDATE, ORIGIN_CERT or PRIVATE_CERT (a covering
 *   certificate) for a proxied name is remembered; a report that asked a remembered origin and did
 *   not find the name there marks that entry stale (one it did not ask stays as it is). A name counts as proxied when the map has it, the imported zone file
 *   or the last scan of this page session says so, or a server answered it with a Cloudflare
 *   Origin CA certificate; "Also names not known to be behind a CDN" takes every name.
 *
 * Nothing here reaches the network. Every string is rendered through h() / text nodes: names and
 * server names come from files.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, DataTable, FileDrop, IconButton, announce, checkbox, confirmDialog, textInput
} from './components.js';
import { t, registerStrings, formatDate, formatDateTime, formatNumber } from '../i18n.js';
import { state } from '../state.js';
import { originKey, originTarget, sanitizeOriginMap, ORIGIN_DEFAULT_PORT } from '../lib/originmap.js';
import { addManualOrigin, removeOrigins, setRemember, readCliReports } from '../lib/originfill.js';
import { keptHereOnly, originMap, recordOrigins, recordText, saveOrigins, serverOf, staleText, StaleBadge } from './origin-map.js';

/** Why the form refuses an entry (lib/originmap.js addManualOrigin). */
export const FORM_ERRORS = Object.freeze(['off', 'name', 'ip', 'port', 'limit']);

registerStrings('en', {
  'omp.privacy': 'The origin map stays in this browser, in the current workspace (IndexedDB). It leaves the browser only inside a workspace hand-over file you export yourself.',
  'omp.privacyMemory': 'Browser storage is unavailable, so the origin map is kept in this tab only and is gone when you close it. It is sent nowhere.',
  'omp.lead': 'Which server and port really serves a name behind a CDN, remembered once a CLI sweep, a zone file or a server comparison found it. Verify checks the remembered origins (and a zone file’s) again; a mere candidate is never remembered. Subdomains and SSL Targets rank these origins first and put them in the CLI command.',
  'omp.remember': 'Remember origins in this workspace',
  'omp.rememberHint': 'Off by default. While it is off nothing is written to this map.',
  'omp.offHere': 'Remembering is off: Zone File, Verify, Retire an IP, CLI reports and the form below write nothing here.',
  'omp.offKept': { one: 'The origin kept here is still used for hints until you delete it.', other: 'The {count} origins kept here are still used for hints until you delete them.' },
  'omp.stopTitle': 'Stop remembering origins?',
  'omp.stopBody': { one: 'Nothing new is written to the origin map. The origin it holds stays and is still used; delete it here when you no longer want it.', other: 'Nothing new is written to the origin map. The {count} origins it holds stay and are still used; delete them here when you no longer want them.' },
  'omp.stop': 'Stop remembering',
  'omp.count': { zero: 'No origins remembered yet.', one: '{count} origin · {stale} stale', other: '{count} origins · {stale} stale' },
  'omp.col.name': 'Name',
  'omp.col.origin': 'Origin',
  'omp.col.server': 'Server',
  'omp.col.source': 'Source',
  'omp.col.confirmed': 'Last confirmed',
  'omp.col.status': 'Status',
  'omp.col.actions': 'Actions',
  'omp.active': 'Active',
  'omp.firstSeen': 'First seen {date}',
  'omp.empty': 'Nothing remembered yet. Remember a zone file’s origins, import a CLI report, remember the new server of a comparison, or add one below.',
  'omp.edit': 'Edit {name} → {target}',
  'omp.delete': 'Delete {name} → {target}',
  'omp.deleted': 'Deleted {name} → {target}.',
  'omp.removeStale': { one: 'Remove the stale entry', other: 'Remove the {count} stale entries' },
  'omp.removedStale': { one: '{count} stale entry removed.', other: '{count} stale entries removed.' },
  'omp.forget': 'Forget the origin map',
  'omp.forgetConfirm': { one: 'Delete the origin remembered in this workspace? This cannot be undone.', other: 'Delete the {count} origins remembered in this workspace? This cannot be undone.' },
  'omp.forgotten': 'The origin map of this workspace is empty.',
  'omp.formTitle': 'Add an origin',
  'omp.formEditTitle': 'Change an origin',
  'omp.formSubtitle': 'A name behind a CDN and the server that really serves it.',
  'omp.f.name': 'Name',
  'omp.f.ip': 'Address',
  'omp.f.port': 'Port',
  'omp.f.server': 'Server',
  'omp.f.serverHint': 'Optional: taken from your inventory when the address is in it.',
  'omp.add': 'Add',
  'omp.save': 'Save',
  'omp.cancel': 'Cancel',
  'omp.added': 'Remembered {name} → {target}.',
  'omp.err.off': 'Turn on “Remember origins in this workspace” first.',
  'omp.err.name': 'Not a host name: shop.example.com, or *.example.com for the names directly under it.',
  'omp.err.ip': 'Not an IP address.',
  'omp.err.port': 'A port is a number from 1 to 65535.',
  'omp.err.limit': 'The origin map holds no more entries for this name, or in all. Delete some first.',
  'omp.importTitle': 'Import CLI reports',
  'omp.importSubtitle': 'The --json reports of ssl_origin_scan.py, read in this browser',
  'omp.importDrop': 'Drop the report.json files here',
  'omp.importHint': 'A server that answers UPDATED, NEEDS_UPDATE, ORIGIN_CERT or PRIVATE_CERT (a certificate covering the name) for a name behind a CDN is remembered. A report that asked a remembered origin and did not find the name there marks that entry stale; an origin the report did not ask stays as it is.',
  'omp.importAll': 'Also names not known to be behind a CDN',
  'omp.importAllHint': 'Otherwise only names the origin map, the imported zone file or the last scan in this tab show behind a CDN are added (and those a server answered with a Cloudflare Origin CA certificate).',
  'omp.importFile': '{file}: {text}',
  'omp.importError': '{file}: not read ({reason}).',
  'omp.file.too-large': 'larger than 64 MB',
  'omp.file.not-json': 'not JSON',
  'omp.file.not-report': 'not a report of ssl_origin_scan.py',
  'omp.file.version': 'a report of another CLI version, {version}',
  'omp.file.no-results': 'no results in it'
});

registerStrings('tr', {
  'omp.privacy': 'Origin haritası bu tarayıcıda, geçerli çalışma alanında (IndexedDB) kalır. Tarayıcıdan yalnızca kendi dışa aktardığınız bir çalışma alanı devir dosyasının içinde çıkar.',
  'omp.privacyMemory': 'Tarayıcı depolaması kullanılamıyor; origin haritası yalnızca bu sekmede tutulur ve sekmeyi kapattığınızda silinir. Hiçbir yere gönderilmez.',
  'omp.lead': 'Bir CDN’in arkasındaki adı gerçekte hangi sunucunun ve portun sunduğu; bir CLI taraması, zone dosyası ya da sunucu karşılaştırması bir kez bulduğunda hatırlanır. Doğrula, hatırlanan origin’leri (ve bir zone dosyasınınkileri) yeniden kontrol eder; yalnızca aday olan bir adresi asla hatırlamaz. Subdomain Tarama ve SSL Hedefleri bu origin’leri ilk sıraya koyar ve CLI komutuna ekler.',
  'omp.remember': 'Bu çalışma alanında origin’leri hatırla',
  'omp.rememberHint': 'Varsayılan olarak kapalı. Kapalıyken bu haritaya hiçbir şey yazılmaz.',
  'omp.offHere': 'Hatırlama kapalı: Zone Dosyası, Doğrula, IP emekliye ayırma, CLI raporları ve aşağıdaki form buraya hiçbir şey yazmaz.',
  'omp.offKept': { other: 'Burada tutulan {count} origin, siz silene kadar ipuçlarında kullanılmaya devam eder.' },
  'omp.stopTitle': 'Origin’leri hatırlama durdurulsun mu?',
  'omp.stopBody': { other: 'Origin haritasına yeni bir şey yazılmaz. İçindeki {count} origin kalır ve kullanılmaya devam eder; artık istemediğinizde onları buradan silin.' },
  'omp.stop': 'Hatırlamayı durdur',
  'omp.count': { zero: 'Henüz hatırlanan origin yok.', other: '{count} origin · {stale} eskimiş' },
  'omp.col.name': 'Ad',
  'omp.col.origin': 'Origin',
  'omp.col.server': 'Sunucu',
  'omp.col.source': 'Kaynak',
  'omp.col.confirmed': 'Son doğrulama',
  'omp.col.status': 'Durum',
  'omp.col.actions': 'İşlemler',
  'omp.active': 'Geçerli',
  'omp.firstSeen': 'İlk görülme: {date}',
  'omp.empty': 'Henüz hatırlanan bir şey yok. Bir zone dosyasının origin’lerini hatırlatın, bir CLI raporu içe aktarın, bir karşılaştırmadaki yeni sunucuyu hatırlatın ya da aşağıdan bir tane ekleyin.',
  'omp.edit': '{name} → {target} kaydını düzenle',
  'omp.delete': '{name} → {target} kaydını sil',
  'omp.deleted': '{name} → {target} silindi.',
  'omp.removeStale': { other: 'Eskimiş {count} kaydı kaldır' },
  'omp.removedStale': { other: 'Eskimiş {count} kayıt kaldırıldı.' },
  'omp.forget': 'Origin haritasını unut',
  'omp.forgetConfirm': { other: 'Bu çalışma alanında hatırlanan {count} origin silinsin mi? Bu işlem geri alınamaz.' },
  'omp.forgotten': 'Bu çalışma alanının origin haritası boş.',
  'omp.formTitle': 'Origin ekle',
  'omp.formEditTitle': 'Origin’i değiştir',
  'omp.formSubtitle': 'CDN arkasındaki bir ad ve onu gerçekte sunan sunucu.',
  'omp.f.name': 'Ad',
  'omp.f.ip': 'Adres',
  'omp.f.port': 'Port',
  'omp.f.server': 'Sunucu',
  'omp.f.serverHint': 'İsteğe bağlı: adres envanterinizdeyse oradan alınır.',
  'omp.add': 'Ekle',
  'omp.save': 'Kaydet',
  'omp.cancel': 'Vazgeç',
  'omp.added': '{name} → {target} hatırlandı.',
  'omp.err.off': 'Önce “Bu çalışma alanında origin’leri hatırla” seçeneğini açın.',
  'omp.err.name': 'Geçerli bir host adı değil: shop.example.com ya da hemen altındaki adlar için *.example.com.',
  'omp.err.ip': 'Geçerli bir IP adresi değil.',
  'omp.err.port': 'Port 1 ile 65535 arasında bir sayıdır.',
  'omp.err.limit': 'Origin haritası bu ad için ya da toplamda daha fazla kayıt tutmuyor. Önce bazılarını silin.',
  'omp.importTitle': 'CLI raporlarını içe aktar',
  'omp.importSubtitle': 'ssl_origin_scan.py’nin --json raporları, bu tarayıcıda okunur',
  'omp.importDrop': 'report.json dosyalarını buraya bırakın',
  'omp.importHint': 'CDN arkasındaki bir ad için UPDATED, NEEDS_UPDATE, ORIGIN_CERT ya da PRIVATE_CERT (adı kapsayan bir sertifika) yanıtı veren sunucu hatırlanır. Hatırlanan bir origin’i sorup adı orada bulamayan rapor, o kaydı eskimiş olarak işaretler; raporun sormadığı bir origin olduğu gibi kalır.',
  'omp.importAll': 'CDN arkasında olduğu bilinmeyen adlar da eklensin',
  'omp.importAllHint': 'Aksi halde yalnızca origin haritasının, içe aktarılan zone dosyasının ya da bu sekmedeki son taramanın CDN arkasında gösterdiği adlar eklenir (bir sunucunun Cloudflare Origin CA sertifikasıyla yanıt verdiği adlar da).',
  'omp.importFile': '{file}: {text}',
  'omp.importError': '{file}: okunamadı ({reason}).',
  'omp.file.too-large': '64 MB’tan büyük',
  'omp.file.not-json': 'JSON değil',
  'omp.file.not-report': 'ssl_origin_scan.py raporu değil',
  'omp.file.version': 'başka bir CLI sürümünün raporu, {version}',
  'omp.file.no-results': 'içinde sonuç yok'
});

/** Names this page session knows to be behind a CDN: the imported zone's proxied names and the last scan's. */
function sessionProxied() {
  const names = new Set();
  const zone = state.getSession('zone');
  for (const p of zone && Array.isArray(zone.proxied) ? zone.proxied : []) if (p && typeof p.name === 'string') names.add(p.name);
  const scan = state.getSession('scanHosts');
  for (const n of scan && Array.isArray(scan.proxied) ? scan.proxied : []) names.add(n);
  return names;
}

/**
 * The Origin map tab of the Servers view.
 * @param {{ ctx: import('../app.js').ViewContext }} opts
 * @returns {{ el: HTMLElement, refresh(): void, destroy(): void }}
 */
export function OriginMapPanel({ ctx }) {
  const el = h('div', { class: 'stack om-panel', dataset: { role: 'origin-map' } });
  const S = { editing: null, form: { name: '', ip: '', port: '', server: '' }, all: false, outcome: null, importLines: [] };

  const map = () => originMap() || { v: 1, remember: false, entries: [] };
  const save = (next) => saveOrigins(sanitizeOriginMap(next));
  // Not a live region: say() announces each message once (announce(), or the focus moved onto it).
  const outcomeEl = h('div', { class: 'om-outcome', dataset: { role: 'om-outcome' }, attrs: { tabindex: -1 } });

  /**
   * Say what a click did, once; `wrote` adds that it is kept in this tab only when browser storage
   * is unavailable. When that click's control went away (a deleted row), the keyboard focus goes
   * to the message, which is then read as it gets the focus.
   */
  function say(message, variant = 'ok', { wrote = false } = {}) {
    const text = wrote && keptHereOnly() ? `${message} ${t('om.memoryOnly')}` : message;
    const shown = wrote && keptHereOnly() && variant === 'ok' ? 'warn' : variant;
    S.outcome = { message: text, variant: shown };
    clear(outcomeEl);
    outcomeEl.append(Alert({ variant: shown, compact: true, message: text, dismissible: true, onDismiss: () => { S.outcome = null; } }));
    const doc = globalThis.document;
    if (doc && (!doc.activeElement || doc.activeElement === doc.body || !doc.activeElement.isConnected)) outcomeEl.focus({ preventScroll: true });
    else announce(text);
  }

  async function toggle(on) {
    const count = map().entries.length;
    if (!on && count) {
      const ok = await confirmDialog({
        title: t('omp.stopTitle'), message: t('omp.stopBody', { count }), confirmLabel: t('omp.stop')
      });
      if (!ok) {
        render();
        return;
      }
    }
    // The map as it is now: a Verify batch or another tab may have written it while the dialog was open.
    save(setRemember(map(), on));
    render();
  }

  function remove(entry) {
    save(removeOrigins(map(), [originKey(entry)]));
    if (S.editing === originKey(entry)) S.editing = null;
    render();
    say(t('omp.deleted', { name: entry.name, target: originTarget(entry) }), 'info', { wrote: true });
  }

  function edit(entry) {
    S.editing = originKey(entry);
    S.form = { name: entry.name, ip: entry.ip, port: String(entry.port), server: entry.server || '' };
    render();
    const field = el.querySelector('[data-role="om-name"]');
    if (field) field.focus();
  }

  function removeStale() {
    const stale = map().entries.filter((e) => e.stale);
    save(removeOrigins(map(), stale.map(originKey)));
    render();
    say(t('omp.removedStale', { count: stale.length }), 'info', { wrote: true });
  }

  async function forget() {
    const n = map().entries.length;
    const ok = await confirmDialog({ message: t('omp.forgetConfirm', { count: n }), confirmLabel: t('omp.forget'), danger: true });
    if (!ok) return;
    save(removeOrigins(map(), map().entries.map(originKey)));
    S.editing = null;
    render();
    say(t('omp.forgotten'), 'info', { wrote: true });
  }

  function submit() {
    const res = addManualOrigin(map(), S.form, { at: new Date(), replace: S.editing, serverOf });
    if (res.error) {
      render();
      const field = el.querySelector(`[data-role="om-${res.error === 'off' || res.error === 'limit' ? 'name' : res.error}"]`);
      say(t(`omp.err.${res.error}`), 'error');
      if (field) field.focus();
      return;
    }
    save(res.map);
    const [name, ip, port] = res.key.split('|');
    S.editing = null;
    S.form = { name: '', ip: '', port: '', server: '' };
    render();
    say(t('omp.added', { name, target: originTarget({ ip, port: Number(port) }) }), 'ok', { wrote: true });
  }

  function importReports(files) {
    const { reports, errors } = readCliReports(files);
    const known = sessionProxied();
    const lines = errors.map((e) => ({ variant: 'warn', text: t('omp.importError', { file: e.name, reason: t(`omp.file.${e.error}`, { version: e.detail || '?' }) }) }));
    for (const r of reports) {
      const originCert = new Set(r.originCertNames);
      const res = recordOrigins(r.observations, {
        source: 'cli-json', at: r.at || new Date(),
        proxied: S.all ? null : (name) => known.has(name) || originCert.has(name)
      });
      lines.push({ variant: res.staled.length ? 'warn' : 'ok', text: t('omp.importFile', { file: r.name, text: recordText(res) }) });
    }
    S.importLines = lines;
    render();
    announce(lines.map((l) => l.text).join(' '));
  }

  /** An entry's Edit button (found again by its key: Cancel puts the focus back on it). */
  function editButton(e) {
    const button = IconButton({ icon: 'edit', size: 'sm', label: t('omp.edit', { name: e.name, target: originTarget(e) }), onClick: () => edit(e) });
    Object.assign(button.dataset, { action: 'om-edit', key: originKey(e) });
    return button;
  }

  /** Leave the edit form; the focus goes back to the Edit button of the entry (or to the name field). */
  function cancelEdit() {
    const key = S.editing;
    S.editing = null;
    S.form = { name: '', ip: '', port: '', server: '' };
    render();
    const back = [...el.querySelectorAll('[data-action="om-edit"]')].find((b) => b.dataset.key === key) || el.querySelector('[data-role="om-name"]');
    if (back && !back.disabled) back.focus();
  }

  function rememberSwitch(m) {
    const sw = checkbox({
      label: t('omp.remember'), hint: t('omp.rememberHint'), checked: m.remember, switch: true, className: 'om-remember',
      onChange: (on) => toggle(on)
    });
    sw.input.dataset.role = 'om-remember';
    return sw.el;
  }

  function tableCard(m) {
    const stale = m.entries.filter((e) => e.stale).length;
    const table = DataTable({
      caption: t('om.title'),
      rows: m.entries,
      rowKey: originKey,
      dense: true,
      search: m.entries.length > 10,
      pageSize: 200,
      sort: { key: 'name', dir: 'asc' },
      empty: t('omp.empty'),
      className: 'om-table',
      rowClass: (e) => (e.stale ? 'om-row-stale' : null),
      export: { filename: 'origin-map' },
      columns: [
        { key: 'name', label: t('omp.col.name'), mono: true, sortable: true, render: (e) => h('span', { class: 'om-name' }, e.name) },
        { key: 'origin', label: t('omp.col.origin'), mono: true, sortable: true, sortValue: (e) => originTarget(e), exportValue: (e) => originTarget(e), render: (e) => originTarget(e) },
        { key: 'server', label: t('omp.col.server'), sortable: true, render: (e) => e.server || '' },
        { key: 'source', label: t('omp.col.source'), sortable: true, exportValue: (e) => e.source, sortValue: (e) => t(`om.source.${e.source}`), render: (e) => t(`om.source.${e.source}`) },
        {
          key: 'lastConfirmed', label: t('omp.col.confirmed'), sortable: true,
          render: (e) => h('span', { title: `${formatDateTime(e.lastConfirmed)} · ${t('omp.firstSeen', { date: formatDate(e.firstSeen) })}` }, formatDate(e.lastConfirmed))
        },
        {
          key: 'status', label: t('omp.col.status'), wrap: true, sortable: true, sortValue: (e) => (e.stale ? 1 : 0),
          exportValue: (e) => (e.stale ? `stale: ${e.stale.reason}` : 'active'),
          render: (e) => (e.stale
            ? h('div', { class: 'om-status', dataset: { stale: e.stale.reason } }, StaleBadge(e), h('span', { class: 'text-sm om-why' }, staleText(e)))
            : Badge(t('omp.active'), { variant: 'ok', icon: 'check' }))
        },
        {
          key: 'actions', label: t('omp.col.actions'), export: false,
          render: (e) => h('div', { class: 'cluster om-actions' },
            m.remember ? editButton(e) : null,
            IconButton({ icon: 'trash', size: 'sm', label: t('omp.delete', { name: e.name, target: originTarget(e) }), onClick: () => remove(e) }))
        }
      ]
    });
    return Card({
      title: t('om.title'),
      subtitle: t('omp.lead'),
      icon: 'map-pin',
      className: 'om-card',
      children: h('div', { class: 'stack-sm' },
        rememberSwitch(m),
        m.remember ? null : Alert({
          variant: 'info', compact: true, icon: 'map-pin',
          message: h('span', { dataset: { role: 'om-off' } }, t('omp.offHere'), m.entries.length ? ` ${t('omp.offKept', { count: m.entries.length })}` : '')
        }),
        h('p', { class: 'muted text-sm', dataset: { role: 'om-count' } }, t('omp.count', { count: m.entries.length, stale: formatNumber(stale) })),
        table.el,
        m.entries.length ? h('div', { class: 'cluster' },
          stale ? Button({ label: t('omp.removeStale', { count: stale }), icon: 'trash', size: 'sm', dataset: { action: 'om-remove-stale' }, onClick: removeStale }) : null,
          Button({ label: t('omp.forget'), icon: 'x-circle', size: 'sm', variant: 'ghost', dataset: { action: 'om-forget' }, onClick: forget })) : null,
        outcomeEl)
    });
  }

  function formCard(m) {
    const input = (key, label, opts = {}) => {
      const f = textInput({
        label, value: S.form[key], mono: key !== 'server', hint: opts.hint || null, placeholder: opts.placeholder || '',
        inputmode: opts.inputmode || null, className: `om-f-${key}`,
        attrs: { 'data-role': `om-${key}` },
        onInput: (v) => { S.form[key] = v; },
        onEnter: () => submit()
      });
      f.input.disabled = !m.remember;
      return f.el;
    };
    return Card({
      title: S.editing ? t('omp.formEditTitle') : t('omp.formTitle'),
      subtitle: t('omp.formSubtitle'),
      icon: S.editing ? 'edit' : 'plus',
      className: 'om-form-card',
      children: h('div', { class: 'stack-sm', dataset: { shortcutScope: 'origin-form' } },
        h('div', { class: 'om-form' },
          input('name', t('omp.f.name'), { placeholder: 'shop.example.com' }),
          input('ip', t('omp.f.ip'), { placeholder: '203.0.113.10' }),
          input('port', t('omp.f.port'), { placeholder: String(ORIGIN_DEFAULT_PORT), inputmode: 'numeric' }),
          input('server', t('omp.f.server'), { hint: t('omp.f.serverHint') })),
        h('div', { class: 'cluster' },
          Button({
            label: S.editing ? t('omp.save') : t('omp.add'), icon: 'check', variant: 'primary', disabled: !m.remember,
            dataset: { action: 'om-add', shortcut: 'submit' }, onClick: submit
          }),
          S.editing ? Button({ label: t('omp.cancel'), variant: 'ghost', dataset: { action: 'om-cancel' }, onClick: cancelEdit }) : null))
    });
  }

  function importCard(m) {
    const drop = FileDrop({
      accept: '.json', multiple: true, compact: true, icon: 'upload', maxFiles: 20, maxBytes: 64 * 1024 * 1024,
      title: t('omp.importDrop'), onFiles: (files) => importReports(files)
    });
    const all = checkbox({ label: t('omp.importAll'), hint: t('omp.importAllHint'), checked: S.all, onChange: (on) => { S.all = on; } });
    return Card({
      title: t('omp.importTitle'),
      subtitle: t('omp.importSubtitle'),
      icon: 'terminal',
      className: 'om-import-card',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'text-sm' }, t('omp.importHint')),
        m.remember ? drop.el : null,
        m.remember ? all.el : null,
        // Not a live region: importReports announces the lines once.
        h('div', { class: 'stack-sm', dataset: { role: 'om-import-result' } },
          S.importLines.map((l) => Alert({ variant: l.variant, compact: true, message: l.text }))))
    });
  }

  function render() {
    const m = map();
    const active = globalThis.document && globalThis.document.activeElement;
    const focusKey = active && el.contains(active) ? (active.dataset.role || active.dataset.action || null) : null;
    clear(el);
    el.append(
      keptHereOnly() ? Alert({ variant: 'warn', icon: 'alert', compact: true, message: t('omp.privacyMemory') })
        : Alert({ variant: 'ok', icon: 'lock', compact: true, message: t('omp.privacy') }),
      tableCard(m),
      h('div', { class: 'om-columns' }, formCard(m), importCard(m)));
    if (S.outcome) {
      clear(outcomeEl);
      outcomeEl.append(Alert({ variant: S.outcome.variant, compact: true, message: S.outcome.message, dismissible: true, onDismiss: () => { S.outcome = null; } }));
    }
    const again = focusKey ? el.querySelector(`[data-role="${focusKey}"], [data-action="${focusKey}"]`) : null;
    if (again && !again.disabled) again.focus({ preventScroll: true });
  }

  const off = state.subscribe(({ key, value }) => {
    if (key === 'cleared' || key === 'workspace') {
      S.editing = null;
      S.form = { name: '', ip: '', port: '', server: '' };
      S.outcome = null;
      S.importLines = [];
      render();
    } else if (key === 'workspaceData' && value && Array.isArray(value.parts) && value.parts.includes('origins')) {
      render();
    }
  });

  render();
  return { el, refresh: render, destroy: off };
}
