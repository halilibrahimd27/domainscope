/**
 * ui/rollout-panel.js — SSL Targets › Rollout: the board of a new certificate's rollout and the
 * deploy snippets of each server (lib/rollout.js, lib/deploysnippets.js). Loaded on the first
 * show of the tab (views/scan.js), for a finished scan with a certificate.
 *
 * - The board: one row per server that needs the certificate (per server and set with several),
 *   three steps to tick (installed, reloaded, verified), progress counts, CSV export. The ticks are
 *   kept in the workspace (the 'rollout' part) under the certificate's fingerprints, so loading the
 *   same certificate another day brings them back; rows ticked in an earlier scan that this one did
 *   not find stay on the board.
 * - The Verify tab: a server where every check saw the new certificate is marked verified by
 *   itself (views/scan.js calls `refresh()` when the checks change); the Verify column shows what
 *   the checks saw.
 * - Deploy snippets: a server and a platform, the options that platform takes (kept with the scan
 *   run in this tab only, never stored), then the commands section by section, each with Copy.
 *
 * Nothing here reaches the network. Names come from CT logs, zone files and the inventory: they
 * are rendered as text, and lib/deploysnippets.js validates and quotes them in commands.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, Card, CodeBlock, DataTable, EmptyState, ProgressBar, announce, confirmDialog, select, textInput, toast } from './components.js';
import { t, registerStrings, formatDateTime, formatNumber } from '../i18n.js';
import { downloadText, timestampedName } from './download.js';
import { toCsv } from '../lib/export.js';
import { computeFingerprints } from '../lib/x509.js';
import {
  ROLLOUT_STEPS, ROLLOUT_STAGES, ROLLOUT_VERIFY, ROLLOUT_CSV_COLUMNS, boardId, setKey, rolloutRows, parseRollout, serializeRollout,
  setStep, setTotal, resetBoard, findBoard, verifyStatus, applyVerify, boardRows, rolloutProgress, rolloutCsvRows
} from '../lib/rollout.js';
import {
  DEPLOY_PLATFORMS, SNIPPET_SECTIONS, SNIPPET_NOTES, SNIPPET_WARNINGS, PLATFORM_OPTIONS, deploySnippet
} from '../lib/deploysnippets.js';

const OPTION_KEYS = Object.freeze([...new Set(Object.values(PLATFORM_OPTIONS).flat())]);

registerStrings('en', {
  'ro.caption': 'Rollout board',
  'ro.intro': 'A checklist of the servers that need the new certificate: tick each step as you go. The board is kept in this workspace, so loading the same certificate again brings it back.',
  'ro.introSets': 'One row per server and certificate set.',
  'ro.preparing': 'Reading the certificate fingerprints…',
  'ro.noFp': 'The certificate fingerprint could not be computed, so the board cannot be kept.',
  'ro.empty': 'No server in this scan needs the certificate.',
  'ro.emptyHint': 'Load your server list in step 3 to see which of your servers need it.',
  'ro.progress': '{verified} of {total} verified · {installed} installed · {reloaded} reloaded',
  'ro.progressLabel': 'Rollout progress',
  'ro.auto': { one: '{count} confirmed by the Verify tab', other: '{count} confirmed by the Verify tab' },
  'ro.saved': 'Kept in this workspace.',
  'ro.saveFailed': 'Not saved: the browser refused storage. The ticks last until this page is closed.',
  'ro.col.server': 'Server',
  'ro.col.set': 'Set',
  'ro.col.targets': 'Addresses',
  'ro.col.names': 'Names',
  'ro.col.verify': 'Verify tab',
  'ro.col.deploy': 'Deploy',
  'ro.step.installed': 'Installed',
  'ro.step.reloaded': 'Reloaded',
  'ro.step.verified': 'Verified',
  'ro.stepLabel': '{step}: {server}',
  'ro.outside': 'outside your server list',
  'ro.private': 'private address',
  'ro.savedRow': 'from an earlier scan',
  'ro.byVerify': 'by the Verify tab',
  'ro.more': '+{count} more',
  'ro.vfy.confirmed': 'new certificate',
  'ro.vfy.old': 'old certificate',
  'ro.vfy.mixed': 'partly new',
  'ro.vfy.other': 'no certificate verdict',
  'ro.vfy.unchecked': 'not checked',
  'ro.stage.todo': 'to do',
  'ro.stage.installed': 'installed',
  'ro.stage.reloaded': 'reloaded',
  'ro.stage.verified': 'verified',
  'ro.export': 'Export CSV',
  'ro.exported': 'Rollout board exported',
  'ro.reset': 'Clear the board',
  'ro.resetTitle': 'Clear the Rollout board?',
  'ro.resetBody': 'Every tick on this certificate’s board is removed from this workspace.',
  'ro.resetDone': 'Board cleared',
  'ro.marked': { one: 'The Verify tab saw the new certificate on {count} server: marked verified.', other: 'The Verify tab saw the new certificate on {count} servers: marked verified.' },
  'ro.unmarked': { one: 'The Verify tab saw an old certificate on {count} server it had marked verified.', other: 'The Verify tab saw an old certificate on {count} servers it had marked verified.' },
  'ro.snip.title': 'Deploy snippets',
  'ro.snip.intro': 'Commands for one server: where the files go, the configuration, a test and reload, then a check that it serves the new certificate. Names from CT logs and zone files are checked and quoted; read the commands before you run them.',
  'ro.snip.server': 'Server',
  'ro.snip.platform': 'Platform',
  'ro.snip.open': 'Snippets',
  'ro.snip.openFor': 'Deploy snippets for {server}',
  'ro.snip.none': 'No server to deploy to.',
  'ro.snip.optHint': 'Kept in this tab only.',
  'ro.platform.nginx': 'nginx',
  'ro.platform.apache': 'Apache httpd',
  'ro.platform.haproxy': 'HAProxy (combined PEM)',
  'ro.platform.iis': 'IIS (PowerShell)',
  'ro.platform.tomcat': 'Tomcat (PKCS12 keystore)',
  'ro.platform.kubernetes': 'Kubernetes TLS secret',
  'ro.platform.traefik': 'Traefik',
  'ro.platform.caddy': 'Caddy',
  'ro.platform.aws-acm': 'AWS Certificate Manager',
  'ro.platform.azure-keyvault': 'Azure Key Vault',
  'ro.platform.f5': 'F5 BIG-IP (tmsh)',
  'ro.opt.site': 'IIS site',
  'ro.opt.namespace': 'Namespace',
  'ro.opt.secret': 'Secret name',
  'ro.opt.arn': 'Certificate ARN (to reimport)',
  'ro.opt.region': 'Region',
  'ro.opt.vault': 'Key vault name',
  'ro.opt.certName': 'Certificate name in the vault',
  'ro.opt.profile': 'Client SSL profile',
  'ro.sec.combine': 'Prepare the file',
  'ro.sec.files': 'Copy the files (from your machine)',
  'ro.sec.install': 'Install (on the server)',
  'ro.sec.config': 'Configuration',
  'ro.sec.test': 'Test',
  'ro.sec.reload': 'Reload',
  'ro.sec.verify': 'Verify',
  'ro.note.key-yours': 'DomainScope never has your private key: use the key the certificate was issued for.',
  'ro.note.paths': 'The paths are common defaults: adjust them to your layout.',
  'ro.note.pfx': 'IIS imports a PFX file (certificate, intermediates and key, protected by a password).',
  'ro.note.p12': 'Tomcat reads a PKCS12 keystore: openssl asks for its password, which goes into server.xml.',
  'ro.note.k8s-reload': 'Ingress controllers pick up a changed secret by themselves: nothing to reload.',
  'ro.note.traefik-watch': 'Traefik reloads the certificates of a file provider by itself when it watches the file.',
  'ro.note.traefik-acme': 'A certificate Traefik obtains itself (ACME) needs nothing from here.',
  'ro.note.caddy-auto': 'Caddy manages its own certificates by default: this is for a certificate you bring.',
  'ro.note.acm-reimport': 'A reimport keeps the ARN, so the load balancers and CloudFront distributions using it serve the new certificate without a change.',
  'ro.note.acm-new': 'Without an ARN this imports a new certificate: attach the ARN it prints to your load balancer or distribution.',
  'ro.note.acm-region': 'Add --region: an ACM certificate lives in one region (us-east-1 for CloudFront).',
  'ro.note.kv-pfx': 'Key Vault imports a PFX file; the password is read without echo.',
  'ro.note.kv-consumers': 'Services reading the vault (App Service, Application Gateway, Front Door) take the new version on their next sync.',
  'ro.note.f5-sync': 'In a device group, sync the configuration to the peers afterwards.',
  'ro.note.iis-live': 'IIS serves the new binding at once: no restart is needed.',
  'ro.note.verify-anywhere': 'The checks run from any machine with openssl and curl.',
  'ro.note.verify-sni': 'Each check connects to the address itself with the server name, so it sees what that server serves, whatever DNS says.',
  'ro.warn.unsafe-name': { one: '{count} name was left out: it is not a valid host name.', other: '{count} names were left out: they are not valid host names.' },
  'ro.warn.unsafe-server': 'The server name is not a host name: the commands use its address.',
  'ro.warn.no-name': 'No concrete name: the check connects without a server name.',
  'ro.warn.no-address': 'No address is known for this server.',
  'ro.warn.bad-option': '{field}: not a valid value, the default is used.',
  'ro.warn.missing-option': '{field} is needed: replace the placeholder.',
  'ro.warn.bad-fingerprint': 'The new certificate’s fingerprint is not known: the check prints what the server serves.',
  'ro.warn.too-many': { one: '{count} more address is not in the check.', other: '{count} more addresses are not in the check.' }
});

registerStrings('tr', {
  'ro.caption': 'Dağıtım panosu',
  'ro.intro': 'Yeni sertifikayı bekleyen sunucuların kontrol listesi: ilerledikçe her adımı işaretleyin. Pano bu çalışma alanında tutulur; aynı sertifikayı yeniden yüklediğinizde geri gelir.',
  'ro.introSets': 'Her sunucu ve sertifika kümesi için bir satır.',
  'ro.preparing': 'Sertifika parmak izleri okunuyor…',
  'ro.noFp': 'Sertifikanın parmak izi hesaplanamadı; pano saklanamıyor.',
  'ro.empty': 'Bu taramada sertifikayı bekleyen sunucu yok.',
  'ro.emptyHint': 'Hangi sunucularınızın onu beklediğini görmek için 3. adımda sunucu listenizi yükleyin.',
  'ro.progress': 'Doğrulanan: {verified}/{total} · kurulan: {installed} · yeniden yüklenen: {reloaded}',
  'ro.progressLabel': 'Dağıtım ilerlemesi',
  'ro.auto': { one: 'Doğrula sekmesinin onayladığı: {count}', other: 'Doğrula sekmesinin onayladığı: {count}' },
  'ro.saved': 'Bu çalışma alanında tutulur.',
  'ro.saveFailed': 'Kaydedilemedi: tarayıcı depolamaya izin vermedi. İşaretler bu sayfa kapanana kadar kalır.',
  'ro.col.server': 'Sunucu',
  'ro.col.set': 'Küme',
  'ro.col.targets': 'Adresler',
  'ro.col.names': 'Adlar',
  'ro.col.verify': 'Doğrula sekmesi',
  'ro.col.deploy': 'Dağıtım',
  'ro.step.installed': 'Kuruldu',
  'ro.step.reloaded': 'Yeniden yüklendi',
  'ro.step.verified': 'Doğrulandı',
  'ro.stepLabel': '{step}: {server}',
  'ro.outside': 'sunucu listenizin dışında',
  'ro.private': 'özel adres',
  'ro.savedRow': 'önceki bir taramadan',
  'ro.byVerify': 'Doğrula sekmesi işaretledi',
  'ro.more': '+{count} tane daha',
  'ro.vfy.confirmed': 'yeni sertifika',
  'ro.vfy.old': 'eski sertifika',
  'ro.vfy.mixed': 'kısmen yeni',
  'ro.vfy.other': 'sertifika hakkında sonuç yok',
  'ro.vfy.unchecked': 'kontrol edilmedi',
  'ro.stage.todo': 'yapılacak',
  'ro.stage.installed': 'kuruldu',
  'ro.stage.reloaded': 'yeniden yüklendi',
  'ro.stage.verified': 'doğrulandı',
  'ro.export': 'CSV olarak dışa aktar',
  'ro.exported': 'Dağıtım panosu dışa aktarıldı',
  'ro.reset': 'Panoyu temizle',
  'ro.resetTitle': 'Dağıtım panosu temizlensin mi?',
  'ro.resetBody': 'Bu sertifikanın panosundaki tüm işaretler bu çalışma alanından kaldırılır.',
  'ro.resetDone': 'Pano temizlendi',
  'ro.marked': { one: 'Doğrula sekmesi yeni sertifikayı {count} sunucuda gördü: doğrulandı olarak işaretlendi.', other: 'Doğrula sekmesi yeni sertifikayı {count} sunucuda gördü: doğrulandı olarak işaretlendi.' },
  'ro.unmarked': { one: 'Doğrula sekmesi, doğrulandı olarak işaretlediği {count} sunucuda eski bir sertifika gördü.', other: 'Doğrula sekmesi, doğrulandı olarak işaretlediği {count} sunucuda eski bir sertifika gördü.' },
  'ro.snip.title': 'Dağıtım komutları',
  'ro.snip.intro': 'Tek bir sunucu için komutlar: dosyaların yeri, yapılandırma, test ve yeniden yükleme, ardından yeni sertifikanın sunulduğunun kontrolü. CT kayıtlarından ve zone dosyalarından gelen adlar denetlenir ve tırnak içine alınır; komutları çalıştırmadan önce okuyun.',
  'ro.snip.server': 'Sunucu',
  'ro.snip.platform': 'Platform',
  'ro.snip.open': 'Komutlar',
  'ro.snip.openFor': '{server} sunucusunun dağıtım komutları',
  'ro.snip.none': 'Dağıtım yapılacak sunucu yok.',
  'ro.snip.optHint': 'Yalnızca bu sekmede tutulur.',
  'ro.platform.nginx': 'nginx',
  'ro.platform.apache': 'Apache httpd',
  'ro.platform.haproxy': 'HAProxy (birleşik PEM)',
  'ro.platform.iis': 'IIS (PowerShell)',
  'ro.platform.tomcat': 'Tomcat (PKCS12 anahtar deposu)',
  'ro.platform.kubernetes': 'Kubernetes TLS secret',
  'ro.platform.traefik': 'Traefik',
  'ro.platform.caddy': 'Caddy',
  'ro.platform.aws-acm': 'AWS Certificate Manager',
  'ro.platform.azure-keyvault': 'Azure Key Vault',
  'ro.platform.f5': 'F5 BIG-IP (tmsh)',
  'ro.opt.site': 'IIS sitesi',
  'ro.opt.namespace': 'Namespace',
  'ro.opt.secret': 'Secret adı',
  'ro.opt.arn': 'Sertifika ARN’si (yeniden içe aktarmak için)',
  'ro.opt.region': 'Bölge',
  'ro.opt.vault': 'Key Vault adı',
  'ro.opt.certName': 'Kasadaki sertifika adı',
  'ro.opt.profile': 'Client SSL profili',
  'ro.sec.combine': 'Dosyayı hazırlayın',
  'ro.sec.files': 'Dosyaları kopyalayın (kendi makinenizden)',
  'ro.sec.install': 'Kurun (sunucuda)',
  'ro.sec.config': 'Yapılandırma',
  'ro.sec.test': 'Test',
  'ro.sec.reload': 'Yeniden yükleme',
  'ro.sec.verify': 'Doğrulama',
  'ro.note.key-yours': 'DomainScope özel anahtarınızı hiçbir zaman görmez: sertifikanın verildiği anahtarı kullanın.',
  'ro.note.paths': 'Yollar yaygın varsayılanlardır: kendi düzeninize göre değiştirin.',
  'ro.note.pfx': 'IIS bir PFX dosyası içe aktarır (sertifika, ara sertifikalar ve anahtar, parola korumalı).',
  'ro.note.p12': 'Tomcat bir PKCS12 anahtar deposu okur: openssl parolasını sorar; parola server.xml dosyasına yazılır.',
  'ro.note.k8s-reload': 'Ingress denetleyicileri değişen secret’ı kendiliğinden alır: yeniden yüklenecek bir şey yok.',
  'ro.note.traefik-watch': 'Traefik, dosyayı izleyen bir file provider’ın sertifikalarını kendiliğinden yeniden yükler.',
  'ro.note.traefik-acme': 'Traefik’in kendisinin aldığı (ACME) bir sertifika için buradan bir şey gerekmez.',
  'ro.note.caddy-auto': 'Caddy varsayılan olarak kendi sertifikalarını yönetir: bu, sizin getirdiğiniz bir sertifika içindir.',
  'ro.note.acm-reimport': 'Yeniden içe aktarma ARN’yi korur; onu kullanan yük dengeleyiciler ve CloudFront dağıtımları değişiklik gerekmeden yeni sertifikayı sunar.',
  'ro.note.acm-new': 'ARN olmadan bu komut yeni bir sertifika içe aktarır: yazdırdığı ARN’yi yük dengeleyicinize veya dağıtımınıza bağlayın.',
  'ro.note.acm-region': '--region ekleyin: bir ACM sertifikası tek bir bölgede bulunur (CloudFront için us-east-1).',
  'ro.note.kv-pfx': 'Key Vault bir PFX dosyası içe aktarır; parola ekranda gösterilmeden okunur.',
  'ro.note.kv-consumers': 'Kasayı okuyan hizmetler (App Service, Application Gateway, Front Door) yeni sürümü bir sonraki eşitlemede alır.',
  'ro.note.f5-sync': 'Bir cihaz grubunda, ardından yapılandırmayı eşlere eşitleyin.',
  'ro.note.iis-live': 'IIS yeni bağlamayı hemen sunar: yeniden başlatma gerekmez.',
  'ro.note.verify-anywhere': 'Kontroller openssl ve curl bulunan herhangi bir makineden çalışır.',
  'ro.note.verify-sni': 'Her kontrol sunucu adıyla doğrudan adrese bağlanır; böylece DNS ne derse desin o sunucunun ne sunduğunu görür.',
  'ro.warn.unsafe-name': { one: '{count} ad çıkarıldı: geçerli bir host adı değil.', other: '{count} ad çıkarıldı: geçerli host adları değil.' },
  'ro.warn.unsafe-server': 'Sunucu adı bir host adı değil: komutlar adresini kullanır.',
  'ro.warn.no-name': 'Somut bir ad yok: kontrol sunucu adı olmadan bağlanır.',
  'ro.warn.no-address': 'Bu sunucunun bilinen bir adresi yok.',
  'ro.warn.bad-option': '{field}: geçerli bir değer değil, varsayılan kullanılıyor.',
  'ro.warn.missing-option': '{field} gerekli: yer tutucuyu değiştirin.',
  'ro.warn.bad-fingerprint': 'Yeni sertifikanın parmak izi bilinmiyor: kontrol, sunucunun sunduğunu yazdırır.',
  'ro.warn.too-many': { one: '{count} adres daha kontrolde yok.', other: '{count} adres daha kontrolde yok.' }
});

/**
 * Every i18n key this panel builds from a code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...ROLLOUT_STEPS.map((s) => `ro.step.${s}`), ...ROLLOUT_STAGES.map((s) => `ro.stage.${s}`), ...ROLLOUT_VERIFY.map((s) => `ro.vfy.${s}`),
    ...DEPLOY_PLATFORMS.map((p) => `ro.platform.${p}`), ...OPTION_KEYS.map((k) => `ro.opt.${k}`), ...SNIPPET_SECTIONS.map((s) => `ro.sec.${s}`),
    ...SNIPPET_NOTES.map((n) => `ro.note.${n}`), ...SNIPPET_WARNINGS.map((w) => `ro.warn.${w}`)
  ];
}

const VERIFY_VARIANT = { confirmed: 'ok', old: 'error', mixed: 'warn', other: 'neutral' };
const targetText = (x) => (x.ip.includes(':') ? `[${x.ip}]:${x.port}` : `${x.ip}:${x.port}`);
const firstName = (c) => (c && ((c.hostnames && c.hostnames[0]) || c.subjectCN)) || '';

/**
 * The Rollout tab body for a finished scan run with a certificate.
 * @param {{ run: object, ctx: import('../app.js').ViewContext, sets?: object[]|null, plan?: object|null,
 *   onChange?: () => void }} opts `sets` / `plan`: several certificates (lib/certsets.js);
 *   `onChange` refreshes the tab badge
 * @returns {{ el: HTMLElement, refresh(): void, badge(): { value: string, variant: string|null }|null, dispose(): void }}
 */
export function RolloutPanel({ run, ctx, sets = null, plan = null, onChange = null }) {
  const store = ctx.state;
  const el = h('div', { class: 'stack ro-panel', dataset: { panel: 'rollout' } });
  const certs = sets ? sets.flatMap((s) => s.certs) : [run.config.cert];
  const label = sets ? sets.map((s) => s.names[0] || '').filter(Boolean).join(', ') : firstName(run.config.cert);
  // What the snippets were set to (platform, options, server): with the run, in this tab only.
  const prefs = run.rollout || (run.rollout = { platform: DEPLOY_PLATFORMS[0], options: {}, row: null });
  let disposed = false;
  let id = null;
  let fpsOf = null; // set id ('' for one certificate) → SHA-256 fingerprints
  let rows = [];
  let view = [];
  let saveFailed = false;
  let note = null;

  const statusHost = h('div', { class: 'stack-sm ro-status', attrs: { 'aria-live': 'polite' } });
  const progressHost = h('div', { class: 'stack-sm ro-progress' });
  const resetBtn = Button({ size: 'sm', variant: 'ghost', icon: 'trash', label: t('ro.reset'), dataset: { action: 'ro-reset' }, onClick: () => reset() });
  const actions = h('div', { class: 'cluster ro-actions' },
    Button({ size: 'sm', icon: 'download', label: t('ro.export'), dataset: { action: 'ro-export' }, onClick: () => exportCsv() }), resetBtn);
  const tableHost = h('div', { class: 'ro-table' });
  const snipHost = h('div', { class: 'ro-snippets' });

  el.append(EmptyState({ compact: true, icon: 'clock', message: t('ro.preparing') }));

  const current = () => parseRollout(store.workspaceData('rollout'));
  const board = () => ({ id, label });

  function save(next) {
    const done = store.setWorkspaceData('rollout', serializeRollout(next));
    Promise.resolve(done).then((ok) => {
      if (disposed || (ok !== false) === !saveFailed) return;
      saveFailed = ok === false;
      renderStatus();
    }, () => {
      if (disposed) return;
      saveFailed = true;
      renderStatus();
    });
  }

  function statuses() {
    return verifyStatus(run.verify ? run.verify.rows : [], rows);
  }

  /** The Verify tab's checks applied to the stored board (and saved when that changed it). */
  function applyChecks(st) {
    const out = applyVerify(current(), board(), rows, st);
    if (!out.marked.length && !out.unmarked.length) return;
    save(out.state);
    note = out.unmarked.length ? { variant: 'warn', text: t('ro.unmarked', { count: out.unmarked.length }) }
      : { variant: 'ok', text: t('ro.marked', { count: out.marked.length }) };
    announce(note.text);
  }

  function rebuild() {
    const st = statuses();
    applyChecks(st);
    view = boardRows(current(), id, rows, st);
    keepTotal();
  }

  /** The stored board keeps how many rows the tab shows (Home's "3 of 5 servers updated"): written when that changed. */
  function keepTotal() {
    const saved = id ? findBoard(current(), id) : null;
    if (saved && saved.total !== view.length) save(setTotal(current(), id, view.length));
  }

  /* --- the table ------------------------------------------------------------------- */
  function stepCell(row, step) {
    const when = row[step];
    const input = h('input', {
      type: 'checkbox', class: 'check-input', checked: !!when,
      dataset: { roKey: row.key, roStep: step },
      attrs: { 'aria-label': t('ro.stepLabel', { step: t(`ro.step.${step}`), server: row.name }) },
      on: { change: () => tick(row, step, input.checked) }
    });
    return h('label', { class: 'ro-step' }, input,
      when ? h('span', { class: 'ro-when muted' }, formatDateTime(new Date(when))) : null,
      step === 'verified' && row.verifiedBy === 'verify' ? Badge(t('ro.byVerify'), { variant: 'ok', icon: 'check' }) : null);
  }

  function serverCell(row) {
    const tags = [];
    if (!row.server) tags.push(Badge(t(row.private ? 'ro.private' : 'ro.outside'), { variant: 'neutral' }));
    if (row.saved) tags.push(Badge(t('ro.savedRow'), { variant: 'neutral', icon: 'clock' }));
    return h('div', { class: 'stack-sm' }, h('span', { class: 'mono ro-name' }, row.name), tags.length ? h('div', { class: 'cluster' }, ...tags) : null);
  }

  function namesCell(row) {
    const list = row.names || [];
    const more = list.length - 3;
    return h('span', { class: 'mono ro-names', attrs: { title: list.join('\n') || null } },
      list.slice(0, 3).join(', '), more > 0 ? h('span', { class: 'muted' }, ` ${t('ro.more', { count: formatNumber(more) })}`) : null);
  }

  function verifyCell(row) {
    const v = row.verify;
    if (!v || v.status === 'unchecked') return h('span', { class: 'muted' }, t('ro.vfy.unchecked'));
    const b = Badge(t(`ro.vfy.${v.status}`), { variant: VERIFY_VARIANT[v.status] || 'neutral' });
    b.dataset.verify = v.status;
    return b;
  }

  const table = DataTable({
    caption: t('ro.caption'),
    rows: [],
    dense: true,
    cellLabels: true,
    rowKey: (r) => r.key,
    className: 'ro-board',
    rowClass: (r) => ({ 'ro-row-done': r.stage === 'verified', 'ro-row-saved': r.saved }),
    columns: [
      { key: 'server', label: t('ro.col.server'), sortable: true, sortValue: (r) => r.name, render: serverCell },
      sets ? { key: 'set', label: t('ro.col.set'), sortable: true, sortValue: (r) => r.set || '', render: (r) => (r.set ? Badge(t('rw.set', { id: r.set }), { variant: 'info' }) : '') } : null,
      { key: 'targets', label: t('ro.col.targets'), mono: true, wrap: true, sortValue: (r) => (r.targets[0] ? r.targets[0].ip : ''), render: (r) => r.targets.map(targetText).join(' ') },
      { key: 'names', label: t('ro.col.names'), wrap: true, sortValue: (r) => r.names[0] || '', render: namesCell },
      ...ROLLOUT_STEPS.map((step) => ({ key: step, label: t(`ro.step.${step}`), sortable: true, sortValue: (r) => r[step] || '', render: (r) => stepCell(r, step) })),
      { key: 'verify', label: t('ro.col.verify'), sortable: true, sortValue: (r) => (r.verify ? ROLLOUT_VERIFY.indexOf(r.verify.status) : 9), render: verifyCell },
      {
        key: 'deploy', label: t('ro.col.deploy'), render: (r) => (r.targets.length || r.server ? Button({
          size: 'sm', variant: 'ghost', icon: 'terminal', label: t('ro.snip.open'), dataset: { action: 'ro-snippets', roKey: r.key },
          ariaLabel: t('ro.snip.openFor', { server: r.name }), onClick: () => openSnippets(r.key)
        }) : '')
      }
    ].filter(Boolean)
  });

  function tick(row, step, on) {
    save(setStep(current(), board(), row, step, on));
    rebuild();
    table.setRows(view);
    const again = [...table.el.querySelectorAll('input[data-ro-step]')].find((i) => i.dataset.roKey === row.key && i.dataset.roStep === step);
    if (again) again.focus();
    renderProgress();
    if (onChange) onChange();
  }

  /* --- progress, status, actions --------------------------------------------------- */
  function renderProgress() {
    clear(progressHost);
    // Clear the board: only when this certificate has a stored board.
    resetBtn.disabled = !findBoard(current(), id);
    const p = rolloutProgress(view);
    const bar = ProgressBar({ label: t('ro.progressLabel'), value: p.verified, max: Math.max(1, p.total), showCount: false });
    progressHost.append(
      h('p', { class: 'ro-counts', dataset: { total: p.total, verified: p.verified, installed: p.installed, reloaded: p.reloaded } },
        t('ro.progress', { verified: formatNumber(p.verified), total: formatNumber(p.total), installed: formatNumber(p.installed), reloaded: formatNumber(p.reloaded) }),
        p.auto ? h('span', { class: 'muted' }, ` · ${t('ro.auto', { count: p.auto })}`) : null),
      bar.el || bar);
  }

  function renderStatus() {
    clear(statusHost);
    statusHost.append(saveFailed
      ? Alert({ variant: 'warn', compact: true, message: t('ro.saveFailed') })
      : h('p', { class: 'muted ro-saved' }, t('ro.saved')));
    if (note) {
      const a = Alert({ variant: note.variant, compact: true, message: note.text });
      a.classList.add('ro-note');
      statusHost.append(a);
    }
  }

  function exportCsv() {
    const csv = toCsv(rolloutCsvRows(view), ROLLOUT_CSV_COLUMNS);
    downloadText(timestampedName('rollout', 'csv', label), csv, 'text/csv;charset=utf-8');
    toast(t('ro.exported'), { type: 'success' });
  }

  async function reset() {
    const ok = await confirmDialog({ title: t('ro.resetTitle'), message: t('ro.resetBody'), confirmLabel: t('ro.reset'), danger: true });
    if (!ok || disposed) return;
    save(resetBoard(current(), id));
    note = null;
    renderAll();
    toast(t('ro.resetDone'));
    if (onChange) onChange();
  }

  /* --- deploy snippets ------------------------------------------------------------- */
  function snippetInput(row) {
    const set = row.set && sets ? sets.find((s) => s.id === row.set) : null;
    const leaf = set ? set.certs[0] : run.config.cert;
    return {
      server: row.server ? { name: row.server.name } : null,
      targets: row.targets, names: row.names,
      fingerprints: fpsOf.get(row.set || '') || [],
      certName: set ? set.names[0] || firstName(leaf) : firstName(leaf),
      notBefore: leaf && leaf.notBefore instanceof Date ? leaf.notBefore : null
    };
  }

  function openSnippets(key) {
    prefs.row = key;
    renderSnippets();
    const target = snipHost.querySelector('[data-role="ro-snip-server"]');
    if (target) {
      snipHost.scrollIntoView({ block: 'start' });
      target.focus();
    }
  }

  function renderSnippets() {
    clear(snipHost);
    const choices = view.filter((r) => r.targets.length || r.server);
    if (!choices.length) {
      snipHost.append(Card({ title: t('ro.snip.title'), children: EmptyState({ compact: true, icon: 'server', message: t('ro.snip.none') }) }));
      return;
    }
    if (!choices.some((r) => r.key === prefs.row)) prefs.row = choices[0].key;
    const row = choices.find((r) => r.key === prefs.row);
    const serverSel = select({
      label: t('ro.snip.server'), value: row.key,
      options: choices.map((r) => ({ value: r.key, label: r.set ? `${r.name} · ${t('rw.set', { id: r.set })}` : r.name })),
      onChange: (v) => {
        prefs.row = v;
        renderSnippets();
        focusRole('ro-snip-server');
      }
    });
    serverSel.input.dataset.role = 'ro-snip-server';
    const platformSel = select({
      label: t('ro.snip.platform'), value: prefs.platform,
      options: DEPLOY_PLATFORMS.map((p) => ({ value: p, label: t(`ro.platform.${p}`) })),
      onChange: (v) => {
        prefs.platform = v;
        renderSnippets();
        focusRole('ro-snip-platform');
      }
    });
    platformSel.input.dataset.role = 'ro-snip-platform';
    const fields = (PLATFORM_OPTIONS[prefs.platform] || []).map((key) => {
      const f = textInput({
        label: t(`ro.opt.${key}`), value: prefs.options[key] || '', mono: true, hint: t('ro.snip.optHint'),
        attrs: { 'data-ro-opt': key },
        onInput: (v) => {
          prefs.options[key] = v;
          renderCode();
        }
      });
      return f.el;
    });
    const codeHost = h('div', { class: 'stack ro-code' });
    function renderCode() {
      clear(codeHost);
      const s = deploySnippet(prefs.platform, snippetInput(row), prefs.options);
      if (s.warnings.length) {
        const a = Alert({
          variant: 'warn', compact: true,
          children: h('ul', { class: 'stack-sm' }, ...s.warnings.map((w) => h('li', { dataset: { warn: w.code } },
            t(`ro.warn.${w.code}`, { count: w.count || 0, field: w.field ? t(`ro.opt.${w.field}`) : '' }))))
        });
        a.classList.add('ro-warnings');
        codeHost.append(a);
      }
      for (const sec of s.sections) {
        codeHost.append(h('section', { class: 'stack-sm ro-sec', dataset: { section: sec.id, shell: sec.shell } },
          h('h4', { class: 'ro-sec-title' }, t(`ro.sec.${sec.id}`)),
          CodeBlock(sec.lines.join('\n'), { label: t(`ro.sec.${sec.id}`), copy: true })));
      }
      codeHost.append(h('ul', { class: 'stack-sm muted ro-notes' }, ...s.notes.map((n) => h('li', { dataset: { note: n } }, t(`ro.note.${n}`)))));
    }
    renderCode();
    snipHost.append(Card({
      title: t('ro.snip.title'),
      children: h('div', { class: 'stack' },
        h('p', { class: 'muted' }, t('ro.snip.intro')),
        h('div', { class: 'grid-auto ro-snip-fields' }, serverSel.el, platformSel.el, ...fields),
        codeHost)
    }));
  }

  function focusRole(role) {
    const target = snipHost.querySelector(`[data-role="${role}"]`);
    if (target) target.focus();
  }

  /* --- assemble ------------------------------------------------------------------------ */
  function renderAll() {
    if (disposed) return;
    clear(el);
    if (!id) {
      el.append(Alert({ variant: 'error', compact: true, message: t('ro.noFp') }));
      return;
    }
    rebuild();
    el.append(h('p', { class: 'muted ro-intro' }, t('ro.intro'), sets ? ` ${t('ro.introSets')}` : ''));
    if (!view.length) {
      el.append(EmptyState({ compact: true, icon: 'server', message: t('ro.empty') }));
      if (!(run.config.inventoryServers > 0)) el.append(h('p', { class: 'muted' }, t('ro.emptyHint')));
      return;
    }
    renderProgress();
    renderStatus();
    table.setRows(view);
    el.append(progressHost, statusHost, actions, tableHost, snipHost);
    if (!tableHost.firstChild) tableHost.append(table.el);
    renderSnippets();
  }

  // The fingerprints first (they name the board), then everything.
  Promise.all(certs.map((c) => (c && c.der ? computeFingerprints(c.der).then((f) => f.sha256, () => null) : null))).then((list) => {
    if (disposed) return;
    fpsOf = new Map();
    let i = 0;
    if (sets) {
      for (const s of sets) {
        fpsOf.set(s.id, list.slice(i, i + s.certs.length).filter(Boolean));
        i += s.certs.length;
      }
    } else fpsOf.set('', list.filter(Boolean));
    id = boardId(list.filter(Boolean));
    const keys = sets ? new Map(sets.map((s) => [s.id, setKey(fpsOf.get(s.id))])) : null;
    rows = rolloutRows(run.result, { plan: sets ? plan : null, setKeys: keys });
    renderAll();
    if (onChange) onChange();
  });

  // Another tab changed the board, another workspace is active, or local data was deleted.
  const off = store.subscribe(({ key, value, origin }) => {
    if (disposed || !id) return;
    if (key === 'cleared' || key === 'workspace' || (key === 'workspaceData' && origin !== 'local' && value && (value.parts || []).includes('rollout'))) {
      note = null;
      renderAll();
      if (onChange) onChange();
    }
  });

  return {
    el,
    /** The Verify tab's checks changed: mark what they confirmed, redraw the Verify column and the counts. */
    refresh() {
      if (disposed || !id || !view.length) return;
      const before = JSON.stringify(view.map((r) => [r.key, r.verify, r.verified]));
      rebuild();
      if (JSON.stringify(view.map((r) => [r.key, r.verify, r.verified])) === before) return;
      table.setRows(view);
      renderProgress();
      renderStatus();
    },
    /** Tab badge "verified/total", or null before the board is read. */
    badge() {
      if (!id || !view.length) return null;
      const p = rolloutProgress(view);
      return { value: `${p.verified}/${p.total}`, variant: p.verified === p.total ? 'ok' : null };
    },
    dispose() {
      disposed = true;
      if (typeof off === 'function') off();
    }
  };
}
