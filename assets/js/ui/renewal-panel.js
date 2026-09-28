/**
 * ui/renewal-panel.js — SSL Targets with several certificates at once ("renewal week").
 *
 * A renewal week often brings an RSA + ECDSA pair for the same names plus a few other
 * certificates. lib/certsets.js groups them into sets and plans which set each server needs;
 * this module draws it:
 *
 *   - {@link RenewalSets}: step 1's list — the sets with their names, and each certificate's key
 *     type, validity, expiry and files (Remove on each); files that add nothing and why;
 *   - {@link RenewalPlanPanel}: the "Renewal plan" results tab — the sets, the server × set matrix
 *     (the names each server needs from each set; labelled cards on a phone), the per-server CSV
 *     work list and the names no certificate covers;
 *   - {@link CertFileButtons}: one download per certificate for the CLI's repeated `--cert`
 *     (the Behind CDN card and the Verify tab's CLI card).
 *
 * It lives in ui/ (every views/*.js module is a routed view), so the view hands in what only it
 * knows (the Certificate view's validity badge). Names come from certificates and DNS: every
 * string goes through h() / text nodes.
 */

import { h } from './dom.js';
import { Badge, Button, DataTable, EmptyState, Icon, IconButton, TruncatedList, toast } from './components.js';
import { downloadText, timestampedName } from './download.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { toCsv } from '../lib/export.js';
import { pemEncode } from '../lib/x509.js';
import { WORKLIST_COLUMNS, cliCertFiles, workListRows } from '../lib/certsets.js';

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'rw.set': 'Set {id}',
  'rw.certs': { one: '{count} certificate', other: '{count} certificates' },
  'rw.sets': { one: '{count} set', other: '{count} sets' },
  'rw.names': { one: '{count} name', other: '{count} names' },
  'rw.intro': 'Certificates with the same names form one set (an RSA + ECDSA pair). One scan covers the names of every set, and each host gets the set that names it exactly, else the most specific wildcard, else the one that expires last.',
  'rw.expires': 'expires {date}',
  'rw.details': 'Details of this certificate ({key}, {file})',
  'rw.removeCert': 'Remove this certificate ({key}, {file})',
  'rw.removeFile': 'Remove {file}',
  'rw.skipped': 'Not used',
  'rw.skip.key': 'a private key only: ignored, never needed',
  'rw.skip.csr': 'a certificate signing request, not a certificate',
  'rw.skip.p12': 'a PKCS#12 bundle: extract the certificate first',
  'rw.skip.none': 'no certificate found',
  'rw.skip.ca': { one: 'a CA certificate only, used as the chain', other: '{count} CA certificates only, used as the chain' },
  'rw.skip.noNames': 'a certificate without DNS names ({subject})',
  'rw.keyIgnored': 'A private key was ignored in {files}. It is never needed; keep it secret.',
  'rw.add': 'Add certificates',
  'rw.addTitle': 'Drop more certificate files here',
  'rw.removeAll': 'Remove all',

  'rw.tab': 'Renewal plan',
  'rw.plan.intro': 'Which certificate set each of your servers needs, from one scan of every set’s names. A name gets the set that names it exactly, else the most specific wildcard, else the one that expires last.',
  'rw.plan.setsTitle': 'Certificate sets',
  'rw.plan.setUse': 'Hosts: {hosts} · servers: {servers} · expires {date}',
  'rw.plan.setUseOut': 'Hosts: {hosts} · servers: {servers} · addresses not in your list: {addresses} · expires {date}',
  'rw.plan.matrixTitle': 'Servers and sets',
  'rw.plan.caption': 'The names each server needs from each certificate set',
  'rw.plan.worklist': 'Work list (CSV)',
  'rw.plan.worklistTitle': 'One row per server and set: server, IP, names, set, key types, files',
  'rw.plan.empty': 'None of your servers serves a name these certificates cover.',
  'rw.plan.noInventory': 'No servers saved: the plan lists the addresses the names resolve to. Add your inventory to see your servers.',
  'rw.col.server': 'Server',
  'rw.col.total': 'Names',
  'rw.notInList': 'not in your list',
  'rw.private': 'private',
  'rw.maybe': 'possible origin',
  'rw.maybeTitle': 'Only an origin hint points here: confirm with the CLI before installing.',
  'rw.hint': 'origin hint',
  'rw.uncovered': { zero: 'Every host the scan found is covered by a certificate', one: '{count} host no certificate covers', other: '{count} hosts no certificate covers' },
  'rw.uncovered.desc': 'Hosts the scan found that none of the loaded certificates covers. They keep the certificate they have: renew them separately, or add their certificate to this renewal.',
  'rw.col.name': 'Host name',
  'rw.col.onServers': 'Your servers',
  'rw.col.dns': 'DNS',
  'rw.resolves': 'resolves',
  'rw.noAddress': 'no address',
  'rw.sum': { one: '{sets} certificate sets: {count} server needs one of them — see “Renewal plan”.', other: '{sets} certificate sets: {count} servers need one of them — see “Renewal plan”.' },
  'rw.sum.uncovered': { one: '{count} host no loaded certificate covers — see “Renewal plan”.', other: '{count} hosts no loaded certificate covers — see “Renewal plan”.' },
  'rw.sum.open': 'Renewal plan',
  'rw.sum.noInventory': '{sets} certificate sets: the Renewal plan lists which set each address the names resolve to needs. Add your servers to see them by name.',
  'rw.host.setTitle': 'Set {id}: covered by {name}',
  'rw.cli.files': 'One --cert per certificate: a server serving any of them is UPDATED, and the report names which.',
  'rw.cli.onlyCovered': 'Only names one of the certificates covers',
  'rw.cli.file': 'Download {file}',
  'rw.cli.fileTitle': '{set} · {key}',
  'rw.dane.pick': 'Certificate',
  'rw.dane.one': 'The TLSA check compares one certificate at a time. Pick the one to check:',
  'rw.dane.option': '{set} · {key} · {file}',
  'rw.exported': '{file} downloaded'
});

registerStrings('tr', {
  'rw.set': '{id} seti',
  'rw.certs': { one: '{count} sertifika', other: '{count} sertifika' },
  'rw.sets': { one: '{count} set', other: '{count} set' },
  'rw.names': { one: '{count} ad', other: '{count} ad' },
  'rw.intro': 'Adları aynı olan sertifikalar bir set oluşturur (bir RSA + ECDSA ikilisi gibi). Tek tarama tüm setlerin adlarını kapsar; her host’a onu tam adıyla içeren set, yoksa en belirgin joker (wildcard), o da yoksa süresi en geç dolan set verilir.',
  'rw.expires': '{date} tarihinde doluyor',
  'rw.details': 'Bu sertifikanın ayrıntıları ({key}, {file})',
  'rw.removeCert': 'Bu sertifikayı kaldır ({key}, {file})',
  'rw.removeFile': '{file} dosyasını kaldır',
  'rw.skipped': 'Kullanılmayanlar',
  'rw.skip.key': 'yalnızca özel anahtar: yok sayıldı, hiç gerekmez',
  'rw.skip.csr': 'sertifika imzalama isteği (CSR), sertifika değil',
  'rw.skip.p12': 'PKCS#12 paketi: önce sertifikayı çıkarın',
  'rw.skip.none': 'sertifika bulunamadı',
  'rw.skip.ca': { one: 'yalnızca bir CA sertifikası, zincir olarak kullanılıyor', other: 'yalnızca {count} CA sertifikası, zincir olarak kullanılıyor' },
  'rw.skip.noNames': 'DNS adı olmayan bir sertifika ({subject})',
  'rw.keyIgnored': '{files} içindeki özel anahtar yok sayıldı. Hiç gerekmez; gizli tutun.',
  'rw.add': 'Sertifika ekle',
  'rw.addTitle': 'Başka sertifika dosyalarını buraya bırakın',
  'rw.removeAll': 'Tümünü kaldır',

  'rw.tab': 'Yenileme planı',
  'rw.plan.intro': 'Tüm setlerin adları tek taramada kontrol edildi; sunucularınızdan her birinin hangi sertifika setine ihtiyacı olduğu burada. Bir ada onu tam adıyla içeren set, yoksa en belirgin joker, o da yoksa süresi en geç dolan set verilir.',
  'rw.plan.setsTitle': 'Sertifika setleri',
  'rw.plan.setUse': 'Host: {hosts} · sunucu: {servers} · {date} tarihinde doluyor',
  'rw.plan.setUseOut': 'Host: {hosts} · sunucu: {servers} · listenizde olmayan adres: {addresses} · {date} tarihinde doluyor',
  'rw.plan.matrixTitle': 'Sunucular ve setler',
  'rw.plan.caption': 'Her sunucunun her sertifika setinden ihtiyaç duyduğu adlar',
  'rw.plan.worklist': 'İş listesi (CSV)',
  'rw.plan.worklistTitle': 'Sunucu ve set başına bir satır: sunucu, IP, adlar, set, anahtar türleri, dosyalar',
  'rw.plan.empty': 'Sunucularınızın hiçbiri bu sertifikaların kapsadığı bir adı sunmuyor.',
  'rw.plan.noInventory': 'Kayıtlı sunucu yok: plan, adların çözümlendiği adresleri listeliyor. Sunucularınızı görmek için envanterinizi ekleyin.',
  'rw.col.server': 'Sunucu',
  'rw.col.total': 'Adlar',
  'rw.notInList': 'listenizde yok',
  'rw.private': 'özel',
  'rw.maybe': 'olası asıl sunucu',
  'rw.maybeTitle': 'Buraya yalnızca bir asıl sunucu ipucu işaret ediyor: kurmadan önce CLI ile doğrulayın.',
  'rw.hint': 'asıl sunucu ipucu',
  'rw.uncovered': { zero: 'Taramanın bulduğu her host bir sertifikanın kapsamında', one: 'Hiçbir sertifikanın kapsamadığı {count} host', other: 'Hiçbir sertifikanın kapsamadığı {count} host' },
  'rw.uncovered.desc': 'Taramanın bulduğu ama yüklenen sertifikaların hiçbirinin kapsamadığı host’lar. Şu anki sertifikalarını korurlar: ayrıca yenileyin ya da sertifikalarını bu yenilemeye ekleyin.',
  'rw.col.name': 'Host adı',
  'rw.col.onServers': 'Sunucularınız',
  'rw.col.dns': 'DNS',
  'rw.resolves': 'çözümleniyor',
  'rw.noAddress': 'adres yok',
  'rw.sum': { one: '{sets} sertifika seti: {count} sunucunun bunlardan birine ihtiyacı var — “Yenileme planı”na bakın.', other: '{sets} sertifika seti: {count} sunucunun bunlardan birine ihtiyacı var — “Yenileme planı”na bakın.' },
  'rw.sum.uncovered': { one: 'Yüklenen hiçbir sertifikanın kapsamadığı {count} host var — “Yenileme planı”na bakın.', other: 'Yüklenen hiçbir sertifikanın kapsamadığı {count} host var — “Yenileme planı”na bakın.' },
  'rw.sum.open': 'Yenileme planı',
  'rw.sum.noInventory': '{sets} sertifika seti: Yenileme planı, adların çözümlendiği her adresin hangi sete ihtiyacı olduğunu listeliyor. Adlarıyla görmek için sunucularınızı ekleyin.',
  'rw.host.setTitle': '{id} seti: {name} kapsıyor',
  'rw.cli.files': 'Her sertifika için bir --cert: bunlardan herhangi birini sunan sunucu UPDATED olur ve rapor hangisi olduğunu yazar.',
  'rw.cli.onlyCovered': 'Yalnızca sertifikalardan birinin kapsadığı adlar',
  'rw.cli.file': '{file} indir',
  'rw.cli.fileTitle': '{set} · {key}',
  'rw.dane.pick': 'Sertifika',
  'rw.dane.one': 'TLSA kontrolü sertifikaları tek tek karşılaştırır. Kontrol edilecek olanı seçin:',
  'rw.dane.option': '{set} · {key} · {file}',
  'rw.exported': '{file} indirildi'
});

/* ------------------------------------------------------------------------ */
/* Small pieces                                                             */
/* ------------------------------------------------------------------------ */

/**
 * "Set A" as a badge (the matrix columns, the Hosts tab, Verify).
 * @param {string} id
 * @param {{ title?: string|null, variant?: string }} [opts]
 * @returns {HTMLElement}
 */
export function SetBadge(id, { title = null, variant = 'accent' } = {}) {
  const b = Badge(t('rw.set', { id }), { variant, icon: 'layers', title, className: 'rw-set-badge' });
  b.dataset.set = id;
  return b;
}

/** Why a file adds nothing (lib/certsets SKIP_ISSUES + the parser's codes). */
function skipText(s) {
  if (s.issue === 'ca-only') return t('rw.skip.ca', { count: s.count || 1 });
  if (s.issue === 'no-names') return t('rw.skip.noNames', { subject: s.subject || '—' });
  const codes = s.codes || [];
  if (codes.includes('PKCS12_UNSUPPORTED')) return t('rw.skip.p12');
  if (codes.includes('CSR_NOT_CERT')) return t('rw.skip.csr');
  if (codes.includes('PRIVATE_KEY_PRESENT')) return t('rw.skip.key');
  return t('rw.skip.none');
}

const fileLabel = (files) => (files || []).filter(Boolean).join(', ') || '—';

/** A button with a `data-action` (step 1 finds the Remove buttons by it to keep the focus in the list). */
const withAction = (btn, action) => {
  btn.dataset.action = action;
  return btn;
};

/**
 * One download button per certificate of the renewal, named as the CLI command names it
 * (lib/certsets cliCertFiles: new-cert-a-rsa.pem …). The file holds that certificate only.
 * @param {import('../lib/certsets.js').CertSet[]} sets
 * @returns {HTMLButtonElement[]}
 */
export function CertFileButtons(sets) {
  return cliCertFiles(sets).map(({ file, set, leaf }) => Button({
    icon: 'download', label: file, size: 'sm', title: t('rw.cli.fileTitle', { set: t('rw.set', { id: set }), key: leaf.keyType }),
    ariaLabel: t('rw.cli.file', { file }), dataset: { action: 'cli-cert-file', file },
    onClick: () => {
      const saved = downloadText(file, pemEncode(leaf.cert.der), 'application/x-pem-file');
      toast(t('rw.exported', { file: saved }), { type: 'success', timeout: 2500 });
    }
  }));
}

/* ------------------------------------------------------------------------ */
/* Step 1: the loaded certificates as sets                                  */
/* ------------------------------------------------------------------------ */

/**
 * Step 1 of SSL Targets with several certificates: the sets (names; each certificate's key
 * type, validity, expiry and files, with Details and Remove) and the files that add nothing.
 * The buttons carry `data-action` rw-details, rw-remove-leaf and rw-remove-file; the head
 * (`.rw-sets-head`) takes the focus from script (tabindex -1).
 * @param {{ bundle: import('../lib/certsets.js').RenewalBundle,
 *   validity?: ((cert: object) => HTMLElement)|null,
 *   onRemoveLeaf: (leaf: import('../lib/certsets.js').RenewalLeaf) => void,
 *   onRemoveFile: (entry: { index: number, key?: string }) => void,
 *   onDetails?: ((leaf: import('../lib/certsets.js').RenewalLeaf) => void)|null }} opts
 *   `onRemoveFile` gets the `bundle.skipped` entry (its file's index, or the key of a leaf without names)
 * @returns {HTMLElement}
 */
export function RenewalSets({ bundle, validity = null, onRemoveLeaf, onRemoveFile, onDetails = null }) {
  const names = new Set(bundle.leaves.flatMap((l) => l.names));
  const el = h('div', {
    class: 'rw-sets stack-sm',
    dataset: { role: 'renewal-sets', sets: String(bundle.sets.length), certs: String(bundle.leaves.length) }
  },
  // Files without a usable certificate only (a key, a CSR): just the list of what is not used.
  bundle.leaves.length ? h('p', { class: 'rw-sets-head', tabindex: -1 }, Icon('layers', { size: 15 }),
    h('span', null, [
      t('rw.certs', { count: bundle.leaves.length }), t('rw.sets', { count: bundle.sets.length }), t('rw.names', { count: names.size })
    ].join(' · '))) : null,
  bundle.leaves.length ? h('p', { class: 'muted text-xs rw-sets-intro' }, t('rw.intro')) : null);

  for (const set of bundle.sets) {
    el.append(h('section', { class: 'rw-set', dataset: { set: set.id }, attrs: { 'aria-label': t('rw.set', { id: set.id }) } },
      h('div', { class: 'rw-set-head' }, SetBadge(set.id), TruncatedList(set.names, { max: 4, inline: true })),
      h('ul', { class: 'rw-leaves' }, set.leaves.map((leaf) => h('li', { class: 'rw-leaf', dataset: { key: leaf.keySlug } },
        h('div', { class: 'rw-leaf-facts' },
          Badge(leaf.keyType, { variant: 'neutral', icon: 'key', mono: true, className: 'rw-key' }),
          validity ? validity(leaf.cert) : null,
          h('span', { class: 'rw-leaf-exp text-sm' }, t('rw.expires', { date: formatDate(leaf.cert.notAfter) })),
          h('span', { class: 'rw-leaf-files text-sm muted mono' }, fileLabel(leaf.files))),
        h('div', { class: 'rw-leaf-actions' },
          // Named by key type and file, like Remove: a list of buttons tells the certificates apart.
          onDetails ? withAction(IconButton({
            icon: 'eye', size: 'sm', label: t('rw.details', { key: leaf.keyType, file: fileLabel(leaf.files) }), onClick: () => onDetails(leaf)
          }), 'rw-details') : null,
          withAction(IconButton({
            icon: 'x', size: 'sm', label: t('rw.removeCert', { key: leaf.keyType, file: fileLabel(leaf.files) }),
            onClick: () => onRemoveLeaf(leaf)
          }), 'rw-remove-leaf')))))));
  }

  if (bundle.skipped.length) {
    el.append(h('div', { class: 'rw-skipped', dataset: { role: 'renewal-skipped' } },
      h('div', { class: 'rw-skipped-title text-sm' }, t('rw.skipped')),
      h('ul', { class: 'rw-skipped-list' }, bundle.skipped.map((s) => h('li', { class: 'rw-skip', dataset: { issue: s.issue } },
        Icon('alert', { size: 14 }),
        h('span', { class: 'rw-skip-text text-sm' }, h('span', { class: 'mono' }, s.file || '—'), ` — ${skipText(s)}`),
        withAction(IconButton({ icon: 'x', size: 'sm', label: t('rw.removeFile', { file: s.file || '—' }), onClick: () => onRemoveFile(s) }),
          'rw-remove-file'))))));
  }
  if (bundle.keyFiles && bundle.keyFiles.length) {
    el.append(h('p', { class: 'rw-key-note text-sm', dataset: { warning: 'PRIVATE_KEY_PRESENT' } },
      Icon('key', { size: 14 }), h('span', null, t('rw.keyIgnored', { files: bundle.keyFiles.join(', ') }))));
  }
  return el;
}

/* ------------------------------------------------------------------------ */
/* The "Renewal plan" tab                                                   */
/* ------------------------------------------------------------------------ */

/** A matrix cell: the names a server needs from one set (an origin hint marked as such). */
function cellNames(entries) {
  if (!entries || !entries.length) return null;
  return TruncatedList(entries, {
    max: 4,
    render: (e) => h('span', { class: ['rw-cell-name', { 'is-hint': e.via === 'hint' }], title: e.ips.join(', ') || null }, e.name,
      e.via === 'hint' ? h('span', { class: 'muted' }, ` · ${t('rw.hint')}`) : null)
  });
}

/** Server cell: the server's name and addresses, or an address outside the inventory. */
function serverCell(row) {
  if (!row.server) {
    return h('div', { class: 'rw-srv' },
      h('span', { class: 'rw-srv-name mono' }, row.ip),
      h('span', { class: 'cluster rw-srv-badges' },
        Badge(t('rw.notInList'), { variant: 'neutral' }),
        row.private ? Badge(t('rw.private'), { variant: 'private', icon: 'lock' }) : null));
  }
  return h('div', { class: 'rw-srv' },
    h('span', { class: 'rw-srv-name' }, row.server.name),
    row.server.ips.length ? h('span', { class: 'rw-srv-ips mono text-xs muted' }, row.server.ips.join(', ')) : null,
    row.maybe ? h('span', { class: 'cluster rw-srv-badges' }, Badge(t('rw.maybe'), { variant: 'info', icon: 'help', title: t('rw.maybeTitle') })) : null);
}

/**
 * The "Renewal plan" results tab of SSL Targets with several certificate sets.
 * @param {{ plan: import('../lib/certsets.js').RenewalPlan, inventory: boolean, subject?: string }} opts
 *   `inventory`: the scan had servers to match (else the matrix holds addresses only)
 * @returns {HTMLElement}
 */
export function RenewalPlanPanel({ plan, inventory, subject = '' }) {
  const sets = plan.sets;
  const save = (base, ext, text, mime) => {
    const file = downloadText(timestampedName(base, ext, subject), text, mime);
    toast(t('rw.exported', { file }), { type: 'success', timeout: 2500 });
  };
  const workCsv = (rows) => toCsv(workListRows({ sets, rows }), WORKLIST_COLUMNS);

  const setCards = h('div', { class: 'rw-plan-sets', attrs: { role: 'list', 'aria-label': t('rw.plan.setsTitle') } },
    sets.map((set) => {
      // Your servers and the addresses outside the inventory, apart (the summary counts servers only).
      const use = plan.perSet[set.id] || { names: 0, rows: 0, servers: 0, addresses: 0 };
      return h('div', {
        class: 'rw-plan-set', attrs: { role: 'listitem' },
        dataset: { set: set.id, hosts: String(use.names), servers: String(use.servers), addresses: String(use.addresses) }
      },
        h('div', { class: 'rw-plan-set-head' }, SetBadge(set.id),
          set.keyTypes.map((k) => Badge(k, { variant: 'neutral', icon: 'key', mono: true, className: 'rw-key' }))),
        TruncatedList(set.names, { max: 4, inline: true }),
        h('div', { class: 'text-sm muted' }, t(use.addresses ? 'rw.plan.setUseOut' : 'rw.plan.setUse', {
          hosts: formatNumber(use.names), servers: formatNumber(use.servers), addresses: formatNumber(use.addresses),
          date: set.expires ? formatDate(set.expires) : '—'
        })),
        h('div', { class: 'text-xs muted mono rw-plan-set-files' }, fileLabel(set.files)));
    }));

  const columns = [
    {
      key: 'server', label: t('rw.col.server'), sortable: true,
      sortValue: (r) => (r.server ? `0 ${r.server.name}` : `1 ${r.ip}`),
      searchValue: (r) => (r.server ? [r.server.name, ...r.server.ips].join(' ') : r.ip),
      exportValue: (r) => (r.server ? r.server.name : r.ip),
      render: serverCell
    },
    ...sets.map((set) => ({
      key: `set-${set.id}`, label: t('rw.set', { id: set.id }), className: 'rw-col-set', sortable: true, defaultDir: 'desc',
      sortValue: (r) => (r.cells[set.id] ? r.cells[set.id].length : 0),
      searchValue: (r) => (r.cells[set.id] || []).map((e) => e.name).join(' '),
      exportValue: (r) => (r.cells[set.id] || []).map((e) => e.name).join(' '),
      render: (r) => cellNames(r.cells[set.id])
    })),
    {
      key: 'total', label: t('rw.col.total'), sortable: true, align: 'end', className: 'num', defaultDir: 'desc',
      sortValue: (r) => Object.values(r.cells).reduce((n, list) => n + list.length, 0),
      render: (r) => formatNumber(Object.values(r.cells).reduce((n, list) => n + list.length, 0))
    }
  ];
  const matrix = DataTable({
    caption: t('rw.plan.caption'),
    rows: plan.rows,
    rowKey: (r) => r.key,
    search: plan.rows.length > 8,
    cellLabels: true,
    empty: t(inventory ? 'rw.plan.empty' : 'rw.plan.noInventory'),
    rowClass: (r) => ({ 'rw-row-needs': r.needsCert, 'rw-row-maybe': r.maybe }),
    className: 'rw-matrix',
    // Its export is the work list (the button above); the scan's full JSON carries the plan.
    export: false,
    columns
  });

  const uncoveredTable = plan.uncovered.length ? DataTable({
    caption: t('rw.uncovered', { count: plan.uncovered.length }),
    rows: plan.uncovered,
    rowKey: (u) => u.name,
    dense: true,
    search: plan.uncovered.length > 10,
    className: 'rw-uncovered',
    export: { filename: 'uncovered-names', subject },
    columns: [
      { key: 'name', label: t('rw.col.name'), mono: true, sortable: true, searchValue: (u) => u.name },
      {
        key: 'servers', label: t('rw.col.onServers'), sortable: true,
        sortValue: (u) => (u.servers[0] ? u.servers[0].name : ''),
        searchValue: (u) => u.servers.map((s) => `${s.name} ${s.ip}`).join(' '),
        exportValue: (u) => [...new Set(u.servers.map((s) => s.name))].join(' '),
        render: (u) => (u.servers.length ? TruncatedList([...new Set(u.servers.map((s) => s.name))], { max: 3, mono: false }) : null)
      },
      {
        key: 'dns', label: t('rw.col.dns'), sortable: true,
        sortValue: (u) => (u.resolving ? 0 : 1),
        exportValue: (u) => (u.resolving ? 'resolves' : 'no-address'),
        render: (u) => (u.resolving ? Badge(t('rw.resolves'), { variant: 'direct' }) : Badge(t('rw.noAddress'), { variant: 'neutral' }))
      }
    ]
  }) : null;

  return h('div', { class: 'rw-plan stack', dataset: { role: 'renewal-plan', rows: String(plan.rows.length), uncovered: String(plan.uncovered.length) } },
    h('p', { class: 'muted text-sm' }, t('rw.plan.intro')),
    h('h3', { class: 'scan-subtitle' }, t('rw.plan.setsTitle')),
    setCards,
    h('div', { class: 'rw-plan-matrix-head' },
      h('h3', { class: 'scan-subtitle' }, t('rw.plan.matrixTitle')),
      Button({
        label: t('rw.plan.worklist'), icon: 'download', size: 'sm', title: t('rw.plan.worklistTitle'), dataset: { export: 'worklist' },
        disabled: !plan.rows.length, onClick: () => save('renewal-worklist', 'csv', workCsv(plan.rows), 'text/csv;charset=utf-8')
      })),
    matrix.el,
    uncoveredTable ? h('h3', { class: 'scan-subtitle', dataset: { role: 'renewal-uncovered-title' } }, t('rw.uncovered', { count: plan.uncovered.length })) : null,
    uncoveredTable ? h('p', { class: 'muted text-sm' }, t('rw.uncovered.desc')) : null,
    uncoveredTable ? uncoveredTable.el : EmptyState({ compact: true, icon: 'check-circle', message: t('rw.uncovered', { count: 0 }) }));
}
