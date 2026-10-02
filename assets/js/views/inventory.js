/**
 * views/inventory.js — "Servers": paste or import the server inventory, see it parsed live,
 * fix warnings, save it to the current workspace (state.js → lib/workspace.js, this browser's
 * IndexedDB). Each workspace has its own inventory, so one customer's addresses never meet
 * another's (no DUPLICATE_IP across customers); the editor card names the workspace.
 *
 * The inventory is what turns DNS answers into "these 10 of your 300 servers need the new
 * certificate": other views read it through `ctx.state.inventory` / `ctx.getInventoryIndex()`.
 * Nothing here ever leaves the browser.
 */

import { h, clear, debounce } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, DataTable, Disclosure, FileDrop, Icon, Modal, StatCard, Tabs,
  TruncatedList, confirmDialog, ipSortValue, textarea, toast
} from '../ui/components.js';
import { downloadText } from '../ui/download.js';
import { formatNumber, formatRelative, registerStrings } from '../i18n.js';
import { parseInventory, addressTargets, serverTargets } from '../lib/inventory.js';
import { terminatesTls, topologyTokens } from '../lib/topology.js';
import { TopologyCard } from '../ui/topology.js';
import { cliServerName } from '../lib/export.js';
import { isPrivateIP, ipVersion } from '../lib/netinfo.js';
import { workspaceLabel } from '../ui/workspace-ui.js';

/** Route id. */
export const id = 'inventory';
/** i18n key of the page title. */
export const titleKey = 'nav.inventory';
/** Nav/page icon. */
export const icon = 'server';

/** File types offered by the importer. */
const ACCEPT = '.txt,.csv,.tsv,.ini,.cfg,.conf,.yml,.yaml,.json,.jsonl,.hosts,.list,.lst';

/** Example inventories (all verified to parse with lib/inventory.parseInventory). */
const EXAMPLES = [
  {
    id: 'lines',
    labelKey: 'inv.ex.lines',
    text: '# name  ip [ip ...]\nweb01        10.0.1.11\nweb02        10.0.1.12  2001:db8::12\nlb-eu        203.0.113.5\n10.0.2.20    db01\n'
  },
  {
    id: 'hosts',
    labelKey: 'inv.ex.hosts',
    text: '127.0.0.1     localhost\n10.0.1.11     web01.corp.local web01\n10.0.1.12     web02.corp.local web02\n192.168.10.5  mail.example.com.tr mail\n'
  },
  {
    id: 'csv',
    labelKey: 'inv.ex.csv',
    text: 'hostname,ip_address,environment\nweb01,10.0.1.11,prod\nweb02,10.0.1.12,prod\napi01,10.0.3.21,staging\n'
  },
  {
    id: 'ini',
    labelKey: 'inv.ex.ini',
    text: '[web]\nweb01 ansible_host=10.0.1.11\nweb02 ansible_host=10.0.1.12\n\n[db]\ndb01 ansible_host=10.0.2.20\n'
  },
  {
    id: 'yaml',
    labelKey: 'inv.ex.yaml',
    text: 'all:\n  children:\n    web:\n      hosts:\n        web01:\n          ansible_host: 10.0.1.11\n        web02:\n          ansible_host: 10.0.1.12\n'
  },
  {
    id: 'json',
    labelKey: 'inv.ex.json',
    text: '[\n  { "name": "web01", "ip": "10.0.1.11" },\n  { "name": "web02", "ips": ["10.0.1.12", "2001:db8::12"] }\n]\n'
  },
  {
    id: 'topology',
    labelKey: 'inv.ex.topology',
    text: '# where TLS terminates: lb01 and lb02 share 203.0.113.50 and forward to web01 and web02\n'
      + 'lb01   203.0.113.2  vip=203.0.113.50 backends=web01,web02\n'
      + 'lb02   203.0.113.3  vip=203.0.113.50 backends=web01,web02\n'
      + 'web01  10.0.1.11    terminates_tls=no\n'
      + 'web02  10.0.1.12    ports=8443\n'
      + 'app01  10.0.2.20    nat=203.0.113.10\n'
  }
];

registerStrings('en', {
  'inv.privacyTitle': 'Stays in your browser',
  'inv.privacy': 'The inventory is parsed and stored only on this device, with the current workspace (this browser’s IndexedDB). It is never uploaded — the other tools use it locally to match DNS answers to your servers. Each workspace has its own inventory.',
  'inv.workspace': 'Workspace: {name}',
  'inv.workspaceTitle': 'This inventory belongs to the workspace “{name}”. Switch workspaces in the header.',
  'inv.editorTitle': 'Inventory',
  'inv.editorSubtitle': 'Paste it or import a file — any common format works',
  'inv.textareaLabel': 'Server inventory',
  'inv.placeholder': '# one server per line: name and IP address(es)\nweb01 10.0.1.11\nweb02 10.0.1.12 2001:db8::12\n\n# also: /etc/hosts, CSV/TSV, Ansible INI/YAML, JSON',
  'inv.dropTitle': 'Import a file',
  'inv.dropHint': 'drop it here, click to choose, or paste',
  'inv.save': 'Save inventory',
  'inv.clear': 'Clear',
  'inv.clearConfirm': 'Remove the saved inventory of this workspace from this browser?',
  'inv.cleared': 'Inventory cleared',
  'inv.saved': { zero: 'Inventory saved (empty)', one: 'Inventory saved: {count} server', other: 'Inventory saved: {count} servers' },
  'inv.notPersisted': 'Could not write to browser storage — the inventory is kept only until this tab is closed.',
  'inv.unsaved': 'Unsaved changes',
  'inv.unsavedHint': 'The other tools use the saved inventory — save to apply your changes.',
  'inv.savedAt': 'Saved {when}',
  'inv.notSaved': 'Nothing saved yet',
  'inv.importTitle': 'Import “{name}”',
  'inv.importBody': 'The editor already contains an inventory. Replace it with the file, or append the file to it?',
  'inv.replace': 'Replace',
  'inv.append': 'Append',
  'inv.imported': '{name} loaded — review it and press Save.',
  'inv.stat.servers': 'Servers',
  'inv.stat.ips': 'IP addresses',
  'inv.stat.ipsHint': '{v4} IPv4 · {v6} IPv6 · {priv} private',
  'inv.stat.groups': 'Groups',
  'inv.stat.warnings': 'Warnings',
  'inv.stat.lines': { zero: 'no lines', one: '{count} line', other: '{count} lines' },
  'inv.tableTitle': 'Parsed servers',
  'inv.tableSubtitle': 'What the tools will match against',
  'inv.col.name': 'Server',
  'inv.col.ips': 'IP addresses',
  'inv.col.groups': 'Groups',
  'inv.col.line': 'Line',
  'inv.private': 'private',
  'inv.aliases': 'also: {names}',
  'inv.empty': 'No servers yet. Paste your inventory on the left or load an example.',
  'inv.targets': 'targets.txt',
  'inv.targetsTitle': 'Download "name ip" lines for the CLI (-t targets.txt)',
  'inv.warningsTitle': 'Warnings',
  'inv.warningsSubtitle': 'Lines that could not be used as-is — click one to jump to it',
  'inv.warn.NO_IP': 'No IP address — this server cannot be matched',
  'inv.warn.INVALID_IP': 'Invalid IP address',
  'inv.warn.DUPLICATE_IP': 'The same IP address (on the same port) belongs to several servers',
  'inv.warn.PARSE': 'Line could not be understood',
  'inv.warn.INVALID_IP.port': 'Invalid port — a port is a number from 1 to 65535',
  'inv.warn.PARSE.hostPort': 'Host name with a port — servers are matched by address here, so write the address with the port',
  'inv.warn.INVALID_IP.zone': 'IPv6 zone id — an address written with a zone (%eth0) cannot be a target with a port',
  'inv.warn.PARSE.sshPort': 'Ansible SSH port — a port on an Ansible host is its SSH port (ansible_port), not a TLS port: the CLI scans this server on its -p ports',
  'inv.warn.TOPOLOGY': 'Topology key that could not be used',
  'inv.warn.TOPOLOGY.ports': 'Invalid ports= — TLS ports are numbers from 1 to 65535, comma separated (ports=443,8443)',
  'inv.warn.TOPOLOGY.plainPorts': 'ports= lists a port that usually carries no TLS (22, 80 …) — the server is scanned on these ports instead of -p: list its TLS ports',
  'inv.warn.TOPOLOGY.terminatesTls': 'Invalid terminates_tls= — write yes or no',
  'inv.warn.TOPOLOGY.vip': 'Invalid vip= — a shared address is an IP address without a port',
  'inv.warn.TOPOLOGY.nat': 'Invalid nat= — a public address is an IP address without a port',
  'inv.warn.TOPOLOGY.backends': 'Invalid backends= — list server names (or their addresses), comma separated',
  'inv.warn.TOPOLOGY.unknownBackend': 'Unknown backend — no server of that name or address in the inventory',
  'inv.warn.TOPOLOGY.selfBackend': 'A server cannot be its own backend',
  'inv.warn.TOPOLOGY.conflict': 'terminates_tls given both ways — yes is kept, the safe value',
  'inv.warn.TOPOLOGY.noServer': 'Topology key without a server — write it after the server’s name and address',
  'inv.warn.TOPOLOGY.groupVars': 'Group variables are not read for the topology — set it on each host',
  'inv.warn.TOPOLOGY.noTermination': 'TLS terminates nowhere behind this load balancer — it passes TLS through (terminates_tls=no) and every backend says terminates_tls=no too',
  'inv.badge.lb': 'load balancer',
  'inv.badge.plain': 'no certificate',
  'inv.lineN': 'line {n}',
  'inv.wholeInput': 'input',
  'inv.formatsTitle': 'Supported formats & examples',
  'inv.useExample': 'Use this example',
  'inv.exampleConfirm': 'Replace the current editor content with this example?',
  'inv.ex.lines': 'Name + IP',
  'inv.ex.hosts': '/etc/hosts',
  'inv.ex.csv': 'CSV / TSV',
  'inv.ex.ini': 'Ansible INI',
  'inv.ex.yaml': 'YAML',
  'inv.ex.json': 'JSON',
  'inv.ex.topology': 'Topology',
  'inv.topologyNote': 'Topology keys on a server’s line (or as CSV columns, Ansible host variables, JSON keys) say where TLS terminates: ports=443,8443 (its TLS ports, for addresses written without a port; in JSON and YAML the key is tls_ports, since a ports key there usually lists every open port), terminates_tls=no (a plain-HTTP backend that never gets the certificate), vip= (an address an HA pair shares), backends=web01,web02 (a load balancer and the servers behind it) and nat= (the public address DNS answers with). SSL Targets and the CLI follow them.',
  'inv.formatsNote': 'Comments (#, ;, //) are ignored. The same server on several lines merges its IPs. CSV headers such as name/hostname/server and ip/ip_address/public_ip/private_ip/address are recognised; JSON from Terraform, AWS, Ansible and kubectl works too. An address written with a port (203.0.113.10:8443, [2001:db8::1]:8443) keeps it: the CLI scans it on that port instead of -p. In an Ansible INI inventory (a [group] section, or a line with ansible_* variables) the port of the host at the start of a line (203.0.113.10:2222) is Ansible’s SSH port, so that host is scanned on -p.'
});

registerStrings('tr', {
  'inv.privacyTitle': 'Tarayıcınızda kalır',
  'inv.privacy': 'Envanter yalnızca bu cihazda, geçerli çalışma alanıyla birlikte ayrıştırılır ve saklanır (bu tarayıcının IndexedDB deposu). Hiçbir yere yüklenmez — diğer araçlar DNS yanıtlarını sunucularınızla yerel olarak eşleştirmek için kullanır. Her çalışma alanının kendi envanteri vardır.',
  'inv.workspace': 'Çalışma alanı: {name}',
  'inv.workspaceTitle': 'Bu envanter “{name}” çalışma alanına ait. Çalışma alanını üst çubuktan değiştirin.',
  'inv.editorTitle': 'Envanter',
  'inv.editorSubtitle': 'Yapıştırın veya dosya içe aktarın — yaygın biçimlerin hepsi olur',
  'inv.textareaLabel': 'Sunucu envanteri',
  'inv.placeholder': '# her satıra bir sunucu: ad ve IP adres(ler)i\nweb01 10.0.1.11\nweb02 10.0.1.12 2001:db8::12\n\n# ayrıca: /etc/hosts, CSV/TSV, Ansible INI/YAML, JSON',
  'inv.dropTitle': 'Dosya içe aktar',
  'inv.dropHint': 'buraya bırakın, seçmek için tıklayın veya yapıştırın',
  'inv.save': 'Envanteri kaydet',
  'inv.clear': 'Temizle',
  'inv.clearConfirm': 'Bu çalışma alanının kayıtlı envanteri bu tarayıcıdan kaldırılsın mı?',
  'inv.cleared': 'Envanter temizlendi',
  'inv.saved': { zero: 'Envanter kaydedildi (boş)', other: 'Envanter kaydedildi: {count} sunucu' },
  'inv.notPersisted': 'Tarayıcı depolamasına yazılamadı — envanter yalnızca bu sekme kapanana kadar tutulacak.',
  'inv.unsaved': 'Kaydedilmemiş değişiklikler',
  'inv.unsavedHint': 'Diğer araçlar kayıtlı envanteri kullanır — değişikliklerin geçerli olması için kaydedin.',
  'inv.savedAt': '{when} kaydedildi',
  'inv.notSaved': 'Henüz kayıt yok',
  'inv.importTitle': '“{name}” içe aktarılıyor',
  'inv.importBody': 'Düzenleyicide zaten bir envanter var. Dosyayla değiştirilsin mi, yoksa sonuna mı eklensin?',
  'inv.replace': 'Değiştir',
  'inv.append': 'Sonuna ekle',
  'inv.imported': '{name} yüklendi — kontrol edip Kaydet’e basın.',
  'inv.stat.servers': 'Sunucular',
  'inv.stat.ips': 'IP adresleri',
  'inv.stat.ipsHint': '{v4} IPv4 · {v6} IPv6 · {priv} özel',
  'inv.stat.groups': 'Gruplar',
  'inv.stat.warnings': 'Uyarılar',
  'inv.stat.lines': { zero: 'satır yok', other: '{count} satır' },
  'inv.tableTitle': 'Ayrıştırılan sunucular',
  'inv.tableSubtitle': 'Araçların eşleştirme yapacağı liste',
  'inv.col.name': 'Sunucu',
  'inv.col.ips': 'IP adresleri',
  'inv.col.groups': 'Gruplar',
  'inv.col.line': 'Satır',
  'inv.private': 'özel',
  'inv.aliases': 'diğer adlar: {names}',
  'inv.empty': 'Henüz sunucu yok. Envanterinizi soldaki alana yapıştırın veya bir örnek yükleyin.',
  'inv.targets': 'targets.txt',
  'inv.targetsTitle': 'CLI için "ad ip" satırlarını indir (-t targets.txt)',
  'inv.warningsTitle': 'Uyarılar',
  'inv.warningsSubtitle': 'Olduğu gibi kullanılamayan satırlar — gitmek için tıklayın',
  'inv.warn.NO_IP': 'IP adresi yok — bu sunucu eşleştirilemez',
  'inv.warn.INVALID_IP': 'Geçersiz IP adresi',
  'inv.warn.DUPLICATE_IP': 'Aynı IP adresi (aynı portta) birden fazla sunucuya ait',
  'inv.warn.PARSE': 'Satır anlaşılamadı',
  'inv.warn.INVALID_IP.port': 'Geçersiz port — port 1 ile 65535 arasında bir sayıdır',
  'inv.warn.PARSE.hostPort': 'Portlu host adı — burada sunucular adresle eşleştirilir; adresi portuyla yazın',
  'inv.warn.INVALID_IP.zone': 'IPv6 bölge kimliği (zone id) — bölgesiyle (%eth0) yazılan bir adres portlu bir hedef olamaz',
  'inv.warn.PARSE.sshPort': 'Ansible SSH portu — bir Ansible host adının ya da adresinin portu SSH portudur (ansible_port), TLS portu değil: CLI bu sunucuyu -p portlarından tarar',
  'inv.warn.TOPOLOGY': 'Kullanılamayan topoloji anahtarı',
  'inv.warn.TOPOLOGY.ports': 'Geçersiz ports= — TLS portları 1 ile 65535 arasında, virgülle ayrılmış sayılardır (ports=443,8443)',
  'inv.warn.TOPOLOGY.plainPorts': 'ports= genelde TLS taşımayan bir port içeriyor (22, 80 …) — sunucu -p yerine bu portlardan taranır: TLS portlarını yazın',
  'inv.warn.TOPOLOGY.terminatesTls': 'Geçersiz terminates_tls= — yes ya da no yazın',
  'inv.warn.TOPOLOGY.vip': 'Geçersiz vip= — paylaşılan adres portsuz bir IP adresidir',
  'inv.warn.TOPOLOGY.nat': 'Geçersiz nat= — genel adres portsuz bir IP adresidir',
  'inv.warn.TOPOLOGY.backends': 'Geçersiz backends= — sunucu adlarını (ya da adreslerini) virgülle ayırarak yazın',
  'inv.warn.TOPOLOGY.unknownBackend': 'Bilinmeyen arka uç sunucusu — envanterde bu ad ya da adreste bir sunucu yok',
  'inv.warn.TOPOLOGY.selfBackend': 'Bir sunucu kendi arka ucu olamaz',
  'inv.warn.TOPOLOGY.conflict': 'terminates_tls iki farklı değerle yazılmış — güvenli olan yes geçerli',
  'inv.warn.TOPOLOGY.noServer': 'Sunucusu olmayan topoloji anahtarı — sunucunun adından ve adresinden sonra yazın',
  'inv.warn.TOPOLOGY.groupVars': 'Grup değişkenleri topoloji için okunmaz — her host için ayrı yazın',
  'inv.warn.TOPOLOGY.noTermination': 'Bu yük dengeleyicinin arkasında TLS hiçbir yerde sonlanmıyor — TLS’i olduğu gibi iletiyor (terminates_tls=no) ve her arka uç da terminates_tls=no diyor',
  'inv.badge.lb': 'yük dengeleyici',
  'inv.badge.plain': 'sertifika gerekmez',
  'inv.lineN': '{n}. satır',
  'inv.wholeInput': 'girdi',
  'inv.formatsTitle': 'Desteklenen biçimler ve örnekler',
  'inv.useExample': 'Bu örneği kullan',
  'inv.exampleConfirm': 'Düzenleyicideki içerik bu örnekle değiştirilsin mi?',
  'inv.ex.lines': 'Ad + IP',
  'inv.ex.hosts': '/etc/hosts',
  'inv.ex.csv': 'CSV / TSV',
  'inv.ex.ini': 'Ansible INI',
  'inv.ex.yaml': 'YAML',
  'inv.ex.json': 'JSON',
  'inv.ex.topology': 'Topoloji',
  'inv.topologyNote': 'Bir sunucunun satırındaki (ya da CSV sütunu, Ansible host değişkeni, JSON anahtarı olarak yazılan) topoloji anahtarları TLS’in nerede sonlandığını söyler: ports=443,8443 (portsuz yazılan adreslerinin TLS portları; JSON ve YAML’da anahtar tls_ports’tur, çünkü oradaki ports anahtarı genelde açık portların hepsidir), terminates_tls=no (sertifikayı hiç almayan düz HTTP arka uç sunucusu), vip= (bir HA çiftinin paylaştığı adres), backends=web01,web02 (yük dengeleyici ve arkasındaki sunucular) ve nat= (DNS’in döndürdüğü genel adres). SSL Hedefleri ve CLI bunlara uyar.',
  'inv.formatsNote': 'Yorumlar (#, ;, //) yok sayılır. Birden çok satırda geçen aynı sunucunun IP’leri birleştirilir. name/hostname/server ve ip/ip_address/public_ip/private_ip/address gibi CSV başlıkları tanınır; Terraform, AWS, Ansible ve kubectl JSON çıktıları da çalışır. Portuyla yazılan bir adres (203.0.113.10:8443, [2001:db8::1]:8443) portunu korur: CLI onu -p yerine o porttan tarar. Ansible INI envanterinde ([grup] bölümü ya da ansible_* değişkenli bir satır) satır başındaki host adının ya da adresin portu (203.0.113.10:2222) Ansible’ın SSH portudur; o sunucu -p portlarından taranır.'
});

/* ------------------------------------------------------------------------ */

let teardown = null;

/**
 * "name ip ip…" lines for the CLI's -t option, one per server. The name is made one CLI token
 * (lib/export.cliServerName), so "Web Server 1" or "#bastion" is neither split, merged with
 * another server nor read as a comment. An address written with a port keeps it
 * (lib/inventory.serverTargets: "web01 203.0.113.10:8443"), so the CLI scans the same ip:port;
 * so does a server's `ports=`. Its other topology keys follow (lib/topology.topologyTokens:
 * "web01 10.0.0.21 terminates_tls=no", "lb01 203.0.113.2 backends=web01,web02 vip=203.0.113.50").
 * @param {Array<{ name: string, ips: string[], ports?: object }>} servers
 * @returns {string}
 */
export function targetsText(servers) {
  const lines = servers.filter((s) => s.ips.length)
    .map((s) => [cliServerName(s.name), ...serverTargets(s), ...topologyTokens(s, cliServerName)].filter(Boolean).join(' '));
  return lines.length ? `${lines.join('\n')}\n` : '';
}

/** A server's addresses as the table shows them: `{ ip, target }`, the target with its own port if any. */
const endpointsOf = (s) => s.ips.flatMap((ip) => addressTargets(s, ip).map((target) => ({ ip, target })));

/**
 * Character offsets [start, end) of 1-based line `n` in `text`.
 * @param {string} text
 * @param {number} n
 * @returns {[number, number]}
 */
export function lineRange(text, n) {
  const lines = String(text).split('\n');
  const idx = Math.min(Math.max(1, n), lines.length) - 1;
  let start = 0;
  for (let i = 0; i < idx; i += 1) start += lines[i].length + 1;
  return [start, start + lines[idx].length];
}

/**
 * Mount the Servers view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { t, state } = ctx;
  const saved = state.inventory;
  const draft = state.takeSession('inventoryDraft');
  const restoredText = ctx.restored && typeof ctx.restored.text === 'string' ? ctx.restored.text : undefined;
  const initialText = restoredText ?? draft ?? saved.text;

  let parsed = parseInventory(initialText);

  /* --- editor ---------------------------------------------------------- */
  const editor = textarea({
    label: t('inv.textareaLabel'),
    value: initialText,
    rows: 16,
    placeholder: t('inv.placeholder'),
    className: 'inv-editor-field',
    attrs: { 'data-role': 'inventory-text', 'data-shortcut': 'focus' }
  });
  editor.el.querySelector('.field-label').classList.add('sr-only');

  const statusEl = h('div', { class: 'inv-status', attrs: { 'aria-live': 'polite' } });
  const saveBtn = Button({ label: t('inv.save'), icon: 'check', variant: 'primary', onClick: save, dataset: { action: 'save', shortcut: 'submit' } });
  const clearBtn = Button({ label: t('inv.clear'), icon: 'trash', variant: 'ghost', onClick: clearAll, dataset: { action: 'clear' } });

  const drop = FileDrop({
    accept: ACCEPT,
    multiple: true,
    compact: true,
    icon: 'upload',
    title: t('inv.dropTitle'),
    hint: t('inv.dropHint'),
    maxBytes: 8 * 1024 * 1024,
    onFiles: (files) => importFiles(files)
  });

  const examplesTabs = Tabs(EXAMPLES.map((ex) => ({
    id: ex.id,
    label: t(ex.labelKey),
    content: () => h('div', { class: 'stack-sm' },
      CodeBlock(ex.text, { label: t(ex.labelKey) }),
      h('div', { class: 'cluster' },
        Button({ label: t('inv.useExample'), icon: 'arrow-down', size: 'sm', dataset: { example: ex.id }, onClick: () => useExample(ex) })))
  })), { label: t('inv.formatsTitle'), className: 'inv-examples' });

  const wsName = workspaceLabel(state.workspace);
  const editorCard = Card({
    title: t('inv.editorTitle'),
    subtitle: t('inv.editorSubtitle'),
    icon: 'file-text',
    className: 'inv-editor',
    actions: Badge(t('inv.workspace', { name: wsName }), {
      icon: 'briefcase', variant: 'accent', className: 'inv-workspace', title: t('inv.workspaceTitle', { name: wsName })
    }),
    children: h('div', { class: 'stack' },
      drop,
      editor.el,
      h('div', { class: 'inv-actions' }, statusEl, h('div', { class: 'inv-buttons' }, clearBtn, saveBtn)),
      Disclosure({
        summary: t('inv.formatsTitle'),
        className: 'inv-formats',
        children: h('div', { class: 'stack-sm' }, h('p', { class: 'muted text-sm' }, t('inv.formatsNote')),
          h('p', { class: 'muted text-sm', dataset: { role: 'topology-note' } }, t('inv.topologyNote')), examplesTabs)
      }))
  });

  /* --- results --------------------------------------------------------- */
  const stats = {
    servers: StatCard({ label: t('inv.stat.servers'), icon: 'server', variant: 'accent' }),
    ips: StatCard({ label: t('inv.stat.ips'), icon: 'network' }),
    groups: StatCard({ label: t('inv.stat.groups'), icon: 'layers' }),
    warnings: StatCard({ label: t('inv.stat.warnings'), icon: 'alert' })
  };

  const targetsBtn = Button({
    label: t('inv.targets'),
    icon: 'download',
    size: 'sm',
    title: t('inv.targetsTitle'),
    dataset: { action: 'targets' },
    onClick: () => downloadText('targets.txt', targetsText(parsed.servers))
  });

  const table = DataTable({
    caption: t('inv.tableTitle'),
    search: true,
    pageSize: 200,
    sort: { key: 'line', dir: 'asc' },
    empty: t('inv.empty'),
    rowKey: (s) => s.id,
    toolbar: targetsBtn,
    export: { filename: 'servers' },
    columns: [
      {
        key: 'name',
        label: t('inv.col.name'),
        sortable: true,
        sortValue: (s) => s.name,
        searchValue: (s) => [s.name, ...(s.aliases || [])].join(' '),
        exportValue: (s) => s.name,
        render: (s) => h('div', { class: 'inv-name' },
          h('span', { class: 'inv-name-main' }, s.name),
          s.aliases && s.aliases.length ? h('span', { class: 'inv-aliases' }, t('inv.aliases', { names: s.aliases.join(', ') })) : null,
          s.backends || !terminatesTls(s) ? h('span', { class: 'cluster inv-topo' },
            s.backends ? Badge(t('inv.badge.lb'), { variant: 'accent', icon: 'git-branch' }) : null,
            terminatesTls(s) ? null : Badge(t('inv.badge.plain'), { variant: 'ok', icon: 'unlock' })) : null)
      },
      {
        key: 'ips',
        label: t('inv.col.ips'),
        sortable: true,
        sortValue: (s) => ipSortValue(s.ips[0]),
        searchValue: (s) => serverTargets(s).join(' '),
        exportValue: (s) => serverTargets(s).join(' '),
        render: (s) => TruncatedList(endpointsOf(s), {
          max: 4,
          render: (e) => h('span', { class: 'inv-ip' }, e.target,
            isPrivateIP(e.ip) ? Badge(t('inv.private'), { variant: 'private', className: 'inv-ip-badge' }) : null)
        })
      },
      {
        key: 'groups',
        label: t('inv.col.groups'),
        sortable: true,
        sortValue: (s) => s.groups[0],
        searchValue: (s) => s.groups.join(' '),
        exportValue: (s) => s.groups.join(' '),
        render: (s) => (s.groups.length ? h('div', { class: 'cluster inv-groups' }, s.groups.map((g) => Badge(g, { variant: 'neutral' }))) : null)
      },
      {
        key: 'line',
        label: t('inv.col.line'),
        sortable: true,
        align: 'end',
        width: '5.5rem',
        className: 'num',
        render: (s) => h('button', {
          type: 'button',
          class: 'link-btn num',
          title: t('inv.lineN', { n: s.line }),
          on: { click: () => jumpToLine(s.line) }
        }, String(s.line))
      }
    ]
  });

  const warningsList = h('ul', { class: 'inv-warnings' });
  const warningsCard = Card({
    title: t('inv.warningsTitle'),
    subtitle: t('inv.warningsSubtitle'),
    icon: 'alert',
    className: 'inv-warnings-card',
    padded: false,
    children: warningsList
  });

  // Where TLS terminates (load balancers, VIPs, NAT): only for an inventory with topology keys.
  const topologySlot = h('div', { class: 'inv-topology', dataset: { role: 'topology-slot' } });

  // No part of the editor's form: Ctrl/Cmd+Enter in the table's filter saves nothing.
  const resultsCol = h('div', { class: 'stack inv-results', dataset: { shortcutScope: 'results' } },
    h('div', { class: 'stat-grid inv-stats' }, stats.servers, stats.ips, stats.groups, stats.warnings),
    warningsCard,
    topologySlot,
    Card({ title: t('inv.tableTitle'), subtitle: t('inv.tableSubtitle'), icon: 'server', children: table }));

  container.append(
    Alert({ variant: 'ok', icon: 'lock', title: t('inv.privacyTitle'), message: t('inv.privacy'), compact: true }),
    h('div', { class: 'inv-layout' }, editorCard, resultsCol));

  /* --- behaviour ------------------------------------------------------- */
  function isDirty() {
    return editor.value !== state.inventory.text;
  }

  function renderStatus() {
    clear(statusEl);
    const dirty = isDirty();
    if (dirty) {
      statusEl.append(Badge(t('inv.unsaved'), { variant: 'warn', icon: 'alert', title: t('inv.unsavedHint') }));
    } else if (state.inventory.updatedAt) {
      statusEl.append(h('span', { class: 'muted text-sm', title: state.inventory.updatedAt.toLocaleString() },
        Icon('check', { size: 14 }), ' ', t('inv.savedAt', { when: formatRelative(state.inventory.updatedAt) })));
    } else {
      statusEl.append(h('span', { class: 'muted text-sm' }, t('inv.notSaved')));
    }
    saveBtn.disabled = !dirty;
    clearBtn.disabled = !editor.value && !state.inventory.text;
  }

  function renderResults() {
    const { servers, warnings, stats: st } = parsed;
    const ips = servers.flatMap((s) => s.ips);
    const v6 = ips.filter((ip) => ipVersion(ip) === 6).length;
    const priv = ips.filter((ip) => isPrivateIP(ip)).length;
    const groups = new Set(servers.flatMap((s) => s.groups));
    stats.servers.set({ value: servers.length, hint: t('inv.stat.lines', { count: st.lines }) });
    stats.ips.set({
      value: ips.length,
      hint: ips.length ? t('inv.stat.ipsHint', { v4: formatNumber(ips.length - v6), v6: formatNumber(v6), priv: formatNumber(priv) }) : null
    });
    stats.groups.set({ value: groups.size, hint: groups.size ? [...groups].slice(0, 4).join(', ') + (groups.size > 4 ? '…' : '') : null });
    stats.warnings.set({ value: warnings.length, variant: warnings.length ? 'warn' : 'default' });
    table.setRows(servers);
    targetsBtn.disabled = !servers.some((s) => s.ips.length);
    clear(topologySlot);
    const topology = TopologyCard(servers);
    topologySlot.hidden = !topology;
    if (topology) topologySlot.append(topology);

    clear(warningsList);
    warningsCard.hidden = warnings.length === 0;
    for (const w of warnings.slice(0, 200)) {
      warningsList.append(h('li', null, h('button', {
        type: 'button',
        class: 'inv-warning',
        dataset: { code: w.code, line: w.line, reason: w.reason },
        disabled: !w.line,
        on: { click: () => jumpToLine(w.line) }
      },
      h('span', { class: 'inv-warning-line num' }, w.line ? t('inv.lineN', { n: w.line }) : t('inv.wholeInput')),
      h('span', { class: 'inv-warning-body' },
        h('span', { class: 'inv-warning-code' }, t(w.reason ? `inv.warn.${w.code}.${w.reason}` : `inv.warn.${w.code}`)),
        w.text ? h('code', { class: 'inv-warning-text' }, w.text) : null,
        w.detail && w.detail !== w.text ? h('span', { class: 'inv-warning-detail mono' }, w.detail) : null))));
    }
    if (warnings.length > 200) warningsList.append(h('li', { class: 'muted text-sm inv-warning-more' }, t('common.moreCount', { count: formatNumber(warnings.length - 200) })));
  }

  const reparse = () => {
    parsed = parseInventory(editor.value);
    renderResults();
    renderStatus();
  };
  const reparseSoon = debounce(reparse, 200);
  editor.input.addEventListener('input', () => {
    renderStatus();
    reparseSoon();
  });

  function save() {
    reparseSoon.cancel();
    const { persisted, inventory, done } = state.setInventory(editor.value);
    parsed = { servers: inventory.servers, warnings: inventory.warnings, stats: inventory.stats };
    renderResults();
    renderStatus();
    if (!persisted && editor.value.trim()) {
      toast(t('inv.notPersisted'), { type: 'warn', timeout: 8000 });
      return;
    }
    toast(t('inv.saved', { count: inventory.servers.length }), { type: 'success' });
    // The write itself finishes a moment later; a full disk or a blocked database says so then.
    done.then((ok) => {
      if (!ok && inventory.text.trim()) toast(t('inv.notPersisted'), { type: 'warn', timeout: 8000 });
    });
  }

  async function clearAll() {
    if (state.inventory.text || editor.value.trim()) {
      const ok = await confirmDialog({ message: t('inv.clearConfirm'), confirmLabel: t('inv.clear'), danger: true });
      if (!ok) return;
    }
    editor.value = '';
    state.clearInventory();
    reparse();
    toast(t('inv.cleared'), { type: 'info' });
    editor.focus();
  }

  async function importFiles(files) {
    const incoming = files.map((f) => f.text.replace(/\s+$/, '')).join('\n\n');
    const name = files.map((f) => f.name).join(', ');
    let mode = 'replace';
    if (editor.value.trim()) {
      mode = await Modal({
        title: t('inv.importTitle', { name }),
        size: 'sm',
        content: h('p', { class: 'modal-message' }, t('inv.importBody')),
        actions: [
          { label: t('common.cancel'), value: null },
          { label: t('inv.append'), value: 'append', icon: 'plus' },
          { label: t('inv.replace'), value: 'replace', variant: 'primary', autofocus: true }
        ]
      }).open();
      if (!mode) return;
    }
    editor.value = mode === 'append' ? `${editor.value.replace(/\s+$/, '')}\n\n${incoming}\n` : `${incoming}\n`;
    reparse();
    toast(t('inv.imported', { name }), { type: 'info' });
  }

  async function useExample(ex) {
    if (editor.value.trim() && editor.value !== ex.text) {
      const ok = await confirmDialog({ message: t('inv.exampleConfirm'), confirmLabel: t('inv.replace') });
      if (!ok) return;
    }
    editor.value = ex.text;
    reparse();
    editor.input.scrollIntoView({ block: 'nearest' });
  }

  function jumpToLine(n) {
    if (!n) return;
    const ta = editor.input;
    const [start, end] = lineRange(ta.value, n);
    ta.focus({ preventScroll: true });
    ta.setSelectionRange(start, end);
    const lh = parseFloat(globalThis.getComputedStyle(ta).lineHeight) || 20;
    ta.scrollTop = Math.max(0, (n - 1) * lh - ta.clientHeight / 3);
    ta.scrollIntoView({ block: 'nearest' });
  }

  // Another tab saved/cleared the inventory: follow it unless the user has unsaved edits.
  let lastSavedText = state.inventory.text;
  const unsubscribe = state.subscribe(({ key, origin }) => {
    if (key === 'cleared' || key === 'workspace') {
      // "Delete all local data" (Settings, while this view is open) or another workspace: the
      // editor shows what is saved now, unsaved edits dropped, so no session draft keeps the
      // other data and Save cannot write it into this workspace.
      reparseSoon.cancel();
      editor.value = state.inventory.text;
      lastSavedText = state.inventory.text;
      reparse();
      return;
    }
    if (key !== 'inventory') return;
    const wasClean = editor.value === lastSavedText;
    lastSavedText = state.inventory.text;
    if (origin === 'external' && wasClean) {
      editor.value = lastSavedText;
      reparse();
    } else {
      renderStatus();
    }
  });

  // Refresh the relative "Saved … ago" label now and then.
  const timer = setInterval(renderStatus, 30000);

  renderResults();
  renderStatus();

  teardown = () => {
    unsubscribe();
    clearInterval(timer);
    reparseSoon.cancel();
    // Keep an unsaved draft for this session so navigating away does not lose it.
    if (isDirty()) state.setSession('inventoryDraft', editor.value);
  };
  snapshotFn = () => ({ text: editor.value });
  dirtyFn = isDirty;
}

let snapshotFn = null;
let dirtyFn = null;

/** Clean up listeners; keep unsaved edits as a session draft. */
export function unmount() {
  if (teardown) teardown();
  teardown = null;
  snapshotFn = null;
  dirtyFn = null;
}

/**
 * Does the editor hold changes that are not saved? (The shell asks before a switch to another
 * workspace, which would drop them: they belong to this one.)
 * @returns {boolean}
 */
export function unsaved() {
  return dirtyFn ? dirtyFn() : false;
}

/**
 * State to carry over a re-mount (language change): the editor text.
 * @returns {{ text: string }|null}
 */
export function snapshot() {
  return snapshotFn ? snapshotFn() : null;
}

export default { id, titleKey, icon, mount, unmount, snapshot, unsaved };
