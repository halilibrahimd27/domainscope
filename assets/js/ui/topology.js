/**
 * ui/topology.js — where TLS really terminates, shown from the inventory's topology keys
 * (lib/inventory.js reads them, lib/topology.js applies them):
 *
 *   - {@link TopologyNotes}: what one server group of a scan is (SSL Targets › Servers, the
 *     Renewal plan): a load balancer and its backends, behind which load balancer, a VIP to
 *     install on every holder, the public NAT address, its own TLS ports;
 *   - {@link noCertStatus}: a server group that gets no certificate ('plain' / 'passthrough');
 *   - {@link TopologyCard}: the Servers view's compact load balancer → backends tree, the VIPs
 *     and the NAT pairs;
 *   - {@link TopologyWarnings}: the inventory's TOPOLOGY warnings in SSL Targets, where they
 *     change which servers get the certificate (the words of each are registered here).
 *
 * Builds DOM with h() only (no innerHTML); styles in assets/css/views/topology.css.
 */

import { h } from './dom.js';
import { Alert, Badge, Card, Icon } from './components.js';
import { t, registerStrings } from '../i18n.js';
import { inventoryTopology, terminatesTls } from '../lib/topology.js';

registerStrings('en', {
  'topo.title': 'Where TLS terminates',
  'topo.subtitle': 'Load balancers, shared addresses and NAT from your inventory',
  'topo.howTo': 'Add them to a server’s line: ports=443,8443 · terminates_tls=no · vip=203.0.113.50 · backends=web01,web02 · nat=203.0.113.10',
  'topo.lbs': 'Load balancers',
  'topo.vips': 'Shared addresses (VIP)',
  'topo.nats': 'NAT: public address → server',
  'topo.plainTitle': 'No TLS here',
  'topo.portsTitle': 'Own TLS ports',
  'topo.terminates': 'terminates TLS',
  'topo.passthrough': 'passes TLS through',
  'topo.plain': 'plain HTTP',
  'topo.plainNote': 'no certificate',
  'topo.reencrypts': 're-encrypts',
  'topo.reencryptsNote': 'needs the certificate',
  'topo.vipHolders2': 'install on both: {a} and {b}',
  'topo.vipHoldersN': 'install on all {count}: {names}',
  'topo.vipHolder1': 'only {name} holds it',
  'topo.vipMixed': 'install on {tls}; {plain}: terminates_tls=no — check the inventory',
  'topo.vipPlainAll': 'plain HTTP on {names} (terminates_tls=no) — no certificate',
  'topo.noBackends': 'none of its backends is in the inventory',
  'topo.noTermination': 'TLS terminates nowhere behind it: every backend says terminates_tls=no too — check the inventory',
  'topo.introScan': 'Your inventory says where TLS terminates: the servers behind a load balancer (or a VIP pair) come right after it, and a server with terminates_tls=no needs no certificate unless DNS points at it directly.',
  'topo.note.lb': 'Load balancer → {names}',
  'topo.note.passthrough': { one: 'Passes TLS through to {names}: no certificate here', other: 'Passes TLS through to {names}: no certificate here' },
  'topo.note.behindPlain': 'Behind {lb} — plain HTTP, no certificate needed',
  'topo.note.behindTls': 'Behind {lb} — re-encrypts: install here too',
  'topo.note.behind': 'Behind {lb}',
  'topo.note.suspect': 'DNS points here directly but the inventory says terminates_tls=no — check the inventory',
  'topo.note.plain': 'terminates_tls=no — plain HTTP, no certificate needed',
  'topo.note.vip1': 'VIP {ip}',
  'topo.note.vip2': 'VIP {ip} — install on both: {a} and {b}',
  'topo.note.vipN': 'VIP {ip} — install on all {count}: {names}',
  'topo.note.vipPlain': 'VIP {ip}: the inventory says terminates_tls=no for {names} — check it',
  'topo.note.nat': 'Reached at {ip} (NAT) → {addresses}',
  'topo.note.ports': 'TLS ports {ports}',
  'topo.status.plain': 'No certificate needed',
  'topo.status.passthrough': 'TLS passthrough',
  'topo.via.lb': 'Through {lb}',
  'topo.warnings': {
    one: 'Your inventory has {count} topology warning — it affects which servers get the certificate',
    other: 'Your inventory has {count} topology warnings — they affect which servers get the certificate'
  },
  'topo.warnings.line': 'Line {n}',
  'topo.warnings.more': '…and {count} more on the Servers page',
  'topo.warnings.fix': 'Fix on the Servers page',
  // The inventory's TOPOLOGY warnings (lib/inventory.js TOPOLOGY_REASONS): the Servers view and SSL Targets
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
  'inv.warn.TOPOLOGY.vipMixed': 'The holders of this VIP disagree — some say terminates_tls=no, some do not: whichever holds the VIP serves its names',
  'inv.warn.TOPOLOGY.cycle': 'Backends that lead back to this load balancer (the loop is shown) — it cannot sit behind itself: check the inventory',
  'inv.warn.TOPOLOGY.ownedAddress': 'This vip= / nat= address is also a server’s own address (in brackets) — which server answers there is unclear: check the inventory',
  'inv.warn.TOPOLOGY.nearMiss': 'Not a topology key — did you mean the one in brackets? It is not read',
  'topo.planPlain': { one: '{count} server the names reach needs no certificate', other: '{count} servers the names reach need no certificate' },
  'topo.sum.suspect': {
    one: '{count} server of your list says terminates_tls=no, but DNS points at it directly: it is counted as needing the certificate — check the inventory.',
    other: '{count} servers of your list say terminates_tls=no, but DNS points at them directly: they are counted as needing the certificate — check the inventory.'
  },
  'topo.sum.nowhere': {
    one: 'TLS terminates nowhere in your inventory for {names}: every server it reaches says terminates_tls=no — check the inventory.',
    other: 'TLS terminates nowhere in your inventory for {count} names ({names}): every server they reach says terminates_tls=no — check the inventory.'
  }
});

registerStrings('tr', {
  'topo.title': 'TLS nerede sonlanıyor',
  'topo.subtitle': 'Envanterinizdeki yük dengeleyiciler, paylaşılan adresler ve NAT',
  'topo.howTo': 'Bir sunucunun satırına ekleyin: ports=443,8443 · terminates_tls=no · vip=203.0.113.50 · backends=web01,web02 · nat=203.0.113.10',
  'topo.lbs': 'Yük dengeleyiciler',
  'topo.vips': 'Paylaşılan adresler (VIP)',
  'topo.nats': 'NAT: genel adres → sunucu',
  'topo.plainTitle': 'TLS sonlandırmayanlar',
  'topo.portsTitle': 'Kendi TLS portları',
  'topo.terminates': 'TLS’i sonlandırıyor',
  'topo.passthrough': 'TLS’i olduğu gibi iletiyor',
  'topo.plain': 'düz HTTP',
  'topo.plainNote': 'sertifika gerekmez',
  'topo.reencrypts': 'yeniden şifreliyor',
  'topo.reencryptsNote': 'sertifika gerekir',
  'topo.vipHolders2': 'ikisine de kurun: {a} ve {b}',
  'topo.vipHoldersN': '{count} sunucunun hepsine kurun: {names}',
  'topo.vipHolder1': 'yalnızca {name} sunucusunda',
  'topo.vipMixed': 'kurulacak: {tls}; {plain} için terminates_tls=no yazılmış — envanteri kontrol edin',
  'topo.vipPlainAll': '{names} üzerinde düz HTTP (terminates_tls=no) — sertifika gerekmez',
  'topo.noBackends': 'arkasındaki sunucuların hiçbiri envanterde yok',
  'topo.noTermination': 'Arkasında TLS hiçbir yerde sonlanmıyor: her arka uç da terminates_tls=no diyor — envanteri kontrol edin',
  'topo.introScan': 'Envanteriniz TLS’in nerede sonlandığını söylüyor: bir yük dengeleyicinin (ya da VIP çiftinin) arkasındaki sunucular hemen altında listelenir; terminates_tls=no olan bir sunucuya, DNS doğrudan ona işaret etmiyorsa sertifika gerekmez.',
  'topo.note.lb': 'Yük dengeleyici → {names}',
  'topo.note.passthrough': {
    one: 'TLS’i {names} sunucusuna olduğu gibi iletiyor: burada sertifika gerekmez',
    other: 'TLS’i {names} sunucularına olduğu gibi iletiyor: burada sertifika gerekmez'
  },
  'topo.note.behindPlain': '{lb} arkasında — düz HTTP, sertifika gerekmez',
  'topo.note.behindTls': '{lb} arkasında — trafiği yeniden şifreliyor: buraya da kurun',
  'topo.note.behind': '{lb} arkasında',
  'topo.note.suspect': 'DNS doğrudan buraya işaret ediyor ama envanter terminates_tls=no diyor — envanteri kontrol edin',
  'topo.note.plain': 'terminates_tls=no — düz HTTP, sertifika gerekmez',
  'topo.note.vip1': 'VIP {ip}',
  'topo.note.vip2': 'VIP {ip} — ikisine de kurun: {a} ve {b}',
  'topo.note.vipN': 'VIP {ip} — {count} sunucunun hepsine kurun: {names}',
  'topo.note.vipPlain': 'VIP {ip}: envanter {names} için terminates_tls=no diyor — kontrol edin',
  'topo.note.nat': '{ip} adresinden erişiliyor (NAT) → {addresses}',
  'topo.note.ports': 'TLS portları: {ports}',
  'topo.status.plain': 'Sertifika gerekmiyor',
  'topo.status.passthrough': 'TLS geçişi (passthrough)',
  'topo.via.lb': '{lb} üzerinden',
  'topo.warnings': {
    one: 'Envanterinizde {count} topoloji uyarısı var — sertifikanın hangi sunuculara kurulacağını etkiliyor',
    other: 'Envanterinizde {count} topoloji uyarısı var — sertifikanın hangi sunuculara kurulacağını etkiliyor'
  },
  'topo.warnings.line': 'Satır {n}',
  'topo.warnings.more': '…ve Sunucular sayfasında {count} uyarı daha',
  'topo.warnings.fix': 'Sunucular sayfasında düzeltin',
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
  'inv.warn.TOPOLOGY.vipMixed': 'Bu VIP’i tutan sunucular çelişiyor — bazıları terminates_tls=no diyor, bazıları demiyor: VIP hangisindeyse adları o sunar',
  'inv.warn.TOPOLOGY.cycle': 'Arka uçları bu yük dengeleyiciye geri dönüyor (döngü gösteriliyor) — kendi arkasında duramaz: envanteri kontrol edin',
  'inv.warn.TOPOLOGY.ownedAddress': 'Bu vip= / nat= adresi aynı zamanda bir sunucunun kendi adresi (parantez içinde) — orada hangi sunucunun yanıt verdiği belli değil: envanteri kontrol edin',
  'inv.warn.TOPOLOGY.nearMiss': 'Bu bir topoloji anahtarı değil — parantez içindekini mi demek istediniz? Bu anahtar okunmuyor',
  'topo.planPlain': { one: 'Adların ulaştığı {count} sunucuya sertifika gerekmiyor', other: 'Adların ulaştığı {count} sunucuya sertifika gerekmiyor' },
  'topo.sum.suspect': {
    one: 'Listenizdeki {count} sunucu için envanter terminates_tls=no diyor, ama DNS doğrudan ona işaret ediyor: sertifika gerekiyor sayıldı — envanteri kontrol edin.',
    other: 'Listenizdeki {count} sunucu için envanter terminates_tls=no diyor, ama DNS doğrudan onlara işaret ediyor: sertifika gerekiyor sayıldı — envanteri kontrol edin.'
  },
  'topo.sum.nowhere': {
    one: '{names} için envanterinizde TLS hiçbir yerde sonlanmıyor: ulaştığı her sunucu terminates_tls=no diyor — envanteri kontrol edin.',
    other: '{count} ad için ({names}) envanterinizde TLS hiçbir yerde sonlanmıyor: ulaştıkları her sunucu terminates_tls=no diyor — envanteri kontrol edin.'
  }
});

/**
 * A server group that gets no certificate: 'passthrough' (a load balancer with terminates_tls=no
 * passing TLS to its backends), 'plain' (any other server with terminates_tls=no), else null.
 * @param {{ topology?: { terminatesTls: boolean, backends: object[] } }|null} group
 * @returns {'plain'|'passthrough'|null}
 */
export function noCertStatus(group) {
  const topo = group && group.topology;
  // suspect: DNS points here directly though the inventory says no — it gets the certificate
  if (!topo || topo.terminatesTls !== false || topo.suspect) return null;
  return topo.backends && topo.backends.length ? 'passthrough' : 'plain';
}

/** "install on both: a and b" / "install on all 3: a, b, c" for the holders of a VIP. */
function vipText(ip, servers) {
  if (servers.length === 2) return t('topo.note.vip2', { ip, a: servers[0], b: servers[1] });
  if (servers.length > 2) return t('topo.note.vipN', { ip, count: servers.length, names: servers.join(', ') });
  return t('topo.note.vip1', { ip });
}

/**
 * The topology notes of one server group of a scan (lib/topology.js GroupTopology), one line per
 * fact, the action first: install here too / on both, or no certificate needed. null without one.
 * @param {object|null|undefined} topology
 * @returns {HTMLElement|null}
 */
export function TopologyNotes(topology) {
  if (!topology) return null;
  const notes = [];
  const note = (kind, icon, text) => notes.push(h('li', { class: 'topo-note', dataset: { topo: kind } }, Icon(icon, { size: 12 }), h('span', null, text)));
  const backendCount = (topology.backends || []).length;
  const backends = (topology.backends || []).map((b) => b.name).join(', ');
  const behind = (topology.behind || []).join(', ');
  // The inventory says terminates_tls=no, DNS disagrees: the certificate goes here, and no note may say otherwise.
  const suspect = !!topology.suspect;
  if (suspect) note('suspect', 'alert', t('topo.note.suspect'));
  if (behind) {
    if (suspect) note('behind', 'arrow-right', t('topo.note.behind', { lb: behind }));
    else if (topology.terminatesTls) note('behind-tls', 'arrow-right', t('topo.note.behindTls', { lb: behind }));
    else note('behind-plain', 'arrow-right', t('topo.note.behindPlain', { lb: behind }));
  }
  if (backends) {
    if (topology.terminatesTls || suspect) note('lb', 'git-branch', t('topo.note.lb', { names: backends }));
    else note('passthrough', 'git-branch', t('topo.note.passthrough', { count: backendCount, names: backends }));
  } else if (!topology.terminatesTls && !behind && !suspect) {
    note('plain', 'unlock', t('topo.note.plain'));
  }
  for (const v of topology.vips || []) {
    note('vip', 'share', vipText(v.ip, v.servers || []));
    // DNS reaches every holder, so each needs it; the inventory saying no for some is a contradiction
    if (v.plain && v.plain.length) note('suspect', 'alert', t('topo.note.vipPlain', { ip: v.ip, names: v.plain.join(', ') }));
  }
  for (const n of topology.nats || []) note('nat', 'swap', t('topo.note.nat', { ip: n.ip, addresses: (n.addresses || []).join(', ') }));
  if (topology.tlsPorts && topology.tlsPorts.length) note('ports', 'hash', t('topo.note.ports', { ports: topology.tlsPorts.join(', ') }));
  return notes.length ? h('ul', { class: 'topo-notes' }, notes) : null;
}

/**
 * The inventory's TOPOLOGY warnings for SSL Targets, where they change which servers get the
 * certificate: the first `limit` with their line, what each means and its token, and a link to
 * the Servers view to fix them (`href`). null without one.
 * @param {Array<{ line: number, code: string, reason?: string, detail?: string }>} warnings
 * @param {{ href?: string|null, limit?: number }} [opts]
 * @returns {HTMLElement|null}
 */
export function TopologyWarnings(warnings, { href = null, limit = 5 } = {}) {
  const list = (Array.isArray(warnings) ? warnings : []).filter((w) => w && w.code === 'TOPOLOGY');
  if (!list.length) return null;
  const el = Alert({
    variant: 'warn',
    compact: true,
    title: t('topo.warnings', { count: list.length }),
    children: [
      h('ul', { class: 'topo-warnings' }, list.slice(0, limit).map((w) => h('li', { dataset: { reason: w.reason || '' } },
        w.line ? h('span', { class: 'topo-warnings-line num' }, t('topo.warnings.line', { n: w.line })) : null,
        h('span', null, t(w.reason ? `inv.warn.TOPOLOGY.${w.reason}` : 'inv.warn.TOPOLOGY')),
        w.detail ? h('code', { class: 'topo-warnings-detail' }, w.detail) : null))),
      list.length > limit ? h('p', { class: 'muted text-xs' }, t('topo.warnings.more', { count: list.length - limit })) : null
    ],
    actions: href ? [h('a', { class: 'btn btn-secondary btn-sm', href }, Icon('sliders', { size: 14 }), h('span', { class: 'btn-label' }, t('topo.warnings.fix')))] : null
  });
  el.dataset.role = 'topology-warnings';
  return el;
}

/** A server's name and its own addresses, for the card. */
function serverLine(server, ...extra) {
  return h('div', { class: 'topo-node' },
    h('span', { class: 'topo-name' }, server.name),
    server.ips.length ? h('span', { class: 'topo-ips' }, server.ips.join(', ')) : null,
    ...extra);
}

/**
 * The Servers view's topology card: each load balancer with its backends as a compact tree
 * (does the backend get the certificate?), every VIP with the servers holding it, the NAT pairs,
 * the servers that never get the certificate outside any load balancer and the servers with
 * their own TLS ports. null for an inventory without a topology key.
 * @param {Array<object>} servers lib/inventory.js Server[]
 * @returns {HTMLElement|null}
 */
export function TopologyCard(servers) {
  const topo = inventoryTopology(servers);
  if (!topo.any) return null;
  const sections = [];
  // `key`: the inventory key the section is about, as written (never upper-cased with the title)
  const section = (role, title, list, key = null) => sections.push(h('section', { class: 'topo-section', dataset: { role } },
    h('h3', { class: 'topo-heading' }, title, key ? h('code', { class: 'topo-key' }, key) : null), list));

  if (topo.lbs.length) {
    section('lbs', t('topo.lbs'), h('ul', { class: 'topo-tree' }, topo.lbs.map(({ server, backends }) => {
      const tls = terminatesTls(server);
      return h('li', { class: 'topo-lb', dataset: { server: server.name } },
        serverLine(server, Badge(t(tls ? 'topo.terminates' : 'topo.passthrough'), { variant: tls ? 'warn' : 'neutral', icon: tls ? 'lock' : 'arrow-right' })),
        backends.length
          ? h('ul', { class: 'topo-backends' }, backends.map((b) => {
            const own = terminatesTls(b);
            return h('li', { class: 'topo-backend', dataset: { server: b.name, tls: String(own) } },
              // a short badge says what the backend does, the text after it what that means (it wraps on a phone)
              serverLine(b, Badge(t(own ? 'topo.reencrypts' : 'topo.plain'), { variant: own ? 'warn' : 'ok', icon: own ? 'lock' : 'unlock' }),
                h('span', { class: 'topo-badge-note' }, t(own ? 'topo.reencryptsNote' : 'topo.plainNote'))));
          }))
          : h('p', { class: 'muted text-xs topo-empty' }, t('topo.noBackends')),
        topo.nowhere.has(server) ? h('p', { class: 'topo-warn', dataset: { topo: 'nowhere' } }, Icon('alert', { size: 12 }), h('span', null, t('topo.noTermination'))) : null);
    })));
  }
  if (topo.vips.length) {
    section('vips', t('topo.vips'), h('ul', { class: 'topo-list' }, topo.vips.map((v) => {
      // Without DNS the inventory is all there is: install on the holders that terminate TLS, say when they disagree.
      const names = v.servers.filter((s) => !v.plain.includes(s)).map((s) => s.name);
      const plain = v.plain.map((s) => s.name).join(', ');
      let action;
      if (!names.length) action = t('topo.vipPlainAll', { names: plain });
      else if (plain) action = t('topo.vipMixed', { tls: names.join(', '), plain });
      else {
        action = names.length === 2 ? t('topo.vipHolders2', { a: names[0], b: names[1] })
          : names.length > 2 ? t('topo.vipHoldersN', { count: names.length, names: names.join(', ') }) : t('topo.vipHolder1', { name: names[0] });
      }
      return h('li', { class: ['topo-item', { 'topo-item-warn': !!(names.length && plain) }], dataset: { vip: v.ip } },
        h('span', { class: 'topo-ips' }, v.ip), Icon('arrow-right', { size: 12 }), h('span', null, action));
    })));
  }
  if (topo.nats.length) {
    section('nats', t('topo.nats'), h('ul', { class: 'topo-list' }, topo.nats.map((n) => h('li', { class: 'topo-item', dataset: { nat: n.ip } },
      h('span', { class: 'topo-ips' }, n.ip), Icon('arrow-right', { size: 12 }), serverLine(n.server)))));
  }
  const behindLb = new Set(topo.backendOf.keys());
  const loose = topo.plain.filter((s) => !behindLb.has(s) && !topo.lbs.some((lb) => lb.server === s));
  if (loose.length) {
    section('plain', t('topo.plainTitle'), h('ul', { class: 'topo-list' }, loose.map((s) => h('li', { class: 'topo-item' }, serverLine(s)))), 'terminates_tls=no');
  }
  if (topo.ported.length) {
    section('ports', t('topo.portsTitle'), h('ul', { class: 'topo-list' }, topo.ported.map((s) => h('li', { class: 'topo-item' },
      h('span', { class: 'topo-name' }, s.name), h('span', { class: 'topo-ips' }, s.tlsPorts.join(', '))))), 'ports=');
  }
  return Card({
    title: t('topo.title'),
    subtitle: t('topo.subtitle'),
    icon: 'git-branch',
    className: 'topo-card',
    children: h('div', { class: 'stack-sm', dataset: { role: 'inventory-topology' } }, ...sections, h('p', { class: 'muted text-xs topo-howto' }, t('topo.howTo')))
  });
}
