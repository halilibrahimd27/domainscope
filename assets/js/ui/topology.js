/**
 * ui/topology.js — where TLS really terminates, shown from the inventory's topology keys
 * (lib/inventory.js reads them, lib/topology.js applies them):
 *
 *   - {@link TopologyNotes}: what one server group of a scan is (SSL Targets › Servers, the
 *     Renewal plan): a load balancer and its backends, behind which load balancer, a VIP to
 *     install on every holder, the public NAT address, its own TLS ports;
 *   - {@link noCertStatus}: a server group that gets no certificate ('plain' / 'passthrough');
 *   - {@link TopologyCard}: the Servers view's compact load balancer → backends tree, the VIPs
 *     and the NAT pairs.
 *
 * Builds DOM with h() only (no innerHTML); styles in assets/css/views/topology.css.
 */

import { h } from './dom.js';
import { Badge, Card, Icon } from './components.js';
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
  'topo.plain': 'plain HTTP — no certificate',
  'topo.reencrypts': 're-encrypts — needs the certificate',
  'topo.vipHolders2': 'install on both: {a} and {b}',
  'topo.vipHoldersN': 'install on all {count}: {names}',
  'topo.vipHolder1': 'only {name} holds it',
  'topo.noBackends': 'none of its backends is in the inventory',
  'topo.noTermination': 'TLS terminates nowhere behind it: every backend says terminates_tls=no too — check the inventory',
  'topo.introScan': 'Your inventory says where TLS terminates: the servers behind a load balancer (or a VIP pair) come right after it, and a server with terminates_tls=no needs no certificate.',
  'topo.note.lb': 'Load balancer → {names}',
  'topo.note.passthrough': 'Passes TLS through to {names}: no certificate here',
  'topo.note.behindPlain': 'Behind {lb} — plain HTTP, no certificate needed',
  'topo.note.behindTls': 'Behind {lb} — re-encrypts: install here too',
  'topo.note.behind': 'Behind {lb}',
  'topo.note.suspect': 'DNS points here directly but the inventory says terminates_tls=no — check the inventory',
  'topo.note.plain': 'terminates_tls=no — plain HTTP, no certificate needed',
  'topo.note.vip1': 'VIP {ip}',
  'topo.note.vip2': 'VIP {ip} — install on both: {a} and {b}',
  'topo.note.vipN': 'VIP {ip} — install on all {count}: {names}',
  'topo.note.nat': 'Reached at {ip} (NAT) → {addresses}',
  'topo.note.ports': 'TLS ports {ports}',
  'topo.status.plain': 'No certificate needed',
  'topo.status.passthrough': 'TLS passthrough',
  'topo.via.lb': 'Through {lb}',
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
  'topo.plain': 'düz HTTP — sertifika gerekmez',
  'topo.reencrypts': 'yeniden şifreliyor — sertifika gerekir',
  'topo.vipHolders2': 'ikisine de kurun: {a} ve {b}',
  'topo.vipHoldersN': '{count} sunucunun hepsine kurun: {names}',
  'topo.vipHolder1': 'yalnızca {name} tutuyor',
  'topo.noBackends': 'arkasındaki sunucuların hiçbiri envanterde yok',
  'topo.noTermination': 'Arkasında TLS hiçbir yerde sonlanmıyor: her arka uç da terminates_tls=no diyor — envanteri kontrol edin',
  'topo.introScan': 'Envanteriniz TLS’in nerede sonlandığını söylüyor: bir yük dengeleyicinin (ya da VIP çiftinin) arkasındaki sunucular hemen altında gelir; terminates_tls=no olan bir sunucuya sertifika gerekmez.',
  'topo.note.lb': 'Yük dengeleyici → {names}',
  'topo.note.passthrough': 'TLS’i {names} sunucularına olduğu gibi iletiyor: burada sertifika gerekmez',
  'topo.note.behindPlain': '{lb} arkasında — düz HTTP, sertifika gerekmez',
  'topo.note.behindTls': '{lb} arkasında — trafiği yeniden şifreliyor: buraya da kurun',
  'topo.note.behind': '{lb} arkasında',
  'topo.note.suspect': 'DNS doğrudan buraya işaret ediyor ama envanter terminates_tls=no diyor — envanteri kontrol edin',
  'topo.note.plain': 'terminates_tls=no — düz HTTP, sertifika gerekmez',
  'topo.note.vip1': 'VIP {ip}',
  'topo.note.vip2': 'VIP {ip} — ikisine de kurun: {a} ve {b}',
  'topo.note.vipN': 'VIP {ip} — {count} sunucunun hepsine kurun: {names}',
  'topo.note.nat': '{ip} adresinden erişiliyor (NAT) → {addresses}',
  'topo.note.ports': 'TLS portları: {ports}',
  'topo.status.plain': 'Sertifika gerekmiyor',
  'topo.status.passthrough': 'TLS geçişi (passthrough)',
  'topo.via.lb': '{lb} üzerinden',
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
    else note('passthrough', 'git-branch', t('topo.note.passthrough', { names: backends }));
  } else if (!topology.terminatesTls && !behind && !suspect) {
    note('plain', 'unlock', t('topo.note.plain'));
  }
  for (const v of topology.vips || []) note('vip', 'share', vipText(v.ip, v.servers || []));
  for (const n of topology.nats || []) note('nat', 'swap', t('topo.note.nat', { ip: n.ip, addresses: (n.addresses || []).join(', ') }));
  if (topology.tlsPorts && topology.tlsPorts.length) note('ports', 'hash', t('topo.note.ports', { ports: topology.tlsPorts.join(', ') }));
  return notes.length ? h('ul', { class: 'topo-notes' }, notes) : null;
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
              serverLine(b, Badge(t(own ? 'topo.reencrypts' : 'topo.plain'), { variant: own ? 'warn' : 'ok', icon: own ? 'lock' : 'unlock' })));
          }))
          : h('p', { class: 'muted text-xs topo-empty' }, t('topo.noBackends')),
        topo.nowhere.has(server) ? h('p', { class: 'topo-warn', dataset: { topo: 'nowhere' } }, Icon('alert', { size: 12 }), h('span', null, t('topo.noTermination'))) : null);
    })));
  }
  if (topo.vips.length) {
    section('vips', t('topo.vips'), h('ul', { class: 'topo-list' }, topo.vips.map((v) => {
      const names = v.servers.map((s) => s.name);
      const action = names.length === 2 ? t('topo.vipHolders2', { a: names[0], b: names[1] })
        : names.length > 2 ? t('topo.vipHoldersN', { count: names.length, names: names.join(', ') }) : t('topo.vipHolder1', { name: names[0] });
      return h('li', { class: 'topo-item', dataset: { vip: v.ip } }, h('span', { class: 'topo-ips' }, v.ip), Icon('arrow-right', { size: 12 }), h('span', null, action));
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
