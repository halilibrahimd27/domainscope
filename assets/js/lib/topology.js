/**
 * topology.js — where TLS really terminates, from the topology keys of the inventory
 * (lib/inventory.js reads them: `ports=`, `terminates_tls=`, `vip=`, `backends=`, `nat=`).
 *
 *   - {@link inventoryTopology}: load balancers and their backends, VIPs with their holders, NAT
 *     pairs, the servers that never get the certificate (the Servers view's topology card);
 *   - {@link applyTopology}: a scan's server groups (lib/scanner ServerGroup) with the names of
 *     a load balancer reaching its backends, and what each group's topology says;
 *   - {@link orderByLoadBalancer}: each load balancer followed by what is behind it.
 *
 * DOM-free and pure; kept apart from lib/inventory.js, which the start route loads.
 */

import { normalizeIP } from './netinfo.js';

/** @typedef {import('./inventory.js').Server} Server */

/**
 * Does the server get the certificate? `terminates_tls` is yes unless the inventory says no.
 * @param {{ terminatesTls?: boolean }|null} server
 * @returns {boolean}
 */
export function terminatesTls(server) {
  return !(server && server.terminatesTls === false);
}

/**
 * The topology of `server` as `key=value` tokens of a targets.txt line, the way
 * cli/ssl_origin_scan.py reads them: `terminates_tls=no`, `backends=…` (each backend as the CLI
 * names it: `cliName(name)`, or the name itself when that is an address), `vip=…`, `nat=…`.
 * The TLS ports are not written: inventory.addressTargets already writes each address on them.
 * @param {Server} server
 * @param {(name: string) => string} [cliName] lib/export cliServerName
 * @returns {string[]}
 */
export function topologyTokens(server, cliName = (n) => n) {
  if (!server) return [];
  const out = [];
  if (server.terminatesTls === false) out.push('terminates_tls=no');
  if (Array.isArray(server.backends) && server.backends.length) {
    const names = server.backends.map((n) => cliName(n) || (normalizeIP(n) ? n : '')).filter(Boolean);
    if (names.length) out.push(`backends=${names.join(',')}`);
  }
  if (Array.isArray(server.vips) && server.vips.length) out.push(`vip=${server.vips.join(',')}`);
  if (Array.isArray(server.nats) && server.nats.length) out.push(`nat=${server.nats.join(',')}`);
  return out;
}

/** How strongly a name ties to a server (lib/scanner.js, lib/certsets.js): DNS, the zone file, an origin hint. */
const VIA_RANK = { dns: 0, zone: 1, hint: 2 };

/**
 * The topology an inventory describes: load balancers with their backends, shared addresses
 * (VIPs) with every server holding them, NAT pairs, the servers that never get the
 * certificate and those with TLS ports of their own, the load balancers passing TLS through with
 * no server terminating it behind them (`nowhere`). `any` is false for an inventory without a
 * topology key (nothing changes then).
 * @param {Server[]} servers
 * @returns {{ any: boolean, lbs: Array<{ server: Server, backends: Server[] }>, backendOf: Map<Server, Server[]>,
 *   vips: Array<{ ip: string, servers: Server[], plain: Server[] }>, nats: Array<{ ip: string, server: Server }>,
 *   plain: Server[], ported: Server[], nowhere: Set<Server> }} (a VIP's `plain`: its holders saying terminates_tls=no)
 */
export function inventoryTopology(servers) {
  const list = (Array.isArray(servers) ? servers : []).filter((s) => s && Array.isArray(s.ips));
  const byName = new Map(list.map((s) => [String(s.name).toLowerCase(), s]));
  const lbs = [];
  const backendOf = new Map();
  for (const s of list) {
    if (!Array.isArray(s.backends) || !s.backends.length) continue;
    const backends = [...new Set(s.backends.map((n) => byName.get(String(n).toLowerCase())).filter((b) => b && b !== s))];
    lbs.push({ server: s, backends });
    for (const b of backends) {
      if (!backendOf.has(b)) backendOf.set(b, []);
      backendOf.get(b).push(s);
    }
  }
  const vipMap = new Map();
  for (const s of list) {
    for (const ip of Array.isArray(s.vips) ? s.vips : []) {
      if (!vipMap.has(ip)) vipMap.set(ip, []);
      if (!vipMap.get(ip).includes(s)) vipMap.get(ip).push(s);
    }
  }
  const vips = [...vipMap].map(([ip, holders]) => ({ ip, servers: holders, plain: holders.filter((h) => !terminatesTls(h)) }));
  const nats = list.flatMap((s) => (Array.isArray(s.nats) ? s.nats : []).map((ip) => ({ ip, server: s })));
  const plain = list.filter((s) => !terminatesTls(s));
  const ported = list.filter((s) => Array.isArray(s.tlsPorts) && s.tlsPorts.length);
  const any = list.some((s) => s.terminatesTls !== undefined) || lbs.length > 0 || vips.length > 0 || nats.length > 0 || ported.length > 0;
  // passthrough load balancers with no backend terminating TLS, through every passthrough tier
  const lbOf = new Map(lbs.map((lb) => [lb.server, lb.backends]));
  const nowhere = new Set(lbs.filter((lb) => {
    if (terminatesTls(lb.server)) return false;
    const seen = new Set([lb.server]);
    const queue = [...lb.backends];
    while (queue.length) {
      const b = queue.shift();
      if (seen.has(b)) continue;
      seen.add(b);
      if (terminatesTls(b)) return false;
      queue.push(...(lbOf.get(b) || []));
    }
    return true;
  }).map((lb) => lb.server));
  return { any, lbs, backendOf, vips, nats, plain, ported, nowhere };
}

/**
 * @typedef {object} GroupTopology Where TLS terminates for one server of a scan (ServerGroup.topology).
 * @property {boolean} terminatesTls false: plain HTTP, no certificate needed here
 * @property {Array<{ id: string, name: string, terminatesTls: boolean }>} backends its `backends=` (a load balancer)
 * @property {string[]} behind the load balancers of the scan it was reached through
 * @property {Array<{ ip: string, servers: string[], plain: string[] }>} vips the shared addresses a scanned name
 *   answered with, every server holding each (install the certificate on all of them: DNS reaches each) and
 *   those of them the inventory says terminates_tls=no for (the holders disagree: check it)
 * @property {Array<{ ip: string, addresses: string[] }>} nats the public addresses a scanned name answered with,
 *   and the server's own addresses behind them
 * @property {number[]} tlsPorts its `ports=` ([] without)
 * @property {boolean} suspect the inventory and DNS disagree, so it is counted as getting the certificate:
 *   terminates_tls=no, yet a covered name reaches it directly (and it forwards to no backend), or a name
 *   that would terminate TLS nowhere reaches it directly
 * @property {string[]} nowhere the covered names DNS sends here directly that reach only terminates_tls=no servers
 */

/**
 * Apply the inventory topology to the server groups of a scan (lib/scanner ServerGroup:
 * `{ server, hosts: [{ name, ip, covered, via, through? }] }`). A load balancer's names reach its
 * backends: each backend gets a group (or more hosts in its own) with one entry per name and own
 * address, keeping the load balancer's `covered` and the strongest `via` it came with, and
 * `lbs`: every load balancer right in front that passed it (both of a VIP pair) — through every
 * tier of load balancers. A name that reaches the backend directly keeps its own entry. Every
 * group the topology says something about gets `topology` ({@link GroupTopology}); the caller
 * computes `needsCert` with {@link terminatesTls}, or `suspect`: where the inventory and DNS
 * disagree it errs toward "needs the certificate". Without a topology key in the inventory the
 * groups are returned as they are.
 * @param {Array<object>} groups
 * @param {Server[]} servers the inventory
 * @returns {Array<object>} the groups, then the backend groups it added (in the order reached)
 */
export function applyTopology(groups, servers) {
  const list = Array.isArray(groups) ? groups : [];
  const topo = inventoryTopology(servers);
  if (!topo.any) return list;
  const out = [...list];
  const byServer = new Map(out.map((g) => [g.server, g]));
  const lbsOf = new Map(topo.lbs.map((lb) => [lb.server, lb.backends]));
  const behind = new Map();
  const groupOf = (server) => {
    let g = byServer.get(server);
    if (!g) {
      g = { server, hosts: [], needsCert: false, maybeNeedsCert: false };
      byServer.set(server, g);
      out.push(g);
    }
    return g;
  };
  // Breadth first from every load balancer the scan reached: a backend that is itself a load
  // balancer passes the names on.
  const queue = out.filter((g) => lbsOf.has(g.server) && g.hosts.length);
  for (let i = 0; i < queue.length; i += 1) {
    const lb = queue[i];
    for (const backend of lbsOf.get(lb.server) || []) {
      const g = groupOf(backend);
      if (!behind.has(g)) behind.set(g, []);
      if (!behind.get(g).includes(lb.server.name)) behind.get(g).push(lb.server.name);
      let added = false;
      for (const e of lb.hosts) {
        const rank = VIA_RANK[e.via] ?? 9;
        for (const ip of backend.ips) {
          const known = g.hosts.find((x) => x.name === e.name && x.ip === ip);
          if (!known) {
            g.hosts.push({ name: e.name, ip, covered: e.covered ?? null, via: e.via, lbs: [lb.server.name] });
            added = true;
          } else if (rank < (VIA_RANK[known.via] ?? 9)) {
            // a stronger tie than the one known (DNS over an origin hint, also over a direct one) replaces it
            known.via = e.via;
            known.lbs = [lb.server.name];
            added = true;
          } else if (known.lbs && rank === (VIA_RANK[known.via] ?? 9) && !known.lbs.includes(lb.server.name)) {
            known.lbs.push(lb.server.name); // the same name through the other one of a VIP pair
          }
        }
      }
      // a backend that is a load balancer passes what it got on (again, when a tie got stronger)
      if (added && lbsOf.has(backend) && queue.indexOf(g, i + 1) === -1) queue.push(g);
    }
  }
  // The inventory and DNS disagree: a terminates_tls=no server forwarding to no backend that a
  // covered name reaches directly (its own address, a VIP or NAT address it holds), and every
  // server DNS reaches directly for a name that would terminate TLS nowhere, get the certificate.
  const covered = (e) => (e.via === 'dns' || e.via === 'zone') && e.covered !== false;
  const suspect = new Set(out.filter((g) => !terminatesTls(g.server) && !(lbsOf.get(g.server) || []).length
    && g.hosts.some((e) => covered(e) && !e.lbs)));
  const reach = new Map(); // name → { tls: it terminates somewhere, direct: the groups DNS sends it to }
  for (const g of out) {
    const tls = terminatesTls(g.server) || suspect.has(g);
    for (const e of g.hosts) {
      if (!covered(e)) continue;
      let r = reach.get(e.name);
      if (!r) reach.set(e.name, (r = { tls: false, direct: new Set() }));
      r.tls = r.tls || tls;
      if (!e.lbs) r.direct.add(g);
    }
  }
  const nowhere = new Map();
  for (const [name, r] of reach) {
    if (r.tls) continue;
    for (const g of r.direct) {
      suspect.add(g);
      nowhere.set(g, [...(nowhere.get(g) || []), name]);
    }
  }
  const vipHolders = new Map(topo.vips.map((v) => [v.ip, v]));
  for (const g of out) {
    const s = g.server || {};
    const vipIps = [...new Set(g.hosts.filter((e) => e.through === 'vip').map((e) => normalizeIP(e.ip) || e.ip))];
    const natIps = [...new Set(g.hosts.filter((e) => e.through === 'nat').map((e) => normalizeIP(e.ip) || e.ip))];
    const backends = (lbsOf.get(s) || []).map((b) => ({ id: String(b.id ?? b.name), name: b.name, terminatesTls: terminatesTls(b) }));
    const t = {
      terminatesTls: terminatesTls(s),
      backends,
      behind: behind.get(g) || [],
      vips: vipIps.map((ip) => {
        const v = vipHolders.get(ip);
        return v ? { ip, servers: v.servers.map((x) => x.name), plain: v.plain.map((x) => x.name) } : { ip, servers: [s.name], plain: [] };
      }),
      nats: natIps.map((ip) => ({ ip, addresses: [...(s.ips || [])] })),
      tlsPorts: Array.isArray(s.tlsPorts) ? [...s.tlsPorts] : [],
      suspect: suspect.has(g),
      nowhere: nowhere.get(g) || []
    };
    if (!t.terminatesTls || t.backends.length || t.behind.length || t.vips.length || t.nats.length || t.tlsPorts.length) g.topology = t;
  }
  return out;
}

/**
 * What a group's topology says, in English, for the CSV exports (the Servers CSV, the renewal
 * work list): `load balancer for web01, web02`, `behind lb01 (plain HTTP, no certificate)`,
 * `VIP 203.0.113.50 (lb01, lb02)`, `NAT 203.0.113.10 -> 10.0.0.30`, `TLS ports 443,8443`.
 * @param {GroupTopology|null|undefined} t
 * @returns {string[]}
 */
export function topologyNotes(t) {
  if (!t) return [];
  const out = [];
  // A suspect group gets the certificate: nothing here may claim it needs none.
  if (t.suspect) out.push('terminates_tls=no, yet DNS points here directly (check the inventory)');
  if (t.backends && t.backends.length) {
    out.push(`load balancer for ${t.backends.map((b) => b.name).join(', ')}${t.terminatesTls || t.suspect ? '' : ' (passes TLS through)'}`);
  }
  if (t.behind && t.behind.length) {
    out.push(`behind ${t.behind.join(', ')}${t.suspect ? '' : ` (${t.terminatesTls ? 're-encrypts' : 'plain HTTP, no certificate'})`}`);
  } else if (!t.terminatesTls && !t.suspect && !(t.backends && t.backends.length)) out.push('terminates_tls=no (no certificate)');
  for (const v of t.vips || []) out.push(`VIP ${v.ip} (${v.servers.join(', ')}${v.plain && v.plain.length ? `; terminates_tls=no: ${v.plain.join(', ')}` : ''})`);
  for (const n of t.nats || []) out.push(`NAT ${n.ip} -> ${n.addresses.join(', ')}`);
  if (t.tlsPorts && t.tlsPorts.length) out.push(`TLS ports ${t.tlsPorts.join(',')}`);
  return out;
}

/** A `Topology` CSV column (lib/export toCsv) over rows carrying a {@link GroupTopology} as `topology`. */
export const TOPOLOGY_CSV_COLUMN = Object.freeze({ key: 'topology', header: 'Topology', get: (row) => topologyNotes(row && row.topology).join('; ') });

/**
 * The covered names of a scan that reach only terminates_tls=no servers (GroupTopology.nowhere),
 * in the order of the groups: TLS terminates nowhere the inventory says.
 * @param {Array<{ topology?: GroupTopology }>} groups
 * @returns {string[]}
 */
export function tlsNowhere(groups) {
  return [...new Set((Array.isArray(groups) ? groups : []).flatMap((g) => (g && g.topology && g.topology.nowhere) || []))];
}

/**
 * The `keys` writer of lib/export targetsForCli for a scan's targets.txt: {@link topologyTokens},
 * without `terminates_tls=no` for a server the scan found DNS pointing at directly
 * (GroupTopology.suspect), so the CLI scans it rather than skipping it.
 * @param {{ servers?: Array<{ server: object, topology?: GroupTopology }> }|null} result ScanResult
 * @param {(name: string) => string} [cliName]
 * @returns {(server: object) => string[]}
 */
export function scanTargetsKeys(result, cliName) {
  const id = (s) => String(s.id ?? s.name);
  const direct = new Set((result && Array.isArray(result.servers) ? result.servers : [])
    .filter((g) => g && g.server && g.topology && g.topology.suspect).map((g) => id(g.server)));
  return (server) => topologyTokens(direct.has(id(server)) ? { ...server, terminatesTls: undefined } : server, cliName);
}

/**
 * Put each load balancer's backend groups right after it (keeping the order otherwise), so a
 * list of server groups reads as "lb01, then what is behind lb01". The holders of a VIP the scan
 * reached come together, as one load balancer ("lb01, lb02, then what is behind them"). Groups
 * no load balancer of the list reached stay where they are.
 * @param {Array<{ server: { name: string }, topology?: GroupTopology }>} groups
 * @returns {Array<object>} a new array
 */
export function orderByLoadBalancer(groups) {
  const list = Array.isArray(groups) ? groups : [];
  if (!list.some((g) => g && g.topology)) return [...list];
  const byName = new Map(list.map((g) => [g.server.name, g]));
  const out = [];
  const placed = new Set();
  const reachedByListed = (g) => !!g.topology && g.topology.behind.some((n) => n !== g.server.name && byName.has(n));
  /** The other holders of the VIPs `g` was reached at, in list order (none behind a listed load balancer). */
  const partners = (g) => {
    const names = new Set((g.topology ? g.topology.vips : []).flatMap((v) => v.servers));
    return list.filter((x) => x !== g && names.has(x.server.name) && !reachedByListed(x));
  };
  const place = (g) => {
    if (placed.has(g)) return;
    const pair = [g, ...partners(g)].filter((x) => !placed.has(x));
    for (const x of pair) {
      placed.add(x);
      out.push(x);
    }
    for (const x of pair) {
      for (const b of x.topology ? x.topology.backends : []) {
        const bg = byName.get(b.name);
        if (bg && bg.topology && bg.topology.behind.includes(x.server.name)) place(bg);
      }
    }
  };
  for (const g of list) if (!reachedByListed(g)) place(g);
  for (const g of list) place(g); // load balancers in a loop: whatever is left, in order
  return out;
}
