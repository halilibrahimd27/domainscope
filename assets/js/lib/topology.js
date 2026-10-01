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
import { terminatesTls } from './inventory.js';

/** @typedef {import('./inventory.js').Server} Server */

/**
 * The topology an inventory describes: load balancers with their backends, shared addresses
 * (VIPs) with every server holding them, NAT pairs, the servers that never get the
 * certificate and those with TLS ports of their own. `any` is false for an inventory without a
 * topology key (nothing changes then).
 * @param {Server[]} servers
 * @returns {{ any: boolean, lbs: Array<{ server: Server, backends: Server[] }>, backendOf: Map<Server, Server[]>,
 *   vips: Array<{ ip: string, servers: Server[] }>, nats: Array<{ ip: string, server: Server }>,
 *   plain: Server[], ported: Server[] }}
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
  const vips = [...vipMap].map(([ip, holders]) => ({ ip, servers: holders }));
  const nats = list.flatMap((s) => (Array.isArray(s.nats) ? s.nats : []).map((ip) => ({ ip, server: s })));
  const plain = list.filter((s) => !terminatesTls(s));
  const ported = list.filter((s) => Array.isArray(s.tlsPorts) && s.tlsPorts.length);
  const any = list.some((s) => s.terminatesTls !== undefined) || lbs.length > 0 || vips.length > 0 || nats.length > 0 || ported.length > 0;
  return { any, lbs, backendOf, vips, nats, plain, ported };
}

/**
 * @typedef {object} GroupTopology Where TLS terminates for one server of a scan (ServerGroup.topology).
 * @property {boolean} terminatesTls false: plain HTTP, no certificate needed here
 * @property {Array<{ id: string, name: string, terminatesTls: boolean }>} backends its `backends=` (a load balancer)
 * @property {string[]} behind the load balancers of the scan it was reached through
 * @property {Array<{ ip: string, servers: string[] }>} vips the shared addresses a scanned name answered with, and
 *   every server holding each (install the certificate on all of them)
 * @property {Array<{ ip: string, addresses: string[] }>} nats the public addresses a scanned name answered with,
 *   and the server's own addresses behind them
 * @property {number[]} tlsPorts its `ports=` ([] without)
 */

/**
 * Apply the inventory topology to the server groups of a scan (lib/scanner ServerGroup:
 * `{ server, hosts: [{ name, ip, covered, via, through? }] }`). A load balancer's names reach its
 * backends: each backend gets a group (or more hosts in its own) with one entry per name and own
 * address, marked `lb: <load balancer name>` and keeping the load balancer's `via` and
 * `covered` — through every tier of load balancers. Every group the topology says something
 * about gets `topology` ({@link GroupTopology}); the caller computes `needsCert` with
 * {@link terminatesTls}. Without a topology key in the inventory the groups are returned as they are.
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
        for (const ip of backend.ips) {
          if (g.hosts.some((x) => x.name === e.name && x.ip === ip)) continue;
          g.hosts.push({ name: e.name, ip, covered: e.covered ?? null, via: e.via, lb: lb.server.name });
          added = true;
        }
      }
      if (added && lbsOf.has(backend) && !queue.includes(g)) queue.push(g);
    }
  }
  const vipHolders = new Map(topo.vips.map((v) => [v.ip, v.servers.map((s) => s.name)]));
  for (const g of out) {
    const s = g.server || {};
    const vipIps = [...new Set(g.hosts.filter((e) => e.through === 'vip').map((e) => normalizeIP(e.ip) || e.ip))];
    const natIps = [...new Set(g.hosts.filter((e) => e.through === 'nat').map((e) => normalizeIP(e.ip) || e.ip))];
    const backends = (lbsOf.get(s) || []).map((b) => ({ id: String(b.id ?? b.name), name: b.name, terminatesTls: terminatesTls(b) }));
    const t = {
      terminatesTls: terminatesTls(s),
      backends,
      behind: behind.get(g) || [],
      vips: vipIps.map((ip) => ({ ip, servers: vipHolders.get(ip) || [s.name] })),
      nats: natIps.map((ip) => ({ ip, addresses: [...(s.ips || [])] })),
      tlsPorts: Array.isArray(s.tlsPorts) ? [...s.tlsPorts] : []
    };
    if (!t.terminatesTls || t.backends.length || t.behind.length || t.vips.length || t.nats.length || t.tlsPorts.length) g.topology = t;
  }
  return out;
}

/**
 * Put each load balancer's backend groups right after it (keeping the order otherwise), so a
 * list of server groups reads as "lb01, then what is behind lb01". Groups no load balancer of
 * the list reached stay where they are.
 * @param {Array<{ server: { name: string }, topology?: GroupTopology }>} groups
 * @returns {Array<object>} a new array
 */
export function orderByLoadBalancer(groups) {
  const list = Array.isArray(groups) ? groups : [];
  if (!list.some((g) => g && g.topology)) return [...list];
  const byName = new Map(list.map((g) => [g.server.name, g]));
  const out = [];
  const placed = new Set();
  const place = (g) => {
    if (placed.has(g)) return;
    placed.add(g);
    out.push(g);
    for (const b of g.topology ? g.topology.backends : []) {
      const bg = byName.get(b.name);
      if (bg && bg.topology && bg.topology.behind.includes(g.server.name)) place(bg);
    }
  };
  const reachedByListed = (g) => !!g.topology && g.topology.behind.some((n) => n !== g.server.name && byName.has(n));
  for (const g of list) if (!reachedByListed(g)) place(g);
  for (const g of list) place(g); // load balancers in a loop: whatever is left, in order
  return out;
}
