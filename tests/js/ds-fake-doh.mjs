/**
 * A fake DNS-over-HTTPS service for the headless runner's offline tests (tests/js/ds-runner.test.js).
 *
 * The zone is the Zone File e2e suite's fake live zone (tests/e2e/zone.e2e.mjs fakeTable): the
 * records of the Cloudflare export fixture, every proxied name answering the Cloudflare edge
 * except www, which answers its origin (the proxy switched off live → origin-exposed), and a newer
 * SOA serial. {@link createFakeFetch} answers RFC 8484 GET `?dns=` requests from such a table in
 * Node, as the suite's in-page stub does in the browser; every other request gets `other()`
 * (by default a 404: RDAP, the passive sources and CT fail cleanly, nothing leaves the machine).
 *
 * Loaded with `node --import <this file>` and DS_FAKE_DOH=1 in the environment it replaces
 * globalThis.fetch of a spawned runner, and DS_FAKE_DOH_LOG=<file> receives the questions asked
 * (JSON) when the process exits. Documentation data only (example.com, 192.0.2.0/24,
 * 198.51.100.0/24, 2001:db8::/32, the fake Cloudflare edge 104.16.1.1).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeMessage, decodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseZone } from '../../assets/js/lib/zoneparse.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const CF_EXPORT = join(ROOT, 'tests', 'fixtures', 'zones', 'cloudflare-export.txt');
export const CF_EDGE_V4 = '104.16.1.1';
export const CF_EDGE_V6 = '2606:4700::6810:101';

/**
 * The fake live zone of the Cloudflare export: `{ name: { TYPE: [dnswire data…] } }`.
 * @returns {Record<string, Record<string, any[]>>}
 */
export function zoneTable() {
  const z = parseZone(readFileSync(CF_EXPORT, 'utf8'), { filename: 'example.com.txt' });
  const table = {};
  const proxied = new Set();
  for (const r of z.records) {
    if (r.data === null || r.data === undefined || r.duplicateOf !== undefined) continue;
    if (r.name.endsWith('.dev.example.com')) continue; // below the delegation: served by the child zone
    const node = table[r.name] || (table[r.name] = {});
    (node[r.type] || (node[r.type] = [])).push(r.data);
    if (r.proxied === true) proxied.add(r.name);
  }
  for (const name of proxied) {
    const node = table[name];
    delete node.CNAME;
    node.A = [CF_EDGE_V4];
    if (name === 'www.example.com' || node.AAAA) node.AAAA = [CF_EDGE_V6];
  }
  table['www.example.com'].A = ['192.0.2.10'];
  const soa = table['example.com'].SOA[0];
  table['example.com'].SOA = [{ ...soa, serial: Number(soa.serial) + 1 }];
  return table;
}

/**
 * One answer from a table with the in-page stub's rules: CNAME chains inside the apex, a
 * `*.parent` node for names without a node of their own (RFC 4592), NXDOMAIN outside the table.
 * @param {object} table
 * @param {string} apex
 * @param {string} qname
 * @param {string} type
 * @returns {{ rcode: string, answers: object[] }}
 */
export function answerFrom(table, apex, qname, type) {
  const hasBelow = (name) => Object.keys(table).some((k) => k.endsWith(`.${name}`));
  const nodeOf = (name) => {
    if (table[name]) return table[name];
    const parent = name.split('.').slice(1).join('.');
    if (table[`*.${parent}`] && !hasBelow(name)) return table[`*.${parent}`];
    return null;
  };
  const answers = [];
  let name = qname;
  for (let hop = 0; hop < 8; hop += 1) {
    const node = nodeOf(name);
    if (!node) return { rcode: hop || hasBelow(name) ? 'NOERROR' : 'NXDOMAIN', answers };
    if (node[type]) {
      for (const data of node[type]) answers.push({ name, type, ttl: 300, data });
      return { rcode: 'NOERROR', answers };
    }
    if (node.CNAME && type !== 'CNAME') {
      const target = String(node.CNAME[0]).replace(/[.]$/, '');
      answers.push({ name, type: 'CNAME', ttl: 300, data: target });
      if (target !== apex && !target.endsWith(`.${apex}`)) return { rcode: 'NOERROR', answers };
      name = target;
      continue;
    }
    return { rcode: 'NOERROR', answers };
  }
  return { rcode: 'NOERROR', answers };
}

/**
 * A fetch that answers DoH wire queries from `table` (names outside `apex` are NXDOMAIN) and
 * every other request with `other(url, init)` (a 404 by default). `log` receives each question.
 * @param {object} table
 * @param {{ apex?: string, log?: Array<{ name: string, type: string, url: string }>, other?: Function,
 *   rcodes?: Record<string, string> }} [opts] `rcodes`: 'name|TYPE' → a forced rcode (SERVFAIL …)
 * @returns {typeof fetch}
 */
export function createFakeFetch(table, { apex = 'example.com', log = [], other, rcodes = {} } = {}) {
  const soa = table[apex] && table[apex].SOA ? table[apex].SOA[0] : null;
  return async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const m = /[?&]dns=([^&]+)/.exec(url);
    if (!m) {
      if (typeof other === 'function') return other(url, init);
      return new Response('not found', { status: 404 });
    }
    const q = decodeMessage(base64UrlDecode(decodeURIComponent(m[1]))).questions[0];
    const name = String(q.name).toLowerCase().replace(/[.]$/, '');
    log.push({ name, type: q.type, url: url.slice(0, url.indexOf('?')) });
    const forced = rcodes[`${name}|${q.type}`];
    const out = forced ? { rcode: forced, answers: [] }
      : (name === apex || name.endsWith(`.${apex}`)) ? answerFrom(table, apex, name, q.type) : { rcode: 'NXDOMAIN', answers: [] };
    return new Response(encodeMessage({
      id: 0, flags: { qr: true, rd: true, ra: true }, rcode: out.rcode,
      questions: [{ name: q.name, type: q.type }], answers: out.answers,
      authorities: out.answers.length || !soa ? [] : [{ name: apex, type: 'SOA', ttl: 300, data: soa }], edns: {}
    }), { headers: { 'content-type': 'application/dns-message' } });
  };
}

// `node --import tests/js/ds-fake-doh.mjs` with DS_FAKE_DOH=1: the spawned runner's fetch.
if (process.env.DS_FAKE_DOH === '1') {
  const log = [];
  globalThis.fetch = createFakeFetch(zoneTable(), { log });
  if (process.env.DS_FAKE_DOH_LOG) {
    process.on('exit', () => writeFileSync(process.env.DS_FAKE_DOH_LOG, JSON.stringify(log)));
  }
}
