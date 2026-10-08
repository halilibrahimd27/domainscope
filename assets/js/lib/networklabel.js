/**
 * networklabel.js — the provider network-tier label of a direct address (ROADMAP P2.10, the
 * follow-up wave 6 left): whose published or announced address space holds it — "Cloudflare
 * network, not necessarily proxied", "AWS network" — for IP Intel's operator cell and SSL Targets'
 * Behind CDN rows.
 *
 * Two sources, merged:
 * - the weekly range dataset's network tier (lib/netinfo.js matchNetworkByIP, also on a direct
 *   classifyResolution as `network`): the operators' own published lists and Cloudflare's announced
 *   prefixes (AS13335, AS209242) — offline, at once, but only once the dataset has loaded;
 * - the AS-based hint of IP Intel (lib/ipintel.js networkHint): the origin AS RIPEstat names, for
 *   the well-known networks the dataset does not list (Akamai, Hetzner, OVHcloud …).
 * The dataset decides the operator when it knows the address (a published range is the stronger
 * evidence); the AS number joins it when the hint names the same operator.
 *
 * Display only: an address in a network tier stays `direct` (no edge range holds it), nothing here
 * changes a classification, a sweep or a coverage decision. DOM-free; runs in browsers and Node 22.
 */

import { matchNetworkByIP } from './netinfo.js';

/**
 * How the address relates to its operator: `outside-proxy-ranges` (a CDN's network, outside the
 * ranges it proxies websites from: not necessarily proxied), `cdn-edge` (a CDN that publishes no
 * edge list: most likely an edge), `hosted` (a cloud / hosting network: a server reached directly).
 */
export const LABEL_RELATIONS = Object.freeze(['outside-proxy-ranges', 'cdn-edge', 'hosted']);
/** Where a label comes from: the range dataset, the origin AS, or both naming the same operator. */
export const LABEL_SOURCES = Object.freeze(['ranges', 'asn', 'both']);
/** Network-tier ids the AS-based table knows under another id (Google Cloud is announced by Google's ASes). */
const SAME_OPERATOR = Object.freeze({ 'google-cloud': 'google' });

/**
 * @typedef {object} NetworkLabel
 * @property {string} id the network-tier id (lib/netinfo.js NETWORKS) or the AS-based one (lib/ipintel.js INFRA_NETWORKS)
 * @property {string} name the operator's name
 * @property {string} category 'cdn'|'waf'|'cloud'|'hosting'|'platform'
 * @property {'outside-proxy-ranges'|'cdn-edge'|'hosted'} relation
 * @property {number|null} asn the origin AS, when known and the same operator's
 * @property {'ranges'|'asn'|'both'} source
 */

/**
 * The network label of an address, or null: for a classification other than `direct` (a proxied,
 * CDN, platform or private answer already names its operator, or has none), and for an address
 * neither source knows. `classification.network` is read first; `ip` is looked up in the network
 * tier when it is missing (an answer classified before the dataset loaded).
 * @param {{ classification?: { kind?: string, network?: object|null }|null, ip?: string|null,
 *   hint?: { id: string, name: string, category: string, asn: number, relation: string }|null }} input
 *   `hint`: lib/ipintel.js networkHint of the address
 * @returns {NetworkLabel|null}
 */
export function networkLabel({ classification = null, ip = null, hint = null } = {}) {
  if (classification && classification.kind && classification.kind !== 'direct') return null;
  const ranges = (classification && classification.network) || (ip ? matchNetworkByIP(ip) : null);
  if (ranges) {
    const same = !!hint && (hint.id === ranges.id || hint.id === SAME_OPERATOR[ranges.id]);
    return {
      id: ranges.id,
      name: ranges.name,
      category: ranges.category,
      relation: ranges.category === 'cdn' || ranges.category === 'waf' ? 'outside-proxy-ranges' : 'hosted',
      asn: same && Number.isInteger(hint.asn) ? hint.asn : null,
      source: same ? 'both' : 'ranges'
    };
  }
  if (hint && LABEL_RELATIONS.includes(hint.relation)) {
    return { id: hint.id, name: hint.name, category: hint.category, relation: hint.relation, asn: Number.isInteger(hint.asn) ? hint.asn : null, source: 'asn' };
  }
  return null;
}

/**
 * The label of the first address of a list that has one (a host's answer: its A then AAAA
 * addresses), or null.
 * @param {string[]} ips
 * @param {{ kind?: string, network?: object|null }|null} [classification]
 * @returns {NetworkLabel|null}
 */
export function firstNetworkLabel(ips, classification = null) {
  if (classification && classification.kind && classification.kind !== 'direct') return null;
  if (classification && classification.network) return networkLabel({ classification });
  for (const ip of Array.isArray(ips) ? ips : []) {
    const label = networkLabel({ ip });
    if (label) return label;
  }
  return null;
}
