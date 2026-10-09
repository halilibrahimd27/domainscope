/**
 * density.js — compact result layouts, as data.
 *
 * - DNS Lookup ({@link lookupLayout}): a type whose answer is plain NODATA ("the name exists but
 *   has no AAAA records") gets no card of its own but a place in one "No records: AAAA, CAA, …"
 *   line, and what every answer shares (the resolver that answered, its PoP / NSID and the header
 *   flags) is said once in the summary instead of on every card; a card repeats only what
 *   differs from that.
 * - IP Intel ({@link foldZeroStats}): stat cards whose count is zero fold into one sentence; and
 *   ({@link addressLines}) a long IPv6 address may break in two in its narrow column on a phone.
 *
 * Pure: no DOM, network, clock or i18n.
 */

/**
 * A long IPv6 address in two parts for a narrow cell (IP Intel's address column at 320 px): split
 * after the colon nearest its middle — after a whole `::`, never inside one — so the column's least
 * width is half the address, not all of it (a break opportunity goes between the parts). An
 * address of at most `max` characters (every IPv4 one) or a value without a colon stays one part.
 * @param {string} ip
 * @param {{ max?: number }} [opts]
 * @returns {string[]} one or two parts; joined they give the value back
 */
export function addressLines(ip, { max = 20 } = {}) {
  const s = String(ip ?? '');
  if (s.length <= max || !s.includes(':')) return [s];
  let at = -1;
  for (let i = 0; i < s.length - 1; i += 1) {
    if (s[i] !== ':' || s[i + 1] === ':') continue;
    if (at < 0 || Math.abs(i + 1 - s.length / 2) < Math.abs(at + 1 - s.length / 2)) at = i;
  }
  return at < 0 ? [s] : [s.slice(0, at + 1), s.slice(at + 1)];
}

/** DNS header flags shown by DNS Lookup, in display order. */
export const LOOKUP_FLAGS = Object.freeze(['aa', 'tc', 'rd', 'ra', 'ad', 'cd']);

/**
 * Is a DoH answer plain NODATA for `type`: NOERROR with an empty answer section (no record of the
 * type, no alias chain, nothing else) and no Extended DNS Error? Such an answer says only "no
 * records" (its negative-caching SOA and any DNSSEC denial proof sit in the authority section).
 * NXDOMAIN, an alias whose target has no such records, and a failed query are not NODATA.
 * @param {object|null} response lib/doh.js DnsResponse
 * @returns {boolean}
 */
export function isNoData(response) {
  if (!response || response.ok !== true || response.rcode !== 'NOERROR') return false;
  if (Array.isArray(response.answers) && response.answers.length) return false;
  return !(Array.isArray(response.ede) && response.ede.length);
}

/** The flags of an answer as a stable 'aa,rd,ra' string (set flags only). */
function flagKey(response) {
  const f = (response && response.flags) || {};
  return LOOKUP_FLAGS.filter((k) => f[k]).join(',');
}

/**
 * @typedef {object} LookupLayout
 * @property {string[]} cards types that keep a card, in query order: still pending, with records or
 *   an alias chain, an error rcode (NXDOMAIN, SERVFAIL …) or a failed query
 * @property {string[]} noRecords the NODATA types ({@link isNoData}), in query order
 * @property {string[]} failed types whose query got no DNS answer (transport failure)
 * @property {string[]} pending types without a response yet
 * @property {{ resolver: string|null, nsid: string|null, flags: Record<string, boolean>|null }} shared what every
 *   DNS answer has in common (null where they differ, or before the first answer); `nsid` is null too
 *   when no answer carried one
 * @property {Record<string, { resolver: boolean, nsid: boolean, flags: boolean }>} own per card type with a DNS
 *   answer: which parts it shows itself because they differ from `shared`
 */

/**
 * Lay out the answers of one DNS Lookup.
 * @param {string[]} types the queried types, in order
 * @param {Array<object|null>} responses DnsResponse per type (null while pending), same order
 * @returns {LookupLayout}
 */
export function lookupLayout(types, responses) {
  const list = Array.isArray(types) ? types : [];
  const res = Array.isArray(responses) ? responses : [];
  const out = { cards: [], noRecords: [], failed: [], pending: [], shared: { resolver: null, nsid: null, flags: null }, own: {} };
  const answered = [];
  list.forEach((type, i) => {
    const r = res[i] || null;
    if (!r) {
      out.pending.push(type);
      out.cards.push(type);
    } else if (r.ok !== true) {
      out.failed.push(type);
      out.cards.push(type);
    } else {
      answered.push([type, r]);
      if (isNoData(r)) out.noRecords.push(type);
      else out.cards.push(type);
    }
  });
  if (!answered.length) return out;
  const same = (get) => {
    const first = get(answered[0][1]);
    return answered.every(([, r]) => get(r) === first) ? first : undefined;
  };
  const resolver = same((r) => r.resolver || null);
  const nsid = same((r) => r.nsid || null);
  const flags = same(flagKey);
  out.shared.resolver = resolver === undefined ? null : resolver;
  out.shared.nsid = nsid === undefined ? null : nsid;
  if (flags !== undefined) {
    const on = new Set(flags ? flags.split(',') : []);
    out.shared.flags = Object.fromEntries(LOOKUP_FLAGS.map((k) => [k, on.has(k)]));
  }
  for (const [type, r] of answered) {
    if (!out.cards.includes(type)) continue;
    out.own[type] = { resolver: resolver === undefined && !!r.resolver, nsid: nsid === undefined && !!r.nsid, flags: flags === undefined };
  }
  return out;
}

/**
 * Split stat cards into the ones to show and the zero counts to fold into one sentence.
 * @param {Array<{ id: string, value: number|null }>} stats in display order
 * @param {{ foldable?: string[] }} [opts] ids that may fold (a count that is still growing — lookups
 *   in flight — should not be listed)
 * @returns {{ shown: string[], folded: string[] }} ids, in display order
 */
export function foldZeroStats(stats, { foldable = [] } = {}) {
  const shown = [];
  const folded = [];
  for (const s of Array.isArray(stats) ? stats : []) {
    if (!s || typeof s.id !== 'string') continue;
    if (foldable.includes(s.id) && s.value === 0) folded.push(s.id);
    else shown.push(s.id);
  }
  return { shown, folded };
}
