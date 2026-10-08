/**
 * A small DohClient stand-in for the SPF / readable-records tests (tests/js/spfcheck.test.js,
 * spfexplain.test.js, records.test.js): `query(name, type)` answers from a zone map with real
 * wire-format RRs (encoded and decoded by lib/dnswire.js, so the data has the DohClient's shapes),
 * follows CNAMEs, says NXDOMAIN for a name it does not have (NOERROR when a name below it exists),
 * and fails a `name|TYPE` listed in `fail` (no DNS answer: a transport error) or answers the rcode
 * listed in `rcodes`. Every question is recorded in `calls`. Documentation data only.
 */

import { encodeMessage, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';

const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

/** Real decoded RRs (the shapes a DohClient answer has). */
export function rrs(list) {
  if (!list.length) return [];
  return decodeMessage(encodeMessage({ answers: list.map((r) => ({ ttl: 300, ...r })) })).answers;
}

/**
 * @param {Record<string, Record<string, any>>} zone `{ name: { TYPE: value | value[], CNAME: target } }`; a TXT
 *   value is a string or an array of character-strings
 * @param {{ fail?: Record<string, string>, rcodes?: Record<string, string>, cached?: boolean }} [opts]
 * @returns {{ query: Function, calls: Array<{ name: string, type: string }> }}
 */
export function zoneDns(zone, { fail = {}, rcodes = {} } = {}) {
  const calls = [];
  const below = (name) => Object.keys(zone).some((k) => k.endsWith(`.${name}`));
  async function query(qname, type = 'A', { signal } = {}) {
    throwIfAborted(signal);
    const name = String(qname).toLowerCase().replace(/\.$/, '');
    calls.push({ name, type });
    const base = { name, type, resolver: 'fake', ok: true, rcode: 'NOERROR', flags: { qr: true, rd: true, ra: true }, answers: [], authorities: [], ede: [], error: null, errorKind: null };
    const f = fail[`${name}|${type}`] ?? fail[name];
    if (f) return { ...base, ok: false, rcode: null, flags: null, error: f, errorKind: 'network' };
    const forced = rcodes[`${name}|${type}`];
    if (forced) return { ...base, rcode: forced };
    const answers = [];
    let cur = name;
    let rcode = 'NOERROR';
    for (let i = 0; i < 8; i += 1) {
      const node = zone[cur];
      if (!node) {
        if (!below(cur)) rcode = 'NXDOMAIN';
        break;
      }
      if (node.CNAME && type !== 'CNAME') {
        answers.push({ name: cur, type: 'CNAME', data: node.CNAME });
        cur = node.CNAME;
        continue;
      }
      for (const data of asList(node[type])) answers.push({ name: cur, type, data: type === 'TXT' && !Array.isArray(data) ? [data] : data });
      break;
    }
    return { ...base, rcode, answers: rrs(answers) };
  }
  return { query, calls };
}
