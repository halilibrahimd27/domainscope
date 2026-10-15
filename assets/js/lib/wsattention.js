/**
 * wsattention.js — the workspace switcher's attention count: how many things a workspace needs a
 * look at, from its own parts (`rdapSeen`, `ctSeen`, `waivers`), as one number. A count only,
 * never a domain name: the switcher is on screen during screen-shares. It applies Home's rules
 * (lib/homedigest.js), so the number is what Home would list in that workspace as an error or a
 * warning, not a second opinion. DOM-free.
 */

import { ctAttention, regAttention, waiverAttention } from './homedigest.js';

/**
 * @param {{ ctSeen?: unknown, rdapSeen?: unknown, waivers?: unknown }} parts a workspace's parts
 * @param {number|Date} now
 * @returns {number} the items that need attention (0: nothing)
 */
export function attentionCount(parts, now) {
  const p = parts || {};
  const rows = [...ctAttention(p.ctSeen, now), ...regAttention(p.rdapSeen, now), ...waiverAttention(p.waivers, now)];
  let count = 0;
  for (const row of rows) {
    if (row.severity !== 'error' && row.severity !== 'warn') continue;
    count += Math.max(1, Array.isArray(row.names) ? row.names.length : 1);
  }
  return count;
}
