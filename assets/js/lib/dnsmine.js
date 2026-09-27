/**
 * dnsmine.js — discover in-domain hostnames from the domain's own DNS records,
 * with no third-party API and no brute force. Pure logic + an injected DoH
 * client; DOM-free (browser + Node).
 *
 * A zone leaks the names it depends on all over its own records: MX exchanges,
 * NS targets, the SOA master name, SPF `a:`/`mx:`/`include:`/`exists:` hosts,
 * DMARC `rua`/`ruf` report mailboxes, CAA `iodef`, SVCB/HTTPS targets, CNAME
 * targets, and the ~40 well-known SRV service names (`_autodiscover._tcp`,
 * `_sip._tls`, …). Following those references finds real hosts (mail, ns1,
 * autodiscover, lyncdiscover, matrix …) that CT logs and passive sources often
 * miss — and it is polite: a handful of queries against public recursive
 * resolvers, never the target's authoritative servers directly.
 *
 * Names that belong to the queried domain are returned in `names` (with
 * per-record `evidence`); names outside it (external NS, SPF includes, CA
 * `issue` domains, cross-org DMARC report domains) are returned as
 * `externalRefs` for context. `names` never holds a name with a `_`-prefixed
 * label: `_dmarc`, `_sip._tls` or `_spf` name a record, not a host, so the
 * probed query names (and in-domain `include:_spf.<domain>`) are not reported.
 */

import { normalizeHostname, isSubdomainOf, sortHostnames } from './domain.js';
import { normalizeIP } from './netinfo.js';

/**
 * Well-known SRV service owners (~40). Queried as `<service>.<domain>` SRV; a
 * non-null target that lives in the domain is a discovered host.
 */
export const SRV_SERVICES = Object.freeze([
  '_autodiscover._tcp', '_sipfederationtls._tcp', '_sipinternaltls._tcp', '_sip._tls', '_sip._tcp',
  '_sips._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp', '_jabber._tcp',
  '_caldav._tcp', '_caldavs._tcp', '_carddav._tcp', '_carddavs._tcp',
  '_imap._tcp', '_imaps._tcp', '_pop3._tcp', '_pop3s._tcp',
  '_submission._tcp', '_submissions._tcp', '_smtp._tcp', '_smtps._tcp',
  '_ldap._tcp', '_ldaps._tcp', '_kerberos._tcp', '_kerberos._udp',
  '_kerberos-master._tcp', '_kpasswd._tcp', '_kpasswd._udp', '_gc._tcp',
  '_matrix._tcp', '_matrix-fed._tcp', '_minecraft._tcp', '_ts3._udp',
  '_h323cs._tcp', '_http._tcp', '_https._tcp', '_stun._udp', '_stuns._tcp',
  '_turn._udp', '_turns._tcp', '_vlmcs._tcp'
]);

/** Records queried at the apex, with the RR type to ask for. */
const APEX_QUERIES = [
  ['NS', 'NS'], ['SOA', 'SOA'], ['MX', 'MX'], ['TXT', 'TXT'], ['CAA', 'CAA'], ['HTTPS', 'HTTPS']
];

/** Strip an SPF/mechanism qualifier and a trailing `/cidr`; drop macro hosts. */
function cleanHost(value) {
  if (typeof value !== 'string') return null;
  let s = value.trim();
  const slash = s.indexOf('/');
  if (slash !== -1) s = s.slice(0, slash);
  if (!s || s.includes('%')) return null; // SPF macro — can't resolve statically
  return s;
}

/** Join a TXT record's character-strings into one string. */
function txtString(rr) {
  if (!rr || rr.type !== 'TXT') return '';
  if (Array.isArray(rr.data)) return rr.data.join('');
  return typeof rr.data === 'string' ? rr.data : '';
}

/** Does a name carry a service label (`_dmarc`, `_tcp`, `_spf` …)? Those name records, not hosts. */
function hasServiceLabel(name) {
  return name.split('.').some((label) => label.startsWith('_'));
}

/**
 * The mailbox domain of an SOA RNAME ('hostmaster.example.com' → 'example.com'),
 * honouring a '\.' escape in the local part ('dns\.admin.example.com' →
 * 'example.com'), as dnswire's decoder does for `email`. Null when there is none.
 */
function soaMailDomain(rname) {
  const m = /^(?:[^.\\]|\\.)+\.(.+)$/.exec(rname);
  return m ? m[1] : null;
}

/** Extract the host part of a `mailto:` / URL value (for iodef, rua, ruf). */
function hostFromUri(uri) {
  const s = String(uri || '').trim();
  const mail = s.match(/^mailto:([^,!\s]+)/i);
  if (mail) {
    const at = mail[1].lastIndexOf('@');
    return at === -1 ? null : mail[1].slice(at + 1);
  }
  const url = s.match(/^[a-z][a-z0-9+.-]*:\/\/([^/:?#\s]+)/i);
  return url ? url[1] : null;
}

/**
 * Mine a domain's DNS records for in-domain hostnames.
 *
 * @param {string} domain the domain to mine (apex / any zone name)
 * @param {object} opts
 * @param {{ query: Function, ptr?: Function }} opts.dns injected DoH client
 * @param {AbortSignal} [opts.signal]
 * @param {(p: { stage: string, done: number, total: number, name?: string }) => void} [opts.onProgress]
 * @param {boolean} [opts.resolvePtr=false] optional hook: PTR the in-domain IPs
 *   seen in answers (needs `dns.ptr`) and keep in-domain PTR names.
 * @returns {Promise<{ names: string[], evidence: Array<{ name: string, from: string, record: string }>, externalRefs: string[] }>}
 */
export async function mineDnsNames(domain, { dns, signal, onProgress, resolvePtr = false } = {}) {
  const apex = normalizeHostname(String(domain ?? ''), { allowSingleLabel: true });
  if (!apex || !dns || typeof dns.query !== 'function') {
    return { names: [], evidence: [], externalRefs: [] };
  }

  const names = new Set();
  const evidence = [];
  const evidenceSeen = new Set();
  const external = new Set();
  const ips = new Set();

  /**
   * Record a referenced name: in-domain → names + evidence, else externalRefs.
   * An in-domain service-label name (`_dmarc.<domain>`, a CNAME'd probe name)
   * is dropped. The same (name, from, record) is kept once: the SOA carried in
   * the authority section of every NXDOMAIN / NODATA answer is one piece of evidence.
   */
  const addName = (value, from, record) => {
    const norm = normalizeHostname(String(value ?? ''), { allowSingleLabel: true });
    if (!norm) return;
    if (isSubdomainOf(norm, apex)) {
      if (norm === apex) return; // the apex itself is not a discovery
      if (hasServiceLabel(norm)) return; // a record name, never a host
      names.add(norm);
      const rec = String(record ?? norm);
      const key = `${norm}\u0000${from}\u0000${rec}`;
      if (evidenceSeen.has(key)) return;
      evidenceSeen.add(key);
      evidence.push({ name: norm, from, record: rec });
    } else {
      external.add(norm);
    }
  };

  // Build the query plan.
  const plan = [
    ...APEX_QUERIES.map(([, type]) => ({ name: apex, type })),
    { name: `_dmarc.${apex}`, type: 'TXT' },
    ...SRV_SERVICES.map((svc) => ({ name: `${svc}.${apex}`, type: 'SRV' }))
  ];
  const total = plan.length;
  let done = 0;

  const responses = await Promise.all(plan.map(async (item) => {
    let res = null;
    try {
      res = await dns.query(item.name, item.type, { signal });
    } catch (err) {
      if (err && err.name === 'AbortError') throw err;
      res = null;
    }
    done += 1;
    if (typeof onProgress === 'function') {
      try { onProgress({ stage: 'mine', done, total, name: item.name }); } catch { /* ignore */ }
    }
    return { item, res };
  }));

  // First pass: harvest CNAME targets and address records from every answer. The
  // owner of a CNAME is harvested too; a probed service name (`_dmarc`,
  // `_sip._tls` CNAME'd to a vendor) is dropped by addName, never a host.
  for (const { res } of responses) {
    if (!res || !res.ok || !Array.isArray(res.answers)) continue;
    for (const rr of res.answers) {
      if (!rr) continue;
      if (rr.type === 'CNAME' && typeof rr.data === 'string') {
        addName(rr.data, 'CNAME', rr.text || rr.data);
        if (isSubdomainOf(String(rr.name || ''), apex)) addName(rr.name, 'CNAME', rr.text || rr.name);
      } else if ((rr.type === 'A' || rr.type === 'AAAA') && typeof rr.data === 'string') {
        const ip = normalizeIP(rr.data);
        if (ip && isSubdomainOf(String(rr.name || ''), apex)) ips.add(ip);
      }
    }
  }

  // Second pass: record-type-specific extraction.
  for (const { item, res } of responses) {
    if (!res || !res.ok) continue;
    const answers = Array.isArray(res.answers) ? res.answers : [];
    const authorities = Array.isArray(res.authorities) ? res.authorities : [];

    for (const rr of [...answers, ...authorities]) {
      if (!rr) continue;
      switch (rr.type) {
        case 'NS':
          if (typeof rr.data === 'string') addName(rr.data, 'NS', rr.text || rr.data);
          break;
        case 'MX':
          if (rr.data && typeof rr.data.exchange === 'string' && rr.data.exchange !== '.') {
            addName(rr.data.exchange, 'MX', rr.text || rr.data.exchange);
          }
          break;
        case 'SRV':
          if (rr.data && typeof rr.data.target === 'string' && rr.data.target !== '.') {
            addName(rr.data.target, 'SRV', `${item.name} → ${rr.data.target}`);
          }
          break;
        case 'SOA':
          if (rr.data) {
            if (typeof rr.data.mname === 'string') addName(rr.data.mname, 'SOA', rr.data.mname);
            const mailDomain = typeof rr.data.rname === 'string' ? soaMailDomain(rr.data.rname) : null;
            if (mailDomain) addName(mailDomain, 'SOA', rr.data.rname);
          }
          break;
        case 'HTTPS':
        case 'SVCB':
          if (rr.data && typeof rr.data.target === 'string' && rr.data.target !== '.' && rr.data.target !== '') {
            addName(rr.data.target, 'HTTPS', rr.text || rr.data.target);
          }
          break;
        case 'CAA':
          if (rr.data && rr.data.tag === 'iodef') {
            const host = hostFromUri(rr.data.value);
            if (host) addName(host, 'CAA', String(rr.data.value));
          } else if (rr.data && (rr.data.tag === 'issue' || rr.data.tag === 'issuewild')) {
            const ca = cleanHost(String(rr.data.value || '').split(';')[0].trim());
            if (ca) external.add(ca.toLowerCase());
          }
          break;
        case 'TXT': {
          const txt = txtString(rr);
          if (/^v=spf1\b/i.test(txt)) parseSpf(txt, addName);
          else if (/^v=dmarc1\b/i.test(txt) && item.name === `_dmarc.${apex}`) parseDmarc(txt, addName);
          break;
        }
        default:
          break;
      }
    }
  }

  // Optional PTR hook for in-domain IPs seen above.
  if (resolvePtr && typeof dns.ptr === 'function' && ips.size) {
    await Promise.all([...ips].map(async (ip) => {
      let ptrs = [];
      try { ptrs = await dns.ptr(ip, { signal }); } catch (err) {
        if (err && err.name === 'AbortError') throw err;
      }
      for (const p of ptrs) addName(p, 'PTR', `${ip} → ${p}`);
    }));
  }

  return {
    names: sortHostnames([...names]),
    evidence,
    externalRefs: [...external].sort()
  };
}

/** Parse SPF mechanisms and feed referenced hosts to `addName`. */
function parseSpf(txt, addName) {
  for (const raw of txt.split(/\s+/)) {
    if (!raw) continue;
    const tok = raw.replace(/^[+\-~?]/, '');
    let host = null;
    if (/^a:/i.test(tok)) host = tok.slice(2);
    else if (/^mx:/i.test(tok)) host = tok.slice(3);
    else if (/^include:/i.test(tok)) host = tok.slice(8);
    else if (/^exists:/i.test(tok)) host = tok.slice(7);
    else if (/^redirect=/i.test(tok)) host = tok.slice(9);
    else if (/^ptr:/i.test(tok)) host = tok.slice(4);
    const clean = cleanHost(host);
    if (clean) addName(clean, 'SPF', raw);
  }
}

/** Parse DMARC rua/ruf report addresses and feed report hosts to `addName`. */
function parseDmarc(txt, addName) {
  for (const part of txt.split(';')) {
    const m = part.trim().match(/^ru[af]=(.+)$/i);
    if (!m) continue;
    for (const uri of m[1].split(',')) {
      const host = hostFromUri(uri);
      if (host) addName(host, 'DMARC', uri.trim());
    }
  }
}
