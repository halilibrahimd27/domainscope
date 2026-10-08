/**
 * passport.js — "Domain overview": one page per domain for a migration or a customer takeover,
 * the facts an engineer otherwise assembles from five or six views by hand.
 *
 * - Lookups ({@link PASSPORT_LOOKUPS}): RDAP (lib/rdap.js), the zone's NS / SOA / DS / DNSKEY /
 *   MX / TXT / `_dmarc` TXT / HTTPS, the A and AAAA of the apex and of www, CAA (lib/health.js
 *   findCaa, climbing to the registrable domain) and a Domain Health run (lib/health.js
 *   domainHealth without RDAP, which the registration lookup already made). {@link buildPassport}
 *   runs them together and reports each as it lands, so the cards fill progressively; one build
 *   asks each DNS question once ({@link passportDns}: the health run shares the answers).
 * - Cards ({@link PASSPORT_CARDS}): {@link passportCards} turns the raw results into data —
 *   registration, DNS hosting, mail, web, certificates, SaaS verifications, health — with codes
 *   instead of text (the view translates). A lookup that failed is a lib/sourcestatus.js status
 *   on its card, and the card's `retry` names the lookups a Retry asks again.
 * - Tables: {@link DNS_PROVIDERS} (name-server host → DNS provider), {@link MAIL_PLATFORMS} (MX host
 *   and SPF include → mail platform), {@link TXT_VENDORS} (TXT verification token → service; the
 *   token value is never kept, only the vendor and its key) and {@link REGISTRY_WHOIS} (the web
 *   WHOIS of registries without RDAP; any other TLD gets its IANA root-zone page).
 * - Certificate Transparency: {@link lookupCtIssuers} — ONE Cert Spotter request (the single-host
 *   allowance), crt.sh only when Cert Spotter cannot answer — lists the issuers of the domain's
 *   current certificates; the certificates card compares them with CAA (health.checkCaaAllows).
 *   The view asks only on a click.
 * - {@link passportSummaryFacts}: what lib/summary.js domainSummary writes for "Copy summary".
 *
 * Verified live on 2026-09-28 with `Origin: https://halilibrahimd27.github.io`: Cert Spotter
 * `GET /v1/issuances?domain=<d>&match_wildcards=true&expand=issuer&expand=issuer.caa_domains
 * &expand=issuer.operator` answers with ACAO `*` (a preflight is allowed too), one page of current
 * issuances in ascending id order (11 for one busy apex, with a next page behind a `Link` header
 * a browser cannot read), each with `issuer: { friendly_name, name (DN), caa_domains[],
 * operator: { name, website }, pubkey_sha256 }`; it counts against the 100-per-hour single-host
 * allowance, like lib/ctcert.js. Name-server, MX and SPF-include patterns were checked against
 * live answers the same day (Natro: natrohost.com / natro.com, Turhost: turhost.com, İsimtescil:
 * isimtescil.net / dnsenable.com, Yaani: yaanimail.com, Türk Telekom: turktelekomeposta.com).
 *
 * DOM-free; runs in browsers and Node 22. Every network call takes an injected `dns` client
 * (lib/doh.js DohClient contract) or `fetchImpl` and the caller's `signal`; only an abort rejects.
 */

import { errorKind, fetchJson, throwIfAborted, uniq, ParseError } from './util.js';
import { normalizeHostname, registrableDomain, isSubdomainOf, isPublicSuffix } from './domain.js';
import { classifyResolution, normalizeIP } from './netinfo.js';
import { hostResolutionFrom } from './doh.js';
import { rdapDomain } from './rdap.js';
import {
  domainHealth, applyRdap, parseSpf, parseDmarc, findCaa, parseCaa, caaIssuerInfo, caaDomainsForIssuer, checkCaaAllows, CAA_ISSUERS
} from './health.js';
import { CERTSPOTTER_ISSUANCES, CRTSH_BASE, CT_TIMEOUT_MS, CRTSH_TIMEOUT_MS, ctCooldown, noteCertspotterLimit } from './ctcert.js';
import { sourceStatus, dohStatus, rdapStatus } from './sourcestatus.js';
import { trafficLight } from './summarycore.js';
import { scoreHealth } from './healthscore.js';

/** The cards of a passport, in display order. */
export const PASSPORT_CARDS = Object.freeze(['registration', 'dns', 'mail', 'web', 'certs', 'saas', 'health']);

/** Every lookup a passport runs ({@link runLookup}). */
export const PASSPORT_LOOKUPS = Object.freeze([
  'rdap', 'ns', 'soa', 'ds', 'dnskey', 'mx', 'txt', 'dmarc', 'apex', 'www', 'https', 'wwwHttps', 'caa', 'health'
]);

/**
 * The lookups each card is built from. The health card also reads `rdap` (its score includes
 * the registration checks, as Domain Health's does); the DNS card reads the registry's name
 * servers from `rdap` when there are any. A card's Retry asks only its own failed lookups.
 * @type {Readonly<Record<string, ReadonlyArray<string>>>}
 */
export const CARD_LOOKUPS = Object.freeze({
  registration: Object.freeze(['rdap']),
  dns: Object.freeze(['ns', 'soa', 'ds', 'dnskey']),
  mail: Object.freeze(['mx', 'txt', 'dmarc']),
  web: Object.freeze(['apex', 'www', 'https', 'wwwHttps']),
  certs: Object.freeze(['caa']),
  saas: Object.freeze(['txt']),
  health: Object.freeze(['health', 'rdap'])
});

/**
 * The lookups whose DNS questions the Domain Health run asks too (the apex's records and CAA):
 * after a Retry of one of them the view runs the health checks again, on the resolver's cache
 * but for the retried answers, so the score never quotes a failure a card no longer shows.
 */
export const HEALTH_LOOKUPS = Object.freeze(['ns', 'soa', 'ds', 'dnskey', 'mx', 'txt', 'dmarc', 'apex', 'https', 'caa']);

/** Which lookups send what where (the view says it before the click): RDAP or the DoH resolvers. */
export const LOOKUP_SOURCES = Object.freeze(Object.fromEntries(PASSPORT_LOOKUPS.map((id) => [id, id === 'rdap' ? 'rdap' : 'doh'])));

const DAY_MS = 86400000;

/* ------------------------------------------------------------------------ */
/* Names                                                                    */
/* ------------------------------------------------------------------------ */

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');

/**
 * The domain a passport is about: the registrable domain of a host name, URL or `*.name` (IDN →
 * punycode). `host` is set when the input named something below it (`www.example.com`), so the
 * view can say what it reduced. Null for IP addresses, public suffixes and junk.
 * @param {string} input
 * @returns {{ domain: string, host: string|null }|null}
 */
export function passportDomain(input) {
  const raw = String(input ?? '').trim();
  if (!raw || normalizeIP(raw.replace(/^\[|\]$/g, ''))) return null;
  const host = normalizeHostname(raw.replace(/^\*\./, ''));
  if (!host || normalizeIP(host)) return null;
  const domain = registrableDomain(host);
  if (!domain || isPublicSuffix(domain)) return null;
  return { domain, host: host === domain ? null : host };
}

/** Does `host` equal `suffix` or end with `.suffix`? */
function underSuffix(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

/** The first entry of `table` whose `suffixes` or `patterns` match `host`. */
function matchTable(table, host, key = 'suffixes', patternKey = 'patterns') {
  const h = canon(host);
  if (!h) return null;
  return table.find((e) => (e[key] || []).some((s) => underSuffix(h, s)) || (e[patternKey] || []).some((re) => re.test(h))) || null;
}

const freezeTable = (rows) => Object.freeze(rows.map((r) => Object.freeze({
  ...r,
  ...(r.suffixes ? { suffixes: Object.freeze([...r.suffixes]) } : {}),
  ...(r.patterns ? { patterns: Object.freeze([...r.patterns]) } : {}),
  ...(r.mx ? { mx: Object.freeze([...r.mx]) } : {}),
  ...(r.mxPatterns ? { mxPatterns: Object.freeze([...r.mxPatterns]) } : {}),
  ...(r.spf ? { spf: Object.freeze([...r.spf]) } : {})
})));

/* ------------------------------------------------------------------------ */
/* DNS hosting                                                              */
/* ------------------------------------------------------------------------ */

/**
 * Name-server host → DNS provider: a host equal to or under one of `suffixes`, or matching one
 * of `patterns` (lowercase, no trailing dot). Checked against live NS answers on 2026-09-28.
 * @type {ReadonlyArray<{ id: string, name: string, suffixes?: string[], patterns?: RegExp[] }>}
 */
export const DNS_PROVIDERS = freezeTable([
  { id: 'cloudflare', name: 'Cloudflare', suffixes: ['ns.cloudflare.com', 'foundationdns.com', 'foundationdns.net', 'foundationdns.org'] },
  { id: 'route53', name: 'Amazon Route 53', patterns: [/^ns-\d+\.awsdns-\d+\.(?:com|net|org|co\.uk)$/] },
  { id: 'azure', name: 'Azure DNS', patterns: [/^ns\d-\d+\.azure-dns\.(?:com|net|org|info)$/] },
  { id: 'google-cloud', name: 'Google Cloud DNS', patterns: [/^ns-cloud-[a-z]\d+\.googledomains\.com$/] },
  { id: 'ns1', name: 'IBM NS1 Connect', suffixes: ['nsone.net'] },
  { id: 'akamai', name: 'Akamai Edge DNS', suffixes: ['akam.net'] },
  { id: 'ultradns', name: 'UltraDNS', suffixes: ['ultradns.com', 'ultradns.net', 'ultradns.org', 'ultradns.info', 'ultradns.biz', 'ultradns.co.uk'] },
  { id: 'dyn', name: 'Oracle Dyn', suffixes: ['dynect.net'] },
  { id: 'oracle', name: 'Oracle Cloud DNS', suffixes: ['dns.oraclecloud.net'] },
  { id: 'microsoft365', name: 'Microsoft 365', suffixes: ['bdm.microsoftonline.com'] },
  { id: 'digitalocean', name: 'DigitalOcean', suffixes: ['digitalocean.com'] },
  { id: 'hetzner', name: 'Hetzner', suffixes: ['ns.hetzner.com', 'ns.hetzner.de', 'first-ns.de', 'second-ns.de', 'second-ns.com', 'your-server.de'] },
  { id: 'ovh', name: 'OVHcloud', suffixes: ['ovh.net', 'ovh.ca', 'anycast.me'] },
  { id: 'godaddy', name: 'GoDaddy', suffixes: ['domaincontrol.com'] },
  { id: 'namecheap', name: 'Namecheap', suffixes: ['registrar-servers.com'] },
  { id: 'ionos', name: 'IONOS', suffixes: ['ui-dns.com', 'ui-dns.de', 'ui-dns.org', 'ui-dns.biz'] },
  { id: 'strato', name: 'STRATO', suffixes: ['rzone.de'] },
  { id: 'gandi', name: 'Gandi', suffixes: ['gandi.net'] },
  { id: 'hostinger', name: 'Hostinger', suffixes: ['dns-parking.com'] },
  { id: 'natro', name: 'Natro', suffixes: ['natrohost.com', 'natro.com'] },
  { id: 'turhost', name: 'Turhost', suffixes: ['turhost.com'] },
  { id: 'isimtescil', name: 'İsimtescil', suffixes: ['isimtescil.net', 'dnsenable.com'] },
  { id: 'wix', name: 'Wix', suffixes: ['wixdns.net'] },
  { id: 'squarespace', name: 'Squarespace', suffixes: ['squarespacedns.com'] },
  { id: 'vercel', name: 'Vercel', suffixes: ['vercel-dns.com'] },
  { id: 'linode', name: 'Akamai Cloud (Linode)', suffixes: ['linode.com'] },
  { id: 'vultr', name: 'Vultr', suffixes: ['vultr.com'] },
  { id: 'porkbun', name: 'Porkbun', suffixes: ['porkbun.com'] },
  { id: 'cloudns', name: 'ClouDNS', suffixes: ['cloudns.net'] },
  { id: 'dnsmadeeasy', name: 'DNS Made Easy', suffixes: ['dnsmadeeasy.com'] },
  { id: 'he', name: 'Hurricane Electric', suffixes: ['he.net'] },
  { id: 'desec', name: 'deSEC', suffixes: ['desec.io', 'desec.org'] },
  { id: 'yandex', name: 'Yandex', suffixes: ['yandex.net'] },
  { id: 'alibaba', name: 'Alibaba Cloud DNS', suffixes: ['alidns.com', 'hichina.com'] },
  { id: 'dnspod', name: 'DNSPod (Tencent)', suffixes: ['dnspod.net'] },
  { id: 'networksolutions', name: 'Network Solutions', suffixes: ['worldnic.com'] },
  { id: 'wordpress', name: 'WordPress.com', suffixes: ['wordpress.com'] }
]);

/**
 * The DNS provider of a name-server host, or `{ id: 'self' }` for a host under the domain itself
 * (its own name servers), or null when not known.
 * @param {string} nsHost
 * @param {{ domain?: string|null }} [opts]
 * @returns {{ id: string, name: string|null }|null}
 */
export function dnsProviderOf(nsHost, { domain = null } = {}) {
  const host = canon(nsHost);
  if (!host) return null;
  if (domain && isSubdomainOf(host, canon(domain))) return { id: 'self', name: null };
  const hit = matchTable(DNS_PROVIDERS, host);
  return hit ? { id: hit.id, name: hit.name } : null;
}

/**
 * Name-server hosts grouped by provider, in the order they first appear; hosts under the
 * domain itself in `self`, unknown ones in `other`.
 * @param {string[]} nsHosts
 * @param {{ domain?: string|null }} [opts]
 * @returns {{ providers: Array<{ id: string, name: string, hosts: string[] }>, self: string[], other: string[] }}
 */
export function dnsHosting(nsHosts, { domain = null } = {}) {
  const providers = [];
  const self = [];
  const other = [];
  for (const host of uniq((nsHosts || []).map(canon).filter(Boolean))) {
    const p = dnsProviderOf(host, { domain });
    if (!p) other.push(host);
    else if (p.id === 'self') self.push(host);
    else {
      let g = providers.find((x) => x.id === p.id);
      if (!g) {
        g = { id: p.id, name: p.name, hosts: [] };
        providers.push(g);
      }
      g.hosts.push(host);
    }
  }
  return { providers, self, other };
}

/* ------------------------------------------------------------------------ */
/* Mail                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mail platforms by their MX hosts (`mx`: suffixes, `mxPatterns`) and SPF includes (`spf`:
 * suffixes of an `include:` or `redirect=` domain). `kind`: 'mailbox' (hosted mailboxes),
 * 'gateway' (a filtering service in front of the mailboxes), 'forwarding', 'sending' (bulk or
 * transactional mail; SPF only for most). Every SPF include was checked to publish SPF on
 * 2026-09-28.
 * @type {ReadonlyArray<{ id: string, name: string, kind: 'mailbox'|'gateway'|'forwarding'|'sending', mx?: string[], mxPatterns?: RegExp[], spf?: string[] }>}
 */
export const MAIL_PLATFORMS = freezeTable([
  { id: 'microsoft365', name: 'Microsoft 365', kind: 'mailbox', mx: ['mail.protection.outlook.com', 'mx.microsoft'], spf: ['spf.protection.outlook.com'] },
  { id: 'outlook', name: 'Outlook.com', kind: 'mailbox', mx: ['olc.protection.outlook.com'] },
  { id: 'google', name: 'Google Workspace', kind: 'mailbox', mx: ['aspmx.l.google.com', 'googlemail.com', 'smtp.google.com'], spf: ['_spf.google.com'] },
  { id: 'zoho', name: 'Zoho Mail', kind: 'mailbox', mx: ['zoho.com', 'zoho.eu', 'zoho.in', 'zoho.com.au', 'zoho.jp', 'zohomail.com'], spf: ['zoho.com', 'zoho.eu', 'zoho.in', 'zohomail.com'] },
  { id: 'yandex', name: 'Yandex 360', kind: 'mailbox', mx: ['mx.yandex.net', 'mx.yandex.ru'], spf: ['_spf.yandex.net', '_spf.yandex.ru'] },
  { id: 'yaani', name: 'Yaani Mail (Turkcell)', kind: 'mailbox', mx: ['yaanimail.com'] },
  { id: 'turktelekom', name: 'Türk Telekom e-posta', kind: 'mailbox', mx: ['turktelekomeposta.com'] },
  { id: 'mailru', name: 'Mail.ru for business', kind: 'mailbox', mx: ['mxs.mail.ru'], spf: ['_spf.mail.ru'] },
  { id: 'proton', name: 'Proton Mail', kind: 'mailbox', mx: ['protonmail.ch'], spf: ['_spf.protonmail.ch'] },
  { id: 'icloud', name: 'iCloud Mail', kind: 'mailbox', mx: ['mail.icloud.com'], spf: ['icloud.com'] },
  { id: 'fastmail', name: 'Fastmail', kind: 'mailbox', mx: ['messagingengine.com'], spf: ['spf.messagingengine.com'] },
  { id: 'godaddy', name: 'GoDaddy email', kind: 'mailbox', mx: ['secureserver.net'], spf: ['secureserver.net'] },
  { id: 'namecheap', name: 'Namecheap Private Email', kind: 'mailbox', mx: ['privateemail.com'], spf: ['spf.privateemail.com'] },
  { id: 'ovh', name: 'OVHcloud mail', kind: 'mailbox', mx: ['mail.ovh.net', 'mail.ovh.ca'], spf: ['mx.ovh.com'] },
  { id: 'ionos', name: 'IONOS mail', kind: 'mailbox', mx: ['ionos.com', 'ionos.de', 'ionos.co.uk', '1and1.com'], spf: ['_spf-eu.ionos.com', '_spf-us.ionos.com'] },
  { id: 'rackspace', name: 'Rackspace Email', kind: 'mailbox', mx: ['emailsrvr.com'], spf: ['emailsrvr.com'] },
  { id: 'titan', name: 'Titan Email', kind: 'mailbox', mx: ['titan.email'], spf: ['spf.titan.email'] },
  { id: 'hostinger', name: 'Hostinger Email', kind: 'mailbox', mx: ['mail.hostinger.com'], spf: ['_spf.mail.hostinger.com'] },
  { id: 'gandi', name: 'Gandi Mail', kind: 'mailbox', mx: ['mail.gandi.net'], spf: ['_mailcust.gandi.net'] },
  { id: 'migadu', name: 'Migadu', kind: 'mailbox', mx: ['migadu.com'], spf: ['spf.migadu.com'] },
  { id: 'tuta', name: 'Tuta', kind: 'mailbox', mx: ['tutanota.de'], spf: ['spf.tutanota.de'] },
  { id: 'mailboxorg', name: 'mailbox.org', kind: 'mailbox', mx: ['mailbox.org'], spf: ['mailbox.org'] },
  { id: 'mimecast', name: 'Mimecast', kind: 'gateway', mx: ['mimecast.com', 'mimecast.co.za', 'mimecast-offshore.com'], spf: ['_netblocks.mimecast.com'] },
  { id: 'proofpoint', name: 'Proofpoint', kind: 'gateway', mx: ['pphosted.com', 'ppe-hosted.com'], spf: ['pphosted.com', 'ppe-hosted.com'] },
  { id: 'barracuda', name: 'Barracuda Email Protection', kind: 'gateway', mx: ['barracudanetworks.com'], spf: ['barracudanetworks.com'] },
  { id: 'cisco', name: 'Cisco Secure Email', kind: 'gateway', mx: ['iphmx.com'], spf: ['iphmx.com'] },
  { id: 'trendmicro', name: 'Trend Micro Email Security', kind: 'gateway', mx: ['tmes.trendmicro.com', 'tmes.trendmicro.eu', 'hes.trendmicro.com'], spf: ['spf.tmes.trendmicro.com'] },
  { id: 'sophos', name: 'Sophos Email', kind: 'gateway', mx: ['hydra.sophos.com'], spf: ['prod.hydra.sophos.com'] },
  { id: 'symantec', name: 'Symantec Email Security.cloud', kind: 'gateway', mx: ['messagelabs.com'], spf: ['spf.messagelabs.com'] },
  { id: 'hornetsecurity', name: 'Hornetsecurity', kind: 'gateway', mx: ['hornetsecurity.com'], spf: ['spf.hornetsecurity.com'] },
  { id: 'cloudflare', name: 'Cloudflare Email Routing', kind: 'forwarding', mx: ['mx.cloudflare.net'], spf: ['_spf.mx.cloudflare.net'] },
  { id: 'improvmx', name: 'ImprovMX', kind: 'forwarding', mx: ['improvmx.com'], spf: ['spf.improvmx.com'] },
  { id: 'forwardemail', name: 'Forward Email', kind: 'forwarding', mx: ['forwardemail.net'], spf: ['spf.forwardemail.net'] },
  { id: 'amazonses', name: 'Amazon SES', kind: 'sending', mxPatterns: [/^inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$/], spf: ['amazonses.com'] },
  { id: 'mailgun', name: 'Mailgun', kind: 'sending', mx: ['mailgun.org'], spf: ['mailgun.org'] },
  { id: 'sendgrid', name: 'SendGrid', kind: 'sending', mx: ['mx.sendgrid.net'], spf: ['sendgrid.net'] },
  { id: 'postmark', name: 'Postmark', kind: 'sending', mx: ['inbound.postmarkapp.com'], spf: ['spf.mtasv.net'] },
  { id: 'mailchimp', name: 'Mailchimp', kind: 'sending', spf: ['servers.mcsv.net', 'spf.mandrillapp.com'] },
  { id: 'brevo', name: 'Brevo', kind: 'sending', spf: ['spf.brevo.com', 'spf.sendinblue.com'] },
  { id: 'mailjet', name: 'Mailjet', kind: 'sending', spf: ['spf.mailjet.com'] },
  { id: 'sparkpost', name: 'SparkPost', kind: 'sending', spf: ['sparkpostmail.com'] },
  { id: 'salesforce', name: 'Salesforce', kind: 'sending', spf: ['_spf.salesforce.com'] },
  { id: 'hubspot', name: 'HubSpot', kind: 'sending', spf: ['hubspotemail.net'] },
  { id: 'zendesk', name: 'Zendesk', kind: 'sending', spf: ['mail.zendesk.com'] },
  { id: 'freshdesk', name: 'Freshdesk', kind: 'sending', spf: ['email.freshdesk.com'] }
]);

/**
 * The mail platform of an MX host, or null.
 * @param {string} exchange
 * @returns {{ id: string, name: string, kind: string }|null}
 */
export function mailPlatformOf(exchange) {
  const hit = matchTable(MAIL_PLATFORMS, exchange, 'mx', 'mxPatterns');
  return hit ? { id: hit.id, name: hit.name, kind: hit.kind } : null;
}

/**
 * The platforms an SPF record authorises by name: every `include:` in front of `all` and, without
 * an `all`, the `redirect=` domain (receivers never get past `all`: RFC 7208 §5.1, §6.1), matched
 * against {@link MAIL_PLATFORMS} `spf` suffixes. Macro domains (`%{i}…`) and unknown
 * ones are listed in `other` as written.
 * @param {object|string} spf a health.parseSpf() result or the record text
 * @returns {{ senders: Array<{ id: string, name: string, kind: string }>, other: string[] }}
 */
export function spfSenders(spf) {
  const parsed = typeof spf === 'string' ? parseSpf(spf) : spf;
  const terms = (parsed && parsed.terms) || [];
  const hasAll = !!parsed && parsed.all != null && parsed.allIndex >= 0;
  const targets = [];
  for (const term of hasAll ? terms.slice(0, parsed.allIndex) : terms) if (term.mechanism === 'include' && term.value) targets.push(term.value);
  if (!hasAll && parsed && parsed.modifiers && parsed.modifiers.redirect) targets.push(parsed.modifiers.redirect);
  const senders = [];
  const other = [];
  for (const target of uniq(targets.map(canon))) {
    // A macro include (`%{ir}.%{v}.%{d}.spf.has.pphosted.com`) still names its service by its suffix.
    const hit = matchTable(MAIL_PLATFORMS, target, 'spf', null);
    if (!hit) other.push(target);
    else if (!senders.some((s) => s.id === hit.id)) senders.push({ id: hit.id, name: hit.name, kind: hit.kind });
  }
  return { senders, other };
}

/* ------------------------------------------------------------------------ */
/* SaaS verification tokens (TXT)                                           */
/* ------------------------------------------------------------------------ */

const V = (id, name, key, re) => ({ id, name, key, re });

/**
 * TXT verification records → the service that asked for them. `key` is the record's fixed
 * prefix, the only part ever shown: the token after it is never kept or displayed. Prefixes
 * observed in live TXT answers on 2026-09-28 and cross-checked with the nuclei-templates
 * `dns/txt-service-detect.yaml` list (MIT); matched at the start of the record only.
 * @type {ReadonlyArray<{ id: string, name: string, key: string, re: RegExp }>}
 */
export const TXT_VENDORS = Object.freeze([
  V('google', 'Google', 'google-site-verification', /^google-site-verification=/i),
  V('microsoft', 'Microsoft 365', 'MS=', /^MS=\S/),
  V('facebook', 'Meta (Facebook)', 'facebook-domain-verification', /^facebook-domain-verification=/i),
  V('workplace', 'Meta Workplace', 'workplace-domain-verification', /^workplace-domain-verification=/i),
  V('apple', 'Apple', 'apple-domain-verification', /^apple-domain-verification=/i),
  V('atlassian', 'Atlassian', 'atlassian-domain-verification', /^atlassian-domain-verification=/i),
  V('atlassian-sending', 'Atlassian (email sending)', 'atlassian-sending-domain-verification', /^atlassian-sending-domain-verification=/i),
  V('statuspage', 'Atlassian Statuspage', 'status-page-domain-verification', /^status-page-domain-verification=/i),
  V('docusign', 'DocuSign', 'docusign', /^docusign=/i),
  V('stripe', 'Stripe', 'stripe-verification', /^stripe-verification=/i),
  V('zoom', 'Zoom', 'zoom-domain-verification', /^(?:zoom-domain-verification=|ZOOM_verify_)/i),
  V('adobe', 'Adobe', 'adobe-idp-site-verification', /^adobe-idp-site-verification=/i),
  V('adobe-sign', 'Adobe Acrobat Sign', 'adobe-sign-verification', /^adobe-sign-verification=/i),
  V('hubspot', 'HubSpot', 'hubspot-domain-verification', /^hubspot-(?:domain|developer)-verification=/i),
  V('salesforce', 'Salesforce', '00D…', /^00D[A-Za-z0-9]{12,15}=/),
  V('pardot', 'Salesforce Account Engagement (Pardot)', 'pardot', /^pardot[_\d]/i),
  V('sfmc', 'Salesforce Marketing Cloud', 'SFMC-', /^SFMC-/),
  V('dynamics', 'Dynamics 365 Customer Insights', 'd365mktkey', /^d365mktkey=/i),
  V('openai', 'OpenAI', 'openai-domain-verification', /^openai-domain-verification=/i),
  V('anthropic', 'Anthropic', 'anthropic-domain-verification', /^anthropic-domain-verification(?:-[a-z0-9]+)?=/i),
  V('perplexity', 'Perplexity', 'perplexity-ai-domain-verification', /^perplexity-ai-domain-verification(?:-[a-z0-9]+)?=/i),
  V('cursor', 'Cursor', 'cursor-domain-verification', /^cursor-domain-verification(?:-[a-z0-9]+)?=/i),
  V('windsurf', 'Windsurf', 'windsurf-verification', /^windsurf-verification=/i),
  V('elevenlabs', 'ElevenLabs', 'elevenlabs', /^elevenlabs=/i),
  V('slack', 'Slack', 'slack-domain-verification', /^slack-domain-verification=/i),
  V('webex', 'Cisco Webex', 'webexdomainverification', /^webexdomainverification\./i),
  V('cisco', 'Cisco', 'cisco-ci-domain-verification', /^cisco-ci-domain-verification=/i),
  V('dropbox', 'Dropbox', 'dropbox-domain-verification', /^dropbox-domain-verification=/i),
  V('box', 'Box', 'box-domain-verification', /^box-domain-verification=/i),
  V('miro', 'Miro', 'miro-verification', /^miro-verification=/i),
  V('notion', 'Notion', 'notion-domain-verification', /^notion-domain-verification=/i),
  V('figma', 'Figma', 'figma-domain-verification', /^figma-domain-verification=/i),
  V('canva', 'Canva', 'canva-site-verification', /^canva-site-verification=/i),
  V('airtable', 'Airtable', 'airtable-verification', /^airtable-verification=/i),
  V('loom', 'Loom', 'loom-site-verification', /^loom-site-verification=/i),
  V('calendly', 'Calendly', 'calendly-site-verification', /^calendly-site-verification=/i),
  V('krisp', 'Krisp', 'krisp-domain-verification', /^krisp-domain-verification=/i),
  V('linear', 'Linear', 'linear-domain-verification', /^linear-domain-verification=/i),
  V('smartsheet', 'Smartsheet', 'smartsheet-site-validation', /^smartsheet-site-validation=/i),
  V('monday', 'monday.com', 'monday-com-verification', /^monday-com-verification=/i),
  V('whimsical', 'Whimsical', 'whimsical', /^whimsical=/i),
  V('zapier', 'Zapier', 'zapier-domain-verification-challenge', /^zapier-domain-verification-challenge=/i),
  V('teamviewer', 'TeamViewer', 'teamviewer-sso-verification', /^teamviewer-sso-verification=/i),
  V('lastpass', 'LastPass', 'lastpass-verification-code', /^lastpass-verification-code=/i),
  V('1password', '1Password', '1password-site-verification', /^1password-site-verification=/i),
  V('jamf', 'Jamf', 'jamf-site-verification', /^jamf-site-verification=/i),
  V('tailscale', 'Tailscale', 'TAILSCALE-', /^TAILSCALE-/),
  V('duo', 'Duo Security', 'duo_sso_verification', /^duo_sso_verification=/i),
  V('knowbe4', 'KnowBe4', 'knowbe4-site-verification', /^knowbe4-site-verification=/i),
  V('onetrust', 'OneTrust', 'onetrust-domain-verification', /^onetrust-domain-verification=/i),
  V('hackerone', 'HackerOne', 'h1-domain-verification', /^h1-domain-verification=/i),
  V('bugcrowd', 'Bugcrowd', 'bugcrowd-verification', /^bugcrowd-verification=/i),
  V('detectify', 'Detectify', 'detectify-verification', /^detectify-verification=/i),
  V('paloalto', 'Palo Alto Networks', 'paloaltonetworks-site-verification', /^paloaltonetworks-site-verification=/i),
  V('sophos', 'Sophos', 'sophos-domain-verification', /^sophos-domain-verification=/i),
  V('spycloud', 'SpyCloud', 'spycloud-domain-verification', /^spycloud-domain-verification=/i),
  V('haveibeenpwned', 'Have I Been Pwned', 'have-i-been-pwned-verification', /^have-i-been-pwned-verification=/i),
  V('keybase', 'Keybase', 'keybase-site-verification', /^keybase-site-verification=/i),
  V('globalsign', 'GlobalSign', 'globalsign-domain-verification', /^_?globalsign-domain-verification=/i),
  V('twilio', 'Twilio', 'twilio-domain-verification', /^twilio-domain-verification=/i),
  V('postman', 'Postman', 'postman-domain-verification', /^postman-domain-verification=/i),
  V('docker', 'Docker', 'docker-verification', /^docker-verification=/i),
  V('jetbrains', 'JetBrains', 'jetbrains-domain-verification', /^jetbrains-domain-verification=/i),
  V('mongodb', 'MongoDB Atlas', 'mongodb-site-verification', /^mongodb-site-verification=/i),
  V('vercel', 'Vercel', 'vercel-domain-verification', /^vercel-domain-verification(?:-[a-z0-9]+)?=/i),
  V('gitlab', 'GitLab Pages', 'gitlab-pages-verification-code', /^gitlab-pages-verification-code=/i),
  V('fastly', 'Fastly', 'fastly-domain-delegation', /^fastly-domain-delegation-/i),
  V('cloudflare', 'Cloudflare (dashboard SSO)', 'cloudflare_dashboard_sso', /^cloudflare_dashboard_sso=/i),
  V('aws', 'AWS', 'aws-domain-control-verification', /^aws-domain-control-verification=/i),
  V('hcp', 'HashiCorp Cloud Platform', 'hcp-domain-verification', /^hcp-domain-verification=/i),
  V('sonatype', 'Sonatype (Maven Central)', 'OSSRH-', /^OSSRH-\d+$/),
  V('mailgun', 'Mailgun', 'mgverify', /^mgverify=/i),
  V('brevo', 'Brevo', 'brevo-code', /^(?:brevo|sendinblue)-code:/i),
  V('mandrill', 'Mailchimp Transactional', 'mandrill_verify', /^mandrill_verify\./i),
  V('mailerlite', 'MailerLite', 'mailerlite-domain-verification', /^mailerlite-domain-verification=/i),
  V('zoho', 'Zoho', 'zoho-verification', /^zoho-verification=/i),
  V('proton', 'Proton', 'protonmail-verification', /^protonmail-verification=/i),
  V('yandex', 'Yandex', 'yandex-verification', /^yandex-verification[:=]/i),
  V('mailru', 'Mail.ru', 'mailru-verification', /^mailru-verification[:=]/i),
  V('yahoo', 'Yahoo', 'yahoo-verification-key', /^yahoo-verification-key=/i),
  V('pinterest', 'Pinterest', 'pinterest-site-verification', /^pinterest-site-verification=/i),
  V('ahrefs', 'Ahrefs', 'ahrefs-site-verification', /^ahrefs-site-verification_/i),
  V('liveramp', 'LiveRamp', 'liveramp-site-verification', /^liveramp-site-verification=/i),
  V('segment', 'Segment', 'segment-site-verification', /^segment-site-verification=/i),
  V('mixpanel', 'Mixpanel', 'mixpanel-domain-verify', /^mixpanel-domain-verify=/i),
  V('pendo', 'Pendo', 'pendo-domain-verification', /^pendo-domain-verification=/i),
  V('trustpilot', 'Trustpilot', 'trustpilot-one-time-verification', /^trustpilot-one-time-verification/i),
  V('successfactors', 'SAP SuccessFactors', 'successfactors-site-verification', /^successfactors-site-verification=/i),
  V('citrix', 'Citrix', 'citrix-verification-code', /^citrix-verification-code=/i),
  V('logmein', 'GoTo (LogMeIn)', 'logmein-verification-code', /^logmein-verification-code=/i),
  V('autodesk', 'Autodesk', 'autodesk-domain-verification', /^autodesk-domain-verification=/i),
  V('parallels', 'Parallels', 'parallels-domain-verification', /^parallels-domain-verification=/i),
  V('vmware', 'VMware Cloud', 'vmware-cloud-verification', /^vmware-cloud-verification-/i),
  V('dynatrace', 'Dynatrace', 'dynatrace-site-verification', /^dynatrace-site-verification=/i),
  V('infoblox', 'Infoblox', 'infoblox-domain-mastery', /^infoblox-domain-mastery=/i),
  V('nintex', 'Nintex', 'nintex', /^nintex\./i),
  V('loaderio', 'loader.io', 'loaderio', /^loaderio=/i),
  V('lovable', 'Lovable', 'lovable_verification', /^lovable_verification=/i),
  V('gamma', 'Gamma', 'gamma-domain-verification', /^gamma-domain-verification(?:-[a-z0-9]+)?=/i),
  V('serval', 'Serval', 'serval-domain-verification', /^serval-domain-verification(?:-[a-z0-9]+)?=/i),
  V('decagon', 'Decagon', 'decagon-domain-verification', /^decagon-domain-verification(?:-[a-z0-9]+)?=/i)
].map((v) => Object.freeze(v)));

/** Records that configure mail or policy, never a service verification (left out of the SaaS count). */
const POLICY_TXT = /^(?:v=spf1(?:\s|$)|v=DMARC1\b|v=DKIM1\b|v=STSv1\b|v=TLSRPTv1\b|v=BIMI1\b)/i;

/** The joined character-strings of a TXT RR's data (string[] or string). */
function txtText(data) {
  return Array.isArray(data) ? data.map(String).join('') : String(data ?? '');
}

/**
 * The service a TXT verification record belongs to, or null. Only the vendor and the record's
 * fixed key come back — never the token.
 * @param {string|string[]} record
 * @returns {{ id: string, name: string, key: string }|null}
 */
export function txtVendorOf(record) {
  const text = txtText(record).trim();
  const hit = TXT_VENDORS.find((v) => v.re.test(text));
  return hit ? { id: hit.id, name: hit.name, key: hit.key } : null;
}

/**
 * The services a domain's TXT records verify it with: one entry per vendor (how many records),
 * most records first, then by name; `policy` counts the SPF / DMARC / DKIM / MTA-STS / TLS-RPT /
 * BIMI records, `other` the rest nobody recognised. No token value is in the result.
 * @param {Array<string|string[]>} records the TXT records (character-strings joined or not)
 * @returns {{ vendors: Array<{ id: string, name: string, key: string, count: number }>, other: number, policy: number, total: number }}
 */
export function saasFingerprints(records) {
  const byId = new Map();
  let other = 0;
  let policy = 0;
  const list = Array.isArray(records) ? records : [];
  for (const record of list) {
    const text = txtText(record).trim();
    if (POLICY_TXT.test(text)) {
      policy += 1;
      continue;
    }
    const v = txtVendorOf(text);
    if (!v) {
      other += 1;
      continue;
    }
    const entry = byId.get(v.id) || { ...v, count: 0 };
    entry.count += 1;
    byId.set(v.id, entry);
  }
  const vendors = [...byId.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'en'));
  return { vendors, other, policy, total: list.length };
}

/* ------------------------------------------------------------------------ */
/* Registration                                                             */
/* ------------------------------------------------------------------------ */

/**
 * The web WHOIS of registries that publish no RDAP (checked 2026-09-28). `url` takes `{domain}`.
 * Any other TLD without RDAP gets its IANA root-zone page ({@link registryWhois}).
 * @type {Readonly<Record<string, { name: string, url: string }>>}
 */
export const REGISTRY_WHOIS = Object.freeze({
  tr: Object.freeze({ name: 'TRABİS', url: 'https://www.trabis.gov.tr/whois' }),
  de: Object.freeze({ name: 'DENIC', url: 'https://webwhois.denic.de/?lang=en&query={domain}' }),
  jp: Object.freeze({ name: 'JPRS', url: 'https://whois.jprs.jp/en/' }),
  ch: Object.freeze({ name: 'SWITCH', url: 'https://www.nic.ch/whois/' })
});

/**
 * Where to read a domain's registration when its TLD has no RDAP: the registry's own web WHOIS
 * ({@link REGISTRY_WHOIS}), else the TLD's page at IANA (it names the registry and its WHOIS
 * server). Null for a label that is not a TLD.
 * @param {string} tld e.g. 'tr'
 * @param {string} [domain] filled into a URL that takes it
 * @returns {{ name: string|null, url: string, iana: boolean }|null}
 */
export function registryWhois(tld, domain = '') {
  const t = canon(tld);
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(t)) return null;
  const known = REGISTRY_WHOIS[t];
  if (known) return { name: known.name, url: known.url.replace('{domain}', encodeURIComponent(canon(domain))), iana: false };
  return { name: null, url: `https://www.iana.org/domains/root/db/${t}.html`, iana: true };
}

/**
 * Registry status → what it means for the domain ('lock': a *Prohibited flag, 'hold', 'pending',
 * 'ok', 'other'), in RFC 8056 wording ('client hold') or EPP's ('clientHold') alike.
 */
function statusKind(status) {
  const s = canon(status);
  if (/prohibited/.test(s)) return 'lock';
  if (/hold\b/.test(s)) return 'hold';
  if (/pending|redemption/.test(s)) return 'pending';
  if (s === 'ok' || s === 'active' || s === 'associated') return 'ok';
  return 'other';
}

/**
 * RDAP status values with their kind: holds and pending deletes first, then locks. `code` is
 * spelled as the registry sent it (RFC 8056's 'client transfer prohibited' or EPP's
 * 'clientTransferProhibited'); a value repeated in another case counts once.
 * @param {string[]} statuses
 * @returns {Array<{ code: string, kind: 'lock'|'hold'|'pending'|'ok'|'other' }>}
 */
export function rdapStatusFlags(statuses) {
  const order = { hold: 0, pending: 1, lock: 2, ok: 3, other: 4 };
  const seen = new Set();
  const flags = [];
  for (const status of statuses || []) {
    const code = String(status ?? '').trim();
    const key = canon(code);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    flags.push({ code, kind: statusKind(key) });
  }
  return flags.sort((a, b) => order[a.kind] - order[b.kind] || canon(a.code).localeCompare(canon(b.code), 'en'));
}

/** Whole days from `now` until `date` (negative when past), like Domain Health's countdown. */
function daysUntil(date, now) {
  return Math.floor((date.getTime() - now.getTime()) / DAY_MS);
}

/* ------------------------------------------------------------------------ */
/* Small record helpers                                                     */
/* ------------------------------------------------------------------------ */

/** Answer RRs of `type` (any owner: a CNAME'd name's target records count). */
function answers(res, type) {
  return (res && Array.isArray(res.answers) ? res.answers : []).filter((rr) => rr && rr.type === type);
}

/** Did a DNS lookup get a usable answer (NOERROR or NXDOMAIN)? */
function answered(res) {
  return !!res && res.ok !== false && (res.rcode === 'NOERROR' || res.rcode === 'NXDOMAIN');
}

/**
 * Why a lookup gave nothing to show: a lib/sourcestatus.js status for a DNS query that got no
 * answer or an error rcode (SERVFAIL, REFUSED …), for a failed RDAP lookup, or for a lookup that
 * threw; null for an answer (NXDOMAIN and "no records" are answers).
 * @param {object|null|undefined} res a DnsResponse, a {@link hostFailure}-able HostResolution, an rdapDomain result or `{ failed: true, error, errorKind }`
 * @param {{ now?: number }} [opts]
 * @returns {object|null}
 */
export function lookupStatus(res, { now = Date.now() } = {}) {
  if (!res || typeof res !== 'object') return null;
  if (res.failed === true) return sourceStatus({ source: res.source || 'doh', error: res.error, errorKind: res.errorKind }, { now });
  if ('unsupportedTld' in res && 'registrar' in res) return rdapStatus(res, { now });
  if ('ipv4' in res && 'cnames' in res) return hostFailure(res, { now });
  if (res.ok === false) return dohStatus(res, { now }) || sourceStatus({ source: 'doh', error: res.error, errorKind: res.errorKind }, { now });
  const rcode = String(res.rcode || '').toUpperCase();
  if (rcode && rcode !== 'NOERROR' && rcode !== 'NXDOMAIN') return sourceStatus({ source: 'doh', rcode }, { now });
  return null;
}

/** The status of a host resolution that got no usable answer (status ERROR or an error rcode). */
function hostFailure(host, { now }) {
  const st = String(host.status || '').toUpperCase();
  if (st === 'NOERROR' || st === 'NXDOMAIN') return null;
  if (st === 'ERROR' || !st) return sourceStatus({ source: 'doh', error: host.error, errorKind: host.errorKind || 'unknown' }, { now });
  return sourceStatus({ source: 'doh', rcode: st }, { now });
}

/**
 * A DNS zone serial in the common YYYYMMDDnn convention → its date ('2026-09-28'), else null.
 * @param {number|string} serial
 * @returns {string|null}
 */
export function serialDate(serial) {
  const m = /^(\d{4})(\d{2})(\d{2})\d{2}$/.exec(String(serial ?? ''));
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (y < 1990 || y > 2100 || mo < 1 || mo > 12 || d < 1) return null;
  const date = new Date(Date.UTC(y, mo - 1, d));
  if (date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d) return null;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

/* ------------------------------------------------------------------------ */
/* Cards                                                                    */
/* ------------------------------------------------------------------------ */

const clock = (now) => (now instanceof Date ? now : new Date(Number.isFinite(now) ? now : Date.now()));

/** The lookups of a card that have not landed yet. */
function pendingOf(raw, id) {
  return CARD_LOOKUPS[id].filter((l) => raw[l] === undefined);
}

/**
 * The frame every card shares: `state` 'pending' while one of its lookups has not landed,
 * 'ready' once every one has; `failures` the statuses of those that failed; `retry` the
 * lookups a Retry asks again (failed or never run). A card stopped before a lookup landed stays
 * 'pending' here; the view says it was stopped.
 */
function frame(id, raw, own, { now }) {
  const lookups = own || CARD_LOOKUPS[id];
  const failures = [];
  const retry = [];
  for (const l of lookups) {
    const st = lookupStatus(raw[l], { now: now.getTime() });
    if (st) {
      failures.push({ lookup: l, ...st });
      retry.push(l);
    }
  }
  const pending = lookups.filter((l) => raw[l] === undefined);
  return { id, state: pending.length ? 'pending' : 'ready', pending, failures, retry };
}

/** The status of one lookup of a card, or null. */
function failureOf(card, lookup) {
  return card.failures.find((f) => f.lookup === lookup) || null;
}

/** Is the domain known not to exist (NXDOMAIN for its SOA and NS)? */
function nonexistent(raw) {
  return [raw.soa, raw.ns].every((r) => answered(r) && r.rcode === 'NXDOMAIN');
}

/**
 * Registration (RDAP): registrar, dates with the days left, the registry status flags (locks,
 * holds), whether a transfer lock is set, the DNSSEC delegation and the registry's name servers.
 * `outcome`: 'ok' | 'unsupported' (the TLD has no RDAP: `whois` says where to look) |
 * 'not-found' (not registered) | 'invalid' | 'failed' (see `failures`).
 * @param {object} raw lookup results by id
 * @param {{ now?: Date|number }} [opts]
 * @returns {object}
 */
export function registrationCard(raw, { now } = {}) {
  const t = clock(now);
  const card = { ...frame('registration', raw, null, { now: t }), outcome: null };
  const r = raw.rdap;
  if (r === undefined) return card;
  if (r.failed) return { ...card, outcome: 'failed' };
  card.domain = r.domain || null;
  card.tld = r.tld || null;
  if (r.unsupportedTld) return { ...card, outcome: 'unsupported', whois: registryWhois(r.tld, r.domain) };
  if (r.notFound) return { ...card, outcome: 'not-found' };
  if (r.errorKind === 'invalid') return { ...card, outcome: 'invalid' };
  if (!r.ok) {
    if (!card.failures.length) {
      card.failures.push({ lookup: 'rdap', ...sourceStatus({ source: 'rdap', error: r.error, errorKind: r.errorKind }, { now: t.getTime() }) });
      card.retry = ['rdap'];
    }
    return { ...card, outcome: 'failed' };
  }
  const expires = r.expires instanceof Date ? r.expires : null;
  const daysLeft = expires ? daysUntil(expires, t) : null;
  const status = Array.isArray(r.status) ? r.status : [];
  return {
    ...card,
    outcome: 'ok',
    registrar: r.registrar || null,
    registrarUrl: r.registrarUrl || null,
    ianaId: r.registrarIanaId || null,
    created: r.created || null,
    updated: r.updated || null,
    expires,
    daysLeft,
    // Domain Health's thresholds: under 30 days an error, under 60 a warning.
    expiry: daysLeft === null ? null : daysLeft < 0 ? 'expired' : daysLeft < 30 ? 'error' : daysLeft < 60 ? 'warn' : 'ok',
    flags: rdapStatusFlags(status),
    // Only a registry that reports statuses can say the lock is off.
    transferLock: status.length ? status.some((s) => /transfer ?prohibited/.test(canon(s))) : null,
    dnssec: typeof r.dnssecSigned === 'boolean' ? r.dnssecSigned : null,
    nameservers: Array.isArray(r.nameservers) ? r.nameservers : [],
    server: r.rdapServer || null,
    url: r.url || null
  };
}

/**
 * DNS hosting: the zone's name servers grouped by provider (several providers are named — a
 * multi-provider setup or a move half done), the registry's delegation when RDAP listed it and
 * it differs, the SOA primary, contact and serial (with its date when it follows YYYYMMDDnn) and
 * the DNSSEC state: 'validated' (DS at the parent, the resolver validated the keys), 'signed'
 * (DS, not validated), 'failing' (DS, but the DNSKEY lookup failed: validation may be broken),
 * 'unsigned' (no DS), null (not known).
 * @param {object} raw
 * @param {{ now?: Date|number }} [opts]
 * @returns {object}
 */
export function dnsCard(raw, { now } = {}) {
  const t = clock(now);
  const card = frame('dns', raw, null, { now: t });
  card.exists = !nonexistent(raw);
  const domain = raw.domain || null;
  const nsHosts = answered(raw.ns) ? uniq(answers(raw.ns, 'NS').map((rr) => canon(rr.data)).filter(Boolean)).sort() : [];
  card.nameservers = nsHosts;
  card.noNs = answered(raw.ns) && raw.ns.rcode === 'NOERROR' && !nsHosts.length;
  card.hosting = dnsHosting(nsHosts, { domain });
  const registry = raw.rdap && raw.rdap.ok && Array.isArray(raw.rdap.nameservers) ? raw.rdap.nameservers.map(canon).sort() : [];
  card.delegation = registry.length && nsHosts.length && registry.join(' ') !== nsHosts.join(' ')
    ? { registry, onlyRegistry: registry.filter((h) => !nsHosts.includes(h)), onlyZone: nsHosts.filter((h) => !registry.includes(h)) }
    : null;
  const soaRr = answered(raw.soa) ? answers(raw.soa, 'SOA').find((rr) => !domain || canon(rr.name) === domain) : null;
  card.soa = soaRr && soaRr.data ? {
    mname: canon(soaRr.data.mname),
    email: soaRr.data.email || soaRr.data.rname || null,
    serial: soaRr.data.serial ?? null,
    serialDate: serialDate(soaRr.data.serial),
    provider: dnsProviderOf(soaRr.data.mname, { domain })
  } : null;
  let dnssec = null;
  if (answered(raw.ds)) {
    const ds = answers(raw.ds, 'DS');
    if (!ds.length) dnssec = 'unsigned';
    else if (raw.dnskey === undefined) dnssec = 'signed';
    else if (!answered(raw.dnskey)) dnssec = raw.dnskey && raw.dnskey.ok !== false ? 'failing' : 'signed';
    else dnssec = raw.dnskey.flags && raw.dnskey.flags.ad ? 'validated' : 'signed';
    card.dsCount = ds.length;
  }
  card.dnssec = dnssec;
  return card;
}

/**
 * Mail: where the domain receives mail (MX hosts → platforms; 'none' without an MX record, 'null'
 * for a null MX that refuses mail), who SPF lets send (named platforms, the record's `all`
 * qualifier or its redirect) and the DMARC policy — one-liners from lib/health.js parseSpf /
 * parseDmarc.
 * @param {object} raw
 * @param {{ now?: Date|number }} [opts]
 * @returns {object}
 */
export function mailCard(raw, { now } = {}) {
  const t = clock(now);
  const card = frame('mail', raw, null, { now: t });
  card.exists = !nonexistent(raw);
  const domain = raw.domain || null;
  // MX
  card.mx = null;
  if (answered(raw.mx)) {
    const list = answers(raw.mx, 'MX').map((rr) => ({ preference: Number(rr.data && rr.data.preference) || 0, exchange: canon(rr.data && rr.data.exchange) }))
      .sort((a, b) => a.preference - b.preference || a.exchange.localeCompare(b.exchange, 'en'));
    const isNull = list.length === 1 && (list[0].exchange === '' || list[0].exchange === '.');
    const hosts = isNull ? [] : list.map((m) => ({ ...m, platform: mailPlatformOf(m.exchange), own: !!domain && isSubdomainOf(m.exchange, domain) }));
    const platforms = [];
    for (const m of hosts) {
      if (!m.platform) continue;
      let g = platforms.find((p) => p.id === m.platform.id);
      if (!g) {
        g = { ...m.platform, hosts: [] };
        platforms.push(g);
      }
      g.hosts.push(m.exchange);
    }
    card.mx = {
      state: isNull ? 'null' : hosts.length ? 'some' : 'none',
      hosts,
      platforms,
      other: hosts.filter((m) => !m.platform).map((m) => m.exchange)
    };
  }
  // SPF (the domain's own TXT records)
  card.spf = null;
  if (answered(raw.txt)) {
    const records = answers(raw.txt, 'TXT').map((rr) => txtText(rr.data).trim()).filter((s) => /^v=spf1(?:\s|$)/i.test(s));
    if (!records.length) card.spf = { state: 'none' };
    else if (records.length > 1) card.spf = { state: 'many', count: records.length };
    else {
      const parsed = parseSpf(records[0]);
      const { senders, other } = spfSenders(parsed);
      card.spf = {
        state: parsed.valid ? 'ok' : 'invalid',
        record: records[0],
        all: parsed.all,
        redirect: parsed.all === null && parsed.modifiers.redirect ? canon(parsed.modifiers.redirect) : null,
        senders,
        other,
        lookupTerms: parsed.lookupTerms
      };
    }
  }
  // DMARC
  card.dmarc = null;
  if (answered(raw.dmarc)) {
    const records = answers(raw.dmarc, 'TXT').map((rr) => txtText(rr.data).trim()).filter((s) => /^v\s*=\s*DMARC1\b/i.test(s));
    if (!records.length) card.dmarc = { state: 'none' };
    else if (records.length > 1) card.dmarc = { state: 'many', count: records.length };
    else {
      const parsed = parseDmarc(records[0]);
      card.dmarc = {
        state: parsed.valid ? 'ok' : 'invalid',
        record: records[0],
        policy: parsed.policy,
        subdomainPolicy: parsed.subdomainPolicy,
        pct: parsed.pct,
        reports: parsed.rua.length
      };
    }
  }
  return card;
}

/** One web host (apex or www) of the web card. */
function webHost(name, res, { now }) {
  if (res === undefined) return { name, state: 'pending' };
  if (res.failed) return { name, state: 'failed', failure: lookupStatus(res, { now }) };
  const failure = hostFailure(res, { now });
  if (failure) return { name, state: 'failed', failure };
  const cls = classifyResolution(res);
  return {
    name,
    state: res.status === 'NXDOMAIN' && !res.cnames.length ? 'nxdomain' : res.ipv4.length || res.ipv6.length ? 'ok' : res.cnames.length ? 'dangling' : 'nodata',
    cnames: res.cnames,
    ipv4: res.ipv4,
    ipv6: res.ipv6,
    classification: cls
  };
}

/** HTTPS (SVCB) records of a lookup: present / none / null (not known), with the ALPN ids. */
function httpsRecords(res) {
  if (!answered(res)) return null;
  const rrs = answers(res, 'HTTPS');
  if (!rrs.length) return { present: false, alpn: [] };
  return { present: true, alpn: uniq(rrs.flatMap((rr) => (rr.data && rr.data.params && Array.isArray(rr.data.params.alpn) ? rr.data.params.alpn : []))) };
}

/**
 * Web: the apex and www — what each resolves to and who serves it (lib/netinfo.js
 * classifyResolution: Cloudflare, another CDN, a platform, direct, private), whether www is an
 * alias of the apex, and whether each publishes an HTTPS (SVCB) record. `exists` is false for a
 * domain known not to exist (as on the DNS, mail and SaaS cards).
 * @param {object} raw
 * @param {{ now?: Date|number }} [opts]
 * @returns {object}
 */
export function webCard(raw, { now } = {}) {
  const t = clock(now);
  const card = frame('web', raw, null, { now: t });
  card.exists = !nonexistent(raw);
  const domain = raw.domain || '';
  const apex = webHost(domain, raw.apex, { now: t.getTime() });
  const www = webHost(domain ? `www.${domain}` : 'www', raw.www, { now: t.getTime() });
  www.aliasOfApex = www.state === 'ok' && (www.cnames || []).includes(domain);
  www.sameAsApex = www.state === 'ok' && apex.state === 'ok'
    && [...www.ipv4, ...www.ipv6].sort().join(' ') === [...apex.ipv4, ...apex.ipv6].sort().join(' ');
  card.hosts = [apex, www];
  card.https = { apex: httpsRecords(raw.https), www: httpsRecords(raw.wwwHttps) };
  return card;
}

/** The CA a CAA issuer domain names (health.CAA_ISSUERS), or null. */
function caOfIssuerDomain(domain) {
  const d = canon(domain);
  const ca = CAA_ISSUERS.find((c) => c.domains.includes(d));
  return ca ? { id: ca.id, name: ca.name } : null;
}

/**
 * Certificates: which CAs CAA lets issue (with the RFC 8657 restrictions and wildcard-only
 * values), and — once {@link lookupCtIssuers} ran (`raw.ct`) — the issuers of the current
 * certificates in CT, each with health.checkCaaAllows' verdict against that CAA set.
 * `caa.state`, read the way health.checkCaaAllows reads the set (RFC 8659 §4):
 * - 'none': no CAA record, any CA may issue;
 * - 'critical': a property with the critical flag and a tag CAs do not know (`criticalTags`):
 *   no CA may issue at all (§4.1);
 * - 'unrestricted': CAA records but no issue property (iodef, issuewild or other tags only): any
 *   CA may issue for the name itself (§4.2); an issuewild property still limits wildcard
 *   certificates (`wildcardOnly`, `issuewild`);
 * - 'deny-all': issue values that authorise nobody, and no issuewild value that authorises
 *   somebody: no certificate at all;
 * - 'present': the CAs the issue values name (`issue`, empty when only issuewild names CAs:
 *   wildcard certificates only);
 * - null: not known.
 * `ct`: null until asked, else `{ state: 'ok'|'failed', … }`. `exists` is false for a domain
 * known not to exist.
 * @param {object} raw
 * @param {{ now?: Date|number }} [opts]
 * @returns {object}
 */
export function certsCard(raw, { now } = {}) {
  const t = clock(now);
  const card = frame('certs', raw, null, { now: t });
  card.exists = !nonexistent(raw);
  const c = raw.caa;
  card.caa = null;
  if (c && !c.failed && !c.error) {
    const parsed = c.parsed || parseCaa(c.records || []);
    const entry = (e) => ({ issuer: e.issuer, ca: caOfIssuerDomain(e.issuer), restricted: !!e.restricted, critical: !!e.critical });
    const usable = (e) => e.valid && e.issuer && !e.problem;
    const issue = parsed.issue.filter(usable).map(entry);
    const wild = parsed.issuewild.filter(usable).map(entry);
    let state = 'present';
    if (!parsed.count) state = 'none';
    else if (parsed.unknownCritical) state = 'critical';
    else if (!parsed.issue.length) state = 'unrestricted';
    // Without issuewild a wildcard follows issue: nobody either.
    else if (!issue.length && !wild.length) state = 'deny-all';
    card.caa = {
      state,
      foundAt: c.foundAt || null,
      issue,
      issuewild: wild,
      wildcardOnly: parsed.issuewild.length > 0,
      iodef: parsed.iodef.length,
      criticalTags: uniq(parsed.unknown.filter((u) => u.critical).map((u) => u.tag)),
      parsed
    };
  } else if (c && (c.failed || c.error) && !card.failures.length) {
    // findCaa reports a failed climb as text; say which name did not answer.
    const last = Array.isArray(c.chain) && c.chain.length ? c.chain[c.chain.length - 1] : null;
    card.failures.push({ lookup: 'caa', ...sourceStatus({ source: 'doh', rcode: last && last.rcode ? last.rcode : null, error: c.error, errorKind: c.errorKind || 'unknown' }, { now: t.getTime() }) });
    card.retry = ['caa'];
  }
  card.ct = ctSection(raw.ct, card.caa);
  return card;
}

/** The CT part of the certificates card: the issuers with their CAA verdict. */
function ctSection(ct, caa) {
  if (!ct) return null;
  if (ct.status !== 'ok') return { state: 'failed', provider: ct.provider || null, failures: ct.failures || [] };
  const parsed = caa && caa.parsed ? caa.parsed : null;
  const issuers = ct.issuers.map((iss) => {
    let verdict = null;
    if (parsed) {
      const v = checkCaaAllows(parsed, iss.dn || iss.name, { issuerDomains: iss.caaDomains.length ? iss.caaDomains : null });
      verdict = v.verdict;
    }
    return { ...iss, verdict };
  });
  return {
    state: 'ok',
    provider: ct.provider,
    certificates: ct.certificates,
    firstPage: ct.provider === 'certspotter',
    issuers,
    notAllowed: issuers.filter((i) => i.verdict === 'denied').map((i) => i.name)
  };
}

/**
 * SaaS verifications: the services the domain's TXT records verify it with ({@link TXT_VENDORS}),
 * never the tokens.
 * @param {object} raw
 * @param {{ now?: Date|number }} [opts]
 * @returns {object}
 */
export function saasCard(raw, { now } = {}) {
  const card = frame('saas', raw, null, { now: clock(now) });
  card.exists = !nonexistent(raw);
  card.saas = answered(raw.txt) ? saasFingerprints(answers(raw.txt, 'TXT').map((rr) => rr.data)) : null;
  return card;
}

/**
 * Health: the Domain Health score of the domain (lib/health.js checks, lib/summary.js scoring)
 * with the registration checks of the passport's RDAP result applied (health.applyRdap), so it
 * matches what Domain Health shows; the worst problems first (three at most).
 * @param {object} raw
 * @param {{ now?: Date|number, max?: number }} [opts]
 * @returns {object}
 */
export function healthCard(raw, { now, max = 3 } = {}) {
  const t = clock(now);
  const card = frame('health', raw, ['health'], { now: t });
  // The score waits for the registration lookup too, so it never changes under the reader.
  if (raw.rdap === undefined && card.state === 'ready') card.state = 'pending';
  card.report = null;
  if (card.state !== 'ready' || !raw.health || raw.health.failed) return card;
  const report = applyRdap(raw.health, raw.rdap && !raw.rdap.failed ? raw.rdap : null, { now: t });
  const rank = { error: 0, warn: 1 };
  const problems = report.checks.filter((c) => c.severity === 'error' || c.severity === 'warn')
    .map((c, i) => ({ c, i })).sort((a, b) => rank[a.c.severity] - rank[b.c.severity] || a.i - b.i).map((x) => x.c);
  return {
    ...card,
    report,
    summary: report.summary,
    score: scoreHealth(report.checks).score,
    light: trafficLight(report.summary),
    problems: problems.slice(0, max).map((c) => ({ id: c.id, severity: c.severity, titleKey: c.titleKey, params: c.params })),
    moreProblems: Math.max(0, problems.length - max)
  };
}

const BUILDERS = { registration: registrationCard, dns: dnsCard, mail: mailCard, web: webCard, certs: certsCard, saas: saasCard, health: healthCard };

/**
 * Every card of a passport from its raw results (a lookup still running is `undefined`).
 * @param {object} raw lookup id → result, plus `domain`
 * @param {{ now?: Date|number }} [opts]
 * @returns {Record<string, object>} card id → card
 */
export function passportCards(raw, { now } = {}) {
  const r = raw || {};
  return Object.fromEntries(PASSPORT_CARDS.map((id) => [id, BUILDERS[id](r, { now })]));
}

/** The cards that say when the domain does not exist, which they read from the NS and SOA lookups. */
const EXISTS_CARDS = Object.freeze(['mail', 'web', 'certs', 'saas']);

/** The cards a lookup feeds (for a partial re-render when it lands). */
export function cardsOfLookup(lookup) {
  return PASSPORT_CARDS.filter((id) => CARD_LOOKUPS[id].includes(lookup) || (id === 'dns' && lookup === 'rdap')
    || (EXISTS_CARDS.includes(id) && (lookup === 'ns' || lookup === 'soa')));
}

/* ------------------------------------------------------------------------ */
/* Running the lookups                                                      */
/* ------------------------------------------------------------------------ */

const isAbort = (err) => errorKind(err) === 'abort';

/** A lookup that threw (anything but an abort): kept as its status, never as "no data". */
function thrownResult(err, source = 'doh') {
  return { failed: true, source, error: err && err.message ? String(err.message) : String(err), errorKind: errorKind(err) };
}

/**
 * One passport's DNS client: each (name, type, DO, CD) question is asked once per build, and the
 * Domain Health run of the build shares the answers (lib/health.js wraps it again). `noCache`
 * (a Retry) passes past the DohClient's cache. `resolveHost` / `detectWildcard` go to the
 * client's own when it has them, so the health run matches Domain Health's.
 * @param {object} dns lib/doh.js DohClient (or anything with its `query`)
 * @param {{ signal?: AbortSignal, noCache?: boolean }} [opts]
 * @returns {{ query: Function, resolveHost?: Function, detectWildcard?: Function }}
 */
export function passportDns(dns, { signal, noCache = false } = {}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('A DNS client with query(name, type, opts) is required');
  const memo = new Map();
  const client = {
    query(name, type = 'A', opts = {}) {
      const dnssec = !!opts.dnssec;
      const cd = !!opts.cd;
      const key = `${canon(name)}|${type}|${dnssec ? 1 : 0}|${cd ? 1 : 0}`;
      if (!memo.has(key)) {
        const p = (async () => {
          throwIfAborted(opts.signal || signal);
          try {
            return await dns.query(canon(name), type, { dnssec, cd, signal: opts.signal || signal, noCache });
          } catch (err) {
            if (isAbort(err)) throw err;
            return { name: canon(name), type, ok: false, rcode: null, answers: [], authorities: [], error: err && err.message ? err.message : String(err), errorKind: errorKind(err) };
          }
        })();
        memo.set(key, p);
        p.catch(() => memo.delete(key)); // an abort is not an answer
      }
      return memo.get(key);
    }
  };
  if (typeof dns.resolveHost === 'function') client.resolveHost = (name, opts = {}) => dns.resolveHost(name, { ...opts, noCache });
  if (typeof dns.detectWildcard === 'function') client.detectWildcard = (name, opts = {}) => dns.detectWildcard(name, opts);
  return client;
}

/**
 * Run one lookup of a passport ({@link PASSPORT_LOOKUPS}). DNS lookups resolve to a DnsResponse
 * (`apex` / `www`: a doh.js HostResolution), `rdap` to an rdapDomain() result, `caa` to a
 * health.findCaa() result, `health` to a domainHealth() report made without RDAP. Only an abort
 * rejects: anything else that throws comes back as `{ failed: true, error, errorKind }`.
 * @param {string} id
 * @param {string} domain the passport's domain ({@link passportDomain})
 * @param {{ dns: object, fetchImpl?: typeof fetch, signal?: AbortSignal, now?: Date|number }} opts
 *   `dns`: a {@link passportDns} client (shared by one build's lookups)
 * @returns {Promise<object>}
 */
export async function runLookup(id, domain, { dns, fetchImpl = globalThis.fetch, signal, now } = {}) {
  throwIfAborted(signal);
  const name = canon(domain);
  try {
    switch (id) {
      case 'rdap': return await rdapDomain(name, { fetchImpl, signal });
      case 'ns': return await dns.query(name, 'NS');
      case 'soa': return await dns.query(name, 'SOA');
      case 'ds': return await dns.query(name, 'DS', { dnssec: true });
      case 'dnskey': return await dns.query(name, 'DNSKEY', { dnssec: true });
      case 'mx': return await dns.query(name, 'MX');
      case 'txt': return await dns.query(name, 'TXT');
      case 'dmarc': return await dns.query(`_dmarc.${name}`, 'TXT');
      case 'https': return await dns.query(name, 'HTTPS');
      case 'wwwHttps': return await dns.query(`www.${name}`, 'HTTPS');
      case 'apex':
      case 'www': {
        const host = id === 'www' ? `www.${name}` : name;
        const [a, aaaa] = await Promise.all([dns.query(host, 'A'), dns.query(host, 'AAAA')]);
        return hostResolutionFrom(host, a, aaaa);
      }
      case 'caa': return await findCaa(name, { dns, signal });
      case 'health': return await domainHealth(name, { dns, fetchImpl, signal, rdap: false, now: now === undefined ? null : clock(now) });
      default: throw new RangeError(`passport: unknown lookup "${id}"`);
    }
  } catch (err) {
    if (isAbort(err) || err instanceof RangeError) throw err;
    return thrownResult(err, id === 'rdap' ? 'rdap' : 'doh');
  }
}

/**
 * Build a passport: every lookup at once, each result reported through `onLookup` as it lands
 * (the view re-renders the cards it feeds, {@link cardsOfLookup}). Rejects only with an
 * AbortError; what landed before the abort was reported already.
 * @param {string} domain
 * @param {{ dns: object, fetchImpl?: typeof fetch, signal?: AbortSignal, now?: Date|number,
 *   lookups?: string[], noCache?: boolean, onLookup?: (id: string, result: object) => void }} opts
 *   `dns`: a DohClient (wrapped in {@link passportDns} here); `lookups`: a subset (a card's
 *   Retry: its failed lookups, with `noCache`)
 * @returns {Promise<Record<string, object>>} the raw results, plus `domain`
 */
export async function buildPassport(domain, {
  dns, fetchImpl = globalThis.fetch, signal, now, lookups = PASSPORT_LOOKUPS, noCache = false, onLookup
} = {}) {
  const name = canon(domain);
  if (!normalizeHostname(name)) throw new TypeError(`Invalid domain: ${String(domain)}`);
  throwIfAborted(signal);
  const client = passportDns(dns, { signal, noCache });
  const raw = { domain: name };
  await Promise.all(lookups.map(async (id) => {
    const result = await runLookup(id, name, { dns: client, fetchImpl, signal, now });
    throwIfAborted(signal);
    raw[id] = result;
    if (typeof onLookup === 'function') {
      try { onLookup(id, result); } catch { /* observer errors are ignored */ }
    }
  }));
  return raw;
}

/* ------------------------------------------------------------------------ */
/* Certificate Transparency: the issuers of the current certificates        */
/* ------------------------------------------------------------------------ */

const JSON_INIT = Object.freeze({ headers: { accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer' });

/**
 * Cert Spotter issuances of one name with the issuer expanded (its CAA domains and operator
 * too): one single-host request, certificates that cover the name through a wildcard included.
 * @param {string} domain
 * @returns {string}
 */
export function certspotterIssuersUrl(domain) {
  return `${CERTSPOTTER_ISSUANCES}?domain=${encodeURIComponent(canon(domain))}&match_wildcards=true&expand=issuer&expand=issuer.caa_domains&expand=issuer.operator`;
}

/**
 * crt.sh identity search of one name, current certificates only (the fallback).
 * @param {string} domain
 * @returns {string}
 */
export function crtshIssuersUrl(domain) {
  return `${CRTSH_BASE}?q=${encodeURIComponent(canon(domain))}&output=json&exclude=expired`;
}

/** '2026-07-02T00:00:00Z' (Cert Spotter) or '2026-07-02T00:00:00' (crt.sh, UTC without a zone). */
function parseUtc(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  let s = value.trim().replace(' ', 'T');
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : new Date(ms);
}

/**
 * One attribute of a DN string (`dnPart('C=US, O=Let's Encrypt, CN=R11', 'O')` → "Let's Encrypt"),
 * `,` or `/` separated; null when it is not there. Also used by the headless runner (tools/ds).
 * @param {string} dn
 * @param {string} key attribute type (O, CN, …)
 * @returns {string|null}
 */
export function dnPart(dn, key) {
  const m = new RegExp(`(?:^|[,/]\\s*)${key}=("(?:[^"\\\\]|\\\\.)*"|[^,/]+)`, 'i').exec(String(dn ?? ''));
  return m ? m[1].replace(/^"|"$/g, '').trim() : null;
}

/**
 * The name an issuer is listed under: the known CA (health.CAA_ISSUERS), else the DN's O, else
 * its CN. Also used by the headless runner (tools/ds), so its CT issuers read like the card's.
 * @param {string} dn issuer DN
 * @param {string|null} [friendly] Cert Spotter's operator / friendly name
 * @returns {string}
 */
export function issuerName(dn, friendly) {
  const known = caaIssuerInfo(dn);
  if (known.length) return known[0].name;
  return (typeof friendly === 'string' && friendly.trim()) || dnPart(dn, 'O') || dnPart(dn, 'CN') || String(dn || '').trim() || '?';
}

/** Group current certificates by issuer: count, the newest issuance, the intermediates (CN) seen. */
function groupIssuers(certs) {
  const byName = new Map();
  for (const c of certs) {
    const name = issuerName(c.dn, c.friendly);
    const g = byName.get(name) || { name, dn: c.dn, intermediates: [], caaDomains: [], count: 0, newest: null };
    g.count += 1;
    const cn = dnPart(c.dn, 'CN');
    if (cn && !g.intermediates.includes(cn)) g.intermediates.push(cn);
    for (const d of c.caaDomains || []) if (!g.caaDomains.includes(d)) g.caaDomains.push(d);
    if (!g.newest || c.notBefore > g.newest) {
      g.newest = c.notBefore;
      g.dn = c.dn;
    }
    byName.set(name, g);
  }
  return [...byName.values()].sort((a, b) => b.count - a.count || b.newest - a.newest || a.name.localeCompare(b.name, 'en'));
}

/**
 * Issuers of Cert Spotter issuances that are current at `now` and not revoked. The CAA domains
 * are Cert Spotter's own (`issuer.caa_domains`), else those health.caaDomainsForIssuer knows.
 * @param {any[]} rows Cert Spotter JSON rows (with `issuer` expanded)
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ issuers: Array<{ name: string, dn: string, intermediates: string[], caaDomains: string[], count: number, newest: Date }>, certificates: number }}
 */
export function issuersFromCertspotter(rows, { now } = {}) {
  const t = clock(now).getTime();
  const certs = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || typeof row !== 'object' || row.revoked === true) continue;
    const nb = parseUtc(row.not_before);
    const na = parseUtc(row.not_after);
    if (!nb || !na || nb.getTime() > t || na.getTime() < t) continue;
    const iss = row.issuer && typeof row.issuer === 'object' ? row.issuer : {};
    const dn = typeof iss.name === 'string' ? iss.name : '';
    const own = Array.isArray(iss.caa_domains) ? iss.caa_domains.map(canon).filter(Boolean) : [];
    const friendly = (iss.operator && typeof iss.operator.name === 'string' && iss.operator.name) || iss.friendly_name;
    certs.push({ dn, friendly, caaDomains: own.length ? own : caaDomainsForIssuer(dn), notBefore: nb });
  }
  return { issuers: groupIssuers(certs), certificates: certs.length };
}

/**
 * Issuers of crt.sh rows that are current at `now`; the precertificate and the certificate of
 * one issuance (same issuer and serial) count once.
 * @param {any[]} rows crt.sh JSON rows
 * @param {{ now?: Date|number }} [opts]
 * @returns {{ issuers: object[], certificates: number }} as {@link issuersFromCertspotter}
 */
export function issuersFromCrtsh(rows, { now } = {}) {
  const t = clock(now).getTime();
  const seen = new Set();
  const certs = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || typeof row !== 'object') continue;
    const nb = parseUtc(row.not_before);
    const na = parseUtc(row.not_after);
    if (!nb || !na || nb.getTime() > t || na.getTime() < t) continue;
    const key = `${row.issuer_ca_id ?? row.issuer_name ?? ''}|${String(row.serial_number ?? row.id ?? '').toLowerCase().replace(/^0+/, '')}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const dn = typeof row.issuer_name === 'string' ? row.issuer_name : '';
    certs.push({ dn, friendly: null, caaDomains: caaDomainsForIssuer(dn), notBefore: nb });
  }
  return { issuers: groupIssuers(certs), certificates: certs.length };
}

/**
 * The issuers of a domain's current certificates from Certificate Transparency, without
 * burning quota: ONE Cert Spotter request (its single-host allowance: its first page, the
 * oldest current certificates first), and one crt.sh search only when Cert Spotter fails or is
 * cooling down after a 429 (lib/ctcert.js ctCooldown, shared with the Certificate view).
 * Only an abort rejects.
 * @param {string} domain
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, now?: Date|number, cooldown?: object,
 *   timeoutMs?: number, crtshTimeoutMs?: number }} [opts]
 * @returns {Promise<{ domain: string, status: 'ok'|'failed', provider: 'certspotter'|'crtsh'|null,
 *   issuers: object[], certificates: number, requests: number, failures: object[] }>}
 *   `failures`: a lib/sourcestatus.js status per service that could not answer (source
 *   'certspotter' / 'crtsh'); with status 'ok' they say why crt.sh answered instead
 */
export async function lookupCtIssuers(domain, {
  fetchImpl = globalThis.fetch, signal, now, cooldown = ctCooldown, timeoutMs = CT_TIMEOUT_MS, crtshTimeoutMs = CRTSH_TIMEOUT_MS
} = {}) {
  const name = canon(domain);
  if (!normalizeHostname(name)) throw new TypeError(`Invalid domain: ${String(domain)}`);
  throwIfAborted(signal);
  const at = clock(now).getTime();
  const out = { domain: name, status: 'failed', provider: null, issuers: [], certificates: 0, requests: 0, failures: [] };
  const failed = (source, err, extra = {}) => out.failures.push(sourceStatus({
    source, error: err && err.message ? err.message : String(err), errorKind: errorKind(err), status: err && err.status, ...extra
  }, { now: at }));

  const cooling = cooldown.get(at);
  if (cooling) {
    out.failures.push(sourceStatus({ source: 'certspotter', errorKind: 'rate-limit', retryAfterMs: cooling.resetAt ? cooling.resetAt.getTime() - at : null, at }, { now: at }));
  } else {
    try {
      out.requests += 1;
      const rows = await fetchJson(certspotterIssuersUrl(name), { ...JSON_INIT, fetchImpl, signal, timeoutMs });
      if (!Array.isArray(rows)) throw new ParseError('Unexpected Cert Spotter response (expected a JSON array)');
      return { ...out, ...issuersFromCertspotter(rows, { now: at }), status: 'ok', provider: 'certspotter' };
    } catch (err) {
      if (isAbort(err)) throw err;
      const quota = noteCertspotterLimit(err, { at, cooldown });
      failed('certspotter', err, quota && quota.resetAt ? { retryAfterMs: quota.resetAt.getTime() - at, at } : {});
    }
  }
  try {
    out.requests += 1;
    const rows = await fetchJson(crtshIssuersUrl(name), { ...JSON_INIT, fetchImpl, signal, timeoutMs: crtshTimeoutMs });
    if (!Array.isArray(rows)) throw new ParseError('Unexpected crt.sh response (expected a JSON array)');
    return { ...out, ...issuersFromCrtsh(rows, { now: at }), status: 'ok', provider: 'crtsh' };
  } catch (err) {
    if (isAbort(err)) throw err;
    failed('crtsh', err);
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Copy summary                                                             */
/* ------------------------------------------------------------------------ */

/**
 * What "Copy summary" says about a passport (lib/summary.js domainSummary): one fact group per
 * card, names only (vendors, platforms, providers, CAs), never a token, a record value or an
 * address. A part whose lookup failed is `failed: true`, one not finished `pending: true`; the
 * `…Failed` flags name the lookup of a card that failed, so a line never reads as complete
 * without it. `exists: false`: the domain is known not to exist.
 * @param {Record<string, object>} cards {@link passportCards} output
 * @param {{ domain: string, at?: Date|null, host?: string|null }} opts
 * @returns {object}
 */
export function passportSummaryFacts(cards, { domain, at = null, host = null }) {
  const c = cards || {};
  const part = (card) => ({ pending: !card || card.state !== 'ready', failed: !!card && card.failures.length > 0 });
  const failedLookup = (card, lookup) => !!(card.failures && card.failures.some((f) => f.lookup === lookup));
  const reg = c.registration || {};
  const dns = c.dns || {};
  const mail = c.mail || {};
  const web = c.web || {};
  const certs = c.certs || {};
  const saas = c.saas || {};
  const health = c.health || {};
  const hosting = dns.hosting || { providers: [], self: [], other: [] };
  return {
    domain,
    host,
    at,
    registration: {
      ...part(reg),
      outcome: reg.outcome || null,
      registrar: reg.registrar || null,
      expires: reg.expires || null,
      daysLeft: reg.daysLeft ?? null,
      transferLock: reg.transferLock ?? null,
      tld: reg.tld || null,
      whois: reg.whois ? reg.whois.name : null
    },
    dns: {
      ...part(dns),
      exists: dns.exists !== false,
      providers: hosting.providers.map((p) => p.name),
      self: hosting.self.length > 0,
      other: hosting.other,
      nsFailed: failedLookup(dns, 'ns'),
      dnssec: dns.dnssec ?? null,
      delegationDiffers: !!dns.delegation
    },
    mail: {
      ...part(mail),
      exists: mail.exists !== false,
      mx: mail.mx ? mail.mx.state : null,
      mxFailed: failedLookup(mail, 'mx'),
      spfFailed: failedLookup(mail, 'txt'),
      dmarcFailed: failedLookup(mail, 'dmarc'),
      platforms: mail.mx ? mail.mx.platforms.map((p) => p.name) : [],
      other: mail.mx ? mail.mx.other : [],
      // state 'ok' | 'none' (no record) | 'many' | 'invalid'; `all` the qualifier, `redirect` without one
      spf: mail.spf ? { state: mail.spf.state, all: mail.spf.all ?? null, redirect: !!mail.spf.redirect, count: mail.spf.count ?? 1 } : null,
      dmarc: mail.dmarc ? { state: mail.dmarc.state, policy: mail.dmarc.policy ?? null, count: mail.dmarc.count ?? 1 } : null
    },
    web: {
      ...part(web),
      exists: web.exists !== false,
      hosts: (web.hosts || []).map((x) => ({
        name: x.name,
        state: x.state,
        kind: x.classification ? x.classification.kind : null,
        provider: x.classification && x.classification.provider ? x.classification.provider.name : null
      })),
      https: web.https ? [web.https.apex, web.https.www].some((x) => x && x.present) : null,
      // the hosts (apex, www) whose HTTPS record lookup failed
      httpsFailed: [['https', 0], ['wwwHttps', 1]].filter(([l, i]) => failedLookup(web, l) && web.hosts && web.hosts[i]).map(([, i]) => web.hosts[i].name)
    },
    certs: {
      ...part(certs),
      exists: certs.exists !== false,
      caa: certs.caa ? certs.caa.state : null,
      caaFailed: failedLookup(certs, 'caa'),
      // the CAs of issue, and of issuewild when there is one (`wildcard`: it rules wildcard certificates)
      cas: certs.caa ? uniq(certs.caa.issue.map((e) => (e.ca ? e.ca.name : e.issuer))) : [],
      wildcard: !!(certs.caa && certs.caa.wildcardOnly),
      wildCas: certs.caa ? uniq(certs.caa.issuewild.map((e) => (e.ca ? e.ca.name : e.issuer))) : [],
      criticalTags: certs.caa && certs.caa.state === 'critical' ? certs.caa.criticalTags : [],
      ct: certs.ct && certs.ct.state === 'ok' ? {
        issuers: certs.ct.issuers.map((i) => ({ name: i.name, count: i.count })),
        notAllowed: certs.ct.notAllowed
      } : null,
      ctFailed: !!(certs.ct && certs.ct.state === 'failed')
    },
    saas: {
      ...part(saas),
      exists: saas.exists !== false,
      vendors: saas.saas ? saas.saas.vendors.map((v) => v.name) : []
    },
    health: {
      ...part(health),
      pending: !health || health.state !== 'ready',
      failed: !!(health && health.failures && health.failures.length),
      score: health.score ?? null,
      light: health.light || null
    }
  };
}
