/**
 * senders.js — the service behind a DMARC report source: "SendGrid", "Microsoft 365", "an ISP or
 * home network", where a report only gives an address. DOM-free; runs in browsers and Node 22.
 *
 * - {@link SENDER_SERVICES}: DomainScope's own table of about seventy mail services, each with the
 *   suffixes of its SPF includes, its DKIM `d=` and CNAME-target domains, its return-path domains,
 *   its reverse-DNS domains, a {@link SENDER_TYPES} type and a {@link SENDER_GUIDES} guide key (how
 *   to align it, worded by the view in English and Turkish). lib/passport.js names the SPF senders
 *   of the Domain overview from this table too ({@link serviceBySpf}, {@link passportKind}).
 * - {@link identifySource}: one source row of lib/dmarcreport.js → `{ service, type, via,
 *   confidence, … }`, from the strongest evidence down ({@link SENDER_VIAS}): a DKIM signature of
 *   another organisation than the header From, a return-path (or HELO) of another organisation that
 *   passed SPF, the include on the current SPF's path that authorizes the address, the address's
 *   reverse DNS in this table or in the bundled reverse-DNS map, the bundled ISP list, and last the
 *   network's holder (RIPEstat). The first three need nothing but the reports and the SPF the view
 *   already looked up; the rest only follow a click (DMARC & TLS reports › Identify senders).
 * - {@link loadSenderMaps}: the bundled lists (assets/data/senders: `ptr-map.json`, the
 *   mail-relevant reverse-DNS base domains of parsedmarc's map, and `isp.json`, its ISP base
 *   domains; tools/build-senders.mjs writes them), read once from this site on first use.
 * - {@link senderGuide} / {@link groupGuide}: how to align a source or a service group, chosen by
 *   the sources' classes too (none for your own servers, the forwarder's for a forwarder).
 * - {@link groupSources}: the sources folded per service, with totals; {@link serviceCsvRows}.
 *
 * Nothing is sent by this module except the bundled lists, read from this site.
 */

import { fetchJson, throwIfAborted, AbortError, ParseError } from './util.js';
import { registrableDomain } from './domain.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies (frozen; the i18n coverage test derives keys from them)      */
/* ------------------------------------------------------------------------ */

/**
 * What kind of sender a service is (`rpt.svcType.<id>`): mailboxes, an email security gateway, a
 * forwarder, transactional or marketing mail, another software service, a cloud platform, a web
 * host, a managed IT provider, a technology company sending as itself, an ISP or home network, or
 * only a network (its holder is all that is known).
 */
export const SENDER_TYPES = Object.freeze([
  'mailbox', 'security', 'forwarding', 'transactional', 'marketing', 'saas', 'cloud', 'hosting', 'msp', 'technology', 'isp', 'network'
]);
/** The evidence that named a source, strongest first (`rpt.svcVia.<id>`, `rpt.svcHow.<id>`). */
export const SENDER_VIAS = Object.freeze(['dkim', 'return-path', 'spf-include', 'ptr', 'isp', 'asn']);
/**
 * How sure a name is: `high` — authenticated (a DKIM signature that verified, a return-path that
 * passed SPF, the include that authorizes the address); `medium` — the address's reverse DNS,
 * confirmed forward (the name resolves back to it); `low` — a hint only (a reverse name that does
 * not resolve back, or only the network's holder).
 */
export const CONFIDENCES = Object.freeze(['high', 'medium', 'low']);
/** Guides of the services that have their own (`rpt.guide.<id>`); the others use their type's. */
export const SERVICE_GUIDES = Object.freeze([
  'microsoft365', 'google', 'amazonses', 'sendgrid', 'mailchimp', 'mandrill', 'mailgun', 'postmark', 'sparkpost', 'brevo', 'salesforce', 'hubspot', 'zendesk'
]);
/**
 * Every guide text (`rpt.guide.<id>`, params `{ service, domain }`): a service's own, one per
 * type, `forwarded` — a forwarder relayed the domain's mail, whose DKIM signature survived (it
 * names no sender: the service named may be the forwarder or the signer) — and `authorized` — an
 * authorized third party whose type's guide is worded for a server nothing authorizes.
 */
export const SENDER_GUIDES = Object.freeze([...SERVICE_GUIDES, ...SENDER_TYPES, 'forwarded', 'authorized']);
/**
 * The type guides worded for a server nothing authorizes ("authorize it in SPF", "if not, it is
 * spoofing"): an authorized third party gets `authorized` instead ({@link senderGuide}).
 */
export const UNAUTHORIZED_GUIDES = Object.freeze(['cloud', 'hosting', 'msp', 'technology', 'isp', 'network']);
/**
 * The mail-relevant types of parsedmarc's reverse-DNS map (base_reverse_dns_map.csv) → ours.
 * tools/build-senders.mjs keeps only these in ptr-map.json; the map's `ISP` rows go to isp.json.
 */
export const PTR_TYPE_MAP = Object.freeze({
  'Email Provider': 'mailbox',
  'Email Security': 'security',
  Marketing: 'marketing',
  SaaS: 'saas',
  IaaS: 'cloud',
  PaaS: 'cloud',
  'Web Host': 'hosting',
  MSP: 'msp',
  MSSP: 'msp',
  Technology: 'technology'
});
/** Format of the bundled lists this module reads (tools/build-senders.mjs FORMAT); another one is refused. */
export const SENDERS_FORMAT = 1;
/** The files of the bundled lists, under assets/data/senders/. */
export const SENDERS_FILES = Object.freeze(['manifest.json', 'ptr-map.json', 'isp.json']);
/** How long loading the bundled lists may take, bodies included. */
export const SENDERS_TIMEOUT_MS = 15000;
/** Most addresses one "Identify senders" click looks up in reverse DNS. */
export const IDENTIFY_MAX = 200;
/** Columns of {@link serviceCsvRows} (language-neutral). */
export const SERVICE_CSV_COLUMNS = Object.freeze([
  'service', 'type', 'via', 'confidence', 'addresses', 'messages', 'dmarc_pass', 'dmarc_fail', 'spf_aligned_pass', 'dkim_aligned_pass', 'classes', 'evidence', 'sources'
]);

/* ------------------------------------------------------------------------ */
/* The services                                                             */
/* ------------------------------------------------------------------------ */

/**
 * One service. `owns`: registrable domains that are the service's own, which count for every kind
 * of evidence (an SPF include, a DKIM `d=`, a return-path, a reverse name under them); `spf`,
 * `dkim`, `returnPath`, `ptr`: suffixes that count for that evidence only. `guide`: its own guide,
 * else its type's.
 */
const S = (id, name, type, { owns = [], spf = [], dkim = [], returnPath = [], ptr = [], guide = null } = {}) => {
  const all = (list) => Object.freeze([...new Set([...owns, ...list])]);
  return Object.freeze({ id, name, type, guide: guide || type, spf: all(spf), dkim: all(dkim), returnPath: all(returnPath), ptr: all(ptr) });
};

/**
 * DomainScope's own table of mail services. The SPF includes were checked to publish SPF on
 * 2026-10-08 (dns.google), the other domains are each service's own; a source is named by them
 * only with evidence that authenticates it (see {@link identifySource}). Ids shared with
 * lib/passport.js MAIL_PLATFORMS (the MX side) name the same platform.
 * @type {ReadonlyArray<{ id: string, name: string, type: string, guide: string, spf: string[], dkim: string[], returnPath: string[], ptr: string[] }>}
 */
export const SENDER_SERVICES = Object.freeze([
  // Mailboxes
  S('microsoft365', 'Microsoft 365', 'mailbox', { spf: ['spf.protection.outlook.com'], dkim: ['onmicrosoft.com', 'dkim.mail.microsoft'], guide: 'microsoft365' }),
  S('google', 'Google Workspace', 'mailbox', { spf: ['_spf.google.com'], dkim: ['gappssmtp.com'], guide: 'google' }),
  S('zoho', 'Zoho Mail', 'mailbox', { owns: ['zoho.com', 'zoho.eu', 'zoho.in', 'zoho.com.au', 'zoho.jp', 'zohomail.com'] }),
  S('yandex', 'Yandex 360', 'mailbox', { spf: ['_spf.yandex.net', '_spf.yandex.ru'], ptr: ['mail.yandex.net'] }),
  S('mailru', 'Mail.ru for business', 'mailbox', { spf: ['_spf.mail.ru'], ptr: ['mail.ru'] }),
  S('proton', 'Proton Mail', 'mailbox', { owns: ['protonmail.ch', 'proton.ch'] }),
  S('icloud', 'iCloud Mail', 'mailbox', { spf: ['icloud.com'] }),
  S('fastmail', 'Fastmail', 'mailbox', { owns: ['messagingengine.com', 'fastmail.com'], dkim: ['fmhosted.com'] }),
  S('godaddy', 'GoDaddy email', 'mailbox', { owns: ['secureserver.net'] }),
  S('namecheap', 'Namecheap Private Email', 'mailbox', { owns: ['privateemail.com'] }),
  S('ovh', 'OVHcloud mail', 'mailbox', { spf: ['mx.ovh.com'], ptr: ['mail-out.ovh.net'] }),
  S('ionos', 'IONOS mail', 'mailbox', { spf: ['_spf-eu.ionos.com', '_spf-us.ionos.com'], ptr: ['kundenserver.de', 'perfora.net'] }),
  S('rackspace', 'Rackspace Email', 'mailbox', { owns: ['emailsrvr.com'] }),
  S('titan', 'Titan Email', 'mailbox', { owns: ['titan.email'] }),
  S('hostinger', 'Hostinger Email', 'mailbox', { spf: ['mail.hostinger.com'] }),
  S('gandi', 'Gandi Mail', 'mailbox', { spf: ['_mailcust.gandi.net'], ptr: ['mail.gandi.net'] }),
  S('migadu', 'Migadu', 'mailbox', { owns: ['migadu.com'] }),
  S('tuta', 'Tuta', 'mailbox', { owns: ['tutanota.de', 'tuta.io'] }),
  S('mailboxorg', 'mailbox.org', 'mailbox', { owns: ['mailbox.org'] }),
  // Email security gateways (filtering in front of, or after, the mailboxes)
  S('mimecast', 'Mimecast', 'security', { owns: ['mimecast.com', 'mimecast.co.za', 'mimecast-offshore.com'] }),
  S('proofpoint', 'Proofpoint', 'security', { owns: ['pphosted.com', 'ppe-hosted.com'] }),
  S('barracuda', 'Barracuda Email Protection', 'security', { owns: ['barracudanetworks.com', 'barracuda.com'] }),
  S('cisco', 'Cisco Secure Email', 'security', { owns: ['iphmx.com'] }),
  S('trendmicro', 'Trend Micro Email Security', 'security', { spf: ['tmes.trendmicro.com', 'tmes.trendmicro.eu'], ptr: ['tmes.trendmicro.com', 'tmes.trendmicro.eu'] }),
  S('sophos', 'Sophos Email', 'security', { spf: ['hydra.sophos.com'], ptr: ['hydra.sophos.com'] }),
  S('symantec', 'Symantec Email Security.cloud', 'security', { owns: ['messagelabs.com'] }),
  S('hornetsecurity', 'Hornetsecurity', 'security', { owns: ['hornetsecurity.com'] }),
  // Forwarding
  S('cloudflare', 'Cloudflare Email Routing', 'forwarding', { spf: ['mx.cloudflare.net'] }),
  S('improvmx', 'ImprovMX', 'forwarding', { owns: ['improvmx.com'] }),
  S('forwardemail', 'Forward Email', 'forwarding', { owns: ['forwardemail.net'] }),
  // Transactional mail and SMTP relays
  S('amazonses', 'Amazon SES', 'transactional', { owns: ['amazonses.com'], guide: 'amazonses' }),
  S('sendgrid', 'SendGrid', 'transactional', { owns: ['sendgrid.net', 'sendgrid.info'], guide: 'sendgrid' }),
  S('mailgun', 'Mailgun', 'transactional', { owns: ['mailgun.org', 'mailgun.net'], guide: 'mailgun' }),
  S('postmark', 'Postmark', 'transactional', { owns: ['mtasv.net', 'postmarkapp.com'], guide: 'postmark' }),
  S('sparkpost', 'SparkPost', 'transactional', { owns: ['sparkpostmail.com'], guide: 'sparkpost' }),
  S('mandrill', 'Mailchimp Transactional (Mandrill)', 'transactional', { owns: ['mandrillapp.com'], guide: 'mandrill' }),
  S('mailjet', 'Mailjet', 'transactional', { owns: ['mailjet.com'] }),
  S('zeptomail', 'Zoho ZeptoMail', 'transactional', { owns: ['zeptomail.net', 'transmail.net'] }),
  S('elasticemail', 'Elastic Email', 'transactional', { owns: ['elasticemail.com', 'elasticemail.info'] }),
  S('mailersend', 'MailerSend', 'transactional', { owns: ['mailersend.net'] }),
  S('smtp2go', 'SMTP2GO', 'transactional', { owns: ['smtp2go.com', 'smtpcorp.com'] }),
  S('socketlabs', 'SocketLabs', 'transactional', { owns: ['email-od.com', 'socketlabs.com'] }),
  S('smtpcom', 'SMTP.com', 'transactional', { owns: ['smtp.com'] }),
  S('mailchannels', 'MailChannels', 'transactional', { owns: ['mailchannels.net'] }),
  // Marketing
  S('mailchimp', 'Mailchimp', 'marketing', { owns: ['mcsv.net', 'mcdlv.net', 'rsgsv.net'], guide: 'mailchimp' }),
  S('brevo', 'Brevo', 'marketing', { owns: ['brevo.com', 'sendinblue.com'], guide: 'brevo' }),
  S('hubspot', 'HubSpot', 'marketing', { owns: ['hubspotemail.net', 'hubspot.com'], guide: 'hubspot' }),
  S('sfmc', 'Salesforce Marketing Cloud', 'marketing', { owns: ['exacttarget.com'] }),
  S('pardot', 'Salesforce Account Engagement (Pardot)', 'marketing', { owns: ['pardot.com'] }),
  S('klaviyo', 'Klaviyo', 'marketing', { owns: ['klaviyomail.com', 'klaviyo.com'] }),
  S('zohocampaigns', 'Zoho Campaigns', 'marketing', { owns: ['zcsend.net'] }),
  S('mailerlite', 'MailerLite', 'marketing', { owns: ['mlsend.com', 'mailerlite.com'] }),
  S('constantcontact', 'Constant Contact', 'marketing', { owns: ['constantcontact.com', 'ccsend.com'] }),
  S('campaignmonitor', 'Campaign Monitor', 'marketing', { owns: ['createsend.com', 'cmail19.com', 'cmail20.com'] }),
  S('activecampaign', 'ActiveCampaign', 'marketing', { owns: ['emsd1.com', 'activecampaign.com'] }),
  S('aweber', 'AWeber', 'marketing', { owns: ['aweber.com'] }),
  S('marketo', 'Adobe Marketo Engage', 'marketing', { owns: ['mktomail.com'] }),
  S('eloqua', 'Oracle Eloqua', 'marketing', { owns: ['en25.com'] }),
  S('customerio', 'Customer.io', 'marketing', { owns: ['customeriomail.com'] }),
  S('mailpoet', 'MailPoet', 'marketing', { owns: ['mailpoet.com'] }),
  // Software services that send as their customers
  S('salesforce', 'Salesforce', 'saas', { owns: ['salesforce.com'], guide: 'salesforce' }),
  S('zendesk', 'Zendesk', 'saas', { owns: ['zendesk.com', 'zdsys.com'], guide: 'zendesk' }),
  S('freshdesk', 'Freshdesk', 'saas', { owns: ['freshdesk.com', 'freshemail.io'] }),
  S('helpscout', 'Help Scout', 'saas', { owns: ['helpscoutemail.com'] }),
  S('intercom', 'Intercom', 'saas', { owns: ['intercom.io', 'intercom-mail.com'] }),
  S('atlassian', 'Atlassian', 'saas', { owns: ['atlassian.net'] }),
  S('servicenow', 'ServiceNow', 'saas', { owns: ['service-now.com'] }),
  S('netsuite', 'Oracle NetSuite', 'saas', { owns: ['netsuite.com'] }),
  S('shopify', 'Shopify', 'saas', { owns: ['shopify.com', 'shopifyemail.com'] }),
  S('knowbe4', 'KnowBe4', 'saas', { owns: ['knowbe4.com'] }),
  S('exclaimer', 'Exclaimer', 'saas', { owns: ['exclaimer.net'] }),
  S('codetwo', 'CodeTwo', 'saas', { owns: ['emailsignatures365.com'] })
]);

/** The kinds lib/passport.js gives a mail platform (`dov.mail.kind.<kind>`). */
export const PASSPORT_KINDS = Object.freeze(['mailbox', 'gateway', 'forwarding', 'sending']);

/**
 * The Domain overview's kind of a {@link SENDER_TYPES} type: mailboxes, a filtering gateway, a
 * forwarder, or a sending service (everything else).
 * @param {string} type
 * @returns {'mailbox'|'gateway'|'forwarding'|'sending'}
 */
export function passportKind(type) {
  return type === 'mailbox' ? 'mailbox' : type === 'security' ? 'gateway' : type === 'forwarding' ? 'forwarding' : 'sending';
}

/* ------------------------------------------------------------------------ */
/* Matching                                                                 */
/* ------------------------------------------------------------------------ */

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');

/**
 * A name and its parents down to two labels, longest first: `a.b.example.com` → `a.b.example.com`,
 * `b.example.com`, `example.com`. Labels that are not host names (an SPF macro such as `%{ir}`)
 * stay: they only make a longer suffix that no table holds.
 * @param {string} name
 * @returns {string[]}
 */
export function suffixesOf(name) {
  const n = canon(name);
  if (!n || !n.includes('.')) return [];
  const labels = n.split('.');
  if (labels.some((l) => !l)) return [];
  const out = [];
  for (let i = 0; i <= labels.length - 2; i += 1) out.push(labels.slice(i).join('.'));
  return out;
}

/** field → suffix → service, built once. */
let indexes = null;
function indexOf(field) {
  if (!indexes) {
    indexes = {};
    for (const f of ['spf', 'dkim', 'returnPath', 'ptr']) {
      const m = new Map();
      for (const s of SENDER_SERVICES) for (const suffix of s[f]) if (!m.has(suffix)) m.set(suffix, s);
      indexes[f] = m;
    }
  }
  return indexes[field];
}

/** The service whose suffix in `field` is the longest one `name` equals or sits under, or null. */
function byTable(field, name) {
  const index = indexOf(field);
  for (const s of suffixesOf(name)) {
    const hit = index.get(s);
    if (hit) return hit;
  }
  return null;
}

/** A {@link SENDER_SERVICES} entry by id, or null. */
export function serviceById(id) {
  return SENDER_SERVICES.find((s) => s.id === id) || null;
}
/** The service an SPF `include:` / `redirect=` domain belongs to (a macro include by its suffix), or null. */
export const serviceBySpf = (domain) => byTable('spf', domain);
/** The service a DKIM `d=` domain (or a DKIM CNAME target) belongs to, or null. */
export const serviceByDkim = (domain) => byTable('dkim', domain);
/** The service a return-path (envelope from) domain belongs to, or null. */
export const serviceByReturnPath = (domain) => byTable('returnPath', domain);
/** The service a reverse-DNS name belongs to, or null. */
export const serviceByPtr = (name) => byTable('ptr', name);

/**
 * The longest suffix of `name` that `map` (the bundled reverse-DNS map: a Map of base domain →
 * `[name, type]`) holds, with its entry.
 * @param {Map<string, [string, string]>|null|undefined} map
 * @param {string} name
 * @returns {{ key: string, name: string, type: string }|null}
 */
export function lookupMap(map, name) {
  if (!map || typeof map.get !== 'function') return null;
  for (const s of suffixesOf(name)) {
    const hit = map.get(s);
    if (hit) return { key: s, name: hit[0], type: hit[1] };
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Identification                                                           */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} SenderIdentification
 * @property {string|null} id a {@link SENDER_SERVICES} id; null for a name from the bundled map, an ISP or a network
 * @property {string} service the name shown: the service's, the map's, the ISP's base domain, or the network's holder
 * @property {string} type one of {@link SENDER_TYPES}
 * @property {string} via one of {@link SENDER_VIAS}
 * @property {string} confidence one of {@link CONFIDENCES}
 * @property {string} domain the evidence: the DKIM `d=` domain, the return-path domain, the include, the reverse
 *   name, or the AS number (`AS64496`)
 * @property {string} guide one of {@link SENDER_GUIDES}
 */

const orgOf = (d) => registrableDomain(d) || canon(d);

const fromService = (s, via, confidence, domain) => ({ id: s.id, service: s.name, type: s.type, via, confidence, domain, guide: s.guide });
const fromMap = (hit, via, confidence, domain) => ({ id: null, service: hit.name, type: hit.type, via, confidence, domain, guide: hit.type });

/**
 * The first of `names` this table names (`byTable`), else the first the bundled map names: the
 * table always before the map, whatever the order of `names`.
 */
function firstNamed(names, byTable, map, via) {
  for (const d of names) {
    const s = byTable(d);
    if (s) return fromService(s, via, 'high', canon(d));
  }
  for (const d of names) {
    const hit = lookupMap(map, d);
    if (hit) return fromMap(hit, via, 'high', canon(d));
  }
  return null;
}

/** The domains of a source's passing results (DKIM or SPF) of another organisation: the most messages first, then by name. */
function passingForeign(list, foreign) {
  return (list || []).filter((a) => a && a.result === 'pass' && foreign(a.domain))
    .sort((a, b) => (b.messages || 0) - (a.messages || 0) || (canon(a.domain) < canon(b.domain) ? -1 : canon(a.domain) > canon(b.domain) ? 1 : 0))
    .map((a) => a.domain);
}

/**
 * The path of the SPF verdict that authorizes a source: the checked domain first, then each
 * include / redirect domain on the way (lib/health.js spfEvaluate `path`), then the `a` / `mx`
 * host that matched. The current verdict when it passes, else — when the record gives a
 * permerror — what the record lists (`spfListed`); [] when neither authorizes the address.
 * @param {{ spfNow?: object|null, spfListed?: object|null }} row lib/dmarcreport.js classifySources row
 * @returns {string[]}
 */
export function spfPathOf(row) {
  const v = [row && row.spfNow, row && row.spfListed].find((x) => x && x.result === 'pass');
  if (!v) return [];
  const path = Array.isArray(v.path) ? [...v.path] : [];
  if (v.via && v.via.host) path.push(v.via.host);
  return path;
}

/**
 * Name the service behind one sending address of a DMARC report, from the strongest evidence
 * down; the first that names it wins:
 *  1. `dkim` — a DKIM signature that verified, for a domain of another organisation than the
 *     header From (the service's own signing domain: `d=sendgrid.net`);
 *  2. `return-path` — a return-path (or HELO) domain of another organisation that passed SPF;
 *  3. `spf-include` — the include on the current SPF's path that authorizes the address
 *     (`spfPath`, see {@link spfPathOf});
 *  4. `ptr` — the address's reverse name, under a service of this table or a base domain of the
 *     bundled map (`maps.ptr`);
 *  5. `isp` — the reverse name's base domain in the bundled ISP list (`maps.isp`): an ISP or home
 *     network, so spoofing or a user forwarding their mail;
 *  6. `asn` — only the network's holder (RIPEstat), for what nothing else names.
 * Steps 1–3 are `high` confidence (authenticated); 4 and 5 `medium` when the reverse name is
 * forward-confirmed (`ptrConfirmed`), else `low`; 6 `low`. A domain of the header From's own
 * organisation (or the policy domain's) never names a service: that is the domain itself. Within
 * a step this table comes before the bundled map, across every candidate of the step: the
 * signatures (return-paths) the most messages first, then by name, so the name never depends on
 * the order the reports were read; the SPF path in its order, nearest the domain first.
 * @param {{ headerFrom?: string[], dkimAuth?: object[], spfAuth?: object[] }} row a lib/dmarcreport.js source row
 * @param {{ domain?: string|null, spfPath?: string[]|null, ptrName?: string|null, ptrConfirmed?: boolean,
 *   maps?: { ptr?: Map<string, [string, string]>, isp?: Set<string> }|null, holder?: { name: string, asn?: number|null }|null }} [opts]
 *   domain: the policy domain; maps: {@link loadSenderMaps}'s lists (the table alone without them); holder: the
 *   network's holder and AS (lib/ipintel.js info `holder`, `asn`)
 * @returns {SenderIdentification|null} null when nothing names it
 */
export function identifySource(row, { domain = null, spfPath = null, ptrName = null, ptrConfirmed = false, maps = null, holder = null } = {}) {
  if (!row || typeof row !== 'object') return null;
  const orgs = new Set([...(row.headerFrom || []), domain].filter(Boolean).map(orgOf));
  const foreign = (d) => !!canon(d) && !orgs.has(orgOf(d));
  const ptrMap = maps && maps.ptr;
  const authenticated = firstNamed(passingForeign(row.dkimAuth, foreign), serviceByDkim, ptrMap, 'dkim')
    || firstNamed(passingForeign(row.spfAuth, foreign), serviceByReturnPath, ptrMap, 'return-path')
    || firstNamed((spfPath || []).slice(1).filter(foreign), serviceBySpf, ptrMap, 'spf-include');
  if (authenticated) return authenticated;
  const ptr = canon(ptrName);
  if (ptr && foreign(ptr)) {
    const confidence = ptrConfirmed ? 'medium' : 'low';
    const s = serviceByPtr(ptr);
    if (s) return fromService(s, 'ptr', confidence, ptr);
    const hit = lookupMap(ptrMap, ptr);
    if (hit) return fromMap(hit, 'ptr', confidence, ptr);
    const isp = maps && maps.isp && typeof maps.isp.has === 'function' ? suffixesOf(ptr).find((x) => maps.isp.has(x)) : null;
    if (isp) return { id: null, service: isp, type: 'isp', via: 'isp', confidence, domain: ptr, guide: 'isp' };
  }
  if (holder && typeof holder.name === 'string' && holder.name.trim()) {
    const asn = Number.isInteger(holder.asn) ? `AS${holder.asn}` : '';
    return { id: null, service: holder.name.trim(), type: 'network', via: 'asn', confidence: 'low', domain: asn, guide: 'network' };
  }
  return null;
}

/**
 * The guide that fits a named source (`rpt.guide.<key>`), from its class (lib/dmarcreport.js
 * SOURCE_CLASSES) as much as from the service: none for your own server (the class and its fixes
 * say what it needs); `forwarded` for a forwarder, whatever named it (its reverse name and the
 * return-path its forwarding rewrote name the forwarder; a DKIM signature, the sender); for an
 * authorized third party, `authorized` in place of a guide worded for a server nothing authorizes
 * ({@link UNAUTHORIZED_GUIDES}); else — an unknown sender, or no class — the identification's own.
 * @param {SenderIdentification|null} ident
 * @param {{ cls?: string }} [row]
 * @returns {string|null}
 */
export function senderGuide(ident, row = null) {
  if (!ident) return null;
  const cls = row ? row.cls : null;
  if (cls === 'yours') return null;
  if (cls === 'forwarder') return 'forwarded';
  if (cls === 'third-party' && UNAUTHORIZED_GUIDES.includes(ident.guide)) return 'authorized';
  return ident.guide;
}

/**
 * The sources an "Identify senders" click looks up: public addresses that nothing in the reports
 * names, or that only an unconfirmed reverse name, the ISP list or the network names, that are
 * not your own (the server list or your own SPF terms already say whose they are) and that no
 * click has looked up yet; the most messages first, at most `max`.
 * @param {Array<{ ip: string, private?: boolean, messages: number, cls?: string }>} rows
 * @param {{ identOf: (row: object) => SenderIdentification|null, checked?: { has(ip: string): boolean }, max?: number }} opts
 * @returns {object[]}
 */
export function identifyCandidates(rows, { identOf, checked = new Set(), max = IDENTIFY_MAX } = {}) {
  const weak = (id) => !id || id.via === 'asn' || ((id.via === 'ptr' || id.via === 'isp') && id.confidence === 'low');
  return (rows || [])
    .filter((r) => r && !r.private && r.cls !== 'yours' && !checked.has(r.ip) && weak(identOf(r)))
    .sort((a, b) => b.messages - a.messages || String(a.ip).localeCompare(String(b.ip)))
    .slice(0, Math.max(0, max));
}

/* ------------------------------------------------------------------------ */
/* Grouping                                                                 */
/* ------------------------------------------------------------------------ */

const CONF_RANK = Object.freeze({ high: 0, medium: 1, low: 2 });

/**
 * The key a source is grouped under: its service id, `isp` for every ISP or home network, the
 * network's holder, the map's name, or `unnamed`.
 * @param {SenderIdentification|null} ident
 * @returns {string}
 */
export function groupKey(ident) {
  if (!ident) return 'unnamed';
  if (ident.id) return `svc:${ident.id}`;
  if (ident.via === 'isp') return 'isp';
  return `${ident.via === 'asn' ? 'net' : 'name'}:${String(ident.service).toLowerCase()}`;
}

/**
 * @typedef {object} ServiceGroup
 * @property {string} key {@link groupKey}
 * @property {string|null} id a {@link SENDER_SERVICES} id
 * @property {string|null} service the name (null for `isp` and `unnamed`: the view words them)
 * @property {string|null} type
 * @property {string|null} guide
 * @property {string[]} vias the evidence that named its sources, in {@link SENDER_VIAS} order
 * @property {string|null} confidence the best of its sources
 * @property {string[]} evidence the evidence domains (an ISP group: the ISPs' base domains), first seen first
 * @property {object[]} rows its sources, most messages first
 * @property {number} addresses
 * @property {number} messages
 * @property {number} pass
 * @property {number} fail
 * @property {number} spfAligned
 * @property {number} dkimAligned
 * @property {Record<string, number>} classes sources per class (lib/dmarcreport.js SOURCE_CLASSES)
 */

/**
 * The sources folded per service, with totals. Groups with the most messages first, the
 * unnamed group last.
 * @param {object[]} rows lib/dmarcreport.js classifySources rows
 * @param {(row: object) => SenderIdentification|null} identOf
 * @returns {{ groups: ServiceGroup[], totals: { services: number, addresses: number, messages: number, unnamedAddresses: number, unnamedMessages: number } }}
 */
export function groupSources(rows, identOf) {
  const byKey = new Map();
  for (const r of rows || []) {
    const ident = identOf(r);
    const key = groupKey(ident);
    let g = byKey.get(key);
    if (!g) {
      g = {
        key,
        id: ident ? ident.id : null,
        service: ident && key !== 'isp' ? ident.service : null,
        type: ident ? ident.type : null,
        guide: ident ? ident.guide : null,
        vias: [],
        confidence: null,
        evidence: [],
        rows: [],
        addresses: 0,
        messages: 0,
        pass: 0,
        fail: 0,
        spfAligned: 0,
        dkimAligned: 0,
        classes: {}
      };
      byKey.set(key, g);
    }
    g.rows.push(r);
    g.addresses += 1;
    g.messages += r.messages || 0;
    g.pass += r.pass || 0;
    g.fail += r.fail || 0;
    g.spfAligned += r.spfAligned || 0;
    g.dkimAligned += r.dkimAligned || 0;
    if (r.cls) g.classes[r.cls] = (g.classes[r.cls] || 0) + 1;
    if (ident) {
      if (!g.vias.includes(ident.via)) g.vias.push(ident.via);
      if (!g.confidence || CONF_RANK[ident.confidence] < CONF_RANK[g.confidence]) g.confidence = ident.confidence;
      const ev = key === 'isp' ? ident.service : ident.domain;
      if (ev && !g.evidence.includes(ev)) g.evidence.push(ev);
    }
  }
  const groups = [...byKey.values()];
  for (const g of groups) {
    g.vias.sort((a, b) => SENDER_VIAS.indexOf(a) - SENDER_VIAS.indexOf(b));
    g.rows.sort((a, b) => b.messages - a.messages || String(a.ip).localeCompare(String(b.ip)));
  }
  groups.sort((a, b) => (a.key === 'unnamed') - (b.key === 'unnamed') || b.messages - a.messages
    || String(a.service ?? a.key).localeCompare(String(b.service ?? b.key)));
  const unnamed = byKey.get('unnamed');
  return {
    groups,
    totals: {
      services: groups.filter((g) => g.key !== 'unnamed').length,
      addresses: groups.reduce((n, g) => n + g.addresses, 0),
      messages: groups.reduce((n, g) => n + g.messages, 0),
      unnamedAddresses: unnamed ? unnamed.addresses : 0,
      unnamedMessages: unnamed ? unnamed.messages : 0
    }
  };
}

/** The class whose guide a service group shows: the unknown senders first, then the third parties, then the forwarders. */
const GROUP_GUIDE_CLASSES = Object.freeze(['unknown', 'third-party', 'forwarder']);

/**
 * The guide of a service group ({@link groupSources}): {@link senderGuide} for the first class
 * among its sources of unknown senders, authorized third parties and forwarders; none when every
 * source is yours, and for the unnamed group (the view words it). A group whose sources carry no
 * class gets the identification's own.
 * @param {ServiceGroup|null} group
 * @returns {string|null}
 */
export function groupGuide(group) {
  if (!group || group.key === 'unnamed' || !group.guide) return null;
  const classes = group.classes || {};
  if (!Object.values(classes).some((n) => n > 0)) return group.guide;
  const cls = GROUP_GUIDE_CLASSES.find((c) => classes[c] > 0);
  return cls ? senderGuide({ guide: group.guide }, { cls }) : null;
}

/**
 * One CSV row per service group ({@link SERVICE_CSV_COLUMNS}); `service` is empty for the
 * unnamed group and the ISP group's names are its base domains (`evidence`).
 * @param {ServiceGroup[]} groups
 * @returns {object[]}
 */
export function serviceCsvRows(groups) {
  return (groups || []).map((g) => ({
    service: g.key === 'isp' ? 'isp' : g.service || '',
    type: g.type || '',
    via: g.vias.join(' '),
    confidence: g.confidence || '',
    addresses: g.addresses,
    messages: g.messages,
    dmarc_pass: g.pass,
    dmarc_fail: g.fail,
    spf_aligned_pass: g.spfAligned,
    dkim_aligned_pass: g.dkimAligned,
    classes: Object.entries(g.classes).map(([c, n]) => `${c}=${n}`).join(' '),
    evidence: g.evidence.join(' '),
    sources: g.rows.map((r) => r.ip).join(' ')
  }));
}

/* ------------------------------------------------------------------------ */
/* The bundled lists (tools/build-senders.mjs → assets/data/senders/)        */
/* ------------------------------------------------------------------------ */

/** The lists' manifest; the other files sit next to it. */
const SENDERS_BASE = new URL('../../data/senders/manifest.json', import.meta.url);
/** Running in Node (file:// module, tests and tools) vs a browser (http(s):// module). */
const IS_NODE = SENDERS_BASE.protocol === 'file:';
/** A host name as the lists hold it: lowercase labels, at least two. */
const LIST_NAME_RE = /^(?=.{3,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/;
/** The types ptr-map.json may give (parsedmarc's mail-relevant types, as {@link PTR_TYPE_MAP} renames them). */
const MAP_TYPES = new Set(Object.values(PTR_TYPE_MAP));

/**
 * @typedef {object} SenderMaps
 * @property {Map<string, [string, string]>} ptr reverse-DNS base domain → [name, {@link SENDER_TYPES} type]
 * @property {Set<string>} isp the base domains of ISPs and home networks
 * @property {{ generated: string, commit: string|null, ptr: number, isp: number }} info
 */

/**
 * Check and read the three parsed files of assets/data/senders as tools/build-senders.mjs writes
 * them. A list of another format or shape is refused whole.
 * @param {{ manifest: object, ptrMap: object, isp: object }} data
 * @returns {SenderMaps}
 * @throws {TypeError} when a file is not what the builder writes
 */
export function installSenderMaps(data) {
  const { manifest, ptrMap, isp } = data || {};
  const fail = (msg) => { throw new TypeError(msg); };
  if (!manifest || manifest.format !== SENDERS_FORMAT) fail(`manifest: format ${manifest ? JSON.stringify(manifest.format) : 'missing'}, expected ${SENDERS_FORMAT}`);
  if (typeof manifest.generated !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(manifest.generated)) fail('manifest: no date');
  if (!ptrMap || ptrMap.format !== SENDERS_FORMAT || !ptrMap.map || typeof ptrMap.map !== 'object' || Array.isArray(ptrMap.map)) fail('ptr-map.json: not a map');
  if (!isp || isp.format !== SENDERS_FORMAT || !Array.isArray(isp.domains)) fail('isp.json: not a list');
  const ptr = new Map();
  for (const [key, value] of Object.entries(ptrMap.map)) {
    if (!LIST_NAME_RE.test(key)) fail(`ptr-map.json: ${JSON.stringify(key.slice(0, 60))} is not a host name`);
    if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'string' || !value[0].trim() || value[0].length > 200 || !MAP_TYPES.has(value[1])) {
      fail(`ptr-map.json: the entry of ${key} is not [name, type]`);
    }
    ptr.set(key, Object.freeze([value[0], value[1]]));
  }
  const ispSet = new Set();
  for (const d of isp.domains) {
    if (typeof d !== 'string' || !LIST_NAME_RE.test(d)) fail(`isp.json: ${JSON.stringify(String(d).slice(0, 60))} is not a host name`);
    ispSet.add(d);
  }
  const commit = manifest.source && typeof manifest.source.commit === 'string' ? manifest.source.commit : null;
  return { ptr, isp: ispSet, info: Object.freeze({ generated: manifest.generated, commit, ptr: ptr.size, isp: ispSet.size }) };
}

/** One list file: `fs` in Node (unless a fetch is injected), else fetched next to this module. */
async function readSendersFile(name, { fetchImpl, timeoutMs, signal }) {
  const url = new URL(name, SENDERS_BASE);
  if (IS_NODE && !fetchImpl) {
    const { readFile } = await import('node:fs/promises');
    try {
      return JSON.parse(await readFile(url, 'utf8'));
    } catch (err) {
      throw err instanceof SyntaxError ? new ParseError(`${name}: ${err.message}`) : err;
    }
  }
  return fetchJson(url.href, { fetchImpl: fetchImpl || globalThis.fetch, timeoutMs, signal, headers: { accept: 'application/json' } });
}

/** The lists once read, or the read in flight. */
let loaded = null;
let loading = null;

/**
 * Read the bundled lists (assets/data/senders, next to this module) once and check them
 * ({@link installSenderMaps}). Every caller shares one read; a failed read (the files missing, a
 * request that fails or times out, a list refused) rejects, and the next call tries again. Only
 * an abort of `signal` ends the wait early (with an AbortError; the read itself goes on).
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number }} [opts]
 *   fetchImpl: also in Node (tests), instead of reading the files with `fs`
 * @returns {Promise<SenderMaps>}
 */
export function loadSenderMaps({ fetchImpl, signal, timeoutMs = SENDERS_TIMEOUT_MS } = {}) {
  try {
    throwIfAborted(signal);
  } catch (err) {
    return Promise.reject(err);
  }
  if (loaded) return Promise.resolve(loaded);
  if (!loading) {
    const read = Promise.all(SENDERS_FILES.map((name) => readSendersFile(name, { fetchImpl, timeoutMs })))
      .then(([manifest, ptrMap, isp]) => {
        loaded = installSenderMaps({ manifest, ptrMap, isp });
        return loaded;
      });
    loading = read;
    read.catch(() => {
      if (loading === read) loading = null;
    });
  }
  if (!signal) return loading;
  const pending = loading;
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new AbortError('aborted', { cause: signal.reason }));
    signal.addEventListener('abort', onAbort, { once: true });
    pending.then((v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); });
  });
}

/** Forget the lists read (tests). */
export function resetSenderMaps() {
  loaded = null;
  loading = null;
}
