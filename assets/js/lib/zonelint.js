/**
 * zonelint.js — mistakes in an imported DNS zone (ROADMAP P1.2), found before they
 * bite: CNAME conflicts and loops, dangling in-zone targets, occluded data, private
 * and non-global addresses, duplicate RRs, SPF / DMARC / CAA / TTL problems and the
 * Cloudflare-specific ones — proxied origins published through a DNS-only sibling or
 * SPF, error-1000 setups, originless placeholders, Tunnels and SaaS targets.
 * DOM-free, synchronous and pure (no network, no storage). Runs in browsers and Node 22.
 *
 * Every finding is `{ code, severity, name, type, line, recordIds, params, detail }`:
 * its title and why / fix text (EN and TR) are {@link LINT_I18N} `zone.lint.<CODE>` and
 * `zone.lint.<CODE>.why` with `params`; `detail` is English log text the UI never parses.
 * Codes form the closed set {@link LINT_RULES}.
 *
 * Only unique records count (`duplicateOf` unset), except for DUPLICATE_RR. The zone
 * index (zoneorigins.js) is built once and shared with the origin map and drift, so
 * the exposure findings here and the origin map's `exposure` come from one source.
 *
 * Deviations from the zone spec §6.2, per its critic notes:
 *  - ORIGIN_EXPOSED_BY_MX is folded into ORIGIN_EXPOSED_BY_SIBLING (`params.role: 'mx'`),
 *    and a DNS-only CNAME to a proxied host origin is a sibling exposure too (B6);
 *  - MX_TARGET_PROXIED (error) and SRV_TARGET_PROXIED (warn, only off Cloudflare's
 *    proxied HTTP(S) ports) are new: the proxy carries HTTP / HTTPS only (B6);
 *  - "under a wildcard" is RFC 4592 synthesis (`wildcardCovers`), not certificate
 *    matching (B1).
 */

import { normalizeIP, ipInCidr } from './netinfo.js';
import { parseSpf, parseDmarc } from './health.js';
import { txtBytes } from './zonetext.js';
import {
  zoneIndex, proxiedCore, exposureFacts, effectiveTargets, servedTargets, wildcardCovers,
  classifyExternalTarget, isCloudflareIp, isPlaceholder, isSpfRecord, addressOf, isPrivateAddress
} from './zoneorigins.js';

/* ------------------------------------------------------------------------ */
/* Vocabulary                                                               */
/* ------------------------------------------------------------------------ */

/** Severity order used to sort findings. */
export const SEVERITY_ORDER = Object.freeze(['error', 'warn', 'info']);

const rule = (severity, scopes, extra = {}) => Object.freeze({ severity, scopes: Object.freeze(scopes), ...extra });

/**
 * The closed set of lint codes. `severity` is the default; `severityCf` applies to a
 * Cloudflare zone (a CF export / API dump, or any proxy flag); `severityByFormat`
 * overrides by `zone.format`. `scopes` names the sources a rule is about
 * (`all` | `bind` | `cloudflare` | `route53` | `octodns`).
 */
export const LINT_RULES = Object.freeze({
  CNAME_AND_OTHER_DATA: rule('error', ['all']),
  CNAME_AT_APEX: rule('error', ['all'], { severityCf: 'info' }),
  MULTIPLE_CNAME: rule('error', ['all']),
  CNAME_LOOP: rule('error', ['all']),
  CNAME_CHAIN_LONG: rule('warn', ['all']),
  MX_TO_CNAME: rule('error', ['all']),
  NS_TO_CNAME: rule('error', ['all']),
  SRV_TO_CNAME: rule('error', ['all']),
  TARGET_IS_IP: rule('error', ['all']),
  DANGLING_IN_ZONE_TARGET: rule('warn', ['all']),
  DUPLICATE_RR: rule('warn', ['all']),
  OCCLUDED_BY_DELEGATION: rule('warn', ['all']),
  OCCLUDED_BY_DNAME: rule('warn', ['all']),
  PRIVATE_IP: rule('warn', ['all']),
  LOCALHOST_RECORD: rule('warn', ['all']),
  NON_GLOBAL_IPV6: rule('warn', ['all']),
  MIXED_PROXY_FLAGS: rule('warn', ['cloudflare']),
  ORIGIN_EXPOSED_BY_SIBLING: rule('error', ['cloudflare']),
  ORIGIN_EXPOSED_BY_SPF: rule('warn', ['cloudflare']),
  PROXIED_PRIVATE_ORIGIN: rule('error', ['cloudflare']),
  PROXIED_TO_CLOUDFLARE_IP: rule('error', ['cloudflare']),
  ORIGINLESS_PLACEHOLDER: rule('info', ['cloudflare']),
  PROXIED_TUNNEL: rule('info', ['cloudflare']),
  PROXIED_PROVIDER: rule('info', ['cloudflare']),
  MX_TARGET_PROXIED: rule('error', ['cloudflare']),
  SRV_TARGET_PROXIED: rule('warn', ['cloudflare']),
  MULTIPLE_SPF: rule('error', ['all']),
  SPF_INVALID: rule('warn', ['all']),
  SPF_RR_TYPE: rule('warn', ['all']),
  DMARC_INVALID: rule('warn', ['all']),
  TXT_STRING_TOO_LONG: rule('error', ['all'], {
    severityByFormat: Object.freeze({ 'cloudflare-api': 'info', octodns: 'info', 'plesk-info': 'info' })
  }),
  CAA_UNKNOWN_TAG: rule('warn', ['all']),
  CAA_CRITICAL_UNKNOWN_TAG: rule('error', ['all']),
  CAA_FLAGS: rule('warn', ['all']),
  TTL_OUTLIER: rule('info', ['all']),
  TTL_TOO_LOW: rule('info', ['all']),
  SOA_NEGATIVE_TTL: rule('warn', ['all']),
  SINGLE_NS: rule('warn', ['all']),
  ALIAS_TARGET_MISSING: rule('warn', ['route53'])
});

/** CAA property tags a CA may act on (RFC 8659, 8657, 9495). */
export const CAA_KNOWN_TAGS = Object.freeze(['issue', 'issuewild', 'iodef', 'contactemail', 'contactphone', 'issuemail', 'issuevmc']);
/** Ports Cloudflare's proxy serves HTTP / HTTPS on (anything else needs Spectrum). */
export const CF_PROXY_PORTS = Object.freeze([80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]);
/** A chain of more than this many in-zone CNAME hops is CNAME_CHAIN_LONG. */
export const LONG_CHAIN_HOPS = 8;
/** TTL_TOO_LOW below this, TTL_OUTLIER above this or at ≥ 20× the zone median. */
export const TTL_LOW = 30;
export const TTL_HIGH = 172800;
export const TTL_OUTLIER_FACTOR = 20;
/** SOA_NEGATIVE_TTL above this SOA minimum (RFC 2308 suggests 1–3 hours). */
export const SOA_NEGATIVE_TTL_MAX = 86400;

const ADDRESS_TYPES = new Set(['A', 'AAAA']);
const CNAME_COMPANIONS = new Set(['CNAME', 'RRSIG', 'NSEC', 'NSEC3']);
const TARGET_RULE_TYPES = new Set(['CNAME', 'MX', 'SRV', 'NS']);
const CAA_TAGS = new Set(CAA_KNOWN_TAGS);
const PROXY_PORTS = new Set(CF_PROXY_PORTS);
const DOTTED_QUAD = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const SEVERITY_RANK = new Map(SEVERITY_ORDER.map((s, i) => [s, i]));

/**
 * @typedef {object} LintFinding
 * @property {string} code one of {@link LINT_RULES}
 * @property {'error'|'warn'|'info'} severity
 * @property {string} name the name the finding is about (the SPF owner for ORIGIN_EXPOSED_BY_SPF)
 * @property {string} type RR type of the anchoring record ('' for zone-wide findings)
 * @property {number} line 1-based source line of the anchoring record (0 = whole zone)
 * @property {number} source index into `zone.sources` of the anchoring record
 * @property {number[]} recordIds the records involved
 * @property {object} params values for the translated text (never English)
 * @property {string} detail English log text
 */

/** Lint text (`zone.lint.<CODE>` title, `.why`): EN [title, why], TR [title, why]. */
const LINT_TEXT = {
  CNAME_AND_OTHER_DATA: [['CNAME next to other records', '{name} has a CNAME and {types}. A CNAME must be alone at its name; resolvers answer unpredictably and BIND refuses the zone. Keep either the CNAME or the other records.'],
    ['CNAME başka kayıtlarla birlikte', '{name} adında hem CNAME hem {types} var. CNAME kendi adında tek başına olmalı; çözümleyiciler tutarsız yanıt verir, BIND zone’u yüklemez. Ya CNAME’i ya da diğer kayıtları tutun.']],
  CNAME_AT_APEX: [['CNAME at the zone apex', '{name} is a CNAME to {target}. Outside Cloudflare (which flattens it) a CNAME cannot sit next to the SOA and NS records.'],
    ['Zone kökünde CNAME', '{name}, {target} adresine CNAME. Cloudflare dışında (orada düzleştirilir) CNAME, SOA ve NS kayıtlarının yanında duramaz.']],
  MULTIPLE_CNAME: [['Several CNAMEs at one name', '{name} has {count} CNAME records; only one is allowed.'], ['Bir adda birden fazla CNAME', '{name} adında {count} CNAME kaydı var; yalnızca bir tane olabilir.']],
  CNAME_LOOP: [['CNAME loop', '{name} never resolves: {chain}.'], ['CNAME döngüsü', '{name} hiç çözümlenmez: {chain}.']],
  CNAME_CHAIN_LONG: [['Long CNAME chain', '{name} goes through {hops} CNAME hops inside the zone; resolvers may give up.'], ['Uzun CNAME zinciri', '{name} zone içinde {hops} CNAME adımından geçiyor; çözümleyiciler vazgeçebilir.']],
  MX_TO_CNAME: [['MX points to a CNAME', 'The mail host of {name} is a CNAME. RFC 2181 requires an MX target with its own address; some mail servers refuse to deliver.'], ['MX bir CNAME’e işaret ediyor', '{name} adının e-posta sunucusu bir CNAME. RFC 2181’e göre MX hedefinin kendi adresi olmalı; bazı e-posta sunucuları teslim etmeyi reddeder.']],
  NS_TO_CNAME: [['NS points to a CNAME', 'A name server of {name} is a CNAME, which RFC 2181 forbids.'], ['NS bir CNAME’e işaret ediyor', '{name} adının bir ad sunucusu CNAME; RFC 2181 bunu yasaklar.']],
  SRV_TO_CNAME: [['SRV points to a CNAME', 'The SRV target of {name} is a CNAME, which RFC 2782 forbids.'], ['SRV bir CNAME’e işaret ediyor', '{name} adının SRV hedefi bir CNAME; RFC 2782 bunu yasaklar.']],
  TARGET_IS_IP: [['Target is an IP address', 'The target of {name} is {target}, an IP address; this record type needs a host name.'], ['Hedef bir IP adresi', '{name} kaydının hedefi {target}, bir IP adresi; bu kayıt türü host adı ister.']],
  DANGLING_IN_ZONE_TARGET: [['Target has no records', '{name} points to {target}, which has no records in this zone.'], ['Hedefin kaydı yok', '{name}, bu zone’da hiç kaydı olmayan {target} adresine işaret ediyor.']],
  DUPLICATE_RR: [['Duplicate record', 'The same {type} record of {name} is listed twice.'], ['Yinelenen kayıt', '{name} adının aynı {type} kaydı iki kez yazılmış.']],
  OCCLUDED_BY_DELEGATION: [['Record hidden below a delegation', '{name} is under {cut}, which is delegated to other name servers; this zone never serves it. Move it into the child zone or delete it.'], ['Yetki devrinin altında kalmış kayıt', '{name}, başka ad sunucularına devredilen {cut} altında; bu zone onu hiçbir zaman sunmaz. Kaydı alt zone’a taşıyın ya da silin.']],
  OCCLUDED_BY_DNAME: [['Record hidden below a DNAME', '{name} is below the DNAME at {dname}; this zone never serves it.'], ['DNAME altında kalmış kayıt', '{name}, {dname} adındaki DNAME’in altında; bu zone onu hiçbir zaman sunmaz.']],
  PRIVATE_IP: [['Private address in a public zone', '{name} points at {ip}. Public resolvers return it to anyone, which leaks internal addressing. Move internal names to an internal (split-horizon) zone.'], ['Herkese açık zone’da özel adres', '{name}, {ip} adresine işaret ediyor. Genel çözümleyiciler bunu herkese döndürür; iç adresleme sızar. İç adları dahili (split-horizon) bir zone’a taşıyın.']],
  LOCALHOST_RECORD: [['localhost in a public zone', '{name} points at {ip}. Hosting panels add it by default; it lets pages on other subdomains share cookies with a local process. Delete it.'], ['Herkese açık zone’da localhost', '{name}, {ip} adresine işaret ediyor. Barındırma panelleri bunu varsayılan olarak ekler; yerel bir süreçle çerez paylaşımına yol açar. Silin.']],
  NON_GLOBAL_IPV6: [['Non-global IPv6 address', '{name} points at {ip}, outside the global unicast range.'], ['Genel olmayan IPv6 adresi', '{name}, genel tekil yayın aralığı dışındaki {ip} adresine işaret ediyor.']],
  MIXED_PROXY_FLAGS: [['Proxied and DNS-only on one name', '{name} has both. Cloudflare then proxies every A/AAAA of this name, so the DNS-only flag has no effect.'], ['Aynı adda hem proxy’li hem yalnızca DNS', '{name} ikisine de sahip. Cloudflare bu durumda adın tüm A/AAAA kayıtlarını proxy’ler; yalnızca DNS ayarının etkisi olmaz.']],
  ORIGIN_EXPOSED_BY_SIBLING: [['Proxied origin published by a DNS-only name', '{name} is DNS-only and publishes the origin behind proxied {proxied}. Anyone can reach the server directly and bypass Cloudflare’s WAF and DDoS protection. Proxy it too, move it, or allow only Cloudflare’s ranges on the origin firewall.'],
    ['Proxy’li origin, yalnızca DNS olan bir adla yayımlanıyor', '{name} yalnızca DNS ve proxy’li {proxied} adlarının arkasındaki origin’i yayımlıyor. Herkes sunucuya doğrudan ulaşıp Cloudflare’in WAF ve DDoS korumasını atlayabilir. Onu da proxy’leyin, taşıyın ya da origin güvenlik duvarında yalnızca Cloudflare aralıklarına izin verin.']],
  ORIGIN_EXPOSED_BY_SPF: [['SPF reveals a proxied origin', 'The SPF record of {spfName} authorises {ips}, the origin of proxied {proxied}: mail and web share a server, and SPF is public.'], ['SPF proxy’li bir origin’i ele veriyor', '{spfName} SPF kaydı, proxy’li {proxied} adlarının origin’i olan {ips} adresine izin veriyor: e-posta ve web aynı sunucuda ve SPF herkese açık.']],
  PROXIED_PRIVATE_ORIGIN: [['Proxied to a private address', '{name} is proxied to {ip}, which Cloudflare’s edge cannot reach.'], ['Özel bir adrese proxy’lenmiş', '{name}, Cloudflare’in erişemediği {ip} adresine proxy’lenmiş.']],
  PROXIED_TO_CLOUDFLARE_IP: [['Proxied record points at Cloudflare', 'Cloudflare answers {name} ({ip}) with error 1000 “DNS points to prohibited IP”. Point it at your origin server.'], ['Proxy’li kayıt Cloudflare’e işaret ediyor', 'Cloudflare, {name} ({ip}) için 1000 “DNS points to prohibited IP” hatası verir. Kaydı origin sunucunuza yönlendirin.']],
  ORIGINLESS_PLACEHOLDER: [['Placeholder record', '{name} points at {ip}: a Worker or a redirect rule answers it; there is no server behind it.'], ['Yer tutucu kayıt', '{name}, {ip} adresine işaret ediyor: onu bir Worker ya da yönlendirme kuralı yanıtlar; arkasında sunucu yok.']],
  PROXIED_TUNNEL: [['Origin is a Cloudflare Tunnel', '{name} goes through a Tunnel; there is no inbound origin to sweep.'], ['Origin bir Cloudflare Tunnel', '{name} bir Tunnel üzerinden gidiyor; taranacak dışarıdan erişilen origin yok.']],
  PROXIED_PROVIDER: [['Origin is a third party', '{name} points at {provider} ({target}); its certificate is managed there.'], ['Origin üçüncü taraf', '{name}, {provider} ({target}) üzerine işaret ediyor; sertifikası orada yönetilir.']],
  MX_TARGET_PROXIED: [['Mail host is proxied', 'The mail host {target} of {name} is proxied, but Cloudflare’s proxy carries HTTP(S) only: mail to it fails.'], ['E-posta sunucusu proxy’li', '{name} adının e-posta sunucusu {target} proxy’li, ama Cloudflare proxy’si yalnızca HTTP(S) taşır: ona giden e-posta başarısız olur.']],
  SRV_TARGET_PROXIED: [['SRV target is proxied', 'The SRV target {target} of {name} is proxied on port {port}, which Cloudflare’s proxy does not carry.'], ['SRV hedefi proxy’li', '{name} adının SRV hedefi {target}, Cloudflare proxy’sinin taşımadığı {port} portunda proxy’li.']],
  MULTIPLE_SPF: [['More than one SPF record', '{name} has {count} “v=spf1” records. Receivers treat this as a permanent error and SPF fails for all mail. Merge them into one record.'], ['Birden fazla SPF kaydı', '{name} adında {count} adet “v=spf1” kaydı var. Alıcılar bunu kalıcı hata sayar ve tüm e-postalarda SPF başarısız olur. Hepsini tek kayıtta birleştirin.']],
  SPF_INVALID: [['Invalid SPF record', 'The SPF record of {name} has an error ({error}).'], ['Geçersiz SPF kaydı', '{name} SPF kaydında hata var ({error}).']],
  SPF_RR_TYPE: [['Obsolete SPF record type', '{name} uses record type SPF (99); publish the policy as TXT only.'], ['Eskimiş SPF kayıt türü', '{name} SPF (99) kayıt türünü kullanıyor; politikayı yalnızca TXT olarak yayımlayın.']],
  DMARC_INVALID: [['Invalid DMARC record', 'The DMARC record of {name} has an error ({error}).'], ['Geçersiz DMARC kaydı', '{name} DMARC kaydında hata var ({error}).']],
  TXT_STRING_TOO_LONG: [['TXT string too long', 'One string of {name} is {bytes} bytes; the maximum is 255. Split it into several quoted strings.'], ['TXT dizesi çok uzun', '{name} adının bir dizesi {bytes} bayt; en fazla 255 olabilir. Birkaç tırnaklı dizeye bölün.']],
  CAA_UNKNOWN_TAG: [['Unknown CAA tag', 'The CAA record of {name} uses the tag “{tag}”, which CAs ignore.'], ['Bilinmeyen CAA etiketi', '{name} CAA kaydı, CA’ların yok saydığı “{tag}” etiketini kullanıyor.']],
  CAA_CRITICAL_UNKNOWN_TAG: [['Unknown critical CAA tag', 'The CAA record of {name} marks the tag “{tag}” critical (flags {flags}): every CA must refuse to issue for {name} and its subdomains without their own CAA. Correct the tag, or set the flags to 0.'], ['Bilinmeyen kritik CAA etiketi', '{name} CAA kaydı “{tag}” etiketini kritik olarak işaretliyor (işaretler {flags}): tüm CA’lar {name} ve kendi CAA kaydı olmayan alt alan adları için sertifika vermeyi reddetmek zorundadır. Etiketi düzeltin ya da işaretleri 0 yapın.']],
  CAA_FLAGS: [['Unusual CAA flags', 'The CAA record of {name} has flags {flags}; a critical flag on an unknown tag blocks every CA.'], ['Olağan dışı CAA işaretleri', '{name} CAA kaydının işaretleri {flags}; bilinmeyen bir etikette kritik işaret tüm CA’ları engeller.']],
  TTL_OUTLIER: [['Unusually long TTL', '{name} has a TTL of {ttl} s, while {median} s is typical in this zone: a change takes that long to reach everyone.'], ['Alışılmadık uzun TTL', '{name} için TTL {ttl} sn; bu zone’da tipik olan {median} sn: bir değişikliğin herkese ulaşması bu kadar sürer.']],
  TTL_TOO_LOW: [['Very short TTL', '{name} has a TTL of {ttl} s; resolvers query it constantly and some raise it anyway.'], ['Çok kısa TTL', '{name} için TTL {ttl} sn; çözümleyiciler onu sürekli sorgular, bazıları yine de yükseltir.']],
  SOA_NEGATIVE_TTL: [['Long negative-caching TTL', 'The SOA minimum of {name} is {minimum} s: a newly added name may stay “missing” that long.'], ['Uzun negatif önbellek TTL’i', '{name} SOA minimumu {minimum} sn: yeni eklenen bir ad bu kadar süre “yok” görünebilir.']],
  SINGLE_NS: [['Only one name server', '{name} lists a single name server; if it fails the whole zone is unreachable.'], ['Yalnızca bir ad sunucusu', '{name} tek bir ad sunucusu listeliyor; o çökerse tüm zone erişilemez olur.']],
  ALIAS_TARGET_MISSING: [['Alias target not in the file', 'The alias of {name} points to {target} in this zone, which has no such record.'], ['Alias hedefi dosyada yok', '{name} alias’ı bu zone’daki {target} adına işaret ediyor, ama böyle bir kayıt yok.']]
};

function buildLintStrings(lang) {
  const out = {};
  for (const [code, pair] of Object.entries(LINT_TEXT)) {
    const [title, why] = pair[lang];
    out[`zone.lint.${code}`] = title;
    out[`zone.lint.${code}.why`] = why;
  }
  return out;
}

/**
 * English and Turkish texts of every finding: `zone.lint.<CODE>` (the title) and
 * `zone.lint.<CODE>.why` (what it breaks and what to do), with the finding's `params` as
 * `{placeholders}`. The Zone File view and the DNS change request register them.
 * @type {{ en: Object<string, string>, tr: Object<string, string> }}
 */
export const LINT_I18N = Object.freeze({ en: Object.freeze(buildLintStrings(0)), tr: Object.freeze(buildLintStrings(1)) });

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function joinedText(r) {
  if (Array.isArray(r.data)) return r.data.map((s) => String(s ?? '')).join('');
  return typeof r.data === 'string' ? r.data : '';
}

const canonName = (v) => {
  const s = String(v ?? '').trim().toLowerCase();
  return s === '.' ? '' : s.replace(/\.$/, '');
};

/**
 * The answer a record is served in. Routing variants (a Route 53 / cli53 SetIdentifier, an
 * octoDNS geo code, each octoDNS dynamic value) are alternatives, never served together;
 * multivalue answers and plain records are one answer ('').
 */
function variantKey(r) {
  const rt = r.routing;
  if (!rt || rt.policy === 'multivalue') return '';
  if (rt.policy === 'dynamic') return `dynamic#${r.id}`;
  return `${rt.policy}|${rt.id ?? ''}`;
}

/** The records of `list` that are served together and clash, or null. */
function clashingGroup(list) {
  if (list.length < 2) return null;
  const groups = new Map();
  for (const r of list) {
    const k = variantKey(r);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  }
  if (groups.has('') && groups.size > 1) return list; // a plain record next to routed ones
  for (const g of groups.values()) if (g.length > 1) return g;
  return null;
}

/* ------------------------------------------------------------------------ */
/* Lint                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Lint a parsed zone.
 * @param {object} zone Zone (zoneparse shape; a fatal zone gives no findings)
 * @returns {{ findings: LintFinding[], occluded: Map<string, 'cut'|'dname'>, occludedIds: Set<number>,
 *   proxiedOrigins: Set<string> }} findings sorted by severity, then line; `occluded`:
 *   names whose every record is hidden by a delegation or a DNAME; `occludedIds`: every
 *   occluded record; `proxiedOrigins`: the real origin addresses of the proxied names
 */
export function lintZone(zone) {
  const idx = zoneIndex(zone);
  const core = proxiedCore(idx);
  const findings = [];
  const live = (r) => !idx.occludedRecords.has(r);
  const inZone = (t) => !!idx.origin && !!t && idx.inZone(t);

  const severityOf = (code) => {
    const def = LINT_RULES[code];
    if (def.severityByFormat && idx.format && def.severityByFormat[idx.format]) return def.severityByFormat[idx.format];
    if (def.severityCf && idx.cloudflare) return def.severityCf;
    return def.severity;
  };
  const push = (code, anchor, params, detail, involved = anchor ? [anchor] : []) => {
    findings.push({
      code,
      severity: severityOf(code),
      name: typeof params.name === 'string' ? params.name : typeof params.spfName === 'string' ? params.spfName : anchor ? anchor.name : '',
      type: anchor ? anchor.type : '',
      line: anchor && Number.isInteger(anchor.line) ? anchor.line : 0,
      source: anchor && Number.isInteger(anchor.source) ? anchor.source : 0,
      recordIds: [...new Set(involved.map(idx.idOf))].sort((a, b) => a - b),
      params,
      detail
    });
  };

  // ---- per name ----------------------------------------------------------
  for (const [name, recs] of idx.byName) {
    const cnames = recs.filter((r) => r.type === 'CNAME');
    if (cnames.length) {
      // Cloudflare flattens an apex CNAME into the A / AAAA it serves: only those clash with it there.
      const flattened = idx.cloudflare && name === idx.origin;
      const others = [...new Set(recs.filter((r) => !CNAME_COMPANIONS.has(r.type) && (!flattened || ADDRESS_TYPES.has(r.type)))
        .map((r) => r.type))].sort();
      if (others.length) {
        push('CNAME_AND_OTHER_DATA', cnames[0], { name, types: others }, `CNAME next to ${others.join(', ')}`, recs);
      }
      if (name === idx.origin) {
        const target = effectiveTargets(cnames[0])[0] ?? '';
        push('CNAME_AT_APEX', cnames[0], { name, target },
          idx.cloudflare ? 'apex CNAME (Cloudflare flattens it)' : 'a CNAME cannot sit at the zone apex next to SOA / NS');
      }
      const clash = clashingGroup(cnames);
      if (clash) push('MULTIPLE_CNAME', clash[1], { name, count: clash.length }, `${clash.length} CNAMEs at one name`, clash);
    }
    const spf = clashingGroup(recs.filter((r) => r.type === 'TXT' && isSpfRecord(r)));
    if (spf) push('MULTIPLE_SPF', spf[1], { name, count: spf.length }, `${spf.length} SPF records: RFC 7208 permerror`, spf);
    const spfType = recs.find((r) => r.type === 'SPF');
    if (spfType) push('SPF_RR_TYPE', spfType, { name }, 'RR type SPF (99) is obsolete; publish TXT only');
    const addrs = recs.filter((r) => ADDRESS_TYPES.has(r.type) && live(r));
    if (addrs.some((r) => r.proxied === true) && addrs.some((r) => r.proxied === false)) {
      push('MIXED_PROXY_FLAGS', addrs.find((r) => r.proxied === false), { name },
        'one proxied A/AAAA makes Cloudflare proxy every A/AAAA of the name', addrs);
    }
  }

  // ---- per record --------------------------------------------------------
  const localhost = idx.origin ? `localhost.${idx.origin}` : null;
  for (const r of idx.unique) {
    if (!live(r)) continue;
    const ip = addressOf(r);
    if (ip) {
      const proxiedName = core.proxiedAddressNames.has(r.name);
      if (r.name === localhost) {
        push('LOCALHOST_RECORD', r, { name: r.name, ip }, 'localhost.<zone> in public DNS');
      } else if (proxiedName) {
        if (isPlaceholder(ip)) push('ORIGINLESS_PLACEHOLDER', r, { name: r.name, ip }, 'originless placeholder: a Worker or redirect, no server');
        else if (isCloudflareIp(ip)) push('PROXIED_TO_CLOUDFLARE_IP', r, { name: r.name, ip }, 'proxied to a Cloudflare address: error 1000');
        else if (isPrivateAddress(ip)) push('PROXIED_PRIVATE_ORIGIN', r, { name: r.name, ip }, 'proxied to a private address the edge cannot reach');
      } else if (isPrivateAddress(ip)) {
        push('PRIVATE_IP', r, { name: r.name, ip }, 'private address published in DNS');
      } else if (r.type === 'AAAA' && !ipInCidr(ip, '2000::/3')) {
        push('NON_GLOBAL_IPV6', r, { name: r.name, ip }, 'AAAA outside 2000::/3');
      }
    }

    if (TARGET_RULE_TYPES.has(r.type)) {
      const served = servedTargets(r);
      const eff = effectiveTargets(r);
      for (let i = 0; i < served.length; i += 1) {
        const s = served[i];
        if (!s) continue;
        if (DOTTED_QUAD.test(s) && normalizeIP(s)) {
          push('TARGET_IS_IP', r, { name: r.name, target: s }, `${r.type} target is an IP literal`);
          continue;
        }
        const t = eff[i];
        if (!inZone(t)) continue;
        if (r.type !== 'CNAME' && (idx.byName.get(t) || []).some((x) => x.type === 'CNAME' && live(x))) {
          push(`${r.type}_TO_CNAME`, r, { name: r.name, target: t }, `${r.type} target is a CNAME (RFC 2181 §10.3)`);
        }
        if (!idx.partial && !idx.owners.has(t) && !wildcardCovers(idx, t) && !idx.cutAtOrAbove(t)) {
          push('DANGLING_IN_ZONE_TARGET', r, { name: r.name, target: t }, `in-zone ${r.type} target has no records`);
        }
      }
    }

    if (idx.cloudflare && r.type === 'CNAME' && r.proxied === true) {
      const t = effectiveTargets(r)[0] ?? '';
      if (t && !inZone(t)) {
        const ext = classifyExternalTarget(t);
        if (ext.kind === 'tunnel') push('PROXIED_TUNNEL', r, { name: r.name, target: t }, 'origin is a Cloudflare Tunnel');
        else if (ext.kind === 'provider') {
          push('PROXIED_PROVIDER', r, { name: r.name, target: t, provider: ext.provider }, `origin is a third party (${ext.provider})`);
        }
      }
    }
    if (idx.cloudflare && (r.type === 'MX' || r.type === 'SRV')) {
      const t = effectiveTargets(r)[0] ?? '';
      if (t && core.rows.has(t)) {
        if (r.type === 'MX') {
          push('MX_TARGET_PROXIED', r, { name: r.name, target: t }, 'mail exchange is proxied: the proxy carries HTTP(S) only');
        } else {
          const port = r.data && Number.isInteger(r.data.port) ? r.data.port : null;
          if (!PROXY_PORTS.has(port)) push('SRV_TARGET_PROXIED', r, { name: r.name, target: t, port }, 'SRV target is proxied on a non-HTTP port');
        }
      }
    }

    if (r.type === 'TXT' || r.type === 'SPF') {
      // The bytes the zone holds (its text): `data` decodes each string on its own, so a character
      // split across two strings, or a byte that is not UTF-8, would count twice.
      let bytes = 0;
      if (Array.isArray(r.data)) for (const s of txtBytes(r)) bytes = Math.max(bytes, s.length);
      if (bytes > 255) push('TXT_STRING_TOO_LONG', r, { name: r.name, bytes }, `one character-string is ${bytes} bytes (max 255)`);
      if (isSpfRecord(r)) {
        const spf = parseSpf(joinedText(r));
        if (spf.errors.length) {
          push('SPF_INVALID', r, { name: r.name, error: spf.errors[0].code, token: spf.errors[0].token }, `SPF: ${spf.errors[0].code}`);
        }
      }
      if (r.type === 'TXT' && r.name.startsWith('_dmarc.') && /^v\s*=\s*dmarc1/i.test(joinedText(r).trim())) {
        const dmarc = parseDmarc(joinedText(r));
        if (dmarc.errors.length) push('DMARC_INVALID', r, { name: r.name, error: dmarc.errors[0].code }, `DMARC: ${dmarc.errors[0].code}`);
      }
    }

    if (r.type === 'CAA' && r.data && typeof r.data.tag === 'string') {
      const tag = r.data.tag.toLowerCase();
      const flags = Number(r.data.flags);
      // RFC 8659 §4.1: a CA must not issue where a critical property has a tag it does not know.
      if (!CAA_TAGS.has(tag) && flags & 128) push('CAA_CRITICAL_UNKNOWN_TAG', r, { name: r.name, tag, flags }, `critical unknown CAA tag "${tag}": no CA may issue`);
      else if (!CAA_TAGS.has(tag)) push('CAA_UNKNOWN_TAG', r, { name: r.name, tag }, `unknown CAA tag "${tag}"`);
      if (flags !== 0 && flags !== 128) push('CAA_FLAGS', r, { name: r.name, flags }, `CAA flags ${flags}`);
    }

    if (r.type === 'SOA' && r.data && Number(r.data.minimum) > SOA_NEGATIVE_TTL_MAX) {
      push('SOA_NEGATIVE_TTL', r, { name: r.name, minimum: Number(r.data.minimum) }, 'negative-cache TTL over one day');
    }

    if (r.alias && r.alias.provider === 'same-zone' && !idx.partial) {
      const t = canonName(r.alias.target);
      if (inZone(t) && !idx.owners.has(t) && !wildcardCovers(idx, t)) {
        push('ALIAS_TARGET_MISSING', r, { name: r.name, target: t }, 'same-zone alias target is not in the file');
      }
    }
  }

  // ---- duplicates (the only rule that looks at repeated RRs) --------------
  const byId = new Map(idx.records.map((r) => [idx.idOf(r), r]));
  for (const r of idx.records) {
    if (r.duplicateOf === undefined || r.duplicateOf === null) continue;
    const first = byId.get(r.duplicateOf);
    push('DUPLICATE_RR', r, { name: r.name, type: r.type }, 'identical record listed twice', first ? [r, first] : [r]);
  }

  // ---- occlusion, one finding per (name, type) ----------------------------
  const occGroups = new Map();
  for (const [r, occ] of idx.occludedRecords) {
    const key = `${r.name}\u0000${r.type}`;
    const g = occGroups.get(key);
    if (g) g.recs.push(r);
    else occGroups.set(key, { occ, recs: [r] });
  }
  for (const { occ, recs } of occGroups.values()) {
    const r = recs[0];
    if (occ.kind === 'dname') push('OCCLUDED_BY_DNAME', r, { name: r.name, dname: occ.by }, `below the DNAME at ${occ.by}`, recs);
    else push('OCCLUDED_BY_DELEGATION', r, { name: r.name, cut: occ.by }, `hidden by the delegation ${occ.by ?? ''}`.trim(), recs);
  }

  // ---- CNAME graph: loops and long chains ---------------------------------
  cnameGraphRules(idx, live, inZone, push);

  // ---- TTLs ---------------------------------------------------------------
  const eligible = idx.unique.filter((r) => live(r) && Number.isFinite(r.ttl) && !r.ttlAuto && !r.alias && r.type !== 'SOA' && r.type !== 'NS');
  const ttls = eligible.map((r) => r.ttl).sort((a, b) => a - b);
  const median = ttls.length ? ttls[(ttls.length - 1) >> 1] : null;
  const seenTtl = new Set();
  for (const r of eligible) {
    const key = `${r.name}\u0000${r.type}\u0000${r.ttl}`;
    if (seenTtl.has(key)) continue;
    seenTtl.add(key);
    if (r.ttl < TTL_LOW) push('TTL_TOO_LOW', r, { name: r.name, ttl: r.ttl, median }, `TTL ${r.ttl}s`);
    else if (r.ttl > TTL_HIGH || (median > 0 && r.ttl >= TTL_OUTLIER_FACTOR * median)) {
      push('TTL_OUTLIER', r, { name: r.name, ttl: r.ttl, median }, `TTL ${r.ttl}s vs median ${median}s`);
    }
  }

  // ---- apex NS --------------------------------------------------------------
  if (idx.origin) {
    const ns = (idx.byName.get(idx.origin) || []).filter((r) => r.type === 'NS');
    if (ns.length === 1) push('SINGLE_NS', ns[0], { name: idx.origin }, 'only one name server');
  }

  // ---- origin exposure ------------------------------------------------------
  for (const f of exposureFacts(idx)) {
    if (f.by === 'spf') {
      push('ORIGIN_EXPOSED_BY_SPF', f.record, { spfName: f.name, ips: f.ips, proxied: f.proxied },
        `SPF authorises the origin ${f.ips.join(', ')} of proxied names`);
    } else {
      const role = f.by === 'mx' ? 'mx' : 'record';
      const params = f.ip ? { name: f.name, ip: f.ip, proxied: f.proxied, role } : { name: f.name, host: f.host, proxied: f.proxied, role };
      push('ORIGIN_EXPOSED_BY_SIBLING', f.record, params, `DNS-only ${f.name} publishes the origin ${f.ip || f.host}`);
    }
  }

  findings.sort((a, b) => (SEVERITY_RANK.get(a.severity) - SEVERITY_RANK.get(b.severity))
    || (a.source - b.source) || (a.line - b.line) || (a.code < b.code ? -1 : a.code > b.code ? 1 : 0)
    || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));

  const occludedIds = new Set([...idx.occludedRecords.keys()].map(idx.idOf));
  return { findings, occluded: new Map(idx.occludedNames), occludedIds, proxiedOrigins: new Set(core.originIps.keys()) };
}

/** CNAME_LOOP (once per cycle) and CNAME_CHAIN_LONG (at chain heads). */
function cnameGraphRules(idx, live, inZone, push) {
  const next = new Map();
  const recOf = new Map();
  const order = new Map();
  for (const r of idx.unique) {
    if (r.type !== 'CNAME' || !live(r) || next.has(r.name)) continue;
    const t = effectiveTargets(r)[0] ?? '';
    if (!inZone(t)) continue;
    next.set(r.name, t);
    recOf.set(r.name, r);
    order.set(r.name, order.size);
  }
  const state = new Map();
  const inCycle = new Set();
  for (const start of next.keys()) {
    if (state.has(start)) continue;
    const path = [];
    const onPath = new Map();
    let cur = start;
    while (next.has(cur) && !state.has(cur)) {
      state.set(cur, 1);
      onPath.set(cur, path.length);
      path.push(cur);
      cur = next.get(cur);
    }
    if (onPath.has(cur)) {
      const cycle = path.slice(onPath.get(cur));
      for (const n of cycle) inCycle.add(n);
      let first = 0;
      for (let i = 1; i < cycle.length; i += 1) if (order.get(cycle[i]) < order.get(cycle[first])) first = i;
      const chain = [...cycle.slice(first), ...cycle.slice(0, first), cycle[first]];
      push('CNAME_LOOP', recOf.get(cycle[first]), { name: cycle[first], chain }, `CNAME loop ${chain.join(' > ')}`,
        cycle.map((n) => recOf.get(n)));
    }
    for (const n of path) state.set(n, 2);
  }
  // Depth (hops to a name without an in-zone CNAME); names leading into a loop have none.
  const depth = new Map();
  for (const start of next.keys()) {
    if (depth.has(start)) continue;
    const path = [];
    let cur = start;
    let base = 0;
    for (;;) {
      if (depth.has(cur)) { base = depth.get(cur); break; }
      if (inCycle.has(cur)) { base = null; break; }
      if (!next.has(cur)) { base = 0; break; }
      path.push(cur);
      cur = next.get(cur);
    }
    for (let i = path.length - 1; i >= 0; i -= 1) {
      base = base === null ? null : base + 1;
      depth.set(path[i], base);
    }
  }
  const targeted = new Set(next.values());
  for (const head of next.keys()) {
    const hops = depth.get(head);
    if (targeted.has(head) || hops === null || hops <= LONG_CHAIN_HOPS) continue;
    push('CNAME_CHAIN_LONG', recOf.get(head), { name: head, hops }, `${hops} in-zone CNAME hops`);
  }
}
