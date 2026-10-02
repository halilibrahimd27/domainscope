/**
 * Public DNS-over-HTTPS resolvers usable from a browser (CORS-enabled) and the
 * EDNS Client Subnet (ECS) "vantage points" used by the Global DNS view.
 *
 * Pure data + tiny helpers; DOM-free. Every entry below was verified live on
 * 2026-09-23 by tests/live/verify-resolvers.mjs:
 *  - resolvers: HTTP/2 GET ?dns= with an Origin header → 200 + Access-Control-Allow-Origin,
 *    DNSSEC validation (dnssec-failed.org → SERVFAIL, AD on signed names), filtering
 *    (malware test domain), NSID support, and whether ECS is echoed / honoured;
 *    plus a real headless-Chrome fetch from an http://127.0.0.1 origin.
 *  - browsers: tests/live/browser-doh-matrix.mjs fetched every resolver and vantage from a
 *    page in real Chrome 153 and Edge 153 (3 fresh profiles × 3 repeats each, GET / POST /
 *    JSON forms, protocol from Chrome's NetLog). Results for GET ?dns= (what doh.js sends):
 *    18/18 for every resolver except Quad9 and Quad9 ECS (HTTP/3 without CORS, see below),
 *    Control D (unreachable from the test network, see its entry) and one IIJ timeout; all
 *    31 ECS vantages 558/558 on Google with scope /24. POST needs a CORS preflight that
 *    Google, IIJ, CleanBrowsing, Tiarap and CZ.NIC fail, so GET is the only portable form.
 *  - vantages: each /24's country (and city) with RIPEstat maxmind-geo-lite, its
 *    origin ASN with RIPEstat prefix-overview, and Google DoH returning an ECS
 *    scope / geo-specific answers for it.
 * The mainland China vantages and AliDNS, which they are asked through (ECS_RESOLVERS), were
 * added and verified the same way on 2026-10-02 (AliDNS: its own answers per subnet, no scope).
 */

/** Date the lists below were last verified live. */
export const RESOLVERS_VERIFIED = '2026-09-23';

/**
 * @typedef {object} Resolver
 * @property {string} id
 * @property {string} name
 * @property {string} operator
 * @property {string} url RFC 8484 endpoint (GET ?dns=<base64url>, accept: application/dns-message)
 * @property {string} location e.g. 'Anycast', 'Japan'
 * @property {string|null} countryCode ISO 3166-1 alpha-2 for unicast resolvers, null for anycast
 * @property {boolean} ecs honours a client-supplied ECS option (answers differ per subnet)
 * @property {boolean} dnssecValidating
 * @property {null|'malware'|'security'|'family'} filtering
 * @property {string} homepage
 * @property {boolean} ecsEcho extension: echoes the ECS option (with scope prefix) in responses
 * @property {boolean} nsid extension: answers the NSID option (RFC 5001) with a PoP/instance id
 * @property {boolean} browserReliable extension: false when browsers often fail to read the answer
 * @property {null|'h3-no-cors'} issue extension: machine-readable reason when browserReliable is false
 */

/**
 * The 12 CORS-enabled DoH resolvers (spec §3), all re-verified live.
 *
 * Quad9 caveat (measured in real Chrome/Edge with tests/live/browser-doh-matrix.mjs):
 * Quad9's HTTP/3 front end answers with only content-type / content-length — no
 * Access-Control-Allow-Origin (its HTTP/2 answers carry `*`). Browsers use HTTP/3 for
 * Quad9 from the very first request, because the HTTPS DNS record of dns.quad9.net
 * (and dns9/10/11/12) advertises alpn=h3,h2, so the page gets a CORS error (Chrome
 * reports MissingAllowOriginHeader; GET 1/18 and 2/18 ok for quad9 / quad9-ecs). No
 * client-side workaround exists — fetch() cannot pin HTTP/2, and every alternative was
 * measured: IP-literal URLs (https://9.9.9.9/dns-query; the certificate has IP SANs)
 * skip the HTTPS record but switch to h3 via Alt-Svc after the first answer (fresh 3/3,
 * warm 0/6); the old port 5053 no longer answers (TCP timeout; 8443 is not DoH); the
 * JSON form and POST fail the same way over h3 (POST also fails its preflight). So the
 * entries are kept for the Global DNS view (which shows them as "not readable in
 * browsers", and they do answer on networks that block QUIC) and for Node, where they
 * work, but they are flagged `browserReliable: false, issue: 'h3-no-cors'` and left out
 * of DEFAULT_CHAIN and of the DohClient bulk balance pool.
 *
 * @type {ReadonlyArray<Resolver>}
 */
export const RESOLVERS = Object.freeze([
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    operator: 'Cloudflare, Inc.',
    url: 'https://cloudflare-dns.com/dns-query',
    location: 'Anycast',
    countryCode: null,
    ecs: false,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://one.one.one.one/',
    ecsEcho: false,
    nsid: true,
    browserReliable: true,
    issue: null
  },
  {
    id: 'cloudflare-family',
    name: 'Cloudflare Family',
    operator: 'Cloudflare, Inc.',
    url: 'https://family.cloudflare-dns.com/dns-query',
    location: 'Anycast',
    countryCode: null,
    ecs: false,
    dnssecValidating: true,
    filtering: 'family',
    homepage: 'https://one.one.one.one/family/',
    ecsEcho: false,
    nsid: true,
    browserReliable: true,
    issue: null
  },
  {
    id: 'google',
    name: 'Google Public DNS',
    operator: 'Google LLC',
    url: 'https://dns.google/dns-query',
    location: 'Anycast',
    countryCode: null,
    ecs: true,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://developers.google.com/speed/public-dns',
    ecsEcho: true,
    nsid: true,
    browserReliable: true,
    issue: null
  },
  {
    id: 'quad9',
    name: 'Quad9',
    operator: 'Quad9 Foundation',
    url: 'https://dns.quad9.net/dns-query',
    location: 'Anycast',
    countryCode: null,
    ecs: false,
    dnssecValidating: true,
    filtering: 'malware',
    homepage: 'https://quad9.net/',
    ecsEcho: false,
    nsid: true,
    browserReliable: false,
    issue: 'h3-no-cors'
  },
  {
    id: 'quad9-ecs',
    name: 'Quad9 (ECS)',
    operator: 'Quad9 Foundation',
    url: 'https://dns11.quad9.net/dns-query',
    location: 'Anycast',
    countryCode: null,
    ecs: true, // honours client ECS (answers change) but does not echo the option → no scope
    dnssecValidating: true,
    filtering: 'malware',
    homepage: 'https://quad9.net/service/service-addresses-and-features/',
    ecsEcho: false,
    nsid: true,
    browserReliable: false,
    issue: 'h3-no-cors'
  },
  {
    // Reachability caveat: on 2026-09-23 freedns.controld.com (76.76.2.11 / 76.76.10.11)
    // timed out on TCP 443, 853 and 53 from the test connection (one consumer ISP) for the whole
    // test (18/18 browser GETs: ERR_CONNECTION_TIMED_OUT), while other Control D addresses
    // (76.76.2.22) answered — a network-level block or outage, not a browser issue. It is
    // therefore not in DEFAULT_CHAIN nor the bulk balance pool, where every query sent to it
    // would wait for the full request timeout. (dns.controld.com/p0 answers but REFUSES every
    // query: it serves account profiles only.)
    id: 'controld',
    name: 'Control D (unfiltered)',
    operator: 'Control D',
    url: 'https://freedns.controld.com/p0',
    location: 'Anycast',
    countryCode: null,
    ecs: false, // echoes ECS with scope 0 but ignores it
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://controld.com/free-dns',
    ecsEcho: true,
    nsid: false,
    browserReliable: true,
    issue: null
  },
  {
    id: 'dnssb',
    name: 'DNS.SB',
    operator: 'xTom',
    url: 'https://doh.dns.sb/dns-query',
    location: 'Anycast',
    countryCode: null,
    ecs: false,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://dns.sb/',
    ecsEcho: false,
    nsid: true,
    browserReliable: true,
    issue: null
  },
  {
    id: 'iij',
    name: 'IIJ Public DNS',
    operator: 'Internet Initiative Japan',
    url: 'https://public.dns.iij.jp/dns-query',
    location: 'Japan',
    countryCode: 'JP',
    ecs: false,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://public.dns.iij.jp/',
    ecsEcho: false,
    nsid: true,
    browserReliable: true,
    issue: null
  },
  {
    id: 'cleanbrowsing',
    name: 'CleanBrowsing Security',
    operator: 'CleanBrowsing',
    url: 'https://doh.cleanbrowsing.org/doh/security-filter/',
    location: 'Anycast',
    countryCode: null,
    ecs: false,
    dnssecValidating: true,
    filtering: 'security',
    homepage: 'https://cleanbrowsing.org/filters/',
    ecsEcho: false,
    nsid: true,
    browserReliable: true,
    issue: null
  },
  {
    id: 'tiar',
    name: 'Tiarap',
    operator: 'Tiarap Inc.',
    url: 'https://doh.tiar.app/dns-query',
    location: 'Singapore',
    countryCode: 'SG',
    ecs: false,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://tiarap.org/',
    ecsEcho: false,
    nsid: false,
    browserReliable: true,
    issue: null
  },
  {
    id: 'seby',
    name: 'seby.io',
    operator: 'seby.io',
    url: 'https://doh.seby.io/dns-query',
    location: 'Australia',
    countryCode: 'AU',
    ecs: false,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://dns.seby.io/',
    ecsEcho: false,
    nsid: false,
    browserReliable: true,
    issue: null
  },
  {
    id: 'cznic',
    name: 'CZ.NIC ODVR',
    operator: 'CZ.NIC',
    url: 'https://odvr.nic.cz/doh',
    location: 'Czechia',
    countryCode: 'CZ',
    ecs: false,
    dnssecValidating: true,
    filtering: null,
    homepage: 'https://www.nic.cz/odvr/',
    ecsEcho: false,
    nsid: true,
    browserReliable: true,
    issue: null
  }
].map((r) => Object.freeze(r)));

/**
 * Resolvers asked only on behalf of a location (Global DNS ECS vantages whose `resolver` names
 * them), never in a failover chain, the bulk pool, a picker or the settings: they are not general
 * resolvers for this page.
 *
 * AliDNS (Alibaba Cloud), verified live on 2026-10-02 (docs/RESEARCH.md › Mainland China vantage):
 * its RFC 8484 endpoint (/dns-query) sends no Access-Control-Allow-Origin, so it is asked in the JSON
 * form, `/resolve?name=&type=&edns_client_subnet=` (`format: 'json'`, lib/dohjson.js), which sends `*`
 * — on 400 and 401 answers too (real Chrome: 16/16 reads from two fresh profiles over HTTP/2; an
 * earlier run read it over HTTP/3 after Alt-Svc as well). It applies the subnet it is given: the
 * three mainland ISP /24s below get edges inside their own ISP, and for names whose GeoDNS ignores
 * Google's ECS it answers what mainland users get (a mainland CDN where Google's ECS answer is an
 * overseas edge). It echoes the subnet without a scope prefix (`ecsEcho: false`), does not validate
 * DNSSEC (a broken signature still resolves), and ignores `do` / `cd`.
 * @type {ReadonlyArray<Resolver & { format: 'json' }>}
 */
export const ECS_RESOLVERS = Object.freeze([
  {
    id: 'alidns',
    name: 'AliDNS (ECS)',
    operator: 'Alibaba Cloud',
    url: 'https://dns.alidns.com/resolve',
    format: 'json',
    location: 'Anycast',
    countryCode: null,
    ecs: true,
    dnssecValidating: false,
    filtering: null,
    homepage: 'https://www.alidns.com/',
    ecsEcho: false,
    nsid: false,
    browserReliable: true,
    issue: null
  }
].map((r) => Object.freeze(r)));

/**
 * Failover order for general lookups (resolver ids): unfiltered, DNSSEC-validating
 * resolvers that real browsers read reliably (18/18 GETs in Chrome + Edge). Quad9 is not
 * here — browsers cannot read it (h3-no-cors) and, as a malware-filtering resolver, it
 * would report flagged customer names as NXDOMAIN in a scan.
 */
export const DEFAULT_CHAIN = Object.freeze(['cloudflare', 'google', 'dnssb', 'cznic']);

/**
 * Resolver used for geo (ECS) queries: Google is the only CORS-usable resolver that both
 * honours client-supplied ECS and echoes the scope prefix (verified live).
 */
export const DEFAULT_GEO_RESOLVER = 'google';

/**
 * @typedef {object} GeoVantage
 * @property {string} id stable id, e.g. 'tr-ist-tt'
 * @property {string} countryCode ISO 3166-1 alpha-2
 * @property {string|null} city
 * @property {string} nameTr display name (Turkish)
 * @property {string} nameEn display name (English)
 * @property {string} subnet IPv4 /24 of a large consumer ISP, used as the ECS source
 * @property {string} isp
 * @property {number} asn origin AS of the /24 (RIPEstat prefix-overview)
 * @property {string} verifiedCountry country reported by RIPEstat maxmind-geo-lite
 * @property {string|null} verifiedCity extension: city reported by maxmind-geo-lite (null: it reports none)
 * @property {'EU'|'AS'|'NA'|'SA'|'AF'|'OC'} continent extension, for grouping
 * @property {string} [resolver] extension: the resolver asked for this location (an {@link ECS_RESOLVERS} id);
 *   without one, {@link DEFAULT_GEO_RESOLVER}
 * @property {string} [group] extension: the row group the Global DNS view shows it in ('cn': mainland China)
 */

// Compact constructor; `verifiedCity` is MaxMind's city when it differs from the display city
// (e.g. a borough or suburb of the metro area named in `city`).
const v = (id, countryCode, continent, city, nameTr, nameEn, subnet, isp, asn, verifiedCity = city) => Object.freeze({
  id, countryCode, city, nameTr, nameEn, subnet, isp, asn, verifiedCountry: countryCode, verifiedCity, continent
});
// Mainland China, asked through AliDNS: MaxMind places these /24s in CN without a city, so the city
// is the one the ISP publishes for the DNS servers of that network (Beijing Unicom 202.106.0.20,
// Shanghai Telecom 202.96.209.133, Guangdong Mobile 211.136.192.6) and the origin AS names the
// province (AS4808 China Unicom Beijing, AS4812 China Telecom Shanghai, AS56040 China Mobile Guangdong).
const cn = (id, city, nameTr, nameEn, subnet, isp, asn) => Object.freeze({
  ...v(id, 'CN', 'AS', city, nameTr, nameEn, subnet, isp, asn, null), resolver: 'alidns', group: 'cn'
});

/**
 * ECS vantage points: one big-ISP /24 per location. Querying Google DoH with
 * `ecs: vantage.subnet` approximates what a user of that ISP would get from a
 * geo-aware authoritative (CDNs such as CloudFront, Wikimedia, Microsoft 365, Meta).
 * Note: some CDNs (e.g. Akamai) ignore ECS from Google and answer by resolver location.
 *
 * @type {ReadonlyArray<GeoVantage>}
 */
export const GEO_VANTAGES = Object.freeze([
  // Türkiye — four vantages over three ISPs and three cities
  v('tr-ist-tt', 'TR', 'EU', 'Istanbul', 'İstanbul, Türkiye', 'Istanbul, Türkiye', '78.181.32.0/24', 'Türk Telekom', 9121),
  v('tr-ank-tt', 'TR', 'EU', 'Ankara', 'Ankara, Türkiye', 'Ankara, Türkiye', '85.99.192.0/24', 'Türk Telekom', 9121),
  v('tr-izm-sol', 'TR', 'EU', 'Izmir', 'İzmir, Türkiye', 'Izmir, Türkiye', '176.41.48.0/24', 'Turkcell Superonline', 34984),
  v('tr-ist-vf', 'TR', 'EU', 'Istanbul', 'İstanbul, Türkiye', 'Istanbul, Türkiye', '31.145.64.0/24', 'Vodafone Türkiye', 15924),
  v('az-bak', 'AZ', 'AS', 'Baku', 'Bakü, Azerbaycan', 'Baku, Azerbaijan', '213.154.8.0/24', 'Aztelekom', 28787),
  // Europe
  v('de-ham', 'DE', 'EU', 'Hamburg', 'Hamburg, Almanya', 'Hamburg, Germany', '79.208.0.0/24', 'Deutsche Telekom', 3320),
  v('nl-ams', 'NL', 'EU', 'Amsterdam', 'Amsterdam, Hollanda', 'Amsterdam, Netherlands', '82.169.128.0/24', 'KPN', 1136),
  v('gb-lon', 'GB', 'EU', 'London', 'Londra, Birleşik Krallık', 'London, United Kingdom', '83.245.18.0/24', 'BT', 2856),
  v('fr-par', 'FR', 'EU', 'Paris', 'Paris, Fransa', 'Paris, France', '86.246.0.0/24', 'Orange', 3215),
  v('it-mil', 'IT', 'EU', 'Milan', 'Milano, İtalya', 'Milan, Italy', '79.16.128.0/24', 'TIM', 3269),
  v('es-bcn', 'ES', 'EU', 'Barcelona', 'Barselona, İspanya', 'Barcelona, Spain', '80.32.64.0/24', 'Movistar (Telefónica)', 3352),
  v('pl-waw', 'PL', 'EU', 'Warsaw', 'Varşova, Polonya', 'Warsaw, Poland', '5.184.64.0/24', 'Orange Polska', 5617),
  v('se-sto', 'SE', 'EU', 'Stockholm', 'Stockholm, İsveç', 'Stockholm, Sweden', '194.103.242.0/24', 'Telia', 3301),
  v('ru-mow', 'RU', 'EU', 'Moscow', 'Moskova, Rusya', 'Moscow, Russia', '95.73.154.0/24', 'Rostelecom', 12389),
  v('ua-iev', 'UA', 'EU', 'Kyiv', 'Kiev, Ukrayna', 'Kyiv, Ukraine', '46.211.64.0/24', 'Kyivstar', 15895),
  // Americas
  v('us-east', 'US', 'NA', 'Washington', 'Washington DC bölgesi, ABD (doğu)', 'Washington DC area, United States (east)', '71.178.64.0/24', 'Verizon', 701, 'Fairfax'),
  v('us-west', 'US', 'NA', 'San Mateo', 'San Mateo (Körfez Bölgesi), ABD (batı)', 'San Mateo (Bay Area), United States (west)', '73.93.0.0/24', 'Comcast Xfinity', 7922),
  v('ca-tor', 'CA', 'NA', 'Toronto', 'Toronto, Kanada', 'Toronto, Canada', '142.117.64.0/24', 'Bell Canada', 577),
  v('mx-mex', 'MX', 'NA', 'Mexico City', 'Meksiko, Meksika', 'Mexico City, Mexico', '201.103.0.0/24', 'Telmex', 8151, 'Cuauhtémoc'),
  v('br-sao', 'BR', 'SA', 'São Paulo', 'São Paulo, Brezilya', 'São Paulo, Brazil', '177.140.16.0/24', 'Claro', 28573),
  v('ar-bue', 'AR', 'SA', 'Buenos Aires', 'Buenos Aires, Arjantin', 'Buenos Aires, Argentina', '181.167.0.0/24', 'Telecom Argentina', 7303),
  // Asia / Middle East
  v('ae-dxb', 'AE', 'AS', 'Dubai', 'Dubai, BAE', 'Dubai, United Arab Emirates', '2.49.0.0/24', 'e& (Etisalat)', 5384),
  v('in-bom', 'IN', 'AS', 'Mumbai', 'Mumbai, Hindistan', 'Mumbai, India', '49.36.106.0/24', 'Reliance Jio', 55836),
  v('sg-sin', 'SG', 'AS', 'Singapore', 'Singapur', 'Singapore', '42.61.64.0/24', 'Singtel', 3758),
  v('id-jkt', 'ID', 'AS', 'Jakarta', 'Cakarta, Endonezya', 'Jakarta, Indonesia', '118.96.5.0/24', 'Telkom Indonesia', 7713, 'Bekasi'),
  v('hk-hkg', 'HK', 'AS', 'Hong Kong', 'Hong Kong', 'Hong Kong', '112.119.128.0/24', 'HKT Netvigator', 4760, 'Kowloon'),
  v('jp-tyo', 'JP', 'AS', 'Tokyo', 'Tokyo, Japonya', 'Tokyo, Japan', '221.186.0.0/24', 'NTT OCN', 4713),
  v('kr-sel', 'KR', 'AS', 'Seoul', 'Seul, Güney Kore', 'Seoul, South Korea', '121.128.0.0/24', 'KT', 4766),
  // Oceania / Africa
  v('au-mel', 'AU', 'OC', 'Melbourne', 'Melbourne, Avustralya', 'Melbourne, Australia', '1.136.0.0/24', 'Telstra', 1221),
  v('za-cpt', 'ZA', 'AF', 'Cape Town', 'Cape Town, Güney Afrika', 'Cape Town, South Africa', '197.229.0.0/24', 'Telkom SA', 37457),
  v('eg-cai', 'EG', 'AF', 'Cairo', 'Kahire, Mısır', 'Cairo, Egypt', '41.41.232.0/24', 'Telecom Egypt (WE)', 8452),
  // Mainland China — three ISPs in three cities, asked through AliDNS (Google's ECS answers miss
  // what mainland users get for names whose GeoDNS decides by resolver)
  cn('cn-bjs-cu', 'Beijing', 'Pekin, Çin', 'Beijing, China', '202.106.0.0/24', 'China Unicom', 4808),
  cn('cn-sha-ct', 'Shanghai', 'Şanghay, Çin', 'Shanghai, China', '202.96.209.0/24', 'China Telecom', 4812),
  cn('cn-can-cm', 'Guangzhou', 'Guangzhou, Çin', 'Guangzhou, China', '211.136.192.0/24', 'China Mobile', 56040)
]);

/**
 * Look up a resolver by id.
 * @param {string} id
 * @returns {Resolver|undefined}
 */
export function getResolver(id) {
  return RESOLVERS.find((r) => r.id === id);
}

/**
 * Look up any resolver by id: a general one ({@link RESOLVERS}) or one asked only for a location
 * ({@link ECS_RESOLVERS}).
 * @param {string} id
 * @returns {Resolver|undefined}
 */
export function getAnyResolver(id) {
  return getResolver(id) || ECS_RESOLVERS.find((r) => r.id === id);
}

/**
 * Look up a geo vantage by id (extension).
 * @param {string} id
 * @returns {GeoVantage|undefined}
 */
export function getVantage(id) {
  return GEO_VANTAGES.find((g) => g.id === id);
}

/**
 * Regional-indicator flag emoji for an ISO 3166-1 alpha-2 code ('tr' → 🇹🇷).
 * Anything that is not two ASCII letters (null for anycast, '', 'XYZ') → '🌐'.
 * @param {string|null|undefined} countryCode
 * @returns {string}
 */
export function flagEmoji(countryCode) {
  if (typeof countryCode !== 'string' || !/^[A-Za-z]{2}$/.test(countryCode)) return '\u{1F310}';
  const cc = countryCode.toUpperCase();
  return String.fromCodePoint(0x1f1e6 + cc.charCodeAt(0) - 65, 0x1f1e6 + cc.charCodeAt(1) - 65);
}
