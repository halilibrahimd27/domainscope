/**
 * netinfo.js — CDN/WAF/platform detection by IP range or CNAME suffix, and the classification of
 * a name's DNS answer. The IP parsing, CIDR math, private-range checks and PTR names live in
 * lib/ip.js (all of it is re-exported here); DOM-free; runs in browsers and Node 22.
 *
 * The IP ranges come in two tiers. The edge tier (the providers' proxy / CDN / platform ranges)
 * decides the classification; the network tier (an operator's whole published space) only names
 * the network of a 'direct' answer. Both are refreshed weekly by tools/build-ranges.mjs into
 * assets/data/ranges/, which {@link loadRanges} reads once; until it has (or when it cannot), the
 * built-in edge table below is used and there is no network tier.
 */

import { parseIP, normalizeIP, parseCidr, isPrivateIP } from './ip.js';
import { AbortError, ParseError, errorKind, fetchJson, throwIfAborted } from './util.js';

export * from './ip.js';

/* ------------------------------------------------------------------------ */
/* Providers                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Date the built-in IP ranges below were fetched from their official sources. The weekly dataset
 * has its own date ({@link rangesInfo}).
 */
export const RANGES_UPDATED = '2026-09-23';

// Official range sources (all fetched 2026-09-23). IP ranges are included
// ONLY where an official, machine- or docs-published list was retrieved:
//   Cloudflare  https://www.cloudflare.com/ips-v4 , /ips-v6
//   Fastly      https://api.fastly.com/public-ip-list
//   CloudFront  https://ip-ranges.amazonaws.com/ip-ranges.json (service "CLOUDFRONT",
//               syncToken 1790141226; equals the union of
//               https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips)
//   Imperva     https://my.imperva.com/api/integration/v1/ips (POST resp_format=json)
//   Sucuri      https://docs.sucuri.net/website-firewall/sucuri-firewall-troubleshooting-guide/
//               (documented firewall ranges; edge IPs outside them rely on CNAME detection)
//   GitHub Pages https://api.github.com/meta ("pages")
//   Netlify     https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/
//               (apex load balancer 75.2.60.5)
//   Vercel      https://vercel.com/docs/domains/working-with-domains/add-a-domain (apex A 76.76.21.21)
// Not included (no stable official list): Akamai, Azure Front Door (weekly
// service-tag file), Bunny & Gcore (hundreds of churning /32 edge IPs; Gcore's
// list even contains 172.31.0.7), KeyCDN (origin-shield list only), CDN77,
// Medianova, StackPath, Edgio, Shopify (docs not retrievable), others.

const CLOUDFLARE_CIDRS = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
  '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
  '2a06:98c0::/29', '2c0f:f248::/32'
];

const FASTLY_CIDRS = [
  '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23', '103.245.224.0/24',
  '104.156.80.0/20', '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/17', '151.101.0.0/16',
  '157.52.64.0/18', '167.82.0.0/17', '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20',
  '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16',
  '2a04:4e40::/32', '2a04:4e42::/32'
];

const CLOUDFRONT_CIDRS = [
  '3.10.17.128/25', '3.11.53.0/24', '3.29.40.64/26', '3.29.40.128/26', '3.29.40.192/26', '3.29.57.0/26',
  '3.35.130.128/25', '3.101.158.0/23', '3.107.43.128/25', '3.107.44.0/25', '3.107.44.128/25', '3.128.93.0/24',
  '3.134.215.0/24', '3.146.232.0/22', '3.147.164.0/22', '3.147.244.0/22', '3.160.0.0/14', '3.164.0.0/18',
  '3.164.64.0/18', '3.164.128.0/17', '3.165.0.0/16', '3.166.0.0/15', '3.168.0.0/14', '3.172.0.0/18',
  '3.172.64.0/18', '3.173.0.0/17', '3.173.128.0/18', '3.173.192.0/18', '3.174.0.0/15', '3.231.2.0/25',
  '3.234.232.224/27', '3.236.48.0/23', '3.236.169.192/26', '13.32.0.0/15', '13.35.0.0/16', '13.54.63.128/26',
  '13.59.250.0/26', '13.113.196.64/26', '13.113.203.0/24', '13.124.199.0/24', '13.134.24.0/23', '13.134.94.0/23',
  '13.203.133.0/26', '13.210.67.128/26', '13.224.0.0/14', '13.228.69.0/24', '13.233.177.192/26', '13.249.0.0/16',
  '15.158.0.0/16', '15.188.184.0/24', '15.207.13.128/25', '15.207.213.128/25', '18.64.0.0/14', '18.68.0.0/16',
  '18.154.0.0/15', '18.160.0.0/15', '18.164.0.0/15', '18.172.0.0/15', '18.175.65.0/24', '18.175.66.0/24',
  '18.175.67.0/24', '18.192.142.0/23', '18.199.68.0/22', '18.199.72.0/22', '18.199.76.0/22', '18.200.212.0/23',
  '18.216.170.128/25', '18.229.220.192/26', '18.230.229.0/24', '18.230.230.0/25', '18.238.0.0/15', '18.244.0.0/15',
  '23.91.0.0/19', '23.228.212.0/24', '23.228.213.0/24', '23.228.214.0/24', '23.228.220.0/24', '23.228.221.0/24',
  '23.228.222.0/24', '23.228.223.0/24', '23.228.244.0/24', '23.228.246.0/24', '23.228.247.0/24', '23.228.248.0/24',
  '23.228.249.0/24', '23.228.250.0/24', '23.228.251.0/24', '23.234.192.0/18', '24.110.32.0/19', '24.110.128.0/17',
  '34.195.252.0/24', '34.216.51.0/25', '34.223.12.224/27', '34.223.80.192/26', '34.226.14.0/24', '35.93.168.0/23',
  '35.93.170.0/23', '35.93.172.0/23', '35.158.136.0/24', '35.162.63.192/26', '35.167.191.128/26', '36.103.232.0/25',
  '36.103.232.128/26', '43.218.56.64/26', '43.218.56.128/26', '43.218.56.192/26', '43.218.71.0/26', '44.220.194.0/23',
  '44.220.196.0/23', '44.220.198.0/23', '44.220.200.0/23', '44.220.202.0/23', '44.222.66.0/24', '44.227.178.0/24',
  '44.234.90.252/30', '44.234.108.128/25', '47.129.82.0/24', '47.129.83.0/24', '47.129.84.0/24', '51.44.234.0/23',
  '51.44.236.0/23', '51.44.238.0/23', '51.74.192.0/18', '52.15.127.128/26', '52.46.0.0/18', '52.47.139.0/24',
  '52.52.191.128/26', '52.56.127.0/25', '52.57.254.0/24', '52.66.194.128/26', '52.78.247.128/26', '52.82.128.0/19',
  '52.84.0.0/15', '52.124.128.0/17', '52.199.127.192/26', '52.212.248.0/26', '52.220.191.0/26', '52.222.128.0/17',
  '54.182.0.0/16', '54.192.0.0/16', '54.230.0.0/17', '54.230.128.0/18', '54.230.200.0/21', '54.230.208.0/20',
  '54.230.224.0/19', '54.233.255.128/26', '54.239.128.0/18', '54.239.192.0/19', '54.240.128.0/18', '56.125.46.0/24',
  '56.125.47.0/32', '56.125.48.0/24', '57.182.253.0/24', '57.183.42.0/25', '58.254.138.0/25', '58.254.138.128/26',
  '64.252.64.0/18', '64.252.128.0/18', '65.8.0.0/16', '65.9.0.0/17', '65.9.128.0/18', '70.132.0.0/18',
  '71.152.0.0/17', '99.79.169.0/24', '99.84.0.0/16', '99.86.0.0/16', '108.138.0.0/15', '108.156.0.0/14',
  '111.13.171.128/26', '111.13.171.192/26', '111.13.185.32/27', '111.13.185.64/27', '116.129.226.0/25', '116.129.226.128/26',
  '118.193.97.64/26', '118.193.97.128/25', '119.147.182.0/25', '119.147.182.128/26', '120.52.12.64/26', '120.52.22.96/27',
  '120.52.39.128/27', '120.52.153.192/26', '120.232.236.0/25', '120.232.236.128/26', '120.253.240.192/26', '120.253.241.160/27',
  '120.253.245.128/26', '120.253.245.192/27', '130.176.0.0/17', '130.176.128.0/18', '130.176.192.0/19', '130.176.224.0/20',
  '143.204.0.0/16', '144.220.0.0/16', '180.163.57.0/25', '180.163.57.128/26', '204.246.164.0/22', '204.246.168.0/22',
  '204.246.172.0/24', '204.246.173.0/24', '204.246.174.0/23', '204.246.176.0/20', '205.251.202.0/23', '205.251.204.0/23',
  '205.251.206.0/23', '205.251.208.0/20', '205.251.249.0/24', '205.251.250.0/23', '205.251.252.0/23', '205.251.254.0/24',
  '216.137.32.0/19',
  '2001:3fc6:20::/43', '2400:7fc0:500::/40', '2404:c2c0:500::/40', '2409:8c00:2421:300::/56',
  '2409:8c00:2421:400::/56', '2600:9000:ddd::/48', '2600:9000:eee::/48', '2600:9000:fff::/48',
  '2600:9000:1000::/36', '2600:9000:2000::/36', '2600:9000:3000::/36', '2600:9000:4000::/36',
  '2600:9000:5200::/40', '2600:9000:5308::/45', '2600:9000:5310::/44', '2600:9000:5320::/43',
  '2600:9000:5340::/42', '2600:9000:5380::/41', '2600:9000:6000::/36', '2600:9000:f000::/38',
  '2600:9000:f400::/40', '2600:9000:f500::/43', '2600:9000:f520::/44', '2600:9000:f534::/46',
  '2600:9000:f538::/45', '2600:9000:f540::/42', '2600:9000:f580::/41', '2600:9000:f600::/39',
  '2600:9000:f800::/37', '2600:f0f0:601::/48', '2600:f0f0:602::/47', '2600:f0f0:5504::/46'
];

const IMPERVA_CIDRS = [
  '199.83.128.0/21', '198.143.32.0/19', '149.126.72.0/21', '103.28.248.0/22', '185.11.124.0/22',
  '192.230.64.0/18', '45.64.64.0/22', '107.154.0.0/16', '45.60.0.0/16', '45.223.0.0/16',
  '131.125.128.0/17',
  '2a02:e980::/29'
];

const SUCURI_CIDRS = [
  '192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22', '208.109.0.0/22',
  '2a02:fe80::/29'
];

const GITHUB_PAGES_CIDRS = [
  '192.30.252.153/32', '192.30.252.154/32', '185.199.108.153/32', '185.199.109.153/32',
  '185.199.110.153/32', '185.199.111.153/32',
  '2606:50c0:8000::153/128', '2606:50c0:8001::153/128', '2606:50c0:8002::153/128',
  '2606:50c0:8003::153/128'
];

/**
 * Build a frozen provider record. `toJSON` (non-enumerable) omits the large
 * `cidrs` array (replaced by `cidrCount`) and stringifies regexes, so JSON
 * exports that embed providers stay small.
 */
function defineProvider(def) {
  const p = {
    id: def.id,
    name: def.name,
    category: def.category,
    hidesOrigin: def.hidesOrigin,
    certManagedByProvider: def.certManagedByProvider,
    cidrs: Object.freeze([...(def.cidrs || [])]),
    cnameSuffixes: Object.freeze([...(def.cnameSuffixes || [])]),
    cnamePatterns: Object.freeze([...(def.cnamePatterns || [])]),
    dnsOnly: !!def.dnsOnly,
    homepage: def.homepage || null,
    rangesSource: def.rangesSource || null
  };
  Object.defineProperty(p, 'toJSON', {
    enumerable: false,
    value() {
      const { cidrs, cnamePatterns, ...rest } = this;
      return { ...rest, cidrCount: cidrs.length, cnamePatterns: cnamePatterns.map((r) => r.source) };
    }
  });
  return Object.freeze(p);
}

/** A CDN or WAF recognised by CNAME only: visitors reach its edges, which hold the certificate. */
const edgeByName = (id, name, cnameSuffixes, category = 'cdn', cnamePatterns = []) => defineProvider({
  id, name, category, hidesOrigin: true, certManagedByProvider: true, cnameSuffixes, cnamePatterns
});

/**
 * Known CDNs, WAFs, load balancers and hosting platforms.
 *
 * Fields: `id`, `name`, `category` ('cdn'|'waf'|'platform'|'loadbalancer'|
 * 'hosting'), `hidesOrigin` (visitors reach the provider, your origin server
 * is hidden behind it), `certManagedByProvider` (TLS for the hostname is
 * terminated by the provider — the certificate visitors see lives there, not
 * on your servers), `cidrs` (verified official ranges only), `cnameSuffixes`
 * (label-boundary suffix match). Extensions: `cnamePatterns` (RegExp[]),
 * `dnsOnly` (DNS-level traffic steering: the answer IPs are your real
 * endpoints), `homepage`, `rangesSource`.
 * @type {ReadonlyArray<object>}
 */
export const PROVIDERS = Object.freeze([
  defineProvider({
    id: 'cloudflare', name: 'Cloudflare', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    // cloudflarecn.net: the China Network (its edges there are a partner's, not in the ranges)
    cidrs: CLOUDFLARE_CIDRS, cnameSuffixes: ['cdn.cloudflare.net', 'cloudflare.net', 'cloudflarecn.net'],
    homepage: 'https://www.cloudflare.com/', rangesSource: 'https://www.cloudflare.com/ips/'
  }),
  defineProvider({
    id: 'fastly', name: 'Fastly', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cidrs: FASTLY_CIDRS, cnameSuffixes: ['fastly.net', 'fastlylb.net'],
    homepage: 'https://www.fastly.com/', rangesSource: 'https://api.fastly.com/public-ip-list'
  }),
  defineProvider({
    id: 'cloudfront', name: 'Amazon CloudFront', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cidrs: CLOUDFRONT_CIDRS, cnameSuffixes: ['cloudfront.net'],
    homepage: 'https://aws.amazon.com/cloudfront/', rangesSource: 'https://ip-ranges.amazonaws.com/ip-ranges.json'
  }),
  defineProvider({
    id: 'akamai', name: 'Akamai', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['akamaiedge.net', 'akamai.net', 'edgekey.net', 'edgesuite.net', 'akamaized.net',
      'akamaihd.net', 'akamaitechnologies.com', 'akamaiedge-staging.net', 'edgekey-staging.net',
      'edgesuite-staging.net'],
    homepage: 'https://www.akamai.com/'
  }),
  defineProvider({
    id: 'azure-frontdoor', name: 'Azure Front Door / Azure CDN', category: 'cdn', hidesOrigin: true,
    certManagedByProvider: true, cnameSuffixes: ['azurefd.net', 'azureedge.net', 't-msedge.net'],
    homepage: 'https://azure.microsoft.com/products/frontdoor'
  }),
  defineProvider({
    id: 'imperva', name: 'Imperva (Incapsula)', category: 'waf', hidesOrigin: true, certManagedByProvider: true,
    cidrs: IMPERVA_CIDRS, cnameSuffixes: ['incapdns.net', 'impervadns.net'],
    homepage: 'https://www.imperva.com/', rangesSource: 'https://my.imperva.com/api/integration/v1/ips'
  }),
  defineProvider({
    id: 'sucuri', name: 'Sucuri Website Firewall', category: 'waf', hidesOrigin: true, certManagedByProvider: true,
    cidrs: SUCURI_CIDRS, cnameSuffixes: ['sucuri.net'],
    homepage: 'https://sucuri.net/',
    rangesSource: 'https://docs.sucuri.net/website-firewall/sucuri-firewall-troubleshooting-guide/'
  }),
  defineProvider({
    id: 'stackpath', name: 'StackPath / Highwinds', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['stackpathdns.com', 'stackpathcdn.com', 'hwcdn.net'], homepage: 'https://www.stackpath.com/'
  }),
  defineProvider({
    id: 'bunny', name: 'Bunny CDN', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['b-cdn.net'], homepage: 'https://bunny.net/'
  }),
  defineProvider({
    id: 'keycdn', name: 'KeyCDN', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['kxcdn.com'], homepage: 'https://www.keycdn.com/'
  }),
  defineProvider({
    id: 'cdn77', name: 'CDN77', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['cdn77.org', 'cdn77.net'], homepage: 'https://www.cdn77.com/'
  }),
  defineProvider({
    id: 'edgio', name: 'Edgio / Edgecast', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['edgecastcdn.net', 'systemcdn.net', 'edgio.net', 'llnwd.net'], homepage: 'https://edg.io/'
  }),
  defineProvider({
    id: 'medianova', name: 'Medianova', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['mncdn.com', 'mncdn.net'], homepage: 'https://www.medianova.com/'
  }),
  defineProvider({
    id: 'gcore', name: 'Gcore CDN', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['gcdn.co'], homepage: 'https://gcore.com/'
  }),
  defineProvider({
    id: 'cachefly', name: 'CacheFly', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['cachefly.net'], homepage: 'https://www.cachefly.com/'
  }),
  // Mainland China (Global DNS's China rows): by CNAME only — none publishes its edge ranges. Each
  // suffix was in AliDNS's answers for a mainland vantage on 2026-10-02 or is on ProjectDiscovery
  // cdncheck's list (or the operator's docs) for the same operator, and its zone is delegated to that
  // operator's name servers or names it in its SOA (docs/RESEARCH.md). A steering name that hands out
  // the operator's own servers (Alibaba's *.gds.alibabadns.com, JD's *.gslb.qianxun.com) is not one.
  edgeByName('alibaba-cdn', 'Alibaba Cloud CDN', ['kunlunsl.com', 'kunluncan.com', 'kunlunar.com', 'kunlunno.com',
    'kunlunaq.com', 'kunlunca.com', 'kunlunea.com', 'kunlunpi.com', 'kunlungr.com', 'alikunlun.com', 'alikunlun.net',
    'cdngslb.com', 'queniubl.com', 'queniukw.com', 'queniumf.com', 'queniuqy.com', 'queniusa.com', 'queniusy.com',
    'tbcache.com', 'alicdn.com']),
  edgeByName('alibaba-waf', 'Alibaba Cloud WAF / Anti-DDoS', ['yundunwaf1.com', 'yundunwaf2.com', 'yundunwaf3.com',
    'yundunwaf4.com', 'yundunwaf5.com', 'alicloudwaf.com'], 'waf', [/(?:^|\.)aliyunddos\d{4}\.com$/]),
  edgeByName('tencent-cdn', 'Tencent Cloud CDN', ['dnsv1.com', 'dnsv1.com.cn', 'cdntip.com', 'spcdntip.com', 'tdnsv5.com',
    'tdnsstic1.cn', 'tdnsdp1.cn']),
  edgeByName('tencent-edgeone', 'Tencent EdgeOne', ['dnse0.com', 'dnse1.com', 'dnse2.com', 'dnse3.com', 'dnse4.com',
    'dnse5.com', 'dnse0.cn']),
  edgeByName('tencent-waf', 'Tencent Cloud WAF', ['qcloudwaf.com', 'qcloudwzgj.com', 'qcloudzygj.com', 'qcloudcjgj.com'], 'waf'),
  edgeByName('huawei-cdn', 'Huawei Cloud CDN', ['cdnhwc1.com', 'cdnhwc2.com', 'cdnhwc3.com', 'cdnhwc4.com', 'cdnhwc5.com',
    'cdnhwc6.com', 'cdnhwc7.com', 'cdnhwc8.com']),
  edgeByName('baidu-cdn', 'Baidu AI Cloud CDN', ['bdydns.com', 'jomodns.com']),
  edgeByName('wangsu', 'Wangsu (ChinaNetCenter)', ['wscdns.com', 'wscloudcdn.com', 'wswebcdn.com', 'wswebpic.com',
    'wsglb0.com', 'wsdvs.com', 'wsssec.com', 'lxdns.com', 'cdn20.com', 'cdn30.com', 'wtxcdn.com', 'mwcloudcdn.com',
    'mwcname.com', 'speedcdns.com', '51cdn.com', 'ourplat.net', 'chinanetcenter.com']),
  edgeByName('baishan', 'Baishan Cloud', ['bsgslb.cn', 'qingcdn.com', 'trpcdn.net', 'bsclink.cn']),
  edgeByName('volcengine', 'Volcano Engine CDN', ['vedcdnlb.com', 'cdnbuild.net']),
  edgeByName('kingsoft-cdn', 'Kingsoft Cloud CDN', ['ks-cdn.com', 'ksyuncdn.com']),
  edgeByName('jdcloud-cdn', 'JD Cloud CDN', ['jcloud-cdn.com', 'jcloudimg.com', 'jdcdn.com']),
  edgeByName('ctyun-cdn', 'CTYun CDN (China Telecom)', ['ctdns.cn', 'ctadns.cn']),
  edgeByName('qiniu', 'Qiniu Cloud CDN', ['qiniudns.com']),
  edgeByName('upyun', 'Upyun CDN', ['aicdn.com']),
  defineProvider({
    id: 'aws-elb', name: 'AWS Elastic Load Balancing', category: 'loadbalancer', hidesOrigin: true,
    certManagedByProvider: true, cnameSuffixes: ['elb.amazonaws.com', 'elb.amazonaws.com.cn'],
    homepage: 'https://aws.amazon.com/elasticloadbalancing/'
  }),
  defineProvider({
    id: 'azure-trafficmanager', name: 'Azure Traffic Manager', category: 'loadbalancer', hidesOrigin: false,
    certManagedByProvider: false, dnsOnly: true, cnameSuffixes: ['trafficmanager.net'],
    homepage: 'https://azure.microsoft.com/products/traffic-manager'
  }),
  defineProvider({
    id: 'aws-s3', name: 'Amazon S3', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['s3.amazonaws.com'],
    // s3.amazonaws.com, s3-website-us-east-1.amazonaws.com, bucket.s3.eu-west-1.amazonaws.com,
    // bucket.s3-website.eu-central-1.amazonaws.com, s3.dualstack.… (label must start with "s3").
    // One way to split a name: a hyphen is never both a separator and a label character (a
    // near-miss with a long hyphen run backtracked exponentially on an untrusted CNAME / PTR).
    cnamePatterns: [/(?:^|\.)s3(?:-[a-z0-9-]+)?(?:\.[a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?$/],
    homepage: 'https://aws.amazon.com/s3/'
  }),
  defineProvider({
    id: 'azure-appservice', name: 'Azure App Service / Static Web Apps', category: 'platform', hidesOrigin: false,
    certManagedByProvider: true, cnameSuffixes: ['azurewebsites.net', 'azurestaticapps.net'],
    homepage: 'https://azure.microsoft.com/products/app-service'
  }),
  defineProvider({
    id: 'github-pages', name: 'GitHub Pages', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cidrs: GITHUB_PAGES_CIDRS, cnameSuffixes: ['github.io'],
    homepage: 'https://pages.github.com/', rangesSource: 'https://api.github.com/meta'
  }),
  defineProvider({
    id: 'gitlab-pages', name: 'GitLab Pages', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['gitlab.io'], homepage: 'https://docs.gitlab.com/ee/user/project/pages/'
  }),
  defineProvider({
    id: 'heroku', name: 'Heroku', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'], homepage: 'https://www.heroku.com/'
  }),
  defineProvider({
    id: 'vercel', name: 'Vercel', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cidrs: ['76.76.21.21/32'], cnameSuffixes: ['vercel-dns.com', 'vercel.app'],
    cnamePatterns: [/(?:^|\.)vercel-dns-\d+\.com$/],
    homepage: 'https://vercel.com/', rangesSource: 'https://vercel.com/docs/domains/working-with-domains/add-a-domain'
  }),
  defineProvider({
    id: 'netlify', name: 'Netlify', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cidrs: ['75.2.60.5/32'], cnameSuffixes: ['netlify.app', 'netlify.com'],
    homepage: 'https://www.netlify.com/',
    rangesSource: 'https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/'
  }),
  defineProvider({
    id: 'google-hosted', name: 'Google-hosted (ghs.googlehosted.com)', category: 'platform', hidesOrigin: false,
    certManagedByProvider: true, cnameSuffixes: ['ghs.googlehosted.com', 'googlehosted.com'],
    homepage: 'https://support.google.com/a/answer/47283'
  }),
  defineProvider({
    id: 'firebase', name: 'Firebase Hosting', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['web.app', 'firebaseapp.com'], homepage: 'https://firebase.google.com/docs/hosting'
  }),
  defineProvider({
    id: 'shopify', name: 'Shopify', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['myshopify.com'], homepage: 'https://www.shopify.com/'
  }),
  defineProvider({
    id: 'wpengine', name: 'WP Engine', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['wpengine.com', 'wpenginepowered.com'], homepage: 'https://wpengine.com/'
  }),
  defineProvider({
    id: 'pantheon', name: 'Pantheon', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['pantheonsite.io', 'pantheon.io'], homepage: 'https://pantheon.io/'
  }),
  defineProvider({
    id: 'render', name: 'Render', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['onrender.com'], homepage: 'https://render.com/'
  }),
  defineProvider({
    id: 'fly', name: 'Fly.io', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['fly.dev'], homepage: 'https://fly.io/'
  }),
  defineProvider({
    id: 'railway', name: 'Railway', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['railway.app'], homepage: 'https://railway.com/'
  }),
  defineProvider({
    id: 'digitalocean-app', name: 'DigitalOcean App Platform', category: 'platform', hidesOrigin: false,
    certManagedByProvider: true, cnameSuffixes: ['ondigitalocean.app'],
    homepage: 'https://www.digitalocean.com/products/app-platform'
  }),
  defineProvider({
    id: 'wix', name: 'Wix', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['wixdns.net'], homepage: 'https://www.wix.com/'
  }),
  defineProvider({
    id: 'squarespace', name: 'Squarespace', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['squarespace.com'], homepage: 'https://www.squarespace.com/'
  }),
  defineProvider({
    id: 'webflow', name: 'Webflow', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['webflow.com', 'webflow.io'], homepage: 'https://webflow.com/'
  })
]);

/**
 * Look up a provider by id.
 * @param {string} id
 * @returns {object|undefined}
 */
export function getProvider(id) {
  return PROVIDERS.find((p) => p.id === id);
}

/** Provider categories whose address space many unrelated customers share. */
export const SHARED_PROVIDER_CATEGORIES = Object.freeze(['cdn', 'waf', 'platform', 'loadbalancer', 'hosting', 'cloud']);

/**
 * Is `provider` multi-tenant address space — a CDN / WAF edge, a hosting
 * platform, a shared load balancer or a cloud — where one address or block
 * serves many unrelated customers? A DNS-only steering provider (its answers
 * are the customer's own endpoints) is not. Accepts a PROVIDERS entry or any
 * `{ category, dnsOnly? }` record (e.g. an ipintel INFRA_NETWORKS entry).
 * Extension; display / sweep-policy hint only.
 * @param {{ category?: string, dnsOnly?: boolean }|null|undefined} provider
 * @returns {boolean}
 */
export function isSharedProvider(provider) {
  if (!provider || typeof provider !== 'object' || provider.dnsOnly) return false;
  return SHARED_PROVIDER_CATEGORIES.includes(provider.category);
}

/* ------------------------------------------------------------------------ */
/* The range dataset (tools/build-ranges.mjs → assets/data/ranges/)         */
/* ------------------------------------------------------------------------ */

/** Format of the range dataset this module reads (tools/build-ranges.mjs FORMAT); another one is refused. */
export const RANGES_FORMAT = 1;
/** The files of the range dataset, under assets/data/ranges/. */
export const RANGES_FILES = Object.freeze(['manifest.json', 'edges.json', 'networks.json']);
/** How long loading the dataset may take, bodies included. */
export const RANGES_TIMEOUT_MS = 15000;
/** Where the ranges in use come from: the weekly dataset, or the built-in table above. */
export const RANGES_SOURCES = Object.freeze(['data', 'built-in']);

/** The dataset's manifest; the other files sit next to it. */
const RANGES_BASE = new URL('../../data/ranges/manifest.json', import.meta.url);
/** Running in Node (file:// module, tests and tools) vs a browser (http(s):// module). */
const IS_NODE = RANGES_BASE.protocol === 'file:';

const defineNetwork = (id, name, category) => Object.freeze({ id, name, category, tier: 'network' });

/**
 * The operators of the dataset's network tier, in lookup order: their whole published (or, for
 * Cloudflare, announced) address space. Display only — an answer there that no edge range holds
 * is still 'direct' (the address is reached as such); {@link classifyResolution} only names the
 * network. Cloudflare's entry is the second tier of ROADMAP P2.10: the prefixes AS13335 and
 * AS209242 announce (Spectrum, WARP, BYOIP, 1.1.1.1 …), not necessarily proxied. Google Cloud's
 * customer ranges come before the rest of Google's. Ids match lib/ipintel.js INFRA_NETWORKS.
 * Empty until the dataset loads.
 * @type {ReadonlyArray<{ id: string, name: string, category: 'cdn'|'cloud'|'hosting', tier: 'network' }>}
 */
export const NETWORKS = Object.freeze([
  defineNetwork('cloudflare', 'Cloudflare', 'cdn'),
  defineNetwork('aws', 'AWS', 'cloud'),
  defineNetwork('google-cloud', 'Google Cloud', 'cloud'),
  defineNetwork('google', 'Google', 'cloud'),
  defineNetwork('oracle', 'Oracle Cloud', 'cloud'),
  defineNetwork('digitalocean', 'DigitalOcean', 'hosting')
]);

/** The installed dataset, or null (the built-in table is in use). */
let dataset = null;
/** Why the last load did not install the dataset: { error, errorKind }, or null. */
let loadFailure = null;
/** The load in flight (or done), shared by every caller. */
let loading = null;
let edgeIndex = null; // [{ provider, table }] in PROVIDERS order
let networkIndex = null; // [{ network, table }] in NETWORKS order
let suffixIndex = null; // Map<suffix, provider>

const byStart = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);

/** Prefix texts → per IP version, sorted non-overlapping [start, end] intervals (a binary search table). */
function compileTable(prefixes) {
  const raw = { 4: [], 6: [] };
  for (const text of prefixes) {
    const c = parseCidr(text);
    if (c) raw[c.version].push([c.network, c.network + (1n << BigInt((c.version === 4 ? 32 : 128) - c.prefix)) - 1n]);
  }
  const table = {};
  for (const v of [4, 6]) {
    const starts = [];
    const ends = [];
    for (const [s, e] of raw[v].sort(byStart)) {
      const last = ends.length - 1;
      if (last >= 0 && s <= ends[last] + 1n) {
        if (e > ends[last]) ends[last] = e;
      } else {
        starts.push(s);
        ends.push(e);
      }
    }
    table[v] = { starts, ends };
  }
  return table;
}

function tableHolds(table, version, value) {
  const { starts, ends } = table[version];
  let lo = 0;
  let hi = starts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (starts[mid] <= value) lo = mid + 1;
    else hi = mid - 1;
  }
  return hi >= 0 && value <= ends[hi];
}

/** Does `table` hold the parsed address? An IPv4-mapped IPv6 address matches IPv4 ranges (as cidrContains). */
function inTable(table, addr) {
  if (tableHolds(table, addr.version, addr.value)) return true;
  return addr.version === 6 && addr.value >> 32n === 0xffffn && tableHolds(table, 4, addr.value & 0xffffffffn);
}

/** The edge ranges in use: the dataset's list of a provider when it has one, else the built-in table. */
function edgeTables() {
  if (!edgeIndex) {
    edgeIndex = [];
    for (const provider of PROVIDERS) {
      const list = (dataset && dataset.edges.get(provider.id)) || provider.cidrs;
      if (list.length) edgeIndex.push({ provider, table: compileTable(list) });
    }
  }
  return edgeIndex;
}

function networkTables() {
  if (!networkIndex) {
    networkIndex = [];
    for (const network of NETWORKS) {
      const list = dataset && dataset.networks.get(network.id);
      if (list && list.length) networkIndex.push({ network, table: compileTable(list) });
    }
  }
  return networkIndex;
}

/** A tier file's entries: id → non-empty list of prefix texts. Throws on any other shape. */
function tierEntries(obj, what) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new TypeError(`${what}: not an object`);
  const out = new Map();
  for (const [id, list] of Object.entries(obj)) {
    if (!Array.isArray(list) || !list.length) throw new TypeError(`${what}: ${id} is not a list of prefixes`);
    for (const p of list) if (typeof p !== 'string' || !parseCidr(p)) throw new TypeError(`${what}: ${id} holds ${JSON.stringify(String(p).slice(0, 40))}`);
    out.set(id, Object.freeze([...list]));
  }
  return out;
}

/**
 * @typedef {object} RangesInfo
 * @property {'data'|'built-in'} source where the ranges in use come from ({@link RANGES_SOURCES})
 * @property {string} updated YYYY-MM-DD: the dataset's date, or {@link RANGES_UPDATED} for the built-in table
 * @property {Record<string, number>} edges prefixes per provider in use for the classification
 * @property {Record<string, number>} networks prefixes per network-tier operator (empty without the dataset)
 * @property {string|null} error why the dataset is not in use, when a load failed (null otherwise)
 * @property {string|null} errorKind lib/util.js errorKind of that failure ('parse' for a refused dataset)
 */

/**
 * The ranges in use right now.
 * @returns {RangesInfo}
 */
export function rangesInfo() {
  const edges = {};
  for (const { provider } of edgeTables()) edges[provider.id] = ((dataset && dataset.edges.get(provider.id)) || provider.cidrs).length;
  const networks = {};
  for (const { network } of networkTables()) networks[network.id] = dataset.networks.get(network.id).length;
  return {
    source: dataset ? 'data' : 'built-in',
    updated: dataset ? dataset.generated : RANGES_UPDATED,
    edges,
    networks,
    error: dataset || !loadFailure ? null : loadFailure.error,
    errorKind: dataset || !loadFailure ? null : loadFailure.errorKind
  };
}

/**
 * Use a range dataset — the three parsed files of assets/data/ranges as tools/build-ranges.mjs
 * writes them — for {@link matchProviderByIP}, {@link matchNetworkByIP} and
 * {@link classifyResolution}. A provider the edge file does not list keeps its built-in ranges
 * (Imperva, Sucuri, Netlify, Vercel). A dataset of another format or shape is refused whole and
 * the ranges in use stay as they were. `null` goes back to the built-in table.
 * @param {{ manifest: object, edges: object, networks: object }|null} data
 * @returns {RangesInfo} with `error` / `errorKind: 'parse'` when the dataset was refused
 */
export function installRanges(data) {
  if (data === null) {
    dataset = null;
    loadFailure = null;
    loading = null; // a later loadRanges() reads the files again
  } else {
    try {
      const manifest = data && data.manifest;
      if (!manifest || manifest.format !== RANGES_FORMAT) throw new TypeError(`manifest: format ${manifest ? JSON.stringify(manifest.format) : 'missing'}, expected ${RANGES_FORMAT}`);
      if (typeof manifest.generated !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(manifest.generated)) throw new TypeError('manifest: no date');
      dataset = { generated: manifest.generated, edges: tierEntries(data.edges, 'edges'), networks: tierEntries(data.networks, 'networks') };
      loadFailure = null;
    } catch (err) {
      loadFailure = { error: String(err && err.message ? err.message : err), errorKind: 'parse' };
    }
  }
  edgeIndex = null;
  networkIndex = null;
  return rangesInfo();
}

/** One dataset file: `fs` in Node (unless a fetch is injected), else fetched next to this module. */
async function readRangesFile(name, { fetchImpl, timeoutMs }) {
  const url = new URL(name, RANGES_BASE);
  if (IS_NODE && !fetchImpl) {
    const { readFile } = await import('node:fs/promises');
    try {
      return JSON.parse(await readFile(url, 'utf8'));
    } catch (err) {
      throw err instanceof SyntaxError ? new ParseError(`${name}: ${err.message}`) : err;
    }
  }
  return fetchJson(url.href, { fetchImpl: fetchImpl || globalThis.fetch, timeoutMs, headers: { accept: 'application/json' } });
}

/** Wait for `promise`, or reject with an AbortError as soon as `signal` aborts (the work itself goes on). */
function abortable(promise, signal) {
  if (!signal) return promise;
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new AbortError('aborted', { cause: signal.reason }));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then((v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); });
  });
}

/**
 * Load the range dataset (assets/data/ranges, next to this module) once and install it
 * ({@link installRanges}). Every caller shares one load; a failed load is tried again by the next
 * call. Until it succeeds — the files are missing, a request fails or times out, the dataset is
 * refused — the built-in table stays in use and the result says why. In a browser the load starts
 * when this module is first imported; a run that must not change its ranges halfway awaits it.
 * Only an abort of `signal` rejects (it ends the wait, not the shared load).
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number }} [opts]
 *   fetchImpl: also in Node (tests), instead of reading the files with `fs`
 * @returns {Promise<RangesInfo>}
 */
export function loadRanges({ fetchImpl, signal, timeoutMs = RANGES_TIMEOUT_MS } = {}) {
  if (dataset) return Promise.resolve(rangesInfo());
  if (!loading) {
    loading = Promise.all(RANGES_FILES.map((name) => readRangesFile(name, { fetchImpl, timeoutMs })))
      .then(([manifest, edges, networks]) => installRanges({ manifest, edges, networks }))
      .catch((err) => {
        loadFailure = { error: String(err && err.message ? err.message : err), errorKind: errorKind(err) };
        return rangesInfo();
      })
      .then((info) => {
        if (!dataset) loading = null; // the next call tries again
        return info;
      });
  }
  return abortable(loading, signal);
}

/**
 * Operator network (the dataset's network tier) whose published space holds `ip`, first match in
 * {@link NETWORKS} order; null for an address outside them, a bad input, or while the dataset is
 * not loaded. Display only: the classification's kind does not depend on it.
 * @param {string} ip
 * @returns {{ id: string, name: string, category: string, tier: 'network' }|null}
 */
export function matchNetworkByIP(ip) {
  const addr = parseIP(ip);
  if (!addr) return null;
  for (const { network, table } of networkTables()) if (inTable(table, addr)) return network;
  return null;
}

function suffixes() {
  if (!suffixIndex) {
    suffixIndex = new Map();
    for (const provider of PROVIDERS) {
      for (const suffix of provider.cnameSuffixes) {
        if (!suffixIndex.has(suffix)) suffixIndex.set(suffix, provider);
      }
    }
  }
  return suffixIndex;
}

/**
 * Provider whose published IP ranges contain `ip` (first match in PROVIDERS
 * order), or null. The ranges are the weekly dataset's once {@link loadRanges}
 * installed it, else the built-in table ({@link rangesInfo}).
 * @param {string} ip
 * @returns {object|null}
 */
export function matchProviderByIP(ip) {
  const addr = parseIP(ip);
  if (!addr) return null;
  for (const { provider, table } of edgeTables()) {
    if (inTable(table, addr)) return provider;
  }
  return null;
}

/**
 * Provider whose CNAME suffix matches `hostname` on a label boundary
 * (longest suffix wins), then provider regex patterns; or null.
 * @param {string} hostname
 * @returns {object|null}
 */
export function matchProviderByCname(hostname) {
  if (typeof hostname !== 'string') return null;
  let h = hostname.trim().toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (!h) return null;
  const index = suffixes();
  const labels = h.split('.');
  for (let i = 0; i < labels.length; i += 1) {
    const hit = index.get(labels.slice(i).join('.'));
    if (hit) return hit;
  }
  for (const provider of PROVIDERS) {
    if (provider.cnamePatterns.some((re) => re.test(h))) return provider;
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Classification                                                           */
/* ------------------------------------------------------------------------ */

function rankOf(provider) {
  if (provider.dnsOnly) return Infinity;
  if (provider.id === 'cloudflare') return 0;
  if (provider.category === 'cdn' || provider.category === 'waf') return 1;
  return 2; // platform / loadbalancer / hosting
}

function kindOf(provider) {
  if (provider.id === 'cloudflare') return 'cloudflare';
  if (provider.category === 'cdn' || provider.category === 'waf') return 'cdn';
  return 'platform';
}

function reasonOf(provider, via) {
  const group = provider.id === 'cloudflare' ? 'cloudflare' : provider.category;
  return `class.${group}.${via}`;
}

/**
 * Classify a host's DNS resolution.
 *
 * Priority: nxdomain (no CNAME) > dangling/unresolved > cloudflare > cdn/waf
 * > platform/loadbalancer > private (all IPs private) > direct.
 * `dangling` is true when a CNAME chain exists but yields no address
 * (NXDOMAIN target, NODATA, or a failed lookup).
 *
 * reasonKey values: class.nxdomain, class.dangling.nxdomain,
 * class.dangling.noaddress, class.dangling.error, class.nodata, class.error,
 * class.cloudflare.ip, class.cloudflare.cname, class.cdn.ip, class.cdn.cname,
 * class.waf.ip, class.waf.cname, class.platform.ip, class.platform.cname,
 * class.loadbalancer.ip, class.loadbalancer.cname, class.hosting.ip,
 * class.hosting.cname, class.private, class.direct.
 *
 * Two tiers (ROADMAP P2.10): only the edge ranges ({@link matchProviderByIP}) make an answer
 * Cloudflare-proxied, CDN or platform. A 'direct' answer with an address in the network tier
 * ({@link matchNetworkByIP}, once the dataset is loaded) also carries `network`, the first such
 * address's operator — for Cloudflare, "Cloudflare network, not necessarily proxied". Its kind,
 * reasonKey and flags stay those of a direct answer; without a match there is no `network` key.
 *
 * @param {{ status?: string, ipv4?: string[], ipv6?: string[], cnames?: string[] }} res
 * @returns {{ kind: 'cloudflare'|'cdn'|'platform'|'direct'|'private'|'unresolved'|'nxdomain',
 *   provider: object|null, hidesOrigin: boolean, certManagedByProvider: boolean,
 *   dangling: boolean, reasonKey: string, via: 'ip'|'cname'|null,
 *   network?: { id: string, name: string, category: string, tier: 'network' } }}
 */
export function classifyResolution({ status, ipv4 = [], ipv6 = [], cnames = [] } = {}) {
  const ips = [...new Set([...(ipv4 || []), ...(ipv6 || [])].map(normalizeIP).filter(Boolean))];
  const chain = (cnames || [])
    .filter((c) => typeof c === 'string')
    .map((c) => c.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);
  const st = typeof status === 'string' && status ? status.toUpperCase() : (ips.length ? 'NOERROR' : 'ERROR');
  const result = (kind, reasonKey, extra = {}) => ({
    kind, provider: null, hidesOrigin: false, certManagedByProvider: false, dangling: false, reasonKey, via: null, ...extra
  });

  // Provider evidence: IP matches first, then the CNAME chain in order.
  const candidates = [];
  for (const ip of ips) {
    const p = matchProviderByIP(ip);
    if (p) candidates.push({ provider: p, via: 'ip' });
  }
  for (const c of chain) {
    const p = matchProviderByCname(c);
    if (p) candidates.push({ provider: p, via: 'cname' });
  }

  if (ips.length === 0) {
    if (chain.length === 0) {
      if (st === 'NXDOMAIN') return result('nxdomain', 'class.nxdomain');
      return result('unresolved', st === 'NOERROR' ? 'class.nodata' : 'class.error');
    }
    // Dangling CNAME: the provider (if any) hints at takeover-prone services.
    let reasonKey = 'class.dangling.error';
    if (st === 'NXDOMAIN') reasonKey = 'class.dangling.nxdomain';
    else if (st === 'NOERROR') reasonKey = 'class.dangling.noaddress';
    const hit = candidates[0] || null;
    return result('unresolved', reasonKey, {
      dangling: true, provider: hit ? hit.provider : null, via: hit ? 'cname' : null
    });
  }

  let best = null;
  for (const c of candidates) {
    if (!best || rankOf(c.provider) < rankOf(best.provider)) best = c;
  }
  if (best && !best.provider.dnsOnly) {
    return result(kindOf(best.provider), reasonOf(best.provider, best.via), {
      provider: best.provider,
      hidesOrigin: best.provider.hidesOrigin,
      certManagedByProvider: best.provider.certManagedByProvider,
      via: best.via
    });
  }
  // Only DNS-level steering (or nothing): the answer IPs are the real endpoints.
  const extra = best ? { provider: best.provider, via: best.via } : {};
  if (ips.every(isPrivateIP)) return result('private', 'class.private', extra);
  for (const ip of ips) {
    const network = matchNetworkByIP(ip);
    if (network) {
      extra.network = network;
      break;
    }
  }
  return result('direct', 'class.direct', extra);
}

// In a browser, start loading the dataset as soon as a view imports this module (Node — tests,
// tools — loads it only when asked). A failure leaves the built-in table in use.
if (!IS_NODE && typeof globalThis.fetch === 'function') loadRanges();
