import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ipVersion, normalizeIP, parseIP, parseCidr, ipInCidr, isPrivateIP, privateRangeOf, isGloballyRoutable,
  reversePtrName, formatIP, RANGES_UPDATED, PROVIDERS, getProvider,
  matchProviderByIP, matchProviderByCname, classifyResolution, isSharedProvider, SHARED_PROVIDER_CATEGORIES
} from '../../assets/js/lib/netinfo.js';

/* -------------------------------------------------------------------- */
/* ipVersion / parseIP / normalizeIP                                    */
/* -------------------------------------------------------------------- */

test('ipVersion', () => {
  assert.equal(ipVersion('1.2.3.4'), 4);
  assert.equal(ipVersion('::1'), 6);
  assert.equal(ipVersion('2001:db8::1'), 6);
  assert.equal(ipVersion('nope'), 0);
  assert.equal(ipVersion('256.0.0.1'), 0);
});

test('normalizeIP: IPv4', () => {
  assert.equal(normalizeIP('1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeIP(' 010.0.0.1 '), null); // leading zero / ambiguous octal
  assert.equal(normalizeIP('1.2.3'), null);
  assert.equal(normalizeIP('1.2.3.256'), null);
});

test('normalizeIP: IPv6 RFC 5952 (longest run, leftmost tie, no single-group ::)', () => {
  assert.equal(normalizeIP('2001:0DB8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
  assert.equal(normalizeIP('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1'); // leftmost longer run
  assert.equal(normalizeIP('2001:0:0:1:0:0:0:1'), '2001:0:0:1::1'); // second run is longer
  assert.equal(normalizeIP('1:2:3:4:5:6:7:0'), '1:2:3:4:5:6:7:0'); // single zero not compressed
  assert.equal(normalizeIP('::'), '::');
  assert.equal(normalizeIP('::1'), '::1');
  assert.equal(normalizeIP('1::'), '1::');
});

test('normalizeIP: brackets, zone id, IPv4-mapped', () => {
  assert.equal(normalizeIP('[2001:db8::1]'), '2001:db8::1');
  assert.equal(normalizeIP('fe80::1%eth0'), 'fe80::1');
  assert.equal(normalizeIP('::ffff:1.2.3.4'), '::ffff:1.2.3.4');
  assert.equal(normalizeIP('::FFFF:0102:0304'), '::ffff:1.2.3.4');
  assert.equal(normalizeIP('0:0:0:0:0:ffff:1.2.3.4'), '::ffff:1.2.3.4');
  assert.equal(normalizeIP('1:2:3:4:5:6:1.2.3.4'), '1:2:3:4:5:6:102:304'); // not ffff-mapped
});

test('normalizeIP: malformed IPv6', () => {
  for (const bad of ['1::2::3', ':1::2', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', 'gggg::1', '12345::1', '']) {
    assert.equal(normalizeIP(bad), null, bad);
  }
});

test('parseIP returns version and bigint; formatIP round-trips', () => {
  const a = parseIP('1.2.3.4');
  assert.equal(a.version, 4);
  assert.equal(a.value, (1n << 24n) | (2n << 16n) | (3n << 8n) | 4n);
  assert.equal(formatIP(a.value, 4), '1.2.3.4');
  const b = parseIP('2001:db8::1');
  assert.equal(formatIP(b.value, 6), '2001:db8::1');
});

/* -------------------------------------------------------------------- */
/* CIDR                                                                 */
/* -------------------------------------------------------------------- */

test('parseCidr masks host bits and validates prefix', () => {
  assert.deepEqual(parseCidr('10.0.0.5/8'), { version: 4, network: parseIP('10.0.0.0').value, prefix: 8 });
  assert.equal(parseCidr('10.0.0.0/33'), null);
  assert.equal(parseCidr('2001:db8::/129'), null);
  assert.deepEqual(parseCidr('1.2.3.4'), { version: 4, network: parseIP('1.2.3.4').value, prefix: 32 }); // bare host route
  assert.equal(parseCidr('2001:db8::1').prefix, 128);
  assert.equal(parseCidr('nonsense'), null);
});

test('ipInCidr', () => {
  assert.equal(ipInCidr('10.1.2.3', '10.0.0.0/8'), true);
  assert.equal(ipInCidr('11.0.0.1', '10.0.0.0/8'), false);
  assert.equal(ipInCidr('2001:db8::5', '2001:db8::/32'), true);
  assert.equal(ipInCidr('2001:db9::5', '2001:db8::/32'), false);
  assert.equal(ipInCidr('1.2.3.4', '2001:db8::/32'), false); // family mismatch
});

test('ipInCidr: IPv4-mapped IPv6 matches IPv4 ranges', () => {
  assert.equal(ipInCidr('::ffff:10.1.2.3', '10.0.0.0/8'), true);
});

/* -------------------------------------------------------------------- */
/* isPrivateIP                                                          */
/* -------------------------------------------------------------------- */

test('isPrivateIP: v4 ranges', () => {
  for (const ip of ['0.1.2.3', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.1.1',
    '172.16.0.1', '172.31.255.255', '192.168.1.1', '192.0.0.1', '198.18.0.1']) {
    assert.equal(isPrivateIP(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '11.0.0.1']) {
    assert.equal(isPrivateIP(ip), false, ip);
  }
});

test('isPrivateIP: v6 ranges + mapped', () => {
  assert.equal(isPrivateIP('::1'), true);
  assert.equal(isPrivateIP('::'), true);
  assert.equal(isPrivateIP('fc00::1'), true);
  assert.equal(isPrivateIP('fd12::1'), true);
  assert.equal(isPrivateIP('fe80::1'), true);
  assert.equal(isPrivateIP('2001:db8::1'), false);
  assert.equal(isPrivateIP('::ffff:10.0.0.1'), true);
  assert.equal(isPrivateIP('::ffff:8.8.8.8'), false);
  assert.equal(isPrivateIP('garbage'), false);
});

test('privateRangeOf: the private range holding an address', () => {
  assert.equal(privateRangeOf('10.20.30.40'), '10.0.0.0/8');
  assert.equal(privateRangeOf('198.19.255.255'), '198.18.0.0/15');
  assert.equal(privateRangeOf('192.0.0.9'), '192.0.0.0/24');
  assert.equal(privateRangeOf('::ffff:172.16.5.4'), '172.16.0.0/12');
  assert.equal(privateRangeOf('fd12::1'), 'fc00::/7');
  assert.equal(privateRangeOf('::'), '::/128');
  for (const ip of ['192.0.2.1', '2001:db8::1', 'garbage', '']) assert.equal(privateRangeOf(ip), null, ip);
});

/* -------------------------------------------------------------------- */
/* reversePtrName                                                       */
/* -------------------------------------------------------------------- */

test('reversePtrName', () => {
  assert.equal(reversePtrName('1.2.3.4'), '4.3.2.1.in-addr.arpa');
  assert.equal(reversePtrName('2001:db8::1'),
    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
  assert.throws(() => reversePtrName('nope'), TypeError);
});

/* -------------------------------------------------------------------- */
/* PROVIDERS                                                            */
/* -------------------------------------------------------------------- */

test('RANGES_UPDATED is the fetch date', () => {
  assert.equal(RANGES_UPDATED, '2026-09-23');
});

test('PROVIDERS has the required ids with valid shape', () => {
  const ids = new Set(PROVIDERS.map((p) => p.id));
  for (const id of ['cloudflare', 'fastly', 'cloudfront', 'akamai', 'imperva', 'sucuri', 'stackpath',
    'bunny', 'keycdn', 'cdn77', 'medianova', 'gcore', 'aws-elb', 'aws-s3', 'azure-appservice',
    'github-pages', 'heroku', 'vercel', 'netlify', 'google-hosted', 'firebase', 'shopify', 'wpengine',
    'render', 'fly', 'railway', 'digitalocean-app', 'azure-trafficmanager', 'azure-frontdoor']) {
    assert.ok(ids.has(id), `missing provider ${id}`);
  }
  for (const p of PROVIDERS) {
    assert.equal(typeof p.name, 'string');
    assert.ok(['cdn', 'waf', 'platform', 'loadbalancer', 'hosting'].includes(p.category), p.id);
    assert.equal(typeof p.hidesOrigin, 'boolean');
    assert.equal(typeof p.certManagedByProvider, 'boolean');
    assert.ok(Array.isArray(p.cidrs));
    assert.ok(Array.isArray(p.cnameSuffixes));
    for (const c of p.cidrs) assert.ok(parseCidr(c), `${p.id} bad cidr ${c}`);
  }
});

test('getProvider', () => {
  assert.equal(getProvider('cloudflare').name, 'Cloudflare');
  assert.equal(getProvider('nope'), undefined);
});

test('Cloudflare and Fastly verbatim ranges are present', () => {
  const cf = getProvider('cloudflare');
  assert.ok(cf.cidrs.includes('104.16.0.0/13'));
  assert.ok(cf.cidrs.includes('2606:4700::/32'));
  const fastly = getProvider('fastly');
  assert.ok(fastly.cidrs.includes('151.101.0.0/16'));
  assert.ok(fastly.cidrs.includes('2a04:4e40::/32'));
});

test('matchProviderByIP', () => {
  assert.equal(matchProviderByIP('104.16.1.1').id, 'cloudflare');
  assert.equal(matchProviderByIP('2606:4700::1').id, 'cloudflare');
  assert.equal(matchProviderByIP('151.101.1.1').id, 'fastly');
  assert.equal(matchProviderByIP('13.32.0.1').id, 'cloudfront');
  assert.equal(matchProviderByIP('45.60.0.1').id, 'imperva');
  assert.equal(matchProviderByIP('192.88.134.1').id, 'sucuri');
  assert.equal(matchProviderByIP('185.199.108.153').id, 'github-pages');
  assert.equal(matchProviderByIP('75.2.60.5').id, 'netlify');
  assert.equal(matchProviderByIP('8.8.8.8'), null);
  assert.equal(matchProviderByIP('::ffff:104.16.1.1').id, 'cloudflare');
});

test('matchProviderByCname: label-boundary suffix match', () => {
  assert.equal(matchProviderByCname('foo.cdn.cloudflare.net').id, 'cloudflare');
  assert.equal(matchProviderByCname('abc.map.fastly.net').id, 'fastly');
  assert.equal(matchProviderByCname('d123.cloudfront.net').id, 'cloudfront');
  assert.equal(matchProviderByCname('x.akamaiedge.net').id, 'akamai');
  assert.equal(matchProviderByCname('site.incapdns.net').id, 'imperva');
  assert.equal(matchProviderByCname('my-lb-123.eu-west-1.elb.amazonaws.com').id, 'aws-elb');
  assert.equal(matchProviderByCname('user.github.io').id, 'github-pages');
  assert.equal(matchProviderByCname('app.herokuapp.com').id, 'heroku');
  assert.equal(matchProviderByCname('notcloudflare.net'), null);
  assert.equal(matchProviderByCname('evil-cloudfront.net.attacker.com'), null);
  assert.equal(matchProviderByCname('foo.trafficmanager.net').id, 'azure-trafficmanager');
});

test('mainland China: CDNs and WAFs recognised by CNAME only (Global DNS’s China rows)', () => {
  // The shapes AliDNS answered the mainland China vantages with (2026-10-02), owners scrubbed.
  const seen = {
    'www.example.com.w.kunluncan.com': 'alibaba-cdn',
    'www.example.com.w.cdngslb.com': 'alibaba-cdn',
    'www.example.com.w.alikunlun.com': 'alibaba-cdn',
    'www.example.com.queniusa.com': 'alibaba-cdn',
    'www.example.com.danuoyi.tbcache.com': 'alibaba-cdn',
    'img.example.com.danuoyi.alicdn.com': 'alibaba-cdn',
    'www.example.com.0abcdefg.c.yundunwaf1.com': 'alibaba-waf',
    'x0abcdefg.yundunwaf4.com': 'alibaba-waf',
    'x0abcdefg.aliyunddos1002.com': 'alibaba-waf',
    'www.example.com.cdn.dnsv1.com': 'tencent-cdn',
    'www.example.com.dsa.dnsv1.com.cn': 'tencent-cdn',
    'best.sched.sma-dk.tdnsstic1.cn': 'tencent-cdn',
    'www.example.com.eo.dnse2.com': 'tencent-edgeone',
    'eo.0abcdefg.share.dnse1.com': 'tencent-edgeone',
    'www.example.com.eo.dnse0.cn': 'tencent-edgeone',
    '0abcdef-cl2.qcloudwzgj.com': 'tencent-waf',
    'www.example.com.c.cdnhwc1.com': 'huawei-cdn',
    'hcdnw.example.gslb.c.cdnhwc2.com': 'huawei-cdn',
    'www.example.com.a.bdydns.com': 'baidu-cdn',
    'opencdn.jomodns.com': 'baidu-cdn',
    'www.example.com.wscdns.com': 'wangsu',
    'www.example.com.lxdns.com': 'wangsu',
    'www.example.com.cdn20.com': 'wangsu',
    'www.example.com.bsgslb.cn': 'baishan',
    'www.example.com.c.vedcdnlb.com': 'volcengine',
    'example.s.dsa.cdnbuild.net': 'volcengine',
    'www.example.com.download.ks-cdn.com': 'kingsoft-cdn',
    'q2.gslb.ksyuncdn.com': 'kingsoft-cdn',
    'www.example.com.s.galileo.jcloud-cdn.com': 'jdcloud-cdn',
    'www.example.com.ctdns.cn': 'ctyun-cdn',
    'cdn-example.qiniudns.com': 'qiniu',
    'cdn-example.b0.aicdn.com': 'upyun',
    // Cloudflare's China Network: edges of a partner there, outside Cloudflare's ranges
    'www.example.com.cdn.cloudflarecn.net': 'cloudflare'
  };
  for (const [name, id] of Object.entries(seen)) assert.equal(matchProviderByCname(name)?.id, id, name);
  for (const id of new Set(Object.values(seen))) {
    const p = getProvider(id);
    assert.ok(['cdn', 'waf'].includes(p.category) && p.hidesOrigin && p.certManagedByProvider && !p.dnsOnly, id);
    if (id !== 'cloudflare') assert.deepEqual(p.cidrs, [], `${id}: by CNAME only`);
  }
  // Steering names that hand out an operator's own servers, rejected suffixes and look-alikes.
  for (const name of [
    'www.example.com.gds.alibabadns.com', 'www.example.com.gslb.qianxun.com', 'www.example.com.akadns.net',
    'x.huaweicloudwaf.com', 'www.example.com.ctlcdn.cn', 'res.example.com.sched.legopic1-dk.tdnsv6.com', 'notkunluncan.com', 'kunluncan.com.example.net',
    'x.aliyunddos12.com', 'x.aliyunddos1002.com.example.net', 'x.notaliyunddos1002.com', 'notcloudflarecn.net'
  ]) assert.equal(matchProviderByCname(name), null, name);
  // No suffix is listed twice or under another operator's suffix (the first one would win).
  const all = PROVIDERS.flatMap((p) => p.cnameSuffixes.map((s) => [s, p.id]));
  assert.equal(new Set(all.map(([s]) => s)).size, all.length, 'every suffix once');
  assert.deepEqual(all.filter(([s, id]) => all.some(([t, other]) => other !== id && t.endsWith(`.${s}`))), [], 'no suffix under another operator’s');
  // An address behind such a name is that CDN's (or WAF's) edge, not a direct server.
  const cdn = classifyResolution({ status: 'NOERROR', ipv4: ['198.51.100.17'], cnames: ['www.example.com.w.kunluncan.com'] });
  assert.deepEqual([cdn.kind, cdn.provider.name, cdn.reasonKey, cdn.hidesOrigin, cdn.via], ['cdn', 'Alibaba Cloud CDN', 'class.cdn.cname', true, 'cname']);
  const waf = classifyResolution({ status: 'NOERROR', ipv4: ['198.51.100.18'], cnames: ['x0abcdefg.yundunwaf4.com'] });
  assert.deepEqual([waf.kind, waf.provider.id, waf.reasonKey], ['cdn', 'alibaba-waf', 'class.waf.cname']);
  const china = classifyResolution({ status: 'NOERROR', ipv4: ['198.51.100.19'], cnames: ['www.example.com.cdn.cloudflarecn.net'] });
  assert.deepEqual([china.kind, china.reasonKey], ['cloudflare', 'class.cloudflare.cname']);
});

test('matchProviderByCname: regex patterns (S3, Vercel)', () => {
  assert.equal(matchProviderByCname('bucket.s3.eu-west-1.amazonaws.com').id, 'aws-s3');
  assert.equal(matchProviderByCname('bucket.s3-website-us-east-1.amazonaws.com').id, 'aws-s3');
  assert.equal(matchProviderByCname('cname.vercel-dns.com').id, 'vercel');
  assert.equal(matchProviderByCname('abcd.vercel-dns-017.com').id, 'vercel');
});

/* -------------------------------------------------------------------- */
/* classifyResolution (priority order)                                  */
/* -------------------------------------------------------------------- */

test('classify: nxdomain with no CNAME', () => {
  const r = classifyResolution({ status: 'NXDOMAIN' });
  assert.equal(r.kind, 'nxdomain');
  assert.equal(r.dangling, false);
  assert.equal(r.reasonKey, 'class.nxdomain');
});

test('classify: dangling CNAME (chain but no address)', () => {
  const nx = classifyResolution({ status: 'NXDOMAIN', cnames: ['gone.herokudns.com'] });
  assert.equal(nx.kind, 'unresolved');
  assert.equal(nx.dangling, true);
  assert.equal(nx.reasonKey, 'class.dangling.nxdomain');
  assert.equal(nx.provider.id, 'heroku');

  const nodata = classifyResolution({ status: 'NOERROR', cnames: ['x.example.com'] });
  assert.equal(nodata.dangling, true);
  assert.equal(nodata.reasonKey, 'class.dangling.noaddress');
});

test('classify: unresolved without CNAME is not dangling', () => {
  assert.equal(classifyResolution({ status: 'SERVFAIL' }).kind, 'unresolved');
  assert.equal(classifyResolution({ status: 'SERVFAIL' }).dangling, false);
  assert.equal(classifyResolution({ status: 'NOERROR', ipv4: [] }).reasonKey, 'class.nodata');
});

test('classify: cloudflare wins over other evidence', () => {
  const r = classifyResolution({ status: 'NOERROR', ipv4: ['104.16.1.1'], cnames: ['x.akamaiedge.net'] });
  assert.equal(r.kind, 'cloudflare');
  assert.equal(r.provider.id, 'cloudflare');
  assert.equal(r.hidesOrigin, true);
  assert.equal(r.certManagedByProvider, true);
  assert.equal(r.reasonKey, 'class.cloudflare.ip');
});

test('classify: cdn/waf by IP and CNAME', () => {
  assert.equal(classifyResolution({ ipv4: ['151.101.1.1'] }).kind, 'cdn');
  assert.equal(classifyResolution({ ipv4: ['151.101.1.1'] }).reasonKey, 'class.cdn.ip');
  const waf = classifyResolution({ status: 'NOERROR', ipv4: ['203.0.113.9'], cnames: ['site.incapdns.net'] });
  assert.equal(waf.kind, 'cdn');
  assert.equal(waf.provider.id, 'imperva');
  assert.equal(waf.reasonKey, 'class.waf.cname');
});

test('classify: platform via CNAME (github pages)', () => {
  const r = classifyResolution({ status: 'NOERROR', ipv4: ['185.199.108.153'], cnames: ['user.github.io'] });
  assert.equal(r.kind, 'platform');
  assert.equal(r.provider.id, 'github-pages');
});

test('classify: cdn (IP) beats platform (CNAME)', () => {
  const r = classifyResolution({ ipv4: ['104.16.1.1'], cnames: ['app.herokuapp.com'] });
  assert.equal(r.kind, 'cloudflare');
});

test('classify: private when all IPs private', () => {
  const r = classifyResolution({ status: 'NOERROR', ipv4: ['10.0.0.1', '192.168.1.1'] });
  assert.equal(r.kind, 'private');
  assert.equal(r.reasonKey, 'class.private');
});

test('classify: direct public IP', () => {
  const r = classifyResolution({ status: 'NOERROR', ipv4: ['8.8.8.8'], ipv6: ['2001:db8::1'] });
  assert.equal(r.kind, 'direct');
  assert.equal(r.provider, null);
  assert.equal(r.hidesOrigin, false);
  assert.equal(r.reasonKey, 'class.direct');
});

test('classify: DNS-only steering (Traffic Manager) does not hide origin', () => {
  const r = classifyResolution({ status: 'NOERROR', ipv4: ['8.8.8.8'], cnames: ['app.trafficmanager.net'] });
  assert.equal(r.kind, 'direct');
  assert.equal(r.provider.id, 'azure-trafficmanager');
  assert.equal(r.hidesOrigin, false);
});

test('classify: mixed private + public is direct, not private', () => {
  const r = classifyResolution({ ipv4: ['10.0.0.1', '8.8.8.8'] });
  assert.equal(r.kind, 'direct');
});

/* -------------------------------------------------------------------- */
/* isGloballyRoutable (what Globalping / InternetDB can reach)          */
/* -------------------------------------------------------------------- */

test('isGloballyRoutable: public unicast v4, v6 and IPv4-mapped v6', () => {
  for (const ip of ['140.82.121.4', '1.1.1.1', '8.8.8.8', '45.33.32.156', '104.16.124.96',
    '2606:4700::6810:7c60', '2a01:4f8::1', '2001:4860:4860::8888', '2001:3::1', '2001:db9::1',
    '3fff:1000::1', '::ffff:140.82.121.4', '[2606:4700::1111]']) {
    assert.equal(isGloballyRoutable(ip), true, ip);
  }
});

test('isGloballyRoutable: every v4 range Globalping refuses (free 400 "private hostname", verified live)', () => {
  for (const ip of ['10.0.0.1', '172.16.5.4', '172.16.0.1', '192.168.1.1', '127.0.0.1', '100.64.0.1',
    '169.254.1.1', '169.254.169.254', '192.0.0.8', '0.0.0.0', '198.18.0.1', '198.19.255.255',
    '192.0.2.1', '198.51.100.7', '203.0.113.5', // TEST-NET-1/2/3
    '224.0.0.1', '239.255.255.250', // multicast 224/4
    '240.0.0.1', '255.255.255.255']) { // 240/4 incl. limited broadcast
    assert.equal(isGloballyRoutable(ip), false, ip);
  }
});

test('isGloballyRoutable: 192.88.99/24 (deprecated 6to4 relay) refused conservatively', () => {
  assert.equal(isGloballyRoutable('192.88.99.1'), false);
});

test('isGloballyRoutable: IPv6 is an allowlist (2000::/3 minus special prefixes)', () => {
  // refused by the API for free: ::, ::1, ULA, link-local, multicast, discard-only, documentation
  for (const ip of ['::', '::1', 'fd00::1', 'fc00::1', 'fe80::1', 'ff02::1', '100::1', '2001:db8::1']) {
    assert.equal(isGloballyRoutable(ip), false, ip);
  }
  // 3fff::/20 (RFC 9637 documentation) was ACCEPTED and charged: the client must refuse it itself
  assert.equal(isGloballyRoutable('3fff::1'), false);
  assert.equal(isGloballyRoutable('3fff:fff:ffff::1'), false, 'last /20 block of 3fff::/20');
  for (const ip of ['2001:2::1', '64:ff9b::808:808', 'fec0::1', '2001::1', '2001:10::1', '2001:20::1',
    '2002::1', '::0.0.0.1', '4000::1', 'e000::1']) {
    assert.equal(isGloballyRoutable(ip), false, ip);
  }
});

test('isGloballyRoutable: IPv4-mapped v6 follows the v4 rules; invalid input is false', () => {
  assert.equal(isGloballyRoutable('::ffff:10.0.0.1'), false);
  assert.equal(isGloballyRoutable('::ffff:192.0.2.1'), false);
  assert.equal(isGloballyRoutable('::ffff:8.8.8.8'), true);
  for (const bad of ['x', '', '1.2.3', '256.1.1.1', '010.0.0.1', 'github.com', null, undefined, 42]) {
    assert.equal(isGloballyRoutable(bad), false, String(bad));
  }
});

test('isPrivateIP keeps its meaning: documentation / multicast space is not "private"', () => {
  assert.equal(isPrivateIP('192.0.2.1'), false);
  assert.equal(isPrivateIP('224.0.0.1'), false);
  assert.equal(isPrivateIP('2001:db8::1'), false);
  assert.equal(isGloballyRoutable('192.0.2.1'), false);
});

/* -------------------------------------------------------------------- */
/* isSharedProvider (multi-tenant address space)                        */
/* -------------------------------------------------------------------- */

test('isSharedProvider: CDN / WAF / platform / loadbalancer / hosting / cloud are shared', () => {
  for (const cat of SHARED_PROVIDER_CATEGORIES) {
    assert.equal(isSharedProvider({ category: cat }), true, cat);
  }
  // real PROVIDERS entries
  assert.equal(isSharedProvider(getProvider('cloudflare')), true);
  assert.equal(isSharedProvider(getProvider('cloudfront')), true);
  assert.equal(isSharedProvider(getProvider('github-pages')), true);
  // an ipintel INFRA_NETWORKS-shaped record is accepted too
  assert.equal(isSharedProvider({ category: 'cloud' }), true);
  assert.equal(isSharedProvider({ category: 'hosting' }), true);
});

test('isSharedProvider: a DNS-only steering provider and null / unknown are not shared', () => {
  assert.equal(isSharedProvider(getProvider('azure-trafficmanager')), false, 'dnsOnly answers are the real endpoints');
  assert.equal(isSharedProvider({ category: 'cloud', dnsOnly: true }), false);
  assert.equal(isSharedProvider(null), false);
  assert.equal(isSharedProvider(undefined), false);
  assert.equal(isSharedProvider({}), false);
  assert.equal(isSharedProvider({ category: 'router' }), false, 'an unknown category is not shared');
});
