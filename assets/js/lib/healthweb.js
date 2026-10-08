/**
 * healthweb.js — the Web category of Domain Health (SPEC §5.78), next to the checks of
 * lib/health.js and in the same Check shape (`{ id, severity, titleKey, detailKey, params,
 * category, group: 'web' }`):
 *
 * - the HTTPS (SVCB) record: lib/health's `https-rr.present` (filed under Web now), plus
 *   `https-rr.none` and `https-rr.error` read from the report (no new lookup);
 * - www and the bare domain: `www.<domain>` A / AAAA, asked through the same DNS client, against
 *   the report's apex addresses — both resolve (an alias of the bare domain, of a host, or
 *   addresses of its own), only one of them does, a CNAME whose target does not exist (a
 *   takeover risk) or private addresses;
 * - the HTTP security grade of lib/observatory.js, as the `observatory.grade` check.
 *
 * The HSTS preload list has no API a page can read (no CORS): the view links to it, nothing is
 * fetched. English and Turkish texts ship in {@link HEALTH_WEB_I18N}. DOM-free.
 */

import { throwIfAborted } from './util.js';
import { normalizeHostname } from './domain.js';
import { isPrivateIP } from './ip.js';
import { countSeverities } from './healthscore.js';

/** Check ids this module emits (lib/health's `https-rr.present` is filed under Web too). */
export const WEB_CHECK_IDS = Object.freeze([
  'https-rr.none', 'https-rr.error',
  'www.ok', 'www.differs', 'www.missing', 'www.apex-missing', 'www.none', 'www.dangling', 'www.private-ip', 'www.error',
  'observatory.grade'
]);

/** Categories (the id before the first '.') of the Web group. */
export const WEB_CATEGORIES = Object.freeze(['https-rr', 'www', 'observatory']);

/** The HSTS preload list's status page of a domain (a link; it sends no CORS headers). */
export const HSTS_PRELOAD_URL = 'https://hstspreload.org/';

/** Why the www comparison did not run: the name is below a zone apex, is itself www, or does not exist. */
export const WWW_SKIP_REASONS = Object.freeze(['not-apex', 'is-www', 'no-domain']);

const arr = (v) => (Array.isArray(v) ? v : []);
const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const list = (values) => [...new Set(arr(values).map(String))].join(', ');

/**
 * A Web check, in lib/health's Check shape.
 * @param {string} id
 * @param {'ok'|'info'|'warn'|'error'} severity
 * @param {Record<string, string|number>} [params]
 * @returns {{ id: string, severity: string, titleKey: string, detailKey: string, params: object, category: string, group: 'web' }}
 */
export function webCheck(id, severity, params = {}) {
  const clean = {};
  for (const [k, v] of Object.entries(params)) clean[k] = v === null || v === undefined ? '' : Array.isArray(v) ? list(v) : v;
  return { id, severity, titleKey: `health.${id}.title`, detailKey: `health.${id}.detail`, params: clean, category: id.slice(0, id.indexOf('.')), group: 'web' };
}

/** HSTS preload status page of a domain. */
export function hstsPreloadUrl(domain) {
  return `${HSTS_PRELOAD_URL}?domain=${encodeURIComponent(domain)}`;
}

const failedRes = (r) => !r || !r.ok || (r.rcode && r.rcode !== 'NOERROR' && r.rcode !== 'NXDOMAIN');
const errText = (r) => (r && (r.error || r.rcode)) || 'no answer';

/** The CNAME chain from `name` in an answer section, in order. */
function cnameChain(answers, name) {
  const chain = [];
  let cur = canon(name);
  for (let i = 0; i < 10; i += 1) {
    const rr = arr(answers).find((x) => x && x.type === 'CNAME' && canon(x.name) === cur);
    if (!rr) break;
    cur = canon(rr.data);
    if (chain.includes(cur)) break;
    chain.push(cur);
  }
  return chain;
}

/** Whether a report says the checked name does not exist. */
const nameMissing = (report) => arr(report && report.checks).some((c) => c && /^domain\./.test(c.id));

/**
 * The HTTPS-record checks of the Web group, read from a lib/health report: none published
 * (info: optional) or a failed lookup (info: not known). `https-rr.present` comes from lib/health.
 * @param {object} report lib/health.js domainHealth result
 * @returns {object[]}
 */
export function httpsRecordChecks(report) {
  if (!report || nameMissing(report)) return [];
  const failed = arr(report.failedLookups);
  const rec = report.records || {};
  if (failed.includes('https')) return [webCheck('https-rr.error', 'info', { domain: report.domain })];
  const hasAddress = arr(rec.a).length + arr(rec.aaaa).length > 0;
  if (!arr(rec.https).length && hasAddress) return [webCheck('https-rr.none', 'info', { domain: report.domain })];
  return [];
}

/**
 * Compare `www.<domain>` with the bare domain: two lookups (A, AAAA) through `dns`.
 * @param {object} report lib/health.js domainHealth result
 * @param {{ dns: { query: Function }, signal?: AbortSignal }} opts
 * @returns {Promise<{ checks: object[], www: { name: string, skipped: string|null, ipv4: string[], ipv6: string[], cnames: string[],
 *   status: string|null, error: string|null } }>}
 */
export async function wwwConsistency(report, { dns, signal } = {}) {
  const domain = normalizeHostname(report && report.domain ? report.domain : '') || '';
  const www = `www.${domain}`;
  const out = { name: www, skipped: null, ipv4: [], ipv6: [], cnames: [], status: null, error: null };
  const skip = (reason) => ({ checks: [], www: { ...out, skipped: reason } });
  if (!domain || nameMissing(report)) return skip('no-domain');
  if (domain.startsWith('www.')) return skip('is-www');
  if (report.apex === false) return skip('not-apex');
  throwIfAborted(signal);
  const [aR, aaaaR] = await Promise.all([dns.query(www, 'A', { signal }), dns.query(www, 'AAAA', { signal })]);
  throwIfAborted(signal);
  const pick = (res, type) => [...new Set(arr(res && res.answers).filter((rr) => rr && rr.type === type).map((rr) => String(rr.data)))];
  out.ipv4 = pick(aR, 'A');
  out.ipv6 = pick(aaaaR, 'AAAA');
  out.cnames = cnameChain([...arr(aR && aR.answers), ...arr(aaaaR && aaaaR.answers)], www);
  out.status = aR && aR.ok ? aR.rcode || 'NOERROR' : 'failed';
  const wwwIps = [...out.ipv4, ...out.ipv6];
  const rec = report.records || {};
  const apexIps = [...arr(rec.a), ...arr(rec.aaaa)];
  const apexFailed = arr(report.failedLookups).some((k) => k === 'a' || k === 'aaaa');
  const checks = [];
  // A family that failed while the other answered nothing: whether www resolves is not known.
  if (!wwwIps.length && (failedRes(aR) || failedRes(aaaaR))) {
    out.error = errText(failedRes(aR) ? aR : aaaaR);
    checks.push(webCheck('www.error', 'info', { www, error: out.error }));
    return { checks, www: out };
  }
  const target = out.cnames.length ? out.cnames[out.cnames.length - 1] : '';
  if (!wwwIps.length && out.cnames.length && aR.rcode === 'NXDOMAIN') {
    checks.push(webCheck('www.dangling', 'error', { www, target, chain: [www, ...out.cnames].join(' → ') }));
    return { checks, www: out };
  }
  if (wwwIps.length && apexIps.length) {
    const how = out.cnames.length ? `CNAME → ${target}` : list(wwwIps);
    checks.push(webCheck('www.ok', 'ok', { www, domain, how }));
    // Both with addresses of their own and none in common: one should redirect to the other.
    if (!out.cnames.length && !wwwIps.some((ip) => apexIps.includes(ip))) {
      checks.push(webCheck('www.differs', 'info', { www, domain, wwwIps: list(wwwIps), apexIps: list(apexIps) }));
    }
  } else if (apexIps.length) {
    checks.push(webCheck('www.missing', 'warn', { www, domain }));
  } else if (wwwIps.length) {
    if (!apexFailed) checks.push(webCheck('www.apex-missing', 'warn', { www, domain }));
  } else if (!apexFailed) {
    checks.push(webCheck('www.none', 'info', { www, domain }));
  }
  const priv = wwwIps.filter((ip) => isPrivateIP(ip));
  if (priv.length) checks.push(webCheck('www.private-ip', 'warn', { www, ips: list(priv) }));
  return { checks, www: out };
}

/**
 * The severity of an Observatory grade: A+ … A- ok, B+ … C- info, D+ … F a warning.
 * @param {string} grade
 * @returns {'ok'|'info'|'warn'}
 */
export function observatorySeverity(grade) {
  const g = String(grade || '').trim().toUpperCase();
  if (g.startsWith('A')) return 'ok';
  if (g.startsWith('B') || g.startsWith('C')) return 'info';
  return 'warn';
}

/**
 * The Web check of an Observatory result (lib/observatory.js), or null for a failure.
 * @param {{ ok: boolean, host: string, grade?: string, score?: number|null, testsFailed?: number|null, testsQuantity?: number|null }|null} result
 * @returns {object|null}
 */
export function observatoryCheck(result) {
  if (!result || !result.ok) return null;
  const n = (v) => (Number.isFinite(v) ? v : '?');
  return webCheck('observatory.grade', observatorySeverity(result.grade), {
    host: result.host, grade: result.grade, score: n(result.score), failed: n(result.testsFailed), total: n(result.testsQuantity)
  });
}

/**
 * The Web checks that are not lib/health's own (every {@link WEB_CHECK_IDS} id), so a merge can replace them.
 * @param {{ id: string }} c
 * @returns {boolean}
 */
export const isWebCheck = (c) => !!c && WEB_CHECK_IDS.includes(c.id);

/**
 * A report with `checks` in place of its Web checks of the same kind (`replace` picks the ones
 * to drop), its summary counted again. The report object is not changed.
 * @param {object} report
 * @param {object[]} checks
 * @param {(c: object) => boolean} [replace] default: every {@link WEB_CHECK_IDS} check
 * @returns {object}
 */
export function withWebChecks(report, checks, replace = isWebCheck) {
  const kept = arr(report && report.checks).filter((c) => !replace(c));
  const all = [...kept, ...arr(checks)];
  return { ...report, checks: all, summary: countSeverities(all) };
}

/**
 * The Web step of a check, after lib/health's: the www comparison (two DNS lookups) and the
 * HTTPS-record checks, merged into the report (`report.web` keeps what was seen).
 * @param {object} report lib/health.js domainHealth result
 * @param {{ dns: { query: Function }, signal?: AbortSignal }} opts
 * @returns {Promise<object>} the report with its Web checks
 */
export async function addWebChecks(report, { dns, signal } = {}) {
  const www = await wwwConsistency(report, { dns, signal });
  const checks = [...httpsRecordChecks(report), ...www.checks];
  const keep = report.web && report.web.observatory ? report.web.observatory : null;
  const merged = withWebChecks(report, keep && keep.ok ? [...checks, observatoryCheck(keep)] : checks);
  merged.web = { www: www.www, observatory: keep };
  return merged;
}

/**
 * The report with an Observatory result: its grade check replaces an earlier one; a failure
 * removes it (the view shows the failure as a status, never as a grade).
 * @param {object} report
 * @param {object} result lib/observatory.js observatoryScan result
 * @returns {object}
 */
export function withObservatory(report, result) {
  const check = observatoryCheck(result);
  const merged = withWebChecks(report, check ? [check] : [], (c) => c && c.id === 'observatory.grade');
  merged.web = { ...(report.web || {}), observatory: result };
  return merged;
}

// [id, [en, tr] title, [en, tr] detail]
const STRINGS = [
  ['https-rr.none', ['No HTTPS record', 'HTTPS kaydı yok'],
    ['{domain} publishes no HTTPS (SVCB) record. It is optional: with one, browsers learn from DNS that the site speaks HTTPS (and HTTP/3, ECH) before the first request.',
      '{domain} için HTTPS (SVCB) kaydı yayınlanmamış. Zorunlu değildir; kayıt olduğunda tarayıcılar sitenin HTTPS (ve HTTP/3, ECH) desteklediğini ilk istekten önce DNS’ten öğrenir.']],
  ['https-rr.error', ['HTTPS record lookup failed', 'HTTPS kaydı sorgulanamadı'],
    ['The HTTPS (SVCB) record of {domain} could not be read, so whether it has one is not known.',
      '{domain} adının HTTPS (SVCB) kaydı okunamadı; kaydın olup olmadığı bilinmiyor.']],
  ['www.ok', ['www and the bare domain both resolve', 'www ve çıplak alan adı çözülüyor'],
    ['{www} resolves ({how}), and so does {domain}: visitors reach the site with or without “www.”.',
      '{www} çözülüyor ({how}), {domain} de çözülüyor: ziyaretçiler siteye “www.” ile de onsuz da ulaşır.']],
  ['www.differs', ['www and the bare domain point to different servers', 'www ve çıplak alan adı farklı sunuculara gidiyor'],
    ['{www} answers {wwwIps}, {domain} answers {apexIps}. That is fine when one redirects to the other; make sure both serve the same site over HTTPS.',
      '{www} {wwwIps} adreslerini, {domain} {apexIps} adreslerini döndürüyor. Biri diğerine yönlendiriyorsa sorun yoktur; ikisinin de aynı siteyi HTTPS ile sunduğundan emin olun.']],
  ['www.missing', ['www does not resolve', 'www çözülmüyor'],
    ['{domain} has an address but {www} has none: visitors who type “www.” get an error.',
      '{domain} adının adresi var ama {www} adının yok: “www.” yazan ziyaretçiler hata alır.']],
  ['www.apex-missing', ['Only www resolves', 'Yalnızca www çözülüyor'],
    ['{www} resolves but {domain} has no A / AAAA record: visitors who type the bare domain get an error.',
      '{www} çözülüyor ama {domain} için A / AAAA kaydı yok: çıplak alan adını yazan ziyaretçiler hata alır.']],
  ['www.none', ['No web site', 'Web sitesi yok'],
    ['Neither {domain} nor {www} has an address. That is expected for a domain used only for email.',
      '{domain} adının da {www} adının da adresi yok. Yalnızca e-posta için kullanılan bir alan adında bu beklenen bir durumdur.']],
  ['www.dangling', ['www points to a name that does not exist', 'www var olmayan bir ada işaret ediyor'],
    ['{www} is an alias (CNAME) of {target}, which does not exist (chain: {chain}). Whoever registers or claims {target} can serve content on {www}.',
      '{www}, var olmayan {target} adının takma adıdır (zincir: {chain}). {target} adını kaydeden ya da üstlenen herkes {www} üzerinde içerik yayınlayabilir.']],
  ['www.private-ip', ['www points to private IPs', 'www özel IP’lere işaret ediyor'],
    ['Public DNS answers private addresses for {www}: {ips}. They are unreachable from the Internet and leak internal addressing.',
      'Genel DNS, {www} için özel adresler döndürüyor: {ips}. Bu adreslere İnternet’ten erişilemez ve iç ağ yapısı açığa çıkar.']],
  ['www.error', ['www lookup failed', 'www sorgulanamadı'],
    ['Could not resolve {www} ({error}), so whether it reaches the site is not known.',
      '{www} çözülemedi ({error}); siteye ulaşıp ulaşmadığı bilinmiyor.']],
  ['observatory.grade', ['HTTP security grade {grade}', 'HTTP güvenlik notu {grade}'],
    ['Mozilla’s HTTP Observatory graded {host} {grade} ({score}/100): {failed} of {total} tests failed. It grades the security headers the site sends (Content-Security-Policy, HSTS, cookies, framing, MIME sniffing, Referrer-Policy, the redirect to HTTPS), not the certificate or DNS.',
      'Mozilla HTTP Observatory, {host} için {grade} notunu verdi ({score}/100): {total} testten {failed} tanesi başarısız. Sitenin gönderdiği güvenlik başlıklarını (Content-Security-Policy, HSTS, çerezler, çerçeveleme, MIME koklama, Referrer-Policy, HTTPS’e yönlendirme) notlar; sertifikayı ya da DNS’i değil.']]
];

function buildStrings(lang) {
  const out = { 'health.group.web': ['Web', 'Web'][lang] };
  for (const [id, title, detail] of STRINGS) {
    out[`health.${id}.title`] = title[lang];
    out[`health.${id}.detail`] = detail[lang];
  }
  return out;
}

/** English and Turkish texts of the Web checks and the Web group (the view registers them). */
export const HEALTH_WEB_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
