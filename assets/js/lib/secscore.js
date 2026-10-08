/**
 * secscore.js — a domain security score in the manner of CSC's Domain Security Report, which
 * scores companies' domains on eight measures: an enterprise-class (corporate) registrar, a
 * registry lock, CAA, DNS redundancy (name servers at two DNS providers or more), DNSSEC, SPF,
 * DKIM and DMARC at quarantine or reject.
 *
 * Each measure is a lib/policy.js rule with a fixed requirement ({@link SECURITY_MEASURES}), so a
 * measure says pass, fail or 'unknown' with the evidence of a policy cell — the same words in the
 * Domain portfolio's Domain security tab, its policy matrix (the `corporate` preset asks for these
 * and the registrar's full lock) and the headless runner's `audit`. A measure that could not be
 * checked (a lookup failed, a registry without RDAP, a registrar without an IANA ID, DKIM not
 * asked) is 'unknown': it never counts as met, and it is never called failed.
 *
 * - {@link securityScore}: one domain's measures and its score, 0 to {@link SECURITY_MAX};
 * - {@link securityAdoption}: how many domains of a portfolio meet each measure;
 * - {@link securityTotals}: the portfolio's average, how many meet all eight, what is not known;
 * - {@link securityCsv} / {@link securityExport}: the rows as CSV (worded) and as codes (JSON).
 *
 * Texts are keys of {@link SECURITY_I18N} (English and Turkish) and of lib/policy.js POLICY_I18N
 * (the evidence). Pure: no DOM, network, storage or clock. Runs in browsers and Node 22.
 */

import { parsePolicy, evaluatePolicy, evidenceText } from './policy.js';
import { toCsv } from './export.js';

const measure = (id, rule, value) => Object.freeze({ id, rule, value });

/**
 * The eight measures in CSC's order: `rule` is the lib/policy.js rule that checks it, `value` the
 * requirement. DNSSEC counts when the zone is signed (DS at the parent); DMARC when its policy is
 * quarantine or reject; CAA when a record restricts issuance (one that allows no CA counts too).
 * @type {ReadonlyArray<{ id: string, rule: string, value: any }>}
 */
export const SECURITY_MEASURES = Object.freeze([
  measure('registrar', 'registrar.class', 'corporate'),
  measure('registryLock', 'registryLock', true),
  measure('caa', 'caa', 'present'),
  measure('dnsRedundancy', 'ns.providers', '>= 2'),
  measure('dnssec', 'dnssec', '>= signed'),
  measure('spf', 'spf', 'valid'),
  measure('dkim', 'dkim', true),
  measure('dmarc', 'dmarc.policy', '>= quarantine')
]);

/** The best score: every measure met. */
export const SECURITY_MAX = SECURITY_MEASURES.length;

/** The measures as one policy (lib/policy.js), parsed once. */
const MEASURES_POLICY = parsePolicy({ name: 'domain security', rules: Object.fromEntries(SECURITY_MEASURES.map((m) => [m.rule, m.value])) }).policy;

/**
 * One domain's measures and score.
 * @param {object} facts lib/portfolio.js portfolioFacts
 * @returns {{ domain: string|null, score: number, fail: number, unknown: number, max: number,
 *   measures: Array<{ id: string, rule: string, status: 'pass'|'fail'|'unknown', actual: any,
 *   evidence: { key: string, params: object }, required: string }> }} `score`: the measures met;
 *   `fail` / `unknown`: the measures not met / not known
 */
export function securityScore(facts) {
  const cells = new Map(evaluatePolicy(MEASURES_POLICY, facts || {}).map((c) => [c.id, c]));
  const measures = SECURITY_MEASURES.map((m) => {
    const c = cells.get(m.rule);
    return { id: m.id, rule: m.rule, status: c.status, actual: c.actual, evidence: c.evidence, required: c.required };
  });
  const count = (s) => measures.filter((x) => x.status === s).length;
  return { domain: facts && facts.domain ? facts.domain : null, score: count('pass'), fail: count('fail'), unknown: count('unknown'), max: SECURITY_MAX, measures };
}

/**
 * The score of every domain, in the list's order.
 * @param {object[]} factsList
 * @returns {ReturnType<typeof securityScore>[]}
 */
export function securityScores(factsList) {
  return (factsList || []).filter(Boolean).map(securityScore);
}

/**
 * How many domains meet each measure: `pass`, `fail` and `unknown` add up to `total`; `share` is
 * the met ones of all (null without a domain) — a domain whose measure is not known is no
 * adopter, and the bar shows it apart.
 * @param {ReturnType<typeof securityScore>[]} rows
 * @returns {Array<{ id: string, pass: number, fail: number, unknown: number, total: number, share: number|null }>}
 */
export function securityAdoption(rows) {
  const list = rows || [];
  return SECURITY_MEASURES.map((m, i) => {
    const count = (s) => list.filter((r) => r.measures[i] && r.measures[i].status === s).length;
    const pass = count('pass');
    return { id: m.id, pass, fail: count('fail'), unknown: count('unknown'), total: list.length, share: list.length ? pass / list.length : null };
  });
}

/**
 * The portfolio in a few numbers: its domains, the average score (a measure not known counts as
 * not met, as in the score), how many meet all eight, and how many measures of how many domains
 * could not be checked.
 * @param {ReturnType<typeof securityScore>[]} rows
 * @returns {{ domains: number, average: number|null, full: number, unknownDomains: number, unknownMeasures: number }}
 */
export function securityTotals(rows) {
  const list = rows || [];
  return {
    domains: list.length,
    average: list.length ? list.reduce((n, r) => n + r.score, 0) / list.length : null,
    full: list.filter((r) => r.score === SECURITY_MAX).length,
    unknownDomains: list.filter((r) => r.unknown > 0).length,
    unknownMeasures: list.reduce((n, r) => n + r.unknown, 0)
  };
}

/**
 * The band of a score, for its colour: 'ok' (all eight), 'info' (6–7), 'warn' (4–5), 'error' (0–3).
 * @param {number} score
 * @returns {'ok'|'info'|'warn'|'error'}
 */
export function scoreBand(score) {
  if (score >= SECURITY_MAX) return 'ok';
  if (score >= SECURITY_MAX - 2) return 'info';
  return score >= SECURITY_MAX / 2 ? 'warn' : 'error';
}

/**
 * The rows as CSV: the domain, its score, the measures not known, then one column per measure —
 * "PASS", "FAIL" or "UNKNOWN" with the evidence (`FAIL · no CAA record: any CA may issue`), as the
 * policy matrix's CSV writes a cell. Formula-looking cells are defused by lib/export.js toCsv.
 * @param {ReturnType<typeof securityScore>[]} rows
 * @param {{ t: Function }} opts `t` speaks SECURITY_I18N and lib/policy.js POLICY_I18N
 * @returns {string}
 */
export function securityCsv(rows, { t }) {
  return toCsv(rows || [], [
    { key: 'domain', header: t('sec.csv.domain') },
    { key: 'score', header: t('sec.csv.score', { max: SECURITY_MAX }) },
    { key: 'unknown', header: t('sec.csv.unknown') },
    ...SECURITY_MEASURES.map((m, i) => ({
      key: m.id,
      header: t(`sec.m.${m.id}`),
      get: (row) => {
        const c = row.measures[i];
        return c ? `${c.status.toUpperCase()} · ${evidenceText(c, t)}` : '';
      }
    }))
  ]);
}

/**
 * A row as codes, for a JSON report (the runner's `audit` targets): the score, the measures not
 * known and each measure's status by id.
 * @param {ReturnType<typeof securityScore>} row
 * @returns {{ score: number, max: number, unknown: number, measures: Record<string, 'pass'|'fail'|'unknown'> }}
 */
export function securityExport(row) {
  return { score: row.score, max: row.max, unknown: row.unknown, measures: Object.fromEntries(row.measures.map((m) => [m.id, m.status])) };
}

/* ------------------------------------------------------------------------ */
/* Texts                                                                    */
/* ------------------------------------------------------------------------ */

const STRINGS = [
  ['sec.m.registrar', ['Corporate registrar', 'Kurumsal kayıt firması']],
  ['sec.m.registryLock', ['Registry lock', 'Kayıt kuruluşu kilidi']],
  ['sec.m.caa', ['CAA', 'CAA']],
  ['sec.m.dnsRedundancy', ['DNS redundancy', 'DNS yedekliliği']],
  ['sec.m.dnssec', ['DNSSEC', 'DNSSEC']],
  ['sec.m.spf', ['SPF', 'SPF']],
  ['sec.m.dkim', ['DKIM', 'DKIM']],
  ['sec.m.dmarc', ['DMARC', 'DMARC']],

  ['sec.d.registrar', ['The registrar is a corporate one, by its IANA ID (MarkMonitor, CSC, Com Laude, Safenames and the like): brand protection, registry locks, change control.',
    'Kayıt firması, IANA kimliğine göre kurumsal bir firma (MarkMonitor, CSC, Com Laude, Safenames gibi): marka koruması, kayıt kuruluşu kilidi, değişiklik denetimi.']],
  ['sec.d.registryLock', ['Server transfer, update and delete prohibited: the registry itself refuses a transfer, a change of name servers and deletion until the registrar asks it out of band.',
    'Server transfer, update ve delete prohibited: kayıt firması bant dışından isteyene kadar transferi, ad sunucusu değişikliğini ve silmeyi kayıt kuruluşunun kendisi reddeder.']],
  ['sec.d.caa', ['A CAA record names the CAs that may issue certificates for the domain.', 'Bir CAA kaydı, alan adı için sertifika verebilecek CA’ları belirtir.']],
  ['sec.d.dnsRedundancy', ['The name servers are at two DNS providers or more: an outage at one leaves the domain answering.',
    'Ad sunucuları iki ya da daha fazla DNS sağlayıcısında: birindeki kesinti alan adını yanıtsız bırakmaz.']],
  ['sec.d.dnssec', ['The zone is signed: a DS record at the parent.', 'Zone imzalı: üst zone’da DS kaydı var.']],
  ['sec.d.spf', ['One valid SPF record.', 'Geçerli tek bir SPF kaydı.']],
  ['sec.d.dkim', ['A DKIM key at one of the common selectors.', 'Yaygın seçicilerden birinde DKIM anahtarı.']],
  ['sec.d.dmarc', ['A DMARC policy of quarantine or reject.', 'quarantine ya da reject DMARC politikası.']],

  ['sec.csv.domain', ['Domain', 'Alan adı']],
  ['sec.csv.score', ['Score (of {max})', 'Puan ({max} üzerinden)']],
  ['sec.csv.unknown', ['Not known', 'Bilinmeyen']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of every `sec.*` key a library builds: the measures' names
 * (`sec.m.<id>`) and what each asks (`sec.d.<id>`), the CSV's headers.
 * @type {{ en: Record<string, string>, tr: Record<string, string> }}
 */
export const SECURITY_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
