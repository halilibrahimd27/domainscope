/**
 * ui/locale-evidence.js — the market packs a scan's evidence added, and why (lib/localeevidence.js,
 * SPEC §5.89), in the run header of Subdomains (ui/subdomains-run.js) and SSL Targets
 * (views/scan.js). Both plan lines say "plus market packs if the scan finds evidence"; both runs
 * then say which pack the evidence added — "Turkish pack added for example.com. Evidence: words in
 * the names found (bayi, destek, kampanya), the mail servers’ domain ending (.com.tr)." — as soon
 * as the wordlist stage starts, and keep it with the run.
 *
 * Loaded with a Subdomains scan's results and with SSL Targets, never on the start route; the
 * strings are registered here. Styles: views/subdomains.css, which SSL Targets loads too.
 * DOM-free at import time (the tests import it in Node).
 */
import { t, registerStrings } from '../i18n.js';
import { h, clear } from './dom.js';
import { Alert } from './components.js';
import { languageName } from '../views/subdomains.js';

/** Pack words named per language in the evidence sentence (the rest is counted). */
const EVIDENCE_WORDS_SHOWN = 5;

/**
 * How a run chose each scanned domain's locale packs: the finished result's
 * `options.wordlist.perDomain` (lib/scanner.js), or — while the wordlist stage runs — the
 * `locales` of its stage event. `[]` before the wordlist stage, or for a level without packs.
 * @param {object} run a Subdomains or SSL Targets run
 * @returns {Array<{ domain: string, locales: string[], source: string|null, evidence: object|null }>}
 */
export function localeChoicesOf(run) {
  const wl = run && run.result && run.result.options ? run.result.options.wordlist : null;
  if (wl && Array.isArray(wl.perDomain)) {
    return wl.perDomain.map((d) => ({ domain: d.domain, locales: d.locales || [], source: d.localeSource || null, evidence: d.localeEvidence || null }));
  }
  const st = run && run.stages ? run.stages.bruteforce : null;
  const list = st && st.info && Array.isArray(st.info.locales) ? st.info.locales : [];
  return list.map((d) => ({ domain: d.domain, locales: d.locales || [], source: d.source || null, evidence: d.evidence || null }));
}

/**
 * One sentence per pack the evidence added (lib/localeevidence.js): "Turkish pack added for
 * example.com. Evidence: words in the names found (bayi, destek, kampanya), the mail servers’
 * domain ending (.com.tr)." Only the packs that loaded, in the order they were picked.
 * @param {ReturnType<typeof localeChoicesOf>} choices
 * @returns {Array<{ domain: string, locale: string, text: string }>}
 */
export function localeEvidenceTexts(choices) {
  const out = [];
  for (const c of Array.isArray(choices) ? choices : []) {
    if (!c || c.source !== 'evidence' || !c.evidence || !Array.isArray(c.evidence.signals)) continue;
    for (const cc of c.locales) {
      const s = c.evidence.signals.find((x) => x.locale === cc);
      if (!s) continue;
      const reasons = [];
      if (s.points && s.points.words > 0 && s.words.length) {
        const shown = s.words.slice(0, EVIDENCE_WORDS_SHOWN);
        const more = Math.max(0, (s.wordCount || shown.length) - shown.length);
        reasons.push(t('sub.loc.words', { list: more ? `${shown.join(', ')} ${t('sub.loc.more', { count: more })}` : shown.join(', ') }));
      }
      if (s.points && s.points.letters > 0 && s.letters.length) reasons.push(t('sub.loc.letters', { list: s.letters.join(', ') }));
      if (s.points && s.points.ns > 0 && s.ns.length) reasons.push(t('sub.loc.ns', { list: s.ns.join(', '), count: s.ns.length }));
      if (s.points && s.points.mx > 0 && s.mx.length) reasons.push(t('sub.loc.mx', { list: s.mx.join(', '), count: s.mx.length }));
      out.push({ domain: c.domain, locale: cc, text: t('sub.loc.added', { language: languageName(cc), domain: c.domain, reasons: reasons.join(', ') }) });
    }
  }
  return out;
}

/**
 * The run header's banner of the packs the evidence added: hidden until one is, then one line
 * per pack (`.sub-locale-line`, with `data-locale` and `data-domain`). Call `render()` when the
 * wordlist stage starts, when the run ends and when a kept run is drawn again; it redraws only
 * when the sentences changed.
 * @param {object} run a Subdomains or SSL Targets run (`result`, `stages`)
 * @returns {{ el: HTMLElement, render: () => void }}
 */
export function LocaleEvidenceBanner(run) {
  const el = h('div', { class: 'sub-locale-host', hidden: true });
  let shown = '';
  function render() {
    const lines = localeEvidenceTexts(localeChoicesOf(run));
    const key = lines.map((l) => l.text).join('\n');
    if (key === shown) return;
    shown = key;
    clear(el);
    el.hidden = !lines.length;
    if (!lines.length) return;
    const alert = Alert({
      variant: 'info',
      compact: true,
      icon: 'globe',
      message: lines.map((l) => h('p', { class: 'sub-locale-line', dataset: { locale: l.locale, domain: l.domain } }, l.text))
    });
    alert.classList.add('sub-locale-banner');
    el.append(alert);
  }
  return { el, render };
}

registerStrings('en', {
  'sub.loc.added': '{language} pack added for {domain}. Evidence: {reasons}.',
  'sub.loc.words': 'words in the names found ({list})',
  'sub.loc.more': 'and {count} more',
  'sub.loc.letters': 'the letters of IDN names ({list})',
  'sub.loc.ns': { one: 'the name servers’ domain ending ({list})', other: 'the name servers’ domain endings ({list})' },
  'sub.loc.mx': { one: 'the mail servers’ domain ending ({list})', other: 'the mail servers’ domain endings ({list})' }
});

registerStrings('tr', {
  'sub.loc.added': '{domain} için {language} paket eklendi. Kanıt: {reasons}.',
  'sub.loc.words': 'bulunan adlardaki kelimeler ({list})',
  'sub.loc.more': 've {count} kelime daha',
  'sub.loc.letters': 'IDN adlarındaki harfler ({list})',
  'sub.loc.ns': { one: 'ad sunucularının alan adı uzantısı ({list})', other: 'ad sunucularının alan adı uzantıları ({list})' },
  'sub.loc.mx': { one: 'posta sunucularının alan adı uzantısı ({list})', other: 'posta sunucularının alan adı uzantıları ({list})' }
});
