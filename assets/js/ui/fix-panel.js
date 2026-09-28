/**
 * ui/fix-panel.js — what a DNS change request (lib/fixes.js) produces, rendered once for every
 * place that has one:
 *
 * - {@link ChangeOutputs}: the record sets as they change (added, kept, removed values), the
 *   instructions for the DNS admin in English and Turkish, the change as BIND, a Route 53 change
 *   batch, the Cloudflare API (curl; the token stays a shell variable), octoDNS and Terraform, and
 *   the "is it live?" link (lib/changecheck.js: only the zone and the expected records are in it).
 * - {@link HealthFixPanel} / {@link LintFixPanel}: "Show the fix" of a Domain Health check or a
 *   Zone File finding — the fix's advice, its records through {@link ChangeOutputs}, and a link
 *   that opens the same change in the DNS change request to edit it. A missing CAA record asks
 *   which CAs issue for the domain from Certificate Transparency (one Cert Spotter request, only
 *   on its click; lib/passport.js lookupCtIssuers).
 *
 * The Health and Zone File views load this module on the first "Show the fix" (it brings the zone
 * parser and linter the validation uses). Every value is DNS data or the user's input: rendered as
 * text, never as HTML. Styles: assets/css/views/fix.css. It lives in ui/ (not views/) because every
 * views/*.js module is a routed view.
 */

import { h, clear, append } from './dom.js';
import {
  Alert, Badge, Button, ButtonLink, CodeBlock, Icon, SegmentedControl, SeverityIcon, Tabs, describeError, setButtonBusy
} from './components.js';
import { downloadText, sanitizeFilename } from './download.js';
import { t, registerStrings, getLang, hasString } from '../i18n.js';
import {
  FIX_FORMATS, FIX_FORMAT_EXT, FIX_I18N, TXT_FAMILIES, FIX_FIELDS, changeTemplate, renderFix, formatNotes, changeInstructions,
  validateChange, hasErrors, rrsetPlan, rrsetAction, valueText, healthFix, lintFix, caaFixFromIssuers, templateInput
} from '../lib/fixes.js';
import { LINT_I18N } from '../lib/zonelint.js';
import { checkFromRequest, encodeCheck } from '../lib/changecheck.js';

// Template, field, format, note, problem and instruction texts ship with lib/fixes.js; the
// linter's finding texts (a change is validated with it) with lib/zonelint.js.
registerStrings('en', FIX_I18N.en);
registerStrings('tr', FIX_I18N.tr);
registerStrings('en', LINT_I18N.en);
registerStrings('tr', LINT_I18N.tr);

registerStrings('en', {
  'fixp.sets': 'What changes',
  'fixp.ttl': 'TTL {ttl}',
  'fixp.notRead': 'The values there now were not read.',
  'fixp.keepOthers': 'The other {type} values of the name stay.',
  'fixp.familyOthers': 'The other TXT records of the name stay.',
  'fixp.admin': 'For the DNS admin',
  'fixp.adminIntro': 'The same request in either language: copy it into the ticket or the email.',
  'fixp.lang': 'Language of the instructions',
  'fixp.download': 'Download',
  'fixp.formats': 'Output formats',
  'fixp.check': 'Is it live?',
  'fixp.checkIntro': 'Once the change is made, this link shows it record by record: four public resolvers (Cloudflare, Google, DNS.SB, CZ.NIC) are asked, each answer reads done, not yet or wrong value, and the page checks again until everything is done.',
  'fixp.checkPrivacy': 'The link holds only the zone and these records — the new values, and the old ones where they were read. Nothing is stored on a server; anyone who opens it asks the resolvers from their own browser.',
  'fixp.checkOpen': 'Open the check',
  'fixp.checkLink': 'Check link',
  'fixp.checkNone.too-long': 'No check link: the expected records would make it longer than {max} characters.',
  'fixp.checkNone.too-many': 'No check link: a link holds at most {sets} record sets and {values} values.',
  'fixp.checkNone.empty': 'No check link: this change has no record to check.',
  'fixp.checkNone.zone': 'No check link: the zone name is missing.',
  'fixp.problems': 'Before you send it',
  'fixp.blocked': 'Fix the errors above first: the change is not written out while it has one.',
  'fixp.edit': 'Edit in DNS change request',
  'fixp.ct.title': 'Which CAs issue for {domain}?',
  'fixp.ct.body': 'A CAA record should name the CAs your certificates come from. The current certificates of {domain} in Certificate Transparency tell which ones; looking them up sends the name to Cert Spotter (one request, crt.sh if it cannot answer).',
  'fixp.ct.run': 'Look up the CAs (1 Cert Spotter request)',
  'fixp.ct.none': 'Certificate Transparency lists no current certificate for {domain}: choose the CAs yourself in the DNS change request.',
  'fixp.ct.failed': 'The CAs could not be looked up ({reason}). Try again, or choose them yourself in the DNS change request.',
  'fixp.ct.found': { one: 'From {count} current certificate in Certificate Transparency ({provider}).', other: 'From {count} current certificates in Certificate Transparency ({provider}).' },
  'fixp.noFix': 'This finding has no automatic fix here.'
});

registerStrings('tr', {
  'fixp.sets': 'Neler değişiyor',
  'fixp.ttl': 'TTL {ttl}',
  'fixp.notRead': 'Şu anki değerler okunmadı.',
  'fixp.keepOthers': 'Adın diğer {type} değerleri kalır.',
  'fixp.familyOthers': 'Adın diğer TXT kayıtları kalır.',
  'fixp.admin': 'DNS yöneticisi için',
  'fixp.adminIntro': 'Aynı talep iki dilde: talebe (ticket) ya da e-postaya kopyalayın.',
  'fixp.lang': 'Talimatların dili',
  'fixp.download': 'İndir',
  'fixp.formats': 'Çıktı biçimleri',
  'fixp.check': 'Yayında mı?',
  'fixp.checkIntro': 'Değişiklik yapıldıktan sonra bu bağlantı onu kayıt kayıt gösterir: dört genel çözümleyiciye (Cloudflare, Google, DNS.SB, CZ.NIC) sorulur, her yanıt tamam, henüz değil ya da yanlış değer olarak gösterilir ve sayfa her şey tamamlanana kadar yeniden kontrol eder.',
  'fixp.checkPrivacy': 'Bağlantı yalnızca zone’u ve bu kayıtları taşır — yeni değerleri ve okunmuşsa eski değerleri. Hiçbir sunucuda bir şey saklanmaz; bağlantıyı açan herkes çözümleyicilere kendi tarayıcısından sorar.',
  'fixp.checkOpen': 'Kontrolü aç',
  'fixp.checkLink': 'Kontrol bağlantısı',
  'fixp.checkNone.too-long': 'Kontrol bağlantısı yok: beklenen kayıtlarla bağlantı {max} karakterden uzun olurdu.',
  'fixp.checkNone.too-many': 'Kontrol bağlantısı yok: bir bağlantı en fazla {sets} kayıt kümesi ve {values} değer taşır.',
  'fixp.checkNone.empty': 'Kontrol bağlantısı yok: bu değişiklikte kontrol edilecek kayıt yok.',
  'fixp.checkNone.zone': 'Kontrol bağlantısı yok: zone adı eksik.',
  'fixp.problems': 'Göndermeden önce',
  'fixp.blocked': 'Önce yukarıdaki hataları düzeltin: hata varken değişiklik yazılmaz.',
  'fixp.edit': 'DNS değişiklik talebinde düzenle',
  'fixp.ct.title': '{domain} için hangi otoriteler sertifika veriyor?',
  'fixp.ct.body': 'CAA kaydı, sertifikalarınızı veren otoriteleri belirtmelidir. {domain} alan adının Sertifika Şeffaflığı’ndaki (CT) güncel sertifikaları hangileri olduğunu söyler; aramak için ad Cert Spotter’a gönderilir (tek istek; yanıt veremezse crt.sh).',
  'fixp.ct.run': 'Otoriteleri bul (1 Cert Spotter isteği)',
  'fixp.ct.none': 'Sertifika Şeffaflığı {domain} için güncel bir sertifika listelemiyor: otoriteleri DNS değişiklik talebinde kendiniz seçin.',
  'fixp.ct.failed': 'Otoriteler bulunamadı ({reason}). Yeniden deneyin ya da DNS değişiklik talebinde kendiniz seçin.',
  'fixp.ct.found': 'Sertifika Şeffaflığı’ndaki {count} güncel sertifikadan ({provider}).',
  'fixp.noFix': 'Bu bulgunun burada otomatik bir düzeltmesi yok.'
});

/** The link of a check (`#/change/check?…`) in this page, and as an absolute URL to share. */
export const checkHash = (query) => `#/change/check?${query}`;
export function checkUrl(query) {
  const base = globalThis.location ? String(globalThis.location.href).split('#')[0] : '';
  return `${base}${checkHash(query)}`;
}

/**
 * The route params that open a template's form in the DNS change request: `t` and every field
 * that differs from its default (lists comma-joined, booleans '1' / '0').
 * @param {string} template
 * @param {Record<string, any>} input
 * @returns {Record<string, string>}
 */
export function builderParams(template, input) {
  const tpl = changeTemplate(template);
  if (!tpl) return {};
  const form = templateInput(template, input);
  const out = { t: template };
  for (const f of tpl.fields) {
    const def = FIX_FIELDS[f];
    const v = form[f];
    if (def.kind === 'check') {
      if (v !== !!def.default) out[f] = v ? '1' : '0';
    } else if (def.kind === 'multi') {
      if (v.join(',') !== (def.default || []).join(',')) out[f] = v.join(',') || '-';
    } else if (String(v) !== '' && String(v) !== String(def.default ?? '')) out[f] = String(v);
  }
  return out;
}

const problemParams = (p) => {
  const params = { ...(p.params || {}) };
  if (Array.isArray(params.types)) params.types = params.types.join(', ');
  return params;
};

/** A change problem (a fix.* or zone.lint.* key) as text in the UI language: a lint finding's title. */
export function problemText(p) {
  return hasString(p.key) ? t(p.key, problemParams(p)) : p.key;
}

/**
 * The problems of a change, errors first, each with its severity icon; a lint finding with its
 * title and what it breaks (`zone.lint.<CODE>.why`).
 * @param {Array<{ severity: string, key: string, params?: object }>} problems
 * @returns {HTMLUListElement}
 */
export function ProblemList(problems) {
  return h('ul', { class: 'fix-problems' }, problems.map((p) => {
    const why = p.key.startsWith('zone.lint.') && hasString(`${p.key}.why`) ? t(`${p.key}.why`, problemParams(p)) : null;
    return h('li', { class: 'fix-problem', dataset: { severity: p.severity, key: p.key } },
      SeverityIcon(p.severity === 'warn' ? 'warn' : p.severity, { size: 16 }),
      h('span', { class: 'fix-problem-text' }, why ? [h('strong', null, problemText(p)), ' ', why] : problemText(p)));
  }));
}

const ACTION_BADGE = Object.freeze({ add: 'ok', replace: 'info', delete: 'error', ttl: 'warn', rewrite: 'info', unchanged: 'neutral' });

/** One record set as it changes: its action, name, type and TTL, then each value added, kept or removed. */
function SetItem(r) {
  const plan = rrsetPlan(r);
  const action = rrsetAction(r, plan);
  const key = (v) => valueText(r.type, v);
  const addKeys = new Set(plan.add.map(key));
  const rows = [];
  const shown = r.mode === 'none' ? [] : (plan.after || r.values);
  for (const v of shown) rows.push(['add', addKeys.has(key(v)) && action !== 'ttl' && action !== 'rewrite' ? 'add' : 'keep', v]);
  for (const v of plan.remove || []) rows.push(['remove', 'remove', v]);
  const notes = [];
  if (plan.remove === null && r.mode !== 'has') notes.push(t('fixp.notRead'));
  if (r.mode === 'has') notes.push(t('fixp.keepOthers', { type: r.type }));
  if (r.family && r.mode !== 'none') notes.push(t('fixp.familyOthers'));
  return h('li', { class: ['fix-set', `fix-set-${action}`], dataset: { action, name: r.name, type: r.type } },
    h('div', { class: 'fix-set-head' },
      Badge(t(`fix.ins.action.${action}`), { variant: ACTION_BADGE[action] }),
      h('span', { class: 'fix-set-type' }, r.family ? `${r.type} · ${TXT_FAMILIES[r.family]}` : r.type),
      h('span', { class: 'fix-set-name mono' }, r.name),
      r.mode !== 'none' ? h('span', { class: 'fix-set-ttl muted' }, t('fixp.ttl', { ttl: r.ttl })) : null),
    rows.length ? h('ul', { class: 'fix-values' }, rows.map(([, kind, v]) => h('li', { class: ['fix-value', `fix-value-${kind}`, 'mono'] },
      h('span', { class: 'fix-value-mark', attrs: { 'aria-hidden': 'true' } }, kind === 'add' ? '+' : kind === 'remove' ? '−' : ' '),
      h('span', { class: 'sr-only' }, kind === 'add' ? `${t('fix.ins.action.add')}: ` : kind === 'remove' ? `${t('fix.ins.action.delete')}: ` : ''),
      h(kind === 'remove' ? 'del' : 'span', { class: 'fix-value-text' }, key(v))))) : null,
    notes.length ? h('p', { class: 'fix-set-note muted text-sm' }, notes.join(' ')) : null);
}

/**
 * Everything a change request produces: the sets, the admin's instructions (English / Turkish),
 * every code format with a download, and the check link.
 * @param {import('../lib/fixes.js').ChangeRequest} req a request without errors
 * @param {{ fileStem?: string, check?: boolean, className?: string }} [opts]
 *   `fileStem`: the downloads' name before the extension; `check`: show the check link (default true)
 * @returns {HTMLElement}
 */
export function ChangeOutputs(req, { fileStem = null, check = true, className = '' } = {}) {
  const link = check ? encodeCheck(checkFromRequest(req)) : null;
  const url = link && link.ok ? checkUrl(link.query) : null;
  const stem = sanitizeFilename(fileStem || `dns-change-${req.zone || 'zone'}`);
  let lang = getLang();

  const adminHost = h('div', { class: 'fix-admin-text' });
  const renderAdmin = () => {
    clear(adminHost);
    adminHost.append(CodeBlock(changeInstructions(req, { lang, checkUrl: url }), { wrap: true, label: lang === 'tr' ? 'Türkçe' : 'English', className: 'fix-code' }));
  };
  const langCtl = SegmentedControl({
    label: t('fixp.lang'),
    size: 'sm',
    value: lang,
    className: 'fix-lang',
    options: [{ value: 'en', label: 'English' }, { value: 'tr', label: 'Türkçe' }],
    onChange: (v) => {
      lang = v;
      renderAdmin();
    }
  });
  langCtl.el.dataset.control = 'fix-lang';
  renderAdmin();
  const adminTab = h('div', { class: 'stack-sm fix-tab' },
    h('div', { class: 'fix-tab-head' }, h('p', { class: 'muted text-sm fix-how' }, t('fixp.adminIntro')), langCtl.el),
    adminHost);

  const formatTab = (format) => () => {
    const text = renderFix(req, format);
    const notes = formatNotes(req, format);
    return h('div', { class: 'stack-sm fix-tab', dataset: { format } },
      h('div', { class: 'fix-tab-head' },
        h('p', { class: 'muted text-sm fix-how' }, t(`fix.fmt.${format}.how`)),
        Button({
          label: t('fixp.download'), icon: 'download', size: 'sm', variant: 'ghost', dataset: { action: 'fix-download', format },
          onClick: () => downloadText(`${stem}.${FIX_FORMAT_EXT[format]}`, text, format === 'route53' ? 'application/json;charset=utf-8' : 'text/plain;charset=utf-8')
        })),
      notes.length ? Alert({ variant: 'warn', compact: true, message: h('ul', { class: 'fix-format-notes' }, notes.map((n) => h('li', null, t(n.key, n.params)))) }) : null,
      CodeBlock(text, { label: t(`fix.fmt.${format}`), className: 'fix-code', maxHeight: '28rem' }));
  };
  const tabs = Tabs([
    { id: 'admin', label: t('fixp.admin'), content: adminTab },
    ...FIX_FORMATS.map((f) => ({ id: f, label: t(`fix.fmt.${f}`), content: formatTab(f) }))
  ], { label: t('fixp.formats'), className: 'fix-tabs' });

  let checkEl = null;
  if (check) {
    checkEl = h('section', { class: 'fix-check card', dataset: { check: link.ok ? 'ok' : link.reason } },
      h('h3', { class: 'fix-check-title' }, Icon('globe', { size: 16 }), ' ', t('fixp.check')),
      link.ok ? [
        h('p', { class: 'text-sm fix-check-intro' }, t('fixp.checkIntro')),
        CodeBlock(url, { label: t('fixp.checkLink'), wrap: true, className: 'fix-check-url' }),
        h('div', { class: 'cluster fix-check-actions' },
          ButtonLink({ href: checkHash(link.query), label: t('fixp.checkOpen'), icon: 'arrow-right', size: 'sm', variant: 'primary' })),
        h('p', { class: 'muted text-sm fix-check-privacy' }, Icon('lock', { size: 14 }), ' ', t('fixp.checkPrivacy'))
      ] : Alert({ variant: 'info', compact: true, message: t(`fixp.checkNone.${link.reason}`, { max: 4000, sets: 20, values: 40 }) }));
  }

  return h('div', { class: ['stack', 'fix-outputs', className] },
    h('section', { class: 'fix-sets-section' },
      h('h3', { class: 'fix-sets-title' }, t('fixp.sets')),
      h('ul', { class: 'fix-sets' }, req.rrsets.map(SetItem))),
    tabs.el,
    checkEl);
}

/**
 * A fix's body: its advice, then (records) the change's problems and outputs, and the link that
 * opens it in the DNS change request.
 * @param {import('../lib/fixes.js').Fix|null} fix
 * @param {{ ctx: object, domain?: string|null }} opts
 * @returns {HTMLElement}
 */
export function FixPanel(fix, { ctx, domain = null } = {}) {
  const el = h('div', { class: 'stack-sm fix-panel', dataset: { fix: fix ? fix.id : 'none', kind: fix ? fix.kind : 'none' } });
  const render = (f) => {
    clear(el);
    if (!f) {
      el.append(h('p', { class: 'muted text-sm' }, t('fixp.noFix')));
      return;
    }
    el.dataset.kind = f.kind;
    for (const a of f.advice) el.append(h('p', { class: 'fix-advice text-sm' }, Icon('lightbulb', { size: 14 }), ' ', t(a.key, a.params)));
    const edit = f.template ? ButtonLink({ href: ctx.href('change', builderParams(f.template, f.input)), label: t('fixp.edit'), icon: 'edit', size: 'sm', variant: 'ghost' }) : null;
    if (f.kind === 'records' && f.needsCt) {
      append(el, ctBlock(f), edit ? h('div', { class: 'cluster' }, edit) : null);
      return;
    }
    if (f.kind === 'records' && f.request) {
      const problems = validateChange(f.request);
      if (problems.length) el.append(h('div', { class: 'fix-problems-wrap' }, h('h3', { class: 'fix-sets-title' }, t('fixp.problems')), ProblemList(problems)));
      if (hasErrors({ problems })) el.append(h('p', { class: 'text-sm' }, t('fixp.blocked')));
      else el.append(ChangeOutputs(f.request, { fileStem: `dns-fix-${f.id}-${f.request.zone || ''}` }));
    }
    if (edit) el.append(h('div', { class: 'cluster fix-edit' }, edit));
  };

  /** A missing CAA record: which CAs issue, from Certificate Transparency, on a click. */
  const ctBlock = (f) => {
    const name = domain || (f.input && f.input.domain) || '';
    const status = h('div', { class: 'fix-ct-status', attrs: { 'aria-live': 'polite' } });
    const btn = Button({
      label: t('fixp.ct.run'), icon: 'search', size: 'sm', variant: 'primary', dataset: { action: 'fix-ct' },
      onClick: async () => {
        if (!ctx.requireOnline()) return;
        setButtonBusy(btn, true);
        clear(status);
        try {
          const { lookupCtIssuers } = await import('../lib/passport.js');
          const res = await lookupCtIssuers(name, { signal: ctx.signal });
          if (res.status !== 'ok') {
            status.append(Alert({ variant: 'warn', compact: true, message: t('fixp.ct.failed', { reason: res.failures.map((x) => x.error || x.errorKind).filter(Boolean).join('; ') || '—' }) }));
          } else if (!res.issuers.length) {
            status.append(Alert({ variant: 'info', compact: true, message: t('fixp.ct.none', { domain: name }) }));
          } else {
            render(caaFixFromIssuers(f, res.issuers));
            el.prepend(h('p', { class: 'muted text-sm fix-ct-found' }, t('fixp.ct.found', { count: res.certificates, provider: res.provider === 'crtsh' ? 'crt.sh' : 'Cert Spotter' })));
            return;
          }
        } catch (err) {
          if (err && err.name === 'AbortError') return;
          ctx.checkOutdated();
          status.append(Alert({ variant: 'warn', compact: true, message: t('fixp.ct.failed', { reason: describeError(err).message }) }));
        }
        setButtonBusy(btn, false);
      }
    });
    return h('div', { class: 'stack-sm fix-ct', dataset: { ct: 'ask' } },
      h('h3', { class: 'fix-sets-title' }, t('fixp.ct.title', { domain: name })),
      h('p', { class: 'text-sm' }, t('fixp.ct.body', { domain: name })),
      h('div', { class: 'cluster' }, btn),
      status);
  };

  render(fix);
  return el;
}

/**
 * "Show the fix" of a Domain Health check.
 * @param {{ id: string }} check
 * @param {object} report the lib/health.js report
 * @param {{ ctx: object }} opts
 * @returns {HTMLElement}
 */
export function HealthFixPanel(check, report, { ctx }) {
  return FixPanel(healthFix(check, report), { ctx, domain: report && report.domain });
}

/**
 * "Show the fix" of a Zone File finding.
 * @param {{ code: string, name: string, type: string, params?: object }} finding
 * @param {object} zone the parsed zone
 * @param {{ ctx: object }} opts
 * @returns {HTMLElement}
 */
export function LintFixPanel(finding, zone, { ctx }) {
  return FixPanel(lintFix(finding, zone), { ctx });
}
