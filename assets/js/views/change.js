/**
 * views/change.js — "DNS change request": one DNS change, written once for everyone who touches it.
 *
 * Main page (`#/change`): pick a template (ACME DNS-01 TXT, a CNAME delegation of
 * `_acme-challenge`, Microsoft 365 or Google Workspace mail, CAA for your CAs, an SPF include,
 * a DMARC step-up, lowered TTLs, one plain record set, a parked domain's lock-down) and fill the
 * form. lib/fixes.js builds the change as you type — nothing is sent — and checks it with the
 * zone linter; ui/fix-panel.js shows the admin's instructions in English and Turkish, BIND,
 * Route 53, the Cloudflare API, octoDNS, Terraform and the "is it live?" link. "Read the current
 * records", only on its click, asks your DoH resolvers for the names and types the change
 * touches (names and types only): the change then keeps what it must keep (a whole-set Route 53
 * UPSERT, the other TXT records next to an SPF record), removes old values by value, and counts
 * the new SPF record's lookups with its includes as they are published now.
 *
 * Check page (`#/change/check?z=example.com&r=…`): the expected records come from the link alone
 * (lib/changecheck.js), which holds nothing else. Four public resolvers are asked for each record;
 * each answer reads done, not yet or wrong value. The page asks again with a growing wait, never
 * before a resolver's cached answer can have expired, and stops when every record is done, after
 * two hours, or when nothing can change before then (a long TTL). Stop / Check now / Check again.
 *
 * Shareable: `#/change?t=caa&domain=example.com&cas=letsencrypt` opens a form (the "Edit in DNS
 * change request" of Domain Health and Zone File); a carried target fills the domain
 * (`domain=…&run=0`). The form and a check's answers are kept for the page session (module
 * state), and forgotten on "Delete all local data" and a workspace switch.
 */

import { h, clear, debounce } from '../ui/dom.js';
import {
  Alert, Badge, Button, Card, CopyButton, EmptyState, Icon, SeverityIcon, announce, checkbox, checkboxGroup, select, setButtonBusy, textInput,
  textarea
} from '../ui/components.js';
import { registerStrings, hasString, localeTag, formatDateTime, formatDuration, formatNumber } from '../i18n.js';
import { state as stateSingleton } from '../state.js';
import {
  CHANGE_TEMPLATES, FIX_FIELDS, FIX_CAS, TEMPLATE_IDS, TXT_FAMILIES, buildChange, changeTemplate, templateInput, validateChange, hasErrors,
  readCurrent, countSpfLookups, valueText
} from '../lib/fixes.js';
import { CHECK_RESOLVERS, CHECK_LIMITS, decodeCheck, checkRound, checkState, nextCheck, pairKey } from '../lib/changecheck.js';
import { normalizeHostname, registrableDomain } from '../lib/domain.js';
import { getResolver } from '../lib/resolvers.js';
import { isFillOnly } from '../lib/session.js';
import { ChangeOutputs, ProblemList, builderParams, checkUrl } from '../ui/fix-panel.js';

/** Route id (`#/change`). */
export const id = 'change';
/** i18n key of the page title. */
export const titleKey = 'nav.change';
/** Icon name (ui/components.js Icon). */
export const icon = 'edit';

registerStrings('en', {
  'chg.template': 'Template',
  'chg.form': 'The change',
  'chg.read': 'Read the current records',
  'chg.readAgain': 'Read again',
  'chg.privacy': 'Nothing is sent while you fill in the form. “Read the current records” sends only the names and record types of the change to your DNS-over-HTTPS resolvers.',
  'chg.needsRead': 'This change is built from what the names hold now: read the current records first, or the outputs say what they cannot know.',
  'chg.readDone': { one: 'Current records read at {time}: {count} name and type.', other: 'Current records read at {time}: {count} names and types.' },
  'chg.readFailed': { one: '{count} lookup got no answer: its values stay unknown.', other: '{count} lookups got no answer: their values stay unknown.' },
  'chg.readStale': 'The form names records that were not read: read again to include them.',
  'chg.readError': 'The current records could not be read ({reason}).',
  'chg.spfCounting': 'SPF lookups counted with the includes as they are published now.',
  'chg.problems': 'Before you send it',
  'chg.blocked': 'Fix the errors above: the change is written out once it has none.',
  'chg.emptyTitle': 'A DNS change, written once for everyone',
  'chg.emptyBody': 'Fill in the form: the instructions for the DNS admin, the code for BIND, Route 53, Cloudflare, octoDNS and Terraform, and a link that shows when the change is live appear here.',
  'chg.check.title': 'Is the change live?',
  'chg.check.zone': 'Zone {zone}',
  'chg.check.head.done': 'Done: every resolver sees the change.',
  'chg.check.head.done-partial': { one: 'Done on every resolver that answered; {count} resolver did not answer.', other: 'Done on every resolver that answered; {count} resolvers did not answer.' },
  'chg.check.head.wrong': 'A resolver serves a value that is neither the new nor the old one: check what was published.',
  'chg.check.head.pending': { one: 'Not live everywhere yet: {done} of {count} record set done.', other: 'Not live everywhere yet: {done} of {count} record sets done.' },
  'chg.check.head.unknown': 'Asking the resolvers…',
  'chg.check.stop.timeout': 'Stopped after two hours. Check again when the change has been made.',
  'chg.check.stop.cached': 'Stopped: the resolvers that are not done yet keep their cached answer until {time}, so asking before then shows nothing new.',
  'chg.check.stop.user': 'Stopped.',
  'chg.check.checked': 'Checked {time}',
  'chg.check.next': 'Next check in {wait}',
  'chg.check.running': 'Checking…',
  'chg.check.now': 'Check now',
  'chg.check.stop': 'Stop',
  'chg.check.again': 'Check again',
  'chg.check.copy': 'Copy link',
  'chg.check.mode.is': 'must be exactly',
  'chg.check.mode.has': 'must include',
  'chg.check.mode.none': 'must be gone',
  'chg.check.maxTtl': 'resolvers’ copies expiring within {ttl} s',
  'chg.check.expected': 'Expected',
  'chg.check.old': 'Before',
  'chg.check.nothing': 'no record',
  'chg.check.v.done': 'Done',
  'chg.check.v.waiting': 'Asking…',
  'chg.check.v.wrong': 'Wrong value',
  'chg.check.v.error': 'No answer ({reason})',
  'chg.check.p.missing': 'Not yet: no record',
  'chg.check.p.old': 'Not yet: still the old value',
  'chg.check.p.other': 'Not yet: another value',
  'chg.check.p.partial': 'Not yet: values missing',
  'chg.check.p.ttl': 'Not yet: cached with the old TTL',
  'chg.check.p.present': 'Not yet: still there',
  'chg.check.seen': 'Serves',
  'chg.check.cached': 'cached until {time}',
  'chg.check.privacy': 'Everything on this page came from its link: the zone and the records above, nothing else. The page asks four public DNS resolvers — names and record types only — from your browser; nothing is stored on a server.',
  'chg.check.own': 'Write a DNS change request',
  'chg.check.bad': 'This check link cannot be read',
  'chg.check.bad.too-long': 'It is longer than {max} characters.',
  'chg.check.bad.too-many': 'It holds more record sets or values than a check takes.',
  'chg.check.bad.version': 'It was made by a newer version of DomainScope.',
  'chg.check.bad.zone': 'Its zone name is missing or invalid.',
  'chg.check.bad.empty': 'It holds no record to check.',
  'chg.check.bad.set': 'One of its records cannot be read: {detail}',
  'chg.check.offline': 'You are offline: the check starts when you press Check now with a connection.'
});

registerStrings('tr', {
  'chg.template': 'Şablon',
  'chg.form': 'Değişiklik',
  'chg.read': 'Mevcut kayıtları oku',
  'chg.readAgain': 'Yeniden oku',
  'chg.privacy': 'Formu doldururken hiçbir şey gönderilmez. “Mevcut kayıtları oku” yalnızca değişikliğin adlarını ve kayıt türlerini DNS-over-HTTPS çözümleyicilerinize gönderir.',
  'chg.needsRead': 'Bu değişiklik adların şu an tuttuklarından oluşturulur: önce mevcut kayıtları okuyun; yoksa çıktılar bilemediklerini belirtir.',
  'chg.readDone': 'Mevcut kayıtlar {time} saatinde okundu: {count} ad ve tür.',
  'chg.readFailed': '{count} sorgu yanıt almadı: değerleri bilinmiyor.',
  'chg.readStale': 'Formda okunmamış kayıtlar var: onları da almak için yeniden okuyun.',
  'chg.readError': 'Mevcut kayıtlar okunamadı ({reason}).',
  'chg.spfCounting': 'SPF sorguları include’ların şu anki hâliyle sayıldı.',
  'chg.problems': 'Göndermeden önce',
  'chg.blocked': 'Yukarıdaki hataları düzeltin: hata kalmayınca değişiklik yazılır.',
  'chg.emptyTitle': 'Bir DNS değişikliği, herkes için bir kez yazılır',
  'chg.emptyBody': 'Formu doldurun: DNS yöneticisi için talimatlar, BIND, Route 53, Cloudflare, octoDNS ve Terraform kodu ve değişikliğin ne zaman yayında olduğunu gösteren bir bağlantı burada belirir.',
  'chg.check.title': 'Değişiklik yayında mı?',
  'chg.check.zone': 'Zone {zone}',
  'chg.check.head.done': 'Tamam: tüm çözümleyiciler değişikliği görüyor.',
  'chg.check.head.done-partial': 'Yanıt veren tüm çözümleyicilerde tamam; {count} çözümleyici yanıt vermedi.',
  'chg.check.head.wrong': 'Bir çözümleyici ne yeni ne de eski olan bir değer döndürüyor: yayınlananı kontrol edin.',
  'chg.check.head.pending': 'Henüz her yerde yayında değil: {count} kayıt kümesinden {done} tanesi tamam.',
  'chg.check.head.unknown': 'Çözümleyicilere soruluyor…',
  'chg.check.stop.timeout': 'İki saat sonra durduruldu. Değişiklik yapıldığında yeniden kontrol edin.',
  'chg.check.stop.cached': 'Durduruldu: henüz tamamlanmayan çözümleyiciler önbellekteki yanıtlarını {time} saatine kadar tutar; o zamandan önce sormak yeni bir şey göstermez.',
  'chg.check.stop.user': 'Durduruldu.',
  'chg.check.checked': 'Kontrol: {time}',
  'chg.check.next': 'Sonraki kontrol {wait} sonra',
  'chg.check.running': 'Kontrol ediliyor…',
  'chg.check.now': 'Şimdi kontrol et',
  'chg.check.stop': 'Durdur',
  'chg.check.again': 'Yeniden kontrol et',
  'chg.check.copy': 'Bağlantıyı kopyala',
  'chg.check.mode.is': 'tam olarak bu olmalı',
  'chg.check.mode.has': 'bunları içermeli',
  'chg.check.mode.none': 'kalkmış olmalı',
  'chg.check.maxTtl': 'çözümleyicilerdeki kopyalar {ttl} sn içinde sona ermeli',
  'chg.check.expected': 'Beklenen',
  'chg.check.old': 'Önceki',
  'chg.check.nothing': 'kayıt yok',
  'chg.check.v.done': 'Tamam',
  'chg.check.v.waiting': 'Soruluyor…',
  'chg.check.v.wrong': 'Yanlış değer',
  'chg.check.v.error': 'Yanıt yok ({reason})',
  'chg.check.p.missing': 'Henüz değil: kayıt yok',
  'chg.check.p.old': 'Henüz değil: hâlâ eski değer',
  'chg.check.p.other': 'Henüz değil: başka bir değer',
  'chg.check.p.partial': 'Henüz değil: eksik değerler var',
  'chg.check.p.ttl': 'Henüz değil: eski TTL ile önbellekte',
  'chg.check.p.present': 'Henüz değil: hâlâ duruyor',
  'chg.check.seen': 'Döndürdüğü',
  'chg.check.cached': '{time} saatine kadar önbellekte',
  'chg.check.privacy': 'Bu sayfadaki her şey bağlantısından geldi: zone ve yukarıdaki kayıtlar, başka hiçbir şey. Sayfa dört genel DNS çözümleyicisine — yalnızca adlar ve kayıt türleri — tarayıcınızdan sorar; hiçbir sunucuda bir şey saklanmaz.',
  'chg.check.own': 'DNS değişiklik talebi yazın',
  'chg.check.bad': 'Bu kontrol bağlantısı okunamıyor',
  'chg.check.bad.too-long': '{max} karakterden uzun.',
  'chg.check.bad.too-many': 'Bir kontrolün alabileceğinden fazla kayıt kümesi ya da değer taşıyor.',
  'chg.check.bad.version': 'DomainScope’un daha yeni bir sürümüyle oluşturulmuş.',
  'chg.check.bad.zone': 'Zone adı eksik ya da geçersiz.',
  'chg.check.bad.empty': 'Kontrol edilecek bir kayıt taşımıyor.',
  'chg.check.bad.set': 'Kayıtlarından biri okunamıyor: {detail}',
  'chg.check.offline': 'Çevrimdışısınız: kontrol, bağlantı varken Şimdi kontrol et’e bastığınızda başlar.'
});

/* ------------------------------------------------------------------------ */
/* Module state (page session only)                                          */
/* ------------------------------------------------------------------------ */

/** The form: the template on screen and each template's values, the carried domain, the last read. */
let draft = null;
/** The last check: its query, answers and timing, so a language switch or a return resumes it. */
let checkMemo = null;

function freshDraft() {
  return { template: 'acme-txt', forms: {}, carried: null, read: null };
}

stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared' && key !== 'workspace') return;
  draft = null;
  if (checkMemo && checkMemo.timer) clearTimeout(checkMemo.timer);
  checkMemo = null;
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/** A time of day in the UI language ('14:02:07'), a date too when it is not today. */
function clockTime(at) {
  const d = at instanceof Date ? at : new Date(at);
  const today = new Date().toDateString() === d.toDateString();
  return today ? new Intl.DateTimeFormat(localeTag(), { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(d) : formatDateTime(d);
}

/** The field a carried domain fills in a template: its domain, else its name. */
export function subjectField(template) {
  const tpl = changeTemplate(template);
  if (!tpl) return null;
  return tpl.fields.includes('domain') ? 'domain' : tpl.fields.includes('name') ? 'name' : null;
}

/**
 * The form a route opens: `t=<template>` with its fields (a shared form, "Edit in DNS change
 * request"), else null.
 * @param {Record<string, string>} params
 * @returns {{ template: string, input: Record<string, any> }|null}
 */
export function routeForm(params) {
  const template = TEMPLATE_IDS.includes(params.t) ? params.t : null;
  if (!template) return null;
  const input = {};
  for (const f of changeTemplate(template).fields) {
    if (params[f] === undefined) continue;
    input[f] = FIX_FIELDS[f].kind === 'multi' && params[f] === '-' ? [] : params[f];
  }
  return { template, input: templateInput(template, input) };
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * Mount the view: the check page for `#/change/check`, else the form.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  if (ctx.sub === 'check') return mountCheck(container, ctx);
  return mountBuilder(container, ctx);
}

/* --- the form ------------------------------------------------------------------- */

function mountBuilder(container, ctx) {
  const { t } = ctx;
  if (!draft) draft = freshDraft();
  const fromRoute = routeForm(ctx.params);
  if (fromRoute) {
    draft.template = fromRoute.template;
    draft.forms[fromRoute.template] = fromRoute.input;
  }
  const formOf = (tpl) => {
    if (!draft.forms[tpl]) draft.forms[tpl] = templateInput(tpl, {});
    return draft.forms[tpl];
  };
  // A carried domain fills the form's domain (or name) while it is empty or holds the last carried one.
  const carried = !fromRoute && typeof ctx.params.domain === 'string' ? ctx.params.domain.trim() : '';
  if (carried) {
    const f = subjectField(draft.template);
    const form = formOf(draft.template);
    if (f && (!form[f] || form[f] === draft.carried || !isFillOnly(ctx.params))) form[f] = carried;
    draft.carried = isFillOnly(ctx.params) ? carried : null;
  }

  const tplSelect = select({
    label: t('chg.template'),
    options: CHANGE_TEMPLATES.map((x) => ({ value: x.id, label: t(`fix.tpl.${x.id}`) })),
    value: draft.template,
    className: 'chg-template',
    onChange: (v) => {
      draft.template = v;
      renderFields();
      rebuild();
    }
  });
  tplSelect.input.dataset.role = 'change-template';
  const tplDesc = h('p', { class: 'muted text-sm chg-template-desc' });
  const fieldsEl = h('div', { class: 'chg-fields' });
  // The form's one action: Ctrl/Cmd+Enter reads the current records (nothing else is ever sent).
  const readBtn = Button({ label: t('chg.read'), icon: 'search', dataset: { action: 'change-read', shortcut: 'submit' }, onClick: () => readNow() });
  const readNote = h('div', { class: 'chg-read-note text-sm', attrs: { 'aria-live': 'polite' } });
  const formCard = Card({
    className: 'chg-form-card',
    children: h('div', { class: 'stack' },
      h('div', { class: 'stack-sm' }, tplSelect.el, tplDesc),
      fieldsEl,
      h('div', { class: 'chg-form-foot' },
        h('p', { class: 'muted text-sm chg-privacy' }, Icon('lock', { size: 14 }), ' ', t('chg.privacy')),
        h('div', { class: 'chg-buttons' }, readBtn)),
      readNote)
  });
  const problemsEl = h('div', { class: 'chg-problems' });
  // A form of its own for the shell's Ctrl/Cmd+Enter: nothing in the outputs reads the records.
  const outputsEl = h('div', { class: 'chg-outputs', dataset: { shortcutScope: 'results' } });
  container.append(h('div', { class: 'stack-lg chg-view', dataset: { page: 'builder' } }, formCard, problemsEl, outputsEl));

  /** The widgets of the fields on screen: id → { el, get() }. */
  let widgets = {};
  const onInput = debounce(() => rebuild(), 180);
  const store = (f, v) => {
    formOf(draft.template)[f] = v;
  };

  function fieldLabel(f) {
    if (f === 'name' && draft.template.startsWith('acme-')) return [t('fix.field.name.acme'), t('fix.field.name.acme.hint')];
    const key = `fix.field.${f}`;
    const tpl = changeTemplate(draft.template);
    const hintKey = `${key}.hint`;
    let hint = null;
    if (f === 'ttl') hint = t(hintKey, { ttl: tpl.ttl });
    else if (f === 'zone') hint = t(hintKey, { zone: defaultZone() });
    else if (hasString(hintKey)) hint = t(hintKey);
    return [t(key), hint];
  }

  function widgetFor(f) {
    const def = FIX_FIELDS[f];
    const value = formOf(draft.template)[f];
    const [label, hint] = fieldLabel(f);
    const attrs = { 'data-field': f };
    if (def.kind === 'check') {
      const cb = checkbox({ label, checked: !!value, hint, onChange: (on) => { store(f, on); rebuild(); } });
      cb.input.dataset.field = f;
      return { el: cb.el };
    }
    if (def.kind === 'select') {
      const s = select({
        label, hint, value,
        options: def.options.map((o) => ({ value: o, label: def.literal ? o : t(`fix.opt.${f}.${o}`) })),
        onChange: (v) => { store(f, v); rebuild(); }
      });
      s.input.dataset.field = f;
      return { el: s.el };
    }
    if (def.kind === 'multi') {
      const options = f === 'cas' ? FIX_CAS.map((c) => ({ value: c.id, label: c.name })) : def.options.map((o) => ({ value: o, label: o }));
      const g = checkboxGroup({ legend: label, hint, options, values: value, inline: true, onChange: (vals) => { store(f, vals); rebuild(); } });
      g.el.dataset.field = f;
      return { el: g.el };
    }
    if (def.kind === 'lines' || f === 'dkimKey') {
      const ta = textarea({
        label, hint, value, rows: f === 'dkimKey' ? 3 : 4, wrap: f === 'dkimKey', attrs,
        onInput: (v) => { store(f, v); onInput(); }
      });
      return { el: ta.el };
    }
    const mono = ['domain', 'name', 'target', 'mxHost', 'tenant', 'zone', 'dkimSelector', 'accountUri'].includes(f);
    const input = textInput({
      label, hint, value, mono,
      optional: !!def.optional,
      inputmode: def.kind === 'ttl' || def.kind === 'number' ? 'numeric' : def.kind === 'email' ? 'email' : null,
      placeholder: placeholderOf(f),
      attrs: { ...attrs, ...(f === subjectField(draft.template) ? { 'data-shortcut': 'focus' } : {}) },
      onInput: (v) => { store(f, v); onInput(); }
    });
    return { el: input.el };
  }

  /** The zone an empty zone field stands for: the registrable domain of the domain / name. */
  function defaultZone() {
    const subject = String(formOf(draft.template)[subjectField(draft.template)] ?? '').trim().replace(/^\*\./, '');
    const host = normalizeHostname(subject);
    return (host && registrableDomain(host.replace(/^_[^.]*\./, ''))) || 'example.com';
  }

  function placeholderOf(f) {
    switch (f) {
      case 'domain': return 'example.com';
      case 'name': return draft.template.startsWith('acme-') ? '*.example.com' : 'www.example.com';
      case 'target': return 'd420c923.auth.example.net';
      case 'rua': case 'iodef': return 'dmarc-reports@example.com';
      case 'tenant': return 'example.onmicrosoft.com';
      case 'accountUri': return 'https://acme-v02.api.letsencrypt.org/acme/acct/123456';
      case 'ttl': return String(changeTemplate(draft.template).ttl);
      case 'pct': return '100';
      default: return '';
    }
  }

  function renderFields() {
    clear(fieldsEl);
    widgets = {};
    tplSelect.value = draft.template;
    tplDesc.textContent = t(`fix.tpl.${draft.template}.desc`);
    for (const f of changeTemplate(draft.template).fields) {
      widgets[f] = widgetFor(f);
      const wide = ['lines', 'multi'].includes(FIX_FIELDS[f].kind) || f === 'dkimKey';
      fieldsEl.append(h('div', { class: ['chg-field', { 'chg-field-wide': wide }], dataset: { fieldBox: f } }, widgets[f].el));
    }
  }

  /* --- build ---------------------------------------------------------------------- */
  let req = null;

  /** What the last read found, when it read this request's zone. */
  function currentFor(zone) {
    return draft.read && draft.read.zone === zone && draft.read.template === draft.template ? draft.read : null;
  }

  function rebuild() {
    const form = formOf(draft.template);
    const first = buildChange(draft.template, form, {});
    const read = currentFor(first.zone);
    req = read ? buildChange(draft.template, form, { current: read.current }) : first;
    const problems = validateChange(req, read ? { current: read.current, spf: read.spf } : {});
    const params = builderParams(draft.template, form);
    if (JSON.stringify(params) !== JSON.stringify(ctx.params)) ctx.setParams(params);
    renderReadNote(read);
    clear(problemsEl);
    clear(outputsEl);
    const tpl = changeTemplate(draft.template);
    const unread = tpl.needsCurrent && !read && first.zone;
    if (unread) problemsEl.append(Alert({ variant: 'info', compact: true, message: t('chg.needsRead') }));
    const shown = problems.filter((p) => !(unread && p.key === 'fix.p.read-first'));
    const started = !first.problems.some((p) => p.key === 'fix.p.domain-missing' || p.key === 'fix.p.name-missing');
    if (!started) {
      outputsEl.append(h('div', { class: 'card chg-empty' }, EmptyState({ icon: 'edit', title: t('chg.emptyTitle'), message: t('chg.emptyBody') })));
      return;
    }
    if (shown.length) {
      problemsEl.append(h('section', { class: 'card chg-problems-card', dataset: { problems: shown.length } },
        h('h2', { class: 'section-title' }, t('chg.problems')), ProblemList(shown)));
    }
    if (hasErrors({ problems })) {
      outputsEl.append(h('p', { class: 'muted text-sm chg-blocked' }, t('chg.blocked')));
      return;
    }
    outputsEl.append(ChangeOutputs(req, { fileStem: `dns-change-${req.zone}` }));
  }

  function renderReadNote(read) {
    clear(readNote);
    readBtn.querySelector('.btn-label').textContent = read ? t('chg.readAgain') : t('chg.read');
    if (!read) return;
    const lines = [t('chg.readDone', { time: clockTime(read.at), count: read.count })];
    if (read.failed) lines.push(t('chg.readFailed', { count: read.failed }));
    if (req && req.reads.some((q) => !Object.hasOwn(read.current, `${q.name}|${q.type}`))) lines.push(t('chg.readStale'));
    if (read.spf && Object.keys(read.spf).length) lines.push(t('chg.spfCounting'));
    readNote.append(h('p', { class: 'muted', title: formatDateTime(read.at) }, Icon('check', { size: 14 }), ' ', lines.join(' ')));
  }

  /* --- read the current records ----------------------------------------------------- */
  async function readNow() {
    const base = buildChange(draft.template, formOf(draft.template), {});
    if (!base.zone || !base.reads.length) {
      rebuild();
      return;
    }
    if (!ctx.requireOnline()) return;
    ctx.runStarted(base.zone);
    setButtonBusy(readBtn, true);
    ctx.setBusy(t('chg.read'));
    try {
      const dns = await ctx.getDns();
      // What the template looks at (the SPF record it edits, the records whose TTL it lowers) and
      // what its records collide with; then what the change built from those answers adds.
      const current = await readCurrent(base.reads, { dns, signal: ctx.signal });
      const next = buildChange(draft.template, formOf(draft.template), { current });
      const extra = next.reads.filter((q) => !Object.hasOwn(current, `${q.name}|${q.type}`));
      if (extra.length) Object.assign(current, await readCurrent(extra, { dns, signal: ctx.signal }));
      const spf = await countSpfLookups(buildChange(draft.template, formOf(draft.template), { current }), { dns, signal: ctx.signal });
      const values = Object.values(current);
      draft.read = { template: draft.template, zone: base.zone, current, spf, at: new Date(), count: values.length, failed: values.filter((c) => c.status === 'error').length };
      rebuild();
      announce(readNote.textContent);
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      ctx.checkOutdated();
      clear(readNote);
      readNote.append(Alert({ variant: 'warn', compact: true, message: t('chg.readError', { reason: err && err.message ? err.message : String(err) }) }));
    } finally {
      if (readBtn.isConnected) setButtonBusy(readBtn, false);
      ctx.setBusy(false);
    }
  }

  renderFields();
  rebuild();
}

/* --- the check page --------------------------------------------------------------- */

const VERDICT_BADGE = Object.freeze({ done: ['ok', 'check-circle'], pending: ['warn', 'clock'], wrong: ['error', 'x-circle'], error: ['neutral', 'help'], waiting: ['neutral', 'clock'] });
const HEAD_VARIANT = Object.freeze({ done: 'ok', 'done-partial': 'ok', wrong: 'error', pending: 'warn', unknown: 'info' });

function mountCheck(container, ctx) {
  const { t } = ctx;
  const decoded = decodeCheck(ctx.searchParams);
  const view = h('div', { class: 'stack-lg chg-view chg-check', dataset: { page: 'check' } });
  container.append(view);
  if (!decoded.ok) {
    view.dataset.state = 'bad';
    view.append(Alert({
      variant: 'error',
      title: t('chg.check.bad'),
      message: t(`chg.check.bad.${decoded.error}`, { max: formatNumber(CHECK_LIMITS.chars), detail: decoded.detail || '' }),
      actions: [h('a', { class: 'btn btn-secondary btn-sm', href: ctx.href('change') }, t('chg.check.own'))]
    }));
    return;
  }
  const check = decoded.check;
  // The link as it was opened (its readable form), for Copy link and to resume the same check.
  const hash = String(globalThis.location ? globalThis.location.hash : '');
  const query = hash.startsWith('#/change/check?') ? hash.slice('#/change/check?'.length) : ctx.searchParams.toString();
  if (!checkMemo || checkMemo.query !== query) {
    if (checkMemo && checkMemo.timer) clearTimeout(checkMemo.timer);
    checkMemo = { query, latest: new Map(), startedAt: Date.now(), round: 0, errorRounds: 0, lastAt: null, nextAt: null, pairs: null, stop: null, cachedUntil: null, timer: null, running: false };
  }
  const memo = checkMemo;
  let ticker = null;

  const headEl = h('div', { class: 'chg-check-head-wrap', attrs: { 'aria-live': 'polite' } });
  const metaEl = h('p', { class: 'muted text-sm chg-check-meta' });
  const nowBtn = Button({ label: t('chg.check.now'), icon: 'refresh', size: 'sm', variant: 'primary', dataset: { action: 'check-now', shortcut: 'submit' }, onClick: () => checkNow() });
  const stopBtn = Button({ label: t('chg.check.stop'), icon: 'stop', size: 'sm', dataset: { action: 'check-stop', shortcut: 'cancel' }, onClick: () => stop() });
  const againBtn = Button({ label: t('chg.check.again'), icon: 'refresh', size: 'sm', variant: 'primary', dataset: { action: 'check-again' }, onClick: () => again() });
  const copyBtn = CopyButton(() => checkUrl(query), { label: t('chg.check.copy'), size: 'sm', variant: 'ghost', toastOnCopy: true });
  const setsEl = h('div', { class: 'stack chg-sets' });
  const hero = h('section', { class: 'card chg-hero' },
    h('div', { class: 'chg-hero-top' },
      h('h2', { class: 'chg-hero-title' }, t('chg.check.title')),
      Badge(t('chg.check.zone', { zone: check.zone }), { variant: 'neutral', mono: true, className: 'chg-zone' })),
    headEl, metaEl,
    h('div', { class: 'cluster chg-hero-actions' }, nowBtn, stopBtn, againBtn, copyBtn));
  view.append(hero, setsEl,
    h('p', { class: 'muted text-sm chg-check-privacy' }, Icon('lock', { size: 14 }), ' ', t('chg.check.privacy')),
    h('p', { class: 'text-sm' }, h('a', { href: ctx.href('change') }, Icon('edit', { size: 14 }), ' ', t('chg.check.own'))));

  const resolverName = (rid) => (getResolver(rid) || { name: rid }).name;
  const values = (type, list) => (list.length ? list.map((v) => h('li', { class: 'mono chg-value' }, valueText(type, v))) : [h('li', { class: 'muted chg-value' }, t('chg.check.nothing'))]);

  function setCard(exp, i) {
    const kind = exp.family ? `${exp.type} · ${TXT_FAMILIES[exp.family]}` : exp.type;
    const mode = [t(`chg.check.mode.${exp.mode}`)];
    if (exp.maxTtl !== null) mode.push(t('chg.check.maxTtl', { ttl: formatNumber(exp.maxTtl) }));
    const res = h('ul', { class: 'chg-resolvers' });
    const card = h('section', { class: 'card chg-set', dataset: { set: i, name: exp.name, type: exp.type } },
      h('div', { class: 'chg-set-head' },
        h('span', { class: 'chg-set-type' }, kind),
        h('span', { class: 'mono chg-set-name' }, exp.name),
        h('span', { class: 'muted text-sm chg-set-mode' }, mode.join(' · '))),
      h('div', { class: 'chg-set-values' },
        exp.mode !== 'none' ? h('div', { class: 'chg-set-col' }, h('div', { class: 'chg-label' }, t('chg.check.expected')), h('ul', { class: 'chg-values' }, values(exp.type, exp.values))) : null,
        exp.old ? h('div', { class: 'chg-set-col chg-set-old' }, h('div', { class: 'chg-label' }, t('chg.check.old')), h('ul', { class: 'chg-values' }, values(exp.type, exp.old))) : null),
      res);
    card.resolversEl = res;
    return card;
  }

  const cards = check.sets.map(setCard);
  setsEl.append(...cards);

  function renderSet(i) {
    const exp = check.sets[i];
    const list = cards[i].resolversEl;
    clear(list);
    for (const rid of CHECK_RESOLVERS) {
      const r = memo.latest.get(pairKey(i, rid));
      const v = r ? r.verdict : 'waiting';
      let label;
      if (v === 'pending') label = t(`chg.check.p.${r.reason}`);
      else if (v === 'error') label = t('chg.check.v.error', { reason: r.reason });
      else label = t(`chg.check.v.${v}`);
      const [variant, iconName] = VERDICT_BADGE[v];
      const showSeen = r && (v === 'pending' || v === 'wrong') && r.reason !== 'missing' && r.reason !== 'ttl';
      const cached = r && v === 'pending' && Number.isFinite(r.ttl) && r.ttl > 0 ? t('chg.check.cached', { time: clockTime(r.at + r.ttl * 1000) }) : null;
      list.append(h('li', { class: ['chg-res', `chg-res-${v}`], dataset: { resolver: rid, verdict: v, reason: r && r.reason ? r.reason : '' } },
        h('span', { class: 'chg-res-name' }, resolverName(rid)),
        Badge(label, { variant, icon: iconName, className: 'chg-res-verdict' }),
        showSeen || cached ? h('div', { class: 'chg-res-detail text-sm' },
          showSeen ? [h('span', { class: 'muted' }, `${t('chg.check.seen')}: `), h('span', { class: 'mono chg-res-seen' }, r.seen.length ? r.seen.map((x) => valueText(exp.type, x)).join(', ') : t('chg.check.nothing'))] : null,
          cached ? h('span', { class: 'muted chg-res-cached' }, `${showSeen ? ' · ' : ''}${cached}`) : null) : null));
    }
    const st = checkState({ sets: [exp] }, new Map(CHECK_RESOLVERS.map((rid) => [pairKey(0, rid), memo.latest.get(pairKey(i, rid))]).filter(([, x]) => x)));
    cards[i].dataset.state = st.sets[0].state;
  }

  let lastHeadline = null;
  function renderHead() {
    const st = checkState(check, memo.latest);
    view.dataset.state = memo.stop || (memo.running ? 'running' : 'waiting');
    view.dataset.headline = st.headline;
    // The schedule, for the tests (and anyone curious): rounds so far, the next one (ms epoch).
    view.dataset.round = String(memo.round);
    view.dataset.nextAt = memo.nextAt && !memo.stop ? String(memo.nextAt) : '';
    view.dataset.nextPairs = memo.nextAt && !memo.stop ? (memo.pairs || []).join(' ') : '';
    clear(headEl);
    const doneSets = st.sets.filter((s) => s.state === 'done').length;
    const params = { count: check.sets.length, done: doneSets };
    if (st.headline === 'done-partial') params.count = CHECK_RESOLVERS.filter((rid) => check.sets.every((_, i) => { const r = memo.latest.get(pairKey(i, rid)); return r && r.verdict === 'error'; })).length || 1;
    const headline = Alert({ variant: HEAD_VARIANT[st.headline], compact: true, message: t(`chg.check.head.${st.headline}`, params) });
    headline.dataset.headline = st.headline;
    headEl.append(headline);
    if (memo.stop && memo.stop !== 'done') {
      headEl.append(h('p', { class: 'text-sm chg-stopped', dataset: { stop: memo.stop } },
        t(`chg.check.stop.${memo.stop}`, { time: memo.cachedUntil ? formatDateTime(memo.cachedUntil) : '' })));
    }
    if (lastHeadline !== null && lastHeadline !== st.headline) announce(headline.textContent);
    lastHeadline = st.headline;
    renderMeta();
    const stopped = !!memo.stop;
    nowBtn.hidden = stopped;
    stopBtn.hidden = stopped;
    againBtn.hidden = !stopped;
    nowBtn.disabled = memo.running;
  }

  function renderMeta() {
    const parts = [];
    if (memo.running) parts.push(t('chg.check.running'));
    else if (memo.lastAt) parts.push(t('chg.check.checked', { time: clockTime(memo.lastAt) }));
    if (!memo.stop && !memo.running && memo.nextAt) parts.push(t('chg.check.next', { wait: formatDuration(Math.max(0, memo.nextAt - Date.now())) }));
    metaEl.textContent = parts.join(' · ');
  }

  function renderAll() {
    check.sets.forEach((_, i) => renderSet(i));
    renderHead();
  }

  async function runRound(only, { quiet = false } = {}) {
    if (memo.running) return;
    if (!ctx.requireOnline({ quiet })) {
      metaEl.textContent = t('chg.check.offline');
      return;
    }
    clearTimeout(memo.timer);
    memo.timer = null;
    memo.nextAt = null;
    memo.running = true;
    renderHead();
    ctx.setBusy(true);
    try {
      const dns = await ctx.getDns();
      const results = await checkRound(check, {
        dns, only, signal: ctx.signal,
        onResult: (r) => {
          memo.latest.set(pairKey(r.set, r.resolver), r);
          if (view.isConnected) renderSet(r.set);
        }
      });
      memo.round += 1;
      memo.errorRounds = results.some((r) => r.verdict === 'error') ? memo.errorRounds + 1 : 0;
      memo.lastAt = new Date();
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      ctx.checkOutdated();
      throw err;
    } finally {
      memo.running = false;
      ctx.setBusy(false);
    }
    schedule();
  }

  function schedule() {
    clearTimeout(memo.timer);
    const n = nextCheck({ latest: memo.latest, check, round: memo.round, startedAt: memo.startedAt, now: Date.now(), errorRounds: memo.errorRounds });
    memo.stop = n.stop;
    memo.cachedUntil = n.cachedUntil ? new Date(n.cachedUntil) : null;
    memo.nextAt = n.at;
    memo.pairs = n.pairs;
    if (!n.stop) memo.timer = setTimeout(() => { if (view.isConnected) runRound(new Set(n.pairs), { quiet: true }); }, Math.max(0, n.at - Date.now()));
    if (view.isConnected) renderAll();
  }

  function openPairs() {
    const out = new Set();
    check.sets.forEach((_, i) => {
      for (const rid of CHECK_RESOLVERS) {
        const r = memo.latest.get(pairKey(i, rid));
        if (!r || r.verdict !== 'done') out.add(pairKey(i, rid));
      }
    });
    return out;
  }

  function checkNow() {
    memo.stop = null;
    runRound(openPairs());
  }

  function stop() {
    clearTimeout(memo.timer);
    memo.timer = null;
    memo.stop = 'user';
    memo.nextAt = null;
    renderHead();
    againBtn.focus();
  }

  function again() {
    Object.assign(memo, { startedAt: Date.now(), round: 0, errorRounds: 0, stop: null, cachedUntil: null });
    runRound(openPairs());
    nowBtn.focus();
  }

  ticker = setInterval(() => { if (view.isConnected) renderMeta(); }, 1000);
  ctx.onCleanup(() => {
    clearInterval(ticker);
    // The memo keeps the answers; its timer only runs while the page is on screen.
    clearTimeout(memo.timer);
    memo.timer = null;
    memo.running = false;
  });

  ctx.runStarted(check.zone);
  renderAll();
  if (memo.stop) return;
  if (!memo.lastAt) runRound(null, { quiet: true });
  else schedule();
}
