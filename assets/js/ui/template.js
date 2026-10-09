/**
 * ui/template.js — the page template's components (docs/DESIGN.md §5, §7; redesign phase 2): every
 * tool renders the same regions in the same order, and these draw them.
 *
 *   1  .page-header        the shell's (app.js renderPageHeader)
 *   2  .tool-input         ToolInput — one card: the primary field first, optional fields, examples
 *                          (ExampleChips), options (OptionsDisclosure) and the PrivacyNote; compact
 *                          from the moment a run starts (one row: the field, a summary line with Edit, Run).
 *                          A file tool's is FileInput: the drop zone and the rest, then one compact row
 *                          ("2 reports loaded · Add files · Forget all") once something is loaded
 *   3  .run-bar            RunBar — the page's primary button and its Stop in one slot; on a phone a
 *                          floating copy at the bottom while the inline one is out of view; a wizard's
 *                          bar (SSL Targets) sticks itself, with its info lines
 *   4  .result-head        ResultHeader — title (a verdict, or "<subject> — <what>"), key metric, meta (time,
 *                          counts, the kept-result note, the progress while running), StatusSummary +
 *                          ResultActions, NextSteps, RelatedLinks ("Also check:")
 *   5  .result-tabs        components.js Tabs
 *   6  .metric-strip       MetricStrip — read-only figures; zeros fold into one sentence
 *   7  .finding-list       FindingList — one card, one row per finding, the worst first, "n more"
 *   8  .result-body        the tool's own sections
 *   —  EmptyState          the empty result region: one line, the chips of what it checks, no card
 *
 * The views import this module statically, so it loads with the first tool and never with Home
 * (the start-route test keeps it off the start route). Its styles are in style.css § 4 ("Page
 * template"); its pure decisions (status order, action placement, the floating bar…) are
 * lib/template.js's. Every text is rendered as text (dom.js), never HTML.
 *
 * Selector policy (DESIGN §8): a view passes its own classes (`className`) and keeps its data-action /
 * data-export / data-role hooks on the controls it hands in; the template adds its shared classes
 * next to them.
 *
 * @example
 *   const run = RunBar({ label: t('hlt.run'), dataset: { action: 'run', shortcut: 'submit' },
 *     stopDataset: { action: 'stop', shortcut: 'cancel' }, onRun: start, onStop: stop });
 *   const input = ToolInput({ className: 'hlt-form-card', primary: domainField.el, run,
 *     extras: [ExampleChips({ examples: ['example.com'], onPick })], privacy: PrivacyNote({ text: t('hlt.privacy') }),
 *     summary: () => optionsSummary([...]) });
 *   const head = ResultHeader({ className: 'hlt-hero' });
 *   head.set('title', ResultTitle({ severity: 'warn', text: t('hlt.light.warn') }));
 *   head.set('status', StatusSummary({ items, verdict: true }).el);
 *   head.set('actions', ResultActions({ summary, report, exports, link: () => url }).el);
 */

import { h, clear, uid, append } from './dom.js';
import { Button, CopyButton, Disclosure, Icon, MenuButton, announce, copyText, toast } from './components.js';
import { registerStrings, t, formatNumber } from '../i18n.js';
import {
  actionPlan, barStuck, findingRows, FINDINGS_MAX, PHONE_MAX_WIDTH, relatedLinks, runBarFloats, splitAtSubject, statusItems
} from '../lib/template.js';
import { foldZeroStats } from '../lib/density.js';

registerStrings('en', {
  'result.export': 'Export',
  'result.print': 'Print / save as PDF',
  'result.plainTitle': 'Copy as plain text',
  'result.related': 'Also check:',
  'result.edit': 'Edit',
  'result.editLabel': 'Edit the options',
  'result.ready': 'Ready to check {subject} — nothing has been sent yet.',
  'result.checking': 'Checking {subject}…',
  'result.sourcesFailed': { one: '{count} source failed', other: '{count} sources failed' },
  'result.more': 'More actions',
  'result.statusLabel': 'The result in numbers',
  'result.actionsLabel': 'Actions on this result',
  'result.nextLabel': 'Next steps',
  'result.try': 'Try:',
  'result.checks': 'What it checks',
  'result.zero': 'None: {list}',
  'result.linkCopied': 'Link copied.',
  'result.privacyMore': 'What is sent',
  'result.findings': 'Findings',
  'result.moreFindings': { one: '{count} more', other: '{count} more' },
  'result.fewerFindings': 'Show fewer'
});

registerStrings('tr', {
  'result.export': 'Dışa aktar',
  'result.print': 'Yazdır / PDF olarak kaydet',
  'result.plainTitle': 'Düz metin olarak kopyala',
  'result.related': 'Ayrıca bakın:',
  'result.edit': 'Düzenle',
  'result.editLabel': 'Seçenekleri düzenle',
  'result.ready': '{subject} kontrole hazır — henüz hiçbir şey gönderilmedi.',
  'result.checking': '{subject} kontrol ediliyor…',
  'result.sourcesFailed': '{count} kaynak başarısız oldu',
  'result.more': 'Diğer işlemler',
  'result.statusLabel': 'Sayılarla sonuç',
  'result.actionsLabel': 'Bu sonuçla ilgili işlemler',
  'result.nextLabel': 'Sonraki adımlar',
  'result.try': 'Deneyin:',
  'result.checks': 'Neleri kontrol eder',
  'result.zero': 'Hiç yok: {list}',
  'result.linkCopied': 'Bağlantı kopyalandı.',
  'result.privacyMore': 'Ne gönderilir',
  'result.findings': 'Bulgular',
  'result.moreFindings': '{count} tane daha',
  'result.fewerFindings': 'Daha az göster'
});

/** The status icons (DESIGN §6.2): every colour comes with an icon and a word. */
export const STATUS_ICONS = Object.freeze({ error: 'x-circle', warn: 'alert', info: 'info', ok: 'check-circle' });

/** A control character no translation holds: it marks where a sentence's subject goes. */
const SUBJECT = '\u0001';

/** The phone layout (DESIGN §3.4) as a MediaQueryList, or null where matchMedia is missing (Node). */
function phoneQuery() {
  const mm = globalThis.matchMedia;
  return typeof mm === 'function' ? mm(`(max-width: ${PHONE_MAX_WIDTH}px)`) : null;
}

/** Is `el` (or anything in it) holding the keyboard focus? */
function hasFocus(el) {
  const doc = globalThis.document;
  return !!(doc && el && typeof el.contains === 'function' && doc.activeElement && el.contains(doc.activeElement));
}

/** A selector that finds a control again after a redraw: its data-action, data-export, data-menu or data-status. */
function focusKey(el) {
  if (!el || !el.dataset) return null;
  for (const name of ['action', 'export', 'menu', 'status', 'view']) {
    const value = el.dataset[name];
    if (value) return `[data-${name}="${globalThis.CSS && CSS.escape ? CSS.escape(value) : value}"]`;
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Small parts                                                              */
/* ------------------------------------------------------------------------ */

/**
 * A sentence with its subject drawn on its own (mono by default) inside the words the language
 * puts around it: "Overview of example.com" / "example.com özeti".
 * @param {(params: object) => string} translate e.g. (p) => t('dov.resultsTitle', p)
 * @param {string} subject
 * @param {{ mono?: boolean, className?: string, name?: string }} [opts] `name`: the placeholder ('subject' by default)
 * @returns {Array<string|Node>}
 */
export function withSubject(translate, subject, { mono = true, className = '', name = 'subject' } = {}) {
  const parts = splitAtSubject(translate({ [name]: SUBJECT }), SUBJECT);
  const node = h('span', { class: [{ mono }, 'result-subject', className] }, subject);
  if (!parts) return [node];
  return [parts[0] || null, node, parts[1] || null].filter((x) => x !== null);
}

/**
 * The privacy note of a tool (DESIGN §5.1, region 2's footer; principle 6): one quiet line next to
 * the Run button that says what is sent and to whom, with an optional link to About › What this
 * page sent. Neutral: a privacy note is not good news.
 * @param {{ text: string|Node, href?: string|null, linkLabel?: string|null, className?: string }} opts
 * @returns {HTMLParagraphElement}
 */
export function PrivacyNote({ text, href = null, linkLabel = null, className = '' }) {
  return h('p', { class: ['privacy-note', className] },
    Icon('lock', { size: 13, className: 'privacy-note-icon' }),
    h('span', { class: 'privacy-note-text' }, text,
      href ? [' ', h('a', { class: 'privacy-note-link', href, dataset: { view: 'about' } }, linkLabel || t('result.privacyMore'))] : null));
}

/**
 * "Try:" and example chips (DESIGN §7): a click fills the form (`onPick`) and moves the focus to
 * Run (`focus`) — it sends nothing. Each chip keeps `data-example`.
 * @param {{ examples: Array<string|{ value: string, label?: string, title?: string }>, onPick: (value: string, example: object) => void,
 *   focus?: HTMLElement|(() => HTMLElement|null)|null, label?: string|null, className?: string }} opts
 * @returns {HTMLElement}
 */
export function ExampleChips({ examples, onPick, focus = null, label = null, className = '' }) {
  const list = (examples || []).map((x) => (typeof x === 'string' ? { value: x } : x)).filter((x) => x && x.value);
  const text = label || t('result.try');
  return h('div', { class: ['example-chips', className], attrs: { role: 'group', 'aria-label': text } },
    h('span', { class: 'example-chips-label', attrs: { 'aria-hidden': 'true' } }, text),
    list.map((x) => h('button', {
      type: 'button',
      class: 'chip mono example-chip',
      title: x.title || null,
      dataset: { example: x.value },
      on: {
        click: () => {
          if (typeof onPick === 'function') onPick(x.value, x);
          const target = typeof focus === 'function' ? focus() : focus;
          if (target && typeof target.focus === 'function') target.focus();
        }
      }
    }, h('span', { class: 'chip-label' }, x.label || x.value))));
}

/**
 * Options behind a disclosure, with a one-line summary of the choices that differ from their
 * default next to its title (DESIGN §7; it generalises Subdomains' and SSL Targets' Advanced options).
 * @param {{ label: string, summary?: string|(() => string), children?: any, open?: boolean, className?: string }} opts
 * @returns {{ el: HTMLDetailsElement, refresh(): void, setOpen(open: boolean): void }}
 */
export function OptionsDisclosure({ label, summary = '', children = null, open = false, className = '' }) {
  const summaryText = h('span', { class: 'options-summary' });
  const el = h('details', { class: ['disclosure', 'options-disclosure', className], open },
    h('summary', { class: 'disclosure-summary' },
      Icon('chevron-right', { size: 14, className: 'disclosure-chevron' }),
      h('span', { class: 'options-label' }, label), ' ', summaryText),
    h('div', { class: 'disclosure-body' }, children));
  const api = {
    el,
    refresh() {
      const text = typeof summary === 'function' ? summary() : summary;
      summaryText.textContent = text || '';
      summaryText.hidden = !text;
    },
    setOpen(on) {
      el.open = !!on;
    }
  };
  api.refresh();
  return api;
}

/* ------------------------------------------------------------------------ */
/* Region 3: the run bar                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The page's primary button and its Stop, in one slot (DESIGN §5.1, region 3; §7 RunBar). Run and
 * Stop are two buttons that take turns: the keyboard focus follows from the one that goes to the
 * one that comes. Once a result is on screen Run turns secondary and reads "Run again"
 * (`setRerun(true)`), and primary again as soon as the input changes (`setRerun(false)`).
 *
 * On a phone a floating copy of the bar (`float`, which the view appends to its container) sticks
 * to the bottom of the screen while the inline Run is out of view and the input holds a value
 * (lib/template.js runBarFloats); its height goes to `--run-bar-h`, which keeps a focused field
 * clear of it (scroll-padding-bottom, style.css). It carries Stop while a run goes on and hides
 * once a result is on screen. It has no hook of its own but `data-role="run-bar-float"`: it clicks
 * the real buttons, whose data-action and data-shortcut stay the view's.
 *
 * `info` puts lines next to the buttons (a wizard's query estimate, its summary, an error): the
 * bar becomes `.run-bar-buttons` + `.run-bar-info`. `sticky` (DESIGN §5.5, the wizard: SSL
 * Targets) makes the bar itself stick to the bottom of the screen where its stylesheet makes it
 * `position: sticky`: it is the last child of its container and rests where that ends;
 * `data-stuck` says when it floats over the container (lib/template.js barStuck — the view's CSS
 * draws the shadow), and its height goes to `--run-bar-h` while it is sticky, which keeps a focused
 * field clear of it. A sticky bar has no floating copy (it is one).
 * @param {{ label: string, icon?: string, dataset?: object, title?: string|null, stopLabel?: string|null, stopDataset?: object,
 *   onRun?: Function|null, onStop?: Function|null, hasValue?: () => boolean, className?: string, size?: 'sm'|'md'|'lg',
 *   info?: Node[], sticky?: boolean, buttonsClass?: string, barDataset?: object }} opts `barDataset`: the bar's own hooks
 * @returns {{ el: HTMLElement, float: HTMLElement, run: HTMLButtonElement, stop: HTMLButtonElement,
 *   setRunning(on: boolean): void, setRerun(on: boolean): void, setPrimary(on: boolean): void, setLabel(text: string): void,
 *   setState(state: string): void, refresh(): void, isRunning(): boolean, isRerun(): boolean, dispose(): void }}
 */
export function RunBar({
  label, icon = 'play', dataset = {}, title = null, stopLabel = null, stopDataset = {}, onRun = null, onStop = null,
  hasValue = () => true, className = '', size = 'md', info = [], sticky = false, buttonsClass = '', barDataset = {}
}) {
  let verb = label;
  let running = false;
  let rerun = false;
  let primary = true;
  let state = 'empty';
  let inlineVisible = true;
  const iconSize = size === 'sm' ? 14 : 16;
  const sizeClass = size !== 'md' ? `btn-${size}` : null;
  const stopText = () => stopLabel || t('common.stop');
  const runLabel = h('span', { class: 'btn-label' }, verb);
  const run = h('button', {
    type: 'button', class: ['btn', 'btn-primary', sizeClass, 'run-bar-run'], title, dataset,
    on: { click: (e) => { if (typeof onRun === 'function') onRun(e); } }
  }, Icon(icon, { size: iconSize }), runLabel);
  const stop = h('button', {
    type: 'button', class: ['btn', 'btn-secondary', sizeClass, 'run-bar-stop'], hidden: true, dataset: stopDataset,
    on: { click: (e) => { if (typeof onStop === 'function') onStop(e); } }
  }, Icon('stop', { size: iconSize }), h('span', { class: 'btn-label' }, stopText()));
  const infoEls = (info || []).filter(Boolean);
  const grouped = !!sticky || infoEls.length > 0;
  const el = grouped
    ? h('div', { class: ['run-bar', 'run-bar-group', { 'run-bar-sticky': !!sticky }, className], dataset: { ...barDataset, ...(sticky ? { stuck: 'false' } : {}) } },
      h('div', { class: ['run-bar-buttons', buttonsClass] }, run, stop),
      infoEls.length ? h('div', { class: 'run-bar-info' }, infoEls) : null)
    : h('div', { class: ['run-bar', className], dataset: barDataset }, run, stop);
  // The phone's floating copy: both icons drawn once, the one that applies shown.
  const floatRunIcon = h('span', { class: 'run-bar-float-icon' }, Icon(icon, { size: 16 }));
  const floatStopIcon = h('span', { class: 'run-bar-float-icon', hidden: true }, Icon('stop', { size: 16 }));
  const floatLabel = h('span', { class: 'btn-label' }, verb);
  const floatBtn = h('button', {
    type: 'button', class: ['btn', 'btn-primary', 'run-bar-float-btn'], dataset: { role: 'run-bar-float' },
    on: { click: () => (running ? stop : run).click() }
  }, floatRunIcon, floatStopIcon, floatLabel);
  const float = h('div', { class: 'run-bar-float', hidden: true }, floatBtn);

  const setVariant = (btn, variant) => {
    btn.classList.remove('btn-primary', 'btn-secondary');
    btn.classList.add(`btn-${variant}`);
  };
  const phone = phoneQuery();
  const root = () => (globalThis.document ? globalThis.document.documentElement : null);

  function syncRun() {
    const again = rerun && !running;
    runLabel.textContent = again ? t('common.rerun') : verb;
    setVariant(run, primary && !again ? 'primary' : 'secondary');
  }

  function syncFloat() {
    // A sticky bar is its own floating bar: --run-bar-h is its height (measureSticky).
    if (sticky) return;
    const show = runBarFloats({ phone: !!(phone && phone.matches), inlineVisible, hasValue: !!hasValue(), state: running ? 'running' : state });
    float.hidden = !show;
    floatRunIcon.hidden = running;
    floatStopIcon.hidden = !running;
    floatLabel.textContent = running ? stopText() : rerun ? t('common.rerun') : verb;
    setVariant(floatBtn, running ? 'secondary' : 'primary');
    const r = root();
    if (!r || !r.style) return;
    if (show && float.isConnected) r.style.setProperty('--run-bar-h', `${Math.ceil(float.getBoundingClientRect().height)}px`);
    else r.style.removeProperty('--run-bar-h');
  }

  let observer = null;
  if (!sticky && typeof globalThis.IntersectionObserver === 'function') {
    observer = new globalThis.IntersectionObserver((entries) => {
      for (const entry of entries) inlineVisible = entry.isIntersecting;
      syncFloat();
    });
    observer.observe(el);
  }
  const onMedia = () => {
    if (el.isConnected || float.isConnected) syncFloat();
  };
  if (!sticky && phone && typeof phone.addEventListener === 'function') phone.addEventListener('change', onMedia);

  /* The sticky variant: whether the bar floats (data-stuck) and its height (--run-bar-h), measured
     once per frame after a scroll, a resize or a change of its own size or its container's. */
  let stickyQueued = false;
  let stickyStopped = false;
  let resizer = null;
  let watched = null;
  const measureSticky = () => {
    stickyQueued = false;
    if (stickyStopped || !el.isConnected || typeof globalThis.getComputedStyle !== 'function') return;
    const box = el.parentElement;
    if (resizer && box && watched !== box) {
      if (watched) resizer.unobserve(watched);
      resizer.observe(box);
      watched = box;
    }
    const isSticky = globalThis.getComputedStyle(el).position === 'sticky';
    const r = box ? box.getBoundingClientRect() : { top: 0, bottom: 0 };
    const stuck = barStuck({ sticky: isSticky, top: r.top, bottom: r.bottom, viewportHeight: globalThis.innerHeight });
    if (el.dataset.stuck !== String(stuck)) el.dataset.stuck = String(stuck);
    const rootEl = root();
    if (!rootEl || !rootEl.style) return;
    if (isSticky) rootEl.style.setProperty('--run-bar-h', `${Math.ceil(el.getBoundingClientRect().height)}px`);
    else rootEl.style.removeProperty('--run-bar-h');
  };
  const queueSticky = () => {
    if (stickyQueued || stickyStopped) return;
    stickyQueued = true;
    const raf = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 16));
    raf(measureSticky);
  };
  if (sticky && typeof globalThis.addEventListener === 'function') {
    globalThis.addEventListener('scroll', queueSticky, { passive: true });
    globalThis.addEventListener('resize', queueSticky);
    if (typeof globalThis.ResizeObserver === 'function') {
      resizer = new globalThis.ResizeObserver(queueSticky);
      resizer.observe(el);
    }
  }

  return {
    el,
    float,
    run,
    stop,
    /** A run starts (true) or ends: Stop takes Run's slot; the keyboard focus goes with it. */
    setRunning(on) {
      const doc = globalThis.document;
      const from = !!(doc && doc.activeElement && (on ? run : stop).contains(doc.activeElement));
      running = !!on;
      run.hidden = running;
      stop.hidden = !running;
      syncRun();
      syncFloat();
      if (from) (running ? stop : run).focus();
    },
    /** A result is on screen and the input still asks for it: Run reads "Run again" and turns secondary. */
    setRerun(on) {
      rerun = !!on;
      syncRun();
      syncFloat();
    },
    /** Another primary button leads (a shared link's Start): Run steps back to secondary. */
    setPrimary(on) {
      primary = !!on;
      syncRun();
    },
    /** The verb (a mode that names the run differently). */
    setLabel(text) {
      verb = text;
      syncRun();
      syncFloat();
    },
    /** The template state (lib/template.js TEMPLATE_STATES): the floating bar hides once a result is on screen. */
    setState(next) {
      state = next;
      syncFloat();
    },
    /** The input changed (a value typed or cleared): the floating bar follows; a sticky bar measures itself again. */
    refresh() {
      if (sticky) queueSticky();
      else syncFloat();
    },
    isRunning: () => running,
    isRerun: () => rerun && !running,
    dispose() {
      if (observer) observer.disconnect();
      observer = null;
      if (!sticky && phone && typeof phone.removeEventListener === 'function') phone.removeEventListener('change', onMedia);
      if (sticky) {
        stickyStopped = true;
        if (typeof globalThis.removeEventListener === 'function') {
          globalThis.removeEventListener('scroll', queueSticky);
          globalThis.removeEventListener('resize', queueSticky);
        }
        if (resizer) resizer.disconnect();
        resizer = null;
        watched = null;
      }
      const r = root();
      if (r && r.style) r.style.removeProperty('--run-bar-h');
    }
  };
}

/* ------------------------------------------------------------------------ */
/* Region 2: the tool's input                                               */
/* ------------------------------------------------------------------------ */

/**
 * The tool's input (DESIGN §5.1, region 2): one card. The primary field comes first (it carries
 * `data-shortcut="focus"`), then the fields that sit on its row (`inline`) and the run bar; under
 * it what must always show (`notes`: a validation message, a prompt, a hand-off chip); then the
 * full form only (`more`: option fields; `extras`: examples, the options disclosure) and the
 * privacy note in the footer.
 *
 * From the moment a run starts the card is compact (`setCompact(true)`): one row of the primary
 * field — still an editable field —, a one-line summary of the non-default options (`summary()`)
 * with Edit (aria-expanded), which unfolds the rest, and Run. The privacy note stays.
 *
 * `runAt: 'foot'` (DESIGN §5.1, region 3: a tool with several fields, Renewal readiness) puts the
 * run bar right-aligned in the footer, after the privacy note, in both states: the same element,
 * so the focus stays on it.
 * @param {{ primary: Node, run?: ReturnType<typeof RunBar>|null, inline?: Node[], notes?: Node[], more?: Node[], extras?: Node[],
 *   privacy?: Node|null, summary?: (() => string)|null, label?: string|null, className?: string, fieldsClass?: string, dataset?: object,
 *   runAt?: 'row'|'foot' }} opts
 * @returns {{ el: HTMLElement, setCompact(on: boolean): void, isCompact(): boolean, setEditing(on: boolean): void, refresh(): void }}
 */
export function ToolInput({
  primary, run = null, inline = [], notes = [], more = [], extras = [], privacy = null, summary = null, label = null,
  className = '', fieldsClass = '', dataset = {}, runAt = 'row'
}) {
  const runInFoot = runAt === 'foot' && !!run;
  const moreId = uid('tool-input-more');
  const inlineEls = (inline || []).filter(Boolean);
  const moreEls = (more || []).filter(Boolean);
  const extraEls = (extras || []).filter(Boolean);
  const inlineId = inlineEls.length ? uid('tool-input-inline') : null;
  const unfoldable = inlineEls.length + moreEls.length + extraEls.length > 0;
  const summaryText = h('span', { class: 'tool-input-summary-text' });
  const edit = h('button', {
    type: 'button',
    class: 'link-btn tool-input-edit',
    hidden: !unfoldable,
    dataset: { action: 'tool-input-edit' },
    attrs: { 'aria-expanded': 'false', 'aria-controls': [moreId, inlineId].filter(Boolean).join(' '), 'aria-label': t('result.editLabel') },
    on: { click: () => api.setEditing(edit.getAttribute('aria-expanded') !== 'true') }
  }, t('result.edit'));
  const summaryEl = h('div', { class: 'tool-input-summary', hidden: true }, summaryText, edit);
  const fields = h('div', { class: ['tool-input-fields', fieldsClass] },
    h('div', { class: 'tool-input-primary' }, primary),
    inlineEls.length ? h('div', { class: 'tool-input-inline', id: inlineId }, inlineEls) : null,
    summaryEl,
    run && !runInFoot ? run.el : null);
  const notesEl = h('div', { class: 'tool-input-notes' }, (notes || []).filter(Boolean));
  const moreEl = h('div', { class: 'tool-input-more', id: moreId, hidden: !moreEls.length && !extraEls.length },
    moreEls,
    extraEls.length ? h('div', { class: 'tool-input-extras' }, extraEls) : null);
  const foot = privacy || runInFoot ? h('div', { class: ['tool-input-foot', { 'has-run': runInFoot }] }, privacy, runInFoot ? run.el : null) : null;
  const el = h('div', {
    class: ['tool-input', 'card', className],
    dataset,
    attrs: { role: 'search', 'aria-label': label }
  }, fields, notesEl, moreEl, foot);

  let compact = false;
  const api = {
    el,
    setCompact(on) {
      compact = !!on;
      el.classList.toggle('is-compact', compact);
      summaryEl.hidden = !compact;
      if (!compact) api.setEditing(false);
      api.refresh();
    },
    isCompact: () => compact,
    /** Edit: the compact card shows the rest of the form again (and folds it with a second press). */
    setEditing(on) {
      const open = !!on && compact;
      el.classList.toggle('is-editing', open);
      edit.setAttribute('aria-expanded', String(open));
    },
    /** The summary line again (an option changed). */
    refresh() {
      const text = typeof summary === 'function' ? summary() : '';
      summaryText.textContent = text || '';
      summaryText.hidden = !text;
    }
  };
  return api;
}

/* ------------------------------------------------------------------------ */
/* Region 4: the result header                                              */
/* ------------------------------------------------------------------------ */

/**
 * A result title (DESIGN §5.1, region 4): a verdict tool's status icon and words, or "<subject> —
 * <what>" (`text`, e.g. from {@link withSubject}). The colour of a verdict is on its icon only, and
 * the icon is not read out: the words say it. While running, a spinner takes the icon's place.
 * @param {{ severity?: 'error'|'warn'|'info'|'ok'|null, running?: boolean, icon?: string|null, text: any }} opts
 * @returns {Node[]} for ResultHeader set('title', …)
 */
export function ResultTitle({ severity = null, running = false, icon = null, text }) {
  let mark = null;
  if (running) mark = h('span', { class: 'spinner spinner-inline result-spinner', attrs: { 'aria-hidden': 'true' } });
  else if (severity && STATUS_ICONS[severity]) {
    mark = h('span', { class: ['result-sev', `sev-${severity}`], attrs: { 'aria-hidden': 'true' } }, Icon(STATUS_ICONS[severity], { size: 18 }));
  } else if (icon) mark = h('span', { class: 'result-sev', attrs: { 'aria-hidden': 'true' } }, Icon(icon, { size: 18 }));
  return [mark, h('span', { class: 'result-title-text' }, text)].filter(Boolean);
}

/**
 * The result header (DESIGN §5.1, region 4): one element for the life of a view, present from the
 * moment a run starts. The view fills its parts with `set(part, content)`; an empty part hides.
 *
 * - `title`: the h2 (`.result-title`, focusable from code: the outline reads tool → result);
 * - `key`: the key metric at the right (a grade, days left);
 * - `meta`: time, counts, resolver; under it the kept-result note (`.page-kept`, `data-kept-slot`:
 *   the shell puts "Result from 10:51 · Run again" there, ui/session-ui.js keptSlotOf) and
 *   `progress` while running. A ready prompt's header ("Opened from a link …", `.result-ready`)
 *   is about the name in the box, not a kept result: it has no slot (`kept: false`);
 * - `notes`: what the result needs said (a zone file used, a cancelled run); an empty note takes no
 *   room, and the row hides while none shows — so a live region goes on `el` itself, not here;
 * - `status` (StatusSummary) and `actions` (ResultActions) on one row;
 * - `next` (NextSteps), `related` (RelatedLinks), `sources` (source chips).
 *
 * `setState` marks it ready / running / done / error (`data-state`, aria-busy while running). A
 * part redrawn under the keyboard focus keeps it: on the same control when the new content has one
 * (its data-action, data-export, data-menu or data-status), else on the title.
 * @param {{ className?: string|string[], dataset?: object, level?: 2|3, label?: string|null, kept?: boolean }} [opts]
 * @returns {{ el: HTMLElement, title: HTMLElement, kept: HTMLElement|null, set(part: string, value: any): void,
 *   get(part: string): HTMLElement|null, setState(state: string): void, focusTitle(): void }}
 */
export function ResultHeader({ className = '', dataset = {}, level = 2, label = null, kept: keptSlot = true } = {}) {
  const titleId = uid('result-title');
  const title = h(`h${level}`, { class: 'result-title', id: titleId, attrs: { tabindex: -1 } });
  const parts = {
    title,
    key: h('div', { class: 'result-key', hidden: true }),
    meta: h('div', { class: 'result-meta', hidden: true }),
    progress: h('div', { class: 'result-progress', hidden: true }),
    notes: h('div', { class: 'result-notes', hidden: true }),
    status: h('div', { class: 'result-status', hidden: true }),
    actions: h('div', { class: 'result-actions-slot', hidden: true }),
    next: h('div', { class: 'result-next', hidden: true }),
    related: h('div', { class: 'result-related-slot', hidden: true }),
    sources: h('div', { class: 'result-sources', hidden: true })
  };
  const kept = keptSlot ? h('div', { class: 'page-kept result-kept', hidden: true, dataset: { keptSlot: '' } }) : null;
  const bar = h('div', { class: 'result-bar', hidden: true }, parts.status, parts.actions);
  const el = h('section', {
    class: ['result-head', 'card', className],
    dataset: { state: 'empty', ...dataset },
    attrs: label ? { 'aria-label': label } : { 'aria-labelledby': titleId }
  },
  h('div', { class: 'result-top' },
    h('div', { class: 'result-titles' }, title, parts.meta, kept, parts.progress),
    parts.key),
  parts.notes, bar, parts.next, parts.related, parts.sources);

  return {
    el,
    title,
    kept,
    set(part, value) {
      const host = parts[part];
      if (!host) throw new Error(`ResultHeader: no part "${part}"`);
      const focused = part !== 'title' && hasFocus(host) ? globalThis.document.activeElement : null;
      const key = focused ? focusKey(focused) : null;
      clear(host);
      const list = (Array.isArray(value) ? value : [value]).flat(Infinity).filter((x) => x !== null && x !== undefined && x !== false && x !== '');
      append(host, list);
      if (part !== 'title') host.hidden = !list.length;
      bar.hidden = parts.status.hidden && parts.actions.hidden;
      if (focused) {
        const again = key ? host.querySelector(key) : null;
        if (again && !again.disabled && !again.hidden) again.focus({ preventScroll: true });
        else title.focus({ preventScroll: true });
      }
    },
    get(part) {
      return parts[part] || null;
    },
    setState(state) {
      el.dataset.state = state;
      if (state === 'running') el.setAttribute('aria-busy', 'true');
      else el.removeAttribute('aria-busy');
    },
    focusTitle() {
      title.focus({ preventScroll: true });
    }
  };
}

/**
 * The status summary (DESIGN §5.4): up to five items as "icon count label", error → warn → info →
 * ok → neutral (lib/template.js statusItems). An item with `filter` is a toggle — a button with
 * aria-pressed whose accessible name is its visible text; one with only `onPress` a plain button
 * (it opens what it counts); any other a fact. Not a live region: the view announces the totals
 * once, when the run ends.
 *
 * `update` changes the items in place, by key: an item that stays keeps its node (its words,
 * count, title and pressed state follow), and only an item that comes or goes is added or
 * removed — Subdomains updates its counts every 150 ms while hosts stream in, and a button drawn
 * anew between a press and its release would never get the click. An item whose kind (toggle,
 * button, fact) or severity changes is drawn anew, the keyboard focus moving to its new node.
 * @param {{ items?: Array<{ key: string, severity: string, count: number, text: string, title?: string,
 *   filter?: boolean, onPress?: (key: string) => void }>, verdict?: boolean, pressed?: string|null, label?: string|null, className?: string }} [opts]
 * @returns {{ el: HTMLElement, update(items: object[], opts?: { pressed?: string|null }): void, setPressed(key: string|null): void }}
 */
export function StatusSummary({ items = [], verdict = false, pressed = null, label = null, className = '' } = {}) {
  const el = h('div', { class: ['status-summary', className], attrs: { role: 'group', 'aria-label': label || t('result.statusLabel') } });
  let current = pressed;
  /** The items on screen, by key: { node, text (its words' span), kind, severity, item (the latest: a press reads its onPress) }. */
  const drawn = new Map();
  const kindOf = (item) => (typeof item.onPress === 'function' ? (item.filter ? 'toggle' : 'button') : 'fact');

  function draw(item, kind) {
    const key = item.key;
    const mark = STATUS_ICONS[item.severity]
      ? h('span', { class: ['status-icon', `sev-${item.severity}`], attrs: { 'aria-hidden': 'true' } }, Icon(STATUS_ICONS[item.severity], { size: 14 }))
      : h('span', { class: 'status-dot', attrs: { 'aria-hidden': 'true' } }, '·');
    const text = h('span', { class: 'status-text' });
    const common = { class: ['status-item', `status-${item.severity}`], dataset: { status: key, severity: item.severity } };
    const press = () => {
      const now = drawn.get(key);
      if (now && typeof now.item.onPress === 'function') now.item.onPress(key);
    };
    const node = kind === 'fact' ? h('span', common, mark, text) : h('button', { ...common, type: 'button', on: { click: press } }, mark, text);
    return { node, text, kind, severity: item.severity };
  }

  function fill(d, item) {
    d.item = item;
    if (d.text.textContent !== item.text) d.text.textContent = item.text;
    d.node.dataset.count = String(item.count);
    if (item.title) d.node.setAttribute('title', item.title);
    else d.node.removeAttribute('title');
    if (d.kind === 'toggle') d.node.setAttribute('aria-pressed', String(current === item.key));
  }

  function render(shown) {
    const focused = hasFocus(el) ? globalThis.document.activeElement : null;
    const was = focused && focused.dataset ? focused.dataset.status : null;
    const keys = new Set(shown.map((x) => x.key));
    for (const [key, d] of drawn) {
      if (keys.has(key)) continue;
      d.node.remove();
      drawn.delete(key);
    }
    shown.forEach((item, i) => {
      const kind = kindOf(item);
      let d = drawn.get(item.key);
      if (d && (d.kind !== kind || d.severity !== item.severity)) {
        d.node.remove();
        d = null;
      }
      if (!d) {
        d = draw(item, kind);
        drawn.set(item.key, d);
      }
      fill(d, item);
      // In the order statusItems gives: only an item that came (or changed its place) moves.
      const at = el.childNodes[i] || null;
      if (at !== d.node) el.insertBefore(d.node, at);
    });
    // The item under the focus was drawn anew: the focus goes to its new node.
    if (was && !el.contains(focused)) {
      const again = drawn.get(was);
      if (again && again.kind !== 'fact') again.node.focus({ preventScroll: true });
    }
  }

  const api = {
    el,
    update(next, { pressed: p = current } = {}) {
      current = p;
      render(statusItems(next, { verdict }));
    },
    setPressed(key) {
      current = key;
      for (const d of drawn.values()) if (d.kind === 'toggle') d.node.setAttribute('aria-pressed', String(d.item.key === key));
    }
  };
  api.update(items, { pressed });
  return api;
}

/**
 * A result's standard actions (DESIGN §5.3), always in this order: Copy summary with ¶ (copy as
 * plain text), Report, Export (a plain button for one file, the Export ▾ menu for more, Print
 * last), Copy link. On a phone (lib/template.js PHONE_MAX_WIDTH) only Copy summary stays in the row
 * and the rest goes behind "⋯"; the row is drawn again when the screen crosses that width. The
 * menu items keep their data-action / data-export; Copy link is `data-action="copy-link"`.
 * Tool-specific actions are NextSteps, never here. A destructive action (Remove, Forget: `tail`,
 * which keeps its own confirmation) goes last in the Export ▾ menu, after Print, and so last in
 * "⋯" on a phone (DESIGN §5.3); it carries `data-tail`.
 * @param {{ summary?: { el: HTMLElement, plain?: HTMLElement, setDisabled?: Function, copy?: Function }|null,
 *   report?: HTMLButtonElement|null, exports?: Array<{ label: string, icon?: string, title?: string, onSelect: Function, dataset?: object }>,
 *   print?: boolean|Function, link?: (() => string|null)|null, tail?: Array<{ label: string, icon?: string, onSelect: Function, dataset?: object }>,
 *   className?: string }} [opts]
 * @returns {{ el: HTMLElement, setDisabled(disabled: boolean): void, setExportsDisabled(disabled: boolean): void, dispose(): void }}
 *   `setDisabled`: every action but Copy link (a run goes on: the result on screen is the previous
 *   one); `setExportsDisabled`: the files alone (nothing to export yet)
 */
export function ResultActions({ summary = null, report = null, exports = [], print = false, link = null, tail = [], className = '' } = {}) {
  const el = h('div', { class: ['result-actions', className], attrs: { role: 'group', 'aria-label': t('result.actionsLabel') } });
  const files = (exports || []).filter((x) => x && x.label && typeof x.onSelect === 'function');
  const printItem = print ? {
    label: t('result.print'), icon: 'file-text', dataset: { action: 'print' },
    onSelect: () => (typeof print === 'function' ? print() : globalThis.print && globalThis.print())
  } : null;
  const tailItems = (tail || []).filter((x) => x && x.label && typeof x.onSelect === 'function')
    .map((x) => ({ ...x, icon: x.icon || 'trash', dataset: { ...(x.dataset || {}), tail: '' } }));
  const fileItems = [...files, printItem, ...tailItems].filter(Boolean);
  const hasLink = typeof link === 'function';
  let disabled = false;
  let exportsOff = false;
  const phone = phoneQuery();

  /** The buttons drawn now follow the two switches (Copy summary and Report keep their own state). */
  function syncButtons() {
    if (typeof el.querySelectorAll !== 'function') return;
    for (const btn of el.querySelectorAll('[data-menu="more"], [data-action="print"], [data-tail]')) btn.disabled = disabled;
    for (const btn of el.querySelectorAll('[data-export]')) btn.disabled = disabled || exportsOff;
    for (const btn of el.querySelectorAll('[data-menu="export"]')) btn.disabled = disabled || (exportsOff && !printItem && !tailItems.length);
  }

  async function copyLinkFromMenu() {
    const url = hasLink ? link() : null;
    if (!url) return;
    if (await copyText(url)) {
      announce(t('common.copied'));
      toast(t('result.linkCopied'), { type: 'success', timeout: 2000 });
    } else toast(t('common.copyFailed'), { type: 'error' });
  }

  const linkButton = () => {
    const btn = CopyButton(() => (hasLink ? link() || '' : ''), { label: t('common.copyLink'), icon: 'link', size: 'sm', variant: 'secondary' });
    btn.dataset.action = 'copy-link';
    return btn;
  };

  function render() {
    const focused = hasFocus(el) ? globalThis.document.activeElement : null;
    const key = focused ? focusKey(focused) : null;
    const plan = actionPlan({
      summary: !!summary, report: !!report, files: files.length + tailItems.length, print: !!printItem, link: hasLink, phone: !!(phone && phone.matches)
    });
    clear(el);
    if (summary && summary.plain) summary.plain.hidden = !plan.row.includes('plain');
    for (const id of plan.row) {
      if (id === 'summary') append(el, summary.el);
      else if (id === 'report') append(el, report);
      else if (id === 'export' && plan.exportAs === 'file') {
        const only = fileItems[0];
        append(el, Button({
          label: only.label, icon: only.icon || 'download', size: 'sm', variant: 'secondary', title: only.title || null,
          dataset: only.dataset || {}, onClick: (e) => only.onSelect(e)
        }));
      } else if (id === 'export') {
        const menu = MenuButton({
          label: t('result.export'), icon: 'download', showLabel: true, variant: 'secondary', dataset: { menu: 'export' },
          items: fileItems.map((x) => ({ label: x.label, icon: x.icon || 'download', dataset: x.dataset || {}, onSelect: (e) => x.onSelect(e) }))
        });
        append(el, menu.el);
      } else if (id === 'link') append(el, linkButton());
    }
    if (plan.more.length) {
      const items = [];
      for (const id of plan.more) {
        if (id === 'plain') {
          items.push({ label: t('result.plainTitle'), icon: 'pilcrow', dataset: { action: 'copy-summary-text' }, onSelect: () => summary.copy && summary.copy('text') });
        } else if (id === 'report') {
          items.push({ label: report.textContent.trim(), icon: 'file-text', dataset: { action: 'report' }, onSelect: () => { if (!report.disabled) report.click(); } });
        } else if (id === 'export') {
          for (const x of fileItems) items.push({ label: x.label, icon: x.icon || 'download', dataset: x.dataset || {}, onSelect: (e) => x.onSelect(e) });
        } else if (id === 'link') items.push({ label: t('common.copyLink'), icon: 'link', dataset: { action: 'copy-link' }, onSelect: () => copyLinkFromMenu() });
      }
      const menu = MenuButton({ label: t('result.more'), icon: 'more', dataset: { menu: 'more' }, items });
      append(el, menu.el);
    }
    syncButtons();
    if (key) {
      const again = el.querySelector(key);
      if (again && !again.disabled) again.focus({ preventScroll: true });
    }
  }

  const onMedia = () => {
    if (el.isConnected) render();
  };
  if (phone && typeof phone.addEventListener === 'function') phone.addEventListener('change', onMedia);
  render();
  return {
    el,
    /** While a run goes on the result on screen is the previous one: its actions wait, Copy summary too. */
    setDisabled(on) {
      disabled = !!on;
      if (summary && typeof summary.setDisabled === 'function') summary.setDisabled(disabled);
      if (report) report.disabled = disabled;
      syncButtons();
    },
    /** Nothing to export yet (no row): the files wait, the rest stays. */
    setExportsDisabled(on) {
      exportsOff = !!on;
      syncButtons();
    },
    dispose() {
      if (phone && typeof phone.removeEventListener === 'function') phone.removeEventListener('change', onMedia);
    }
  };
}

/**
 * The tool-specific actions of a result (DESIGN §5.3, "next steps"): ghost buttons or links with
 * their tool's icon, never mixed with the standard actions.
 * @param {{ steps?: Array<{ label: string, icon?: string, href?: string, onClick?: Function, title?: string|null, dataset?: object }>,
 *   label?: string|null, className?: string }} [opts]
 * @returns {HTMLElement|null} null without a step
 */
export function NextSteps({ steps = [], label = null, className = '' } = {}) {
  const list = (steps || []).filter((s) => s && s.label);
  if (!list.length) return null;
  return h('div', { class: ['next-steps', className], attrs: { role: 'group', 'aria-label': label || t('result.nextLabel') } },
    list.map((s) => (s.href
      ? h('a', { class: 'btn btn-ghost btn-sm next-step', href: s.href, title: s.title || null, dataset: s.dataset || {} },
        s.icon ? Icon(s.icon, { size: 14 }) : null, h('span', { class: 'btn-label' }, s.label))
      : Button({
        label: s.label, icon: s.icon || null, size: 'sm', variant: 'ghost', title: s.title || null, className: 'next-step',
        dataset: s.dataset || {}, onClick: s.onClick || null
      }))));
}

/**
 * "Also check:" (DESIGN §3.5): up to four other tools, each with its icon, about the same subject
 * (lib/template.js relatedLinks). `href` comes from the view (ctx.href; a fill-only link has run=0).
 * @param {{ links?: Array<{ view: string, href: string, label: string, icon?: string }>, self?: string|null, label?: string|null,
 *   className?: string }} [opts]
 * @returns {HTMLElement|null} null without a link
 */
export function RelatedLinks({ links = [], self = null, label = null, className = '' } = {}) {
  const list = relatedLinks(links, { self });
  if (!list.length) return null;
  // The links are separated by their icons and a gap (a "·" would start a wrapped line on a phone).
  return h('p', { class: ['result-related', className] },
    h('span', { class: 'result-related-label' }, label || t('result.related')), ' ',
    list.map((x) => h('a', { class: 'related-link', href: x.href, dataset: { view: x.view } },
      x.icon ? Icon(x.icon, { size: 14 }) : null, h('span', null, x.label))));
}

/**
 * The metric strip (DESIGN §5.1, region 6): one row of label-over-value figures, read-only — a
 * result filters through its status summary and its table's Show select. Only an error or warn
 * metric's value is coloured. A zero metric named in `foldable` folds into one sentence ("None:
 * Dangling CNAME, Private IP"; lib/density.js foldZeroStats).
 * @param {{ metrics?: Array<{ id: string, label: string, value: number|string|null, severity?: 'error'|'warn'|null, title?: string|null,
 *   hint?: string|null }>, foldable?: string[], zeroText?: ((labels: string[]) => string)|null, label?: string|null, className?: string }} [opts]
 * @returns {{ el: HTMLElement, update(metrics: object[], opts?: { foldable?: string[] }): void }}
 *   `update`'s `foldable` replaces the list for that drawing (none while counts still grow)
 */
export function MetricStrip({ metrics = [], foldable = [], zeroText = null, label = null, className = '' } = {}) {
  const list = h('dl', { class: 'metric-list' });
  const zero = h('p', { class: 'metric-zero', hidden: true });
  const el = h('div', { class: ['metric-strip', className], attrs: label ? { role: 'group', 'aria-label': label } : {} }, list, zero);
  const api = {
    el,
    update(next, { foldable: fold = foldable } = {}) {
      const all = (next || []).filter((m) => m && m.id);
      const { shown, folded } = foldZeroStats(all.map((m) => ({ id: m.id, value: m.value })), { foldable: fold });
      clear(list);
      for (const id of shown) {
        const m = all.find((x) => x.id === id);
        const value = typeof m.value === 'number' ? formatNumber(m.value) : m.value ?? '—';
        append(list, h('div', { class: 'metric', dataset: { metric: m.id, severity: m.severity || null }, title: m.title || null },
          h('dt', { class: 'metric-label' }, m.label),
          h('dd', { class: ['metric-value', 'num', m.severity === 'error' || m.severity === 'warn' ? `metric-${m.severity}` : null] }, String(value)),
          m.hint ? h('dd', { class: 'metric-hint' }, m.hint) : null));
      }
      const labels = folded.map((id) => all.find((x) => x.id === id).label);
      zero.textContent = labels.length ? (typeof zeroText === 'function' ? zeroText(labels) : t('result.zero', { list: labels.join(', ') })) : '';
      zero.hidden = !labels.length;
      zero.dataset.folded = folded.join(' '); // the folded ids, for a test or a later redraw
    }
  };
  api.update(metrics);
  return api;
}

/**
 * The template's empty result region (DESIGN §5.2): compact — a small icon and ≤ 120 px —, no
 * card: one line on what the tool gives, the chips of what it checks, and optionally a disclosure
 * with the longer explanation and an action (a link to About). It never repeats the purpose line.
 * @param {{ icon?: string, message: string|Node, checks?: Array<string|{ label: string, className?: string, dataset?: object }>,
 *   details?: Node|null, action?: Node|null, className?: string }} opts
 * @returns {HTMLElement}
 */
export function EmptyState({ icon = 'inbox', message, checks = [], details = null, action = null, className = '' }) {
  const items = (checks || []).map((c) => (typeof c === 'string' ? { label: c } : c)).filter((c) => c && c.label);
  return h('div', { class: ['tool-empty', className] },
    icon ? h('span', { class: 'tool-empty-icon', attrs: { 'aria-hidden': 'true' } }, Icon(icon, { size: 18 })) : null,
    h('div', { class: 'tool-empty-body' },
      h('p', { class: 'tool-empty-message' }, message),
      items.length ? h('ul', { class: 'tool-empty-checks', attrs: { 'aria-label': t('result.checks') } },
        items.map((c) => h('li', { class: ['tool-empty-check', c.className || null], dataset: c.dataset || {} }, c.label))) : null,
      details,
      action ? h('p', { class: 'tool-empty-action' }, action) : null));
}

/* ------------------------------------------------------------------------ */
/* Region 7: the findings (phase 3)                                         */
/* ------------------------------------------------------------------------ */

/**
 * The findings of a result (DESIGN §5.1, region 7; §7 FindingList): one card, one row per finding
 * — its status icon (not read out: the words say it), its text and an optional action — in place of
 * stacked alerts. The worst first (lib/template.js findingRows); at most `max` rows show, then
 * "n more" (aria-expanded) shows the rest and folds them again. A row keeps the finding's
 * `dataset` (the view's hooks) next to `data-finding` (its key) and `data-severity`. `update`
 * draws the rows again, "n more" left as it was; without a finding the card hides.
 * @param {{ findings?: Array<{ key: string, severity: 'error'|'warn'|'info'|'ok'|'neutral', text: any, icon?: string|null,
 *   action?: Node|null, dataset?: object }>, max?: number, label?: string|null, className?: string }} [opts]
 * @returns {{ el: HTMLElement, update(findings: object[]): void, isOpen(): boolean }}
 */
export function FindingList({ findings = [], max = FINDINGS_MAX, label = null, className = '' } = {}) {
  const listId = uid('finding-rows');
  const list = h('ul', { class: 'finding-rows', id: listId });
  let open = false;
  let current = [];
  const toggle = h('button', {
    type: 'button',
    class: 'link-btn finding-more',
    hidden: true,
    attrs: { 'aria-expanded': 'false', 'aria-controls': listId },
    on: { click: () => { open = !open; draw(); } }
  });
  const el = h('div', { class: ['finding-list', 'card', className], hidden: true, attrs: { role: 'group', 'aria-label': label || t('result.findings') } }, list, toggle);

  const row = (f, hidden) => h('li', {
    class: ['finding', `finding-${f.severity}`],
    hidden,
    dataset: { ...(f.dataset || {}), finding: f.key, severity: f.severity }
  },
  h('span', { class: ['finding-icon', `sev-${f.severity}`], attrs: { 'aria-hidden': 'true' } }, Icon(f.icon || STATUS_ICONS[f.severity] || 'info', { size: 16 })),
  h('span', { class: 'finding-text' }, f.text),
  f.action ? h('span', { class: 'finding-action' }, f.action) : null);

  function draw() {
    const { shown, more } = findingRows(current, { max });
    clear(list);
    for (const f of shown) list.append(row(f, false));
    for (const f of more) list.append(row(f, !open));
    toggle.hidden = !more.length;
    toggle.textContent = open ? t('result.fewerFindings') : t('result.moreFindings', { count: more.length });
    toggle.setAttribute('aria-expanded', String(open && more.length > 0));
    el.hidden = !shown.length;
  }

  const api = {
    el,
    update(next) {
      current = (next || []).filter(Boolean);
      draw();
    },
    isOpen: () => open
  };
  api.update(findings);
  return api;
}

/* ------------------------------------------------------------------------ */
/* Region 2 of a file tool (phase 3)                                        */
/* ------------------------------------------------------------------------ */

/**
 * A file tool's input (DESIGN §5.5 "File", §7 FileInput): region 2 of Certificate and Certificate
 * estate. With nothing loaded it is one card: an optional head (a 28 px icon, the title, a
 * subtitle), the `body` the view hands in (the drop zone first, then paste, samples, how to) and the
 * privacy note in the footer. Once something is loaded it is one compact row — a disclosure
 * (`more`: "2 reports loaded", "Load another file"; `moreClass`: the view's hook) that holds the
 * same body again, and the `actions` ("Add files", "Forget all") — over the privacy note, which
 * stays. The view draws it again when what is loaded changes.
 * @param {{ loaded?: boolean, icon?: string|null, title?: any, subtitle?: any, body?: Node[], more?: any, moreClass?: string,
 *   moreOpen?: boolean, actions?: Node[], privacy?: Node|null, label?: string|null, className?: string, dataset?: object }} [opts]
 * @returns {{ el: HTMLElement, more: HTMLDetailsElement|null }}
 */
export function FileInput({
  loaded = false, icon = null, title = null, subtitle = null, body = [], more = '', moreClass = '', moreOpen = false, actions = [],
  privacy = null, label = null, className = '', dataset = {}
} = {}) {
  const bodyEls = (body || []).filter(Boolean);
  const actionEls = (actions || []).filter(Boolean);
  const foot = privacy ? h('div', { class: 'tool-input-foot' }, privacy) : null;
  const attrs = { role: 'group', 'aria-label': label || null };
  if (!loaded) {
    const head = title ? h('div', { class: 'file-input-head' },
      icon ? h('span', { class: 'file-input-icon', attrs: { 'aria-hidden': 'true' } }, Icon(icon, { size: 16 })) : null,
      h('div', { class: 'file-input-titles' },
        h('h2', { class: 'file-input-title' }, title),
        subtitle ? h('p', { class: 'file-input-subtitle' }, subtitle) : null)) : null;
    return {
      el: h('section', { class: ['tool-input', 'file-input', 'card', className], dataset, attrs },
        head, h('div', { class: 'file-input-body' }, bodyEls), foot),
      more: null
    };
  }
  const details = Disclosure({
    summary: more,
    className: ['file-input-more', moreClass].filter(Boolean).join(' '),
    open: moreOpen,
    children: h('div', { class: 'file-input-body' }, bodyEls)
  });
  return {
    el: h('section', { class: ['tool-input', 'file-input', 'is-compact', 'card', className], dataset, attrs },
      h('div', { class: 'file-input-row' }, details, actionEls.length ? h('div', { class: 'file-input-actions' }, actionEls) : null),
      foot),
    more: details
  };
}
