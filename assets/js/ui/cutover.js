/**
 * ui/cutover.js — the cutover assistant of the "is it live?" page (`#/change/check`), loaded by
 * views/change.js with that page. Three parts, over the page's own check (its memo and rounds):
 *
 * - **Watch until live**: the page's checking goes on as a long job (ui/jobs.js: the tab title,
 *   the navigation ring, the favicon, "Notify me when done") on the watch's schedule
 *   (lib/cutover.js nextWatch): never sooner than the check's backoff or a resolver's cached copy
 *   can expire, while the page stays open, for up to 24 hours. Stop (Esc) ends it; leaving the page
 *   ends it too (a language switch keeps it). It ends by itself once every resolver serves the
 *   change, and the opted-in desktop notification says so.
 * - **Cache countdown**: a resolver that is not done yet says until when it may keep the answer it
 *   gave ("old answer may be cached until 15:42 · 4:07 left"), counted down every second.
 * - **TTL planner**: from the TTL the resolvers returned (rounded up to a common TTL; editable), a
 *   low TTL and a change time, the plan — lower the TTL at T − its TTL, change at T, live by
 *   T + the low TTL, raise it back from T + 2 × the low TTL — and its checklist in English or
 *   Turkish, to copy, or as a calendar file (.ics, one event per step with a reminder before
 *   each thing to do), with the public resolvers' cache-flush pages to speed the change up.
 *
 * Nothing here sends anything: the rounds are the page's own (names and types to the four
 * resolvers); the flush pages are links the user opens. The planner's fields are kept with the
 * check for the page session.
 */

import { h, clear, debounce } from './dom.js';
import { Alert, Button, CodeBlock, CopyButton, Disclosure, ExternalLink, Icon, SegmentedControl, announce, select, textInput } from './components.js';
import { registerStrings, getLang, localeTag, formatDateTime, formatNumber } from '../i18n.js';
import { state } from '../state.js';
import { startJob, NotifyButton } from './jobs.js';
import { downloadText, timestampedName } from './download.js';
import {
  CUTOVER_I18N, FLUSH_LINKS, PLAN_LOW_TTLS, PLAN_DEFAULT_LOW, nextWatch, watchProgress, cacheCountdown, lastExpiry, clockLeft, observedTtl, likelyTtl,
  defaultChangeAt, ttlPlan, planChecklist, planCalendar
} from '../lib/cutover.js';

registerStrings('en', {
  ...CUTOVER_I18N.en,
  'chg.cut.watch': 'Watch until live',
  'chg.cut.watchTitle': 'Keeps checking on the same schedule — never before a cached answer can expire — while this page stays open, for up to 24 hours. Stop ends it.',
  'chg.cut.watching': 'Watching: asks again on the schedule while this page is open.',
  'chg.cut.progress': { one: '{done} of {count} resolver answer done', other: '{done} of {count} resolver answers done' },
  'chg.cut.lastExpiry': 'every old answer cached now expires by {time}',
  'chg.cut.ended': 'The watch ended.',
  'chg.cut.cd.old': 'old answer may be cached until {time}',
  'chg.cut.cd.empty': '“no record” may be cached until {time}',
  'chg.cut.cd.ttl': 'copy with the old TTL may be cached until {time}',
  'chg.cut.cd.other': 'this answer may be cached until {time}',
  'chg.cut.cd.left': '{left} left',
  'chg.cut.cd.expired': 'expired: the next check gets a fresh answer',
  'chg.cut.plan.title': 'Plan the cutover: TTL timeline and checklist',
  'chg.cut.plan.lead': 'Lower the TTL before the change, so that the old answer leaves every resolver’s cache within minutes of it; raise it back once the change is everywhere.',
  'chg.cut.plan.ttl': 'Current TTL (seconds)',
  'chg.cut.plan.ttlSeen': 'The highest TTL a resolver returned is {seen} s; resolvers count down from the zone’s TTL, so this reads {ttl} s.',
  'chg.cut.plan.ttlNone': 'No resolver has returned the TTL of these records yet: type the TTL the zone gives them.',
  'chg.cut.plan.low': 'Lower it to',
  'chg.cut.plan.seconds': '{n} s',
  'chg.cut.plan.at': 'Change at (your time)',
  'chg.cut.plan.step.lower': 'Lower the TTL from {from} s to {to} s',
  'chg.cut.plan.step.change': 'Make the change',
  'chg.cut.plan.step.live': 'Every resolver serves the new records',
  'chg.cut.plan.step.raise': 'Raise the TTL back to {to} s',
  'chg.cut.plan.when.lower': 'by {time}',
  'chg.cut.plan.when.change': 'at {time}',
  'chg.cut.plan.when.live': 'by {time}',
  'chg.cut.plan.when.raise': 'from {time}',
  'chg.cut.plan.note.late': 'Too late to lower the TTL in time: copies cached with the old TTL can outlive the change. Lowering it now, make the change at {time} or later.',
  'chg.cut.plan.note.past': 'This change time has gone by: pick a later one.',
  'chg.cut.plan.note.already-low': 'The TTL is already {ttl} s or less: there is nothing to lower first.',
  'chg.cut.plan.err.ttl': 'Type the current TTL in seconds (a whole number from 1 to 2147483647).',
  'chg.cut.plan.err.low': 'Pick the TTL to lower it to.',
  'chg.cut.plan.err.time': 'Pick the time of the change.',
  'chg.cut.plan.lang': 'Language of the checklist and the calendar',
  'chg.cut.plan.copy': 'Copy checklist',
  'chg.cut.plan.ics': 'Add to calendar (.ics)',
  'chg.cut.plan.icsTitle': 'One event per step at its time, with a reminder 15 minutes before each thing to do — for Outlook, Google Calendar or Apple Calendar',
  'chg.cut.plan.icsSaved': 'Saved {file}',
  'chg.cut.plan.flush': 'Right after the change, ask the public resolvers to drop their cached copy — their users get the change at once:'
});

registerStrings('tr', {
  ...CUTOVER_I18N.tr,
  'chg.cut.watch': 'Yayına girene kadar izle',
  'chg.cut.watchTitle': 'Aynı takvimle kontrol etmeyi sürdürür — önbellekteki bir yanıtın süresi dolmadan asla sormaz — bu sayfa açık kaldıkça, en fazla 24 saat. Durdur ile biter.',
  'chg.cut.watching': 'İzleniyor: bu sayfa açık kaldıkça takvime göre yeniden sorulur.',
  'chg.cut.progress': '{count} çözümleyici yanıtından {done} tanesi tamam',
  'chg.cut.lastExpiry': 'şu an önbellekteki tüm eski yanıtların süresi en geç {time} saatinde dolar',
  'chg.cut.ended': 'İzleme bitti.',
  'chg.cut.cd.old': 'eski yanıt {time} saatine kadar önbellekte kalabilir',
  'chg.cut.cd.empty': '“kayıt yok” yanıtı {time} saatine kadar önbellekte kalabilir',
  'chg.cut.cd.ttl': 'eski TTL’li kopya {time} saatine kadar önbellekte kalabilir',
  'chg.cut.cd.other': 'bu yanıt {time} saatine kadar önbellekte kalabilir',
  'chg.cut.cd.left': '{left} kaldı',
  'chg.cut.cd.expired': 'süresi doldu: sonraki kontrol taze bir yanıt alır',
  'chg.cut.plan.title': 'Geçişi planlayın: TTL zaman çizelgesi ve kontrol listesi',
  'chg.cut.plan.lead': 'Eski yanıtın değişiklikten sonraki dakikalar içinde tüm çözümleyicilerin önbelleğinden çıkması için TTL değerini değişiklikten önce düşürün; değişiklik her yere ulaşınca yeniden yükseltin.',
  'chg.cut.plan.ttl': 'Mevcut TTL (saniye)',
  'chg.cut.plan.ttlSeen': 'Bir çözümleyicinin döndürdüğü en yüksek TTL {seen} sn; çözümleyiciler zone’daki TTL’den geriye sayar, bu yüzden {ttl} sn olarak okunur.',
  'chg.cut.plan.ttlNone': 'Henüz hiçbir çözümleyici bu kayıtların TTL değerini döndürmedi: zone’daki TTL değerini yazın.',
  'chg.cut.plan.low': 'Düşürülecek değer',
  'chg.cut.plan.seconds': '{n} sn',
  'chg.cut.plan.at': 'Değişiklik zamanı (yerel saatiniz)',
  'chg.cut.plan.step.lower': 'TTL değerini {from} sn’den {to} sn’ye düşürün',
  'chg.cut.plan.step.change': 'Değişikliği yapın',
  'chg.cut.plan.step.live': 'Tüm çözümleyiciler yeni kayıtları döndürür',
  'chg.cut.plan.step.raise': 'TTL değerini yeniden {to} sn’ye yükseltin',
  'chg.cut.plan.when.lower': 'en geç {time}',
  'chg.cut.plan.when.change': 'saat {time}',
  'chg.cut.plan.when.live': 'en geç {time}',
  'chg.cut.plan.when.raise': '{time} itibarıyla',
  'chg.cut.plan.note.late': 'TTL değerini zamanında düşürmek için geç: eski TTL ile önbelleğe alınan kopyalar değişiklikten sonra da kalabilir. Şimdi düşürürseniz değişikliği en erken {time} saatinde yapın.',
  'chg.cut.plan.note.past': 'Bu değişiklik zamanı geçti: daha sonraki bir zaman seçin.',
  'chg.cut.plan.note.already-low': 'TTL zaten {ttl} sn ya da daha düşük: önce düşürülecek bir şey yok.',
  'chg.cut.plan.err.ttl': 'Mevcut TTL değerini saniye olarak yazın (1 ile 2147483647 arasında bir tam sayı).',
  'chg.cut.plan.err.low': 'Düşürülecek TTL değerini seçin.',
  'chg.cut.plan.err.time': 'Değişikliğin zamanını seçin.',
  'chg.cut.plan.lang': 'Kontrol listesinin ve takvimin dili',
  'chg.cut.plan.copy': 'Kontrol listesini kopyala',
  'chg.cut.plan.ics': 'Takvime ekle (.ics)',
  'chg.cut.plan.icsTitle': 'Her adım için kendi saatinde bir etkinlik; yapılacak her işten 15 dakika önce bir hatırlatma — Outlook, Google Takvim ya da Apple Takvim için',
  'chg.cut.plan.icsSaved': '{file} kaydedildi',
  'chg.cut.plan.flush': 'Değişiklikten hemen sonra genel çözümleyicilerden önbellekteki kopyayı silmelerini isteyin — kullanıcıları değişikliği hemen alır:'
});

/** How long a watch outlives its page (a language switch mounts the page again at once). */
const REMOUNT_GRACE_MS = 2000;

/** The watch that runs now (one at a time: there is one check page), for a data clear or workspace switch. */
let active = null;

state.subscribe(({ key }) => {
  if ((key === 'cleared' || key === 'workspace') && active) endWatch(active.memo, 'cancelled');
});

/** A time of day in the UI language ('15:42'), with its date when it is not today. */
function timeOfDay(ms, now = Date.now()) {
  const d = new Date(ms);
  if (new Date(now).toDateString() !== d.toDateString()) return formatDateTime(d);
  return new Intl.DateTimeFormat(localeTag(), { hour: '2-digit', minute: '2-digit' }).format(d);
}

/** '2026-10-08T14:00' (a datetime-local field's value) of a time, in the browser's time zone. */
function localInput(ms) {
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** A datetime-local field's value as ms epoch (the browser's time zone), or null. */
function readLocalInput(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(String(value || ''))) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

/**
 * End the watch of a check: its job finishes (done → the opted-in notification), the memo forgets it.
 * @param {object} memo the check page's memo
 * @param {'done'|'cancelled'|'error'} status
 * @param {string} [body] the notification's text
 */
function endWatch(memo, status, body = '') {
  const w = memo && memo.watch;
  if (!w) return;
  clearTimeout(w.grace);
  memo.watch = null;
  if (active && active.memo === memo) active = null;
  w.job.finish({ status, body });
}

/**
 * Mount the cutover assistant on the check page.
 * @param {{ ctx: object, check: import('../lib/changecheck.js').ExpectedCheck, memo: object, view: HTMLElement,
 *   actions: HTMLElement, before: Node|null, strip: HTMLElement, planner: HTMLElement, url: () => string,
 *   headline: () => string, resume: () => void }} opts
 *   `actions` the hero's buttons (the Watch button goes before `before`); `strip` and `planner` the
 *   slots of the watch line and the planner; `resume` restarts the page's schedule after a stop
 * @returns {{ countdown: (r: object|null) => HTMLElement|null, sync: () => void }}
 */
export function mountCutover({ ctx, check, memo, view, actions, before = null, strip, planner, url, headline, resume }) {
  const { t } = ctx;

  /* --- watch -------------------------------------------------------------------- */
  const watchBtn = Button({ label: t('chg.cut.watch'), icon: 'eye', size: 'sm', title: t('chg.cut.watchTitle'), dataset: { action: 'check-watch' }, onClick: () => startWatch() });
  actions.insertBefore(watchBtn, before && before.parentNode === actions ? before : null);
  const stripText = h('span', { class: 'chg-cut-strip-text' });
  const notifyHost = h('span', { class: 'chg-cut-notify' });
  const stripEl = h('div', { class: 'chg-cut-strip text-sm', hidden: true, dataset: { watch: '' } }, Icon('eye', { size: 14 }), stripText, notifyHost);
  strip.append(stripEl);
  let notifyFor = null;

  function startWatch() {
    if (memo.watch || memo.stop === 'done') return;
    const hadFocus = globalThis.document && globalThis.document.activeElement === watchBtn;
    memo.watch = {
      startedAt: Date.now(),
      job: startJob({ view: 'change' }),
      grace: null,
      // The page's schedule while watching: the watch's 24 hours, the backoff counted from the last round.
      next: (s) => nextWatch({ ...s, startedAt: memo.watch ? memo.watch.startedAt : s.startedAt, lastAt: memo.lastAt ? Number(memo.lastAt) : null })
    };
    active = { memo };
    // A stopped check (Stop, two hours, a long TTL, no answer) goes on; one that runs keeps its next round.
    if (memo.stop) {
      memo.stop = null;
      memo.errorRounds = 0;
      resume();
    } else sync();
    if (hadFocus) view.querySelector('[data-action="check-stop"]:not([hidden])')?.focus();
  }

  /** Follow the page's check: the job's progress, its end, the watch line and the Watch button. */
  function sync() {
    const w = memo.watch;
    if (w && memo.stop) {
      const status = memo.stop === 'user' ? 'cancelled' : memo.stop === 'failed' ? 'error' : 'done';
      const body = memo.stop === 'done' ? headline() : (view.querySelector('.chg-stopped')?.textContent || headline());
      endWatch(memo, status, body);
      announce(t('chg.cut.ended'));
    } else if (w) {
      w.job.update(watchProgress(check, memo.latest).fraction);
    }
    paintStrip();
    watchBtn.hidden = !!memo.watch || memo.stop === 'done';
    planSync();
  }

  function paintStrip() {
    const w = memo.watch;
    stripEl.hidden = !w;
    stripEl.dataset.watch = w ? 'on' : '';
    if (!w) {
      notifyFor = null;
      clear(notifyHost);
      return;
    }
    const p = watchProgress(check, memo.latest);
    const now = Date.now();
    const last = lastExpiry(check, memo.latest, now);
    const parts = [t('chg.cut.watching'), t('chg.cut.progress', { done: p.done, count: p.pairs })];
    if (last && last > now) parts.push(t('chg.cut.lastExpiry', { time: timeOfDay(last, now) }));
    stripText.textContent = ` ${parts.join(' · ')}`;
    if (notifyFor !== w.job) {
      notifyFor = w.job;
      clear(notifyHost);
      notifyHost.append(NotifyButton(w.job));
    }
  }

  /* --- countdown ---------------------------------------------------------------- */
  /** The live countdown of a resolver that is not done yet, or null. */
  function countdown(r) {
    const cd = cacheCountdown(r, Date.now());
    if (!cd) return null;
    const el = h('span', { class: 'muted chg-res-cached chg-cut-countdown', dataset: { cutUntil: String(cd.until), cutKind: cd.kind } });
    paintCountdown(el);
    return el;
  }

  function paintCountdown(el, now = Date.now()) {
    const until = Number(el.dataset.cutUntil);
    const left = until - now;
    el.dataset.expired = left <= 0 ? '1' : '';
    el.textContent = `${t(`chg.cut.cd.${el.dataset.cutKind}`, { time: timeOfDay(until, now) })} · ${left <= 0 ? t('chg.cut.cd.expired') : t('chg.cut.cd.left', { left: clockLeft(left) })}`;
  }

  /* --- planner ------------------------------------------------------------------- */
  const plan = memo.plan || (memo.plan = { ttl: '', ttlEdited: false, low: PLAN_DEFAULT_LOW, at: '', atEdited: false, lang: getLang(), open: false });
  const ttlField = textInput({
    label: t('chg.cut.plan.ttl'), value: plan.ttl, inputmode: 'numeric', mono: true, attrs: { 'data-field': 'cut-ttl' },
    onInput: (v) => { plan.ttl = v.trim(); plan.ttlEdited = true; drawPlanSoon(); }
  });
  const lowField = select({
    label: t('chg.cut.plan.low'), value: String(plan.low),
    options: PLAN_LOW_TTLS.map((s) => ({ value: String(s), label: t('chg.cut.plan.seconds', { n: formatNumber(s) }) })),
    onChange: (v) => { plan.low = Number(v); drawPlan(); }
  });
  lowField.input.dataset.field = 'cut-low';
  const atField = textInput({
    label: t('chg.cut.plan.at'), type: 'datetime-local', value: plan.at, attrs: { 'data-field': 'cut-at' },
    onInput: (v) => { plan.at = v; plan.atEdited = true; drawPlanSoon(); },
    onChange: (v) => { plan.at = v; plan.atEdited = true; drawPlan(); }
  });
  const planOut = h('div', { class: 'stack-sm chg-cut-plan-out', attrs: { 'aria-live': 'polite' } });
  const drawPlanSoon = debounce(() => drawPlan(), 250);
  const box = Disclosure({
    summary: t('chg.cut.plan.title'), open: plan.open, className: 'chg-cut-plan',
    children: h('div', { class: 'stack' },
      h('p', { class: 'muted text-sm' }, t('chg.cut.plan.lead')),
      h('div', { class: 'chg-cut-plan-fields' }, ttlField.el, lowField.el, atField.el),
      planOut)
  });
  box.addEventListener('toggle', () => { plan.open = box.open; });
  planner.append(h('section', { class: 'card chg-cut-plan-card', dataset: { part: 'planner' } }, box));

  /** Fill what the user has not typed: the TTL the resolvers returned, a change time it allows. */
  function planSync() {
    const seen = observedTtl(check, memo.latest).max;
    const likely = likelyTtl(seen);
    if (!plan.ttlEdited && likely && plan.ttl !== String(likely)) {
      plan.ttl = String(likely);
      ttlField.value = plan.ttl;
    }
    ttlField.setHint(seen ? t('chg.cut.plan.ttlSeen', { seen: formatNumber(seen), ttl: formatNumber(likely) }) : t('chg.cut.plan.ttlNone'));
    drawPlan();
  }

  function drawPlan() {
    const now = Date.now();
    const ttl = plan.ttl === '' ? NaN : Number(plan.ttl);
    if (!plan.atEdited && Number.isInteger(ttl) && ttl > 0) {
      const at = localInput(defaultChangeAt(now, ttl, plan.low));
      if (at !== plan.at) {
        plan.at = at;
        atField.value = at;
      }
    }
    const p = ttlPlan({ changeAt: readLocalInput(plan.at), currentTtl: ttl, lowTtl: plan.low, now });
    // Drawn again only when something it shows changes (the earliest time is shown to the minute).
    const key = JSON.stringify([p.ok ? { ...p, earliest: Math.floor(p.earliest / 60000) } : p, plan.lang, getLang()]);
    if (planOut.dataset.key === key) return;
    planOut.dataset.key = key;
    clear(planOut);
    planOut.dataset.state = p.ok ? 'ok' : p.error;
    if (!p.ok) {
      if (plan.ttl !== '' || p.error !== 'ttl') planOut.append(Alert({ variant: 'warn', compact: true, message: t(`chg.cut.plan.err.${p.error}`) }));
      return;
    }
    const steps = [];
    if (p.lower) steps.push(['lower', p.lowerAt, { from: formatNumber(p.currentTtl), to: formatNumber(p.lowTtl) }]);
    steps.push(['change', p.changeAt, {}], ['live', p.liveBy, {}]);
    if (p.lower) steps.push(['raise', p.raiseAt, { to: formatNumber(p.currentTtl) }]);
    planOut.append(h('ol', { class: 'chg-cut-steps' }, steps.map(([step, at, params]) => h('li', { class: 'chg-cut-step', dataset: { step, at: String(at) } },
      h('span', { class: 'chg-cut-when mono' }, t(`chg.cut.plan.when.${step}`, { time: timeOfDay(at, now) })),
      h('span', { class: 'chg-cut-what' }, t(`chg.cut.plan.step.${step}`, params))))));
    for (const note of p.notes) {
      planOut.append(Alert({
        variant: note === 'already-low' ? 'info' : 'warn', compact: true,
        message: t(`chg.cut.plan.note.${note}`, { time: timeOfDay(p.earliest, now), ttl: formatNumber(p.currentTtl) })
      }));
    }
    const text = planChecklist(p, {
      lang: plan.lang, zone: check.zone, records: check.sets.map((s) => `${s.name} ${s.type}`), url: url(),
      offsetOf: (ms) => -new Date(ms).getTimezoneOffset()
    });
    const langCtl = SegmentedControl({
      label: t('chg.cut.plan.lang'), size: 'sm', value: plan.lang, className: 'chg-cut-lang',
      options: [{ value: 'en', label: 'English' }, { value: 'tr', label: 'Türkçe' }],
      onChange: (v) => { plan.lang = v; drawPlan(); }
    });
    langCtl.el.dataset.control = 'cut-lang';
    const copy = CopyButton(() => text, { label: t('chg.cut.plan.copy'), size: 'sm', variant: 'secondary', toastOnCopy: true });
    copy.dataset.action = 'cut-copy';
    // The same steps as calendar events, in the checklist's language (lib/cutover.js planCalendar).
    const ics = Button({
      label: t('chg.cut.plan.ics'), icon: 'calendar', size: 'sm', variant: 'secondary', title: t('chg.cut.plan.icsTitle'), dataset: { action: 'cut-ics' },
      onClick: () => {
        const cal = planCalendar(p, { lang: plan.lang, zone: check.zone, records: check.sets.map((s) => `${s.name} ${s.type}`), url: url(), now: Date.now() });
        const file = downloadText(timestampedName('dns-cutover', 'ics', check.zone), cal, 'text/calendar;charset=utf-8');
        ctx.toast(t('chg.cut.plan.icsSaved', { file }), { type: 'success', timeout: 2500 });
      }
    });
    const flush = h('p', { class: 'muted text-sm chg-cut-flush', dataset: { part: 'flush' } }, t('chg.cut.plan.flush'), ' ',
      FLUSH_LINKS.flatMap((l, i) => [i ? ' · ' : null, ExternalLink(l.url, l.name, { className: 'chg-cut-flush-link' })]).filter(Boolean));
    planOut.append(h('div', { class: 'chg-cut-list-head' }, langCtl.el, h('div', { class: 'cluster chg-cut-list-actions' }, copy, ics)),
      CodeBlock(text, { wrap: true, copy: false, label: plan.lang === 'tr' ? 'Türkçe' : 'English', className: 'chg-cut-list' }), flush);
  }

  /* --- the page's life ------------------------------------------------------------- */
  // A watch of this check from before a language switch: this page takes it over.
  if (memo.watch) {
    clearTimeout(memo.watch.grace);
    memo.watch.grace = null;
    active = { memo };
  }
  const ticker = setInterval(() => {
    if (!view.isConnected) return;
    const now = Date.now();
    for (const el of view.querySelectorAll('[data-cut-until]')) paintCountdown(el, now);
    if (memo.watch) paintStrip();
  }, 1000);
  ctx.onCleanup(() => {
    clearInterval(ticker);
    // Leaving the page ends its watch (its rounds only run while the page is on screen), unless
    // the same check is mounted again at once (a language switch).
    const w = memo.watch;
    if (w) w.grace = setTimeout(() => { if (memo.watch === w) endWatch(memo, 'cancelled'); }, REMOUNT_GRACE_MS);
  });
  sync();
  return { countdown, sync };
}
