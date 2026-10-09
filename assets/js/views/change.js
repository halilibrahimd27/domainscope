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
 * two hours, when nothing can change before then (a long TTL), or when a record had no answer
 * from any resolver three rounds in a row (and says so); offline it says so and asks once the
 * connection is back. Stop (Esc; a round already running still shows its answers, nothing more is
 * asked) / Check now / Check again (every record on every resolver, from scratch); the keyboard
 * focus moves to Stop while a round runs, and to Check again once the check stops. The cutover
 * assistant (ui/cutover.js, loaded with the page) adds Watch until live (the same schedule as a
 * long job for up to 24 hours, with "Notify me when done"), a live cache countdown per resolver
 * and the TTL planner with its checklist.
 *
 * Shareable: `#/change?t=caa&domain=example.com&cas=letsencrypt` opens a form (the "Edit in DNS
 * change request" of Domain Health and Zone File); a carried target fills the domain
 * (`domain=…&run=0`). The form and a check's answers are kept for the page session (module
 * state), and forgotten on "Delete all local data" and a workspace switch.
 *
 * The page template (ui/template.js, docs/DESIGN.md §5.5, Editor): the form is the input card, whole
 * (the output is built as you type), with "Read the current records" as its run bar; the change's
 * result header `.chg-result` — "What changes: + TXT _acme-challenge.example.com", the zone and the
 * template, the errors and warnings and the sets added, changed and removed (lib/fixes.js
 * changeStatus), Copy summary and Copy link (the check page), the next step "Check propagation
 * (Global DNS)" —, the problems and the outputs. The check page's result header `.chg-hero`: the
 * headline as its title, the sets live as its key metric (lib/changecheck.js checkStatus), Copy
 * summary and Copy link, its run row (Check now / Stop / Check again, Watch until live) with what
 * it sends.
 */

import { h, clear, debounce, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, Icon, announce, checkbox, checkboxGroup, describeError, select, textInput, textarea
} from '../ui/components.js';
import { registerStrings, hasString, localeTag, formatDateTime, formatDuration, formatNumber } from '../i18n.js';
import { state as stateSingleton } from '../state.js';
import {
  EmptyState, NextSteps, PrivacyNote, ResultActions, ResultHeader, ResultTitle, RunBar, StatusSummary, ToolInput
} from '../ui/template.js';
import {
  CHANGE_TEMPLATES, FIX_FIELDS, FIX_CAS, TEMPLATE_IDS, TXT_FAMILIES, buildChange, changeTemplate, templateInput, validateChange, hasErrors,
  readCurrent, countSpfLookups, valueText, requestSummaryFacts, changeStatus, changeHeadline
} from '../lib/fixes.js';
import {
  CHECK_RESOLVERS, CHECK_LIMITS, CHECK_HEADLINE_SEVERITY, decodeCheck, linkQuery, checkRound, checkState, checkStatus, nextCheck, pairKey,
  checkFromRequest, encodeCheck
} from '../lib/changecheck.js';
import { normalizeHostname, registrableDomain } from '../lib/domain.js';
import { getResolver } from '../lib/resolvers.js';
import { isFillOnly } from '../lib/session.js';
import { mergeSignals, onceAsync } from '../lib/util.js';
import { ChangeOutputs, ProblemList, builderParams, checkUrl } from '../ui/fix-panel.js';
import { SummaryButton } from '../ui/summary-button.js';
import { registerRunning } from '../ui/jobs.js';
import '../ui/view-summaries.js'; // the Copy summaries of the form's result and the check page: lib/summary.js changeSummary and its texts

/** The check page's cutover assistant: watch mode, the cache countdowns, the TTL planner (loaded with the page). */
const loadCutover = onceAsync(() => import('../ui/cutover.js'));

/** Route id (`#/change`). */
export const id = 'change';
/** i18n key of the page title. */
export const titleKey = 'nav.change';
/** Icon name (ui/components.js Icon). */
export const icon = 'edit';

/** The record types Global DNS asks for that a change can hold: its next step "Check propagation" names the first such set. */
const GLOBAL_CHECK_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA']);

registerStrings('en', {
  'chg.template': 'Template',
  'chg.read': 'Read the current records',
  'chg.readAgain': 'Read again',
  'chg.privacy': 'Nothing is sent while you fill in the form. “Read the current records” sends only the names and record types of the change to your DNS-over-HTTPS resolvers.',
  'chg.needsRead': 'This change is built from what the names hold now: read the current records first, or the outputs say what they cannot know.',
  'chg.readDone': { one: 'Current records read at {time}: {count} name and type.', other: 'Current records read at {time}: {count} names and types.' },
  'chg.readFailed': { one: '{count} lookup got no answer: its values stay unknown.', other: '{count} lookups got no answer: their values stay unknown.' },
  'chg.readStale': 'The form names records that were not read: read again to include them.',
  'chg.readError': 'The current records could not be read ({reason}).',
  'chg.spfCounting': 'SPF lookups counted with the includes as they are published now.',
  'chg.spfStale': 'The SPF record changed after its lookups were counted: read again to count them.',
  'chg.problems': 'Before you send it',
  'chg.blocked': 'Fix the errors above: the change is written out once it has none.',
  'chg.emptyLine': 'Fill in the form: the instructions for the DNS admin, the change as BIND, Route 53, the Cloudflare API, octoDNS and Terraform, and a link that shows when it is live appear here.',
  'chg.result.lead': 'What changes:',
  'chg.result.more': 'and {count} more',
  'chg.result.none': 'Nothing changes: the records are already like this',
  'chg.kind.added': 'added',
  'chg.kind.changed': 'changed',
  'chg.kind.removed': 'removed',
  'chg.count.error': { one: '{count} error', other: '{count} errors' },
  'chg.count.warn': { one: '{count} warning', other: '{count} warnings' },
  'chg.count.added': '{count} added',
  'chg.count.changed': '{count} changed',
  'chg.count.removed': '{count} removed',
  'chg.next.global': 'Check propagation (Global DNS)',
  'chg.next.globalTitle': 'Ask 12 public resolvers and 30+ locations for {name} {type}',
  'chg.check.title': 'Is the change live?',
  'chg.check.purpose': 'Four public resolvers, asked again until every record set is live.',
  'chg.check.keyTitle': '{done} of {count} record sets live everywhere',
  'chg.check.count.wrong': { one: '{count} record set has a wrong value', other: '{count} record sets have a wrong value' },
  'chg.check.count.pending': { one: '{count} record set not live everywhere yet', other: '{count} record sets not live everywhere yet' },
  'chg.check.count.done': { one: '{count} record set live everywhere', other: '{count} record sets live everywhere' },
  'chg.check.count.noanswer': { one: '{count} record set with no answer', other: '{count} record sets with no answer' },
  'chg.check.count.waiting': { one: '{count} record set being asked', other: '{count} record sets being asked' },
  'chg.check.zone': 'Zone {zone}',
  'chg.check.head.done': 'Done: every resolver sees the change.',
  'chg.check.head.done-partial': { one: 'Done on every resolver that answered; {count} resolver did not answer.', other: 'Done on every resolver that answered; {count} resolvers did not answer.' },
  'chg.check.head.wrong': 'A resolver serves a value that is neither the new nor the old one: check what was published.',
  'chg.check.head.pending': { one: 'Not live everywhere yet: {done} of {count} record set done.', other: 'Not live everywhere yet: {done} of {count} record sets done.' },
  'chg.check.head.no-answer': { one: 'No resolver answered for {count} record set, so whether it is live is not known.', other: 'No resolver answered for {count} record sets, so whether they are live is not known.' },
  'chg.check.head.unknown': 'Asking the resolvers…',
  'chg.check.stop.timeout': 'Stopped after two hours. Check again when the change has been made.',
  'chg.check.stop.cached': 'Stopped: the resolvers that are not done yet keep their cached answer until {time}, so asking before then shows nothing new.',
  'chg.check.stop.failed': 'Stopped: no answer in three rounds in a row. DNS-over-HTTPS may be blocked on this network, the connection may be down, or the zone’s name servers may be failing (SERVFAIL). Check again once that is fixed.',
  'chg.check.stop.user': 'Stopped.',
  'chg.check.checked': 'Checked {time}',
  'chg.check.next': 'Next check in {wait}',
  'chg.check.running': 'Checking…',
  'chg.check.now': 'Check now',
  'chg.check.stop': 'Stop',
  'chg.switchRunning': 'The DNS change request’s “is it live?” check',
  'chg.check.again': 'Check again',
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
  'chg.check.v.noAnswer': 'No answer',
  'chg.check.err.timeout': 'timed out',
  'chg.check.err.network': 'network error',
  'chg.check.err.http': 'server error',
  'chg.check.err.rate-limit': 'rate limited',
  'chg.check.err.parse': 'unreadable reply',
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
  'chg.check.offline': 'You are offline: the check goes on once the connection is back.',
  'chg.check.failed': 'The check could not run ({reason}). Check now tries again.'
});

registerStrings('tr', {
  'chg.template': 'Şablon',
  'chg.read': 'Mevcut kayıtları oku',
  'chg.readAgain': 'Yeniden oku',
  'chg.privacy': 'Formu doldururken hiçbir şey gönderilmez. “Mevcut kayıtları oku” yalnızca değişikliğin adlarını ve kayıt türlerini DNS-over-HTTPS çözümleyicilerinize gönderir.',
  'chg.needsRead': 'Bu değişiklik adların şu an tuttuklarından oluşturulur: önce mevcut kayıtları okuyun; yoksa çıktılar bilemediklerini belirtir.',
  'chg.readDone': 'Mevcut kayıtlar {time} saatinde okundu: {count} ad ve tür.',
  'chg.readFailed': '{count} sorgu yanıt almadı: değerleri bilinmiyor.',
  'chg.readStale': 'Formda okunmamış kayıtlar var: onları da almak için yeniden okuyun.',
  'chg.readError': 'Mevcut kayıtlar okunamadı ({reason}).',
  'chg.spfCounting': 'SPF sorguları include’ların şu anki hâliyle sayıldı.',
  'chg.spfStale': 'SPF kaydı, sorguları sayıldıktan sonra değişti: saymak için yeniden okuyun.',
  'chg.problems': 'Göndermeden önce',
  'chg.blocked': 'Yukarıdaki hataları düzeltin: hata kalmayınca değişiklik yazılır.',
  'chg.emptyLine': 'Formu doldurun: DNS yöneticisi için talimatlar, değişikliğin BIND, Route 53, Cloudflare API, octoDNS ve Terraform hâli ve ne zaman yayında olduğunu gösteren bir bağlantı burada belirir.',
  'chg.result.lead': 'Ne değişiyor:',
  'chg.result.more': 've {count} tane daha',
  'chg.result.none': 'Hiçbir şey değişmiyor: kayıtlar zaten böyle',
  'chg.kind.added': 'eklenecek',
  'chg.kind.changed': 'değişecek',
  'chg.kind.removed': 'silinecek',
  'chg.count.error': '{count} hata',
  'chg.count.warn': '{count} uyarı',
  'chg.count.added': '{count} eklenecek',
  'chg.count.changed': '{count} değişecek',
  'chg.count.removed': '{count} silinecek',
  'chg.next.global': 'Yayılmayı kontrol et (Global DNS)',
  'chg.next.globalTitle': '12 genel çözümleyiciye ve 30’dan fazla konuma {name} {type} sorulur',
  'chg.check.title': 'Değişiklik yayında mı?',
  'chg.check.purpose': 'Dört genel çözümleyiciye, her kayıt kümesi yayında olana kadar yeniden sorulur.',
  'chg.check.keyTitle': '{count} kayıt kümesinden {done} tanesi her yerde yayında',
  'chg.check.count.wrong': '{count} kayıt kümesinde yanlış değer var',
  'chg.check.count.pending': '{count} kayıt kümesi henüz her yerde yayında değil',
  'chg.check.count.done': '{count} kayıt kümesi her yerde yayında',
  'chg.check.count.noanswer': '{count} kayıt kümesine yanıt yok',
  'chg.check.count.waiting': '{count} kayıt kümesi soruluyor',
  'chg.check.zone': 'Zone {zone}',
  'chg.check.head.done': 'Tamam: tüm çözümleyiciler değişikliği görüyor.',
  'chg.check.head.done-partial': 'Yanıt veren tüm çözümleyicilerde tamam; {count} çözümleyici yanıt vermedi.',
  'chg.check.head.wrong': 'Bir çözümleyici ne yeni ne de eski olan bir değer döndürüyor: yayınlananı kontrol edin.',
  'chg.check.head.pending': 'Henüz her yerde yayında değil: {count} kayıt kümesinden {done} tanesi tamam.',
  'chg.check.head.no-answer': '{count} kayıt kümesi için hiçbir çözümleyici yanıt vermedi; yayında olup olmadığı bilinmiyor.',
  'chg.check.head.unknown': 'Çözümleyicilere soruluyor…',
  'chg.check.stop.timeout': 'İki saat sonra durduruldu. Değişiklik yapıldığında yeniden kontrol edin.',
  'chg.check.stop.cached': 'Durduruldu: henüz tamamlanmayan çözümleyiciler önbellekteki yanıtlarını {time} saatine kadar tutar; o zamandan önce sormak yeni bir şey göstermez.',
  'chg.check.stop.failed': 'Durduruldu: art arda üç turda yanıt yok. Bu ağda DNS-over-HTTPS engellenmiş, bağlantı kopmuş ya da zone’un ad sunucuları hata veriyor (SERVFAIL) olabilir. Bu düzelince yeniden kontrol edin.',
  'chg.check.stop.user': 'Durduruldu.',
  'chg.check.checked': 'Kontrol: {time}',
  'chg.check.next': 'Sonraki kontrol {wait} sonra',
  'chg.check.running': 'Kontrol ediliyor…',
  'chg.check.now': 'Şimdi kontrol et',
  'chg.check.stop': 'Durdur',
  'chg.switchRunning': 'DNS değişiklik talebinin “yayında mı?” kontrolü',
  'chg.check.again': 'Yeniden kontrol et',
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
  'chg.check.v.noAnswer': 'Yanıt yok',
  'chg.check.err.timeout': 'zaman aşımı',
  'chg.check.err.network': 'ağ hatası',
  'chg.check.err.http': 'sunucu hatası',
  'chg.check.err.rate-limit': 'hız sınırı',
  'chg.check.err.parse': 'anlaşılamayan yanıt',
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
  'chg.check.offline': 'Çevrimdışısınız: bağlantı geri gelince kontrol sürer.',
  'chg.check.failed': 'Kontrol çalışamadı ({reason}). Şimdi kontrol et yeniden dener.'
});

/* ------------------------------------------------------------------------ */
/* Module state (page session only)                                          */
/* ------------------------------------------------------------------------ */

/**
 * The form: the template on screen and each template's values, the carried domain, the last read,
 * and the output tab and instructions' language picked (they stay while the form is edited).
 */
let draft = null;
/** The last check: its query, answers and timing, so a language switch or a return resumes it. */
let checkMemo = null;

function freshDraft() {
  return { template: 'acme-txt', forms: {}, carried: null, read: null, choice: {} };
}

stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared' && key !== 'workspace') return;
  draft = null;
  if (checkMemo && checkMemo.timer) clearTimeout(checkMemo.timer);
  checkMemo = null;
});

/**
 * Is the "is it live?" check of the page on screen still going — a round asking now, the next one
 * scheduled, or one waiting for the connection — until it stops by itself or by Stop? A switch to
 * another workspace forgets it (above), so the shell names it first.
 * @param {object|null} memo the check's state (`checkMemo`)
 * @returns {boolean}
 */
export function checkInProgress(memo) {
  return !!(memo && memo.mounted && !memo.stop && (memo.running || memo.timer || memo.offline));
}
registerRunning('chg.switchRunning', () => checkInProgress(checkMemo));

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for tests)                                        */
/* ------------------------------------------------------------------------ */

/** A time of day in the UI language ('14:02:07'), a date too when it is not today. */
function clockTime(at) {
  const d = at instanceof Date ? at : new Date(at);
  const today = new Date().toDateString() === d.toDateString();
  return today ? new Intl.DateTimeFormat(localeTag(), { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(d) : formatDateTime(d);
}

/** Why a resolver gave no answer, as the page words it (lib/util.js errorKind; `unavailable` is a server error too). */
export const CHECK_ERROR_KINDS = Object.freeze(['timeout', 'network', 'http', 'rate-limit', 'parse']);

/**
 * The badge of a resolver that gave no answer: an error kind in words, a DNS rcode (SERVFAIL,
 * REFUSED …) as it is, anything else as a plain "No answer".
 * @param {string|null} reason judgeAnswer's reason of an error
 * @param {(key: string, params?: object) => string} t
 * @returns {string}
 */
export function errorLabel(reason, t) {
  const kind = reason === 'unavailable' ? 'http' : reason;
  if (CHECK_ERROR_KINDS.includes(kind)) return t('chg.check.v.error', { reason: t(`chg.check.err.${kind}`) });
  if (/^[A-Z][A-Z0-9]*$/.test(String(reason || ''))) return t('chg.check.v.error', { reason });
  return t('chg.check.v.noAnswer');
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
  // The editor's run bar (DESIGN §5.5, Editor): "Read the current records" — the one thing the form
  // sends — with Ctrl/Cmd+Enter; the outputs are built as you type. It is the primary button while
  // the change still needs a read, and steps back once the outputs stand without one.
  const runBar = RunBar({
    label: t('chg.read'),
    icon: 'search',
    dataset: { action: 'change-read', shortcut: 'submit' },
    stopDataset: { action: 'change-read-stop', shortcut: 'cancel' },
    onRun: () => readNow(),
    onStop: () => { if (reading) reading.abort(); },
    className: 'chg-run'
  });
  const readNote = h('div', { class: 'chg-read-note text-sm', attrs: { 'aria-live': 'polite' } });
  // Region 2: one card — the template and what it does, its fields, what was read and Read, what is
  // sent. An editor's form stays whole: it is the input of a result built live.
  const input = ToolInput({
    className: 'chg-form-card',
    fieldsClass: 'chg-form-head',
    label: t('nav.change'),
    primary: h('div', { class: 'stack-sm chg-template-wrap' }, tplSelect.el, tplDesc),
    more: [fieldsEl, h('div', { class: 'chg-run-row' }, readNote, runBar.el)],
    privacy: PrivacyNote({ text: t('chg.privacy'), className: 'chg-privacy' })
  });
  // Region 4: the change's result header; region 7: its problems; region 8: its outputs (the tabs).
  const head = ResultHeader({ className: 'chg-result' });
  /** The result header's actions (Copy summary, Copy link: the check page), drawn per change. */
  let actions = null;
  const problemsEl = h('div', { class: 'chg-problems' });
  // A form of its own for the shell's Ctrl/Cmd+Enter: nothing in the outputs reads the records.
  const outputsEl = h('div', { class: 'chg-outputs', dataset: { shortcutScope: 'results' } });
  const emptyEl = h('div', { class: 'chg-empty' }, EmptyState({
    icon: 'edit',
    message: t('chg.emptyLine'),
    checks: [t('fixp.admin'), 'BIND', 'Route 53', 'Cloudflare API', 'octoDNS', 'Terraform']
  }));
  const resultEl = h('div', { class: 'chg-result-wrap', hidden: true }, head.el, problemsEl, outputsEl);
  container.append(h('div', { class: 'chg-view', dataset: { page: 'builder' } }, input.el, emptyEl, resultEl, runBar.float));
  ctx.onCleanup(() => {
    runBar.dispose();
    if (actions) actions.dispose();
    if (reading) reading.abort();
  });

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

  /** "What changes: + TXT _acme-challenge.example.com and 2 more" (lib/fixes.js changeHeadline). */
  function headTitle(facts) {
    const { set, more } = changeHeadline(facts);
    if (!set) return ResultTitle({ severity: 'ok', text: t('chg.result.none') });
    return ResultTitle({
      icon: 'edit',
      text: [
        h('span', { class: 'chg-head-lead' }, t('chg.result.lead')), ' ',
        h('span', { class: 'chg-sign', dataset: { kind: set.kind }, attrs: { 'aria-hidden': 'true' } }, set.sign),
        h('span', { class: 'sr-only' }, t(`chg.kind.${set.kind}`)), ' ',
        h('span', { class: 'chg-head-type' }, set.family ? `${set.type} · ${set.family}` : set.type), ' ',
        h('span', { class: 'result-subject mono' }, set.name),
        more ? h('span', { class: 'chg-head-more' }, ` ${t('chg.result.more', { count: more })}`) : null
      ]
    });
  }

  function rebuild() {
    const form = formOf(draft.template);
    const first = buildChange(draft.template, form, {});
    const read = currentFor(first.zone);
    req = read ? buildChange(draft.template, form, { current: read.current }) : first;
    const problems = validateChange(req, read ? { current: read.current, spf: read.spf } : {});
    const params = builderParams(draft.template, form);
    if (JSON.stringify(params) !== JSON.stringify(ctx.params)) ctx.setParams(params);
    renderReadNote(read, problems.some((p) => p.key === 'fix.p.spf-recount'));
    clear(problemsEl);
    clear(outputsEl);
    const tpl = changeTemplate(draft.template);
    const unread = tpl.needsCurrent && !read && first.zone;
    const shown = problems.filter((p) => !(unread && p.key === 'fix.p.read-first'));
    const started = !first.problems.some((p) => p.key === 'fix.p.domain-missing' || p.key === 'fix.p.name-missing');
    emptyEl.hidden = started;
    resultEl.hidden = !started;
    // While the change needs a read, Read leads; once its outputs stand, it steps back.
    runBar.setPrimary(!started || !!unread || hasErrors({ problems }));
    if (!started) return;
    const built = req;
    const facts = requestSummaryFacts(built, { problems: shown, templateName: t(`fix.tpl.${built.template}`), at: new Date() });
    const blocked = hasErrors({ problems });
    head.setState('done');
    head.el.dataset.blocked = String(blocked);
    head.set('title', headTitle(facts));
    head.set('meta', [
      h('span', { class: 'chg-head-zone' }, t('chg.check.zone', { zone: built.zone || '—' })),
      h('span', { class: 'chg-head-template' }, t(`fix.tpl.${built.template}`))
    ]);
    head.set('notes', unread ? h('p', { class: 'chg-head-note', dataset: { role: 'needs-read' } }, Icon('info', { size: 14 }), h('span', null, t('chg.needsRead'))) : null);
    // The counts: a press of the errors or the warnings brings the problems into view.
    head.set('status', StatusSummary({
      items: changeStatus(facts).map((item) => ({
        ...item,
        text: t(`chg.count.${item.key}`, { count: item.count }),
        onPress: item.key === 'error' || item.key === 'warn' ? () => focusProblems() : null
      }))
    }).el);
    if (shown.length) {
      problemsEl.append(h('section', { class: 'card chg-problems-card', dataset: { problems: shown.length } },
        h('h3', { class: 'section-title' }, t('chg.problems')), ProblemList(shown)));
    }
    if (actions) actions.dispose();
    actions = null;
    if (blocked) {
      head.set('actions', null);
      head.set('next', null);
      outputsEl.append(h('p', { class: 'muted text-sm chg-blocked' }, t('chg.blocked')));
      return;
    }
    // Copy summary for the ticket: the template, each set and what is done to it, the problems; the
    // change's check link as its URL (lib/summary.js changeSummary), never the form's. Copy link
    // shares that check page too.
    const link = encodeCheck(checkFromRequest(built));
    const checkLink = () => (link.ok ? checkUrl(link.query) : null);
    actions = ResultActions({
      summary: SummaryButton({
        kind: 'change',
        plainLabel: t('result.plainTitle'),
        facts: () => requestSummaryFacts(built, { problems: shown, templateName: t(`fix.tpl.${built.template}`), at: new Date() }),
        url: checkLink
      }),
      link: link.ok ? checkLink : null,
      className: 'chg-result-actions'
    });
    head.set('actions', actions.el);
    const firstSet = built.rrsets.find((r) => GLOBAL_CHECK_TYPES.includes(r.type));
    head.set('next', firstSet ? NextSteps({
      steps: [{
        label: t('chg.next.global'), icon: 'globe', title: t('chg.next.globalTitle', { name: firstSet.name, type: firstSet.type }),
        href: ctx.href('global', { name: firstSet.name, type: firstSet.type }), dataset: { role: 'change-global' }
      }]
    }) : null);
    outputsEl.append(ChangeOutputs(req, { fileStem: `dns-change-${req.zone}`, choice: draft.choice }));
  }

  /** The status summary's errors and warnings: the problems card in view, the keyboard on it. */
  function focusProblems() {
    const card = problemsEl.querySelector('.chg-problems-card');
    if (!card) return;
    card.setAttribute('tabindex', '-1');
    card.scrollIntoView({ block: 'nearest', behavior: scrollBehavior() });
    card.focus({ preventScroll: true });
  }

  function renderReadNote(read, spfStale = false) {
    clear(readNote);
    runBar.setLabel(read ? t('chg.readAgain') : t('chg.read'));
    if (!read) return;
    const lines = [t('chg.readDone', { time: clockTime(read.at), count: read.count })];
    if (read.failed) lines.push(t('chg.readFailed', { count: read.failed }));
    if (req && req.reads.some((q) => !Object.hasOwn(read.current, `${q.name}|${q.type}`))) lines.push(t('chg.readStale'));
    if (spfStale) lines.push(t('chg.spfStale'));
    else if (read.spf && Object.keys(read.spf).length) lines.push(t('chg.spfCounting'));
    readNote.append(h('p', { class: 'muted', title: formatDateTime(read.at) }, Icon('check', { size: 14 }), ' ', lines.join(' ')));
  }

  /* --- read the current records ----------------------------------------------------- */
  /** The read that goes on (its controller), or null. */
  let reading = null;

  async function readNow() {
    const base = buildChange(draft.template, formOf(draft.template), {});
    if (!base.zone || !base.reads.length) {
      rebuild();
      return;
    }
    if (reading || !ctx.requireOnline()) return;
    ctx.runStarted(base.zone);
    const controller = new AbortController();
    reading = controller;
    runBar.setRunning(true);
    ctx.setBusy(t('chg.read'));
    try {
      const dns = await ctx.getDns();
      const signal = mergeSignals(ctx.signal, controller.signal);
      // What the template looks at (the SPF record it edits, the records whose TTL it lowers) and
      // what its records collide with; then what the change built from those answers adds.
      const current = await readCurrent(base.reads, { dns, signal });
      const next = buildChange(draft.template, formOf(draft.template), { current });
      const extra = next.reads.filter((q) => !Object.hasOwn(current, `${q.name}|${q.type}`));
      if (extra.length) Object.assign(current, await readCurrent(extra, { dns, signal }));
      const spf = await countSpfLookups(buildChange(draft.template, formOf(draft.template), { current }), { dns, signal });
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
      if (reading === controller) reading = null;
      if (!ctx.signal.aborted) runBar.setRunning(false);
      ctx.setBusy(false);
    }
  }

  renderFields();
  rebuild();
}

/* --- the check page --------------------------------------------------------------- */

const VERDICT_BADGE = Object.freeze({ done: ['ok', 'check-circle'], pending: ['warn', 'clock'], wrong: ['error', 'x-circle'], error: ['neutral', 'help'], waiting: ['neutral', 'clock'] });

/**
 * The check page's headline: its i18n key and params (the sets done of all; done-partial: the
 * resolvers that failed for at least one set; no-answer: the sets no resolver answered for).
 * @param {{ sets: object[] }} check
 * @param {Map<string, object>} latest
 * @param {ReturnType<typeof checkState>} st
 * @returns {{ key: string, params: { count: number, done: number } }}
 */
export function checkHeadline(check, latest, st) {
  const params = { count: check.sets.length, done: st.sets.filter((s) => s.state === 'done').length };
  if (st.headline === 'done-partial') params.count = CHECK_RESOLVERS.filter((rid) => check.sets.some((_, i) => (latest.get(pairKey(i, rid)) || {}).verdict === 'error')).length;
  if (st.headline === 'no-answer') params.count = st.sets.filter((s) => !s.counts.done).length;
  return { key: `chg.check.head.${st.headline}`, params };
}

/**
 * The Copy summary's facts of the check page (lib/summary.js changeSummary): the headline, each set
 * by name and type (with its TXT family) and what the resolvers answered, why the check stopped and
 * when it last asked. Never a value: those are in the check link the summary carries.
 * @param {{ zone: string, sets: object[] }} check
 * @param {{ latest: Map<string, object>, stop: string|null, cachedUntil: number|null, lastAt: number|null }} memo
 * @param {{ timeText?: (ms: number) => string }} [opts] the stop's time, as the page says it
 * @returns {object}
 */
export function checkSummaryFacts(check, memo, { timeText = (ms) => new Date(ms).toISOString() } = {}) {
  const st = checkState(check, memo.latest);
  return {
    zone: check.zone,
    headline: checkHeadline(check, memo.latest, st),
    sets: check.sets.map((exp, i) => ({
      name: exp.name,
      type: exp.family ? `${exp.type} · ${TXT_FAMILIES[exp.family]}` : exp.type,
      state: st.sets[i].state,
      done: st.sets[i].counts.done,
      resolvers: CHECK_RESOLVERS.length
    })),
    stop: memo.stop && memo.stop !== 'done' ? { key: `chg.check.stop.${memo.stop}`, params: { time: memo.cachedUntil ? timeText(memo.cachedUntil) : '' } } : null,
    at: memo.lastAt || null
  };
}

function mountCheck(container, ctx) {
  const { t } = ctx;
  // A sub-page of its own (#/change/check): the heading names what it does.
  ctx.setHeading({ title: t('chg.check.title'), purpose: t('chg.check.purpose') });
  // The link as it was opened (its readable form): what its length limit counts, Copy link, and
  // resuming the same check.
  const hash = String(globalThis.location ? globalThis.location.hash : '');
  const query = hash.startsWith('#/change/check?') ? hash.slice('#/change/check?'.length) : linkQuery(ctx.searchParams);
  const decoded = decodeCheck(query);
  const view = h('div', { class: 'chg-view chg-check', dataset: { page: 'check' } });
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
  if (!checkMemo || checkMemo.query !== query) {
    if (checkMemo && checkMemo.timer) clearTimeout(checkMemo.timer);
    checkMemo = { query, latest: new Map(), startedAt: Date.now(), round: 0, errorRounds: 0, lastAt: null, nextAt: null, pairs: null, stop: null, cachedUntil: null, timer: null, running: false };
  }
  const memo = checkMemo;
  memo.mounted = true;
  let ticker = null;

  /*
   * Region 4: the check's result header — the headline as its title (its status icon), the record
   * sets live as its key metric, the zone and when it asked, why it stopped, the status summary,
   * Copy summary and Copy link; then its own run row (Check now / Stop / Check again, and the
   * cutover assistant's Watch until live) with what it sends. There is no input: the link is it.
   */
  const head = ResultHeader({ className: 'chg-hero' });
  const metaEl = h('span', { class: 'chg-check-meta' });
  const nowBtn = Button({ label: t('chg.check.now'), icon: 'refresh', size: 'sm', variant: 'primary', dataset: { action: 'check-now', shortcut: 'submit' }, onClick: () => checkNow() });
  const stopBtn = Button({ label: t('chg.check.stop'), icon: 'stop', size: 'sm', dataset: { action: 'check-stop', shortcut: 'cancel' }, onClick: () => stop() });
  const againBtn = Button({ label: t('chg.check.again'), icon: 'refresh', size: 'sm', variant: 'primary', dataset: { action: 'check-again' }, onClick: () => again() });
  const actionBtns = [nowBtn, stopBtn, againBtn];
  const runRow = h('div', { class: 'cluster chg-hero-actions', attrs: { role: 'group', 'aria-label': t('result.nextLabel') } }, nowBtn, stopBtn, againBtn);
  const status = StatusSummary({ className: 'chg-check-status' });
  // Copy summary for the ticket: the headline and each set's answers, with this check's link (also Copy link's).
  const actions = ResultActions({
    summary: SummaryButton({
      kind: 'change',
      plainLabel: t('result.plainTitle'),
      facts: () => checkSummaryFacts(check, memo, { timeText: (ms) => formatDateTime(ms) }),
      url: () => checkUrl(query)
    }),
    link: () => checkUrl(query)
  });
  // Slots of the cutover assistant (ui/cutover.js): the watch line (a note), the TTL planner (the body).
  const watchSlot = h('div', { class: 'chg-cut-slot' });
  const stopHost = h('div', { class: 'chg-stop-host' });
  const planSlot = h('div', { class: 'chg-cut-slot' });
  let cut = null;
  head.set('meta', [Badge(t('chg.check.zone', { zone: check.zone }), { variant: 'neutral', mono: true, className: 'chg-zone' }), metaEl]);
  head.set('notes', [stopHost, watchSlot]);
  head.set('status', status.el);
  head.set('actions', actions.el);
  head.set('next', [runRow, PrivacyNote({ text: t('chg.check.privacy'), className: 'chg-check-privacy' })]);
  const setsEl = h('div', { class: 'stack chg-sets' });
  view.append(head.el, setsEl, planSlot,
    h('p', { class: 'text-sm chg-own' }, h('a', { href: ctx.href('change') }, Icon('edit', { size: 14 }), ' ', t('chg.check.own'))));

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
      else if (v === 'error') label = errorLabel(r.reason, t);
      else label = t(`chg.check.v.${v}`);
      const [variant, iconName] = VERDICT_BADGE[v];
      const showSeen = r && (v === 'pending' || v === 'wrong') && r.reason !== 'missing' && r.reason !== 'ttl';
      // The cutover assistant's live countdown once it is loaded, else the time alone.
      const live = cut && r ? cut.countdown(r) : null;
      const cached = !live && r && v === 'pending' && Number.isFinite(r.ttl) && r.ttl > 0 ? t('chg.check.cached', { time: clockTime(r.at + r.ttl * 1000) }) : null;
      list.append(h('li', { class: ['chg-res', `chg-res-${v}`], dataset: { resolver: rid, verdict: v, reason: r && r.reason ? r.reason : '' } },
        h('span', { class: 'chg-res-name' }, resolverName(rid)),
        Badge(label, { variant, icon: iconName, className: 'chg-res-verdict' }),
        showSeen || cached || live ? h('div', { class: 'chg-res-detail text-sm' },
          showSeen ? [h('span', { class: 'muted' }, `${t('chg.check.seen')}: `), h('span', { class: 'mono chg-res-seen' }, r.seen.length ? r.seen.map((x) => valueText(exp.type, x)).join(', ') : t('chg.check.nothing'))] : null,
          cached ? h('span', { class: 'muted chg-res-cached' }, `${showSeen ? ' · ' : ''}${cached}`) : null,
          live ? (showSeen ? [h('span', { class: 'muted' }, ' · '), live] : live) : null) : null));
    }
    const st = checkState({ sets: [exp] }, new Map(CHECK_RESOLVERS.map((rid) => [pairKey(0, rid), memo.latest.get(pairKey(i, rid))]).filter(([, x]) => x)));
    cards[i].dataset.state = st.sets[0].state;
  }

  /** A status item pressed: the first record set it counts, in view with the keyboard on it. */
  function focusSet(key) {
    const state = key === 'noanswer' || key === 'waiting' ? 'unknown' : key;
    const card = cards.find((c) => c.dataset.state === state);
    if (!card) return;
    card.setAttribute('tabindex', '-1');
    card.scrollIntoView({ block: 'nearest', behavior: scrollBehavior() });
    card.focus({ preventScroll: true });
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
    const head0 = checkHeadline(check, memo.latest, st);
    const words = t(head0.key, head0.params);
    const severity = CHECK_HEADLINE_SEVERITY[st.headline];
    head.setState(memo.running ? 'running' : 'done');
    head.set('title', ResultTitle({
      severity,
      running: !severity && memo.running,
      icon: severity ? null : 'clock',
      text: h('span', { class: 'chg-check-head-wrap', dataset: { headline: st.headline } }, words)
    }));
    const counts = checkStatus(check, memo.latest);
    head.set('key', h('span', { class: 'result-score chg-check-key', title: t('chg.check.keyTitle', { done: counts.done, count: counts.total }) },
      h('span', { class: 'result-score-value num' }, formatNumber(counts.done)),
      h('span', { class: 'result-score-max' }, `/${formatNumber(counts.total)}`)));
    status.update(counts.items.map((item) => ({
      ...item,
      text: t(`chg.check.count.${item.key}`, { count: item.count }),
      onPress: item.key === 'waiting' ? null : (key) => focusSet(key)
    })));
    clear(stopHost);
    if (memo.stop && memo.stop !== 'done') {
      stopHost.append(h('p', { class: 'text-sm chg-stopped', dataset: { stop: memo.stop } }, Icon('stop', { size: 14 }),
        h('span', null, t(`chg.check.stop.${memo.stop}`, { time: memo.cachedUntil ? formatDateTime(memo.cachedUntil) : '' }))));
    }
    // The headline is said when it changes (the header is no live region).
    if (lastHeadline !== null && lastHeadline !== st.headline) announce(words);
    lastHeadline = st.headline;
    renderMeta();
    const stopped = !!memo.stop;
    const focused = actionBtns.find((b) => b === globalThis.document?.activeElement) || null;
    nowBtn.hidden = stopped;
    stopBtn.hidden = stopped;
    againBtn.hidden = !stopped;
    nowBtn.disabled = memo.running;
    // A button that goes (Check now while a round runs, Stop once it stops) hands the keyboard focus
    // to the one that takes its place, never to the page's body.
    if (focused && (focused.hidden || focused.disabled)) (stopped ? againBtn : memo.running ? stopBtn : nowBtn).focus();
    if (cut) cut.sync();
  }

  function renderMeta() {
    const parts = [];
    if (memo.running) parts.push(t('chg.check.running'));
    else if (memo.lastAt) parts.push(t('chg.check.checked', { time: clockTime(memo.lastAt) }));
    if (!memo.stop && !memo.running && memo.nextAt) parts.push(t('chg.check.next', { wait: formatDuration(Math.max(0, memo.nextAt - Date.now())) }));
    if (memo.note && !memo.running) parts.push(memo.note);
    metaEl.textContent = parts.join(' · ');
  }

  function renderAll() {
    check.sets.forEach((_, i) => renderSet(i));
    renderHead();
  }

  async function runRound(only, { quiet = false } = {}) {
    if (memo.running) return;
    if (!ctx.requireOnline({ quiet })) {
      // No round now and none scheduled: the 'online' event asks these pairs once the connection is back.
      clearTimeout(memo.timer);
      memo.timer = null;
      memo.nextAt = null;
      memo.offline = { only };
      memo.note = t('chg.check.offline');
      renderHead();
      return;
    }
    memo.offline = null;
    memo.note = null;
    clearTimeout(memo.timer);
    memo.timer = null;
    memo.nextAt = null;
    memo.running = true;
    // A round of a page left and opened again must not end this one's: only the latest round clears the flag.
    const token = (memo.token || 0) + 1;
    memo.token = token;
    let failed = null;
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
      failed = err;
    } finally {
      if (memo.token === token) memo.running = false;
      ctx.setBusy(false);
    }
    if (failed) {
      // The DoH client could not be loaded (a deploy, the connection): say so; Check now tries again.
      memo.note = t('chg.check.failed', { reason: describeError(failed).message });
      renderHead();
      return;
    }
    if (memo.stop === 'user') {
      // Stopped while this round ran: its answers are shown, nothing more is asked.
      if (view.isConnected) renderAll();
      return;
    }
    schedule();
  }

  function schedule() {
    clearTimeout(memo.timer);
    // Watching (ui/cutover.js): the same backoff and cache waits, for up to 24 hours.
    const n = (memo.watch ? memo.watch.next : nextCheck)({ latest: memo.latest, check, round: memo.round, startedAt: memo.startedAt, now: Date.now(), errorRounds: memo.errorRounds });
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

  /** Start over: every record on every resolver (a finished change can be checked again, e.g. after a revert). */
  function again() {
    const running = memo.running;
    Object.assign(memo, { startedAt: Date.now(), round: 0, errorRounds: 0, stop: null, cachedUntil: null });
    // A round still running (Stop, then Check again) goes on and schedules the next one.
    if (!running) {
      memo.latest = new Map();
      runRound(null);
    } else renderHead();
  }

  /** Back online: the round that could not run (the first one, or a scheduled one) runs now. */
  const onOnline = () => {
    if (!view.isConnected || !memo.offline || memo.stop || memo.running) return;
    runRound(memo.offline.only, { quiet: true });
  };
  globalThis.addEventListener?.('online', onOnline);

  ticker = setInterval(() => { if (view.isConnected) renderMeta(); }, 1000);
  ctx.onCleanup(() => {
    globalThis.removeEventListener?.('online', onOnline);
    clearInterval(ticker);
    actions.dispose();
    // The memo keeps the answers; its timer only runs while the page is on screen.
    clearTimeout(memo.timer);
    memo.timer = null;
    memo.running = false;
    memo.mounted = false;
  });

  ctx.runStarted(check.zone);
  renderAll();
  loadCutover().then((m) => {
    if (!view.isConnected) return;
    cut = m.mountCutover({
      ctx, check, memo, view, actions: runRow, before: null, strip: watchSlot, planner: planSlot, url: () => checkUrl(query),
      headline: () => head.title.textContent, resume: () => schedule()
    });
    renderAll();
  }, () => ctx.checkOutdated());
  if (memo.stop) return;
  if (!memo.lastAt) runRound(null, { quiet: true });
  else schedule();
}
