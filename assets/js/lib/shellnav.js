/**
 * shellnav.js — the app shell's navigation, first-visit task picker and keyboard shortcuts as
 * data: the tool groups (the desktop sidebar and the phone Tools menu read the same table), the
 * start-page jobs, what counts as "the visitor has run something", which command a key press
 * means and which marked control answers it.
 *
 * Pure: no DOM, storage, network, clock or i18n. app.js feeds it the view registry, storage keys,
 * state changes, key events and element lists (duck-typed), and does the rendering and clicking.
 */

/**
 * Tool groups in navigation order (spec §6). A view's `group` in app.js's VIEWS names one of them;
 * `labelKey` is the i18n key of the group heading.
 */
export const NAV_GROUPS = Object.freeze([
  { id: 'discover', labelKey: 'nav.groupDiscover' },
  { id: 'ssl', labelKey: 'nav.groupSsl' },
  { id: 'dns', labelKey: 'nav.groupDns' },
  { id: 'ip', labelKey: 'nav.groupIp' },
  { id: 'mail', labelKey: 'nav.groupMail' },
  { id: 'data', labelKey: 'nav.groupData' }
].map((g) => Object.freeze(g)));

/** Where a view whose group is missing or unknown is listed (last), so no tool ever drops out of the menu. */
export const OTHER_GROUP = Object.freeze({ id: 'other', labelKey: 'nav.groupOther' });

/**
 * The views of a registry grouped for navigation: the known groups in `groups` order, each with
 * its views in registry order; a view with a missing or unknown group goes to a trailing
 * {@link OTHER_GROUP}. Groups without a view are left out.
 * @template {{ id: string, group?: string }} V
 * @param {ReadonlyArray<V>} views the view registry (app.js VIEWS)
 * @param {ReadonlyArray<{ id: string, labelKey: string }>} [groups]
 * @returns {Array<{ id: string, labelKey: string, views: V[] }>}
 */
export function groupViews(views, groups = NAV_GROUPS) {
  const out = groups.map((g) => ({ id: g.id, labelKey: g.labelKey, views: [] }));
  const byId = new Map(out.map((g) => [g.id, g]));
  const other = { id: OTHER_GROUP.id, labelKey: OTHER_GROUP.labelKey, views: [] };
  for (const v of views || []) {
    if (!v || typeof v.id !== 'string') continue;
    (byId.get(v.group) || other).views.push(v);
  }
  return [...out, other].filter((g) => g.views.length);
}

/* ------------------------------------------------------------------------ */
/* First-visit task picker                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The jobs the start page offers a first-time visitor, in display order. `id` names the i18n key
 * `start.task.<id>`; `view` is the tool that does the job.
 */
export const START_TASKS = Object.freeze([
  { id: 'subdomains', view: 'subdomains' },
  { id: 'certificate', view: 'scan' },
  { id: 'health', view: 'health' },
  { id: 'propagation', view: 'global' },
  { id: 'zone', view: 'zone' }
].map((task) => Object.freeze(task)));

/**
 * The start-page jobs whose tool exists in the registry, each with that tool's icon (a card and
 * the tool's navigation entry look alike).
 * @param {ReadonlyArray<{ id: string, icon?: string }>} views the view registry
 * @param {ReadonlyArray<{ id: string, view: string }>} [tasks]
 * @returns {Array<{ id: string, view: string, icon: string|null }>}
 */
export function startTasks(views, tasks = START_TASKS) {
  const byId = new Map((views || []).filter((v) => v && typeof v.id === 'string').map((v) => [v.id, v]));
  return tasks.filter((task) => byId.has(task.view))
    .map((task) => ({ id: task.id, view: task.view, icon: byId.get(task.view).icon || null }));
}

/**
 * Session values (state.setSession names) whose arrival means the visitor ran something: an
 * imported zone file ('zone', views/zone.js) and a loaded certificate ('currentCert', views/cert.js).
 */
export const RUN_SESSION_KEYS = Object.freeze(['zone', 'currentCert']);

/**
 * Does a state change (state.js StateChange) show that the visitor has run something? A saved
 * inventory with servers, or one of {@link RUN_SESSION_KEYS} set. A view going busy (a scan, a
 * lookup) is the other signal; the shell reports that one itself.
 * @param {{ key?: string, value?: any }} change
 * @returns {boolean}
 */
export function isRunSignal(change) {
  const { key, value } = change || {};
  if (key === 'inventory') return !!(value && Array.isArray(value.servers) && value.servers.length);
  if (key === 'session') {
    return !!(value && RUN_SESSION_KEYS.includes(value.name) && value.value !== undefined && value.value !== null);
  }
  return false;
}

/**
 * Stored keys that only a run or a save leaves behind: saved servers (state.js) and the names a
 * finished scan learned (lib/learned.js). Remembered view options are not among them: a switch
 * flipped or a language pack opened on the start page writes those without running anything.
 */
export const RUN_STORAGE_KEYS = Object.freeze(['ssds.inventory', 'ssds.learned.labels']);

/**
 * Has this browser run something here before the picker existed? One of {@link RUN_STORAGE_KEYS}
 * is stored. (Runs that left nothing stored cannot be told apart from a first visit.)
 * @param {Iterable<string>} keys localStorage keys
 * @param {ReadonlyArray<string>} [runKeys]
 * @returns {boolean}
 */
export function hasUsedBefore(keys, runKeys = RUN_STORAGE_KEYS) {
  for (const key of keys || []) {
    if (typeof key === 'string' && runKeys.includes(key)) return true;
  }
  return false;
}

/* ------------------------------------------------------------------------ */
/* Keyboard shortcuts                                                       */
/* ------------------------------------------------------------------------ */

/**
 * The shortcuts, in the order the help dialog lists them. `keys` are key caps; 'Mod' is Ctrl, or
 * ⌘ on Apple platforms ({@link keyCaps}). The i18n key of the description is `keys.<id>`.
 */
export const SHORTCUTS = Object.freeze([
  { id: 'submit', keys: Object.freeze(['Mod', 'Enter']) },
  { id: 'cancel', keys: Object.freeze(['Esc']) },
  { id: 'focus', keys: Object.freeze(['/']) },
  { id: 'help', keys: Object.freeze(['?']) }
].map((s) => Object.freeze(s)));

/** Commands a key press can mean ({@link shortcutFor}). */
export const SHORTCUT_COMMANDS = Object.freeze(SHORTCUTS.map((s) => s.id));

/**
 * Is this an Apple platform (⌘ instead of Ctrl in the help dialog)?
 * @param {string} platform navigator.userAgentData.platform or navigator.platform
 * @returns {boolean}
 */
export function isApplePlatform(platform) {
  return /mac|iphone|ipad|ipod|ios/i.test(String(platform || ''));
}

/**
 * Key caps as shown: 'Mod' becomes '⌘' on Apple platforms and 'Ctrl' elsewhere.
 * @param {ReadonlyArray<string>} keys
 * @param {{ apple?: boolean }} [opts]
 * @returns {string[]}
 */
export function keyCaps(keys, { apple = false } = {}) {
  return (keys || []).map((k) => (k === 'Mod' ? (apple ? '⌘' : 'Ctrl') : k));
}

/** Input types that take no typed text (keys pressed on them are not "typing"). */
const NON_TEXT_INPUTS = new Set(['button', 'checkbox', 'color', 'file', 'hidden', 'image', 'radio', 'range', 'reset', 'submit']);

const tagOf = (target) => String((target && target.tagName) || '').toLowerCase();

/**
 * Is the element one where keys type text (or pick an option by typing)? A text-like input, a
 * textarea, a select or an editable element. Only Ctrl/Cmd+Enter and Esc act there.
 * @param {{ tagName?: string, type?: string, isContentEditable?: boolean }|null} target
 * @returns {boolean}
 */
export function isTypingTarget(target) {
  if (!target) return false;
  if (target.isContentEditable) return true;
  const tag = tagOf(target);
  if (tag === 'textarea' || tag === 'select') return true;
  return tag === 'input' && !NON_TEXT_INPUTS.has(String(target.type || 'text').toLowerCase());
}

/**
 * Is the element a form field (any input, a textarea or a select)? Ctrl/Cmd+Enter submits from one.
 * @param {{ tagName?: string }|null} target
 * @returns {boolean}
 */
export function isFormField(target) {
  const tag = tagOf(target);
  return tag === 'input' || tag === 'textarea' || tag === 'select';
}

/**
 * Does Esc already mean something in this field? A search field with text in it: the browser
 * clears the text with Esc (a table's filter, for one), so there it is not the "cancel the job"
 * shortcut. In the emptied field the next Esc is.
 * @param {{ tagName?: string, type?: string, value?: string }|null} target
 * @returns {boolean}
 */
export function escClearsField(target) {
  return tagOf(target) === 'input' && String(target.type || '').toLowerCase() === 'search' && String(target.value || '') !== '';
}

/**
 * The shortcut a key press means, or null:
 * - `submit`: Ctrl+Enter or ⌘+Enter (no Alt, no Shift) in a form field;
 * - `cancel`: Esc, anywhere (a field included), except in a search field with text
 *   ({@link escClearsField});
 * - `focus`: '/' and `help`: '?', only while not typing (Shift is allowed, as layouts need it for
 *   '/' or '?'; AltGr — Ctrl+Alt together — too; Ctrl, Alt or ⌘ alone is another shortcut).
 * A held key (auto-repeat) and a key pressed while an input method composes text mean nothing.
 * @param {{ key?: string, ctrlKey?: boolean, metaKey?: boolean, altKey?: boolean, shiftKey?: boolean,
 *   repeat?: boolean, isComposing?: boolean, keyCode?: number, target?: object|null }} event
 * @returns {'submit'|'cancel'|'focus'|'help'|null}
 */
export function shortcutFor(event) {
  if (!event || event.repeat || event.isComposing || event.keyCode === 229) return null;
  const { key, target = null } = event;
  const ctrl = !!event.ctrlKey;
  const meta = !!event.metaKey;
  const alt = !!event.altKey;
  if (key === 'Enter') {
    return (ctrl || meta) && !alt && !event.shiftKey && isFormField(target) ? 'submit' : null;
  }
  if (key === 'Escape' || key === 'Esc') return ctrl || meta || alt || event.shiftKey || escClearsField(target) ? null : 'cancel';
  if (key !== '/' && key !== '?') return null;
  if (meta || ctrl !== alt || isTypingTarget(target)) return null;
  return key === '/' ? 'focus' : 'help';
}

/**
 * The control that answers a shortcut: the view marks its buttons `data-shortcut="submit"` /
 * `"cancel"` and its main input `"focus"`; the shell collects them and the focused element's
 * ancestors, and this picks one.
 *
 * Sub-forms: a small form of its own inside a view (a certificate paste box with its Read button,
 * a zone importer, a host name lookup) sits in a container marked `data-shortcut-scope`, and
 * `localOf(node)` returns the sub-form a node is in (null: the view's own form). With `localOf`,
 * only the candidates of the focused element's own form take part: the paste box's Read answers
 * the paste box, the view's Run every field outside a sub-form, and neither stands in for the
 * other (a sub-form further up the page never outranks the view's Run by document order).
 * A sub-form without a submit — a view's results area, a table — answers nothing: a results
 * filter, a table's search box or a panel's option never starts the view's run again.
 *
 * Scopes are then tried nearest first; the first scope holding a candidate decides:
 * - `strict` (submit): its first usable candidate, or null when all of its candidates are hidden or
 *   disabled — the field's own action is not available (a run in progress), and an action of
 *   another form must not stand in for it;
 * - otherwise (cancel, focus): its first usable candidate, else the next scope's.
 * @template T
 * @param {{ candidates: ReadonlyArray<T>, scopes: ReadonlyArray<any>, contains: (scope: any, el: T) => boolean,
 *   usable?: (el: T) => boolean, strict?: boolean, from?: any, localOf?: ((node: any) => any)|null }} opts
 *   candidates in document order; scopes from the focused element (`from`) out to the view's root
 * @returns {T|null}
 */
export function pickShortcutTarget({ candidates, scopes, contains, usable = () => true, strict = false, from = null, localOf = null }) {
  let list = [...(candidates || [])];
  if (localOf) {
    const own = (from && localOf(from)) || null;
    list = list.filter((el) => (localOf(el) || null) === own);
  }
  if (!list.length) return null;
  for (const scope of scopes || []) {
    const inScope = list.filter((el) => contains(scope, el));
    if (!inScope.length) continue;
    const hit = inScope.find((el) => usable(el));
    if (hit !== undefined) return hit;
    if (strict) return null;
  }
  return null;
}
