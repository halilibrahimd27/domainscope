/**
 * ui/workspace-ui.js — the shell's workspace controls (app.js builds them): the switcher in the
 * header, next to the current-target chip, and its entry at the top of the phone Tools menu
 * (below 720 px the header has no room for it). Both open the Workspaces dialog
 * (ui/workspace-panel.js, loaded on first use). Also the name a workspace goes by everywhere:
 * Default is named in the page's language (and neither language's name is free for another
 * workspace), and a storage error in words ({@link storageErrorText}).
 *
 * Every string is rendered through h() / text nodes.
 */

import { h } from './dom.js';
import { Button, Icon, toast } from './components.js';
import { t, registerStrings, LANGS } from '../i18n.js';
import { normalizeWorkspaceName } from '../lib/workspace.js';

/** What Default is called in each language (no other workspace may take one of these names). */
const DEFAULT_NAMES = Object.freeze({ en: 'Default', tr: 'Varsayılan' });

/**
 * Why a workspace write or "Delete all local data" failed, as the page words it (`ws.why.<reason>`):
 * see {@link storageErrorText}.
 */
export const STORAGE_REASONS = Object.freeze(['idb-blocked', 'idb-timeout', 'quota', 'denied', 'not-found', 'other', 'unknown']);

registerStrings('en', {
  'ws.default': DEFAULT_NAMES.en,
  'ws.label': 'Workspace',
  'ws.open': 'Workspace: {name}. Switch or manage workspaces',
  'ws.menuSwitch': 'Switch or manage',
  'ws.switched': 'Now working in “{name}”.',
  'ws.switchTitle': 'Switch workspace?',
  'ws.switchJobs': 'Still running here: {jobs}. Switching to “{name}” stops the work in progress, and its results are not kept.',
  'ws.switchUnsaved': 'The server list has changes that are not saved: they belong to this workspace, and switching to “{name}” drops them.',
  'ws.switchStop': 'Stop and switch',
  'ws.switchAnyway': 'Switch anyway',
  'ws.loadFailed': 'The workspaces could not be opened: {message}',
  'ws.switchFailed': 'The workspace could not be opened: {reason}.',
  'ws.cleared': 'Local data deleted: every workspace (its IndexedDB database too), the settings and the remembered options.',
  'ws.clearedNoDb': 'Local data deleted: every workspace, the settings and the remembered options. This browser gave the page no IndexedDB, so the workspaces were kept only in this tab.',
  'ws.clearedMemory': 'Local data reset: this browser blocks storage for this page, so nothing was saved. The workspaces, the settings and the remembered options of this tab are back to their defaults.',
  'ws.clearFailed': 'Not all local data could be deleted: {reason}.',
  'ws.why.idb-blocked': 'another DomainScope tab kept the database open. Close DomainScope in your other tabs and try again',
  'ws.why.idb-timeout': 'the browser did not open its storage in time',
  'ws.why.quota': 'the browser’s storage for this site is full',
  'ws.why.denied': 'the browser does not allow storage on this page',
  'ws.why.not-found': 'the workspace was deleted in another tab',
  'ws.why.other': 'the browser reported “{detail}”',
  'ws.why.unknown': 'the browser gave no reason'
});

registerStrings('tr', {
  'ws.default': DEFAULT_NAMES.tr,
  'ws.label': 'Çalışma alanı',
  'ws.open': 'Çalışma alanı: {name}. Çalışma alanlarını değiştirin veya yönetin',
  'ws.menuSwitch': 'Değiştir veya yönet',
  'ws.switched': 'Artık “{name}” çalışma alanındasınız.',
  'ws.switchTitle': 'Çalışma alanı değiştirilsin mi?',
  'ws.switchJobs': 'Burada hâlâ çalışıyor: {jobs}. “{name}” alanına geçmek süren işi durdurur ve sonuçları tutulmaz.',
  'ws.switchUnsaved': 'Sunucu listesinde kaydedilmemiş değişiklikler var: bunlar bu çalışma alanına ait ve “{name}” alanına geçmek onları atar.',
  'ws.switchStop': 'Durdur ve geç',
  'ws.switchAnyway': 'Yine de geç',
  'ws.loadFailed': 'Çalışma alanları açılamadı: {message}',
  'ws.switchFailed': 'Çalışma alanı açılamadı: {reason}.',
  'ws.cleared': 'Yerel veriler silindi: tüm çalışma alanları (IndexedDB veritabanıyla birlikte), ayarlar ve hatırlanan seçenekler.',
  'ws.clearedNoDb': 'Yerel veriler silindi: tüm çalışma alanları, ayarlar ve hatırlanan seçenekler. Bu tarayıcı sayfaya IndexedDB vermediği için çalışma alanları yalnızca bu sekmede tutuluyordu.',
  'ws.clearedMemory': 'Yerel veriler sıfırlandı: bu tarayıcı bu sayfa için depolamayı engelliyor, bu yüzden hiçbir şey kaydedilmemişti. Bu sekmedeki çalışma alanları, ayarlar ve hatırlanan seçenekler varsayılanlarına döndü.',
  'ws.clearFailed': 'Yerel verilerin tümü silinemedi: {reason}.',
  'ws.why.idb-blocked': 'başka bir DomainScope sekmesi veritabanını açık tuttu. DomainScope’u diğer sekmelerinizde kapatıp yeniden deneyin',
  'ws.why.idb-timeout': 'tarayıcı depolamasını zamanında açmadı',
  'ws.why.quota': 'tarayıcının bu site için ayırdığı depolama dolu',
  'ws.why.denied': 'tarayıcı bu sayfada depolamaya izin vermiyor',
  'ws.why.not-found': 'çalışma alanı başka bir sekmede silindi',
  'ws.why.other': 'tarayıcı “{detail}” bildirdi',
  'ws.why.unknown': 'tarayıcı bir neden bildirmedi'
});

/**
 * The name a workspace shows: its own, or "Default" in the page's language.
 * @param {{ id?: string, name?: string|null, isDefault?: boolean }|null} ws
 * @returns {string}
 */
export function workspaceLabel(ws) {
  if (!ws || ws.isDefault || ws.id === 'default' || !ws.name) return t('ws.default');
  return ws.name;
}

/**
 * Every name Default goes by, one per language: no other workspace may be called one of them
 * (after a language switch the list would show two rows of the same name).
 * @returns {string[]}
 */
export function defaultWorkspaceNames() {
  return LANGS.map((lang) => DEFAULT_NAMES[lang]);
}

/**
 * Is `name` one of Default's names (any language; case and surrounding space ignored)?
 * @param {string} name
 * @returns {boolean}
 */
export function isDefaultWorkspaceName(name) {
  const clean = normalizeWorkspaceName(name);
  // Both casings: "VARSAYILAN" lower-cases to "varsayılan" only the Turkish way.
  const keys = new Set([clean.toLowerCase(), clean.toLocaleLowerCase('tr')]);
  return !!clean && defaultWorkspaceNames().some((n) => keys.has(n.toLowerCase()));
}

/**
 * Why a workspace write or deletion failed, as one of {@link STORAGE_REASONS}: the browser's full
 * storage, its refusal, workspace-db.js's timeout and blocked deletion, a workspace deleted in
 * another tab; 'other' for any other error, 'unknown' without one.
 * @param {unknown} err
 * @returns {string}
 */
export function storageReason(err) {
  if (!err) return 'unknown';
  const code = typeof err === 'object' ? err.code : null;
  const name = typeof err === 'object' ? err.name : null;
  if (code === 'idb-blocked' || code === 'idb-timeout' || code === 'not-found') return code;
  // 22: the legacy DOMException code of a full storage.
  if (name === 'QuotaExceededError' || code === 22) return 'quota';
  if (name === 'SecurityError' || name === 'NotAllowedError') return 'denied';
  return 'other';
}

/**
 * {@link storageReason} in words, in the page's language (an unknown error keeps its own text,
 * quoted).
 * @param {unknown} err
 * @returns {string}
 */
export function storageErrorText(err) {
  const reason = storageReason(err);
  if (reason !== 'other') return t(`ws.why.${reason}`);
  const detail = (err && typeof err === 'object' ? err.message || err.name : String(err)) || '';
  return detail ? t('ws.why.other', { detail }) : t('ws.why.unknown');
}

/**
 * The header's switcher: the active workspace's name (cut with an ellipsis when long) on a button
 * that opens the Workspaces dialog.
 * @param {{ workspace: { id: string, name: string|null, isDefault: boolean }, onOpen: () => void }} opts
 * @returns {HTMLButtonElement}
 */
export function WorkspaceSwitch({ workspace, onOpen }) {
  const name = workspaceLabel(workspace);
  return h('button', {
    type: 'button',
    class: ['ws-switch', { 'is-default': !!workspace.isDefault }],
    title: t('ws.open', { name }),
    dataset: { control: 'workspace', workspace: workspace.id },
    attrs: { 'aria-haspopup': 'dialog', 'aria-label': t('ws.open', { name }) },
    on: { click: () => onOpen() }
  },
  Icon('briefcase', { size: 15, className: 'ws-switch-icon' }),
  h('span', { class: 'ws-switch-name' }, name),
  Icon('chevron-down', { size: 14, className: 'ws-switch-chevron' }));
}

/**
 * What "Delete all local data" says once state.clearAll() settled: what went — every workspace
 * with its IndexedDB database (also one the page could not open and worked around in memory), the
 * settings and the remembered options; without an IndexedDB the workspaces of this tab only; with
 * storage blocked altogether, that nothing had been saved — or why not all of it could go (the
 * error of the step that failed: clearAll() leaves no other).
 * @param {{ persistence: boolean, workspaceDatabase: boolean, workspaceError: Error|null, lastPersistError: Error|null }} state
 * @param {boolean} ok what clearAll() resolved to
 * @returns {{ type: 'success'|'error', text: string }}
 */
export function clearedMessage(state, ok) {
  if (!ok) return { type: 'error', text: t('ws.clearFailed', { reason: storageErrorText(state.workspaceError || state.lastPersistError) }) };
  if (state.workspaceDatabase) return { type: 'success', text: t('ws.cleared') };
  return { type: 'success', text: t(state.persistence ? 'ws.clearedNoDb' : 'ws.clearedMemory') };
}

/**
 * "Delete all local data" (Settings, About): state.clearAll(), then a toast with
 * {@link clearedMessage}.
 * @param {{ clearAll(): Promise<boolean>, persistence: boolean, workspaceDatabase: boolean,
 *   workspaceError: Error|null, lastPersistError: Error|null }} state
 * @returns {Promise<boolean>}
 */
export async function deleteAllLocalData(state) {
  const ok = await state.clearAll();
  const { type, text } = clearedMessage(state, ok);
  toast(text, { type, timeout: ok ? 7000 : 0 });
  return ok;
}

/**
 * The Tools menu's workspace row (phones): the active workspace and a button to the dialog.
 * @param {{ workspace: { id: string, name: string|null, isDefault: boolean }, onOpen: () => void }} opts
 * @returns {HTMLElement}
 */
export function WorkspaceMenuEntry({ workspace, onOpen }) {
  const name = workspaceLabel(workspace);
  return h('div', { class: 'navmenu-workspace', dataset: { workspace: workspace.id } },
    h('div', { class: 'navmenu-workspace-text' },
      h('span', { class: 'navmenu-workspace-label' }, t('ws.label')),
      h('span', { class: 'navmenu-workspace-name' }, Icon('briefcase', { size: 15 }), h('span', null, name))),
    Button({
      label: t('ws.menuSwitch'),
      size: 'sm',
      dataset: { control: 'workspace-menu' },
      attrs: { 'aria-haspopup': 'dialog' },
      onClick: () => onOpen()
    }));
}
