/**
 * ui/workspace-ui.js — the shell's workspace controls (app.js builds them): the switcher in the
 * header, next to the current-target chip, and its entry at the top of the phone Tools menu
 * (below 720 px the header has no room for it). Both open the Workspaces dialog
 * (ui/workspace-panel.js, loaded on first use). Also the name a workspace goes by everywhere:
 * Default is named in the page's language.
 *
 * Every string is rendered through h() / text nodes.
 */

import { h } from './dom.js';
import { Button, Icon, toast } from './components.js';
import { t, registerStrings } from '../i18n.js';

registerStrings('en', {
  'ws.default': 'Default',
  'ws.label': 'Workspace',
  'ws.open': 'Workspace: {name}. Switch or manage workspaces',
  'ws.menuSwitch': 'Switch or manage',
  'ws.switched': 'Now working in “{name}”.',
  'ws.switchTitle': 'Switch workspace?',
  'ws.switchJobs': 'Still running here: {jobs}. Switching to “{name}” stops it, and its results are not kept.',
  'ws.switchUnsaved': 'The server list has changes that are not saved: they belong to this workspace, and switching to “{name}” drops them.',
  'ws.switchStop': 'Stop and switch',
  'ws.switchAnyway': 'Switch anyway',
  'ws.loadFailed': 'The workspaces could not be opened: {message}',
  'ws.switchFailed': 'The workspace could not be opened: {message}',
  'ws.cleared': 'Local data deleted: every workspace (its IndexedDB database too), the settings and the remembered options.',
  'ws.clearFailed': 'Not all local data could be deleted ({message}). Close DomainScope in your other tabs and try again.'
});

registerStrings('tr', {
  'ws.default': 'Varsayılan',
  'ws.label': 'Çalışma alanı',
  'ws.open': 'Çalışma alanı: {name}. Çalışma alanlarını değiştirin veya yönetin',
  'ws.menuSwitch': 'Değiştir veya yönet',
  'ws.switched': 'Artık “{name}” çalışma alanındasınız.',
  'ws.switchTitle': 'Çalışma alanı değiştirilsin mi?',
  'ws.switchJobs': 'Burada hâlâ çalışıyor: {jobs}. “{name}” alanına geçmek onu durdurur ve sonuçları tutulmaz.',
  'ws.switchUnsaved': 'Sunucu listesinde kaydedilmemiş değişiklikler var: bunlar bu çalışma alanına ait ve “{name}” alanına geçmek onları atar.',
  'ws.switchStop': 'Durdur ve geç',
  'ws.switchAnyway': 'Yine de geç',
  'ws.loadFailed': 'Çalışma alanları açılamadı: {message}',
  'ws.switchFailed': 'Çalışma alanı açılamadı: {message}',
  'ws.cleared': 'Yerel veriler silindi: tüm çalışma alanları (IndexedDB veritabanıyla birlikte), ayarlar ve hatırlanan seçenekler.',
  'ws.clearFailed': 'Yerel verilerin tümü silinemedi ({message}). DomainScope’u diğer sekmelerinizde kapatıp yeniden deneyin.'
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
 * "Delete all local data" (Settings, About): state.clearAll(), then a toast that says what went —
 * every workspace with its IndexedDB database, the settings and the remembered options — or why
 * not all of it could go.
 * @param {{ clearAll(): Promise<boolean>, workspaceError: Error|null, lastPersistError: Error|null }} state
 * @returns {Promise<boolean>}
 */
export async function deleteAllLocalData(state) {
  const ok = await state.clearAll();
  if (ok) {
    toast(t('ws.cleared'), { type: 'success', timeout: 7000 });
  } else {
    const err = state.workspaceError || state.lastPersistError;
    toast(t('ws.clearFailed', { message: err ? err.message || String(err) : '—' }), { type: 'error', timeout: 0 });
  }
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
