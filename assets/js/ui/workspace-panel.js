/**
 * ui/workspace-panel.js — the Workspaces dialog, opened from the header's switcher (or the phone
 * Tools menu) and loaded on first use together with assets/css/workspace.css. Three parts:
 *
 *   - the workspaces: Default and the named ones, switch / rename / delete (with a confirmation;
 *     Default can do neither), and a new one (created and switched to);
 *   - the current workspace: its recent domains (a click makes one the current target, which
 *     every tool fills in), its expected CAs (lib/expectedca.js: the issuer badges of the
 *     Certificate view, SSL Targets and the CAA checks) and free-text notes, both saved as you
 *     type — always into the workspace they were typed in;
 *   - the hand-over file (lib/handover.js): export the current workspace as one JSON file, sealed
 *     with a password if one is given (PBKDF2 + AES-GCM, lib/cryptobox.js; the password is never
 *     kept), and import one as a new workspace or over the one of the same name (after a
 *     confirmation), with a clear message for a wrong password or a changed file.
 *
 * Switching goes through the shell's `switchTo` (it asks first when a long job would stop). What
 * a click did is said in the dialog, under the list or the hand-over file ({@link Outcome}): a
 * toast would sit under the modal dialog, neither seen nor read while it is open. Every string is
 * rendered through h() / text nodes; nothing here reaches the network.
 */

import { h, clear, uid } from './dom.js';
import {
  Alert, Badge, Button, FileDrop, Icon, IconButton, Modal, announce, confirmDialog, setButtonBusy, textInput, textarea
} from './components.js';
import { downloadText, timestampedName } from './download.js';
import { t, registerStrings, formatRelative, formatDateTime } from '../i18n.js';
import { parseInventory } from '../lib/inventory.js';
import { DEFAULT_WORKSPACE_ID, WORKSPACE_LIMITS, WorkspaceError, uniqueWorkspaceName, sanitizeExpectedCas } from '../lib/workspace.js';
import { exportWorkspaceFile, readWorkspaceFile, openWorkspaceFile, HANDOVER_MAX_BYTES } from '../lib/handover.js';
import { MIN_PASSWORD_LENGTH } from '../lib/cryptobox.js';
import { resolveExpectedCa } from '../lib/expectedca.js';
import { workspaceLabel, defaultWorkspaceNames, isDefaultWorkspaceName, storageErrorText } from './workspace-ui.js';

/** The hand-over file errors the dialog words itself (lib/handover.js HandoverError codes). */
export const IMPORT_ERRORS = Object.freeze([
  'too-large', 'not-json', 'not-workspace', 'newer', 'damaged', 'password-required', 'wrong-password', 'unsupported', 'crypto-unavailable'
]);
/** Why a name is refused (lib/workspace.js WorkspaceError codes). */
export const NAME_ERRORS = Object.freeze(['name-empty', 'name-taken', 'limit']);
/** What can be wrong with the export's password fields ({@link passwordProblem}). */
export const PASSWORD_PROBLEMS = Object.freeze(['password-short', 'password-blank', 'mismatch']);
/** How long typing in the notes or the expected CAs waits before it is saved (ms). */
const SAVE_DELAY_MS = 400;

registerStrings('en', {
  'ws.title': 'Workspaces',
  'ws.intro': 'Each workspace keeps its own servers, learned names, custom wordlist, expected CAs, notes and recent domains, so one customer’s data never mixes with another’s. Theme, language, resolvers and parallelism are the same in every workspace. Everything stays in this browser (IndexedDB).',
  'ws.memoryOnly': 'Browser storage is unavailable: the workspaces last until you close this tab.',
  'ws.listTitle': 'Your workspaces',
  'ws.active': 'Active',
  'ws.updated': 'changed {when}',
  'ws.switch': 'Switch',
  'ws.switchTo': 'Switch to “{name}”',
  'ws.rename': 'Rename “{name}”',
  'ws.renameLabel': 'New name for “{name}”',
  'ws.save': 'Save',
  'ws.cancel': 'Cancel',
  'ws.delete': 'Delete “{name}”',
  'ws.deleteConfirm': 'Delete the workspace “{name}” and everything in it: its servers, learned names, custom wordlist, expected CAs, notes and recent domains? This cannot be undone. Export it first to keep a copy.',
  'ws.deleted': 'Workspace “{name}” deleted.',
  'ws.deleteNotSaved': '“{name}” is deleted here, but not in this browser’s storage: {reason}. It comes back when the page is loaded again.',
  'ws.gone': '“{name}” was deleted in another tab.',
  'ws.renamed': 'Renamed to “{name}”.',
  'ws.newLabel': 'New workspace',
  'ws.newPlaceholder': 'Customer or project name',
  'ws.create': 'Create',
  'ws.createHint': 'An empty workspace; you work in it right away.',
  'ws.err.name-empty': 'Give the workspace a name.',
  'ws.err.name-taken': 'A workspace with this name exists already.',
  'ws.err.limit': 'That is the most workspaces this browser keeps ({count}). Delete one first.',
  'ws.notSaved': 'Not saved: {reason}. It lasts until you close this tab.',
  'ws.currentTitle': 'In “{name}”',
  'ws.recentTitle': 'Recent domains',
  'ws.recentHint': 'The domains and host names you worked on here. Pick one to make it the current target: every tool fills it in and runs nothing until you press its button.',
  'ws.recentEmpty': 'None yet: the domains you check in this workspace appear here.',
  'ws.recentUse': 'Make {value} the current target',
  'ws.recentClear': 'Clear the list',
  'ws.recentSet': 'Current target: {value}',
  'ws.expectedLabel': 'Expected CAs',
  'ws.expectedHint': 'One per line: a CA’s name (Let’s Encrypt, DigiCert), its CAA identifier (letsencrypt.org) or part of your own CA’s name. The Certificate view, SSL Targets and the CAA checks then mark each issuer “expected CA” or “unexpected CA”.',
  'ws.expectedKnown': 'Known CA: {ca} (CAA {domains})',
  'ws.expectedText': 'Not a CA this app knows: matched as text in the issuer’s name, or as a CAA identifier written out',
  'ws.notesLabel': 'Notes',
  'ws.notesHint': 'Free text for this workspace: contacts, renewal dates, where the certificates go. Kept in this browser and in the hand-over file.',
  'ws.savedNow': 'Saved',
  'ws.saving': 'Saving…',
  'ws.fileTitle': 'Hand-over file',
  'ws.fileIntro': 'One JSON file with everything in a workspace, to move it to another browser or hand it to a colleague. With a password it is encrypted (AES-GCM, the key derived from the password with PBKDF2-SHA-256) and its file name leaves the workspace’s name out; the password is never stored, and without it the file cannot be opened. Without a password anyone who gets the file can read it, and its file name carries the workspace’s name.',
  'ws.exportTitle': 'Export “{name}”',
  'ws.password': 'Password',
  'ws.passwordOptional': 'optional, at least {count} characters',
  'ws.passwordRepeat': 'Password again',
  'ws.export': 'Export',
  'ws.exporting': 'Encrypting…',
  'ws.err.password-short': 'Use at least {count} characters.',
  'ws.err.password-blank': 'A password of spaces only protects nothing: use letters, digits or symbols.',
  'ws.err.mismatch': 'The two passwords differ.',
  'ws.exportedSealed': '{file} saved, encrypted with your password.',
  'ws.exportedPlain': '{file} saved without a password: anyone who gets the file can read it.',
  'ws.importTitle': 'Import a workspace file',
  'ws.importHint': 'A file exported here or by a colleague. It becomes a new workspace, or replaces the workspace of the same name after you confirm. Nothing is sent anywhere.',
  'ws.importDrop': 'Choose a workspace file',
  'ws.importDropHint': 'drop the .json here or click to choose',
  'ws.importPassword': 'Password of this file',
  'ws.importOpen': 'Open',
  'ws.importOpening': 'Decrypting…',
  'ws.importSealed': 'This file is encrypted. Enter its password.',
  'ws.importSummary': '“{name}” · exported {when}',
  'ws.importSummaryUndated': '“{name}”',
  'ws.importUnnamed': 'Imported workspace',
  'ws.sum.servers': { zero: 'no servers', one: '{count} server', other: '{count} servers' },
  'ws.sum.learned': { zero: 'no learned names', one: '{count} learned name', other: '{count} learned names' },
  'ws.sum.expected': { zero: 'no expected CAs', one: '{count} expected CA', other: '{count} expected CAs' },
  'ws.sum.recent': { zero: 'no recent domains', one: '{count} recent domain', other: '{count} recent domains' },
  'ws.sum.wordlist': 'a custom wordlist',
  'ws.sum.notes': 'notes',
  'ws.sum.encrypted': 'was encrypted',
  'ws.importNew': 'Import as a new workspace',
  'ws.importReplace': 'Replace “{name}”',
  'ws.replaceConfirm': 'Replace everything in “{name}” — its servers, learned names, custom wordlist, expected CAs, notes and recent domains — with the file’s? This cannot be undone.',
  'ws.imported': 'Imported as the new workspace “{name}”.',
  'ws.replaced': '“{name}” replaced with the file’s contents.',
  'ws.err.too-large': 'The file is too large (at most {size}).',
  'ws.err.not-json': 'This file is not JSON. Choose a DomainScope workspace file (.json).',
  'ws.err.not-workspace': 'This JSON file is not a DomainScope workspace file.',
  'ws.err.newer': 'This file was made by a newer version of DomainScope. Reload the page to update it, then import the file again.',
  'ws.err.damaged': 'The file is damaged: it is a workspace file, but parts of it are missing or unreadable. Nothing was imported.',
  'ws.err.password-required': 'This file is encrypted. Enter its password.',
  'ws.err.wrong-password': 'Wrong password, or the file was changed after it was exported. Nothing was imported.',
  'ws.err.unsupported': 'The file is encrypted with a method this version does not know.',
  'ws.err.crypto-unavailable': 'This browser offers no encryption on this page (WebCrypto needs an HTTPS page).'
});

registerStrings('tr', {
  'ws.title': 'Çalışma alanları',
  'ws.intro': 'Her çalışma alanı kendi sunucularını, öğrenilen adlarını, özel kelime listesini, beklenen CA’larını, notlarını ve son alan adlarını tutar; böylece bir müşterinin verisi diğerininkine karışmaz. Tema, dil, çözümleyiciler ve paralellik her çalışma alanında aynıdır. Hepsi bu tarayıcıda kalır (IndexedDB).',
  'ws.memoryOnly': 'Tarayıcı depolaması kullanılamıyor: çalışma alanları bu sekmeyi kapatana kadar tutulur.',
  'ws.listTitle': 'Çalışma alanlarınız',
  'ws.active': 'Etkin',
  'ws.updated': '{when} değişti',
  'ws.switch': 'Geç',
  'ws.switchTo': '“{name}” alanına geç',
  'ws.rename': '“{name}” adını değiştir',
  'ws.renameLabel': '“{name}” için yeni ad',
  'ws.save': 'Kaydet',
  'ws.cancel': 'Vazgeç',
  'ws.delete': '“{name}” alanını sil',
  'ws.deleteConfirm': '“{name}” çalışma alanı ve içindeki her şey silinsin mi: sunucuları, öğrenilen adları, özel kelime listesi, beklenen CA’ları, notları ve son alan adları? Bu işlem geri alınamaz. Bir kopyasını saklamak için önce dışa aktarın.',
  'ws.deleted': '“{name}” çalışma alanı silindi.',
  'ws.deleteNotSaved': '“{name}” burada silindi ama bu tarayıcının depolamasından silinemedi: {reason}. Sayfa yeniden yüklendiğinde geri gelir.',
  'ws.gone': '“{name}” başka bir sekmede silindi.',
  'ws.renamed': 'Yeni adı “{name}”.',
  'ws.newLabel': 'Yeni çalışma alanı',
  'ws.newPlaceholder': 'Müşteri ya da proje adı',
  'ws.create': 'Oluştur',
  'ws.createHint': 'Boş bir çalışma alanı; hemen bu alanda çalışmaya başlarsınız.',
  'ws.err.name-empty': 'Çalışma alanına bir ad verin.',
  'ws.err.name-taken': 'Bu adda bir çalışma alanı zaten var.',
  'ws.err.limit': 'Bu tarayıcının tuttuğu en fazla çalışma alanı sayısına ({count}) ulaşıldı. Önce birini silin.',
  'ws.notSaved': 'Kaydedilemedi: {reason}. Bu sekmeyi kapatana kadar tutulur.',
  'ws.currentTitle': '“{name}” içinde',
  'ws.recentTitle': 'Son alan adları',
  'ws.recentHint': 'Burada üzerinde çalıştığınız alan adları ve host adları. Birini seçerek geçerli hedef yapın: her araç onu doldurur ve düğmesine basana kadar hiçbir şey çalıştırmaz.',
  'ws.recentEmpty': 'Henüz yok: bu çalışma alanında kontrol ettiğiniz alan adları burada görünür.',
  'ws.recentUse': '{value} geçerli hedef olsun',
  'ws.recentClear': 'Listeyi temizle',
  'ws.recentSet': 'Geçerli hedef: {value}',
  'ws.expectedLabel': 'Beklenen CA’lar',
  'ws.expectedHint': 'Her satıra bir tane: bir CA’nın adı (Let’s Encrypt, DigiCert), CAA tanımlayıcısı (letsencrypt.org) ya da kendi CA’nızın adının bir parçası. Sertifika görünümü, SSL Hedefleri ve CAA kontrolleri her sertifikayı vereni “beklenen CA” ya da “beklenmeyen CA” olarak işaretler.',
  'ws.expectedKnown': 'Bilinen CA: {ca} (CAA {domains})',
  'ws.expectedText': 'Bu uygulamanın tanıdığı bir CA değil: verenin adında metin olarak ya da açıkça yazılmış bir CAA tanımlayıcısı olarak eşleştirilir',
  'ws.notesLabel': 'Notlar',
  'ws.notesHint': 'Bu çalışma alanı için serbest metin: ilgili kişiler, yenileme tarihleri, sertifikaların nereye gittiği. Bu tarayıcıda ve devir dosyasında tutulur.',
  'ws.savedNow': 'Kaydedildi',
  'ws.saving': 'Kaydediliyor…',
  'ws.fileTitle': 'Devir dosyası',
  'ws.fileIntro': 'Bir çalışma alanındaki her şey tek bir JSON dosyasında: başka bir tarayıcıya taşımak ya da bir iş arkadaşınıza devretmek için. Parola verirseniz dosya şifrelenir (AES-GCM; anahtar paroladan PBKDF2-SHA-256 ile türetilir) ve dosya adında çalışma alanının adı yer almaz; parola asla saklanmaz ve o olmadan dosya açılamaz. Parolasız dosyayı eline geçiren herkes okuyabilir; dosya adında da çalışma alanının adı bulunur.',
  'ws.exportTitle': '“{name}” alanını dışa aktar',
  'ws.password': 'Parola',
  'ws.passwordOptional': 'isteğe bağlı, en az {count} karakter',
  'ws.passwordRepeat': 'Parola (tekrar)',
  'ws.export': 'Dışa aktar',
  'ws.exporting': 'Şifreleniyor…',
  'ws.err.password-short': 'En az {count} karakter kullanın.',
  'ws.err.password-blank': 'Yalnızca boşluktan oluşan bir parola hiçbir şeyi korumaz: harf, rakam ya da simge kullanın.',
  'ws.err.mismatch': 'İki parola farklı.',
  'ws.exportedSealed': '{file} kaydedildi; parolanızla şifrelendi.',
  'ws.exportedPlain': '{file} parolasız kaydedildi: dosyayı eline geçiren herkes okuyabilir.',
  'ws.importTitle': 'Çalışma alanı dosyası içe aktar',
  'ws.importHint': 'Burada ya da bir iş arkadaşınızın dışa aktardığı bir dosya. Yeni bir çalışma alanı olur ya da onaylarsanız aynı addaki çalışma alanının yerini alır. Hiçbir yere bir şey gönderilmez.',
  'ws.importDrop': 'Bir çalışma alanı dosyası seçin',
  'ws.importDropHint': '.json dosyasını buraya bırakın ya da seçmek için tıklayın',
  'ws.importPassword': 'Bu dosyanın parolası',
  'ws.importOpen': 'Aç',
  'ws.importOpening': 'Şifre çözülüyor…',
  'ws.importSealed': 'Bu dosya şifreli. Parolasını girin.',
  'ws.importSummary': '“{name}” · {when} dışa aktarıldı',
  'ws.importSummaryUndated': '“{name}”',
  'ws.importUnnamed': 'İçe aktarılan çalışma alanı',
  'ws.sum.servers': { zero: 'sunucu yok', other: '{count} sunucu' },
  'ws.sum.learned': { zero: 'öğrenilen ad yok', other: '{count} öğrenilen ad' },
  'ws.sum.expected': { zero: 'beklenen CA yok', other: '{count} beklenen CA' },
  'ws.sum.recent': { zero: 'son alan adı yok', other: '{count} son alan adı' },
  'ws.sum.wordlist': 'bir özel kelime listesi',
  'ws.sum.notes': 'notlar',
  'ws.sum.encrypted': 'şifreliydi',
  'ws.importNew': 'Yeni çalışma alanı olarak içe aktar',
  'ws.importReplace': '“{name}” alanının yerine koy',
  'ws.replaceConfirm': '“{name}” içindeki her şey — sunucuları, öğrenilen adları, özel kelime listesi, beklenen CA’ları, notları ve son alan adları — dosyadakilerle değiştirilsin mi? Bu işlem geri alınamaz.',
  'ws.imported': '“{name}” adlı yeni çalışma alanı olarak içe aktarıldı.',
  'ws.replaced': '“{name}” dosyanın içeriğiyle değiştirildi.',
  'ws.err.too-large': 'Dosya çok büyük (en fazla {size}).',
  'ws.err.not-json': 'Bu dosya JSON değil. Bir DomainScope çalışma alanı dosyası (.json) seçin.',
  'ws.err.not-workspace': 'Bu JSON dosyası bir DomainScope çalışma alanı dosyası değil.',
  'ws.err.newer': 'Bu dosya DomainScope’un daha yeni bir sürümüyle yapılmış. Güncellemek için sayfayı yenileyin, sonra dosyayı yeniden içe aktarın.',
  'ws.err.damaged': 'Dosya bozuk: bir çalışma alanı dosyası ama bazı bölümleri eksik ya da okunamıyor. Hiçbir şey içe aktarılmadı.',
  'ws.err.password-required': 'Bu dosya şifreli. Parolasını girin.',
  'ws.err.wrong-password': 'Parola yanlış ya da dosya dışa aktarıldıktan sonra değiştirilmiş. Hiçbir şey içe aktarılmadı.',
  'ws.err.unsupported': 'Dosya bu sürümün tanımadığı bir yöntemle şifrelenmiş.',
  'ws.err.crypto-unavailable': 'Bu tarayıcı bu sayfada şifreleme sunmuyor (WebCrypto bir HTTPS sayfası gerektirir).'
});

/**
 * Put buttons on the input's own line (a field of ui/components.js keeps its label, hint and
 * error around it, and every aria link).
 * @param {{ input: HTMLElement }} field
 * @param {...HTMLElement} buttons
 */
function inline(field, ...buttons) {
  const row = h('div', { class: 'ws-inline' });
  field.input.replaceWith(row);
  row.append(field.input, ...buttons);
}

/** The text of a refused name (WorkspaceError) or of a failed import (HandoverError). */
function errorMessage(err) {
  const code = err && err.code;
  if (NAME_ERRORS.includes(code)) return t(`ws.err.${code}`, { count: WORKSPACE_LIMITS.count });
  if (IMPORT_ERRORS.includes(code)) return t(`ws.err.${code}`, { size: `${Math.round(HANDOVER_MAX_BYTES / (1024 * 1024))} MB` });
  if (code === 'password-short') return t('ws.err.password-short', { count: MIN_PASSWORD_LENGTH });
  return storageErrorText(err);
}

/**
 * What is wrong with the export's password fields, as an error code (null: fine; an empty password
 * is fine too: the file is then not encrypted): 'password-short' (fewer than MIN_PASSWORD_LENGTH
 * characters), 'password-blank' (spaces only), 'mismatch' (the repetition differs).
 * @param {string} password
 * @param {string} repeat
 * @returns {null|string} one of {@link PASSWORD_PROBLEMS}
 */
export function passwordProblem(password, repeat) {
  const pw = String(password ?? '');
  if (pw && [...pw.normalize('NFC')].length < MIN_PASSWORD_LENGTH) return 'password-short';
  if (pw && !pw.trim()) return 'password-blank';
  if (pw !== String(repeat ?? '')) return 'mismatch';
  return null;
}

/**
 * The hand-over file's name: `domainscope-workspace-<name>-<stamp>.json`; an encrypted file
 * never carries the workspace's name (it would give away the customer the password hides):
 * `domainscope-workspace-encrypted-<stamp>.json`.
 * @param {string} name the workspace's name as shown
 * @param {{ encrypted?: boolean, date?: Date }} [opts]
 * @returns {string}
 */
export function exportFileName(name, { encrypted = false, date = new Date() } = {}) {
  return timestampedName('domainscope-workspace', 'json', encrypted ? 'encrypted' : name, date);
}

/**
 * What an imported workspace holds, in one line: servers, learned names, expected CAs, recent
 * domains, and whether it has a custom wordlist and notes.
 * @param {{ data: object, encrypted?: boolean }} ws
 * @returns {string}
 */
export function importSummary(ws) {
  const d = ws.data;
  const servers = d.inventory ? parseInventory(d.inventory.text).servers.length : 0;
  const parts = [
    t('ws.sum.servers', { count: servers }),
    t('ws.sum.learned', { count: d.learned ? Object.keys(d.learned.labels).length : 0 }),
    t('ws.sum.expected', { count: d.expectedCas.length }),
    t('ws.sum.recent', { count: d.recent.length })
  ];
  if (d.wordlist.trim()) parts.push(t('ws.sum.wordlist'));
  if (d.notes.trim()) parts.push(t('ws.sum.notes'));
  if (ws.encrypted) parts.push(t('ws.sum.encrypted'));
  return parts.join(' · ');
}

/**
 * A line in the dialog that says what the last click did (a toast or a live region in <body> is
 * under the modal dialog and inert while it is open): a result politely, a warning or a failure
 * as an alert. The next message replaces it; it can be dismissed.
 * @param {string} role its data-role
 * @returns {{ el: HTMLElement, show(message: string, variant?: 'ok'|'warn'|'error'): void, clear(): void }}
 */
function Outcome(role) {
  const el = h('div', { class: 'ws-outcome', dataset: { role }, attrs: { 'aria-live': 'polite', 'aria-atomic': 'true' } });
  return {
    el,
    show(message, variant = 'ok') {
      clear(el);
      el.append(Alert({ variant, compact: true, message, dismissible: true }));
      el.scrollIntoView({ block: 'nearest' });
    },
    clear: () => clear(el)
  };
}

/**
 * The workspace an imported file would replace: Default for a file exported from a Default, else
 * the one of the same name (case-insensitive), else none.
 * @param {{ name: string|null, isDefault: boolean }} ws
 * @param {Array<{ id: string, name: string|null, isDefault: boolean }>} list
 * @returns {object|null}
 */
export function replaceTarget(ws, list) {
  if (ws.isDefault) return list.find((w) => w.isDefault) || null;
  const key = String(ws.name || '').toLowerCase();
  return key ? list.find((w) => !w.isDefault && w.name.toLowerCase() === key) || null : null;
}

/**
 * Open the Workspaces dialog.
 * @param {{ state: object, switchTo: (id: string) => Promise<boolean>, setTarget: (value: string) => boolean,
 *   onClose?: () => void, appVersion?: string }} opts `switchTo`: the shell's switch (asks before
 *   stopping a long job); `setTarget`: make a recent domain the current target
 * @returns {{ el: HTMLDialogElement, close(): void }}
 */
export function openWorkspacePanel({ state, switchTo, setTarget, onClose = null, appVersion = '' }) {
  const cleanups = [];
  let renaming = null; // id of the workspace whose name is being edited
  let renamingName = ''; // its name as shown when the edit began (said if another tab deletes it)
  let pending = null; // an import in progress: { text, fileName, encrypted, ws } (ws once it is open)

  const memoryNote = h('div', { class: 'ws-memory' });
  const listEl = h('ul', { class: 'ws-list', dataset: { role: 'ws-list' } });
  const newName = textInput({
    label: t('ws.newLabel'),
    placeholder: t('ws.newPlaceholder'),
    hint: t('ws.createHint'),
    attrs: { maxlength: String(WORKSPACE_LIMITS.name), 'data-role': 'ws-new-name', autocomplete: 'off' },
    onEnter: () => create()
  });
  const createBtn = Button({ label: t('ws.create'), icon: 'plus', variant: 'primary', dataset: { action: 'ws-create' }, onClick: () => create() });
  inline(newName, createBtn);
  const current = h('section', { class: 'ws-section ws-current', dataset: { role: 'ws-current' } });
  const fileBody = h('div', { class: 'ws-file-body' });
  const listOutcome = Outcome('ws-list-outcome');
  const fileOutcome = Outcome('ws-file-outcome');

  const listId = uid('ws-list-title');
  const body = h('div', { class: 'ws-panel' },
    h('p', { class: 'ws-intro' }, t('ws.intro')),
    memoryNote,
    h('section', { class: 'ws-section', attrs: { 'aria-labelledby': listId } },
      h('h3', { class: 'ws-heading', id: listId }, t('ws.listTitle')),
      listEl,
      listOutcome.el,
      h('div', { class: 'ws-new' }, newName.el)),
    current,
    h('section', { class: 'ws-section ws-file' },
      h('h3', { class: 'ws-heading' }, t('ws.fileTitle')),
      h('p', { class: 'ws-note' }, t('ws.fileIntro')),
      fileBody,
      fileOutcome.el));

  const modal = Modal({
    title: t('ws.title'),
    size: 'lg',
    className: 'ws-modal',
    content: body,
    onClose: () => {
      flushEdits();
      for (const fn of cleanups.splice(0)) fn();
      if (onClose) onClose();
    }
  });

  /* --- the list ---------------------------------------------------------- */

  function renderMemoryNote() {
    clear(memoryNote);
    if (!state.workspacePersistence) memoryNote.append(Alert({ variant: 'warn', compact: true, message: t('ws.memoryOnly') }));
  }

  /** @param {{ focusId?: string|null, focusAction?: string|null }} [opts] the row to focus, or one of its buttons */
  function renderList({ focusId = null, focusAction = null } = {}) {
    clear(listEl);
    const activeId = state.workspace.id;
    for (const ws of state.workspaces) {
      const name = workspaceLabel(ws);
      const active = ws.id === activeId;
      const li = h('li', { class: ['ws-item', { 'is-active': active, 'is-undated': !ws.updatedAt }], dataset: { wsId: ws.id, active: active ? '1' : '0' }, attrs: { tabindex: -1 } });
      if (renaming === ws.id) {
        const field = textInput({
          label: t('ws.renameLabel', { name }),
          value: ws.name,
          attrs: { maxlength: String(WORKSPACE_LIMITS.name), 'data-role': 'ws-rename-input' },
          onEnter: () => saveRename(ws, field)
        });
        const cancel = () => {
          renaming = null;
          renderList({ focusId: ws.id, focusAction: 'ws-rename' });
        };
        // Esc cancels the rename only: the dialog stays open.
        field.input.addEventListener('keydown', (e) => {
          if ((e.key !== 'Escape' && e.key !== 'Esc') || e.isComposing) return;
          e.preventDefault();
          e.stopPropagation();
          cancel();
        });
        inline(field,
          Button({ label: t('ws.save'), variant: 'primary', size: 'sm', dataset: { action: 'ws-rename-save' }, onClick: () => saveRename(ws, field) }),
          Button({ label: t('ws.cancel'), variant: 'ghost', size: 'sm', dataset: { action: 'ws-rename-cancel' }, onClick: cancel }));
        li.append(h('div', { class: 'ws-rename' }, field.el));
        listEl.append(li);
        queueMicrotask(() => field.focus());
        continue;
      }
      const actions = h('div', { class: 'ws-item-actions' });
      if (!active) {
        actions.append(Button({
          label: t('ws.switch'), size: 'sm', dataset: { action: 'ws-switch' }, ariaLabel: t('ws.switchTo', { name }),
          onClick: () => doSwitch(ws.id)
        }));
      }
      if (!ws.isDefault) {
        const rename = IconButton({ icon: 'edit', label: t('ws.rename', { name }), size: 'sm', onClick: () => { renaming = ws.id; renamingName = name; renderList(); } });
        rename.dataset.action = 'ws-rename';
        const del = IconButton({ icon: 'trash', label: t('ws.delete', { name }), size: 'sm', onClick: () => remove(ws) });
        del.dataset.action = 'ws-delete';
        actions.append(rename, del);
      }
      li.append(
        h('div', { class: 'ws-item-main' },
          h('span', { class: 'ws-item-name' }, Icon('briefcase', { size: 15 }), h('span', { class: 'ws-item-label' }, name)),
          active ? Badge(t('ws.active'), { variant: 'ok', icon: 'check', className: 'ws-item-badge' }) : null,
          // Default nothing was written to yet has no date: it never changed.
          ws.updatedAt ? h('span', { class: 'ws-item-meta' }, t('ws.updated', { when: formatRelative(new Date(ws.updatedAt)) })) : null),
        actions);
      listEl.append(li);
    }
    if (focusId) {
      const row = listEl.querySelector(`li[data-ws-id="${CSS.escape(focusId)}"]`);
      const target = row && ((focusAction && row.querySelector(`[data-action="${focusAction}"]`)) || row);
      if (target) target.focus({ preventScroll: true });
    }
  }

  /**
   * A change the browser's storage did not take: why, under the list (or the hand-over file). A
   * workspace deleted in another tab is said so (the list follows that tab); anything else lasts
   * until this tab closes.
   * @param {unknown} err
   * @param {string} name the workspace's name as shown
   * @param {ReturnType<typeof Outcome>} [where]
   */
  function notSaved(err, name, where = listOutcome) {
    const gone = err && err.code === 'not-found';
    if (gone) renderList();
    where.show(gone ? t('ws.gone', { name }) : t('ws.notSaved', { reason: storageErrorText(err) }), 'warn');
  }

  async function create() {
    newName.setError(null);
    listOutcome.clear();
    const name = newName.value;
    // A name Default goes by (in either language) is not free for another workspace.
    if (isDefaultWorkspaceName(name)) {
      newName.setError(t('ws.err.name-taken'));
      return;
    }
    setButtonBusy(createBtn, true);
    try {
      const { meta, persisted } = await state.createWorkspace(name);
      newName.value = '';
      if (!persisted) notSaved(state.workspaceError, meta.name);
      await flushEdits();
      await switchTo(meta.id);
      renderList({ focusId: meta.id });
    } catch (err) {
      newName.setError(errorMessage(err));
      newName.focus();
    } finally {
      setButtonBusy(createBtn, false);
    }
  }

  async function saveRename(ws, field) {
    field.setError(null);
    if (isDefaultWorkspaceName(field.value)) {
      field.setError(t('ws.err.name-taken'));
      return;
    }
    try {
      const { meta, persisted } = await state.renameWorkspace(ws.id, field.value);
      renaming = null;
      renderList({ focusId: ws.id, focusAction: 'ws-rename' });
      if (persisted) listOutcome.show(t('ws.renamed', { name: meta.name }));
      else notSaved(state.workspaceError, workspaceLabel(ws));
    } catch (err) {
      if (err && err.code === 'not-found') {
        // Deleted in another tab while its name was being edited.
        renaming = null;
        notSaved(err, workspaceLabel(ws));
        return;
      }
      field.setError(errorMessage(err));
      field.focus();
    }
  }

  async function remove(ws) {
    const name = workspaceLabel(ws);
    const ok = await confirmDialog({ message: t('ws.deleteConfirm', { name }), confirmLabel: t('common.delete'), danger: true });
    if (!ok) return;
    try {
      // Deleting the workspace in use is a switch to Default first (a long job there asks to stop).
      if (ws.id === state.workspace.id) {
        await flushEdits();
        if (!(await switchTo(DEFAULT_WORKSPACE_ID))) return;
      }
      const { persisted } = await state.deleteWorkspace(ws.id);
      renderList({ focusId: state.workspace.id });
      if (persisted) listOutcome.show(t('ws.deleted', { name }));
      else listOutcome.show(t('ws.deleteNotSaved', { name, reason: storageErrorText(state.workspaceError) }), 'warn');
    } catch (err) {
      // Another tab deleted it while the confirmation was open: it is gone all the same.
      renderList({ focusId: state.workspace.id });
      if (err && err.code === 'not-found') notSaved(err, name);
      else listOutcome.show(errorMessage(err), 'error');
    }
  }

  async function doSwitch(id) {
    await flushEdits();
    if (await switchTo(id)) renderList({ focusId: id });
  }

  /* --- the current workspace ---------------------------------------------- */

  /** Edits waiting for their save: each belongs to the workspace it was typed in. */
  const edits = new Map();

  /** Save a typed value into the workspace it was typed in — never into one switched to since. */
  function saveEdit(wsId, part, value) {
    edits.delete(part);
    if (state.workspace.id !== wsId) return Promise.resolve(false);
    return state.setWorkspaceData(part, value);
  }

  function scheduleEdit(wsId, part, read, status) {
    const prev = edits.get(part);
    if (prev) clearTimeout(prev.timer);
    status.textContent = t('ws.saving');
    const entry = {
      run: () => saveEdit(wsId, part, read()).then((ok) => {
        status.textContent = ok ? t('ws.savedNow') : t('ws.notSaved', { reason: storageErrorText(state.workspaceError) });
      }),
      timer: setTimeout(() => entry.run(), SAVE_DELAY_MS)
    };
    edits.set(part, entry);
  }

  /** Save what is still waiting (before a switch, a delete or the dialog closing). */
  function flushEdits() {
    const runs = [...edits.values()].map((e) => {
      clearTimeout(e.timer);
      return e.run();
    });
    return Promise.all(runs);
  }

  function renderCurrent() {
    clear(current);
    const ws = state.workspace;
    const wsId = ws.id;
    const name = workspaceLabel(ws);
    const titleId = uid('ws-current-title');
    current.setAttribute('aria-labelledby', titleId);
    current.dataset.wsId = wsId;

    // Recent domains
    const recent = state.workspaceData('recent');
    const recentList = recent.length
      ? h('ul', { class: 'ws-recent' }, recent.map((r) => h('li', null, h('button', {
        type: 'button',
        class: 'ws-recent-item',
        dataset: { action: 'ws-recent', value: r.value },
        title: t('ws.recentUse', { value: r.value }),
        on: {
          click: () => {
            if (!setTarget(r.value)) return;
            announce(t('ws.recentSet', { value: r.value }));
            modal.close(null);
          }
        }
      }, h('span', { class: 'ws-recent-value mono' }, r.value),
      r.at ? h('span', { class: 'ws-recent-at' }, formatRelative(new Date(r.at))) : null))))
      : h('p', { class: 'ws-empty', dataset: { role: 'ws-recent-empty' }, attrs: { tabindex: -1 } }, t('ws.recentEmpty'));
    const recentClear = recent.length ? Button({
      label: t('ws.recentClear'), icon: 'x', size: 'sm', variant: 'ghost', dataset: { action: 'ws-recent-clear' },
      onClick: () => {
        state.setWorkspaceData('recent', []);
        renderCurrent();
        // The button is gone: the focus goes to what took its place, not out of the dialog.
        const empty = current.querySelector('[data-role="ws-recent-empty"]');
        if (empty) empty.focus({ preventScroll: true });
      }
    }) : null;

    // Expected CAs
    const expectedStatus = h('span', { class: 'ws-status', attrs: { 'aria-live': 'polite' } });
    const expectedList = h('div', { class: 'ws-expected-list', dataset: { role: 'ws-expected-list' } });
    const renderExpected = (entries) => {
      clear(expectedList);
      for (const entry of entries) {
        const r = resolveExpectedCa(entry);
        expectedList.append(Badge(r.ca ? r.ca.name : entry, {
          variant: r.ca ? 'ok' : 'neutral',
          icon: r.ca ? 'shield' : 'file-text',
          title: r.ca ? t('ws.expectedKnown', { ca: r.ca.name, domains: r.ca.domains.slice(0, 3).join(', ') }) : t('ws.expectedText'),
          className: 'ws-expected-entry'
        }));
      }
    };
    const expected = textarea({
      label: t('ws.expectedLabel'),
      value: state.workspaceData('expectedCas').join('\n'),
      rows: 3,
      mono: false,
      wrap: true,
      hint: t('ws.expectedHint'),
      attrs: { 'data-role': 'ws-expected' },
      onInput: (value) => {
        renderExpected(sanitizeExpectedCas(value));
        scheduleEdit(wsId, 'expectedCas', () => sanitizeExpectedCas(expected.value), expectedStatus);
      }
    });
    renderExpected(state.workspaceData('expectedCas'));

    // Notes
    const notesStatus = h('span', { class: 'ws-status', attrs: { 'aria-live': 'polite' } });
    const notes = textarea({
      label: t('ws.notesLabel'),
      value: state.workspaceData('notes'),
      rows: 5,
      mono: false,
      wrap: true,
      hint: t('ws.notesHint'),
      attrs: { 'data-role': 'ws-notes', maxlength: String(WORKSPACE_LIMITS.notes) },
      onInput: () => scheduleEdit(wsId, 'notes', () => notes.value, notesStatus)
    });
    for (const field of [expected, notes]) field.input.addEventListener('blur', () => flushEdits());

    current.append(
      h('h3', { class: 'ws-heading', id: titleId }, t('ws.currentTitle', { name })),
      h('div', { class: 'ws-block' },
        h('div', { class: 'ws-block-head' }, h('span', { class: 'field-label' }, t('ws.recentTitle')), recentClear),
        h('p', { class: 'field-hint' }, t('ws.recentHint')),
        recentList),
      h('div', { class: 'ws-block' }, expected.el, expectedList, expectedStatus),
      h('div', { class: 'ws-block' }, notes.el, notesStatus));
  }

  /* --- the hand-over file -------------------------------------------------- */

  function renderFile() {
    clear(fileBody);
    const ws = state.workspace;
    const name = workspaceLabel(ws);

    // Export
    const pw = textInput({
      label: t('ws.password'),
      type: 'password',
      optional: false,
      hint: t('ws.passwordOptional', { count: MIN_PASSWORD_LENGTH }),
      autocomplete: 'new-password',
      attrs: { 'data-role': 'ws-export-password' }
    });
    const pw2 = textInput({
      label: t('ws.passwordRepeat'),
      type: 'password',
      autocomplete: 'new-password',
      attrs: { 'data-role': 'ws-export-repeat' },
      onEnter: () => doExport()
    });
    const exportBtn = Button({ label: t('ws.export'), icon: 'download', variant: 'primary', dataset: { action: 'ws-export' }, onClick: () => doExport() });

    async function doExport() {
      pw.setError(null);
      pw2.setError(null);
      const password = pw.value;
      const problem = passwordProblem(password, pw2.value);
      if (problem) {
        const field = problem === 'mismatch' ? pw2 : pw;
        field.setError(t(`ws.err.${problem}`, { count: MIN_PASSWORD_LENGTH }));
        field.focus();
        return;
      }
      setButtonBusy(exportBtn, true);
      try {
        await flushEdits();
        const active = state.workspace;
        const data = await state.loadWorkspace(active.id);
        const text = await exportWorkspaceFile({
          name: workspaceLabel(active), isDefault: active.isDefault, data, app: `DomainScope ${appVersion}`.trim(), exportedAt: new Date()
        }, { password: password || null });
        const file = exportFileName(workspaceLabel(active), { encrypted: !!password });
        downloadText(file, text, 'application/json;charset=utf-8');
        fileOutcome.show(t(password ? 'ws.exportedSealed' : 'ws.exportedPlain', { file }), password ? 'ok' : 'warn');
      } catch (err) {
        pw.setError(errorMessage(err));
      } finally {
        // The password is never kept: not in the fields, not anywhere else.
        pw.value = '';
        pw2.value = '';
        setButtonBusy(exportBtn, false);
      }
    }

    const exportPart = h('div', { class: 'ws-block ws-export', dataset: { role: 'ws-export' } },
      h('h4', { class: 'ws-subheading' }, t('ws.exportTitle', { name })),
      h('div', { class: 'ws-passwords' }, pw.el, pw2.el),
      h('div', { class: 'ws-actions' }, exportBtn));

    // Import
    const importArea = h('div', { class: 'ws-import-area' });
    const drop = FileDrop({
      accept: '.json',
      compact: true,
      icon: 'upload',
      title: t('ws.importDrop'),
      hint: t('ws.importDropHint'),
      maxBytes: HANDOVER_MAX_BYTES,
      paste: false,
      onFiles: (files) => startImport(files[0])
    });
    const importPart = h('div', { class: 'ws-block ws-import', dataset: { role: 'ws-import' } },
      h('h4', { class: 'ws-subheading' }, t('ws.importTitle')),
      h('p', { class: 'field-hint' }, t('ws.importHint')),
      drop.el,
      importArea);

    /** The error of a file that cannot be imported, in words, with its code for the tests. */
    function importError(err) {
      const alert = Alert({ variant: 'error', compact: true, message: errorMessage(err) });
      alert.classList.add('ws-import-error');
      alert.dataset.role = 'ws-import-error';
      alert.dataset.code = (err && err.code) || 'unknown';
      return alert;
    }

    function showError(err) {
      clear(importArea);
      importArea.append(importError(err));
    }

    function startImport(file) {
      clear(importArea);
      pending = null;
      if (!file) return;
      let info;
      try {
        info = readWorkspaceFile(file.text);
      } catch (err) {
        showError(err);
        return;
      }
      pending = { text: file.text, fileName: file.name, encrypted: info.encrypted, ws: null };
      if (info.encrypted) askPassword();
      else openFile(null);
    }

    function askPassword(err = null) {
      clear(importArea);
      const field = textInput({
        label: t('ws.importPassword'),
        type: 'password',
        autocomplete: 'off',
        attrs: { 'data-role': 'ws-import-password' },
        onEnter: () => open()
      });
      const openBtn = Button({ label: t('ws.importOpen'), icon: 'unlock', variant: 'primary', dataset: { action: 'ws-import-open' }, onClick: () => open() });
      inline(field, openBtn);
      const box = h('div', { class: 'ws-import-sealed', dataset: { role: 'ws-import-sealed' } },
        h('p', { class: 'ws-note' }, Icon('lock', { size: 14 }), ' ', t('ws.importSealed')),
        field.el);
      if (err) box.prepend(importError(err));
      importArea.append(box);
      queueMicrotask(() => field.focus());

      async function open() {
        const password = field.value;
        setButtonBusy(openBtn, true);
        try {
          await openFile(password);
        } finally {
          // The password is dropped as soon as the file is open (or refused).
          field.value = '';
          if (openBtn.isConnected) setButtonBusy(openBtn, false);
        }
      }
    }

    async function openFile(password) {
      if (!pending) return;
      let ws;
      try {
        ws = await openWorkspaceFile(pending.text, { password });
      } catch (err) {
        if (pending && pending.encrypted && ['wrong-password', 'password-required'].includes(err && err.code)) askPassword(err);
        else showError(err);
        return;
      }
      pending.ws = ws;
      showSummary();
    }

    function showSummary() {
      clear(importArea);
      const ws = pending.ws;
      const name = ws.name || t('ws.importUnnamed');
      const target = replaceTarget(ws, state.workspaces);
      const newBtn = Button({ label: t('ws.importNew'), icon: 'plus', variant: target ? 'secondary' : 'primary', dataset: { action: 'ws-import-new' }, onClick: () => importNew() });
      const replaceBtn = target ? Button({
        label: t('ws.importReplace', { name: workspaceLabel(target) }), icon: 'refresh', variant: 'danger', dataset: { action: 'ws-import-replace' },
        onClick: () => importReplace(target)
      }) : null;
      const cancelBtn = Button({
        label: t('ws.cancel'), variant: 'ghost', dataset: { action: 'ws-import-cancel' },
        onClick: () => {
          pending = null;
          clear(importArea);
        }
      });
      importArea.append(h('div', { class: 'ws-import-summary', dataset: { role: 'ws-import-summary' } },
        h('p', { class: 'ws-import-name' }, Icon('file-text', { size: 15 }), ' ',
          ws.exportedAt ? t('ws.importSummary', { name, when: formatDateTime(ws.exportedAt) }) : t('ws.importSummaryUndated', { name })),
        h('p', { class: 'ws-note' }, importSummary(ws)),
        h('div', { class: 'ws-actions' }, replaceBtn, newBtn, cancelBtn)));
      (replaceBtn || newBtn).focus({ preventScroll: true });

      async function importNew() {
        setButtonBusy(newBtn, true);
        try {
          const unique = uniqueWorkspaceName(name, [...defaultWorkspaceNames(), ...state.workspaces.filter((w) => !w.isDefault).map((w) => w.name)]);
          const { meta, persisted } = await state.createWorkspace(unique, ws.data);
          pending = null;
          clear(importArea);
          if (persisted) fileOutcome.show(t('ws.imported', { name: meta.name }));
          else notSaved(state.workspaceError, meta.name, fileOutcome);
          await flushEdits();
          await switchTo(meta.id);
          renderList({ focusId: meta.id });
        } catch (err) {
          showError(err);
        }
      }

      async function importReplace(into) {
        const label = workspaceLabel(into);
        const ok = await confirmDialog({ message: t('ws.replaceConfirm', { name: label }), confirmLabel: t('ws.importReplace', { name: label }), danger: true });
        if (!ok) return;
        try {
          if (!state.workspaces.some((w) => w.id === into.id)) throw new WorkspaceError('not-found');
          await flushEdits();
          if (into.id !== state.workspace.id && !(await switchTo(into.id))) return;
          const { persisted } = await state.replaceWorkspace(into.id, ws.data);
          pending = null;
          clear(importArea);
          if (persisted) fileOutcome.show(t('ws.replaced', { name: label }));
          else notSaved(state.workspaceError, label, fileOutcome);
          renderCurrent();
        } catch (err) {
          // Deleted in another tab meanwhile: the file stays open, to import as a new workspace.
          if (err && err.code === 'not-found') {
            notSaved(err, label, fileOutcome);
            if (pending) showSummary();
          } else {
            showError(err);
          }
        }
      }
    }

    fileBody.append(exportPart, importPart);
  }

  /* --- following the state -------------------------------------------------- */

  cleanups.push(state.subscribe(({ key, value, origin }) => {
    if (key === 'workspace' || key === 'cleared') {
      edits.clear();
      renaming = null;
      renderList();
      renderCurrent();
      renderFile();
    } else if (key === 'workspaces') {
      // Another tab changed the list while a name is being edited here: the draft stays; a
      // workspace deleted there is said so, with the focus on the active row.
      const draft = renaming ? listEl.querySelector('[data-role="ws-rename-input"]') : null;
      if (renaming && !state.workspaces.some((w) => w.id === renaming)) {
        renaming = null;
        renderList({ focusId: state.workspace.id });
        listOutcome.show(t('ws.gone', { name: renamingName }), 'warn');
      } else {
        renderList();
        const field = draft ? listEl.querySelector('[data-role="ws-rename-input"]') : null;
        if (field) field.value = draft.value;
      }
      if (current.dataset.wsId === state.workspace.id) {
        // A rename of the current workspace: its headings follow.
        const heading = current.querySelector('.ws-heading');
        if (heading) heading.textContent = t('ws.currentTitle', { name: workspaceLabel(state.workspace) });
        const exportHeading = fileBody.querySelector('.ws-export .ws-subheading');
        if (exportHeading) exportHeading.textContent = t('ws.exportTitle', { name: workspaceLabel(state.workspace) });
      }
    } else if (key === 'workspaceData') {
      const parts = (value && value.parts) || [];
      // Another tab (or an import) changed what the dialog shows; never under the user's typing.
      const typing = current.contains(globalThis.document.activeElement) && globalThis.document.activeElement.tagName === 'TEXTAREA';
      if ((origin === 'external' && !typing) || (parts.includes('recent') && !typing)) renderCurrent();
    }
  }));

  renderMemoryNote();
  renderList();
  renderCurrent();
  renderFile();
  modal.open();
  // Straight to the workspaces, not the dialog's close button.
  const first = listEl.querySelector('li.is-active') || listEl.querySelector('li');
  if (first) first.focus({ preventScroll: true });
  return { el: modal.el, close: () => modal.close(null) };
}
