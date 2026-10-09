/**
 * ui/palette.js — the command palette (Ctrl/Cmd+K; the shell's one key handler in app.js loads
 * this module and assets/css/palette.css on first use). One box finds a tool by its name or
 * description in either language, and acts on what is typed: a domain or host name, an IP
 * address, a network, an AS number or a pasted certificate (lib/palette.js); with the box empty
 * it offers the current target, the workspace's recent domains and every tool.
 *
 * An accessible combobox in a modal dialog: the box owns the focus (`aria-activedescendant`),
 * ↓ and ↑ move through the list, Enter opens the entry, Esc or Ctrl/Cmd+K closes, and the focus
 * goes back where it was. Choosing an entry only fills the tool in: actions open it with
 * `run=0`, a tool opens like its navigation link (with the current target filled in), a recent
 * domain or the target goes into the box. Nothing is sent until the tool runs, and nothing typed
 * here is stored. The same search inline ({@link PaletteBox}): the box on top of the phone Tools
 * sheet (one search, not two), its results replacing the sheet's tiles while it holds text.
 */

import { t, getLang, registerStrings, stringIn, interpolate } from '../i18n.js';
import { h, clear, uid } from './dom.js';
import { Modal, Icon } from './components.js';
import { paletteResults, highlightRanges, ACTION_IDS, ENTRY_TYPES } from '../lib/palette.js';

registerStrings('en', {
  'pal.title': 'Search tools and actions',
  'pal.label': 'A tool, or a domain, an IP address, a network, an AS number or a certificate to act on',
  'pal.placeholder': 'Tool, example.com, 192.0.2.10, 198.51.100.0/24, AS64496, PEM…',
  'pal.results': 'Results',
  'pal.count': { one: '{count} result', other: '{count} results' },
  'pal.none': 'Nothing matches “{query}”. Type a tool’s name, a domain or an IP address.',
  'pal.hint': 'An entry only fills the tool in: nothing is sent until you run it.',
  'pal.keys': '↑ ↓ to move · Enter to open · Esc to close',
  'pal.fill': 'Show what you can do with it',
  'pal.reverseIpHint': 'IP Intel — then “Find domains” in the address’s row (HackerTarget)',
  'pal.certHint': 'Certificate — read in this browser, nothing is sent',
  'pal.certFailed': 'The Certificate tool could not be loaded: {message}',
  'pal.type.action': 'Action',
  'pal.type.tool': 'Tool',
  'pal.type.recent': 'Recent',
  'pal.type.target': 'Current target',
  'pal.act.subdomains': 'Find the subdomains of {value}',
  'pal.act.domain': 'Domain overview of {value}',
  'pal.act.health': 'Check the health of {value}',
  'pal.act.lookupMx': 'MX records of {value}',
  'pal.act.lookupTxt': 'TXT records of {value}',
  'pal.act.lookupCaa': 'CAA records of {value}',
  'pal.act.global': 'Compare {value} on resolvers worldwide',
  'pal.act.renew': 'Renewal readiness of {value}',
  'pal.act.ip': 'IP Intel for {value}',
  'pal.act.reverseIp': 'Domains on this IP: {value}',
  'pal.act.ptr': 'Reverse DNS of {value}',
  'pal.act.retire': 'Retire {value}',
  'pal.act.sweep': 'Reverse DNS sweep of {value}',
  'pal.act.cert': 'Open the pasted certificate'
});

registerStrings('tr', {
  'pal.title': 'Araç ve işlem ara',
  'pal.label': 'Bir araç ya da işlem yapılacak bir alan adı, IP adresi, ağ, AS numarası veya sertifika',
  'pal.placeholder': 'Araç, example.com, 192.0.2.10, 198.51.100.0/24, AS64496, PEM…',
  'pal.results': 'Sonuçlar',
  'pal.count': '{count} sonuç',
  'pal.none': '“{query}” ile eşleşen bir şey yok. Bir aracın adını, bir alan adını ya da bir IP adresini yazın.',
  'pal.hint': 'Bir seçenek aracı yalnızca doldurur: siz çalıştırana kadar hiçbir şey gönderilmez.',
  'pal.keys': 'Gezinmek için ↑ ↓ · açmak için Enter · kapatmak için Esc',
  'pal.fill': 'Bununla yapabileceklerinizi göster',
  'pal.reverseIpHint': 'IP Bilgisi — ardından adresin satırındaki “Alan adlarını bul” (HackerTarget)',
  'pal.certHint': 'Sertifika — bu tarayıcıda okunur, hiçbir şey gönderilmez',
  'pal.certFailed': 'Sertifika aracı yüklenemedi: {message}',
  'pal.type.action': 'İşlem',
  'pal.type.tool': 'Araç',
  'pal.type.recent': 'Son kullanılan',
  'pal.type.target': 'Geçerli hedef',
  'pal.act.subdomains': '{value} alan adının subdomain’lerini bul',
  'pal.act.domain': '{value} için alan adı özeti',
  'pal.act.health': '{value} için alan adı sağlığını kontrol et',
  'pal.act.lookupMx': '{value} adının MX kayıtları',
  'pal.act.lookupTxt': '{value} adının TXT kayıtları',
  'pal.act.lookupCaa': '{value} adının CAA kayıtları',
  'pal.act.global': '{value} adını dünya genelindeki çözümleyicilerde karşılaştır',
  'pal.act.renew': '{value} için yenileme hazırlığı',
  'pal.act.ip': '{value} için IP bilgisi',
  'pal.act.reverseIp': 'Bu IP’deki alan adları: {value}',
  'pal.act.ptr': '{value} için ters DNS',
  'pal.act.retire': '{value} adresini emekliye ayır',
  'pal.act.sweep': '{value} için ters DNS taraması',
  'pal.act.cert': 'Yapıştırılan sertifikayı aç'
});

/**
 * The i18n keys this module builds in code (for the coverage test).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [...ACTION_IDS.map((id) => `pal.act.${id}`), ...ENTRY_TYPES.map((type) => `pal.type.${type}`)];
}

/** The most characters of the box the "nothing matches" line repeats (a pasted block would fill the dialog). */
const QUERY_SHOWN = 60;

/** The open palette (one at a time). */
let openApi = null;

/**
 * The palette's box: a text field that owns the focus while the list under it is browsed
 * (`aria-activedescendant`).
 * @param {{ autofocus?: boolean }} [opts] `autofocus`: the dialog focuses it on opening
 * @returns {HTMLInputElement}
 */
function paletteInput({ autofocus = false } = {}) {
  return h('input', {
    type: 'text',
    class: 'pal-input',
    attrs: {
      'aria-label': t('pal.label'), placeholder: t('pal.placeholder'), autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', enterkeyhint: 'go'
    },
    dataset: { role: 'palette-input', autofocus: autofocus ? '1' : null }
  });
}

/**
 * The search the dialog and the inline boxes share: `input` becomes a combobox over a listbox of
 * entries (lib/palette.js paletteResults), ↓ and ↑ move, Enter opens the entry. Choosing an entry
 * only fills a tool in (actions open it with `run=0`, a tool like its navigation link, a pasted
 * certificate in the Certificate view, read in the browser); a recent domain or the current target
 * goes into the box, and its actions follow.
 * @param {{ input: HTMLInputElement, views: ReadonlyArray<{ id: string, icon?: string }>,
 *   navigate: Function, href: (view: string) => string, state: object, session: object,
 *   emptyEntries: boolean, onQuery?: (text: string) => void, leave: (moved: boolean) => void }} opts
 *   `emptyEntries`: an empty box lists the current target, the recent domains and every tool (the
 *   dialog) — else nothing (an inline box, whose host shows its own content then); `leave(moved)`:
 *   an entry opened a tool (`moved`: the route changed)
 * @returns {{ list: HTMLElement, status: HTMLElement, render: () => void, entries: () => object[] }}
 */
function paletteSearch({ input, views, navigate, href, state, session, emptyEntries, onQuery = () => {}, leave }) {
  const other = getLang() === 'en' ? 'tr' : 'en';
  const otherText = (key, params) => {
    const raw = stringIn(other, key);
    return typeof raw === 'string' ? interpolate(raw, params) : '';
  };
  const tools = views.map((v) => ({
    id: v.id, icon: v.icon, title: t(`nav.${v.id}`), altTitle: otherText(`nav.${v.id}`), desc: t(`nav.${v.id}.desc`), altDesc: otherText(`nav.${v.id}.desc`)
  }));
  const toolById = new Map(tools.map((tool) => [tool.id, tool]));
  const actionLabels = Object.fromEntries(ACTION_IDS.map((id) => [id, [t(`pal.act.${id}`, { value: '' }), otherText(`pal.act.${id}`, { value: '' })]]));
  const recent = () => {
    const list = state.workspaceData('recent');
    return Array.isArray(list) ? list.map((r) => (r && typeof r.value === 'string' ? r.value : '')).filter(Boolean) : [];
  };

  const listId = uid('pal-list');
  const statusId = uid('pal-status');
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-expanded', 'false');
  input.setAttribute('aria-controls', listId);
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-describedby', statusId);
  const list = h('div', { id: listId, class: 'pal-list', hidden: true, attrs: { role: 'listbox', 'aria-label': t('pal.results') } });
  const status = h('p', { id: statusId, class: 'pal-status', attrs: { role: 'status', 'aria-live': 'polite' } });

  let entries = [];
  let active = 0;
  let options = [];

  /** The label of a tool with the matched letters marked. */
  function titleNodes(text, positions) {
    const ranges = highlightRanges(text, positions);
    if (!ranges.length) return [text];
    const out = [];
    let at = 0;
    for (const [start, end] of ranges) {
      if (start > at) out.push(text.slice(at, start));
      out.push(h('mark', { class: 'pal-mark' }, text.slice(start, end)));
      at = end;
    }
    if (at < text.length) out.push(text.slice(at));
    return out;
  }

  function entryParts(entry) {
    if (entry.type === 'tool') {
      const tool = toolById.get(entry.id) || {};
      return { icon: tool.icon, label: titleNodes(tool.title || entry.id, entry.title), sub: tool.desc || '' };
    }
    if (entry.type === 'action') {
      const tool = toolById.get(entry.view) || {};
      const label = entry.id === 'cert' ? t('pal.act.cert') : t(`pal.act.${entry.id}`, { value: entry.value });
      const sub = entry.id === 'reverseIp' ? t('pal.reverseIpHint') : entry.id === 'cert' ? t('pal.certHint') : tool.title || '';
      return { icon: tool.icon, label: [label], sub };
    }
    return { icon: entry.type === 'target' ? 'map-pin' : 'clock', label: [h('span', { class: 'mono' }, entry.value)], sub: t('pal.fill') };
  }

  function setActive(i, { scroll = true } = {}) {
    if (!options.length) {
      input.removeAttribute('aria-activedescendant');
      return;
    }
    active = (i + options.length) % options.length;
    options.forEach((el, k) => el.setAttribute('aria-selected', String(k === active)));
    input.setAttribute('aria-activedescendant', options[active].id);
    if (scroll && typeof options[active].scrollIntoView === 'function') options[active].scrollIntoView({ block: 'nearest' });
  }

  function render() {
    const query = input.value;
    clear(list);
    if (!emptyEntries && !query.trim()) {
      // An inline box at rest: its host's own content shows.
      entries = [];
      options = [];
      list.hidden = true;
      status.textContent = '';
      status.hidden = true;
      input.setAttribute('aria-expanded', 'false');
      setActive(0);
      onQuery('');
      return;
    }
    status.hidden = false;
    entries = paletteResults({ query, tools, actionLabels, recent: recent(), target: session.target }).entries;
    options = entries.map((entry, i) => {
      const { icon, label, sub } = entryParts(entry);
      return h('div', {
        id: `${listId}-${i}`,
        class: ['pal-option', `pal-${entry.type}`],
        attrs: { role: 'option', 'aria-selected': 'false' },
        dataset: { entry: entry.key },
        on: {
          mousedown: (event) => event.preventDefault(), // the box keeps the focus
          click: () => choose(entry),
          mousemove: () => {
            if (active !== i) setActive(i, { scroll: false });
          }
        }
      },
      Icon(icon || 'search', { size: 16, className: 'pal-icon' }),
      h('span', { class: 'pal-text' }, h('span', { class: 'pal-label' }, ...label), sub ? h('span', { class: 'pal-sub' }, sub) : null),
      h('span', { class: 'pal-tag' }, t(`pal.type.${entry.type}`)));
    });
    list.append(...options);
    list.hidden = !options.length;
    input.setAttribute('aria-expanded', String(options.length > 0));
    const shown = query.trim();
    status.textContent = options.length ? t('pal.count', { count: options.length })
      : t('pal.none', { query: shown.length > QUERY_SHOWN ? `${shown.slice(0, QUERY_SHOWN)}…` : shown });
    status.classList.toggle('pal-status-none', !options.length);
    setActive(0);
    onQuery(query);
  }

  /** Open a tool or an action's route. */
  function go(view, params) {
    const before = globalThis.location.hash;
    if (params) navigate(view, params);
    else globalThis.location.hash = href(view);
    leave(globalThis.location.hash !== before);
  }

  let reading = false;

  /** Read a pasted certificate with the Certificate view's own loader and open it there. */
  async function openCertificate(text) {
    if (reading) return;
    reading = true;
    try {
      const mod = await import('../views/cert.js');
      mod.setCurrentCert(state, mod.loadCertificateData(text, { name: t('file.pasted'), source: 'paste' }));
    } catch (err) {
      reading = false;
      status.hidden = false;
      status.textContent = t('pal.certFailed', { message: err && err.message ? err.message : String(err) });
      return;
    }
    leave(true);
    navigate('cert', {}, { force: true });
  }

  function choose(entry) {
    if (!entry) return;
    if (entry.type === 'recent' || entry.type === 'target') {
      input.value = entry.value;
      render();
      input.focus();
      return;
    }
    if (entry.type === 'action' && entry.id === 'cert') {
      openCertificate(entry.value);
      return;
    }
    go(entry.view, entry.type === 'action' ? entry.params : null);
  }

  input.addEventListener('input', () => render());
  input.addEventListener('keydown', (event) => {
    if (event.isComposing || event.keyCode === 229) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (!options.length) return;
      event.preventDefault();
      setActive(active + (event.key === 'ArrowDown' ? 1 : -1));
    } else if (event.key === 'Enter' && !event.shiftKey && !event.altKey) {
      if (!options.length) return;
      event.preventDefault();
      choose(entries[active]);
    } else if (event.key === 'Escape' && !emptyEntries && input.value) {
      // An inline box: Esc empties it first (the sheet it sits in closes on the next one).
      event.preventDefault();
      event.stopPropagation();
      input.value = '';
      render();
    }
  });
  return { list, status, render, entries: () => entries };
}

/**
 * Open the palette (once; a second call while it is open does nothing): the box in a modal dialog,
 * the focus in it; Esc or Ctrl/Cmd+K closes it and the focus goes back where it was.
 * @param {{ views: ReadonlyArray<{ id: string, icon?: string }>,
 *   navigate: (view: string, params?: object, opts?: object) => void, href: (view: string) => string,
 *   state: { workspaceData: (part: string) => any, setSession: (name: string, value: any) => void },
 *   session: { target: { value: string, kind: string }|null }, done?: () => void }} api
 *   app.js: the view registry, its router, a navigation link's hash (the current target carried
 *   along), the app state and the page session
 * @returns {{ close: () => void }|null}
 */
export function openPalette({ views, navigate, href, state, session, done = () => {} }) {
  if (openApi) return openApi;
  const doc = globalThis.document;
  const back = doc.activeElement && doc.activeElement !== doc.body ? doc.activeElement : null;
  let left = false; // an entry navigated away: the router moves the focus
  let settled = false;
  const input = paletteInput({ autofocus: true });
  const search = paletteSearch({
    input, views, navigate, href, state, session, emptyEntries: true,
    leave: (moved) => {
      left = moved;
      close();
    }
  });
  const content = h('div', { class: 'pal' },
    h('div', { class: 'pal-box' }, Icon('search', { size: 18, className: 'pal-search-icon' }), input),
    search.status,
    search.list,
    h('p', { class: 'pal-hint' }, t('pal.hint'), h('span', { class: 'pal-keys', attrs: { 'aria-hidden': 'true' } }, t('pal.keys'))));

  /**
   * The palette is done: the shell may open it again and the focus goes back. Run at once by
   * {@link close}, and by the dialog's own close (Esc): the `close` event of a dialog closed by a
   * tap can come late (under Chrome's touch emulation it waited for the next key press).
   */
  function settle() {
    if (settled) return;
    settled = true;
    openApi = null;
    done();
    if (!left && back && back.isConnected) back.focus({ preventScroll: true });
  }

  /** Close the dialog and settle at once. */
  function close() {
    modal.close();
    settle();
  }

  input.addEventListener('keydown', (event) => {
    if (event.isComposing || event.keyCode === 229) return;
    if (/^k$/i.test(event.key) && (event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey) {
      event.preventDefault();
      close();
    }
  });

  const modal = Modal({
    title: t('pal.title'),
    className: 'pal-modal',
    content,
    onClose: settle
  });
  search.render();
  modal.open();
  openApi = { close };
  return openApi;
}

/**
 * The palette's search inline (the phone Tools sheet's box; Home's quick start): the same parser,
 * actions and keys as the dialog, its results under the box while it holds text. An empty box
 * lists nothing: the host shows its own content then (`onQuery('')`). Esc in a box with text
 * empties it. Nothing typed is stored, and an entry only fills a tool in.
 * @param {{ views: ReadonlyArray<{ id: string, icon?: string }>, navigate: Function, href: (view: string) => string,
 *   state: object, session: object, input?: HTMLInputElement|null, onQuery?: (text: string) => void,
 *   onLeave?: () => void }} opts
 *   `input`: a box already on the page to take over (else one is made); `onQuery`: the box's text
 *   after each change; `onLeave`: an entry opened a tool
 * @returns {{ el: HTMLElement, input: HTMLInputElement, render: () => void }}
 *   `el`: the box with its results — or, for a box already on the page, the results alone, to put
 *   after it
 */
export function PaletteBox({ views, navigate, href, state, session, input = null, onQuery = () => {}, onLeave = () => {} }) {
  const field = input || paletteInput();
  const search = paletteSearch({
    input: field, views, navigate, href, state, session, emptyEntries: false, onQuery, leave: () => onLeave()
  });
  const el = input
    ? h('div', { class: 'pal pal-inline pal-results' }, search.status, search.list)
    : h('div', { class: 'pal pal-inline' },
      h('div', { class: 'pal-box' }, Icon('search', { size: 18, className: 'pal-search-icon' }), field),
      search.status,
      search.list);
  search.render();
  return { el, input: field, render: search.render };
}
