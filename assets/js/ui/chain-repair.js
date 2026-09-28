/**
 * ui/chain-repair.js — the missing intermediate, found in this site's copy of the CCADB list and
 * added to fullchain.pem, and the root-store warnings of the chain (lib/chainfix.js), for the
 * Certificate view (above the overview and in its Chain tab) and SSL Targets step 1.
 *
 * - {@link startChainRepair}: one job per loaded file (kept for the page session with the file,
 *   so a language switch or another tab re-renders it at once): the dataset's manifest and roots
 *   table, and only for a chain that stops short of a root, the one or two shards its issuer's
 *   key id points at — files of this site, never a request that carries the certificate.
 * - {@link ChainRepairNotes}: "Missing intermediate found" with what was added (name, issuer,
 *   CA owner, expiry) and Download fullchain.pem; "not in the list" for a lone server certificate
 *   whose issuer the list does not hold; a Retry when the list could not be loaded (offline: the
 *   shards are not kept by the service worker); and, where asked, the root-store warnings — a
 *   store that distrusts certificates issued after a date (with the announcement), a root that was
 *   removed, one that expires before the certificate.
 * - {@link ChainRepairChainPart}: the Chain tab's part — the added intermediates under the file's
 *   chain and where the chain ends, with the stores that trust it.
 *
 * Every string is rendered through h() / text nodes. No AIA URL is ever fetched (they are plain
 * http without CORS): the list replaces them.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, ExternalLink, Icon } from './components.js';
import { t, registerStrings, formatDate, localeTag } from '../i18n.js';
import { createIntermediateStore, fileChain, repairChain, STORES } from '../lib/chainfix.js';

/** The CCADB, credited wherever the list's data is shown (its data licence asks for attribution). */
export const CCADB_URL = 'https://www.ccadb.org/';

registerStrings('en', {
  'chainfix.found.title': { one: 'Missing intermediate found', other: '{count} missing intermediates found' },
  'chainfix.found.leafOnly': {
    one: 'The file holds only the server certificate. The intermediate that issued it is in the CCADB list of public intermediates, so fullchain.pem below puts it after the server certificate.',
    other: 'The file holds only the server certificate. The {count} intermediates it needs are in the CCADB list of public intermediates, so fullchain.pem below puts them after the server certificate, in order.'
  },
  'chainfix.found.partial': {
    one: 'The file stops at {name}, whose issuer is not in it. That issuer is in the CCADB list of public intermediates, so fullchain.pem below adds it.',
    other: 'The file stops at {name}, whose issuer is not in it. The {count} certificates up to the root are in the CCADB list of public intermediates, so fullchain.pem below adds them, in order.'
  },
  'chainfix.found.ct': {
    one: 'Certificate Transparency logs hold the server certificate only. The intermediate that issued it is in the CCADB list of public intermediates, so fullchain.pem below puts it after the server certificate.',
    other: 'Certificate Transparency logs hold the server certificate only. The {count} intermediates it needs are in the CCADB list of public intermediates, so fullchain.pem below puts them after the server certificate, in order.'
  },
  'chainfix.found.untrustedTitle': 'A current root is reachable',
  'chainfix.found.untrusted': {
    one: 'The file’s chain ends at {root}, which no root store trusts for this certificate. A cross-signed certificate in the CCADB list leads on to {next}, so fullchain.pem below adds it.',
    other: 'The file’s chain ends at {root}, which no root store trusts for this certificate. {count} certificates in the CCADB list lead on to {next}, so fullchain.pem below adds them.'
  },
  'chainfix.added': 'Added',
  'chainfix.addedMeta': 'issued by {issuer} · CA owner: {owner} · valid until {date}',
  'chainfix.source': 'From this site’s copy of the CCADB list ({date}). Your certificate was not sent anywhere.',
  'chainfix.download': 'Download fullchain.pem',
  'chainfix.downloadHint': {
    one: 'The server certificate, then its intermediate. Not the root, and never a key.',
    other: 'The server certificate, then its {count} intermediates in order. Not the root, and never a key.'
  },
  'chainfix.notFound': 'The intermediate that issued this certificate ({issuer}) is not in the CCADB list of public intermediates ({date}): it may belong to a private CA or be newer than this copy of the list. Get the chain (CA bundle) from your certificate authority.',
  'chainfix.failed': 'The list of intermediates could not be loaded (you may be offline), so the missing intermediate was not looked up.',

  'chainfix.life.title': 'Root store warnings',
  'chainfix.life.distrusted': '{stores} does not trust certificates from {root} issued after {date}. This one was issued on {issued}.',
  'chainfix.life.renewal-distrusted': '{stores} does not trust certificates from {root} issued after {date}. This one (issued on {issued}) is not affected, but its renewal has to come from another CA.',
  'chainfix.life.removed': '{root} is no longer in the root store of {stores}: their clients reject this chain.',
  'chainfix.life.not-for-tls': '{root} is kept for other uses only, not for websites, by {stores}: their clients reject this chain.',
  'chainfix.life.cut-off': '{stores} trusts certificates from {root} only when they were issued before a cut-off date.',
  'chainfix.life.not-included': '{root} was never in the root store of {stores}.',
  'chainfix.life.root-expired': '{root} expired on {date}: clients no longer trust this chain.',
  'chainfix.life.root-expires': '{root} expires on {date}, before this certificate does ({notAfter}). After that date, clients that check the root’s validity reject the chain.',
  'chainfix.life.announcement': 'Announcement',
  'chainfix.life.source': 'Root store data: CCADB and the stores’ announcements, as of {date}.',
  'chainfix.store.chrome': 'Chrome',
  'chainfix.store.mozilla': 'Mozilla (Firefox)',
  'chainfix.store.apple': 'Apple',
  'chainfix.store.microsoft': 'Microsoft',

  'chainfix.chain.added': 'Added from the CCADB list',
  'chainfix.chain.addedBadge': 'Not in the file',
  'chainfix.chain.root': 'The chain ends at {root} ({owner}).',
  'chainfix.chain.trusted': 'Trusted for websites by {stores}.',
  'chainfix.chain.trustedVia': 'Trusted for websites by {groups}.',
  'chainfix.chain.group': '{stores} through {root}',
  'chainfix.chain.trustedNone': 'No root store trusts it for this certificate.',
  'chainfix.chain.unknownRoot': 'The list does not say which root the added intermediates lead to.'
});

registerStrings('tr', {
  'chainfix.found.title': { one: 'Eksik ara sertifika bulundu', other: '{count} eksik ara sertifika bulundu' },
  'chainfix.found.leafOnly': {
    one: 'Dosyada yalnızca sunucu sertifikası var. Onu veren ara sertifika CCADB’nin herkese açık ara sertifika listesinde bulunuyor; aşağıdaki fullchain.pem onu sunucu sertifikasının arkasına ekler.',
    other: 'Dosyada yalnızca sunucu sertifikası var. Gereken {count} ara sertifika CCADB’nin herkese açık ara sertifika listesinde bulunuyor; aşağıdaki fullchain.pem onları sunucu sertifikasının arkasına sırayla ekler.'
  },
  'chainfix.found.partial': {
    one: 'Dosya {name} sertifikasında bitiyor ve onu veren sertifika dosyada yok. O sertifika CCADB’nin herkese açık ara sertifika listesinde bulunuyor; aşağıdaki fullchain.pem onu ekler.',
    other: 'Dosya {name} sertifikasında bitiyor ve onu veren sertifika dosyada yok. Köke kadar gereken {count} sertifika CCADB’nin herkese açık ara sertifika listesinde bulunuyor; aşağıdaki fullchain.pem onları sırayla ekler.'
  },
  'chainfix.found.ct': {
    one: 'Certificate Transparency kayıtları yalnızca sunucu sertifikasını tutar. Onu veren ara sertifika CCADB’nin herkese açık ara sertifika listesinde bulunuyor; aşağıdaki fullchain.pem onu sunucu sertifikasının arkasına ekler.',
    other: 'Certificate Transparency kayıtları yalnızca sunucu sertifikasını tutar. Gereken {count} ara sertifika CCADB’nin herkese açık ara sertifika listesinde bulunuyor; aşağıdaki fullchain.pem onları sunucu sertifikasının arkasına sırayla ekler.'
  },
  'chainfix.found.untrustedTitle': 'Güncel bir köke ulaşılabiliyor',
  'chainfix.found.untrusted': {
    one: 'Dosyadaki zincir {root} kökünde bitiyor ve hiçbir kök deposu bu sertifika için ona güvenmiyor. CCADB listesindeki çapraz imzalı bir sertifika zinciri {next} köküne taşıyor; aşağıdaki fullchain.pem onu ekler.',
    other: 'Dosyadaki zincir {root} kökünde bitiyor ve hiçbir kök deposu bu sertifika için ona güvenmiyor. CCADB listesindeki {count} sertifika zinciri {next} köküne taşıyor; aşağıdaki fullchain.pem onları ekler.'
  },
  'chainfix.added': 'Eklenen',
  'chainfix.addedMeta': 'veren: {issuer} · CA sahibi: {owner} · geçerlilik sonu: {date}',
  'chainfix.source': 'Bu sitedeki CCADB listesi kopyasından ({date}). Sertifikanız hiçbir yere gönderilmedi.',
  'chainfix.download': 'fullchain.pem indir',
  'chainfix.downloadHint': {
    one: 'Sunucu sertifikası, ardından ara sertifikası. Kök sertifika yok, anahtar hiçbir zaman yok.',
    other: 'Sunucu sertifikası, ardından sırayla {count} ara sertifikası. Kök sertifika yok, anahtar hiçbir zaman yok.'
  },
  'chainfix.notFound': 'Bu sertifikayı veren ara sertifika ({issuer}) CCADB’nin herkese açık ara sertifika listesinde ({date}) yok: özel bir sertifika otoritesine ait olabilir ya da listenin bu kopyasından yenidir. Zinciri (CA bundle) sertifika otoritenizden alın.',
  'chainfix.failed': 'Ara sertifika listesi yüklenemedi (çevrimdışı olabilirsiniz); eksik ara sertifika aranmadı.',

  'chainfix.life.title': 'Kök deposu uyarıları',
  'chainfix.life.distrusted': '{stores}, {root} kökünün {date} tarihinden sonra verdiği sertifikalara güvenmiyor. Bu sertifika {issued} tarihinde verildi.',
  'chainfix.life.renewal-distrusted': '{stores}, {root} kökünün {date} tarihinden sonra verdiği sertifikalara güvenmiyor. Bu sertifika ({issued} tarihinde verildi) etkilenmiyor, ama yenilemesi başka bir sertifika otoritesinden alınmalı.',
  'chainfix.life.removed': '{root} artık {stores} kök deposunda değil: bu depoya dayanan istemciler zinciri reddeder.',
  'chainfix.life.not-for-tls': '{stores}, {root} kökünü web siteleri için değil yalnızca başka amaçlar için tutuyor: bu depoya dayanan istemciler zinciri reddeder.',
  'chainfix.life.cut-off': '{stores}, {root} kökünün sertifikalarına yalnızca bir kesim tarihinden önce verildiyse güveniyor.',
  'chainfix.life.not-included': '{root} hiçbir zaman {stores} kök deposunda olmadı.',
  'chainfix.life.root-expired': '{root} kökünün süresi {date} tarihinde doldu: istemciler artık bu zincire güvenmiyor.',
  'chainfix.life.root-expires': '{root} kökünün süresi {date} tarihinde, yani bu sertifikadan ({notAfter}) önce doluyor. O tarihten sonra kökün geçerliliğini denetleyen istemciler zinciri reddeder.',
  'chainfix.life.announcement': 'Duyuru',
  'chainfix.life.source': 'Kök deposu verisi: CCADB ve depoların duyuruları, {date} itibarıyla.',
  'chainfix.store.chrome': 'Chrome',
  'chainfix.store.mozilla': 'Mozilla (Firefox)',
  'chainfix.store.apple': 'Apple',
  'chainfix.store.microsoft': 'Microsoft',

  'chainfix.chain.added': 'CCADB listesinden eklenenler',
  'chainfix.chain.addedBadge': 'Dosyada yok',
  'chainfix.chain.root': 'Zincir {root} ({owner}) kökünde bitiyor.',
  'chainfix.chain.trusted': 'Web siteleri için güvenenler: {stores}.',
  'chainfix.chain.trustedVia': 'Web siteleri için güvenenler: {groups}.',
  'chainfix.chain.group': '{root} üzerinden {stores}',
  'chainfix.chain.trustedNone': 'Hiçbir kök deposu bu sertifika için ona güvenmiyor.',
  'chainfix.chain.unknownRoot': 'Liste, eklenen ara sertifikaların hangi köke vardığını söylemiyor.'
});

/** The site's copy of the list: one reader for the page, each file fetched once. */
let defaultStore = null;
const storeOf = () => (defaultStore ||= createIntermediateStore());
/** One job per loaded file (its parse result), for the page session. */
const jobs = new WeakMap();

/**
 * Is the file's leaf one whose chain the list can complete: a server certificate (not a CA, not
 * self-signed) that servers can send (not a precertificate)?
 * @param {{ result?: { leaf: object|null } }|null} load a CertLoad
 * @returns {boolean}
 */
export function repairApplies(load) {
  const leaf = load && load.result ? load.result.leaf : null;
  return !!leaf && !leaf.isCA && !leaf.selfSigned && !leaf.isPrecertificate;
}

/**
 * The repair job of a loaded file, started on first use: `{ status: 'running'|'done'|'error',
 * repair, error, watchers }`; each watcher runs once when it ends. A failed job is started again
 * by the next call (Retry).
 * @param {{ result: { certificates: object[], leaf: object|null } }} load a CertLoad
 * @param {{ store?: object, now?: number }} [opts] store: the dataset reader (tests)
 * @returns {{ status: string, repair: import('../lib/chainfix.js').ChainRepair|null, error: Error|null, watchers: Set<Function> }|null}
 *   null when {@link repairApplies} says no
 */
export function startChainRepair(load, { store = null, now = Date.now() } = {}) {
  if (!repairApplies(load)) return null;
  const prev = jobs.get(load.result);
  if (prev && prev.status !== 'error') return prev;
  const job = { status: 'running', repair: null, error: null, watchers: new Set() };
  jobs.set(load.result, job);
  repairChain(load.result, { store: store || storeOf(), now }).then((repair) => {
    Object.assign(job, { status: 'done', repair });
  }, (error) => {
    Object.assign(job, { status: 'error', error });
  }).then(() => {
    const watchers = [...job.watchers];
    job.watchers.clear();
    for (const w of watchers) w(job);
  });
  return job;
}

/**
 * The finished repair of a loaded file, or null (not started, running or failed).
 * @param {object|null} load a CertLoad
 * @returns {import('../lib/chainfix.js').ChainRepair|null}
 */
export function chainRepairOf(load) {
  const job = load && load.result ? jobs.get(load.result) : null;
  return job && job.status === 'done' ? job.repair : null;
}

/**
 * fullchain.pem with the added intermediates, when the list completed the file's chain; else null.
 * @param {object|null} load a CertLoad
 * @returns {object[]|null}
 */
export function repairedFullchain(load) {
  const repair = chainRepairOf(load);
  return repair && repair.status === 'repaired' ? repair.fullchain : null;
}

/** A dataset date ('YYYY-MM-DD') or Date for display, as the calendar day it names (UTC). */
const day = (value) => formatDate(value instanceof Date ? value : `${value}T12:00:00Z`, { utc: true });

/** "Chrome, Apple and Microsoft" in the UI language. */
export function storeList(stores) {
  const names = (stores || []).filter((s) => STORES.includes(s)).map((s) => t(`chainfix.store.${s}`));
  return new Intl.ListFormat(localeTag(), { type: 'conjunction' }).format(names);
}

/** A root's name for sentences: its name in the list (made unique by the build), else its DN. */
const rootName = (root) => (root ? root.name || root.dn || '—' : '—');

/**
 * The title and message of a repaired chain.
 * @param {import('../lib/chainfix.js').ChainRepair} repair status 'repaired'
 * @param {{ source?: string }} load the CertLoad (a Certificate Transparency load is worded as such)
 * @returns {{ title: string, message: string }}
 */
export function repairText(repair, load) {
  const count = repair.added.length;
  if (repair.reason === 'untrusted-root') {
    return {
      title: t('chainfix.found.untrustedTitle'),
      message: t('chainfix.found.untrusted', { count, root: rootName(repair.ownRoot), next: rootName(repair.root) })
    };
  }
  const key = load && load.source === 'ct' ? 'chainfix.found.ct' : repair.chain.length > 1 ? 'chainfix.found.partial' : 'chainfix.found.leafOnly';
  const top = repair.chain[repair.chain.length - 1];
  return { title: t('chainfix.found.title', { count }), message: t(key, { count, name: top.subjectCN || top.subjectDN }) };
}

/**
 * One root-store warning as a sentence.
 * @param {import('../lib/chainfix.js').LifecycleWarning} w
 * @param {{ notAfter: Date }} leaf
 * @returns {string}
 */
export function lifecycleText(w, leaf) {
  return t(`chainfix.life.${w.code}`, {
    stores: storeList(w.stores), root: rootName(w.root), date: w.date ? day(w.date) : '—',
    issued: w.issued ? day(w.issued) : '—', notAfter: day(leaf.notAfter)
  });
}

/**
 * The Chain tab's sentence on where the chain ends and who trusts it: the stores grouped by the
 * root they trust it through when that is not the root it ends at (a cross-signed root in it).
 * @param {import('../lib/chainfix.js').ChainRepair} repair
 * @returns {string|null} null when the chain reaches no known root
 */
export function trustText(repair) {
  const standing = repair && repair.standing;
  if (!standing) return null;
  const end = repair.root || repair.anchors[repair.anchors.length - 1];
  const head = t('chainfix.chain.root', { root: rootName(end), owner: end.owner || '—' });
  if (!standing.trusted.length) return `${head} ${t('chainfix.chain.trustedNone')}`;
  const groups = new Map();
  for (const s of standing.trusted) {
    const via = standing.stores[s].root;
    groups.set(via, [...(groups.get(via) || []), s]);
  }
  if (groups.size === 1 && groups.has(end)) return `${head} ${t('chainfix.chain.trusted', { stores: storeList(standing.trusted) })}`;
  const parts = [...groups].map(([root, stores]) => t('chainfix.chain.group', { stores: storeList(stores), root: rootName(root) }));
  return `${head} ${t('chainfix.chain.trustedVia', { groups: new Intl.ListFormat(localeTag(), { type: 'conjunction' }).format(parts) })}`;
}

/** The CCADB credit line: where the data comes from, with its date and a link. */
function sourceLine(key, date) {
  return h('p', { class: 'muted text-sm chainfix-source' }, t(key, { date: date ? day(date) : '—' }), ' ',
    ExternalLink(CCADB_URL, 'ccadb.org', { className: 'text-sm' }));
}

/** The added intermediates as a list: name, issuer, CA owner, expiry. */
function addedList(repair) {
  return h('ul', { class: 'chainfix-added' }, repair.added.map(({ cert, owner }) => h('li', null,
    h('span', { class: 'chainfix-added-name' }, `${t('chainfix.added')}: `, h('span', { class: 'mono' }, cert.subjectCN || cert.subjectDN)),
    h('span', { class: 'chainfix-added-meta muted text-sm' },
      t('chainfix.addedMeta', { issuer: cert.issuerCN || cert.issuerDN, owner: owner || '—', date: day(cert.notAfter) })))));
}

/**
 * The note of a finished repair (null when there is nothing to say: a complete chain, or an
 * unlisted issuer above an intermediate the file holds).
 */
function repairNote(repair, load, onDownload) {
  if (repair.status === 'repaired') {
    const { title, message } = repairText(repair, load);
    const intermediates = repair.fullchain.length - 1;
    const note = Alert({
      variant: repair.reason === 'untrusted-root' ? 'warn' : 'info',
      icon: 'git-branch',
      title,
      message,
      children: h('div', { class: 'stack-sm chainfix-body' }, addedList(repair), sourceLine('chainfix.source', repair.generated)),
      actions: [
        Button({
          label: t('chainfix.download'), icon: 'download', size: 'sm', dataset: { action: 'chainfix-fullchain' },
          onClick: () => onDownload(repair.fullchain)
        }),
        h('span', { class: 'muted text-sm chainfix-hint' }, t('chainfix.downloadHint', { count: intermediates }))
      ]
    });
    note.dataset.chainfixNote = 'repaired';
    return note;
  }
  if (repair.status === 'not-found' && repair.chain.length === 1) {
    const note = Alert({
      variant: 'info', compact: true, icon: 'search',
      message: t('chainfix.notFound', { issuer: repair.missing.issuerDN, date: repair.generated ? day(repair.generated) : '—' })
    });
    note.dataset.chainfixNote = 'not-found';
    return note;
  }
  return null;
}

/** The root-store warnings of a finished repair, worst first; null without any. */
function lifecycleNote(repair) {
  const standing = repair.standing;
  if (!standing || !standing.warnings.length) return null;
  const warnings = [...standing.warnings].sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'error' ? -1 : 1));
  const worst = warnings[0].severity;
  const note = Alert({
    variant: worst,
    icon: 'shield',
    title: t('chainfix.life.title'),
    children: h('div', { class: 'stack-sm' },
      h('ul', { class: 'chainfix-life' }, warnings.map((w) => h('li', { dataset: { lifeCode: w.code, severity: w.severity } },
        Icon(w.severity === 'error' ? 'x-circle' : 'alert', { size: 14, className: `chainfix-life-icon chainfix-life-${w.severity}` }),
        h('span', null, lifecycleText(w, repair.leaf), w.url ? ' ' : null,
          w.url ? ExternalLink(w.url, t('chainfix.life.announcement'), { className: 'text-sm' }) : null)))),
      sourceLine('chainfix.life.source', repair.generated))
  });
  note.dataset.lifecycle = worst;
  return note;
}

/**
 * The notes of a loaded file's chain: the repair (found, not found, the list not loaded) and, with
 * `lifecycle`, the root-store warnings. Returns its container at once and fills it when the job
 * ends (`data-chainfix` = running | done | error | none); a re-render reuses the finished job.
 * @param {object|null} load a CertLoad
 * @param {{ lifecycle?: boolean, onDownload: (certs: object[]) => void, store?: object, focus?: boolean }} opts
 *   onDownload: saves fullchain.pem (the view names the file); focus: take the keyboard focus once
 *   there is something to say (Retry: its button goes with the note it was in)
 * @returns {HTMLElement}
 */
export function ChainRepairNotes(load, { lifecycle = true, onDownload, store = null, focus = false }) {
  const el = h('div', { class: 'stack-sm chainfix', dataset: { chainfix: 'none' } });
  const job = startChainRepair(load, { store });
  if (!job) return el;
  let focusPending = focus;
  const show = () => {
    fill();
    // Focusable only once it has content: while empty it is not displayed.
    if (focusPending && el.isConnected && el.firstChild) {
      focusPending = false;
      el.setAttribute('tabindex', '-1');
      el.focus({ preventScroll: true });
    }
  };
  const fill = () => {
    clear(el);
    el.dataset.chainfix = job.status;
    if (job.status === 'error') {
      // Only a lone server certificate, which surely needs the list, says it could not be read.
      const { chain, rootCert } = fileChain(load.result.certificates, load.result.leaf);
      if (chain.length > 1 || rootCert) return;
      const note = Alert({
        variant: 'info', compact: true, icon: 'cloud-off', message: t('chainfix.failed'),
        actions: [Button({
          label: t('common.retry'), icon: 'refresh', size: 'sm', dataset: { action: 'chainfix-retry' },
          // The pressed button goes with the note: the keyboard focus moves to what replaces it.
          onClick: () => el.replaceWith(ChainRepairNotes(load, { lifecycle, onDownload, store, focus: true }))
        })]
      });
      note.dataset.chainfixNote = 'failed';
      el.append(note);
      return;
    }
    if (job.status !== 'done') return;
    const repair = repairNote(job.repair, load, onDownload);
    if (repair) el.append(repair);
    const life = lifecycle ? lifecycleNote(job.repair) : null;
    if (life) el.append(life);
  };
  if (job.status === 'running') job.watchers.add(show);
  fill();
  return el;
}

/**
 * The Chain tab's part: the intermediates the list added (under the file's chain, as the chain
 * continues) and where the chain ends, with the stores that trust it. Filled when the job ends.
 * @param {object|null} load a CertLoad
 * @param {{ store?: object }} [opts]
 * @returns {HTMLElement}
 */
export function ChainRepairChainPart(load, { store = null } = {}) {
  const el = h('div', { class: 'stack-sm chainfix-chain', dataset: { chainfix: 'none' } });
  const job = startChainRepair(load, { store });
  if (!job) return el;
  const fill = () => {
    clear(el);
    el.dataset.chainfix = job.status;
    if (job.status !== 'done') return;
    const repair = job.repair;
    if (repair.status === 'repaired') {
      el.append(h('h3', { class: 'chainfix-chain-title' }, t('chainfix.chain.added')),
        h('ol', { class: 'cert-chain chainfix-chain-list' }, repair.added.map(({ cert, owner }) => h('li', { class: 'cert-chain-item cert-chain-added', dataset: { role: 'added' } },
          h('div', { class: 'cert-chain-node', attrs: { 'aria-hidden': 'true' } }, Icon('git-branch', { size: 16 })),
          h('div', { class: 'cert-chain-body card' },
            h('div', { class: 'cert-chain-head' },
              Badge(t('chainfix.chain.addedBadge'), { variant: 'info', icon: 'download' }),
              h('span', { class: 'cert-chain-cn mono' }, cert.subjectCN || cert.subjectDN)),
            h('div', { class: 'cert-chain-meta text-sm' },
              h('span', null, t('chainfix.addedMeta', { issuer: cert.issuerCN || cert.issuerDN, owner: owner || '—', date: day(cert.notAfter) }))))))));
    }
    const trust = trustText(repair);
    if (trust) el.append(h('p', { class: 'text-sm chainfix-trust', dataset: { trusted: String(repair.standing.trusted.length) } }, trust));
    else if (repair.status === 'repaired') el.append(h('p', { class: 'muted text-sm chainfix-trust' }, t('chainfix.chain.unknownRoot')));
    if (repair.status === 'repaired' || trust) el.append(sourceLine('chainfix.life.source', repair.generated));
  };
  if (job.status === 'running') job.watchers.add(fill);
  fill();
  return el;
}
