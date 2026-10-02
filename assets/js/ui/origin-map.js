/**
 * ui/origin-map.js — what the tools that fill or read the workspace's origin map share
 * (lib/originmap.js): the words for a source and a stale entry, the note shown while remembering
 * is off, and {@link recordOrigins}, which applies one run's observations (lib/originfill.js) to
 * the active workspace and says what changed.
 *
 * Used by Zone File (Remember these origins), SSL Targets (Behind CDN, Verify), Retire an IP (the
 * old and the new server) and the Servers view's Origin map tab (ui/origin-map-panel.js). The map
 * never leaves the browser except inside a workspace hand-over file the user exports. Every
 * string is rendered through h() / text nodes.
 */

import { h } from './dom.js';
import { Alert, Badge, toast } from './components.js';
import { t, registerStrings, formatDate, formatNumber } from '../i18n.js';
import { state } from '../state.js';
import { lookupServers } from '../lib/inventory.js';
import { originTarget, ORIGIN_SOURCES, STALE_REASONS } from '../lib/originmap.js';
import { applyObservations } from '../lib/originfill.js';

registerStrings('en', {
  'om.title': 'Origin map',
  'om.source.cli-json': 'CLI report',
  'om.source.zone': 'Zone file',
  'om.source.verify': 'Verify',
  'om.source.compare': 'Old and new server',
  'om.source.manual': 'Added by hand',
  'om.stale': 'Stale',
  'om.stale.cli-elsewhere': 'the CLI found this name on another server ({target}) on {date}',
  'om.stale.cli-not-hosted': 'the CLI found that this server no longer serves the name on {date}',
  'om.stale.verify-elsewhere': 'Verify found this name on another server ({target}) on {date}',
  'om.stale.verify-not-hosted': 'Verify found that this server no longer serves the name on {date}',
  'om.stale.zone-other': 'a zone file named another origin ({target}) on {date}',
  'om.known': 'Remembered',
  'om.known.title': 'This workspace’s origin map remembers this address as the real server behind the name',
  'om.off': 'Remembering origins is off in this workspace, so nothing is written to its origin map.',
  'om.offLink': 'Turn it on in Servers › Origin map',
  'om.open': 'Open the origin map',
  'om.result': 'Origin map: {added} added, {confirmed} confirmed, {staled} marked stale.',
  'om.skipped': {
    one: 'Not remembered: {list} (not known to be behind a CDN).',
    other: 'Not remembered: {count} names not known to be behind a CDN ({list}).'
  },
  'om.notSaved': 'The origin map could not be saved in this browser: it lasts until you close this tab.'
});

registerStrings('tr', {
  'om.title': 'Origin haritası',
  'om.source.cli-json': 'CLI raporu',
  'om.source.zone': 'Zone dosyası',
  'om.source.verify': 'Doğrula',
  'om.source.compare': 'Eski ve yeni sunucu',
  'om.source.manual': 'Elle eklendi',
  'om.stale': 'Eskimiş',
  'om.stale.cli-elsewhere': 'CLI bu adı {date} tarihinde başka bir sunucuda ({target}) buldu',
  'om.stale.cli-not-hosted': 'CLI {date} tarihinde bu adın artık bu sunucuda sunulmadığını gördü',
  'om.stale.verify-elsewhere': 'Doğrula sekmesi bu adı {date} tarihinde başka bir sunucuda ({target}) buldu',
  'om.stale.verify-not-hosted': 'Doğrula sekmesi {date} tarihinde bu adın artık bu sunucuda sunulmadığını gördü',
  'om.stale.zone-other': 'bir zone dosyası {date} tarihinde başka bir origin gösterdi ({target})',
  'om.known': 'Hatırlanan',
  'om.known.title': 'Bu çalışma alanının origin haritası bu adresi adın arkasındaki gerçek sunucu olarak hatırlıyor',
  'om.off': 'Bu çalışma alanında origin’leri hatırlama kapalı; origin haritasına hiçbir şey yazılmıyor.',
  'om.offLink': 'Sunucular › Origin haritası’ndan açın',
  'om.open': 'Origin haritasını aç',
  'om.result': 'Origin haritası: {added} eklendi, {confirmed} doğrulandı, {staled} eskimiş olarak işaretlendi.',
  'om.skipped': {
    other: 'Hatırlanmadı: CDN arkasında olduğu bilinmeyen {count} ad ({list}).'
  },
  'om.notSaved': 'Origin haritası bu tarayıcıya kaydedilemedi: bu sekme kapanana kadar geçerli.'
});

/** The keys this module builds from library codes (tests/js/i18n-coverage.test.js). */
export function generatedKeys() {
  return [...ORIGIN_SOURCES.map((s) => `om.source.${s}`), ...STALE_REASONS.map((r) => `om.stale.${r}`)];
}

/** The active workspace's origin map (a copy), or null. */
export function originMap() {
  return state.workspaceData('origins');
}

/** Is remembering on in the active workspace? */
export function rememberOn() {
  const map = originMap();
  return !!(map && map.remember);
}

/** The inventory server of an address, by name (or null). */
export function serverOf(ip) {
  const hit = lookupServers([ip], state.getInventoryIndex())[0];
  return hit ? String(hit.server.name ?? '') || null : null;
}

/**
 * Why an entry is stale, in words ("the CLI found this name on another server (203.0.113.20) on …").
 * @param {{ stale: { reason: string, at: string, ip?: string, port?: number }|null }} entry
 * @returns {string}
 */
export function staleText(entry) {
  const s = entry && entry.stale;
  if (!s) return '';
  const target = s.ip ? originTarget({ ip: s.ip, port: s.port || 443 }) : '';
  return t(`om.stale.${s.reason}`, { target, date: formatDate(s.at) });
}

/** "Stale" with the reason as its tooltip. */
export function StaleBadge(entry) {
  return Badge(t('om.stale'), { variant: 'warn', icon: 'clock', title: staleText(entry), className: 'om-stale' });
}

/**
 * The note shown where a tool would remember origins while remembering is off: why nothing is
 * written, with a link to the switch.
 * @param {{ href: (view: string, params?: object) => string }} ctx
 * @returns {HTMLElement}
 */
export function OriginMapOffNote(ctx) {
  return Alert({
    variant: 'info', compact: true, icon: 'map-pin',
    message: h('span', { dataset: { role: 'om-off' } }, t('om.off'), ' ',
      h('a', { class: 'link', href: ctx.href('inventory', { tab: 'origins' }) }, t('om.offLink')))
  });
}

/**
 * Apply one run's observations to the active workspace's origin map and save it (nothing when
 * remembering is off). `proxied` decides which names may be added (lib/originmap.js).
 * @param {object[]} observations lib/originfill.js
 * @param {{ source: string, at: Date|string, proxied?: ((name: string) => boolean)|null }} opts
 * @returns {ReturnType<typeof applyObservations> & { done: Promise<boolean> }}
 */
export function recordOrigins(observations, { source, at, proxied = null }) {
  const res = applyObservations(originMap(), observations, { source, at, proxied, serverOf });
  const changed = res.added.length || res.confirmed.length || res.staled.length;
  const done = !res.off && changed ? state.setWorkspaceData('origins', res.map) : Promise.resolve(true);
  done.then((ok) => {
    if (!ok) toast(t('om.notSaved'), { type: 'warn', timeout: 8000 });
  });
  return { ...res, done };
}

/**
 * What {@link recordOrigins} did, in one or two sentences.
 * @param {{ added: string[], confirmed: string[], staled: string[], skipped?: string[] }} res
 * @returns {string}
 */
export function recordText(res) {
  const line = t('om.result', {
    added: formatNumber(res.added.length), confirmed: formatNumber(res.confirmed.length), staled: formatNumber(res.staled.length)
  });
  const skipped = res.skipped || [];
  if (!skipped.length) return line;
  const list = skipped.slice(0, 5).join(', ') + (skipped.length > 5 ? ', …' : '');
  return `${line} ${t('om.skipped', { count: skipped.length, list })}`;
}
