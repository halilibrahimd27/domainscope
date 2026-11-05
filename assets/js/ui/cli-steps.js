/**
 * ui/cli-steps.js — "This part does not run in the browser": the section a tool shows for the
 * work only the companion CLI can do (ping and probe an internal network, connect to every
 * server with SNI…), drawn as a schema of steps, each saying where it runs — this browser, or a
 * machine on your network — so the page never pretends to do what a browser cannot.
 *
 * One card: a badge ("Command line"), the title and why the browser cannot do it, what the
 * browser does instead, then the steps in a row joined by arrows (a column on a phone): each a
 * number, an icon, where it runs, its title and text, an optional command (a code block with Copy)
 * and an optional action (a download link, a button that opens the file picker). `compact` folds
 * the card into one line ("Scanned on your network with ip_scan.py · Show the steps") once the
 * tool has what the steps produce; the steps stay one click away.
 *
 * Styled by assets/css/views/clisteps.css (listed in the views that use it). DOM-free at import.
 */

import { h } from './dom.js';
import { CodeBlock, Icon } from './components.js';
import { registerStrings, t } from '../i18n.js';

/** Where a step runs. */
export const STEP_PLACES = Object.freeze(['browser', 'machine']);

registerStrings('en', {
  'clisteps.badge': 'Command line',
  'clisteps.badgeTitle': 'This part runs on a computer of yours, with a small program from this site, not in the browser',
  'clisteps.place.browser': 'In this browser',
  'clisteps.place.machine': 'On a machine in your network',
  'clisteps.cannot': 'A browser cannot',
  'clisteps.can': 'This page then',
  'clisteps.stepsLabel': 'Steps',
  'clisteps.step': 'Step {n}',
  'clisteps.show': 'Show the steps'
});

registerStrings('tr', {
  'clisteps.badge': 'Komut satırı',
  'clisteps.badgeTitle': 'Bu kısım tarayıcıda değil, bu sitedeki küçük bir programla sizin bir bilgisayarınızda çalışır',
  'clisteps.place.browser': 'Bu tarayıcıda',
  'clisteps.place.machine': 'Ağınızdaki bir makinede',
  'clisteps.cannot': 'Tarayıcı şunları yapamaz',
  'clisteps.can': 'Bu sayfa sonra',
  'clisteps.stepsLabel': 'Adımlar',
  'clisteps.step': '{n}. adım',
  'clisteps.show': 'Adımları göster'
});

/**
 * @typedef {object} CliStep
 * @property {'browser'|'machine'} place where it runs
 * @property {string} icon an ICON_NAMES name
 * @property {string} title
 * @property {string} [text]
 * @property {string} [code] a command (a code block with Copy)
 * @property {string} [codeLabel]
 * @property {Node} [action] a link or a button
 */

/**
 * The section.
 * @param {{ title: string, why: string, cannot?: string[], can?: string[], steps: CliStep[], compact?: boolean,
 *   summary?: string, open?: boolean, onToggle?: (open: boolean) => void, footer?: Node|null, className?: string }} opts
 *   `summary`: the folded card's line (`compact`); `open`: the folded card starts unfolded; `onToggle`: it
 *   was folded or unfolded; `footer`: what follows the steps (more commands)
 * @returns {HTMLElement}
 */
export function CliSteps({ title, why, cannot = [], can = [], steps = [], compact = false, summary = '', open = false, onToggle = null, footer = null, className = '' }) {
  const titleId = `cli-steps-${Math.random().toString(36).slice(2, 9)}`;
  const badge = h('span', { class: 'cli-steps-badge', title: t('clisteps.badgeTitle') }, Icon('terminal', { size: 14 }), t('clisteps.badge'));
  const facts = cannot.length || can.length ? h('div', { class: 'cli-steps-facts' },
    cannot.length ? h('div', { class: 'cli-steps-fact is-cannot' },
      h('span', { class: 'cli-steps-fact-title' }, t('clisteps.cannot')),
      h('ul', null, cannot.map((x) => h('li', null, Icon('x', { size: 14 }), h('span', null, x))))) : null,
    can.length ? h('div', { class: 'cli-steps-fact is-can' },
      h('span', { class: 'cli-steps-fact-title' }, t('clisteps.can')),
      h('ul', null, can.map((x) => h('li', null, Icon('check', { size: 14 }), h('span', null, x))))) : null) : null;
  const list = h('ol', { class: 'cli-steps-list', attrs: { 'aria-label': t('clisteps.stepsLabel') } },
    steps.map((step, i) => h('li', { class: ['cli-step', `is-${STEP_PLACES.includes(step.place) ? step.place : 'browser'}`], dataset: { step: String(i + 1), place: step.place } },
      h('div', { class: 'cli-step-head' },
        h('span', { class: 'cli-step-number', attrs: { 'aria-hidden': 'true' } }, String(i + 1)),
        h('span', { class: 'cli-step-icon', attrs: { 'aria-hidden': 'true' } }, Icon(step.icon || 'chevron-right', { size: 18 })),
        h('span', { class: 'cli-step-place' }, Icon(step.place === 'machine' ? 'server' : 'globe', { size: 12 }), t(`clisteps.place.${step.place === 'machine' ? 'machine' : 'browser'}`))),
      h('h3', { class: 'cli-step-title' }, h('span', { class: 'sr-only' }, `${t('clisteps.step', { n: i + 1 })}: `), step.title),
      step.text ? h('p', { class: 'cli-step-text' }, step.text) : null,
      step.code ? CodeBlock(step.code, { label: step.codeLabel || 'CLI', wrap: true, className: 'cli-step-code' }) : null,
      step.action ? h('div', { class: 'cli-step-action' }, step.action) : null)));
  const body = [h('p', { class: 'cli-steps-why' }, why), facts, list, footer ? h('div', { class: 'cli-steps-footer' }, footer) : null];
  if (compact) {
    return h('section', { class: ['card', 'cli-steps', 'is-compact', className], attrs: { 'aria-labelledby': titleId } },
      h('details', { class: 'cli-steps-fold', open: !!open, on: { toggle: (e) => { if (onToggle) onToggle(e.currentTarget.open); } } },
        h('summary', { class: 'cli-steps-summary' }, badge, h('span', { class: 'cli-steps-summary-text', id: titleId }, summary || title),
          h('span', { class: 'cli-steps-show' }, t('clisteps.show'), Icon('chevron-down', { size: 14 }))),
        h('div', { class: 'cli-steps-body' }, h('h2', { class: 'cli-steps-title' }, title), body)));
  }
  return h('section', { class: ['card', 'cli-steps', className], attrs: { 'aria-labelledby': titleId } },
    h('div', { class: 'cli-steps-head' }, badge, h('h2', { class: 'cli-steps-title', id: titleId }, title)),
    h('div', { class: 'cli-steps-body' }, body));
}
