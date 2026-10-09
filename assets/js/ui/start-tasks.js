/**
 * ui/start-tasks.js — the job cards ("Find every subdomain", "Where must this certificate go?", …),
 * each a link to the tool that does the job. Home's "Start a job" shows them for good: as cards
 * while `state.settings.startTasks` is on, as a compact list once they are folded or the visitor
 * ran something (app.js); About › Where to start lists them as cards. Jobs and tools:
 * lib/shellnav.js START_TASKS. Styles: .start-tasks / .start-task in assets/css/style.css, the
 * compact list in assets/css/views/home.css.
 */

import { h } from './dom.js';
import { Icon } from './components.js';
import { t } from '../i18n.js';
import { startTasks } from '../lib/shellnav.js';

/**
 * The job cards as a list of links (`start.task.<id>` above the tool's name, with its nav icon).
 * @param {{ views: ReadonlyArray<{ id: string, icon?: string }>, href: (view: string) => string,
 *   onPick?: (task: { id: string, view: string }, event: MouseEvent) => void, className?: string, compact?: boolean }} opts
 *   `views`: the navigation registry (a job whose tool is missing is left out); `href`: route of a
 *   view; `onPick`: called on a click before the link is followed (it may preventDefault);
 *   `compact`: the folded list (`.start-tasks-compact`: the job only, the tool's name still read out)
 * @returns {HTMLUListElement}
 */
export function StartTaskList({ views, href, onPick = null, className = '', compact = false }) {
  return h('ul', { class: ['start-tasks', { 'start-tasks-compact': compact }, className] }, startTasks(views).map((task) => h('li', { class: 'start-task-item' },
    h('a', {
      class: 'start-task',
      href: href(task.view),
      dataset: { task: task.id, view: task.view },
      on: onPick ? { click: (event) => onPick(task, event) } : null
    },
    h('span', { class: 'start-task-icon', attrs: { 'aria-hidden': 'true' } }, Icon(task.icon || 'help', { size: 18 })),
    h('span', { class: 'start-task-text' },
      h('span', { class: 'start-task-title' }, t(`start.task.${task.id}`)),
      h('span', { class: 'start-task-tool' }, t(`nav.${task.view}`))),
    Icon('arrow-right', { size: 16, className: 'start-task-arrow' })))));
}
