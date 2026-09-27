/**
 * ui/start-tasks.js — the job cards of the first-visit task picker ("Find every subdomain",
 * "Where must this certificate go?", …), each a link to the tool that does the job. The shell
 * shows them above the start page until the visitor dismisses them or runs something (app.js);
 * About › Where to start lists them always. Jobs and tools: lib/shellnav.js START_TASKS.
 * Styles: .start-tasks / .start-task in assets/css/style.css.
 */

import { h } from './dom.js';
import { Icon } from './components.js';
import { t } from '../i18n.js';
import { startTasks } from '../lib/shellnav.js';

/**
 * The job cards as a list of links (`start.task.<id>` above the tool's name, with its nav icon).
 * @param {{ views: ReadonlyArray<{ id: string, icon?: string }>, href: (view: string) => string,
 *   onPick?: (task: { id: string, view: string }, event: MouseEvent) => void, className?: string }} opts
 *   `views`: the navigation registry (a job whose tool is missing is left out); `href`: route of a
 *   view; `onPick`: called on a click before the link is followed (it may preventDefault)
 * @returns {HTMLUListElement}
 */
export function StartTaskList({ views, href, onPick = null, className = '' }) {
  return h('ul', { class: ['start-tasks', className] }, startTasks(views).map((task) => h('li', { class: 'start-task-item' },
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
