/**
 * view-summaries.js — "Copy summary" of every view but Subdomains and DMARC & TLS reports: loading
 * it loads lib/summary.js, which registers those views' builders, and registers their texts. The
 * views that show such a summary take their summary helpers from here, so the builders and texts
 * come with the first of them, never on the start route (which has lib/summarycore.js: the
 * rendering, the registry and the Subdomains builder, with ui/summary-button.js registering their
 * texts).
 */

import { registerStrings } from '../i18n.js';
import { SUMMARY_I18N } from '../lib/summary.js';

export { permalinkParams, healthScore, trafficLight } from '../lib/summary.js';

registerStrings('en', SUMMARY_I18N.en);
registerStrings('tr', SUMMARY_I18N.tr);
