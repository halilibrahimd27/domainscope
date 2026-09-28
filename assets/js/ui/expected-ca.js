/**
 * ui/expected-ca.js — the "expected CA" / "unexpected CA" badge next to an issuer, against the
 * active workspace's expected CAs (lib/expectedca.js; state.js `workspaceData('expectedCas')`,
 * edited in the Workspaces dialog). Without an expectation there is no badge. Used where an issuer
 * is shown: the Certificate view (its overview and the summary SSL Targets shows too), SSL Targets
 * › Verify (the certificate each server serves) and the CAA checks (Certificate › CAA, Domain
 * Health's CAA card).
 *
 * Every string is rendered through h() / text nodes.
 */

import { Badge } from './components.js';
import { t, registerStrings } from '../i18n.js';
import { expectedCaStatus, expectedCaaStatus } from '../lib/expectedca.js';
import { state } from '../state.js';

registerStrings('en', {
  'eca.expected': 'Expected CA',
  'eca.unexpected': 'Unexpected CA',
  'eca.expectedTitle': 'Issued by a CA this workspace expects ({entry}).',
  'eca.unexpectedTitle': 'Not one of this workspace’s expected CAs ({list}). Change them under Workspaces › Expected CAs.',
  'eca.caaExpectedTitle': 'A CA this workspace expects ({entry}).',
  'eca.caaUnexpectedTitle': 'This CAA value allows a CA that is not one of this workspace’s expected CAs ({list}).'
});

registerStrings('tr', {
  'eca.expected': 'Beklenen CA',
  'eca.unexpected': 'Beklenmeyen CA',
  'eca.expectedTitle': 'Bu çalışma alanının beklediği bir CA tarafından verilmiş ({entry}).',
  'eca.unexpectedTitle': 'Bu çalışma alanının beklenen CA’larından biri değil ({list}). Çalışma alanları › Beklenen CA’lar bölümünden değiştirin.',
  'eca.caaExpectedTitle': 'Bu çalışma alanının beklediği bir CA ({entry}).',
  'eca.caaUnexpectedTitle': 'Bu CAA değeri, bu çalışma alanının beklenen CA’larından biri olmayan bir CA’ya izin veriyor ({list}).'
});

/** The badge of a status (null: no expectation, no badge). */
function badgeOf(status, expected, { caa }) {
  if (!status) return null;
  const list = expected.join(', ');
  const el = status.expected
    ? Badge(t('eca.expected'), { variant: 'ok', icon: 'check-circle', title: t(caa ? 'eca.caaExpectedTitle' : 'eca.expectedTitle', { entry: status.entry }) })
    : Badge(t('eca.unexpected'), { variant: 'warn', icon: 'alert', title: t(caa ? 'eca.caaUnexpectedTitle' : 'eca.unexpectedTitle', { list }) });
  el.classList.add('eca-badge');
  el.dataset.expectedCa = status.expected ? 'expected' : 'unexpected';
  return el;
}

/**
 * The badge of a certificate issuer.
 * @param {string|object} issuer the issuer DN or a parsed issuer name ({ CN, O, … })
 * @param {{ expected?: string[], onlyUnexpected?: boolean }} [opts] the expected CAs (default: the
 *   active workspace's); `onlyUnexpected`: a dense table flags the exceptions only
 * @returns {HTMLElement|null}
 */
export function ExpectedCaBadge(issuer, { expected = state.workspaceData('expectedCas'), onlyUnexpected = false } = {}) {
  const status = expectedCaStatus(issuer, expected);
  if (onlyUnexpected && status && status.expected) return null;
  return badgeOf(status, expected, { caa: false });
}

/**
 * The badge of a CAA issuer domain (an `issue` / `issuewild` value's CA, "letsencrypt.org").
 * @param {string} domain
 * @param {{ expected?: string[] }} [opts]
 * @returns {HTMLElement|null}
 */
export function ExpectedCaaBadge(domain, { expected = state.workspaceData('expectedCas') } = {}) {
  return badgeOf(expectedCaaStatus(domain, expected), expected, { caa: true });
}

/**
 * Does a state change touch the expected CAs (a view redraws its badges then)? Another
 * workspace, "Delete all local data", or an edit of the list.
 * @param {{ key: string, value?: any }} change
 * @returns {boolean}
 */
export function expectedCasChanged({ key, value }) {
  if (key === 'workspace' || key === 'cleared') return true;
  return key === 'workspaceData' && !!value && Array.isArray(value.parts) && value.parts.includes('expectedCas');
}
