/**
 * Known external console noise of live e2e runs. Robtex answers 403 without CORS headers to the
 * HeadlessChrome user agent, so Chrome logs a CORS error (names the URL) and a "Failed to load
 * resource" line (names no URL, only the matching Log entry does). The app handles it; the test
 * tolerates exactly that and nothing else.
 */
export const KNOWN_EXTERNAL_HOSTS = ['freeapi.robtex.com'];

const named = (text) => KNOWN_EXTERNAL_HOSTS.some((host) => String(text).includes(host));

/**
 * @param {Array<{ text?: string, url?: string }>} logErrors the page's Log-domain errors
 * @param {Array<{ text?: string, url?: string }>} consoleErrors the console.error messages
 * @returns {Array<object>} the console errors that are NOT known external noise
 */
export function unexpectedConsoleErrors(logErrors, consoleErrors) {
  // One URL-less "Failed to load resource" line is allowed per known-host log entry.
  let budget = logErrors.filter((e) => named(`${e.text || ''} ${e.url || ''}`)).length;
  return consoleErrors.filter((m) => {
    if (named(`${m.text || ''} ${m.url || ''}`)) return false;
    if (budget > 0 && /^Failed to load resource/.test(m.text || '') && !/https?:\/\//.test(m.text || '')) { budget -= 1; return false; }
    return true;
  });
}

export const isKnownExternal = named;
