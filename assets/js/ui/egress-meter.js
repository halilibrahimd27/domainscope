/**
 * ui/egress-meter.js — counts every request of this page for About › What this page sent
 * (lib/egresslog.js). Two witnesses: a wrapper around window.fetch, installed when the shell
 * boots (before the first view mounts), for each request the page's code starts, a redirect it
 * followed and a request that got no answer; and a buffered PerformanceObserver on Resource
 * Timing for every request the browser made for the page, the app's files loaded before the
 * boot included. The wrapper passes the same arguments to the browser's fetch and returns its
 * answer or error unchanged. The notes the sending code gives (lib/egresslog.js noteRequest: what
 * a POST body carried, a registry's RDAP server) are attached to the signatures here. Browser only.
 */

import { createEgressLog, onRequestNote } from '../lib/egresslog.js';

/** The page session's request log. */
export const egressLog = createEgressLog();

const installed = { fetch: false, resourceTiming: false };

/**
 * Start counting (once; a later call only says what is installed).
 * @param {typeof globalThis} [win]
 * @returns {{ fetch: boolean, resourceTiming: boolean }}
 */
export function startEgressMeter(win = globalThis) {
  if (installed.fetch || installed.resourceTiming) return { ...installed };
  const base = () => (win.location ? win.location.href : undefined);
  const record = (url, via, from = undefined) => egressLog.record(url, { via, base: base(), from });
  onRequestNote((url, note) => egressLog.note(url, note, { base: base() }));
  const original = win.fetch;
  if (typeof original === 'function') {
    win.fetch = function fetch(input, init) {
      const url = typeof input === 'string' ? input : input && typeof input.url === 'string' ? input.url : String(input);
      record(url, 'fetch');
      let pending;
      try {
        pending = original.call(win, input, init);
      } catch (err) {
        record(url, 'failed');
        throw err;
      }
      // A new promise with the same outcome: a rejection nobody handles is still reported as one.
      return Promise.resolve(pending).then((res) => {
        if (res && res.redirected && typeof res.url === 'string' && res.url) record(res.url, 'redirect', url);
        return res;
      }, (err) => {
        record(url, 'failed');
        throw err;
      });
    };
    installed.fetch = true;
  }
  const Observer = win.PerformanceObserver;
  if (typeof Observer === 'function' && (Observer.supportedEntryTypes || []).includes('resource')) {
    try {
      new Observer((list) => {
        for (const entry of list.getEntries()) record(entry.name, 'resource');
      }).observe({ type: 'resource', buffered: true });
      installed.resourceTiming = true;
    } catch {
      // no buffered observers in this engine: the fetch wrapper still counts
    }
  }
  return { ...installed };
}

/**
 * What counts in this page.
 * @returns {{ fetch: boolean, resourceTiming: boolean }}
 */
export function egressMeterStatus() {
  return { ...installed };
}
