/**
 * The workspace UI's pure parts (ui/workspace-ui.js, ui/workspace-panel.js, ui/jobs.js): the
 * hand-over file's name (an encrypted file never names its workspace), the export password
 * checks, Default's names in both languages, storage errors in words in both languages, the
 * Tools menu heading that must not read "Workspace", and the work a switch would stop.
 * No DOM, no storage, no network.
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';

import { t, setLang, hasString, LANGS } from '../../assets/js/i18n.js';
import {
  workspaceLabel, defaultWorkspaceNames, isDefaultWorkspaceName, storageReason, storageErrorText, STORAGE_REASONS
} from '../../assets/js/ui/workspace-ui.js';
import { exportFileName, passwordProblem, importSummary, PASSWORD_PROBLEMS } from '../../assets/js/ui/workspace-panel.js';
import { registerRunning, runningWork, jobList, onJobs, startJob } from '../../assets/js/ui/jobs.js';
import { WorkspaceError, emptyWorkspaceData } from '../../assets/js/lib/workspace.js';
import '../../assets/js/views/zone.js';
import '../../assets/js/views/ptr.js';
import '../../assets/js/ui/verify-panel.js';
import '../../assets/js/ui/parity-panel.js';
import '../../assets/js/ui/origin-compare.js';
import '../../assets/js/views/reports.js';
import '../../assets/js/views/change.js';

after(() => setLang('en'));

/** An error shaped like the browser's DOMException. */
const domError = (name, message = '') => Object.assign(new Error(message), { name });

describe('the hand-over file name', () => {
  const at = new Date(2026, 8, 28, 10, 30);

  test('a plain file carries the workspace name; an encrypted one never does', () => {
    assert.equal(exportFileName('Acme', { date: at }), 'domainscope-workspace-Acme-20260928-1030.json');
    const sealed = exportFileName('Acme', { encrypted: true, date: at });
    assert.equal(sealed, 'domainscope-workspace-encrypted-20260928-1030.json');
    assert.ok(!sealed.includes('Acme'));
    assert.equal(exportFileName('Müşteri A.Ş. — İstanbul', { encrypted: true, date: at }), sealed, 'whatever the name');
  });
});

describe('the export password', () => {
  test('empty is allowed (no encryption); short, spaces only or a different repetition are refused', () => {
    assert.equal(passwordProblem('', ''), null);
    assert.equal(passwordProblem('correct horse', 'correct horse'), null);
    assert.equal(passwordProblem('short', 'short'), 'password-short');
    assert.equal(passwordProblem(' '.repeat(12), ' '.repeat(12)), 'password-blank');
    assert.equal(passwordProblem('\t   \n    ', '\t   \n    '), 'password-blank');
    assert.equal(passwordProblem('correct horse', 'correct horsE'), 'mismatch');
    assert.equal(passwordProblem('', 'typed only here'), 'mismatch');
    assert.equal(passwordProblem('çğıöşü12', 'çğıöşü12'), null, 'counted in characters');
  });

  test('every problem has its words in both languages', () => {
    for (const code of PASSWORD_PROBLEMS) {
      for (const lang of LANGS) assert.ok(hasString(`ws.err.${code}`, lang), `${lang}: ${code}`);
    }
  });
});

describe('Default\'s names', () => {
  test('one per language, the way each language shows it', () => {
    const names = defaultWorkspaceNames();
    assert.equal(names.length, LANGS.length);
    for (const lang of LANGS) {
      setLang(lang);
      assert.ok(names.includes(t('ws.default')), lang);
      assert.equal(workspaceLabel({ id: 'default', name: null, isDefault: true }), t('ws.default'));
    }
    setLang('en');
  });

  test('neither language\'s name is free for another workspace, in any case or spacing', () => {
    for (const name of ['Default', 'default', '  DEFAULT ', 'Varsayılan', 'varsayılan', 'VARSAYILAN', ' Varsayılan​']) {
      assert.equal(isDefaultWorkspaceName(name), true, name);
    }
    for (const name of ['Defaults', 'Default Acme', 'Acme', '', '   ', null]) {
      assert.equal(isDefaultWorkspaceName(name), false, String(name));
    }
  });
});

describe('storage errors in words', () => {
  test('the browser\'s and the backend\'s errors map to a reason', () => {
    assert.equal(storageReason(domError('QuotaExceededError')), 'quota');
    assert.equal(storageReason(domError('SecurityError')), 'denied');
    assert.equal(storageReason(Object.assign(new Error('IndexedDB deletion is blocked by another tab'), { code: 'idb-blocked' })), 'idb-blocked');
    assert.equal(storageReason(Object.assign(new Error('IndexedDB did not open in time'), { code: 'idb-timeout' })), 'idb-timeout');
    assert.equal(storageReason(new WorkspaceError('not-found', 'the workspace was deleted in another tab')), 'not-found');
    assert.equal(storageReason(new TypeError('odd')), 'other');
    assert.equal(storageReason(null), 'unknown');
    for (const reason of STORAGE_REASONS) {
      for (const lang of LANGS) assert.ok(hasString(`ws.why.${reason}`, lang), `${lang}: ${reason}`);
    }
  });

  test('a known reason reads in the page language, never as the browser\'s English message', () => {
    setLang('tr');
    try {
      const quota = storageErrorText(domError('QuotaExceededError', 'The quota has been exceeded.'));
      assert.equal(quota, t('ws.why.quota'));
      assert.ok(!/quota|exceeded/i.test(quota), quota);
      const blocked = storageErrorText(Object.assign(new Error('IndexedDB deletion is blocked by another tab'), { code: 'idb-blocked' }));
      assert.ok(/sekme/.test(blocked) && !/blocked/.test(blocked), blocked);
      // Anything else keeps its own text, quoted inside a Turkish sentence.
      assert.equal(storageErrorText(new TypeError('odd failure')), 'tarayıcı “odd failure” bildirdi');
      assert.equal(storageErrorText(null), t('ws.why.unknown'));
      // A message ending with a period does not end the sentence twice.
      setLang('en');
      assert.equal(t('ws.clearFailed', { reason: storageErrorText(domError('UnknownError', 'The user denied permission to access the database.')) }),
        'Not all local data could be deleted: the browser reported “The user denied permission to access the database”.');
      setLang('tr');
      assert.equal(t('ws.clearFailed', { reason: storageErrorText(domError('QuotaExceededError')) }),
        'Yerel verilerin tümü silinemedi: tarayıcının bu site için ayırdığı depolama dolu.');
    } finally {
      setLang('en');
    }
  });
});

describe('the origin map in words', () => {
  test('an imported hand-over file says when it switches remembering origins on', () => {
    const ws = (origins) => ({ encrypted: false, data: { ...emptyWorkspaceData(), origins } });
    setLang('en');
    assert.match(importSummary(ws({ v: 1, remember: true, entries: [] })), /remembering origins is on$/);
    assert.doesNotMatch(importSummary(ws({ v: 1, remember: false, entries: [{ name: 'www.example.com', ip: '192.0.2.10', port: 443 }] })), /remembering/);
    assert.match(importSummary(ws({ v: 1, remember: false, entries: [{ name: 'www.example.com', ip: '192.0.2.10', port: 443 }] })), /1 remembered origin$/);
    setLang('tr');
    assert.match(importSummary(ws({ v: 1, remember: true, entries: [] })), /origin’leri hatırlama açık$/);
    setLang('en');
  });

  test('an imported hand-over file says it holds a DMARC report history, and when it switches keeping summaries on', () => {
    const text = (keep) => JSON.stringify({ v: 1, keep, updatedAt: null, domains: { 'example.com': { days: { '2026-09-27': { msgs: 1 } }, sources: {}, recent: {}, policy: null, seen: {}, cut: null, checked: null } } });
    const ws = (reportHistory) => ({ encrypted: false, data: { ...emptyWorkspaceData(), reportHistory } });
    setLang('en');
    assert.match(importSummary(ws(text(true))), /a DMARC report history of 1 domain · keeping DMARC report summaries is on$/);
    assert.match(importSummary(ws(text(false))), /a DMARC report history of 1 domain$/);
    assert.doesNotMatch(importSummary(ws('')), /DMARC/);
    assert.doesNotMatch(importSummary(ws('{"v":9}')), /DMARC/, 'a text that is no history says nothing');
    setLang('tr');
    assert.match(importSummary(ws(text(true))), /1 alan adının DMARC rapor geçmişi · DMARC rapor özetlerini tutma açık$/);
    setLang('en');
  });

  test('Turkish: a server that no longer serves the name, and one origin to remember', () => {
    setLang('tr');
    for (const key of ['om.stale.cli-not-hosted', 'om.stale.verify-not-hosted']) {
      assert.match(t(key, { date: '1 Eki 2026' }), /bu adın artık bu sunucuda sunulmadığını gördü$/, key);
    }
    assert.equal(t('zone.remember', { count: 1 }), 'Bu origin’i hatırla');
    assert.equal(t('zone.remember', { count: 2 }), 'Bu 2 origin’i hatırla');
    setLang('en');
    assert.equal(t('zone.remember', { count: 1 }), 'Remember this origin');
  });
});

describe('the shell', () => {
  test('the Tools menu heading of Servers and About is not "Workspace" in either language', () => {
    for (const lang of LANGS) {
      setLang(lang);
      assert.notEqual(t('nav.groupSetup').toLocaleLowerCase(lang), t('ws.label').toLocaleLowerCase(lang), lang);
    }
    setLang('en');
    assert.equal(t('nav.groupSetup'), 'Setup & help');
  });

  test('a switch names what it would stop: the long jobs and the registered work, each once', () => {
    assert.deepEqual(runningWork(), [], 'nothing runs (a Reverse DNS sweep, a Verify batch, the two Globalping comparisons, a DMARC report read and a change check are registered, idle)');
    let busy = true;
    registerRunning('nav.ptr.test', () => busy);
    registerRunning('nav.broken.test', () => {
      throw new Error('its module is gone');
    });
    try {
      assert.deepEqual(runningWork(), ['nav.ptr.test']);
      busy = false;
      assert.deepEqual(runningWork(), []);
    } finally {
      registerRunning('nav.ptr.test', () => false);
      registerRunning('nav.broken.test', () => false);
    }
    for (const lang of LANGS) {
      for (const key of ['vfy.switchRunning', 'nav.ptr', 'par.switchRunning', 'oc.switchRunning', 'rpt.switchRunning', 'chg.switchRunning']) assert.ok(hasString(key, lang), `${key} ${lang}`);
    }
  });

  test('jobList names the running jobs for Home, with their subject and progress; onJobs follows them', () => {
    assert.deepEqual(jobList(), []);
    let calls = 0;
    const stop = onJobs(() => { calls += 1; });
    const sub = startJob({ view: 'subdomains', subject: '  example.com, example.org ' });
    const bulk = startJob({ view: 'bulk' });
    const scan = startJob({ view: 'scan', subject: 'x'.repeat(300) });
    try {
      assert.equal(sub.subject, 'example.com, example.org');
      assert.equal(scan.subject.length, 200, 'a long subject is cut');
      assert.deepEqual(jobList().map((j) => [j.view, j.subject, j.fraction]),
        [['subdomains', 'example.com, example.org', null], ['bulk', null, null], ['scan', 'x'.repeat(200), null]]);
      assert.ok(jobList()[0].startedAt instanceof Date);
      sub.update(0.4);
      assert.equal(jobList()[0].fraction, 0.4);
      assert.deepEqual(runningWork(), ['nav.subdomains', 'nav.bulk', 'nav.scan']);
      bulk.finish({ status: 'cancelled' });
      assert.deepEqual(jobList().map((j) => j.view), ['subdomains', 'scan']);
      assert.ok(calls >= 1, 'a finish renders at once and tells Home');
      stop();
      const before = calls;
      sub.finish({ status: 'done' });
      assert.equal(calls, before, 'a stopped listener hears nothing more');
    } finally {
      for (const job of [sub, bulk, scan]) job.finish({ status: 'cancelled' });
    }
    assert.deepEqual(jobList(), []);
  });
});
