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
import { exportFileName, passwordProblem, PASSWORD_PROBLEMS } from '../../assets/js/ui/workspace-panel.js';
import { registerRunning, runningWork } from '../../assets/js/ui/jobs.js';
import { WorkspaceError } from '../../assets/js/lib/workspace.js';
import '../../assets/js/views/ptr.js';
import '../../assets/js/ui/verify-panel.js';

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
      assert.equal(t('ws.clearFailed', { reason: storageErrorText(domError('QuotaExceededError')) }),
        'Yerel verilerin tümü silinemedi: tarayıcının bu site için ayırdığı depolama dolu.');
    } finally {
      setLang('en');
    }
  });
});

describe('the shell', () => {
  test('the Tools menu heading of Servers and About is not "Workspace" in either language', () => {
    for (const lang of LANGS) {
      setLang(lang);
      assert.notEqual(t('nav.groupData').toLocaleLowerCase(lang), t('ws.label').toLocaleLowerCase(lang), lang);
    }
    setLang('en');
    assert.equal(t('nav.groupData'), 'Setup & info');
  });

  test('a switch names what it would stop: the long jobs and the registered work, each once', () => {
    assert.deepEqual(runningWork(), [], 'nothing runs (a Reverse DNS sweep and a Verify batch are registered, idle)');
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
    for (const lang of LANGS) assert.ok(hasString('vfy.switchRunning', lang) && hasString('nav.ptr', lang), lang);
  });
});
