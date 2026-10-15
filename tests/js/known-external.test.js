import { test } from 'node:test';
import assert from 'node:assert/strict';
import { unexpectedConsoleErrors } from '../e2e/known-external.mjs';

const robtex = { text: 'Failed to load resource: the server responded with a status of 403', url: 'https://freeapi.robtex.com/ipquery/203.0.113.10' };
const bare = { text: 'Failed to load resource: the server responded with a status of 403' };
const cors = { text: "Access to fetch at 'https://freeapi.robtex.com/ipquery/x' from origin 'http://127.0.0.1' has been blocked by CORS policy" };
const other = { text: "Access to fetch at 'https://example.com/x' has been blocked by CORS policy" };

test('known-external filter: only Robtex noise is tolerated', () => {
  assert.deepEqual(unexpectedConsoleErrors([robtex], [cors, bare]), []);
  assert.deepEqual(unexpectedConsoleErrors([], [bare]), [bare], 'no Robtex log entry, no tolerance');
  assert.deepEqual(unexpectedConsoleErrors([robtex], [other]), [other], 'another host CORS error stays');
  assert.deepEqual(unexpectedConsoleErrors([robtex], [bare, bare]), [bare], 'one URL-less line per Robtex log entry');
  assert.deepEqual(unexpectedConsoleErrors([robtex], [{ text: 'ERR_FAILED' }]), [{ text: 'ERR_FAILED' }]);
});
