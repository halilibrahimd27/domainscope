import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WORDLIST_SMALL, WORDLIST_MEDIUM, getWordlist } from '../../assets/js/lib/wordlist.js';

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

test('SMALL is non-trivial and all valid lowercase labels', () => {
  assert.ok(WORDLIST_SMALL.length >= 120, `small=${WORDLIST_SMALL.length}`);
  for (const w of WORDLIST_SMALL) assert.match(w, LABEL_RE, w);
});

test('MEDIUM is ~1000 and all valid lowercase labels', () => {
  assert.ok(WORDLIST_MEDIUM.length >= 800, `medium=${WORDLIST_MEDIUM.length}`);
  for (const w of WORDLIST_MEDIUM) assert.match(w, LABEL_RE, w);
});

test('both lists are unique', () => {
  assert.equal(new Set(WORDLIST_SMALL).size, WORDLIST_SMALL.length);
  assert.equal(new Set(WORDLIST_MEDIUM).size, WORDLIST_MEDIUM.length);
});

test('SMALL is a strict subset of MEDIUM (and appears first, in order)', () => {
  const medium = new Set(WORDLIST_MEDIUM);
  for (const w of WORDLIST_SMALL) assert.ok(medium.has(w), `missing from medium: ${w}`);
  assert.ok(WORDLIST_MEDIUM.length > WORDLIST_SMALL.length);
  WORDLIST_SMALL.forEach((w, i) => assert.equal(WORDLIST_MEDIUM[i], w));
});

test('includes core infra labels', () => {
  const medium = new Set(WORDLIST_MEDIUM);
  for (const w of ['mail', 'webmail', 'smtp', 'mx', 'autodiscover', 'vpn', 'remote', 'owa', 'cpanel',
    'whm', 'plesk', 'ns1', 'ns2', 'ftp', 'sftp', 'git', 'gitlab', 'jenkins', 'grafana', 'kibana',
    'prometheus', 'argocd', 'rancher', 'k8s', 'registry', 'harbor', 'sonar', 'nexus', 'vault', 'sso',
    'auth', 'keycloak', 'ldap']) {
    assert.ok(medium.has(w), `missing infra label: ${w}`);
  }
});

test('includes environment, app and numbered labels', () => {
  const medium = new Set(WORDLIST_MEDIUM);
  for (const w of ['dev', 'test', 'stage', 'staging', 'uat', 'preprod', 'prod', 'beta', 'demo',
    'sandbox', 'qa', 'api', 'app', 'm', 'mobile', 'admin', 'static', 'cdn', 'img', 'media', 'assets',
    'files', 'docs', 'status', 'blog', 'shop', 'store', 'pay', 'crm', 'erp', 'intranet', 'extranet',
    'portal', 'api2', 'web1', 'web2', 'ns3']) {
    assert.ok(medium.has(w), `missing label: ${w}`);
  }
});

test('includes Turkish-market names', () => {
  const medium = new Set(WORDLIST_MEDIUM);
  for (const w of ['yonetim', 'panel', 'destek', 'magaza', 'kargo', 'odeme', 'ik', 'muhasebe', 'bayi',
    'portal', 'b2b']) {
    assert.ok(medium.has(w), `missing TR label: ${w}`);
  }
});

test('getWordlist', () => {
  assert.equal(getWordlist('small'), WORDLIST_SMALL);
  assert.equal(getWordlist('medium'), WORDLIST_MEDIUM);
  assert.equal(getWordlist(), WORDLIST_SMALL);
  assert.deepEqual(getWordlist('off'), []);
  assert.deepEqual(getWordlist('nope'), []);
});

test('lists are frozen', () => {
  assert.ok(Object.isFrozen(WORDLIST_SMALL));
  assert.ok(Object.isFrozen(WORDLIST_MEDIUM));
});
