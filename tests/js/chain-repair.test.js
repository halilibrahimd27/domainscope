/**
 * ui/chain-repair.js (the missing intermediate and the root-store warnings in the Certificate
 * view and SSL Targets step 1) — its pure helpers: which loads it looks at, the job per loaded
 * file (kept, retried after a failure), the repaired fullchain, and the sentences in English and
 * Turkish. The dataset is the test one (tests/fixtures/intermediates/), read from disk.
 * No DOM: the notes themselves are exercised in a real browser by tests/e2e/chainfix.e2e.mjs.
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { setLang } from '../../assets/js/i18n.js';
import { createIntermediateStore, repairChain, rootTable, chainStanding } from '../../assets/js/lib/chainfix.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  CCADB_URL, chainRepairOf, lifecycleText, repairApplies, repairText, repairedFullchain, startChainRepair, storeList, trustText
} from '../../assets/js/ui/chain-repair.js';

const FIXTURES = new URL('../fixtures/', import.meta.url);
const MANIFEST = new URL('intermediates/manifest.json', FIXTURES).href;
const NOW = new Date('2026-09-28T12:00:00Z');
const read = (f) => readFileSync(new URL(f, FIXTURES), 'utf8');
const loadOf = (source, ...files) => ({ name: files[0], source, result: parseCertificates(files.map(read).join('\n')) });

function diskStore({ failFirst = 0 } = {}) {
  let fail = failFirst;
  const fetchImpl = async (url) => {
    if (fail > 0) {
      fail -= 1;
      throw new TypeError('Failed to fetch');
    }
    try {
      return new Response(readFileSync(fileURLToPath(url)));
    } catch {
      return /\/(?:ski|dn)\/[0-9a-f]+\.json$/.test(url) ? new Response('{}') : new Response('', { status: 404 });
    }
  };
  return createIntermediateStore({ url: MANIFEST, fetchImpl });
}

/** Wait for a job's watchers. */
const settled = (job) => (job.status === 'running' ? new Promise((resolve) => job.watchers.add(resolve)) : Promise.resolve(job));

after(() => setLang('en'));

describe('which loads', () => {
  test('a server certificate only: not a CA, not self-signed, not a precertificate, not nothing', () => {
    assert.equal(repairApplies(loadOf('file', 'chainfix_leaf.pem')), true);
    assert.equal(repairApplies(loadOf('file', 'chainfix_inter.pem')), false, 'a CA certificate');
    assert.equal(repairApplies(loadOf('file', 'chainfix_root.pem')), false);
    const leaf = loadOf('ct', 'chainfix_leaf.pem');
    leaf.result.leaf = { ...leaf.result.leaf, isPrecertificate: true };
    assert.equal(repairApplies(leaf), false, 'never served');
    assert.equal(repairApplies(null), false);
    assert.equal(repairApplies({ result: { leaf: null, certificates: [] } }), false);
    assert.equal(startChainRepair(loadOf('file', 'chainfix_root.pem'), { store: diskStore() }), null);
  });
});

describe('the job', () => {
  test('one per loaded file: started once, its repair and fullchain kept', async () => {
    const load = loadOf('file', 'chainfix_leaf.pem');
    const store = diskStore();
    const job = startChainRepair(load, { store, now: NOW });
    assert.equal(job.status, 'running');
    assert.equal(chainRepairOf(load), null, 'nothing before it ends');
    assert.equal(startChainRepair(load, { store }), job, 'the same job while it runs');
    await settled(job);
    assert.equal(job.status, 'done');
    assert.equal(startChainRepair(load, { store }), job, 'and once done');
    assert.equal(chainRepairOf(load).status, 'repaired');
    assert.deepEqual(repairedFullchain(load).map((c) => c.subjectCN), ['www.example.com', 'DomainScope Test Issuing CA']);
    // Another load of the same file is another job.
    assert.notEqual(startChainRepair(loadOf('file', 'chainfix_leaf.pem'), { store }), job);
  });

  test('a complete chain has no repaired fullchain; a failed job starts again on the next call', async () => {
    const complete = loadOf('file', 'chainfix_leaf.pem', 'chainfix_inter.pem');
    await settled(startChainRepair(complete, { store: diskStore(), now: NOW }));
    assert.equal(chainRepairOf(complete).status, 'complete');
    assert.equal(repairedFullchain(complete), null);
    const load = loadOf('file', 'chainfix_leaf_deep.pem');
    const store = diskStore({ failFirst: 1 });
    const failed = await settled(startChainRepair(load, { store, now: NOW }));
    assert.equal(failed.status, 'error');
    assert.equal(chainRepairOf(load), null);
    const again = startChainRepair(load, { store, now: NOW });
    assert.notEqual(again, failed);
    await settled(again);
    assert.equal(chainRepairOf(load).added.length, 2);
  });
});

describe('sentences', () => {
  const repairOf = async (source, ...files) => {
    const load = loadOf(source, ...files);
    return { load, repair: await repairChain(load.result, { store: diskStore(), now: NOW }) };
  };

  test('found: a lone server certificate, one cut short, one from Certificate Transparency, an untrusted root', async () => {
    setLang('en');
    let { load, repair } = await repairOf('file', 'chainfix_leaf.pem');
    assert.deepEqual(repairText(repair, load), {
      title: 'Missing intermediate found',
      message: 'The file holds only the server certificate. The intermediate that issued it is in the CCADB list of public intermediates, so fullchain.pem below puts it after the server certificate.'
    });
    ({ load, repair } = await repairOf('file', 'chainfix_leaf_deep.pem', 'chainfix_deep_ca.pem'));
    assert.match(repairText(repair, load).message, /^The file stops at DomainScope Test Deep CA, whose issuer is not in it\./);
    ({ load, repair } = await repairOf('ct', 'chainfix_leaf_deep.pem'));
    assert.equal(repairText(repair, load).title, '2 missing intermediates found');
    assert.match(repairText(repair, load).message, /^Certificate Transparency logs hold the server certificate only\. The 2 intermediates it needs/);
    ({ load, repair } = await repairOf('file', 'chainfix_leaf.pem', 'chainfix_inter_cross.pem'));
    assert.deepEqual(repairText(repair, load), {
      title: 'A current root is reachable',
      message: 'The file’s chain ends at DomainScope Test Old Root, which no root store trusts for this certificate. A cross-signed certificate in the CCADB list leads on to DomainScope Test Root CA, so fullchain.pem below adds it.'
    });
    setLang('tr');
    ({ load, repair } = await repairOf('file', 'chainfix_leaf.pem'));
    assert.equal(repairText(repair, load).title, 'Eksik ara sertifika bulundu');
    setLang('en');
  });

  test('lifecycle warnings: dates as calendar days, store names, the certificate\'s own expiry', async () => {
    setLang('en');
    const { repair } = await repairOf('file', 'chainfix_leaf_lifecycle.pem');
    const texts = repair.standing.warnings.map((w) => lifecycleText(w, repair.leaf));
    assert.deepEqual(texts, [
      'Chrome does not trust certificates from DomainScope Test Distrusted Root issued after Jan 31, 2026. This one was issued on Mar 1, 2026.',
      'Mozilla (Firefox) does not trust certificates from DomainScope Test Distrusted Root issued after Jun 30, 2026. This one (issued on Mar 1, 2026) is not affected, but its renewal has to come from another CA.',
      'DomainScope Test Distrusted Root expires on Mar 1, 2040, before this certificate does (Jun 1, 2040). After that date, clients that check the root’s validity reject the chain.'
    ]);
    setLang('tr');
    assert.equal(lifecycleText(repair.standing.warnings[0], repair.leaf),
      'Chrome, DomainScope Test Distrusted Root kökünün 31 Oca 2026 tarihinden sonra verdiği sertifikalara güvenmiyor. Bu sertifika 1 Mar 2026 tarihinde verildi.');
    setLang('en');
  });

  test('storeList joins store names in the UI language', () => {
    setLang('en');
    assert.equal(storeList(['chrome', 'apple', 'microsoft']), 'Chrome, Apple, and Microsoft');
    assert.equal(storeList(['mozilla']), 'Mozilla (Firefox)');
    assert.equal(storeList(['opera']), '');
    setLang('tr');
    assert.equal(storeList(['chrome', 'apple']), 'Chrome ve Apple');
    setLang('en');
  });

  test('trustText: where the chain ends and who trusts it, grouped by the root they stop at', async () => {
    setLang('en');
    const { repair } = await repairOf('file', 'chainfix_leaf.pem');
    assert.equal(trustText(repair), 'The chain ends at DomainScope Test Root CA (DomainScope Test). Trusted for websites by Chrome, Mozilla (Firefox), Apple, and Microsoft.');
    const notFound = (await repairOf('file', 'chainfix_leaf_unknown.pem')).repair;
    assert.equal(trustText(notFound), null);
    // A cross-signed root in the chain: the stores that hold it stop there.
    const table = rootTable(JSON.parse(read('intermediates/roots.json')));
    const current = table.roots.find((r) => r.name === 'DomainScope Test Root CA');
    const old = { ...table.roots.find((r) => r.name === 'DomainScope Test Old Root'), stores: { chrome: 'absent', mozilla: 'absent', apple: 'tls', microsoft: 'tls' } };
    const partly = { ...current, stores: { chrome: 'tls', mozilla: 'tls', apple: 'absent', microsoft: 'absent' } };
    const anchors = [partly, old];
    const fake = { ...repair, root: old, anchors, standing: chainStanding(anchors, repair.leaf, NOW) };
    assert.equal(trustText(fake), 'The chain ends at DomainScope Test Old Root (DomainScope Old Test). Trusted for websites by '
      + 'Chrome and Mozilla (Firefox) through DomainScope Test Root CA and Apple and Microsoft through DomainScope Test Old Root.');
    const none = { ...repair, standing: chainStanding([{ ...current, stores: { chrome: 'removed', mozilla: 'removed', apple: 'removed', microsoft: 'removed' } }], repair.leaf, NOW) };
    assert.match(trustText(none), /No root store trusts it for this certificate\.$/);
  });

  test('the CCADB is credited with a link', () => {
    assert.equal(CCADB_URL, 'https://www.ccadb.org/');
  });
});
