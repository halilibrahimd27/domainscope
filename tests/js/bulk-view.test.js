/**
 * views/bulk.js — the parts that run without a DOM: the input parser (JSON lists) and the job
 * runner (cancelling mid-enrichment, the resolver of the run for every PTR query). A fake DNS
 * client and fetch stand in for the network. Documentation data only (example.com, 192.0.2.0/24).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseBulkInput, createJob, runJob } from '../../assets/js/views/bulk.js';

const tick = () => new Promise((resolve) => { setTimeout(resolve, 0); });

async function until(cond, what) {
  for (let i = 0; i < 200; i += 1) {
    if (cond()) return;
    await tick();
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** A DohClient stand-in: `names[i]` resolves to 192.0.2.(i + 1). */
function fakeDns(names, ptr) {
  const calls = [];
  return {
    calls,
    resolveHost: async (name) => ({
      name, status: 'NOERROR', ipv4: [`192.0.2.${names.indexOf(name) + 1}`], ipv6: [], cnames: [], ttl: 60, resolver: 'cloudflare'
    }),
    ptr: (ip, opts = {}) => {
      calls.push({ ip, resolver: opts.resolver });
      return ptr(ip, opts);
    }
  };
}

/** Never settles until the signal aborts (a lookup still in flight when Cancel is pressed). */
const hang = (signal) => new Promise((_, reject) => {
  signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
});

describe('bulk view: input', () => {
  test('a compact JSON array of host names (jq -c, JSON.stringify)', () => {
    const r = parseBulkInput('["a.example.com","b.example.com"]');
    assert.deepEqual([r.names, r.invalid], [['a.example.com', 'b.example.com'], []]);
  });

  test('a pretty-printed array reports no stray brackets', () => {
    const r = parseBulkInput('[\n  "a.example.com",\n  "b.example.com"\n]\n');
    assert.deepEqual([r.names, r.invalid], [['a.example.com', 'b.example.com'], []]);
  });

  test('objects: host-name fields are read, other values ignored; JSON lines too', () => {
    const r = parseBulkInput(JSON.stringify([{ name: 'a.example.com', type: 'A', ttl: 300 }, { hostname: 'b.example.com', ip: '192.0.2.1' }]));
    assert.deepEqual([r.names, r.invalid, r.ips], [['a.example.com', 'b.example.com'], [], []]);
    const lines = parseBulkInput('{"host":"c.example.com","input":"example.com","source":"crtsh"}\n{"host":"d.example.com","input":"example.com","source":"crtsh"}\n');
    assert.deepEqual([lines.names, lines.invalid], [['c.example.com', 'd.example.com'], []]);
    const nested = parseBulkInput('{"names":["e.example.com","f.example.com"],"note":"from the zone"}');
    assert.deepEqual([nested.names, nested.invalid], [['e.example.com', 'f.example.com'], []]);
  });

  test('plain lists are unchanged; text that only looks like JSON is read as a list', () => {
    const r = parseBulkInput('www.example.com, api.example.com\n# comment\n192.0.2.7');
    assert.deepEqual([r.names, r.ips, r.invalid], [['www.example.com', 'api.example.com'], ['192.0.2.7'], []]);
    const broken = parseBulkInput('[a.example.com b.example.com');
    assert.deepEqual([broken.names, broken.invalid], [['b.example.com'], ['[a.example.com']]);
  });
});

describe('bulk view: job runner', () => {
  test('Cancel during PTR lookups: unfinished IPs are marked skipped, only finished ones count', async () => {
    const names = Array.from({ length: 12 }, (_, i) => `h${i}.example.com`);
    const dns = fakeDns(names, (ip, { signal }) => (ip === '192.0.2.1' ? Promise.resolve(['one.example.net']) : hang(signal)));
    const job = createJob(names, { ptr: true, asn: false, noCache: false, resolver: '' });
    const done = runJob(job, { dns, index: null, concurrency: 4 });
    await until(() => job.done === names.length && dns.calls.length === 9, 'every name resolved, 8 PTR lookups in flight');
    job.controller.abort();
    await assert.rejects(done, { name: 'AbortError' });
    await tick();
    const rows = [...job.ips.values()];
    assert.equal(rows.length, 12);
    const first = job.ips.get('192.0.2.1');
    assert.deepEqual([first.ptr, !!first.skipped], [['one.example.net'], false]);
    for (const r of rows.filter((x) => x !== first)) {
      assert.deepEqual([r.ptr, r.skipped, r.enriching], [[], true, false], r.ip);
    }
    assert.equal(job.ipTotal, 12);
    assert.equal(job.ipDone, 1, 'aborted lookups are not counted as done');
  });

  test('ASN mode sends the PTR queries to the resolver chosen for the run', async () => {
    const names = ['a.example.com'];
    const dns = fakeDns(names, async () => ['a.example.net']);
    const fetchImpl = async () => new Response('{}', { status: 404 }); // RIPEstat / ipwho.is: nothing
    const job = createJob(names, { ptr: false, asn: true, noCache: false, resolver: 'quad9' });
    await runJob(job, { dns, index: null, concurrency: 2, fetchImpl });
    assert.deepEqual(dns.calls, [{ ip: '192.0.2.1', resolver: 'quad9' }]);
    assert.deepEqual(job.ips.get('192.0.2.1').ptr, ['a.example.net']);
    const auto = createJob(names, { ptr: false, asn: true, noCache: false, resolver: '' });
    dns.calls.length = 0;
    await runJob(auto, { dns, index: null, concurrency: 2, fetchImpl });
    assert.deepEqual(dns.calls, [{ ip: '192.0.2.1', resolver: undefined }], 'no resolver chosen: the Settings chain');
  });
});
