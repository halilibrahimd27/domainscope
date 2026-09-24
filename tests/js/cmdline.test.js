// Unit tests for assets/js/lib/cmdline.js — safe construction of the
// cli/ssl_origin_scan.py origin-sweep command. The point of the module is that
// a hostile token (shell metacharacters, injection payloads, a leading '-',
// junk) can never reach the command line: it is validated away, and the
// survivors are shell-quoted only when a character requires it. No network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildOriginSweepCommand, buildSweepCommand, quoteArg, validateTargets, validateNames
} from '../../assets/js/lib/cmdline.js';

describe('validateTargets', () => {
  test('accepts and canonicalises IPs and CIDRs, drops everything else', () => {
    const { valid, dropped } = validateTargets([
      '203.0.113.10', '2001:db8:1234::1', '198.51.100.0/24', '2001:db8:1234::/48',
      '203.0.113.5/24',           // host bits masked off → 203.0.113.0/24
      '; rm -rf /', '$(id)', 'notanip', '999.1.1.1', '', '  ', '10.0.0.0/40'
    ]);
    assert.deepEqual(valid, [
      '203.0.113.10', '2001:db8:1234::1', '198.51.100.0/24', '2001:db8:1234::/48', '203.0.113.0/24'
    ]);
    assert.ok(dropped.includes('; rm -rf /'));
    assert.ok(dropped.includes('$(id)'));
    assert.ok(dropped.includes('notanip'));
    assert.ok(dropped.includes('999.1.1.1'));
    assert.ok(dropped.includes('10.0.0.0/40'), 'prefix > 32 is invalid');
  });

  test('dedupes canonical targets', () => {
    const { valid } = validateTargets(['203.0.113.1', '203.0.113.1', '203.0.113.0/24', '203.0.113.9/24']);
    assert.deepEqual(valid, ['203.0.113.1', '203.0.113.0/24']);
  });
});

describe('validateNames', () => {
  test('accepts hostnames (IDN → punycode), drops hostile / malformed', () => {
    const { valid, dropped } = validateNames([
      'app.example.com', 'DEV.Example.COM', 'a_b.example.net', 'xn--mnchen-3ya.example',
      'münchen.example',                 // IDN → punycode, kept
      '-evil.example.com',               // leading '-' (would look like a flag)
      'a b.example.com', 'ex;ample.com', '$(id).com', '`whoami`.com',
      'line\nbreak.com', 'quote".com', "quote'.com",
      `${'a'.repeat(300)}.com`,          // over-long
      '🙂.example'                        // non-ASCII that is not a valid host
    ]);
    assert.ok(valid.includes('app.example.com'));
    assert.ok(valid.includes('dev.example.com'), 'lowercased');
    assert.ok(valid.includes('a_b.example.net'), 'underscore allowed');
    assert.ok(valid.includes('xn--mnchen-3ya.example'));
    assert.ok(!dropped.includes('münchen.example'), 'the IDN folds to punycode, not dropped');
    assert.equal(valid.filter((n) => n === 'xn--mnchen-3ya.example').length, 1, 'the IDN and its punycode dedupe to one token');
    for (const bad of ['-evil.example.com', 'a b.example.com', 'ex;ample.com', '$(id).com', '`whoami`.com', 'line\nbreak.com']) {
      assert.ok(dropped.includes(bad), `dropped ${JSON.stringify(bad)}`);
    }
    assert.ok(!valid.some((n) => n.startsWith('-')), 'no name begins with a hyphen');
    assert.ok(!valid.some((n) => /[^a-z0-9_.-]/.test(n)), 'only letters, digits, _ . -');
  });
});

describe('quoteArg', () => {
  test('leaves safe tokens bare (both shells)', () => {
    for (const s of ['203.0.113.0/24', '2001:db8::1', 'app.example.com', 'cli/ssl_origin_scan.py', 'a_b-c.d']) {
      assert.equal(quoteArg(s, 'posix'), s);
      assert.equal(quoteArg(s, 'powershell'), s);
    }
  });

  test('POSIX single-quotes and escapes only when needed', () => {
    assert.equal(quoteArg('a b', 'posix'), "'a b'");
    assert.equal(quoteArg('; rm -rf /', 'posix'), "'; rm -rf /'");
    assert.equal(quoteArg('$(id)', 'posix'), "'$(id)'");
    assert.equal(quoteArg('a`b`', 'posix'), "'a`b`'");
    assert.equal(quoteArg("a'b", 'posix'), "'a'\\''b'"); // close, escaped quote, reopen
    assert.equal(quoteArg('', 'posix'), "''", 'the empty string must be quoted');
  });

  test('PowerShell single-quotes and doubles embedded quotes', () => {
    assert.equal(quoteArg('a b', 'powershell'), "'a b'");
    assert.equal(quoteArg("a'b", 'powershell'), "'a''b'");
    assert.equal(quoteArg('$(id)', 'powershell'), "'$(id)'");
    assert.equal(quoteArg('a,b', 'powershell'), "'a,b'", 'comma is quoted for PowerShell');
    assert.equal(quoteArg('a,b', 'posix'), 'a,b', 'comma is bare for POSIX');
  });

  test('refuses Unicode quotes (PowerShell closes a literal on U+2018–U+201B) in both shells', () => {
    // PowerShell reads ‘ ’ ‚ ‛ as single quotes: doubling only ASCII "'" would let
    // "x’; Write-Output INJECTED; ’" break out of the literal and run a command.
    for (const payload of ['x’; Write-Output INJECTED; ’', 'x‘y', 'x‚y', 'x‛y', 'münchen']) {
      for (const shell of ['powershell', 'posix']) {
        assert.throws(() => quoteArg(payload, shell), TypeError, `${shell}: ${JSON.stringify(payload)}`);
      }
    }
  });

  test('refuses NUL / CR / LF / TAB and other control characters in both shells', () => {
    for (const payload of ['a\u0000b', 'line\nbreak', 'a\rb', 'a\tb', 'a\u001bb', 'a\u007fb']) {
      for (const shell of ['powershell', 'posix']) {
        assert.throws(() => quoteArg(payload, shell), TypeError, `${shell}: ${JSON.stringify(payload)}`);
      }
    }
  });
});

describe('buildSweepCommand / buildOriginSweepCommand', () => {
  test('builds the canonical command with the default script (POSIX)', () => {
    const { command, targets, names, dropped } = buildSweepCommand({
      targets: ['203.0.113.0/24', '2001:db8:1234::1'],
      names: ['app.example.com', 'www.example.com']
    });
    assert.equal(command, 'ssl_origin_scan.py -t 203.0.113.0/24 2001:db8:1234::1 -n app.example.com www.example.com');
    assert.deepEqual(targets, ['203.0.113.0/24', '2001:db8:1234::1']);
    assert.deepEqual(names, ['app.example.com', 'www.example.com']);
    assert.deepEqual(dropped, { targets: [], names: [], options: [] });
  });

  test('a repo-path script is emitted bare (no quoting needed)', () => {
    const cmd = buildOriginSweepCommand({ targets: ['203.0.113.10'], names: ['www.example.net'], script: 'cli/ssl_origin_scan.py' });
    assert.equal(cmd, 'cli/ssl_origin_scan.py -t 203.0.113.10 -n www.example.net');
  });

  test('hostile targets and names are dropped, never quoted into the command', () => {
    const res = buildSweepCommand({
      targets: ['203.0.113.0/24', '; rm -rf /', '$(reboot)'],
      names: ['ok.example.com', '-rf', 'a b.com', '`id`.com']
    });
    assert.equal(res.command, 'ssl_origin_scan.py -t 203.0.113.0/24 -n ok.example.com');
    // the payloads never appear anywhere in the command
    for (const bad of ['rm -rf', 'reboot', '$(', '`id`', ' b.com']) {
      assert.ok(!res.command.includes(bad), `command must not contain ${bad}`);
    }
    assert.deepEqual(res.dropped.targets, ['; rm -rf /', '$(reboot)']);
    assert.ok(res.dropped.names.includes('-rf') && res.dropped.names.includes('a b.com') && res.dropped.names.includes('`id`.com'));
    assert.deepEqual(res.targets, ['203.0.113.0/24']);
    assert.deepEqual(res.names, ['ok.example.com']);
  });

  test('command is null when no valid target or no valid name survives', () => {
    assert.equal(buildOriginSweepCommand({ targets: [], names: ['ok.example.com'] }), null);
    assert.equal(buildOriginSweepCommand({ targets: ['203.0.113.1'], names: [] }), null);
    assert.equal(buildOriginSweepCommand({ targets: ['nope'], names: ['also nope!'] }), null);
    // valid targets survive even when the command is null (no names)
    const res = buildSweepCommand({ targets: ['203.0.113.1'], names: ['bad name'] });
    assert.equal(res.command, null);
    assert.deepEqual(res.targets, ['203.0.113.1']);
    assert.deepEqual(res.names, []);
  });

  test('PowerShell shell option (validated tokens still need no quoting)', () => {
    const cmd = buildOriginSweepCommand({
      targets: ['198.51.100.0/24'], names: ['app.example.com'], script: 'cli/ssl_origin_scan.py', shell: 'powershell'
    });
    assert.equal(cmd, 'cli/ssl_origin_scan.py -t 198.51.100.0/24 -n app.example.com');
  });

  test('an IPv6 /48 target is a valid CIDR here (the /48-vs-exact policy lives in the scanner)', () => {
    const cmd = buildOriginSweepCommand({ targets: ['2001:db8:abcd::/48'], names: ['app.example.com'] });
    assert.equal(cmd, 'ssl_origin_scan.py -t 2001:db8:abcd::/48 -n app.example.com');
  });

  test('a hostile script token falls back to the default script (both shells)', () => {
    for (const shell of ['posix', 'powershell']) {
      for (const script of ["s’;Write-Output PWN;’", 's;rm -rf /', '$(id)', '-rf', 'a b.py', 'x\ny.py', '']) {
        const res = buildSweepCommand({ targets: ['203.0.113.10'], names: ['app.example.com'], script, shell });
        assert.equal(res.command, 'ssl_origin_scan.py -t 203.0.113.10 -n app.example.com', `${shell}: ${JSON.stringify(script)}`);
      }
    }
  });
});

describe('buildSweepCommand — long name lists go to a names file', () => {
  const many = (n) => Array.from({ length: n }, (_, i) => `service-${i}.example.com`);

  test('1,500 proxied names: short command reading -n proxied-names.txt (both shells)', () => {
    for (const shell of ['posix', 'powershell']) {
      const res = buildSweepCommand({ targets: ['203.0.113.0/24'], names: many(1500), shell });
      assert.equal(res.namesInline, false);
      assert.equal(res.namesFile, 'proxied-names.txt');
      assert.equal(res.command, 'ssl_origin_scan.py -t 203.0.113.0/24 -n proxied-names.txt');
      assert.ok(res.length < 8000 && res.length === res.command.length, `length ${res.length}`);
      assert.equal(res.names.length, 1500, 'the full validated list is still returned (for the file)');
    }
  });

  test('10 names stay inline; the length is reported', () => {
    const res = buildSweepCommand({ targets: ['203.0.113.10'], names: many(10) });
    assert.equal(res.namesInline, true);
    assert.equal(res.namesFile, null);
    assert.ok(res.command.endsWith('service-9.example.com'));
    assert.equal(res.length, res.command.length);
  });

  test('the switch happens past 200 names or 8,000 characters, whichever comes first', () => {
    assert.equal(buildSweepCommand({ targets: ['203.0.113.10'], names: many(200) }).namesInline, true);
    assert.equal(buildSweepCommand({ targets: ['203.0.113.10'], names: many(201) }).namesInline, false);
    const longNames = Array.from({ length: 60 }, (_, i) => `${'a'.repeat(60)}.${'b'.repeat(60)}.svc-${i}.example.com`);
    const res = buildSweepCommand({ targets: ['203.0.113.10'], names: longNames });
    assert.equal(res.namesInline, false, 'few but long names still overflow 8,000 chars');
    assert.ok(res.length < 8000);
  });

  test('custom names file / thresholds; a hostile names file falls back to the default', () => {
    const custom = buildSweepCommand({ targets: ['203.0.113.10'], names: many(5), namesFile: 'out/names.txt', maxInlineNames: 2 });
    assert.equal(custom.command, 'ssl_origin_scan.py -t 203.0.113.10 -n out/names.txt');
    const hostile = buildSweepCommand({ targets: ['203.0.113.10'], names: many(5), namesFile: '$(id).txt', maxInlineNames: 2, shell: 'powershell' });
    assert.equal(hostile.command, 'ssl_origin_scan.py -t 203.0.113.10 -n proxied-names.txt');
    const never = buildSweepCommand({ targets: ['203.0.113.10'], names: many(1500), maxInlineNames: Infinity, maxLength: Infinity });
    assert.equal(never.namesInline, true, 'Infinity thresholds keep every name inline');
  });

  test('the wrapper still returns just the command string', () => {
    assert.equal(buildOriginSweepCommand({ targets: ['203.0.113.10'], names: many(300) }), 'ssl_origin_scan.py -t 203.0.113.10 -n proxied-names.txt');
  });
});

describe('buildSweepCommand — -p / --cert / --json options (Verify CLI card)', () => {
  const base = { targets: ['203.0.113.10', '2001:db8::5'], names: ['www.example.com', 'api.example.com'] };
  const many = (n) => Array.from({ length: n }, (_, i) => `service-${i}.example.com`);

  test('cert and json are appended after the names; dropped.options is empty', () => {
    const res = buildSweepCommand({ ...base, cert: 'new-cert.pem', json: 'verify-cli.json' });
    assert.equal(res.command,
      'ssl_origin_scan.py -t 203.0.113.10 2001:db8::5 -n www.example.com api.example.com --cert new-cert.pem --json verify-cli.json');
    assert.deepEqual(res.dropped, { targets: [], names: [], options: [] });
    assert.equal(res.length, res.command.length);
    assert.equal(buildSweepCommand({ ...base, cert: 'new-cert.pem' }).command,
      'ssl_origin_scan.py -t 203.0.113.10 2001:db8::5 -n www.example.com api.example.com --cert new-cert.pem');
    assert.equal(buildSweepCommand({ ...base, json: 'out/verify-cli.json' }).command,
      'ssl_origin_scan.py -t 203.0.113.10 2001:db8::5 -n www.example.com api.example.com --json out/verify-cli.json');
  });

  test('hostile cert / json paths are dropped (never quoted in) and reported', () => {
    for (const bad of ['-x', 'a b', '../x;y', '$(id).pem', "a'b.pem", 'x\ny.pem', '', 'münchen.pem', 42, {}]) {
      for (const shell of ['posix', 'powershell']) {
        const res = buildSweepCommand({ ...base, shell, cert: bad, json: bad });
        assert.equal(res.command, 'ssl_origin_scan.py -t 203.0.113.10 2001:db8::5 -n www.example.com api.example.com',
          `${shell}: ${JSON.stringify(bad)}`);
        assert.deepEqual(res.dropped.options, ['cert', 'json']);
      }
    }
    // null / undefined mean "not requested", not "dropped"
    assert.deepEqual(buildSweepCommand({ ...base, cert: null, json: undefined }).dropped.options, []);
  });

  test('ports: [443] (the CLI default) and [] give no -p; bad values are dropped one by one', () => {
    assert.ok(!buildSweepCommand({ ...base, ports: [443] }).command.includes('-p'));
    assert.ok(!buildSweepCommand({ ...base, ports: [] }).command.includes('-p'));
    assert.ok(!buildSweepCommand({ ...base, ports: [443, 443] }).command.includes('-p'), 'deduped to exactly [443]');
    const res = buildSweepCommand({ ...base, ports: [443, 8443, 0, 70000] });
    assert.ok(res.command.endsWith(' -n www.example.com api.example.com -p 443,8443'), res.command);
    assert.deepEqual(res.dropped.options, ['ports:0', 'ports:70000']);
    const odd = buildSweepCommand({ ...base, ports: [8443, 1.5, '443', -1, 65535, 8443, NaN] });
    assert.ok(odd.command.endsWith(' -p 8443,65535'), odd.command);
    assert.deepEqual(odd.dropped.options, ['ports:1.5', 'ports:443', 'ports:-1', 'ports:NaN']);
    // a single integer is accepted like a one-element list
    assert.ok(buildSweepCommand({ ...base, ports: 8443 }).command.endsWith(' -p 8443'));
    // every value invalid → no -p (the CLI default applies), all reported
    const none = buildSweepCommand({ ...base, ports: [0] });
    assert.ok(!none.command.includes('-p'));
    assert.deepEqual(none.dropped.options, ['ports:0']);
  });

  test('option order is -p, --cert, --json whatever the argument order', () => {
    const res = buildSweepCommand({ json: 'verify-cli.json', cert: 'new-cert.pem', ports: [8443, 443], ...base });
    assert.ok(res.command.endsWith(' -n www.example.com api.example.com -p 8443,443 --cert new-cert.pem --json verify-cli.json'),
      res.command);
  });

  test('with a names file (more than 200 names) the options follow the file token', () => {
    const res = buildSweepCommand({ targets: ['203.0.113.10'], names: many(250), cert: 'new-cert.pem', json: 'verify-cli.json', ports: [443, 8443] });
    assert.equal(res.namesInline, false);
    assert.equal(res.command, 'ssl_origin_scan.py -t 203.0.113.10 -n proxied-names.txt -p 443,8443 --cert new-cert.pem --json verify-cli.json');
    assert.equal(res.length, res.command.length);
  });

  test('the options count toward the inline length limit', () => {
    const names = many(3);
    const plain = buildSweepCommand({ targets: ['203.0.113.10'], names });
    const withOpts = buildSweepCommand({ targets: ['203.0.113.10'], names, cert: 'new-cert.pem', maxLength: plain.length + 5 });
    assert.equal(buildSweepCommand({ targets: ['203.0.113.10'], names, maxLength: plain.length + 5 }).namesInline, true);
    assert.equal(withOpts.namesInline, false, 'the --cert suffix pushes the inline form over maxLength');
    assert.ok(withOpts.command.endsWith(' -n proxied-names.txt --cert new-cert.pem'));
  });

  test('PowerShell: the comma port list is quoted (a bare a,b is an array there); POSIX leaves it bare', () => {
    const opts = { ...base, ports: [443, 8443], cert: 'new-cert.pem', json: 'verify-cli.json' };
    assert.ok(buildSweepCommand({ ...opts, shell: 'powershell' }).command
      .endsWith(" -n www.example.com api.example.com -p '443,8443' --cert new-cert.pem --json verify-cli.json"));
    assert.ok(buildSweepCommand({ ...opts, shell: 'posix' }).command
      .endsWith(' -n www.example.com api.example.com -p 443,8443 --cert new-cert.pem --json verify-cli.json'));
  });

  test('command stays null without targets or names; the option report still comes back', () => {
    const res = buildSweepCommand({ targets: [], names: ['www.example.com'], cert: '-bad', ports: [0] });
    assert.equal(res.command, null);
    assert.equal(res.length, 0);
    assert.deepEqual(res.dropped.options, ['ports:0', 'cert']);
  });

  test('regression: the existing call shapes are byte-identical when the new options are absent', () => {
    // scanner.js (CDN origin sweep suggestion)
    assert.equal(buildSweepCommand({ targets: ['198.51.100.0/24', '2001:db8:abcd::/48'], names: ['app.example.com', 'shop.example.com'],
      script: 'cli/ssl_origin_scan.py', shell: 'posix' }).command,
    'cli/ssl_origin_scan.py -t 198.51.100.0/24 2001:db8:abcd::/48 -n app.example.com shop.example.com');
    // views/subdomains.js (origin panel, both shells)
    for (const shell of ['posix', 'powershell']) {
      const res = buildSweepCommand({ targets: ['203.0.113.0/24'], names: ['a.example.com'], script: 'ssl_origin_scan.py', shell });
      assert.equal(res.command, 'ssl_origin_scan.py -t 203.0.113.0/24 -n a.example.com');
      assert.deepEqual(Object.keys(res), ['command', 'targets', 'names', 'dropped', 'length', 'namesInline', 'namesFile']);
    }
    const file = buildSweepCommand({ targets: ['203.0.113.0/24'], names: many(1500), shell: 'powershell' });
    assert.equal(file.command, 'ssl_origin_scan.py -t 203.0.113.0/24 -n proxied-names.txt');
    assert.equal(file.length, file.command.length);
  });
});
