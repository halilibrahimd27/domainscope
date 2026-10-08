// lib/deploysnippets.js — quoting rules (POSIX, PowerShell), validation of every interpolated
// value, and the snippet of each platform. Documentation names and addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

import {
  DEPLOY_PLATFORMS, SNIPPET_SECTIONS, SNIPPET_NOTES, SNIPPET_WARNINGS, PLATFORM_OPTIONS, OPTION_RULES, MAX_VERIFY_TARGETS,
  shQuote, psQuote, safeHostname, safeAddress, safeFingerprint, colonFingerprint, fileStem, deploySnippet
} from '../../assets/js/lib/deploysnippets.js';

const FP = 'ab'.repeat(32);
const FP2 = '0123456789abcdef'.repeat(4);
const INPUT = {
  server: { name: 'web01' },
  targets: [{ ip: '192.0.2.10', port: 443 }, { ip: '2001:db8::10', port: 8443 }],
  names: ['www.example.com', '*.example.com', 'api.example.com'],
  fingerprints: [FP],
  certName: '*.example.com',
  notBefore: new Date('2026-10-01T08:00:00Z')
};
const all = (s) => s.sections.flatMap((x) => x.lines).join('\n');
const sec = (s, id) => (s.sections.find((x) => x.id === id) || { lines: [] }).lines.join('\n');

/** Runs a POSIX sh script and returns its stdout (sh is on every CI runner but Windows). */
const sh = (script) => execFileSync('sh', ['-c', script], { encoding: 'utf8' });
const HAVE_SH = (() => {
  try {
    return sh('printf ok') === 'ok';
  } catch {
    return false;
  }
})();

describe('shQuote (POSIX)', () => {
  test('one single-quoted word; an embedded quote is closed, escaped and reopened', () => {
    assert.equal(shQuote('www.example.com'), "'www.example.com'");
    assert.equal(shQuote("it's"), "'it'\\''s'");
    assert.equal(shQuote(''), "''");
    assert.equal(shQuote(443), "'443'");
  });
  test('nothing expands inside: $( ), backquotes, $VAR, globs, ; | & and backslashes stay literal', () => {
    for (const v of ['$(id)', '`id`', '$HOME', '*', 'a;b|c&d', 'a\\b', '"x"', '!x', '~', 'a b']) assert.equal(shQuote(v), `'${v}'`, v);
  });
  test('control characters (newline, CR, NUL, ESC, DEL, C1, U+2028) are refused, not quoted', () => {
    for (const v of ['a\nb', 'a\rb', 'a\u0000b', '\u001b[31m', 'a\u007fb', 'a\u0085b', 'a\u2028b']) assert.equal(shQuote(v), null, JSON.stringify(v));
    assert.equal(shQuote(null), null);
    assert.equal(shQuote(undefined), null);
  });
  test('sh reads every quoted value back as exactly one argument, unchanged', { skip: !HAVE_SH && 'no sh' }, () => {
    for (const v of ["it's", "''", "'$(touch /nonexistent)'", '`id`', '$HOME', 'a b  c', '*', '\\', "x'; echo pwned; '"]) {
      const out = sh(`printf '%s\\n' ${shQuote(v)} | wc -l; printf '%s' ${shQuote(v)}`);
      const [count, ...rest] = out.split('\n');
      assert.equal(Number(count.trim()), 1 + (v.match(/\n/g) || []).length, `one line: ${v}`);
      assert.equal(rest.join('\n'), v, v);
    }
  });
});

describe('psQuote (PowerShell)', () => {
  test('single quotes; an embedded quote is doubled', () => {
    assert.equal(psQuote('Default Web Site'), "'Default Web Site'");
    assert.equal(psQuote("O'Brien"), "'O''Brien'");
  });
  test('the typographic quotes PowerShell also ends a string at are doubled too', () => {
    assert.equal(psQuote('it\u2019s'), "'it\u2019\u2019s'");
    assert.equal(psQuote('\u2018a\u2019'), "'\u2018\u2018a\u2019\u2019'");
    assert.equal(psQuote('\u201aa\u201b'), "'\u201a\u201aa\u201b\u201b'");
  });
  test('no expansion inside single quotes: $var, $(…), backticks and double quotes stay literal', () => {
    for (const v of ['$env:USERPROFILE', '$(Get-Process)', 'a`nb', '"x"', '@(1)', 'a;b|c']) assert.equal(psQuote(v), `'${v}'`, v);
  });
  test('control characters are refused', () => {
    for (const v of ['a\nb', 'a\rb', 'a\u0000b', 'a\u2029b']) assert.equal(psQuote(v), null, JSON.stringify(v));
  });
});

describe('validators', () => {
  test('host names: LDH labels (underscore allowed), lowercased, a wildcard only when asked', () => {
    assert.equal(safeHostname('WWW.Example.COM.'), 'www.example.com');
    assert.equal(safeHostname('_acme.example.com'), '_acme.example.com');
    assert.equal(safeHostname('xn--bcher-kva.example'), 'xn--bcher-kva.example');
    assert.equal(safeHostname('*.example.com'), null);
    assert.equal(safeHostname('*.example.com', { wildcard: true }), '*.example.com');
    assert.equal(safeHostname('web01'), 'web01');
    for (const bad of ["x'$(id).example.com", 'a b.example.com', '-a.example.com', 'a-.example.com', 'a..example.com', 'bücher.example',
      'a\n.example.com', `${'a'.repeat(64)}.example.com`, `${'a.'.repeat(127)}com`, '', null, 7, 'a.*.example.com']) {
      assert.equal(safeHostname(bad, { wildcard: true }), null, JSON.stringify(bad));
    }
  });
  test('addresses are canonical literals; anything else is refused', () => {
    assert.equal(safeAddress('192.0.2.10'), '192.0.2.10');
    assert.equal(safeAddress('2001:DB8:0:0::10'), '2001:db8::10');
    for (const bad of ['192.0.2.300', '192.0.2.10; id', 'example.com', '', null]) assert.equal(safeAddress(bad), null, String(bad));
  });
  test('fingerprints: 64 hex digits, colons and case ignored', () => {
    assert.equal(safeFingerprint(colonFingerprint(FP)), FP);
    assert.equal(safeFingerprint(FP.toUpperCase()), FP);
    assert.equal(safeFingerprint('ab'.repeat(20)), null, 'a SHA-1 is not a SHA-256');
    assert.equal(safeFingerprint(`${FP.slice(2)}zz`), null);
    assert.equal(colonFingerprint(FP).length, 95);
  });
  test('file stem: the first name (`*.` as star.), safe characters, the start date', () => {
    assert.equal(fileStem('*.example.com', new Date('2026-10-01T08:00:00Z')), 'star.example.com-20261001');
    assert.equal(fileStem('www.example.com'), 'www.example.com');
    assert.equal(fileStem("../../etc/x'y"), 'etc-x-y');
    assert.equal(fileStem(''), 'certificate');
    assert.equal(fileStem(null, new Date('invalid')), 'certificate');
  });
  test('option rules: each platform option has a rule; the defaults are valid themselves', () => {
    const ctx = { stem: 'star.example.com-20261001' };
    for (const [platform, keys] of Object.entries(PLATFORM_OPTIONS)) {
      assert.ok(DEPLOY_PLATFORMS.includes(platform), platform);
      for (const key of keys) {
        const rule = OPTION_RULES[key];
        assert.ok(rule, key);
        const d = rule.fallback(ctx);
        if (d !== null) assert.ok(rule.test(d), `${key} default ${d}`);
      }
    }
    assert.ok(OPTION_RULES.namespace.test('web-prod') && !OPTION_RULES.namespace.test('Web_Prod'));
    assert.ok(OPTION_RULES.vault.test('kv-prod') && !OPTION_RULES.vault.test('kv--prod') && !OPTION_RULES.vault.test('1kv'));
    assert.ok(OPTION_RULES.arn.test('arn:aws:acm:eu-west-1:123456789012:certificate/12345678-1234-1234-1234-123456789012'));
    assert.ok(!OPTION_RULES.arn.test("arn:aws:acm:eu-west-1:123456789012:certificate/x'; rm -rf ~"));
    assert.ok(OPTION_RULES.region.test('us-gov-west-1') && !OPTION_RULES.region.test('eu west 1'));
    assert.ok(OPTION_RULES.profile.test('/Common/clientssl-example') && !OPTION_RULES.profile.test('a b'));
    assert.ok(!OPTION_RULES.site.test('a"b'));
  });
});

describe('deploySnippet', () => {
  test('every platform: known sections in order, notes and warnings from the exported lists, a verify section', () => {
    for (const platform of DEPLOY_PLATFORMS) {
      const s = deploySnippet(platform, INPUT, { vault: 'kv-prod' });
      assert.equal(s.platform, platform);
      const ids = s.sections.map((x) => x.id);
      assert.deepEqual(ids, SNIPPET_SECTIONS.filter((id) => ids.includes(id)), `${platform}: ${ids}`);
      assert.equal(ids[ids.length - 1], 'verify', platform);
      for (const n of s.notes) assert.ok(SNIPPET_NOTES.includes(n), `${platform} note ${n}`);
      for (const w of s.warnings) assert.ok(SNIPPET_WARNINGS.includes(w.code), `${platform} warning ${w.code}`);
      assert.ok(s.sections.every((x) => x.lines.length && x.lines.every((l) => typeof l === 'string' && !/[\r\n]/.test(l))), platform);
      assert.deepEqual(s.warnings, [], `${platform}: ${JSON.stringify(s.warnings)}`);
    }
    assert.equal(deploySnippet('lighttpd', INPUT), null);
  });

  test('nginx: file placement, server_name, nginx -t, reload; verify compares the fingerprint per address (IPv6 in brackets)', () => {
    const s = deploySnippet('nginx', INPUT);
    assert.equal(s.shell, 'sh');
    assert.match(sec(s, 'files'), /^scp 'star\.example\.com-20261001\.fullchain\.pem' 'star\.example\.com-20261001\.key' 'web01:\/tmp\/'$/m);
    assert.match(sec(s, 'install'), /sudo install -m 0600 '\/tmp\/star\.example\.com-20261001\.key' '\/etc\/nginx\/ssl\/star\.example\.com-20261001\.key'/);
    assert.match(sec(s, 'config'), /server_name www\.example\.com \*\.example\.com api\.example\.com;/);
    assert.match(sec(s, 'config'), /ssl_certificate {5}\/etc\/nginx\/ssl\/star\.example\.com-20261001\.fullchain\.pem;/);
    assert.equal(sec(s, 'test'), 'sudo nginx -t');
    assert.equal(sec(s, 'reload'), 'sudo systemctl reload nginx');
    const v = sec(s, 'verify');
    assert.ok(v.includes(`# sha256 Fingerprint=${colonFingerprint(FP)}`));
    assert.ok(v.includes(`echo | openssl s_client -connect '192.0.2.10:443' -servername 'www.example.com' 2>/dev/null | openssl x509 -noout -fingerprint -sha256 | grep -qiE '${colonFingerprint(FP)}' && echo 'OK 192.0.2.10:443' || echo 'NOT THE NEW CERTIFICATE 192.0.2.10:443'`));
    assert.ok(v.includes("-connect '[2001:db8::10]:8443'"));
    assert.ok(v.includes("curl --resolve 'www.example.com:443:192.0.2.10' -sS -o /dev/null -w '%{http_code} %{ssl_verify_result}\\n' 'https://www.example.com:443/'"));
    assert.ok(v.includes("curl --resolve 'www.example.com:8443:[2001:db8::10]'"));
    assert.ok(s.notes.includes('key-yours') && s.notes.includes('verify-anywhere'));
  });

  test('two key types (RSA + ECDSA twins): either fingerprint is the new certificate', () => {
    const v = sec(deploySnippet('apache', { ...INPUT, fingerprints: [FP, FP2.toUpperCase(), FP] }), 'verify');
    assert.ok(v.includes(`grep -qiE '${colonFingerprint(FP)}|${colonFingerprint(FP2)}'`), v);
  });

  test('untrusted names from CT / zone files never reach a command: left out and counted', () => {
    const evil = ["x'$(touch /tmp/pwned).example.com", 'a;rm -rf ~.example.com', 'www.example.com\nid', '`id`.example.com', 'www.example.com'];
    for (const platform of DEPLOY_PLATFORMS) {
      const s = deploySnippet(platform, { ...INPUT, names: evil }, { vault: 'kv-prod' });
      const text = all(s);
      assert.ok(!/pwned|rm -rf|`id`|\nid/.test(text), `${platform}: ${text}`);
      assert.deepEqual(s.warnings.find((w) => w.code === 'unsafe-name'), { code: 'unsafe-name', count: 4 }, platform);
    }
  });

  test('a crafted server name is not used as the ssh destination: the first address is', () => {
    const s = deploySnippet('nginx', { ...INPUT, server: { name: "web01'; curl evil" } });
    assert.match(sec(s, 'files'), /^ssh '192\.0\.2\.10'$/m);
    assert.ok(!all(s).includes('curl evil'));
    assert.ok(s.warnings.some((w) => w.code === 'unsafe-server'));
  });

  test('bad addresses and ports are dropped; no address and no name are warnings, the snippet stays usable', () => {
    const s = deploySnippet('haproxy', { ...INPUT, targets: [{ ip: '192.0.2.10; id', port: 443 }, { ip: '192.0.2.20', port: 70000 }], names: ['*.example.com'] });
    assert.ok(sec(s, 'verify').includes("-connect '192.0.2.20:443'"), 'an invalid port falls back to 443');
    assert.ok(!all(s).includes('; id'));
    assert.ok(s.warnings.some((w) => w.code === 'no-name'), 'a wildcard alone gives no SNI name');
    const none = deploySnippet('haproxy', { ...INPUT, targets: [], names: [] });
    assert.ok(none.warnings.some((w) => w.code === 'no-address') && none.warnings.some((w) => w.code === 'no-name'));
    assert.match(sec(none, 'verify'), /openssl s_client -connect 'example\.com:443'/);
    assert.ok(deploySnippet('nginx', { ...INPUT, fingerprints: ['nope'] }).warnings.some((w) => w.code === 'bad-fingerprint'));
  });

  test('at most MAX_VERIFY_TARGETS addresses get a verify line; the rest are counted', () => {
    const targets = Array.from({ length: MAX_VERIFY_TARGETS + 3 }, (_, i) => ({ ip: `198.51.100.${i + 1}`, port: 443 }));
    const s = deploySnippet('nginx', { ...INPUT, targets });
    assert.equal(sec(s, 'verify').split('\n').filter((l) => l.startsWith('echo | openssl')).length, MAX_VERIFY_TARGETS);
    assert.deepEqual(s.warnings.find((w) => w.code === 'too-many'), { code: 'too-many', count: 3 });
  });

  test('HAProxy: one combined PEM (certificate, intermediates, key), mode 0600, haproxy -c', () => {
    const s = deploySnippet('haproxy', INPUT);
    assert.equal(sec(s, 'combine'), "cat 'star.example.com-20261001.fullchain.pem' 'star.example.com-20261001.key' > 'star.example.com-20261001.pem'");
    assert.match(sec(s, 'install'), /install -m 0600 '\/tmp\/star\.example\.com-20261001\.pem'/);
    assert.match(sec(s, 'config'), /bind :443 ssl crt \/etc\/haproxy\/certs\/star\.example\.com-20261001\.pem/);
    assert.equal(sec(s, 'test'), 'sudo haproxy -c -f /etc/haproxy/haproxy.cfg');
  });

  test('IIS: PowerShell — Import-PfxCertificate, a binding per port with SNI, the PFX password read as a SecureString; verify without openssl', () => {
    const s = deploySnippet('iis', INPUT, { site: "Bob's \u2019Shop\u2019" });
    assert.equal(s.shell, 'powershell');
    const c = sec(s, 'config');
    assert.ok(c.includes("$pfxPassword = Read-Host -AsSecureString -Prompt 'PFX password'"));
    assert.ok(c.includes("Import-PfxCertificate -FilePath 'C:\\certs\\star.example.com-20261001.pfx' -CertStoreLocation 'Cert:\\LocalMachine\\My' -Password $pfxPassword"));
    assert.ok(c.includes("New-WebBinding -Name 'Bob''s \u2019\u2019Shop\u2019\u2019' -Protocol https -Port 443 -HostHeader 'www.example.com' -SslFlags 1"), c);
    assert.ok(c.includes("$binding.AddSslCertificate($cert.Thumbprint, 'My')"));
    assert.ok(c.includes('-Port 8443'));
    const v = sec(s, 'verify');
    assert.ok(v.startsWith(`$expected = @('${FP.toUpperCase()}')`));
    assert.ok(v.includes("[System.Net.Sockets.TcpClient]::new('2001:db8::10', 8443)"));
    assert.ok(v.includes("$ssl.AuthenticateAsClient('www.example.com')"));
    assert.ok(v.includes('GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)'));
    assert.ok(v.includes("curl.exe --resolve 'www.example.com:443:192.0.2.10'"));
    assert.ok(!/openssl/.test(v));
    assert.deepEqual(deploySnippet('iis', INPUT, { site: 'a"b' }).warnings, [{ code: 'bad-option', field: 'site' }]);
  });

  test('Tomcat: a PKCS12 keystore from the PEM files, the SSLHostConfig, configtest, restart', () => {
    const s = deploySnippet('tomcat', INPUT);
    assert.equal(sec(s, 'combine'), "openssl pkcs12 -export -in 'star.example.com-20261001.crt' -inkey 'star.example.com-20261001.key' -certfile 'star.example.com-20261001.chain.pem' -name tomcat -out 'star.example.com-20261001.p12'");
    assert.match(sec(s, 'config'), /<SSLHostConfig hostName="www\.example\.com">/);
    assert.match(sec(s, 'config'), /certificateKeystoreType="PKCS12"/);
    assert.match(sec(s, 'test'), /keytool -list -storetype PKCS12/);
    assert.equal(sec(s, 'reload'), 'sudo systemctl restart tomcat');
  });

  test('Kubernetes: kubectl create secret tls … --dry-run=client -o yaml | kubectl apply -f -, names validated', () => {
    const s = deploySnippet('kubernetes', INPUT, { namespace: 'web', secret: 'example-tls' });
    assert.equal(sec(s, 'install'), "kubectl create secret tls 'example-tls' --cert='star.example.com-20261001.fullchain.pem' --key='star.example.com-20261001.key' --namespace 'web' --dry-run=client -o yaml | kubectl apply -f -");
    assert.match(sec(s, 'config'), /secretName: example-tls/);
    assert.match(sec(s, 'test'), /jsonpath='\{\.data\.tls\\\.crt\}' \| base64 -d \| openssl x509 -noout -fingerprint -sha256/);
    const bad = deploySnippet('kubernetes', INPUT, { namespace: 'Web Prod', secret: "x'y" });
    assert.match(sec(bad, 'install'), /secret tls 'tls-star-example-com-20261001' .* --namespace 'default'/);
    assert.deepEqual(bad.warnings, [{ code: 'bad-option', field: 'namespace' }, { code: 'bad-option', field: 'secret' }]);
  });

  test('Traefik and Caddy: the files and the configuration lines, with their notes', () => {
    const tr = deploySnippet('traefik', INPUT);
    assert.match(sec(tr, 'config'), /certFile: \/etc\/traefik\/certs\/star\.example\.com-20261001\.fullchain\.pem/);
    assert.ok(tr.notes.includes('traefik-watch') && tr.notes.includes('traefik-acme'));
    const ca = deploySnippet('caddy', INPUT);
    assert.match(sec(ca, 'config'), /^www\.example\.com, \*\.example\.com, api\.example\.com \{$/m);
    assert.equal(sec(ca, 'test'), 'caddy validate --config /etc/caddy/Caddyfile');
    assert.ok(ca.notes.includes('caddy-auto'));
  });

  test('AWS ACM: import, or reimport with the ARN (its region taken from it); a bad ARN imports anew', () => {
    const arn = 'arn:aws:acm:eu-west-1:123456789012:certificate/12345678-1234-1234-1234-123456789012';
    const re = deploySnippet('aws-acm', INPUT, { arn });
    assert.equal(sec(re, 'install'), `aws acm import-certificate --certificate-arn '${arn}' --certificate 'fileb://star.example.com-20261001.crt' --private-key 'fileb://star.example.com-20261001.key' --certificate-chain 'fileb://star.example.com-20261001.chain.pem' --region 'eu-west-1'`);
    assert.ok(re.notes.includes('acm-reimport'));
    const fresh = deploySnippet('aws-acm', INPUT, { arn: "arn:aws:acm:x'; id" });
    assert.match(sec(fresh, 'install'), /^aws acm import-certificate --certificate 'fileb:/);
    assert.ok(fresh.notes.includes('acm-new') && fresh.notes.includes('acm-region'));
    assert.deepEqual(fresh.warnings, [{ code: 'bad-option', field: 'arn' }]);
  });

  test('Azure Key Vault: import of the PFX, the password read without echo; a missing vault is a quoted placeholder', () => {
    const s = deploySnippet('azure-keyvault', INPUT, { vault: 'kv-prod' });
    assert.ok(sec(s, 'install').includes(`az keyvault certificate import --vault-name 'kv-prod' --name 'star-example-com-20261001' --file 'star.example.com-20261001.pfx' --password "$PFX_PASSWORD"`));
    assert.match(sec(s, 'install'), /^read -rs /);
    const none = deploySnippet('azure-keyvault', INPUT, {});
    assert.ok(sec(none, 'install').includes("--vault-name 'VAULT-NAME'"));
    assert.deepEqual(none.warnings, [{ code: 'missing-option', field: 'vault' }]);
  });

  test('F5 BIG-IP: tmsh install of the certificate, key and chain, the client-ssl profile, save', () => {
    const s = deploySnippet('f5', INPUT, { profile: '/Common/clientssl-example' });
    assert.match(sec(s, 'install'), /^tmsh install sys crypto cert star\.example\.com-20261001 from-local-file \/var\/tmp\/star\.example\.com-20261001\.crt$/m);
    assert.equal(sec(s, 'config'), 'tmsh modify ltm profile client-ssl /Common/clientssl-example cert-key-chain replace-all-with { default { cert star.example.com-20261001 key star.example.com-20261001 chain star.example.com-20261001-chain } }');
    assert.match(sec(s, 'reload'), /^tmsh save sys config$/m);
    assert.match(sec(deploySnippet('f5', { ...INPUT, certName: '1.example.com' }), 'install'), /cert c-1\.example\.com-20261001 /);
    assert.deepEqual(deploySnippet('f5', INPUT, { profile: 'a b; tmsh delete' }).warnings, [{ code: 'bad-option', field: 'profile' }]);
  });
});
