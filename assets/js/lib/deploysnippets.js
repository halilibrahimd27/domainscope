/**
 * lib/deploysnippets.js — per-server deploy snippets for a new certificate (the SSL Targets
 * Rollout tab, ui/rollout-panel.js): where the files go, the configuration lines, a config test
 * and reload, and a check that the server now serves the new certificate, for nginx, Apache httpd,
 * HAProxy, IIS, Tomcat, a Kubernetes TLS secret, Traefik, Caddy, AWS ACM, Azure Key Vault and an F5
 * BIG-IP.
 *
 * Every value put into a command is untrusted: host names come from CT logs and zone files, server
 * names from a pasted inventory, options from the tab's fields. Each one is validated for what it
 * is (a host name, an address, a port, a fingerprint, a Kubernetes or Azure name) and then quoted
 * for its shell anyway: POSIX single quotes ({@link shQuote}) or PowerShell single quotes
 * ({@link psQuote}). A value that fails is left out (a host name) or replaced by a quoted
 * placeholder to edit (an option), and the snippet says so in `warnings`. Control characters are
 * never quoted: they are refused.
 *
 * DOM-free and i18n-free: sections, notes and warnings are codes (the panel words them); the
 * commands themselves are the text to copy.
 */

import { ipVersion, normalizeIP } from './ip.js';

/** The platforms, in the order the panel offers them. */
export const DEPLOY_PLATFORMS = Object.freeze(['nginx', 'apache', 'haproxy', 'iis', 'tomcat', 'kubernetes', 'traefik',
  'caddy', 'aws-acm', 'azure-keyvault', 'f5']);
/** The sections of a snippet, in order (each present at most once). */
export const SNIPPET_SECTIONS = Object.freeze(['combine', 'files', 'install', 'config', 'test', 'reload', 'verify']);
/** Notes a snippet can carry (`ro.note.<code>`). */
export const SNIPPET_NOTES = Object.freeze(['key-yours', 'paths', 'pfx', 'p12', 'k8s-reload', 'traefik-watch',
  'traefik-acme', 'caddy-auto', 'acm-reimport', 'acm-new', 'acm-region', 'kv-pfx', 'kv-consumers', 'f5-sync', 'iis-live',
  'verify-anywhere', 'verify-sni']);
/** Warnings a snippet can carry (`ro.warn.<code>`): what was left out or replaced. */
export const SNIPPET_WARNINGS = Object.freeze(['unsafe-name', 'unsafe-server', 'no-name', 'no-address', 'bad-option',
  'missing-option', 'bad-fingerprint', 'too-many']);
/** The options each platform takes from the tab's fields (validated by {@link OPTION_RULES}). */
export const PLATFORM_OPTIONS = Object.freeze({
  nginx: [], apache: [], haproxy: [], iis: ['site'], tomcat: [], kubernetes: ['namespace', 'secret'], traefik: [], caddy: [],
  'aws-acm': ['arn', 'region'], 'azure-keyvault': ['vault', 'certName'], f5: ['profile']
});
/** At most this many addresses get a verify line (the rest: a warning). */
export const MAX_VERIFY_TARGETS = 16;
/** At most this many names go into a configuration line. */
export const MAX_CONFIG_NAMES = 50;

// C0, DEL, C1 and the Unicode line / paragraph separators: never quoted, refused.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
// PowerShell ends a single-quoted string at any of these (and doubles them to escape).
const PS_QUOTES_RE = /['\u2018\u2019\u201a\u201b]/g;
const LABEL_RE = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;

/**
 * A value as one POSIX shell word: single quotes, an embedded `'` written as `'\''`. Nothing is
 * expanded inside (no `$`, backquote, `\` or glob).
 * @param {unknown} value
 * @returns {string|null} null for a value with a control character (or none at all)
 */
export function shQuote(value) {
  if (value === null || value === undefined) return null;
  const s = String(value);
  if (CONTROL_RE.test(s)) return null;
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * A value as one PowerShell string: single quotes (no `$` or backtick expansion), every quote
 * character PowerShell ends a single-quoted string at (`'` and the typographic ‘ ’ ‚ ‛) doubled.
 * @param {unknown} value
 * @returns {string|null} null for a value with a control character (or none at all)
 */
export function psQuote(value) {
  if (value === null || value === undefined) return null;
  const s = String(value);
  if (CONTROL_RE.test(s)) return null;
  return `'${s.replace(PS_QUOTES_RE, (q) => q + q)}'`;
}

/**
 * A DNS host name as it may appear in a snippet (lowercased): letters, digits, `-` and `_` in
 * labels of 1–63 characters, at most 253 characters, an optional `*.` in front when `wildcard`.
 * IDNs only in their xn-- form.
 * @param {unknown} name
 * @param {{ wildcard?: boolean }} [opts]
 * @returns {string|null}
 */
export function safeHostname(name, { wildcard = false } = {}) {
  if (typeof name !== 'string') return null;
  let s = name.trim().toLowerCase().replace(/\.$/, '');
  let star = '';
  if (wildcard && s.startsWith('*.')) {
    star = '*.';
    s = s.slice(2);
  }
  if (!s || s.length > 253 - star.length) return null;
  const labels = s.split('.');
  if (labels.length < 1 || !labels.every((l) => LABEL_RE.test(l))) return null;
  return star + s;
}

/**
 * An address as one canonical IPv4 / IPv6 literal, or null.
 * @param {unknown} ip
 * @returns {string|null}
 */
export function safeAddress(ip) {
  const n = typeof ip === 'string' ? normalizeIP(ip.trim()) : null;
  return n && ipVersion(n) ? n : null;
}

/**
 * A SHA-256 fingerprint as lowercase hex (colons, spaces and case ignored), or null.
 * @param {unknown} fp
 * @returns {string|null}
 */
export function safeFingerprint(fp) {
  const s = typeof fp === 'string' ? fp.replace(/[:\s]/g, '').toLowerCase() : '';
  return FINGERPRINT_RE.test(s) ? s : null;
}

/** `AB:CD:…` as OpenSSL prints a fingerprint. */
export function colonFingerprint(hex) {
  return hex.toUpperCase().match(/../g).join(':');
}

/**
 * A file-name stem for the certificate's files: its first name (`*.` written `star.`), only
 * `a-z0-9.-`, at most 80 characters, plus the date it starts (`-YYYYMMDD`) so the new files sit
 * next to the old ones.
 * @param {unknown} name
 * @param {Date|null} [notBefore]
 * @returns {string}
 */
export function fileStem(name, notBefore = null) {
  const raw = typeof name === 'string' ? name.trim().toLowerCase().replace(/^\*\./, 'star.') : '';
  const base = raw.replace(/[^a-z0-9.-]+/g, '-').replace(/^[.-]+|[.-]+$/g, '').slice(0, 80).replace(/[.-]+$/, '') || 'certificate';
  const d = notBefore instanceof Date && !Number.isNaN(notBefore.getTime()) ? notBefore.toISOString().slice(0, 10).replace(/-/g, '') : '';
  return d ? `${base}-${d}` : base;
}

/** The validation of each option: a test and the default when it is empty. */
export const OPTION_RULES = Object.freeze({
  // IIS site names: printable, no control characters, quoted for PowerShell.
  site: { test: (v) => v.length <= 260 && !/[\\/?*"<>|]/.test(v), fallback: () => 'Default Web Site' },
  // Kubernetes: a namespace is a DNS-1123 label, a secret name a DNS-1123 subdomain.
  namespace: { test: (v) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(v), fallback: () => 'default' },
  secret: {
    test: (v) => v.length <= 253 && v.split('.').every((l) => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(l)),
    fallback: (ctx) => `tls-${ctx.stem.replace(/\./g, '-')}`.slice(0, 253).replace(/-+$/, '')
  },
  arn: { test: (v) => /^arn:aws(-cn|-us-gov)?:acm:[a-z0-9-]+:\d{12}:certificate\/[0-9a-f-]{36}$/.test(v), fallback: () => null },
  region: { test: (v) => /^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d{1,2}$/.test(v), fallback: () => null },
  // Azure Key Vault: a vault name is 3–24 letters, digits and hyphens starting with a letter; a
  // certificate name 1–127 letters, digits and hyphens.
  vault: { test: (v) => /^[A-Za-z](?!.*--)[A-Za-z0-9-]{1,22}[A-Za-z0-9]$/.test(v), fallback: () => null },
  certName: { test: (v) => /^[A-Za-z0-9-]{1,127}$/.test(v), fallback: (ctx) => ctx.stem.replace(/\./g, '-').slice(0, 127) },
  // F5 object names, with an optional /Partition/ in front.
  profile: { test: (v) => /^(\/[A-Za-z0-9_.-]{1,64}\/)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(v), fallback: (ctx) => `clientssl-${ctx.stem}`.slice(0, 128) }
});

/**
 * The options of one platform, validated: a valid value is kept, an empty one takes its default,
 * an invalid one too (with a 'bad-option' warning). A required one without a default stays null
 * ('missing-option' when the platform needs it).
 */
function readOptions(platform, options, ctx, warnings) {
  const out = {};
  for (const key of PLATFORM_OPTIONS[platform] || []) {
    const raw = options && typeof options[key] === 'string' ? options[key].trim() : '';
    const rule = OPTION_RULES[key];
    if (raw && !CONTROL_RE.test(raw) && rule.test(raw)) out[key] = raw;
    else {
      if (raw) warnings.push({ code: 'bad-option', field: key });
      out[key] = rule.fallback(ctx);
    }
  }
  return out;
}

/**
 * @typedef {object} SnippetInput
 * @property {{ name?: string }|null} [server] the inventory server (null: an address outside it)
 * @property {Array<{ ip: string, port?: number }>} targets where it serves the names
 * @property {string[]} names the names it serves from this certificate (concrete or wildcard)
 * @property {string[]} fingerprints SHA-256 of the new certificate(s) (one per key type)
 * @property {string} [certName] the certificate's first name (for the file names)
 * @property {Date|null} [notBefore]
 */

/**
 * @typedef {object} Snippet
 * @property {string} platform
 * @property {'sh'|'powershell'} shell the shell the commands are written for (verify: sh too)
 * @property {Array<{ id: string, shell: 'sh'|'powershell'|'config', lines: string[] }>} sections
 * @property {string[]} notes {@link SNIPPET_NOTES}
 * @property {Array<{ code: string, count?: number, field?: string }>} warnings {@link SNIPPET_WARNINGS}
 * @property {{ stem: string, cert: string, chain: string, fullchain: string, key: string, combined: string, pfx: string, p12: string }} files
 */

/**
 * The deploy snippet of one server for one platform.
 * @param {string} platform one of {@link DEPLOY_PLATFORMS}
 * @param {SnippetInput} input
 * @param {Record<string, string>} [options] the platform's {@link PLATFORM_OPTIONS} as typed
 * @returns {Snippet|null} null for an unknown platform
 */
export function deploySnippet(platform, input, options = {}) {
  if (!DEPLOY_PLATFORMS.includes(platform)) return null;
  const warnings = [];
  const src = input && typeof input === 'object' ? input : {};
  const stem = fileStem(safeHostname(src.certName, { wildcard: true }) || 'certificate', src.notBefore || null);
  const files = {
    stem, cert: `${stem}.crt`, chain: `${stem}.chain.pem`, fullchain: `${stem}.fullchain.pem`, key: `${stem}.key`,
    combined: `${stem}.pem`, pfx: `${stem}.pfx`, p12: `${stem}.p12`
  };

  // Names: valid ones kept (wildcards for the configuration only), the rest left out and counted.
  const rawNames = Array.isArray(src.names) ? src.names : [];
  const names = [];
  let unsafe = 0;
  for (const n of rawNames) {
    const ok = safeHostname(n, { wildcard: true });
    if (!ok) unsafe += 1;
    else if (!names.includes(ok)) names.push(ok);
  }
  if (unsafe) warnings.push({ code: 'unsafe-name', count: unsafe });
  const concrete = names.filter((n) => !n.startsWith('*.'));
  if (!concrete.length) warnings.push({ code: 'no-name' });
  const configNames = names.slice(0, MAX_CONFIG_NAMES);

  // Addresses and ports.
  const targets = [];
  for (const t of Array.isArray(src.targets) ? src.targets : []) {
    const ip = safeAddress(t && t.ip);
    const port = Number.isInteger(t && t.port) && t.port > 0 && t.port < 65536 ? t.port : 443;
    if (ip && !targets.some((x) => x.ip === ip && x.port === port)) targets.push({ ip, port });
  }
  if (!targets.length) warnings.push({ code: 'no-address' });

  const fps = [];
  for (const f of Array.isArray(src.fingerprints) ? src.fingerprints : []) {
    const ok = safeFingerprint(f);
    if (ok && !fps.includes(ok)) fps.push(ok);
  }
  if (!fps.length) warnings.push({ code: 'bad-fingerprint' });

  // The server as an ssh / scp destination: a host name or an address, else a placeholder.
  const serverName = src.server && typeof src.server.name === 'string' ? src.server.name : '';
  let sshHost = safeHostname(serverName) || safeAddress(serverName) || (targets[0] && targets[0].ip) || null;
  if (serverName && !safeHostname(serverName) && !safeAddress(serverName)) warnings.push({ code: 'unsafe-server' });
  if (!sshHost) sshHost = 'SERVER';

  const ctx = { stem, files, names: configNames, concrete, targets, fps, sshHost, opts: null, notes: [] };
  ctx.opts = readOptions(platform, options, ctx, warnings);
  const built = BUILDERS[platform](ctx, warnings);
  const verify = platform === 'iis' ? verifyPowerShell(ctx) : verifyPosix(ctx);
  if (targets.length > MAX_VERIFY_TARGETS) warnings.push({ code: 'too-many', count: targets.length - MAX_VERIFY_TARGETS });
  const sections = [...built.sections, ...verify];
  const notes = [...new Set([...ctx.notes, ...(platform === 'iis' ? [] : ['verify-anywhere']), 'verify-sni'])];
  return { platform, shell: built.shell, sections, notes, warnings: dedupeWarnings(warnings), files };
}

function dedupeWarnings(list) {
  const seen = new Set();
  return list.filter((w) => {
    const k = `${w.code}|${w.field || ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const q = shQuote;
/** `host:port` for openssl -connect (an IPv6 address in brackets). */
const hostPort = (ip, port) => (ipVersion(ip) === 6 ? `[${ip}]:${port}` : `${ip}:${port}`);
/** The first concrete name served at an address (any concrete name of the server otherwise). */
const sniFor = (ctx) => ctx.concrete[0] || null;

const section = (id, shell, lines) => ({ id, shell, lines });

/** Copy the files to the server (from your machine), then install them there with the right modes. */
function placeFiles(ctx, dir, list) {
  const copy = [`scp ${list.map((f) => q(f)).join(' ')} ${q(`${ctx.sshHost}:/tmp/`)}`, `ssh ${q(ctx.sshHost)}`];
  const install = [`sudo install -d -m 0755 ${q(dir)}`];
  for (const f of list) {
    const secret = f.endsWith('.key') || f.endsWith('.pfx') || f.endsWith('.p12') || f === ctx.files.combined;
    install.push(`sudo install -m ${secret ? '0600' : '0644'} ${q(`/tmp/${f}`)} ${q(`${dir}/${f}`)}`);
  }
  install.push(`rm -f ${list.map((f) => q(`/tmp/${f}`)).join(' ')}`);
  return [section('files', 'sh', copy), section('install', 'sh', install)];
}

const BUILDERS = {
  nginx(ctx) {
    const dir = '/etc/nginx/ssl';
    ctx.notes.push('key-yours', 'paths');
    return {
      shell: 'sh',
      sections: [
        ...placeFiles(ctx, dir, [ctx.files.fullchain, ctx.files.key]),
        section('config', 'config', [
          'server {',
          '    listen 443 ssl;',
          ...(ctx.names.length ? [`    server_name ${ctx.names.join(' ')};`] : []),
          `    ssl_certificate     ${dir}/${ctx.files.fullchain};`,
          `    ssl_certificate_key ${dir}/${ctx.files.key};`,
          '}'
        ]),
        section('test', 'sh', ['sudo nginx -t']),
        section('reload', 'sh', ['sudo systemctl reload nginx'])
      ]
    };
  },
  apache(ctx) {
    const dir = '/etc/ssl/domainscope';
    ctx.notes.push('key-yours', 'paths');
    return {
      shell: 'sh',
      sections: [
        ...placeFiles(ctx, dir, [ctx.files.fullchain, ctx.files.key]),
        section('config', 'config', [
          '<VirtualHost *:443>',
          ...(ctx.concrete.length ? [`    ServerName ${ctx.concrete[0]}`] : []),
          ...(ctx.names.filter((n) => n !== ctx.concrete[0]).length ? [`    ServerAlias ${ctx.names.filter((n) => n !== ctx.concrete[0]).join(' ')}`] : []),
          '    SSLEngine on',
          `    SSLCertificateFile    ${dir}/${ctx.files.fullchain}`,
          `    SSLCertificateKeyFile ${dir}/${ctx.files.key}`,
          '</VirtualHost>'
        ]),
        section('test', 'sh', ['sudo apachectl configtest']),
        section('reload', 'sh', ['sudo apachectl graceful'])
      ]
    };
  },
  haproxy(ctx) {
    const dir = '/etc/haproxy/certs';
    ctx.notes.push('key-yours', 'paths');
    const combined = `${dir}/${ctx.files.combined}`;
    return {
      shell: 'sh',
      sections: [
        section('combine', 'sh', [`cat ${q(ctx.files.fullchain)} ${q(ctx.files.key)} > ${q(ctx.files.combined)}`]),
        ...placeFiles(ctx, dir, [ctx.files.combined]),
        section('config', 'config', ['frontend https', `    bind :443 ssl crt ${combined}`]),
        section('test', 'sh', ['sudo haproxy -c -f /etc/haproxy/haproxy.cfg']),
        section('reload', 'sh', ['sudo systemctl reload haproxy'])
      ]
    };
  },
  iis(ctx) {
    ctx.notes.push('pfx', 'iis-live');
    const p = psQuote;
    const site = p(ctx.opts.site);
    const host = ctx.concrete[0] || '';
    const lines = [
      `$pfxPassword = Read-Host -AsSecureString -Prompt ${p('PFX password')}`,
      `$cert = Import-PfxCertificate -FilePath ${p(`C:\\certs\\${ctx.files.pfx}`)} -CertStoreLocation 'Cert:\\LocalMachine\\My' -Password $pfxPassword`,
      'Import-Module WebAdministration'
    ];
    for (const t of ctx.targets.length ? ctx.targets.slice(0, MAX_VERIFY_TARGETS) : [{ ip: null, port: 443 }]) {
      const bind = `-Name ${site} -Protocol https -Port ${t.port}${host ? ` -HostHeader ${p(host)}` : ''}`;
      lines.push(`if (-not (Get-WebBinding ${bind})) { New-WebBinding ${bind}${host ? ' -SslFlags 1' : ''} }`,
        `$binding = Get-WebBinding ${bind}`, 'try { $binding.RemoveSslCertificate() } catch { }',
        "$binding.AddSslCertificate($cert.Thumbprint, 'My')");
    }
    return {
      shell: 'powershell',
      sections: [
        section('files', 'powershell', ["New-Item -ItemType Directory -Force -Path 'C:\\certs' | Out-Null",
          `Copy-Item -Path ${p(`.\\${ctx.files.pfx}`)} -Destination 'C:\\certs\\'`]),
        section('config', 'powershell', lines),
        section('test', 'powershell', [
          "Get-ChildItem 'Cert:\\LocalMachine\\My' | Where-Object Thumbprint -eq $cert.Thumbprint | Format-List Subject, NotAfter, Thumbprint",
          `Get-WebBinding -Name ${site} -Protocol https | Format-Table bindingInformation, certificateHash`
        ])
      ]
    };
  },
  tomcat(ctx) {
    ctx.notes.push('key-yours', 'p12', 'paths');
    const dir = '/opt/tomcat/conf';
    return {
      shell: 'sh',
      sections: [
        section('combine', 'sh', [`openssl pkcs12 -export -in ${q(ctx.files.cert)} -inkey ${q(ctx.files.key)} -certfile ${q(ctx.files.chain)} -name tomcat -out ${q(ctx.files.p12)}`]),
        ...placeFiles(ctx, dir, [ctx.files.p12]),
        section('config', 'config', [
          `<SSLHostConfig${ctx.concrete.length ? ` hostName="${ctx.concrete[0]}"` : ''}>`,
          `    <Certificate certificateKeystoreFile="conf/${ctx.files.p12}" certificateKeystoreType="PKCS12"`,
          '                 certificateKeystorePassword="${keystore.password}" />',
          '</SSLHostConfig>'
        ]),
        section('test', 'sh', [`sudo keytool -list -storetype PKCS12 -keystore ${q(`${dir}/${ctx.files.p12}`)}`, 'sudo /opt/tomcat/bin/configtest.sh']),
        section('reload', 'sh', ['sudo systemctl restart tomcat'])
      ]
    };
  },
  kubernetes(ctx) {
    ctx.notes.push('key-yours', 'k8s-reload');
    const ns = q(ctx.opts.namespace);
    const secret = q(ctx.opts.secret);
    return {
      shell: 'sh',
      sections: [
        section('install', 'sh', [`kubectl create secret tls ${secret} --cert=${q(ctx.files.fullchain)} --key=${q(ctx.files.key)} --namespace ${ns} --dry-run=client -o yaml | kubectl apply -f -`]),
        section('config', 'config', ['spec:', '  tls:', '    - hosts:', ...ctx.names.map((n) => `        - ${JSON.stringify(n)}`),
          `      secretName: ${ctx.opts.secret}`]),
        section('test', 'sh', [`kubectl get secret ${secret} --namespace ${ns} -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -fingerprint -sha256 -enddate`])
      ]
    };
  },
  traefik(ctx) {
    ctx.notes.push('key-yours', 'traefik-watch', 'traefik-acme', 'paths');
    const dir = '/etc/traefik/certs';
    return {
      shell: 'sh',
      sections: [
        ...placeFiles(ctx, dir, [ctx.files.fullchain, ctx.files.key]),
        section('config', 'config', ['tls:', '  certificates:', `    - certFile: ${dir}/${ctx.files.fullchain}`, `      keyFile: ${dir}/${ctx.files.key}`])
      ]
    };
  },
  caddy(ctx) {
    ctx.notes.push('key-yours', 'caddy-auto', 'paths');
    const dir = '/etc/caddy/certs';
    return {
      shell: 'sh',
      sections: [
        ...placeFiles(ctx, dir, [ctx.files.fullchain, ctx.files.key]),
        section('config', 'config', [`${ctx.names.length ? ctx.names.join(', ') : 'example.com'} {`, `    tls ${dir}/${ctx.files.fullchain} ${dir}/${ctx.files.key}`, '}']),
        section('test', 'sh', ['caddy validate --config /etc/caddy/Caddyfile']),
        section('reload', 'sh', ['sudo systemctl reload caddy'])
      ]
    };
  },
  'aws-acm'(ctx) {
    const arn = ctx.opts.arn;
    const region = ctx.opts.region || (arn ? arn.split(':')[3] : null);
    ctx.notes.push('key-yours', arn ? 'acm-reimport' : 'acm-new');
    if (!region) ctx.notes.push('acm-region');
    const reg = region ? ` --region ${q(region)}` : '';
    const files = `--certificate ${q(`fileb://${ctx.files.cert}`)} --private-key ${q(`fileb://${ctx.files.key}`)} --certificate-chain ${q(`fileb://${ctx.files.chain}`)}`;
    return {
      shell: 'sh',
      sections: [
        section('install', 'sh', [arn
          ? `aws acm import-certificate --certificate-arn ${q(arn)} ${files}${reg}`
          : `aws acm import-certificate ${files}${reg} --query CertificateArn --output text`]),
        section('test', 'sh', [`aws acm describe-certificate --certificate-arn ${arn ? q(arn) : "'ARN'"}${reg} --query 'Certificate.[Status,NotAfter,InUseBy]'`])
      ]
    };
  },
  'azure-keyvault'(ctx, warnings) {
    ctx.notes.push('kv-pfx', 'kv-consumers');
    const vault = ctx.opts.vault;
    if (!vault) warnings.push({ code: 'missing-option', field: 'vault' });
    const v = vault ? q(vault) : "'VAULT-NAME'";
    const name = q(ctx.opts.certName);
    return {
      shell: 'sh',
      sections: [
        section('install', 'sh', ['read -rs -p \'PFX password: \' PFX_PASSWORD; echo',
          `az keyvault certificate import --vault-name ${v} --name ${name} --file ${q(ctx.files.pfx)} --password "$PFX_PASSWORD"`]),
        section('test', 'sh', [`az keyvault certificate show --vault-name ${v} --name ${name} --query cer -o tsv | base64 -d | openssl x509 -inform DER -noout -fingerprint -sha256 -enddate`])
      ]
    };
  },
  f5(ctx) {
    ctx.notes.push('key-yours', 'f5-sync');
    // Object names from the file stem: letters, digits, . - _ only (tmsh needs no quoting then).
    const obj = /^[a-z]/.test(ctx.stem) ? ctx.stem : `c-${ctx.stem}`;
    const profile = ctx.opts.profile;
    return {
      shell: 'sh',
      sections: [
        section('files', 'sh', [`scp ${q(ctx.files.cert)} ${q(ctx.files.key)} ${q(ctx.files.chain)} ${q(`${ctx.sshHost}:/var/tmp/`)}`, `ssh ${q(ctx.sshHost)}`]),
        section('install', 'sh', [`tmsh install sys crypto cert ${obj} from-local-file /var/tmp/${ctx.files.cert}`,
          `tmsh install sys crypto key ${obj} from-local-file /var/tmp/${ctx.files.key}`,
          `tmsh install sys crypto cert ${obj}-chain from-local-file /var/tmp/${ctx.files.chain}`]),
        section('config', 'sh', [`tmsh modify ltm profile client-ssl ${profile} cert-key-chain replace-all-with { default { cert ${obj} key ${obj} chain ${obj}-chain } }`]),
        section('test', 'sh', [`tmsh list sys crypto cert ${obj}`, `tmsh list ltm profile client-ssl ${profile} cert-key-chain`]),
        section('reload', 'sh', ['tmsh save sys config', `rm -f /var/tmp/${ctx.files.cert} /var/tmp/${ctx.files.key} /var/tmp/${ctx.files.chain}`])
      ]
    };
  }
};

/** openssl s_client per address, compared with the expected fingerprint(s); curl --resolve per address. */
function verifyPosix(ctx) {
  const sni = sniFor(ctx);
  const lines = [];
  const pattern = ctx.fps.map(colonFingerprint).join('|');
  for (const t of ctx.targets.slice(0, MAX_VERIFY_TARGETS)) {
    const hp = hostPort(t.ip, t.port);
    const sniArg = sni ? ` -servername ${q(sni)}` : '';
    const fp = `echo | openssl s_client -connect ${q(hp)}${sniArg} 2>/dev/null | openssl x509 -noout -fingerprint -sha256`;
    lines.push(pattern
      ? `${fp} | grep -qiE ${q(pattern)} && echo ${q(`OK ${hp}`)} || echo ${q(`NOT THE NEW CERTIFICATE ${hp}`)}`
      : fp);
    if (sni) {
      const resolveIp = ipVersion(t.ip) === 6 ? `[${t.ip}]` : t.ip;
      lines.push(`curl --resolve ${q(`${sni}:${t.port}:${resolveIp}`)} -sS -o /dev/null -w '%{http_code} %{ssl_verify_result}\\n' ${q(`https://${sni}:${t.port}/`)}`);
    }
  }
  if (!lines.length) lines.push(`echo | openssl s_client -connect ${q(`${sni || 'example.com'}:443`)}${sni ? ` -servername ${q(sni)}` : ''} 2>/dev/null | openssl x509 -noout -fingerprint -sha256`);
  const expected = ctx.fps.map((f) => `# sha256 Fingerprint=${colonFingerprint(f)}`);
  return [section('verify', 'sh', [...expected, ...lines])];
}

/** The same check from Windows PowerShell (no openssl): SslStream, the served certificate's SHA-256. */
function verifyPowerShell(ctx) {
  const p = psQuote;
  const sni = sniFor(ctx);
  const lines = [`$expected = @(${ctx.fps.map((f) => p(f.toUpperCase())).join(', ')})`];
  for (const t of ctx.targets.slice(0, MAX_VERIFY_TARGETS)) {
    const label = hostPort(t.ip, t.port);
    lines.push(`$tcp = [System.Net.Sockets.TcpClient]::new(${p(t.ip)}, ${t.port})`,
      'try {',
      '  $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })',
      `  $ssl.AuthenticateAsClient(${p(sni || t.ip)})`,
      '  $fp = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate).GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)',
      `  if ($expected -contains $fp) { ${p(`OK ${label}`)} } else { ${p(`NOT THE NEW CERTIFICATE ${label}`)}; $fp }`,
      '} finally { $tcp.Dispose() }');
    if (sni) lines.push(`curl.exe --resolve ${p(`${sni}:${t.port}:${ipVersion(t.ip) === 6 ? `[${t.ip}]` : t.ip}`)} -sS -o NUL -w '%{http_code}' ${p(`https://${sni}:${t.port}/`)}`);
  }
  return [section('verify', 'powershell', lines)];
}
