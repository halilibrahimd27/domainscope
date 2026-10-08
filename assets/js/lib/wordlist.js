/**
 * wordlist.js — candidate DNS labels used by the optional name-guessing step
 * of the scanner. The scanner resolves each `<label>.<domain>` over DoH and
 * keeps only names that actually resolve and are not wildcard look-alikes, so
 * this list simply seeds lookups against domains the user already owns.
 *
 * WORDLIST_SMALL  — the most common labels (global infra + a compact core), no I/O.
 * WORDLIST_MEDIUM — ~1000 labels, a strict superset of SMALL (SMALL entries first).
 * Every entry is unique, lowercase, and a valid single DNS label ([a-z0-9-],
 * 1–63 chars, no leading/trailing '-').
 *
 * {@link loadWordlist} extends this with on-demand, self-hosted tiers built by
 * `tools/build-wordlists.mjs` from permissively-licensed sources (SecLists,
 * bitquark, commonspeak2, dnsgen, altdns — see `assets/data/README.md` for the
 * exact licences): the global `smart` base (`wordlist-base.txt`, ~7k), the
 * gzipped `large` (~50k) and `huge` (~130k) tiers, and curated per-market locale
 * packs (`assets/data/locale/<cc>.txt`) selected from the domain's TLD — or, for a
 * TLD without a pack of its own, from a scan's evidence (lib/localeevidence.js). The list
 * is a global product: examples and defaults are generic (no single customer's
 * zone). {@link wordlistInfo} exposes build-time counts; {@link parseCustomWordlist}
 * validates user lists; a per-browser learned store lives in `learned.js`.
 */

import { fetchAndRead } from './util.js';

// Most common labels: web/mail/DNS, remote-access + platform infra, environments,
// apps, and the top-ranked global labels. This core is tried on EVERY domain, so
// it stays language-neutral: market vocabularies (Turkish, German, …) live in
// the locale packs (assets/data/locale/<cc>.txt), selected from the TLD or evidence.
const SMALL_WORDS = [
  // web + mail + dns
  'www', 'www2', 'web', 'mail', 'webmail', 'email', 'smtp', 'pop', 'imap', 'mx', 'mx1', 'mx2',
  'ns', 'ns1', 'ns2', 'ns3', 'dns', 'autodiscover', 'autoconfig', 'owa', 'exchange', 'ftp', 'sftp',
  // remote access / platform infra
  'vpn', 'remote', 'gateway', 'gw', 'proxy', 'lb', 'firewall', 'secure', 'cpanel', 'whm', 'webdisk',
  'plesk', 'panel', 'server', 'host', 'cloud', 'backup', 'monitor', 'monitoring', 'status',
  'git', 'gitlab', 'jenkins', 'grafana', 'kibana', 'prometheus', 'argocd', 'rancher', 'k8s',
  'registry', 'harbor', 'sonar', 'nexus', 'vault', 'sso', 'auth', 'keycloak', 'ldap', 'login', 'id',
  'db', 'mysql', 'jira', 'confluence', 'wiki',
  // environments
  'dev', 'test', 'stage', 'staging', 'uat', 'preprod', 'prod', 'beta', 'demo', 'sandbox', 'qa',
  // apps / content
  'api', 'app', 'apps', 'm', 'mobile', 'admin', 'static', 'cdn', 'img', 'images', 'media', 'assets',
  'files', 'download', 'downloads', 'upload', 'docs', 'doc', 'blog', 'news', 'shop', 'store', 'pay',
  'payment', 'checkout', 'crm', 'erp', 'intranet', 'extranet', 'portal', 'dashboard', 'account',
  'accounts', 'my', 'user', 'users', 'client', 'clients', 'support', 'help', 'helpdesk', 'ticket',
  'search', 'chat', 'video', 'meet', 'calendar', 'analytics', 'stats', 'metrics', 'link', 'go',
  'redirect', 'test1', 'test2', 'old', 'new', 'temp', 'internal', 'external', 'public', 'private',
  'b2b', 'b2c',
  // the highest-ranked labels of the SecLists top-1M frequency list (Cloudflare-
  // derived) not listed above, loopback `localhost` excluded — mostly the
  // standard Microsoft 365 and cPanel records found on org domains worldwide.
  'sip', 'pop3', 'ns4', 'lyncdiscover', 'speedtest', 'dns2', 'enterpriseenrollment',
  'enterpriseregistration', 'dns1', 'ntp', 'mail2', 'zabbix', 'msoid', 'cpcontacts', 'css',
  'cpcalendars'
];

// Additional labels that, together with SMALL, make up the medium list.
const MEDIUM_EXTRA = [
  // mail / messaging / collaboration
  'pop3', 'imap4', 'mx3', 'mx01', 'mx02', 'smtp1', 'smtp2', 'smtp3', 'mailgw', 'mailgateway',
  'mailserver', 'mailhost', 'mail1', 'mail2', 'mail3', 'newsletter', 'mailer', 'mailing', 'lists',
  'list', 'listserv', 'mailman', 'zimbra', 'roundcube', 'squirrelmail', 'horde', 'mail-relay',
  'relay', 'mta', 'spam', 'antispam', 'barracuda', 'proofpoint', 'mimecast', 'mailarchive', 'archive',
  'imaps', 'smtps', 'submission', 'postfix', 'dovecot', 'sieve', 'webmail2', 'mx-backup', 'mailbackup',
  'lync', 'skype', 'teams', 'sfb', 'jabber', 'xmpp', 'im', 'messaging', 'rocketchat', 'mattermost',
  'slack', 'mumble', 'ts', 'ts3', 'discord',
  // dns / infra naming
  'ns4', 'ns5', 'ns01', 'ns02', 'ns03', 'dns3', 'dns4', 'resolver', 'recursor', 'pdns', 'powerdns',
  'bind', 'named', 'dhcp', 'ntp', 'time', 'radius', 'tacacs', 'kerberos', 'kdc', 'ca', 'pki',
  'ocsp', 'crl', 'ipam', 'netbox', 'phpipam', 'dhcp1', 'dhcp2',
  // remote access / security
  'vpn1', 'vpn2', 'vpn3', 'ssl-vpn', 'sslvpn', 'anyconnect', 'globalprotect', 'gp', 'pulse',
  'forticlient', 'fortigate', 'fortinet', 'fw', 'fw1', 'fw2', 'asa', 'pfsense', 'opnsense', 'ssh',
  'bastion', 'jump', 'jumphost', 'jumpbox', 'access', 'rdgateway', 'rds', 'rdweb', 'ts-gateway',
  'citrix2', 'netscaler', 'vdi', 'horizon', 'vmware', 'vcenter', 'esxi', 'esx', 'vsphere', 'xen',
  'xenserver', 'proxmox', 'pve', 'hyperv', 'kvm', 'ovirt', 'nutanix', 'ipmi', 'idrac', 'ilo', 'bmc',
  'kvm1', 'console', 'oob', 'mgmt', 'management', 'mgmt1', 'admin1', 'admin2', 'root', 'sudo',
  // load balancing / proxy / cdn
  'lb1', 'lb2', 'lb01', 'lb02', 'loadbalancer', 'balancer', 'haproxy', 'nginx', 'traefik', 'envoy',
  'varnish', 'squid', 'proxy1', 'proxy2', 'reverse-proxy', 'edge', 'edge1', 'edge2', 'waf', 'cache',
  'cache1', 'cache2', 'cdn1', 'cdn2', 'cdn3', 'static1', 'static2', 'assets1', 'assets2', 'origin',
  'origins', 'pull', 'push', 'stream', 'streaming', 'live', 'vod', 'rtmp',
  // web servers / apps / frameworks
  'web1', 'web2', 'web3', 'web01', 'web02', 'web03', 'www1', 'www3', 'www01', 'app1', 'app2', 'app3',
  'app01', 'app02', 'app03', 'apps1', 'apps2', 'application', 'applications', 'frontend', 'front',
  'backend', 'back', 'middleware', 'services', 'service', 'svc', 'microservice', 'ws', 'wsapi',
  'rest', 'restapi', 'graphql', 'gql', 'soap', 'rpc', 'grpc', 'gateway-api', 'apigw', 'apigateway',
  'api1', 'api2', 'api3', 'api-v1', 'api-v2', 'apiv1', 'apiv2', 'v1', 'v2', 'v3', 'developer',
  'developers', 'partner', 'partners', 'integration', 'integrations', 'connect', 'hooks', 'webhook',
  'webhooks', 'callback', 'oauth', 'openid', 'token', 'idp', 'identity', 'accounts2', 'signin',
  'signup', 'register', 'password', 'reset', 'profile', 'session',
  // devops / ci-cd / source / registries
  'ci', 'cd', 'cicd', 'build', 'builds', 'pipeline', 'pipelines', 'runner', 'runners', 'agent',
  'agents', 'gitea', 'gogs', 'bitbucket', 'stash', 'svn', 'mercurial', 'hg', 'code', 'source',
  'sources', 'repo', 'repos', 'repository', 'artifacts', 'artifactory', 'maven', 'npm', 'pypi',
  'docker', 'dockerregistry', 'quay', 'containers', 'container', 'images-registry', 'helm', 'charts',
  'teamcity', 'bamboo', 'circleci', 'drone', 'concourse', 'spinnaker', 'flux', 'tekton', 'octopus',
  'deploy', 'deployment', 'release', 'releases', 'nightly', 'snapshot',
  // monitoring / logging / observability
  'logs', 'log', 'logging', 'logstash', 'elastic', 'elasticsearch', 'kibana2', 'graylog', 'splunk',
  'loki', 'promtail', 'alertmanager', 'alerts', 'alert', 'nagios', 'icinga', 'zabbix', 'cacti',
  'munin', 'observium', 'librenms', 'prtg', 'solarwinds', 'datadog', 'newrelic', 'sentry', 'jaeger',
  'zipkin', 'tempo', 'thanos', 'cortex', 'victoriametrics', 'influx', 'influxdb', 'telegraf',
  'collectd', 'statsd', 'uptime', 'uptimerobot', 'healthcheck', 'health', 'ping', 'probe', 'metric',
  'dashboards', 'kiali', 'grafana2',
  // databases / storage / cache / queues
  'database', 'databases', 'db1', 'db2', 'db01', 'db02', 'mariadb', 'postgres', 'postgresql', 'pg',
  'pgadmin', 'phpmyadmin', 'adminer', 'oracle', 'mssql', 'sqlserver', 'mongo', 'mongodb', 'couch',
  'couchdb', 'cassandra', 'scylla', 'redis', 'memcache', 'memcached', 'elastic2', 'solr', 'sphinx',
  'clickhouse', 'druid', 'presto', 'trino', 'hive', 'hadoop', 'hdfs', 'spark', 'flink', 'kafka',
  'zookeeper', 'rabbitmq', 'rabbit', 'activemq', 'nats', 'pulsar', 'mq', 'queue', 'broker', 'etcd',
  'consul', 'storage', 'store2', 'nas', 'san', 'ceph', 'gluster', 'minio', 's3', 'swift', 'objects',
  'blob', 'bucket', 'buckets', 'fileserver', 'files1', 'files2', 'share', 'shares', 'smb', 'nfs',
  'drive', 'disk', 'volumes', 'data', 'datastore', 'warehouse', 'dwh', 'datalake', 'lake', 'etl',
  'airflow', 'dbt', 'metabase', 'superset', 'redash', 'looker', 'tableau', 'powerbi', 'bi',
  // environments (expanded)
  'development', 'testing', 'test3', 'tests', 'stg', 'stg1', 'stg2', 'staging1', 'staging2',
  'preproduction', 'pre', 'pre-prod', 'production', 'prod1', 'prod2', 'live1', 'canary', 'blue',
  'green', 'acceptance', 'accept', 'integration-env', 'int', 'training', 'sandbox2', 'lab', 'labs',
  'poc', 'pilot', 'trial', 'experimental', 'experiment', 'staging-api', 'dev-api', 'test-api',
  'dev1', 'dev2', 'dev01', 'dev02', 'devops', 'ops', 'sre', 'infra', 'infrastructure', 'platform',
  // content / media / marketing
  'cdn-static', 'images1', 'images2', 'image', 'photo', 'photos', 'pics', 'picture', 'pictures',
  'thumb', 'thumbs', 'gallery', 'videos', 'video1', 'video2', 'audio', 'music', 'podcast', 'tv',
  'radio', 'player', 'embed', 'content', 'cms', 'wordpress', 'wp', 'drupal', 'joomla', 'ghost',
  'typo3', 'magento', 'prestashop', 'opencart', 'woocommerce', 'blog1', 'blog2', 'blogs', 'forum',
  'forums', 'community', 'discourse', 'board', 'qna', 'faq', 'kb', 'knowledgebase', 'knowledge',
  'learn', 'learning', 'lms', 'moodle', 'academy', 'courses', 'course', 'events', 'event', 'webinar',
  'landing', 'lp', 'promo', 'campaign', 'campaigns', 'ads', 'ad', 'adserver', 'track', 'tracking',
  'tracker', 'pixel', 'tag', 'tags', 'gtm', 'utm', 'seo', 'marketing', 'mkt', 'newsroom', 'press',
  'media1', 'press-kit',
  // e-commerce / payment / finance
  'store1', 'store2', 'shop1', 'shop2', 'shopping', 'cart', 'basket', 'order', 'orders', 'catalog',
  'catalogue', 'products', 'product', 'inventory', 'stock', 'warehouse2', 'pos', 'billing', 'invoice',
  'invoices', 'payments', 'pay1', 'pay2', 'wallet', 'checkout2', 'secure-pay', 'payment-gateway',
  'gateway2', 'merchant', 'paypal', 'stripe',
  'finance', 'financial', 'bank', 'banking', 'money', 'account-finance', 'ledger', 'accounting',
  'tax', 'payroll', 'expense', 'expenses', 'budget', 'treasury', 'trade', 'trading', 'exchange2',
  'market', 'markets', 'quote', 'quotes',
  // business apps / collaboration / crm-erp
  'crm2', 'erp2', 'sap', 'salesforce', 'sfdc', 'dynamics', 'netsuite', 'odoo', 'sugarcrm', 'hubspot',
  'zoho', 'sales', 'marketing2', 'leads', 'lead', 'contacts', 'contact', 'customer', 'customers',
  'vendor', 'vendors', 'supplier', 'suppliers', 'procurement', 'purchasing', 'project', 'projects',
  'pm', 'redmine', 'trello', 'asana', 'monday', 'basecamp', 'clickup', 'notion', 'workspace', 'work',
  'office', 'office365', 'o365', 'sharepoint', 'onedrive', 'gsuite', 'gapps', 'workspace2', 'drive2',
  'meet2', 'zoom', 'webex', 'gotomeeting', 'bluejeans', 'conference', 'conf', 'meeting', 'meetings',
  'booking', 'bookings', 'appointment', 'appointments', 'schedule', 'scheduler', 'timesheet', 'hr',
  'hrms', 'people', 'talent', 'recruit', 'recruiting', 'careers', 'career', 'jobs', 'job', 'apply',
  'onboarding', 'employee', 'employees', 'staff', 'directory', 'phonebook', 'contacts2',
  // admin / internal / management
  'admin3', 'administrator', 'adminpanel', 'admin-panel', 'controlpanel', 'control', 'manage',
  'manager', 'management2', 'backoffice', 'back-office', 'internal2', 'intranet2', 'corp', 'corporate',
  'company', 'private2', 'secret', 'hidden', 'restricted', 'staff2', 'employee-portal', 'ess',
  'selfservice', 'self-service', 'onboard', 'provisioning', 'provision', 'config', 'configuration',
  'settings', 'setup', 'install', 'installer', 'update', 'updates', 'upgrade', 'patch', 'patches',
  'mirror', 'mirrors', 'apt', 'yum', 'repo1', 'repo2', 'packages', 'package', 'dist', 'downloads2',
  'files-internal', 'transfer', 'ftp1', 'ftp2', 'ftps', 'tftp', 'scp', 'rsync', 'sync', 'dropbox',
  'nextcloud', 'owncloud', 'seafile', 'syncthing', 'filecloud',
  // networking / telecom
  'router', 'switch', 'core', 'core1', 'core2', 'dist1', 'dist2', 'access1', 'access2', 'wifi',
  'wlan', 'wireless', 'ap', 'ap1', 'ap2', 'controller', 'wlc', 'voip', 'pbx', 'asterisk', 'freepbx',
  'sip1', 'sip2', 'sbc', 'callmanager', 'cucm', '3cx', 'telephony', 'phone', 'fax', 'sms', 'gsm',
  'modem', 'dsl', 'fiber', 'uplink', 'peering', 'transit', 'bgp', 'looking-glass', 'lg', 'smokeping',
  'speedtest', 'iperf', 'netflow',
  // security / compliance
  'security', 'sec', 'soc', 'siem', 'ids', 'ips', 'nac', 'dlp', 'edr', 'av', 'antivirus', 'clamav',
  'sophos', 'kaspersky', 'trendmicro', 'mcafee', 'crowdstrike', 'defender', 'scan', 'scanner',
  'nessus', 'openvas', 'qualys', 'nmap', 'burp', 'pentest', 'audit', 'compliance', 'grc', 'risk',
  'cert2', 'csirt', 'abuse', 'phishing', 'quarantine', 'honeypot', 'sinkhole', 'threat', 'ioc',
  'secrets', 'keys', 'kms', 'hsm', 'password-manager', 'passwords', 'vault2', 'bitwarden', 'vaultwarden',
  '1password', 'lastpass', 'keepass',
  // cloud / virtualization / containers
  'aws', 'azure', 'gcp', 'gcloud', 'oci', 'digitalocean', 'do', 'linode', 'vultr', 'hetzner', 'ovh',
  'cloud1', 'cloud2', 'private-cloud', 'openstack', 'cloudstack', 'vm', 'vm1', 'vm2', 'vms', 'node',
  'node1', 'node2', 'node01', 'node02', 'worker', 'worker1', 'worker2', 'master', 'master1', 'master2',
  'control-plane', 'kubernetes', 'kube', 'k3s', 'openshift', 'ocp', 'okd', 'minikube', 'kubeadm',
  'ingress', 'egress', 'pod', 'pods', 'namespace', 'cluster', 'cluster1', 'cluster2', 'swarm', 'mesos',
  'nomad', 'portainer', 'kubeapi', 'kubelet', 'dashboard-k8s', 'kubernetes-dashboard', 'lens', 'kubeconfig',
  // misc / utility
  'test-www', 'www-test', 'demo1', 'demo2', 'example', 'sample', 'default', 'temp1', 'tmp', 'backup1',
  'backup2', 'bak', 'archive1', 'archive2', 'legacy', 'old1', 'old2', 'new1', 'new2', 'beta1', 'beta2',
  'alpha', 'rc', 'preview', 'staging-www', 'mirror1', 'mirror2', 'cdn-test', 'static-test', 'assets-cdn',
  'go2', 'link2', 'links', 'short', 'url', 'urls', 'r', 's', 't', 'l', 'redirect2', 'out', 'click',
  'clicks', 'ref', 'aff', 'affiliate', 'affiliates', 'partner2', 'referral', 'invite', 'share2',
  'social', 'feed', 'rss', 'atom', 'sitemap', 'robots', 'well-known', 'acme', 'validation', 'verify',
  'verification', 'confirm', 'activate', 'activation', 'unsubscribe', 'form', 'online', 'franchise',
  'tenders', 'metro'
];

/** Validate + dedupe (case-folded) a list of DNS labels, preserving order. */
function cleanLabels(words) {
  const labelRe = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
  const seen = new Set();
  const out = [];
  for (const raw of words) {
    const label = String(raw).trim().toLowerCase();
    if (!labelRe.test(label) || seen.has(label)) continue;
    seen.add(label);
    out.push(label);
  }
  return out;
}

const SMALL = cleanLabels(SMALL_WORDS);
const MEDIUM = cleanLabels([...SMALL_WORDS, ...MEDIUM_EXTRA]);

/**
 * ~150 most common subdomain labels (global, language-neutral core).
 * @type {string[]}
 */
export const WORDLIST_SMALL = Object.freeze(SMALL);

/**
 * ~1000 subdomain labels. Strict superset of {@link WORDLIST_SMALL}, whose
 * entries appear first (in the same order).
 * @type {string[]}
 */
export const WORDLIST_MEDIUM = Object.freeze(MEDIUM);

/**
 * Return a named wordlist by size.
 * @param {'small'|'medium'} [size='small']
 * @returns {string[]} Empty array for 'off' / unknown sizes.
 */
export function getWordlist(size = 'small') {
  if (size === 'medium') return WORDLIST_MEDIUM;
  if (size === 'small') return WORDLIST_SMALL;
  return [];
}

/* ------------------------------------------------------------------------ */
/* On-demand tiers, locale packs, custom lists (smart / large / huge)        */
/* ------------------------------------------------------------------------ */

/**
 * Ordered discovery levels. `small` is the built-in {@link WORDLIST_SMALL}
 * (no I/O). `smart` adds the global base list; `large` and `huge` extend it
 * with the self-hosted gzipped tiers built by `tools/build-wordlists.mjs`.
 * @type {readonly ['small','smart','large','huge']}
 */
export const WORDLIST_LEVELS = Object.freeze(['small', 'smart', 'large', 'huge']);

/** Locale packs shipped in `assets/data/locale/`. */
export const LOCALE_PACK_CODES = Object.freeze([
  'tr', 'de', 'fr', 'es', 'pt', 'it', 'nl', 'pl', 'ru', 'ar', 'ja', 'zh'
]);

/**
 * The most locale packs the evidence of a scan (lib/localeevidence.js) adds to one domain whose
 * TLD has no pack of its own; the query estimate (lib/scanplan.js) counts the largest ones.
 */
export const LOCALE_EVIDENCE_MAX_PACKS = 3;

/**
 * Embedded build-time manifest (counts / bytes / provenance) so the UI can show
 * sizes without downloading anything. Generated by `tools/build-wordlists.mjs`
 * (see `assets/data/wordlist-manifest.json`); `tests/js/wordlist-info.test.js`
 * asserts these counts match the actual data files, so they stay honest.
 */
const MANIFEST = Object.freeze({
  levels: {
    small: { id: 'small', approxCount: WORDLIST_SMALL.length, bytes: 0, file: null,
      sources: ['DomainScope curated core'], licence: 'MIT' },
    smart: { id: 'smart', approxCount: 7000, bytes: 42399, file: 'wordlist-base.txt',
      sources: ['DomainScope core', 'SecLists', 'bitquark/dnspop', 'commonspeak2', 'dnsgen', 'altdns'],
      licence: 'MIT / Apache-2.0' },
    large: { id: 'large', approxCount: 50000, bytes: 182788, file: 'wordlist-large.txt.gz',
      sources: ['SecLists top-1M', 'bitquark top-100k', 'commonspeak2'], licence: 'MIT / Apache-2.0' },
    huge: { id: 'huge', approxCount: 130000, bytes: 588172, file: 'wordlist-huge.txt.gz',
      sources: ['SecLists top-1M', 'bitquark top-100k', 'commonspeak2'], licence: 'MIT / Apache-2.0' }
  },
  locales: {
    tr: { approxCount: 283, bytes: 2419 }, de: { approxCount: 181, bytes: 1689 },
    fr: { approxCount: 171, bytes: 1531 }, es: { approxCount: 180, bytes: 1615 },
    pt: { approxCount: 169, bytes: 1494 }, it: { approxCount: 152, bytes: 1375 },
    nl: { approxCount: 124, bytes: 1163 }, pl: { approxCount: 127, bytes: 1057 },
    ru: { approxCount: 126, bytes: 1039 }, ar: { approxCount: 128, bytes: 940 },
    ja: { approxCount: 83, bytes: 602 }, zh: { approxCount: 93, bytes: 698 }
  },
  localeLicence: 'MIT (original DomainScope curation, ASCII-folded)'
});

/**
 * Per-level and per-locale metadata for the UI: `{ id, approxCount, bytes,
 * sources, licence }` for each tier, plus `locales` with the same shape.
 * Counts are build-time constants — no download required.
 * @returns {{ levels: Record<string,object>, locales: Record<string,object> }}
 */
export function wordlistInfo() {
  const locales = {};
  for (const cc of LOCALE_PACK_CODES) {
    const m = MANIFEST.locales[cc] || { approxCount: 0, bytes: 0 };
    locales[cc] = { id: cc, approxCount: m.approxCount, bytes: m.bytes,
      sources: ['DomainScope curated'], licence: MANIFEST.localeLicence };
  }
  return {
    levels: {
      small: { ...MANIFEST.levels.small },
      smart: { ...MANIFEST.levels.smart },
      large: { ...MANIFEST.levels.large },
      huge: { ...MANIFEST.levels.huge }
    },
    locales
  };
}

/* ---- label validation ---------------------------------------------------- */

// A single DNS-host label of a data file: [a-z0-9-], 1–63, no leading/trailing '-'.
const HOST_LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
// A label of a custom fragment: also allows '_' (service labels); a fragment
// may hold several dot-separated labels (e.g. `dev.api`).
const CUSTOM_LABEL_RE = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

/** True when every dot-separated label of `s` is a valid custom fragment (≤253). */
function isValidFragment(s) {
  if (!s || s.length > 253) return false;
  const parts = s.split('.');
  for (const p of parts) if (!CUSTOM_LABEL_RE.test(p)) return false;
  return true;
}

/**
 * An IDN fragment (`şube`, `dev.bücher`) → its punycode form through the WHATWG
 * URL parser (as domain.js normalises IDN host names); null for an ASCII token
 * or one the parser cannot take as a host name.
 */
function idnToAscii(tok) {
  if (/^[\x00-\x7f]*$/.test(tok) || /[\s/?#@:[\]\\%*]/.test(tok)) return null;
  let host;
  try {
    host = new URL(`http://${tok}.invalid`).hostname;
  } catch {
    return null;
  }
  return host.endsWith('.invalid') ? host.slice(0, -'.invalid'.length) : null;
}

/**
 * Parse a plain-text wordlist file into validated single labels.
 * Blank lines and `#` comments are skipped; everything is lowercased and deduped.
 * @param {string} text
 * @returns {string[]}
 */
function parseHostLabels(text) {
  const out = [];
  const seen = new Set();
  for (const raw of String(text ?? '').split(/\r\n|\r|\n/)) {
    const line = raw.trim().toLowerCase();
    if (!line || line.startsWith('#')) continue;
    if (!HOST_LABEL_RE.test(line) || seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

/**
 * Parse a user-supplied custom wordlist. Accepts one entry per line, or
 * comma / whitespace separated. Entries may be bare labels (`api`) or
 * multi-label prefixes (`dev.api`); a trailing dot is stripped and IDN labels
 * (`şube`) are converted to punycode (`xn--ube-rza`). Invalid tokens are
 * collected in `rejected`. Capped at 200 000 accepted labels.
 * @param {string} text
 * @returns {{ labels: string[], rejected: string[] }}
 */
export function parseCustomWordlist(text) {
  const CAP = 200000;
  const labels = [];
  const rejected = [];
  const seen = new Set();
  outer: for (const rawLine of String(text ?? '').split(/\r\n|\r|\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue; // whole-line comment
    for (const rawTok of line.split(/[\s,]+/)) {
      if (labels.length >= CAP) break outer;
      let tok = rawTok.trim().toLowerCase().replace(/\.+$/, '');
      if (!tok) continue;
      tok = idnToAscii(tok) ?? tok;
      if (!isValidFragment(tok)) { rejected.push(rawTok.trim()); continue; }
      if (seen.has(tok)) continue;
      seen.add(tok);
      labels.push(tok);
    }
  }
  return { labels, rejected };
}

/* ---- locale selection ----------------------------------------------------- */

// Country-code TLD → locale pack(s); a domain may map to several packs
// (e.g. Switzerland → de, fr, it).
const TLD_LOCALES = {
  tr: ['tr'],
  de: ['de'], at: ['de'], ch: ['de', 'fr', 'it'], li: ['de'],
  fr: ['fr'], be: ['fr', 'nl'], lu: ['fr', 'de'], mc: ['fr'],
  es: ['es'], mx: ['es'], ar: ['es'], co: ['es'], cl: ['es'], pe: ['es'], ve: ['es'],
  ec: ['es'], uy: ['es'], bo: ['es'], py: ['es'], gt: ['es'], cr: ['es'], pa: ['es'],
  do: ['es'], sv: ['es'], hn: ['es'], ni: ['es'],
  br: ['pt'], pt: ['pt'],
  it: ['it'], sm: ['it'],
  nl: ['nl'],
  pl: ['pl'],
  ru: ['ru'], by: ['ru'], kz: ['ru'], ua: ['ru'], kg: ['ru'], uz: ['ru'],
  sa: ['ar'], ae: ['ar'], eg: ['ar'], qa: ['ar'], kw: ['ar'], bh: ['ar'], om: ['ar'],
  jo: ['ar'], lb: ['ar'], ma: ['ar'], dz: ['ar'], tn: ['ar'], iq: ['ar'], ly: ['ar'],
  jp: ['ja'],
  cn: ['zh'], tw: ['zh'], hk: ['zh'], mo: ['zh']
};

/**
 * Locale packs for a domain: those its country-code TLD implies, else — for a TLD that names no
 * market (`.com`, `.io` …) — the ones a scan's evidence picked (`evidence`, a
 * lib/localeevidence.js `localeEvidence()` result for that domain, or any `{ locales }`; at most
 * {@link LOCALE_EVIDENCE_MAX_PACKS}). The TLD always wins over the evidence. Reads the LAST
 * label only: under a ccSLD the ccTLD is still the last label, so `example.com.tr` maps to `tr`
 * through `tr` (no second-level table; add one if a rule ever has to tell `.co` from `.com.co`).
 * Returns known pack codes only.
 * @param {string} [domain]
 * @param {{ locales?: string[] }|null} [evidence]
 * @returns {string[]}
 */
export function localesForDomain(domain, evidence = null) {
  const out = [];
  if (domain && typeof domain === 'string') {
    const parts = domain.trim().toLowerCase().replace(/\.+$/, '').split('.').filter(Boolean);
    const tld = parts.length ? parts[parts.length - 1] : '';
    for (const cc of TLD_LOCALES[tld] || []) if (LOCALE_PACK_CODES.includes(cc) && !out.includes(cc)) out.push(cc);
  }
  if (out.length || !evidence || !Array.isArray(evidence.locales)) return out;
  for (const cc of evidence.locales) {
    if (out.length >= LOCALE_EVIDENCE_MAX_PACKS) break;
    if (LOCALE_PACK_CODES.includes(cc) && !out.includes(cc)) out.push(cc);
  }
  return out;
}

/**
 * Resolve which locale packs to load. Explicit `locales` win ([] disables);
 * otherwise they are inferred from `domain` (and, for a TLD without packs, `evidence`).
 * @param {{ domain?: string, locales?: string[], evidence?: { locales?: string[] }|null }} opts
 * @returns {string[]}
 */
function resolveLocales({ domain, locales, evidence } = {}) {
  if (Array.isArray(locales)) return locales.filter((cc) => LOCALE_PACK_CODES.includes(cc));
  return localesForDomain(domain, evidence || null);
}

/* ---- data-file loading ---------------------------------------------------- */

/** Concatenate arrays keeping first-seen order, de-duplicated. */
function dedupeOrdered(lists) {
  const out = [];
  const seen = new Set();
  for (const list of lists) {
    for (const item of list) {
      if (!seen.has(item)) { seen.add(item); out.push(item); }
    }
  }
  return out;
}

/** Running in Node (file:// module) vs a browser (http(s):// module). */
const IS_NODE = typeof import.meta.url === 'string' && import.meta.url.startsWith('file:');

/** Per-file cache of parsed labels (plain and gzipped files alike). */
const fileCache = new Map();

/** How long one data file may take over fetch, body included (the huge tier is about 600 KB). */
const DATA_TIMEOUT_MS = 60000;

/** Is `err` a cancellation we must not swallow? */
function isAbort(err) {
  return !!err && typeof err === 'object' && err.name === 'AbortError';
}

/** Decode gzip bytes to text. Uses DecompressionStream in the browser, zlib in Node. */
async function gunzipToText(bytes) {
  if (IS_NODE) {
    const { gunzipSync } = await import('node:zlib');
    return Buffer.from(gunzipSync(bytes)).toString('utf8');
  }
  if (typeof DecompressionStream === 'function') {
    const ds = new DecompressionStream('gzip');
    const stream = new Response(bytes).body.pipeThrough(ds);
    return await new Response(stream).text();
  }
  throw new Error('gzip decompression unavailable');
}

/**
 * Load and parse a plain-text data file from `assets/data/`. Browser: `fetch`
 * relative to this module, within `timeoutMs` (the body too); Node: `fs`. Cached.
 * Abort errors propagate.
 * @param {string} relPath e.g. 'wordlist-base.txt' or 'locale/tr.txt'
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, preferFetch?: boolean, timeoutMs?: number }} [opts]
 * @returns {Promise<string[]>}
 */
async function loadTextFile(relPath, { fetchImpl, signal, preferFetch, timeoutMs = DATA_TIMEOUT_MS } = {}) {
  const key = `text:${relPath}`;
  if (fileCache.has(key)) return fileCache.get(key);
  const url = new URL(`../../data/${relPath}`, import.meta.url);
  let text;
  if (IS_NODE && !preferFetch) {
    const { readFile } = await import('node:fs/promises');
    text = await readFile(url, 'utf8');
  } else {
    const impl = typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch;
    text = await fetchAndRead(url, { fetchImpl: impl, signal, timeoutMs, headers: { accept: 'text/plain' } }, (res) => {
      if (!res || !res.ok) throw new Error(`Failed to load ${relPath}: HTTP ${res ? res.status : '?'}`);
      return res.text();
    });
  }
  const parsed = parseHostLabels(text);
  fileCache.set(key, parsed);
  return parsed;
}

/**
 * Load and parse a gzipped data file from `assets/data/`. Node reads bytes with
 * `fs`; the browser fetches bytes and either decompresses them (gzip magic
 * present) or, if GitHub Pages already decoded a `Content-Encoding: gzip`
 * response, reads them as text directly; the fetch, body included, within `timeoutMs`.
 * Cached. Abort errors propagate.
 * @param {string} relPath e.g. 'wordlist-large.txt.gz'
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, preferFetch?: boolean, timeoutMs?: number }} [opts]
 * @returns {Promise<string[]>}
 */
async function loadGzFile(relPath, { fetchImpl, signal, preferFetch, timeoutMs = DATA_TIMEOUT_MS } = {}) {
  const key = `gz:${relPath}`;
  if (fileCache.has(key)) return fileCache.get(key);
  const url = new URL(`../../data/${relPath}`, import.meta.url);
  let text;
  if (IS_NODE && !preferFetch) {
    const { readFile } = await import('node:fs/promises');
    const buf = await readFile(url);
    text = await gunzipToText(buf);
  } else {
    const impl = typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch;
    const bytes = await fetchAndRead(url, { fetchImpl: impl, signal, timeoutMs, headers: { accept: 'application/gzip, text/plain' } }, async (res) => {
      if (!res || !res.ok) throw new Error(`Failed to load ${relPath}: HTTP ${res ? res.status : '?'}`);
      return new Uint8Array(await res.arrayBuffer());
    });
    // 0x1f 0x8b = gzip magic. If absent, the layer below already decompressed it.
    text = (bytes[0] === 0x1f && bytes[1] === 0x8b) ? await gunzipToText(bytes)
      : new TextDecoder().decode(bytes);
  }
  const parsed = parseHostLabels(text);
  fileCache.set(key, parsed);
  return parsed;
}

/** Cache of the built tier lists (base/large/huge), keyed by level. */
const tierCache = new Map();

/** Load the tier list for a level (`smart`→base, `large`, `huge`). Cached. */
async function loadTier(level, opts) {
  if (tierCache.has(level)) return tierCache.get(level);
  let list;
  if (level === 'smart') list = await loadTextFile('wordlist-base.txt', opts);
  else if (level === 'large') list = await loadGzFile('wordlist-large.txt.gz', opts);
  else if (level === 'huge') list = await loadGzFile('wordlist-huge.txt.gz', opts);
  else return [];
  tierCache.set(level, list);
  return list;
}

/** Load the selected locale packs, skipping any that fail (non-fatal). */
async function loadLocalePacks(codes, opts, onInfo) {
  const packs = [];
  for (const cc of codes) {
    try {
      packs.push(await loadTextFile(`locale/${cc}.txt`, opts));
    } catch (err) {
      if (isAbort(err)) throw err;
      if (typeof onInfo === 'function') onInfo({ type: 'locale-missing', locale: cc });
    }
  }
  return packs;
}

/**
 * The labels of every locale pack (or of `codes`), keyed by pack code — the vocabulary
 * lib/localeevidence.js reads the names of a scan against. Same files and cache as the packs
 * {@link loadWordlist} adds (fetched in the browser, read from disk in Node; ≈ 16 KB for all
 * twelve). A pack that cannot load is left out with `onInfo({ type: 'locale-missing', locale })`;
 * an AbortError propagates.
 * @param {{ codes?: string[], fetchImpl?: typeof fetch, signal?: AbortSignal, preferFetch?: boolean,
 *   timeoutMs?: number, onInfo?: (info: object) => void }} [opts]
 * @returns {Promise<Record<string, string[]>>}
 */
export async function loadLocaleVocabulary(opts = {}) {
  const { codes = LOCALE_PACK_CODES, fetchImpl, signal, preferFetch, timeoutMs, onInfo } = opts || {};
  const io = { fetchImpl, signal, preferFetch, timeoutMs };
  const out = {};
  // In parallel: twelve small files, each cached once loaded.
  await Promise.all((Array.isArray(codes) ? codes : []).filter((cc) => LOCALE_PACK_CODES.includes(cc)).map(async (cc) => {
    try {
      out[cc] = await loadTextFile(`locale/${cc}.txt`, io);
    } catch (err) {
      if (isAbort(err)) throw err;
      if (typeof onInfo === 'function') onInfo({ type: 'locale-missing', locale: cc });
    }
  }));
  // Pack order, whatever order the files arrived in.
  const ordered = {};
  for (const cc of LOCALE_PACK_CODES) if (out[cc]) ordered[cc] = out[cc];
  return ordered;
}

/** Validate + normalise caller-supplied extra labels (learned / custom). */
function cleanExtra(extra) {
  if (!Array.isArray(extra)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of extra) {
    const s = String(raw ?? '').trim().toLowerCase().replace(/\.+$/, '');
    if (!s || !isValidFragment(s) || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

// Levels from largest to smallest, for graceful degradation.
const LEVEL_ORDER = ['small', 'smart', 'large', 'huge'];
function smallerLevel(level) {
  const i = LEVEL_ORDER.indexOf(level);
  return i > 0 ? LEVEL_ORDER[i - 1] : 'small';
}

/**
 * Load a wordlist by discovery level, ordered by likelihood:
 *   `extra` (learned / custom, first) → {@link WORDLIST_SMALL} → locale packs →
 *   base → the larger tiers.
 *
 * Levels: `small` (built-in, no I/O), `smart` (base ≈7k), `large` (≈50k),
 * `huge` (≈130k). The gzipped tiers are self-hosted and decoded with
 * `DecompressionStream('gzip')` in the browser and `node:zlib` in Node.
 *
 * Locale packs are auto-selected from `domain`'s country-code TLD — for a TLD
 * without packs, from `evidence` (a lib/localeevidence.js result, see
 * {@link localesForDomain}) — unless `locales` is given (`[]` disables them).
 * On a fetch/decode failure the level degrades
 * to the next smaller one and, if given, `onInfo({type:'degrade',requested,served})`
 * is called; the returned array is always usable.
 *
 * @param {'small'|'smart'|'large'|'huge'} [level='small']
 * @param {{ domain?: string, locales?: string[], evidence?: { locales?: string[] }|null, extra?: string[],
 *           fetchImpl?: typeof fetch, signal?: AbortSignal,
 *           onInfo?: (info: object) => void, preferFetch?: boolean, timeoutMs?: number }} [opts]
 *   `preferFetch` forces the browser fetch/decompress path even under Node
 *   (used by tests to exercise the gzip/degrade branches with a mock fetch);
 *   `timeoutMs`: how long each fetched file may take, body included (a stalled one degrades).
 * @returns {Promise<string[]>} a fresh array (the caller may mutate it)
 */
export async function loadWordlist(level = 'small', opts = {}) {
  const { domain, locales, evidence, extra, fetchImpl, signal, onInfo, preferFetch, timeoutMs } = opts;
  const io = { fetchImpl, signal, preferFetch, timeoutMs };
  const lvl = WORDLIST_LEVELS.includes(level) ? level : 'small';

  const extraLabels = cleanExtra(extra);
  const codes = resolveLocales({ domain, locales, evidence });

  // small: built-in only (plus extra) — preserves the no-I/O contract.
  if (lvl === 'small') {
    return dedupeOrdered([extraLabels, WORDLIST_SMALL]);
  }

  // Locale packs apply to every level from smart up.
  let packs = [];
  try {
    packs = await loadLocalePacks(codes, io, onInfo);
  } catch (err) {
    if (isAbort(err)) throw err;
    packs = [];
  }

  // Tier list, degrading on failure down through smaller tiers to 'small'.
  let tier = [];
  let served = lvl;
  try {
    tier = await loadTier(lvl, io);
  } catch (err) {
    if (isAbort(err)) throw err;
    served = 'small'; // worst case: only the built-in small list
    let fallback = smallerLevel(lvl);
    while (fallback !== 'small') {
      try {
        tier = await loadTier(fallback, io);
        served = fallback;
        break;
      } catch (err2) {
        if (isAbort(err2)) throw err2;
        fallback = smallerLevel(fallback);
      }
    }
    if (typeof onInfo === 'function') {
      onInfo({ type: 'degrade', requested: lvl, served, reason: String(err && err.message || err) });
    }
  }

  return dedupeOrdered([extraLabels, WORDLIST_SMALL, ...packs, tier]);
}

/** Drop the in-memory wordlist caches (extension, mainly for tests). */
export function clearWordlistCache() {
  fileCache.clear();
  tierCache.clear();
}
