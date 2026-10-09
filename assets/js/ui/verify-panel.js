/**
 * ui/verify-panel.js — the "Verify" tab of SSL Targets (ROADMAP P0.1, Phase A).
 *
 * After a scan WITH a certificate, one click checks every (public IP, host name) pair the scan
 * tied to that certificate from the internet: a Globalping probe connects to the IP with the
 * name as SNI and reads the certificate it is served; lib/verify.js compares it in this browser
 * with the loaded certificate and gives the companion CLI's six verdicts.
 *
 * - The job lives on the scan run (`run.verify`), not on the mounted view, so it survives
 *   navigation and language re-mounts; a toast says when it finished in the background and a
 *   new scan cancels it ({@link cancelVerify}).
 * - Nothing is sent when the tab opens, not even the free /limits read. The first send of a page
 *   session shows the consent + cost dialog; consent is never stored and "Delete all local data"
 *   resets it (ui/globalping-gate.js keeps it, with the quota every view shares). Origin checks
 *   (a proxied name on an inventory origin IP, from an origin hint or the zone file) are opt-in.
 * - A finished batch's checks of exact origins (`via` known or zone: the origin map's own entry,
 *   the zone file's origin; never a hint's candidate) go into the workspace's origin map
 *   (ui/origin-map.js, source 'verify') while it remembers origins: one serving the name is
 *   confirmed or remembered, one answering without it (or not at all while the name was found on
 *   another of them) marks that entry stale; the tab says what changed.
 * - Private, reserved and CDN-edge addresses and names Globalping refuses are listed but never
 *   sent. Private and reserved addresses, refused names and every address the internet could not
 *   answer go into a ready-made CLI command; CDN edges do not (the CDN serves its own certificate).
 * - Every string is rendered through h() / text nodes: probe city and network, certificate names
 *   and failure text are untrusted API data.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, ButtonLink, Card, CodeBlock, DataTable, EmptyState, ErrorBanner, ExternalLink, Icon,
  KeyValueList, Modal, ProgressBar, SegmentedControl, announce, checkbox, ipSortValue, setButtonBusy, toast
} from './components.js';
import { Flag } from './flag.js';
// The tab's own run row keeps its privacy note (DESIGN §5.5: a panel that sends something says what).
import { PrivacyNote } from './template.js';
import { downloadText, timestampedName } from './download.js';
import {
  t, registerStrings, formatNumber, formatDate, formatDateTime, formatRelative, formatRegion, daysUntil
} from '../i18n.js';
import { state } from '../state.js';
import { toCsv, toJson } from '../lib/export.js';
import { buildFittedSweepCommand } from '../lib/cmdline.js';
import { pemEncode, formatFingerprint } from '../lib/x509.js';
import { errorKind } from '../lib/util.js';
import { GP_LIMITS } from '../lib/globalping.js';
import { ExpectedCaBadge } from './expected-ca.js';
import { registerRunning } from './jobs.js';
import { hasConsent, grantConsent, sharedQuota, noteQuota, liveQuota, whenText, measurementUrl } from './globalping-gate.js';
import {
  VERIFY_ERRORS, VERIFY_REASONS, VERIFY_WARNINGS, EXPOSURES, NOT_RUN_REASONS, SKIP_REASONS,
  VERIFY_SOFT_CONFIRM_PROBES, VERIFY_MAX_RETRIES, VERIFY_TIMEOUT_S, VERIFY_CSV_COLUMNS, VERIFY_REUSE_WINDOW_MS,
  buildVerifyPairs, scopePairs, createVerifyRows, checkCount, expectationFor, runVerify, recheckRows, requeueRows,
  applyOriginOptIn, isOriginPair, verifyCost, summarizeVerify, notHereParts, verifyHeadline, verifyExportRows, verifyExportJson, cliPlan,
  setExpectations, VERIFY_SET_COLUMNS, VERIFY_PORT
} from '../lib/verify.js';
import { formatEndpoint } from '../lib/inventory.js';
import { setOfName, cliCertFiles } from '../lib/certsets.js';
import { SetBadge, CertFileButtons } from './renewal-panel.js';
import { verifyObservations } from '../lib/originfill.js';
import { OriginMapOffNote, recordOrigins, recordText, staleText } from './origin-map.js';
import { markStaleOrigins } from '../lib/originnow.js';

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'vfy.tab': 'Verify',
  'vfy.switchRunning': 'Verify on Globalping (the probes it has used stay used)',
  'vfy.intro': 'A probe on the internet connects to each IP with the host name (TLS + SNI) and reads the certificate it is served; your browser compares it with the new one.',
  'vfy.caption': 'Checks from the internet',
  'vfy.plan': 'Checks: {checks} · Servers: {servers} · Cost: up to {checks} probes, plus up to {retries} retries if a probe fails (free: {limit} per hour)',
  'vfy.planOrigins.off': 'Optional origin checks not included: {count}',
  'vfy.planOrigins.on': 'Including {count} origin checks',
  'vfy.cliBelow': 'Check private and reserved addresses and names Globalping does not accept from inside your network with the CLI below.',
  'vfy.notHere.private': { one: '{count} private address', other: '{count} private addresses' },
  'vfy.notHere.reserved': { one: '{count} reserved address', other: '{count} reserved addresses' },
  'vfy.notHere.cdn-edge': { one: '{count} CDN address (the CDN serves its own certificate)', other: '{count} CDN addresses (the CDN serves its own certificate)' },
  'vfy.notHere.bad-name': { one: '{count} name Globalping does not accept', other: '{count} names Globalping does not accept' },
  'vfy.notHere.bad-port': { one: '{count} port it cannot check', other: '{count} ports it cannot check' },
  'vfy.notHere.over-cap': { one: '{count} check over the 500 limit', other: '{count} checks over the 500 limit' },
  'vfy.notHere.proxied': { one: '{count} name behind a CDN with no known origin', other: '{count} names behind a CDN with no known origin' },
  'vfy.notHere.managed': { one: '{count} name whose certificate the CDN or platform manages', other: '{count} names whose certificate the CDN or platform manages' },
  'vfy.scope.label': 'Check',
  'vfy.scope.all': 'Every name ({count})',
  'vfy.scope.perIp': 'One name per IP ({count})',
  'vfy.scope.perIpSet': 'One name per IP and set ({count})',
  'vfy.privacy': 'Checks run through Globalping, a free probe network run by jsDelivr and volunteers. Each public IP, host name and port you check goes to Globalping, and one probe sends one HTTPS HEAD request to it (User-Agent “globalping probe”). Anyone who has the measurement ID can read the result, including the server’s response headers, for about six months. Private addresses are never sent; your certificate and inventory names stay in this browser. Only check servers you operate.',
  'vfy.origins': { one: 'Also check whether the origin server behind the CDN answers the internet ({count} check).', other: 'Also check whether origin servers behind the CDN answer the internet ({count} checks).' },
  'vfy.origins.hint': 'This sends each origin IP with the proxied name to Globalping; results are public by measurement ID.',
  'vfy.origins.confirm': { one: '{count} of these checks sends an origin IP behind the CDN together with its proxied name. Anyone with the measurement ID can see that this server answers for that name.', other: '{count} of these checks send an origin IP behind the CDN together with its proxied name. Anyone with the measurement ID can see that the server answers for that name.' },
  'vfy.start': 'Check from the internet',
  'vfy.stop': 'Stop',
  'vfy.recheck': 'Check again ({count})',
  'vfy.confirm.title': 'Send to Globalping?',
  'vfy.confirm.body': '{checks} IP + host name pairs go to Globalping and are checked from the internet. Cost: up to {checks} of the {remaining} probes left this hour (resets {when}), plus up to {retries} retries if a probe fails.',
  'vfy.confirm.partial': 'Only {fit} of the {checks} checks fit into this hour’s free quota ({remaining} left, resets {when}). Servers that need the certificate go first; the rest stay “Not checked” until you check again after the reset.',
  'vfy.confirm.go': 'Send and check',
  'vfy.confirm.goPartial': 'Check {count} now',
  'vfy.progress': 'Checked {done} of {total}',
  'vfy.quota': 'Globalping: {remaining} of {limit} probes left this hour · resets {when}',
  'vfy.quotaFresh': 'Globalping: {remaining} of {limit} probes left this hour',
  'vfy.quotaUnknown': 'Globalping: {limit} probes per hour without an account, shared by everyone behind your IP address.',
  'vfy.quotaOut': { one: 'This hour’s free Globalping quota is used up; it resets {when}. {count} check was not run.', other: 'This hour’s free Globalping quota is used up; it resets {when}. {count} checks were not run.' },
  'vfy.credits': 'More measurements (Globalping credits)',
  'vfy.unreachable': 'Globalping cannot be reached right now.',
  'vfy.failed': 'The check could not run.',
  'vfy.stopped': 'Stopped. Checking again within {minutes} minutes fetches the measurements already paid for, at no extra cost; after that they are sent again.',
  'vfy.empty': 'Nothing here can be checked from the internet: every address is private, reserved or a CDN edge. Check these servers from inside your network with the CLI below.',
  'vfy.empty.noCli': 'Nothing here can be checked from the internet: every address is a CDN edge, and a CDN edge shows the CDN’s certificate, not your server’s.',
  'vfy.empty.none': 'No server address to check from the internet: every name the certificate covers is behind a CDN or a managed platform, or has no address of yours. Add your origin servers on the Inventory page and scan again, or see “Behind CDN”.',
  'vfy.cant': 'The internet check cannot see revocation, the full chain (only a missing intermediate), the second certificate of a dual RSA/ECDSA server, mail and database ports, or private addresses. The CLI checks those from inside your network.',

  'vfy.head.all': { one: 'The new certificate is live on the only server checked from the internet.', other: 'The new certificate is live on all {count} servers checked from the internet.' },
  'vfy.head.some': 'New certificate live on {live} of {total} servers · still old: {old}.',
  'vfy.head.partial': 'New certificate live on {live} of {total} servers.',
  'vfy.head.none': { one: 'The server checked does not serve the new certificate yet.', other: 'None of the {count} servers serves the new certificate yet.' },
  'vfy.head.noAnswer': 'No server returned a certificate; each row says why.',
  'vfy.head.chain': { one: '1 server serves the new certificate without its intermediate. Java, older Android and some API clients will fail. Install the full chain (fullchain.pem).', other: '{count} servers serve the new certificate without its intermediate. Java, older Android and some API clients will fail. Install the full chain (fullchain.pem).' },
  'vfy.head.tlsError': { one: '1 server failed the TLS handshake.', other: '{count} servers failed the TLS handshake.' },
  'vfy.head.unreachable': { one: '1 server did not answer from the internet (no answer or port closed); check it from inside with the CLI.', other: '{count} servers did not answer from the internet (no answer or port closed); check them from inside with the CLI.' },
  'vfy.head.other': { one: '1 server answers, but not for these names.', other: '{count} servers answer, but not for these names.' },
  'vfy.head.originCert': { one: '1 server serves a Cloudflare Origin CA certificate, which only Cloudflare trusts: right on an origin behind Cloudflare Full (strict), an error for visitors who reach it directly. Not counted as old.', other: '{count} servers serve a Cloudflare Origin CA certificate, which only Cloudflare trusts: right on an origin behind Cloudflare Full (strict), an error for visitors who reach it directly. Not counted as old.' },
  'vfy.head.privateCert': { one: '1 server serves a self-signed certificate, which no browser trusts: an error for visitors who reach it directly (Cloudflare accepts it only in Full mode, not Full (strict)). Not counted as old.', other: '{count} servers serve a self-signed certificate, which no browser trusts: an error for visitors who reach it directly (Cloudflare accepts it only in Full mode, not Full (strict)). Not counted as old.' },
  'vfy.head.exposed': { one: '1 origin server behind a CDN answers the internet directly, so anyone can bypass the proxy. Allow only the CDN’s IP ranges on port 443, or use authenticated origin pulls (mTLS) or a tunnel.', other: '{count} origin servers behind a CDN answer the internet directly, so anyone can bypass the proxy. Allow only the CDN’s IP ranges on port 443, or use authenticated origin pulls (mTLS) or a tunnel.' },
  'vfy.head.filtered': { one: '1 origin server behind a CDN did not answer a probe from the internet (probably filtered, as it should be); confirm its certificate from inside with the CLI.', other: '{count} origin servers behind a CDN did not answer a probe from the internet (probably filtered, as they should be); confirm their certificates from inside with the CLI.' },
  'vfy.head.notHere': 'Not checkable from the internet: {list}.',
  'vfy.head.incomplete': { one: '1 server was only partly checked; check again to finish.', other: '{count} servers were only partly checked; check again to finish.' },

  'vfy.col.result': 'Result',
  'vfy.col.name': 'Host name',
  'vfy.col.ip': 'IP address',
  'vfy.col.served': 'Served certificate',
  'vfy.col.from': 'Checked from',
  'vfy.col.set': 'Set',
  'vfy.sets': 'Each name is compared with the certificate set planned for it ({list}); a new certificate of another loaded set counts as new too, marked “Another set”.',

  'vfy.st.UPDATED': 'New certificate',
  'vfy.st.NEEDS_UPDATE': 'Old certificate',
  'vfy.st.ORIGIN_CERT': 'Cloudflare Origin CA certificate',
  'vfy.st.PRIVATE_CERT': 'Self-signed certificate',
  'vfy.st.NOT_HOSTED': 'Name not served here',
  'vfy.st.TLS_ERROR': 'TLS error',
  'vfy.st.TIMEOUT': 'No answer',
  'vfy.st.CLOSED': 'Port closed',
  'vfy.st.NEEDS_UPDATE.other': 'Own certificate (not in the new one)',
  'vfy.st.NEEDS_UPDATE.nocert': 'Serves a certificate',
  'vfy.st.TIMEOUT.origin': 'No answer (probably filtered)',
  'vfy.state.pending': 'Waiting',
  'vfy.state.running': 'Checking…',
  'vfy.state.not-run': 'Not checked',
  'vfy.state.error': 'Check failed',
  'vfy.last': 'Last: {status}',
  'vfy.lastTitle': 'Result of the previous check',
  'vfy.notRun.quota': 'Hourly quota used up',
  'vfy.notRun.budget': 'Not in this batch',
  'vfy.notRun.cancelled': 'Stopped',
  'vfy.notRun.unreachable': 'Globalping unreachable',
  'vfy.notRun.optional': 'Optional, not sent',
  'vfy.skip.private': 'Private IP, use the CLI',
  'vfy.skip.reserved': 'Reserved address, use the CLI',
  'vfy.skip.cdn-edge': 'CDN address, skipped',
  'vfy.skip.cdn-edge.title': 'A CDN address shows the CDN’s certificate, not your server’s.',
  'vfy.skip.bad-name': 'Name Globalping does not accept, use the CLI',
  'vfy.skip.bad-port': 'Port not checkable from the internet, use the CLI',
  'vfy.skip.over-cap': 'Over the 500-check limit',

  'vfy.err.dns': 'The probe reported a DNS error.',
  'vfy.err.private': 'Globalping refused the address as private.',
  'vfy.err.probe': 'The probe had a problem; check again (another probe is used).',
  'vfy.err.offline': 'The probe went offline; check again (another probe is used).',
  'vfy.err.no-probes': 'No probe is available for this check right now.',
  'vfy.err.validation': 'Globalping rejected the request.',
  'vfy.err.deadline': 'No result in time; checking again within {minutes} minutes fetches it once without new cost.',
  'vfy.err.server': 'Globalping answered with a server error; check again later.',
  'vfy.err.network': 'Globalping could not be reached (network error).',
  'vfy.err.bad-response': 'Globalping sent a response this page cannot read.',
  'vfy.err.poll-rate': 'Globalping asked to slow down; check again in a moment.',
  'vfy.err.unknown': 'The check failed for an unknown reason.',

  'vfy.reason.new-cert': 'The fingerprint matches the certificate you loaded.',
  'vfy.reason.old-cert': 'Serves another certificate that covers this name. Install the new one and reload the service.',
  'vfy.reason.no-new-cert': 'Serves this certificate (no new certificate loaded to compare).',
  'vfy.reason.origin-ca': 'Serves a Cloudflare Origin CA certificate for this name. Only Cloudflare trusts it: right while the name stays proxied with Full (strict), an error for anyone who connects directly. Not counted as old (the CLI’s ORIGIN_CERT).',
  'vfy.reason.self-signed': 'Serves a self-signed certificate for this name. No browser trusts it: usual on internal hosts, an error for visitors who connect directly. Not counted as old (the CLI’s PRIVATE_CERT).',
  'vfy.reason.not-covered': 'Answered with a certificate that does not cover this name.',
  'vfy.reason.unrecognized-name': 'The server does not know this name (unrecognized_name alert).',
  'vfy.reason.refused-name': 'Refused this name, while other names on this address work.',
  'vfy.reason.sni-refused': 'Refused the TLS handshake for this name (alert 40).',
  'vfy.reason.tls-alert': 'The server ended the handshake with TLS alert {alert}.',
  'vfy.reason.reset': 'The connection was reset during the TLS handshake.',
  'vfy.reason.not-tls': 'The port answered without TLS. Plain HTTP?',
  'vfy.reason.tls-failed': 'The TLS handshake failed.',
  'vfy.reason.connect-timeout': 'No TCP connection within {seconds} s from this probe: filtered or down.',
  'vfy.reason.tls-timeout': 'Connected, but the handshake timed out.',
  'vfy.reason.refused': 'Connection refused on port {port}.',
  'vfy.reason.unreachable': 'The network reported the address as unreachable.',

  'vfy.warn.chain-incomplete': 'Intermediate missing',
  'vfy.warn.chain-incomplete.title': 'Install the full chain: certificate plus intermediates, e.g. fullchain.pem.',
  'vfy.warn.expired': 'Expired',
  'vfy.warn.expired.title': 'The served certificate is past its end date; browsers refuse it.',
  'vfy.warn.not-yet-valid': 'Not valid yet',
  'vfy.warn.not-yet-valid.title': 'The served certificate’s start date is in the future: check the server clock or the certificate.',
  'vfy.warn.self-signed': 'Self-signed',
  'vfy.warn.self-signed.title': 'The certificate is signed by itself; no browser trusts it.',
  'vfy.warn.untrusted-root': 'Untrusted root',
  'vfy.warn.untrusted-root.title': 'The chain ends in a root certificate that public clients do not trust.',
  'vfy.warn.untrusted': 'Not trusted',
  'vfy.warn.untrusted.title': 'The probe did not trust the certificate; the row details show the exact error.',
  'vfy.warn.name-mismatch': 'Browsers report a name mismatch',
  'vfy.warn.name-mismatch.title': 'The probe’s TLS library rejected the name even though the certificate appears to cover it.',
  'vfy.warn.same-key': 'Same key',
  'vfy.warn.same-key.title': 'The server uses the new certificate’s key pair with an older certificate: only the certificate file was not replaced.',
  'vfy.warn.http-421': 'HTTP 421',
  'vfy.warn.http-421.title': 'The certificate is right, but the web server has no site for this name: 421 Misdirected Request.',
  'vfy.warn.mixed': 'Probes disagree',
  'vfy.warn.mixed.title': 'The probes did not get the same result; the row shows the worst one.',
  'vfy.warn.origin-ca': 'Cloudflare Origin CA',
  'vfy.warn.origin-ca.title': 'Only Cloudflare trusts this certificate. Keep it while the name stays proxied, or install the new public certificate.',
  'vfy.warn.other-set': 'Another set',
  'vfy.warn.other-set.title': 'A new certificate of another loaded set covers this name here, not the set planned for it. Nothing old is served; install the planned set when convenient.',

  'vfy.exp.exposed': 'Origin open to the internet',
  'vfy.exp.exposed.title': '{name} is behind {provider}, but this server answers for it directly, so the proxy can be bypassed.',
  'vfy.exp.filtered': 'Filtered, as expected behind a CDN',
  'vfy.exp.filtered.title': 'Probes from different networks got no answer: the origin accepts only the CDN, as it should.',
  'vfy.exp.closed': 'Port closed, as expected behind a CDN',
  'vfy.exp.closed.title': 'The origin refuses connections from the internet on this port.',
  'vfy.exp.no-answer': 'No answer from one probe (probably filtered)',
  'vfy.exp.no-answer.title': 'One probe got no answer. That usually means the origin accepts only the CDN, but the server could also be down or block that probe’s country.',
  'vfy.exp.not-this-host': 'Answers, but not for this name',
  'vfy.exp.not-this-host.title': 'The server answers the internet, but does not serve this proxied name.',
  'vfy.exp.unknown': 'Inconclusive: see the row details',
  'vfy.exp.unknown.title': 'The result does not show whether the origin answers the internet; the row details show what the probe got.',

  'vfy.expires': 'expires {date} · {rel}',
  'vfy.expired': 'expired {date} · {rel}',
  'vfy.det.reason': 'Result',
  'vfy.det.last': 'Previous result',
  'vfy.det.warnings': 'Warnings',
  'vfy.det.exposure': 'Origin exposure',
  'vfy.det.names': 'Names in the certificate',
  'vfy.det.serial': 'Serial',
  'vfy.det.sha256': 'SHA-256',
  'vfy.det.issuer': 'Issuer',
  'vfy.det.validity': 'Validity',
  'vfy.det.key': 'Key',
  'vfy.det.tls': 'TLS',
  'vfy.det.http': 'HTTP status',
  'vfy.det.error': 'Error',
  'vfy.det.probe': 'Checked from',
  'vfy.det.measurement': 'Measurement',
  'vfy.det.checkedAt': 'Checked at',
  'vfy.det.via': 'Matched via',
  'vfy.det.set': 'Planned set',
  'vfy.det.servedSet': 'Set served',
  'vfy.det.server': 'Server',
  'vfy.det.kind.datacenter': 'data centre',
  'vfy.det.kind.eyeball': 'home or mobile network',
  'vfy.via.dns': 'DNS',
  'vfy.via.hint': 'origin hint',
  'vfy.via.zone': 'zone file',
  'vfy.via.known': 'origin map',

  'vfy.cli.title': 'Check the rest from inside your network',
  'vfy.cli.desc': 'Private, unaccepted and unanswered addresses: run this on a machine inside your network (a jump host). It gives the same verdicts and writes them to verify-cli.json.',
  'vfy.cli.command': 'Command',
  'vfy.cli.none': 'Nothing to run: no address or name here is safe to put on a command line.',
  'vfy.cli.cert': 'Download new-cert.pem',
  'vfy.cli.download': 'Download ssl_origin_scan.py',
  'vfy.cli.dropped': { one: '{count} entry was not safe for a command and was left out', other: '{count} entries were not safe for a command and were left out' },
  'vfy.cli.namesFile': 'The command reads the {count} names from {file}: download it next to the script.',
  'vfy.cli.namesFileDownload': 'Download {file}',
  'vfy.cli.targetsFile': 'The command reads the {count} targets from {file}: download it next to the script.',
  'vfy.cdnLink': 'See “Behind CDN”',
  'vfy.doneToast': 'Verification finished: {live} of {total} servers serve the new certificate',
  'vfy.exported': '{file} downloaded'
});

registerStrings('tr', {
  'vfy.tab': 'Doğrula',
  'vfy.switchRunning': 'Globalping’de Doğrula (kullandığı ölçümler geri gelmez)',
  'vfy.intro': 'İnternetteki bir ölçüm noktası her IP’ye host adıyla bağlanır (TLS + SNI) ve sunulan sertifikayı okur; karşılaştırmayı tarayıcınız yenisiyle yapar.',
  'vfy.caption': 'İnternetten kontroller',
  'vfy.plan': 'Kontrol: {checks} · Sunucu: {servers} · Maliyet: en fazla {checks} ölçüm, bir ölçüm noktası hata verirse en fazla {retries} yeniden deneme (ücretsiz: saatte {limit})',
  'vfy.planOrigins.off': 'Dahil edilmeyen isteğe bağlı asıl sunucu kontrolü: {count}',
  'vfy.planOrigins.on': '{count} asıl sunucu kontrolü dahil',
  'vfy.cliBelow': 'Özel ve ayrılmış adresleri ve Globalping’in kabul etmediği adları aşağıdaki CLI ile ağınızın içinden kontrol edin.',
  'vfy.notHere.private': '{count} özel adres',
  'vfy.notHere.reserved': '{count} ayrılmış adres',
  'vfy.notHere.cdn-edge': '{count} CDN adresi (CDN kendi sertifikasını sunar)',
  'vfy.notHere.bad-name': 'Globalping’in kabul etmediği {count} ad',
  'vfy.notHere.bad-port': 'kontrol edemediği {count} port',
  'vfy.notHere.over-cap': '500 sınırını aşan {count} kontrol',
  'vfy.notHere.proxied': 'asıl sunucusu bilinmeyen, CDN arkasındaki {count} ad',
  'vfy.notHere.managed': 'sertifikasını CDN’in ya da platformun yönettiği {count} ad',
  'vfy.scope.label': 'Kontrol',
  'vfy.scope.all': 'Her ad ({count})',
  'vfy.scope.perIp': 'IP başına bir ad ({count})',
  'vfy.scope.perIpSet': 'IP ve set başına bir ad ({count})',
  'vfy.privacy': 'Kontroller Globalping üzerinden yapılır; Globalping, jsDelivr ve gönüllülerin işlettiği ücretsiz bir ölçüm ağıdır. Kontrol ettiğiniz her genel IP, host adı ve port Globalping’e gider; bir ölçüm noktası ona tek bir HTTPS HEAD isteği gönderir (User-Agent “globalping probe”). Ölçüm kimliğini bilen herkes sonucu, sunucunun yanıt başlıkları dahil, yaklaşık altı ay okuyabilir. Özel adresler asla gönderilmez; sertifikanız ve envanterdeki sunucu adları bu tarayıcıda kalır. Yalnızca yönettiğiniz sunucuları kontrol edin.',
  'vfy.origins': 'CDN arkasındaki asıl sunucuların internete yanıt verip vermediğini de kontrol et ({count} kontrol).',
  'vfy.origins.hint': 'Bu, her asıl sunucu IP’sini proxy’lenen adla birlikte Globalping’e gönderir; sonuçlar ölçüm kimliğiyle herkese açıktır.',
  'vfy.origins.confirm': 'Bu kontrollerin {count} tanesi CDN arkasındaki bir asıl sunucu IP’sini proxy’lenen adıyla birlikte gönderir. Ölçüm kimliğini bilen herkes sunucunun o ad için yanıt verdiğini görebilir.',
  'vfy.start': 'İnternetten kontrol et',
  'vfy.stop': 'Durdur',
  'vfy.recheck': 'Yeniden kontrol et ({count})',
  'vfy.confirm.title': 'Globalping’e gönderilsin mi?',
  'vfy.confirm.body': '{checks} IP + host adı çifti Globalping’e gönderilip internetten kontrol edilecek. Maliyet: bu saat kalan {remaining} ölçümden en fazla {checks} tanesi ({when} sıfırlanır); bir ölçüm noktası hata verirse en fazla {retries} yeniden deneme.',
  'vfy.confirm.partial': '{checks} kontrolün yalnızca {fit} tanesi bu saatin ücretsiz kotasına sığıyor ({remaining} kaldı, {when} sıfırlanır). Önce sertifika gereken sunucular kontrol edilir; kalanlar sıfırlanmadan sonra yeniden kontrol edene kadar “Kontrol edilmedi” olarak kalır.',
  'vfy.confirm.go': 'Gönder ve kontrol et',
  'vfy.confirm.goPartial': 'Şimdi {count} tanesini kontrol et',
  'vfy.progress': '{total} kontrolden {done} tamamlandı',
  'vfy.quota': 'Globalping: bu saat {limit} ölçümden {remaining} kaldı · {when} sıfırlanır',
  'vfy.quotaFresh': 'Globalping: bu saat {limit} ölçümden {remaining} kaldı',
  'vfy.quotaUnknown': 'Globalping: hesapsız saatte {limit} ölçüm; IP adresinizin arkasındaki herkesle ortak.',
  'vfy.quotaOut': 'Bu saatin ücretsiz Globalping kotası doldu; {when} sıfırlanır. {count} kontrol çalıştırılmadı.',
  'vfy.credits': 'Daha fazla ölçüm (Globalping kredileri)',
  'vfy.unreachable': 'Globalping’e şu anda ulaşılamıyor.',
  'vfy.failed': 'Kontrol çalıştırılamadı.',
  'vfy.stopped': 'Durduruldu. {minutes} dakika içinde yeniden kontrol, ücreti ödenmiş ölçümleri ek maliyet olmadan alır; sonrasında yeniden gönderilir.',
  'vfy.empty': 'Burada internetten kontrol edilebilecek bir şey yok: her adres özel, ayrılmış ya da bir CDN ucu. Bu sunucuları aşağıdaki CLI ile ağınızın içinden kontrol edin.',
  'vfy.empty.noCli': 'Burada internetten kontrol edilebilecek bir şey yok: her adres bir CDN ucu ve bir CDN ucu sunucunuzun değil, CDN’in sertifikasını gösterir.',
  'vfy.empty.none': 'İnternetten kontrol edilecek sunucu adresi yok: sertifikanın kapsadığı her ad bir CDN’in ya da yönetilen bir platformun arkasında veya size ait bir adresi yok. Asıl sunucularınızı Envanter sayfasına ekleyip yeniden tarayın ya da “CDN arkası”na bakın.',
  'vfy.cant': 'İnternet kontrolü şunları göremez: iptal durumu, tam zincir (yalnızca eksik ara sertifika görünür), çift RSA/ECDSA sunucunun ikinci sertifikası, posta ve veritabanı portları, özel adresler. CLI bunları ağınızın içinden kontrol eder.',

  'vfy.head.all': 'Yeni sertifika, internetten kontrol edilen {count} sunucunun hepsinde yayında.',
  'vfy.head.some': '{total} sunucunun {live} tanesinde yeni sertifika yayında · hâlâ eski: {old}.',
  'vfy.head.partial': '{total} sunucunun {live} tanesinde yeni sertifika yayında.',
  'vfy.head.none': '{count} sunucunun hiçbiri henüz yeni sertifikayı sunmuyor.',
  'vfy.head.noAnswer': 'Hiçbir sunucu sertifika döndürmedi; nedeni her satırda yazıyor.',
  'vfy.head.chain': '{count} sunucu yeni sertifikayı ara sertifikası olmadan sunuyor. Java, eski Android ve bazı API istemcileri hata verir. Tam zinciri (fullchain.pem) kurun.',
  'vfy.head.tlsError': '{count} sunucuda TLS el sıkışması başarısız oldu.',
  'vfy.head.unreachable': '{count} sunucu internetten yanıt vermedi (yanıt yok ya da port kapalı); CLI ile içeriden kontrol edin.',
  'vfy.head.other': '{count} sunucu yanıt veriyor ama bu adlar için değil.',
  'vfy.head.originCert': '{count} sunucu, yalnızca Cloudflare’in güvendiği bir Cloudflare Origin CA sertifikası sunuyor: Cloudflare Full (strict) arkasındaki asıl sunucuda doğru, ona doğrudan ulaşan ziyaretçiler içinse hata. Eski sayılmaz.',
  'vfy.head.privateCert': '{count} sunucu, hiçbir tarayıcının güvenmediği kendinden imzalı bir sertifika sunuyor: ona doğrudan ulaşan ziyaretçiler için hata (Cloudflare bunu yalnızca Full modunda kabul eder, Full (strict) modunda etmez). Eski sayılmaz.',
  'vfy.head.exposed': 'CDN arkasındaki {count} asıl sunucu internete doğrudan yanıt veriyor; proxy herkesçe atlanabilir. 443 numaralı portta yalnızca CDN’in IP aralıklarına izin verin ya da kimlik doğrulamalı origin çekme (mTLS) veya bir tünel kullanın.',
  'vfy.head.filtered': 'CDN arkasındaki {count} asıl sunucu internetteki bir ölçüm noktasına yanıt vermedi (büyük olasılıkla olması gerektiği gibi filtreli); sertifikasını CLI ile içeriden doğrulayın.',
  'vfy.head.notHere': 'İnternetten kontrol edilemeyenler: {list}.',
  'vfy.head.incomplete': '{count} sunucu yalnızca kısmen kontrol edildi; tamamlamak için yeniden kontrol edin.',

  'vfy.col.result': 'Sonuç',
  'vfy.col.name': 'Host adı',
  'vfy.col.ip': 'IP adresi',
  'vfy.col.served': 'Sunulan sertifika',
  'vfy.col.from': 'Kontrol noktası',
  'vfy.col.set': 'Set',
  'vfy.sets': 'Her ad, onun için planlanan sertifika setiyle karşılaştırılır ({list}); yüklediğiniz başka bir setin yeni sertifikası da yeni sayılır ve “Başka set” olarak işaretlenir.',

  'vfy.st.UPDATED': 'Yeni sertifika',
  'vfy.st.NEEDS_UPDATE': 'Eski sertifika',
  'vfy.st.ORIGIN_CERT': 'Cloudflare Origin CA sertifikası',
  'vfy.st.PRIVATE_CERT': 'Kendinden imzalı sertifika',
  'vfy.st.NOT_HOSTED': 'Bu ad burada sunulmuyor',
  'vfy.st.TLS_ERROR': 'TLS hatası',
  'vfy.st.TIMEOUT': 'Yanıt yok',
  'vfy.st.CLOSED': 'Port kapalı',
  'vfy.st.NEEDS_UPDATE.other': 'Kendi sertifikası (yenisinde yok)',
  'vfy.st.NEEDS_UPDATE.nocert': 'Sertifika sunuyor',
  'vfy.st.TIMEOUT.origin': 'Yanıt yok (büyük olasılıkla filtreli)',
  'vfy.state.pending': 'Sırada',
  'vfy.state.running': 'Kontrol ediliyor…',
  'vfy.state.not-run': 'Kontrol edilmedi',
  'vfy.state.error': 'Kontrol başarısız',
  'vfy.last': 'Son: {status}',
  'vfy.lastTitle': 'Önceki kontrolün sonucu',
  'vfy.notRun.quota': 'Saatlik kota doldu',
  'vfy.notRun.budget': 'Bu partide yok',
  'vfy.notRun.cancelled': 'Durduruldu',
  'vfy.notRun.unreachable': 'Globalping’e ulaşılamadı',
  'vfy.notRun.optional': 'İsteğe bağlı, gönderilmedi',
  'vfy.skip.private': 'Özel IP, CLI’yi kullanın',
  'vfy.skip.reserved': 'Ayrılmış adres, CLI’yi kullanın',
  'vfy.skip.cdn-edge': 'CDN adresi, atlandı',
  'vfy.skip.cdn-edge.title': 'Bir CDN adresi sunucunuzun değil, CDN’in sertifikasını gösterir.',
  'vfy.skip.bad-name': 'Globalping’in kabul etmediği ad, CLI’yi kullanın',
  'vfy.skip.bad-port': 'Port internetten kontrol edilemez, CLI’yi kullanın',
  'vfy.skip.over-cap': '500 kontrol sınırının dışında',

  'vfy.err.dns': 'Ölçüm noktası bir DNS hatası bildirdi.',
  'vfy.err.private': 'Globalping adresi özel olduğu için reddetti.',
  'vfy.err.probe': 'Ölçüm noktasında sorun oldu; yeniden kontrol edin (başka bir nokta kullanılır).',
  'vfy.err.offline': 'Ölçüm noktası çevrim dışı kaldı; yeniden kontrol edin (başka bir nokta kullanılır).',
  'vfy.err.no-probes': 'Bu kontrol için şu anda uygun ölçüm noktası yok.',
  'vfy.err.validation': 'Globalping isteği reddetti.',
  'vfy.err.deadline': 'Sonuç zamanında gelmedi; {minutes} dakika içinde yeniden kontrol, sonucu bir kez ek maliyet olmadan alır.',
  'vfy.err.server': 'Globalping sunucu hatası döndürdü; daha sonra yeniden kontrol edin.',
  'vfy.err.network': 'Globalping’e ulaşılamadı (ağ hatası).',
  'vfy.err.bad-response': 'Globalping bu sayfanın okuyamadığı bir yanıt gönderdi.',
  'vfy.err.poll-rate': 'Globalping yavaşlamamızı istedi; biraz sonra yeniden kontrol edin.',
  'vfy.err.unknown': 'Kontrol bilinmeyen bir nedenle başarısız oldu.',

  'vfy.reason.new-cert': 'Parmak izi yüklediğiniz sertifikayla aynı.',
  'vfy.reason.old-cert': 'Bu adı kapsayan başka bir sertifika sunuyor. Yenisini kurup servisi yeniden yükleyin.',
  'vfy.reason.no-new-cert': 'Bu sertifikayı sunuyor (karşılaştırılacak yeni sertifika yüklenmedi).',
  'vfy.reason.origin-ca': 'Bu ad için bir Cloudflare Origin CA sertifikası sunuyor. Ona yalnızca Cloudflare güvenir: ad Full (strict) ile proxy arkasında kaldıkça doğru, doğrudan bağlanan herkes içinse hata. Eski sayılmaz (CLI’daki ORIGIN_CERT).',
  'vfy.reason.self-signed': 'Bu ad için kendinden imzalı bir sertifika sunuyor. Hiçbir tarayıcı ona güvenmez: iç sunucularda olağan, doğrudan bağlanan ziyaretçiler içinse hata. Eski sayılmaz (CLI’daki PRIVATE_CERT).',
  'vfy.reason.not-covered': 'Bu adı kapsamayan bir sertifikayla yanıt verdi.',
  'vfy.reason.unrecognized-name': 'Sunucu bu adı tanımıyor (unrecognized_name uyarısı).',
  'vfy.reason.refused-name': 'Bu adı reddetti; bu adresteki diğer adlar çalışıyor.',
  'vfy.reason.sni-refused': 'Bu ad için TLS el sıkışmasını reddetti (alert 40).',
  'vfy.reason.tls-alert': 'Sunucu el sıkışmayı {alert} numaralı TLS uyarısıyla bitirdi.',
  'vfy.reason.reset': 'TLS el sıkışması sırasında bağlantı sıfırlandı.',
  'vfy.reason.not-tls': 'Port TLS olmadan yanıt verdi. Düz HTTP olabilir mi?',
  'vfy.reason.tls-failed': 'TLS el sıkışması başarısız oldu.',
  'vfy.reason.connect-timeout': 'Bu ölçüm noktasından {seconds} sn içinde TCP bağlantısı kurulamadı: filtreli ya da kapalı.',
  'vfy.reason.tls-timeout': 'Bağlandı ama el sıkışma zaman aşımına uğradı.',
  'vfy.reason.refused': '{port} portunda bağlantı reddedildi.',
  'vfy.reason.unreachable': 'Ağ bu adrese ulaşılamadığını bildirdi.',

  'vfy.warn.chain-incomplete': 'Ara sertifika eksik',
  'vfy.warn.chain-incomplete.title': 'Tam zinciri kurun: sertifika ve ara sertifikalar, ör. fullchain.pem.',
  'vfy.warn.expired': 'Süresi dolmuş',
  'vfy.warn.expired.title': 'Sunulan sertifikanın bitiş tarihi geçmiş; tarayıcılar reddeder.',
  'vfy.warn.not-yet-valid': 'Henüz geçerli değil',
  'vfy.warn.not-yet-valid.title': 'Sunulan sertifikanın başlangıç tarihi ileride: sunucu saatini ya da sertifikayı kontrol edin.',
  'vfy.warn.self-signed': 'Kendinden imzalı',
  'vfy.warn.self-signed.title': 'Sertifika kendi kendini imzalamış; hiçbir tarayıcı güvenmez.',
  'vfy.warn.untrusted-root': 'Güvenilmeyen kök',
  'vfy.warn.untrusted-root.title': 'Zincir, genel istemcilerin güvenmediği bir kök sertifikayla bitiyor.',
  'vfy.warn.untrusted': 'Güvenilmiyor',
  'vfy.warn.untrusted.title': 'Ölçüm noktası sertifikaya güvenmedi; tam hata satır ayrıntılarında.',
  'vfy.warn.name-mismatch': 'Tarayıcılar ad uyuşmazlığı bildiriyor',
  'vfy.warn.name-mismatch.title': 'Sertifika adı kapsıyor görünse de ölçüm noktasının TLS kütüphanesi adı reddetti.',
  'vfy.warn.same-key': 'Aynı anahtar',
  'vfy.warn.same-key.title': 'Sunucu yeni sertifikanın anahtar çiftini daha eski bir sertifikayla kullanıyor: yalnızca sertifika dosyası değiştirilmemiş.',
  'vfy.warn.http-421': 'HTTP 421',
  'vfy.warn.http-421.title': 'Sertifika doğru ama web sunucusunda bu ad için site yok: 421 Misdirected Request.',
  'vfy.warn.mixed': 'Ölçüm noktaları farklı sonuç verdi',
  'vfy.warn.mixed.title': 'Ölçüm noktaları aynı sonucu almadı; satırda en kötüsü gösteriliyor.',
  'vfy.warn.origin-ca': 'Cloudflare Origin CA',
  'vfy.warn.origin-ca.title': 'Bu sertifikaya yalnızca Cloudflare güvenir. Ad proxy arkasında kaldıkça tutabilirsiniz ya da yeni genel sertifikayı kurun.',
  'vfy.warn.other-set': 'Başka set',
  'vfy.warn.other-set.title': 'Bu adı burada planlanan set değil, yüklediğiniz başka bir setin yeni sertifikası kapsıyor. Eski sertifika sunulmuyor; planlanan seti uygun bir zamanda kurun.',

  'vfy.exp.exposed': 'Asıl sunucu internete açık',
  'vfy.exp.exposed.title': '{name}, {provider} arkasında ama bu sunucu ona doğrudan yanıt veriyor; proxy atlanabilir.',
  'vfy.exp.filtered': 'Filtreli, CDN arkasında beklendiği gibi',
  'vfy.exp.filtered.title': 'Farklı ağlardaki ölçüm noktaları yanıt alamadı: asıl sunucu, olması gerektiği gibi yalnızca CDN’i kabul ediyor.',
  'vfy.exp.closed': 'Port kapalı, CDN arkasında beklendiği gibi',
  'vfy.exp.closed.title': 'Asıl sunucu bu portta internetten gelen bağlantıları reddediyor.',
  'vfy.exp.no-answer': 'Bir ölçüm noktasına yanıt yok (büyük olasılıkla filtreli)',
  'vfy.exp.no-answer.title': 'Bir ölçüm noktası yanıt alamadı. Bu genellikle asıl sunucunun yalnızca CDN’i kabul ettiği anlamına gelir; ama sunucu kapalı olabilir ya da o ölçüm noktasının ülkesini engelliyor olabilir.',
  'vfy.exp.not-this-host': 'Yanıt veriyor ama bu ad için değil',
  'vfy.exp.not-this-host.title': 'Sunucu internete yanıt veriyor ama bu proxy’lenen adı sunmuyor.',
  'vfy.exp.unknown': 'Belirsiz: satır ayrıntılarına bakın',
  'vfy.exp.unknown.title': 'Sonuç, asıl sunucunun internete yanıt verip vermediğini göstermiyor; ölçüm noktasının aldığı yanıt satır ayrıntılarında.',

  'vfy.expires': 'bitiş {date} · {rel}',
  'vfy.expired': 'süresi doldu {date} · {rel}',
  'vfy.det.reason': 'Sonuç',
  'vfy.det.last': 'Önceki sonuç',
  'vfy.det.warnings': 'Uyarılar',
  'vfy.det.exposure': 'Asıl sunucu erişimi',
  'vfy.det.names': 'Sertifikadaki adlar',
  'vfy.det.serial': 'Seri',
  'vfy.det.sha256': 'SHA-256',
  'vfy.det.issuer': 'Veren',
  'vfy.det.validity': 'Geçerlilik',
  'vfy.det.key': 'Anahtar',
  'vfy.det.tls': 'TLS',
  'vfy.det.http': 'HTTP durumu',
  'vfy.det.error': 'Hata',
  'vfy.det.probe': 'Kontrol noktası',
  'vfy.det.measurement': 'Ölçüm',
  'vfy.det.checkedAt': 'Kontrol zamanı',
  'vfy.det.via': 'Eşleşme yolu',
  'vfy.det.set': 'Planlanan set',
  'vfy.det.servedSet': 'Sunulan set',
  'vfy.det.server': 'Sunucu',
  'vfy.det.kind.datacenter': 'veri merkezi',
  'vfy.det.kind.eyeball': 'ev ya da mobil ağ',
  'vfy.via.dns': 'DNS',
  'vfy.via.hint': 'origin ipucu',
  'vfy.via.zone': 'bölge dosyası',
  'vfy.via.known': 'origin haritası',

  'vfy.cli.title': 'Kalanları ağınızın içinden kontrol edin',
  'vfy.cli.desc': 'Özel, kabul edilmeyen ve yanıt vermeyen adresler: bunu ağınızın içindeki bir makinede (jump host) çalıştırın. Aynı sonuç türlerini verir ve verify-cli.json dosyasına yazar.',
  'vfy.cli.command': 'Komut',
  'vfy.cli.none': 'Çalıştırılacak bir şey yok: buradaki hiçbir adres ya da ad komut satırına güvenle konamıyor.',
  'vfy.cli.cert': 'new-cert.pem indir',
  'vfy.cli.download': 'ssl_origin_scan.py indir',
  'vfy.cli.dropped': 'komut için güvenli olmayan {count} girdi dışarıda bırakıldı',
  'vfy.cli.namesFile': 'Komut {count} adı {file} dosyasından okur: dosyayı betiğin yanına indirin.',
  'vfy.cli.namesFileDownload': '{file} indir',
  'vfy.cli.targetsFile': 'Komut {count} hedefi {file} dosyasından okur: dosyayı betiğin yanına indirin.',
  'vfy.cdnLink': '“CDN arkası”na bakın',
  'vfy.doneToast': 'Doğrulama bitti: {total} sunucunun {live} tanesi yeni sertifikayı sunuyor',
  'vfy.exported': '{file} indirildi'
});

/* ------------------------------------------------------------------------ */
/* Constants and module state                                               */
/* ------------------------------------------------------------------------ */

/** Globalping's page about buying more measurements (verified 200 by the critic, 2026-09-24). */
export const GP_CREDITS_URL = 'https://globalping.io/credits';
const VIA_KINDS = ['dns', 'hint', 'zone', 'known'];
const NOTICE_WARNINGS = ['chain-incomplete', 'http-421', 'mixed'];
const DEFAULT_SHELLS = Object.freeze(['posix', 'powershell']);
const DEFAULT_PYTHON = Object.freeze({ posix: 'python3', powershell: 'python' });
const DEFAULT_CLI_PATH = 'cli/ssl_origin_scan.py';
const CLI_SCRIPT = 'ssl_origin_scan.py';
const CLI_CERT_FILE = 'new-cert.pem';
const CLI_JSON_FILE = 'verify-cli.json';
/** The Verify card's names file: never the Behind CDN card's proxied-names.txt (another list). */
const CLI_NAMES_FILE = 'verify-names.txt';
/** Its targets file, used only when the targets alone keep the command too long. */
const CLI_TARGETS_FILE = 'verify-targets.txt';
/** Minutes a paid, unfinished measurement can still be fetched for free (lib VERIFY_REUSE_WINDOW_MS). */
const REUSE_MINUTES = Math.round(VERIFY_REUSE_WINDOW_MS / 60000);
/**
 * The cost preview counts a paid measurement as free only when it is still reusable this much
 * later: the runner decides again when it gets to the row (after the dialog and the first polls).
 */
const REUSE_MARGIN_MS = 30000;
/** Rounds of "the rows or the price changed while the dialog was open, ask again". */
const MAX_CONFIRM_ROUNDS = 4;
/** Skip reasons the CLI card can check from inside the network (lib/verify cliPlan). */
const CLI_NOT_HERE = new Set(['vfy.notHere.private', 'vfy.notHere.reserved', 'vfy.notHere.bad-name', 'vfy.notHere.bad-port']);
/** Exposures that are the expected, safe outcome for an origin behind a CDN (lib EXPECTED_ORIGIN). */
const EXPECTED_EXPOSURES = new Set(['filtered', 'no-answer', 'closed']);

const WARN_STYLE = Object.freeze({
  'chain-incomplete': ['warn', 'link'],
  expired: ['error', 'clock'],
  'not-yet-valid': ['warn', 'clock'],
  'self-signed': ['error', 'alert'],
  'untrusted-root': ['error', 'alert'],
  untrusted: ['error', 'alert'],
  'name-mismatch': ['warn', 'alert'],
  'same-key': ['info', 'key'],
  'http-421': ['warn', 'alert'],
  mixed: ['info', 'help'],
  'origin-ca': ['info', 'cloud'],
  'other-set': ['info', 'layers']
});
const EXP_STYLE = Object.freeze({
  exposed: ['warn', 'unlock'],
  filtered: ['ok', 'shield'],
  closed: ['ok', 'lock'],
  'no-answer': ['info', 'clock'],
  'not-this-host': ['neutral', 'minus-circle'],
  unknown: ['neutral', 'help']
});
const HEAD_ICONS = Object.freeze({
  all: 'check-circle', some: 'alert', none: 'alert', partial: 'info', noAnswer: 'help', incomplete: 'clock',
  chain: 'link', tlsError: 'x-circle', unreachable: 'clock', other: 'minus-circle', originCert: 'cloud',
  privateCert: 'certificate', exposed: 'unlock', filtered: 'shield', notHere: 'lock'
});
/** The warning chip a kind status already says (the status badge carries its explanation). */
const STATUS_WARNING = Object.freeze({ ORIGIN_CERT: 'origin-ca', PRIVATE_CERT: 'self-signed' });

/** Consent purpose of this tab in ui/globalping-gate.js (page session only; "Delete all local data" resets it). */
const CONSENT = 'verify';
/**
 * Whether a confirmed dialog of this page session already carried the origin-check sentence
 * (vfy.origins.confirm). Until then a batch with an origin row always asks (critic C.3.1).
 */
let originsConsented = false;
/** Shell choice when the host view does not share its own (tests, Phase D). */
let fallbackShell = 'posix';
/** Jobs with a batch in flight ("Delete all local data" stops them). */
const liveJobs = new Set();
/** Jobs between a Start / Check again click and their batch (quota read, dialog). */
const launchingJobs = new Set();
// A switch to another workspace stops a batch in flight (its probes are spent): the shell names it first.
registerRunning('vfy.switchRunning', () => liveJobs.size > 0);

state.subscribe(({ key }) => {
  if (key !== 'cleared' && key !== 'workspace') return;
  // The origin check sends a server of the inventory: another workspace's servers ask again. (On
  // 'cleared' the gate also resets the consent and the shared quota itself.)
  originsConsented = false;
  for (const job of [...liveJobs, ...launchingJobs]) {
    if (job.controller) job.controller.abort();
    if (job.launch) job.launch.abort();
  }
});

/* ------------------------------------------------------------------------ */
/* Pure helpers (unit-tested)                                               */
/* ------------------------------------------------------------------------ */

/** Sort key that groups siblings (reversed labels), like the other host tables. */
function hostSortKey(name) {
  return String(name || '').split('.').reverse().join('.');
}

/**
 * True for an origin-hint row: a candidate origin IP, which may simply not host the name (its
 * rank, badge and label). The opt-in and the consent cover every origin pair, the zone file's
 * exact origins too: lib/verify.isOriginPair (critic C.3.1).
 */
export function isHintRow(row) {
  return !!row && row.via === 'hint';
}

/**
 * Probes a batch costs at most: lib/verify.verifyCost() over the rows as they will be queued
 * (a paid, unfinished measurement that may still be polled is free).
 * @param {object[]} rows the rows a click would send (any state)
 * @param {{ now?: number }} [opts]
 * @returns {number}
 */
export function batchCost(rows, { now = Date.now() } = {}) {
  return verifyCost((rows || []).map((r) => ({ ...r, state: 'pending' })), { now }).probes;
}

/**
 * The rows a click sends: before the first batch every pending row; afterwards
 * lib/verify.recheckRows(), minus origin rows while the opt-in is off.
 * @param {object[]} rows
 * @param {{ ran: boolean, origins: boolean, recheck?: (rows: object[]) => object[] }} opts
 * @returns {object[]}
 */
export function targetRows(rows, { ran, origins, recheck = recheckRows }) {
  const list = ran ? recheck(rows || []) : (rows || []).filter((r) => r.state === 'pending');
  return list.filter((r) => r.state !== 'skipped' && (origins || !isOriginPair(r)));
}

/**
 * Plan line numbers for the idle state. `origins` counts the origin checks the opt-in sends (or
 * would): not skipped and not past the cap.
 * @param {object[]} rows
 * @returns {{ checks: number, servers: number, origins: number, originsOn: boolean }}
 */
export function planCounts(rows) {
  const pending = (rows || []).filter((r) => r.state === 'pending');
  const servers = new Set();
  for (const r of pending) {
    servers.add(r.server ? `s:${r.server.id}` : `ip:${r.ip}`);
    for (const s of r.alsoServers || []) servers.add(`s:${s.id}`);
  }
  const origins = (rows || []).filter((r) => isOriginPair(r) && r.state !== 'skipped' && !r.overCap);
  return { checks: pending.length, servers: servers.size, origins: origins.length, originsOn: origins.some((r) => r.state === 'pending') };
}

/**
 * The {list} text of vfy.notHere / vfy.head.notHere ('' when everything is checkable), from
 * lib/verify.notHereParts(): unique addresses for private / reserved / CDN edges, names,
 * checks over the cap, proxied names without a known origin and provider-managed names.
 * @param {object[]} rows
 * @param {object} [stats] buildVerifyPairs() stats
 * @param {Array<{ key: string, params: object }>} [parts] precomputed parts (a headline entry's)
 * @returns {string}
 */
export function notHereText(rows, stats = null, parts = null) {
  const list = Array.isArray(parts) ? parts : notHereParts(summarizeVerify(rows || []), stats);
  return list.map((p) => t(p.key, p.params || { count: p.count })).join(', ');
}

/**
 * Sort rank of the Result column (problems first): 0 old certificate · 1 TLS error, a live
 * certificate with a notice, or a Cloudflare Origin CA / self-signed certificate visitors reach
 * directly · 2 name not served (DNS) / own certificate (not in the new one, or an Origin CA /
 * self-signed one behind a CDN) · 3 no answer / closed ·
 * 4 error / not checked · 5 waiting / running · 6 new certificate · 7 hint or origin rows that
 * behave as expected (filtered, no answer to a TCP connect, port closed, or an origin check that
 * answers but not for this name — whatever its status, TLS_ERROR included: lib `recheckRows()`
 * and `summarizeVerify()` treat the same rows as expected), optional origin checks left out ·
 * 8 skipped.
 * @param {object} row
 * @returns {number}
 */
export function resultRank(row) {
  if (!row) return 9;
  if (row.state === 'skipped') return 8;
  if (row.state === 'pending' || row.state === 'running') return 5;
  // An origin check the user did not opt into is not a problem.
  if (row.state === 'not-run' && row.notRun === 'optional') return 7;
  if (row.state !== 'done') return 4;
  // An origin-hint candidate that is simply not this name's origin (NOT_HOSTED, or a refused SNI).
  if (isHintRow(row) && row.proxied && row.exposure === 'not-this-host') return 7;
  const w = row.warnings || [];
  switch (row.status) {
    case 'NEEDS_UPDATE': return row.newCertCovers === false ? 2 : 0;
    case 'ORIGIN_CERT':
    case 'PRIVATE_CERT': return row.proxied ? 2 : 1;
    case 'TLS_ERROR': return 1;
    case 'UPDATED': return w.some((x) => NOTICE_WARNINGS.includes(x)) ? 1 : 6;
    case 'NOT_HOSTED': return isHintRow(row) ? 7 : 2;
    // A handshake timeout, an unreachable network or a single-probe mix is not "filtered as expected".
    case 'TIMEOUT':
    case 'CLOSED': return row.proxied && EXPECTED_EXPOSURES.has(row.exposure) ? 7 : 3;
    default: return 4;
  }
}

/**
 * i18n key, badge variant and icon of a row's status (null when the row has none).
 * @param {object} row
 * @returns {{ key: string, variant: string, icon: string }|null}
 */
export function statusBadgeSpec(row) {
  switch (row && row.status) {
    case 'UPDATED': return { key: 'vfy.st.UPDATED', variant: 'ok', icon: 'check-circle' };
    case 'NEEDS_UPDATE': {
      if (row.reason === 'no-new-cert') return { key: 'vfy.st.NEEDS_UPDATE.nocert', variant: 'warn', icon: 'alert' };
      return { key: row.newCertCovers === false ? 'vfy.st.NEEDS_UPDATE.other' : 'vfy.st.NEEDS_UPDATE', variant: 'warn', icon: 'alert' };
    }
    // Not old (the CLI's ORIGIN_CERT / PRIVATE_CERT): expected behind a CDN, an error for visitors who reach it directly.
    case 'ORIGIN_CERT': return { key: 'vfy.st.ORIGIN_CERT', variant: row.proxied ? 'info' : 'warn', icon: 'cloud' };
    case 'PRIVATE_CERT': return { key: 'vfy.st.PRIVATE_CERT', variant: row.proxied ? 'info' : 'warn', icon: 'certificate' };
    // Visitors reach a DNS-matched address, so a wrong certificate there matters; an origin hint may just be another site.
    case 'NOT_HOSTED': return { key: 'vfy.st.NOT_HOSTED', variant: isHintRow(row) ? 'neutral' : 'warn', icon: 'minus-circle' };
    case 'TLS_ERROR': return { key: 'vfy.st.TLS_ERROR', variant: 'error', icon: 'x-circle' };
    case 'TIMEOUT': {
      // "Probably filtered" only when no TCP connection was made; a handshake timeout means the origin answered.
      const filtered = row.proxied && (row.reason === 'connect-timeout' || row.exposure === 'no-answer' || row.exposure === 'filtered');
      return { key: filtered ? 'vfy.st.TIMEOUT.origin' : 'vfy.st.TIMEOUT', variant: 'neutral', icon: 'clock' };
    }
    case 'CLOSED': return { key: 'vfy.st.CLOSED', variant: 'neutral', icon: 'x-circle' };
    default: return null;
  }
}

/**
 * Row classes of the checks table: an old certificate is highlighted, except a certificate the
 * new one does not cover (a Cloudflare Origin CA or self-signed one is ORIGIN_CERT /
 * PRIVATE_CERT, never NEEDS_UPDATE, unless the new certificate is of that kind too).
 * @param {object} r VerifyRow
 * @returns {Record<string, boolean>}
 */
export function verifyRowClass(r) {
  return {
    'vfy-row-old': r.state === 'done' && r.status === 'NEEDS_UPDATE' && r.newCertCovers !== false,
    'vfy-row-skipped': r.state === 'skipped',
    'vfy-row-stale': !!r.stale && r.state !== 'done'
  };
}

/**
 * The order a confirmed batch is queued in: the batch's rows first — DNS / zone rows of servers
 * that need the certificate, then the other DNS rows and the remembered origins the workspace's
 * origin map now marks stale (`originStale`), then origin-hint checks (so a partial batch
 * spends the quota where vfy.confirm.partial says) — each in table order, then every other row
 * (the runner only sends 'pending' rows; the rest are there for the per-address works rule).
 * @param {object[]} rows every row of the job
 * @param {object[]} batch the confirmed rows
 * @returns {object[]} a permutation of `rows`
 */
export function runOrder(rows, batch) {
  const list = Array.isArray(rows) ? rows : [];
  const inBatch = new Set(batch || []);
  const rank = (r) => (isHintRow(r) ? 2 : r.needsCert === false || r.originStale ? 1 : 0);
  const first = list.filter((r) => inBatch.has(r)).map((r, i) => ({ r, i }))
    .sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i).map((x) => x.r);
  return [...first, ...list.filter((r) => !inBatch.has(r))];
}

/**
 * The not-checkable sentence ('' when everything is checkable). It points to the CLI card only
 * when that card has rows AND the list holds something the CLI can check (private, reserved,
 * a refused name or port); a proxied or provider-managed name is not checkable there either.
 * @param {object[]} rows
 * @param {object} [stats] buildVerifyPairs() stats
 * @returns {string}
 */
export function notHereSentence(rows, stats = null) {
  const parts = notHereParts(summarizeVerify(rows || []), stats);
  if (!parts.length) return '';
  const text = t('vfy.head.notHere', { list: notHereText(rows, stats, parts) });
  const cli = parts.some((p) => CLI_NOT_HERE.has(p.key)) && cliPlan(rows || []).rows > 0;
  return cli ? `${text} ${t('vfy.cliBelow')}` : text;
}

/**
 * Empty-state key when nothing is checkable: no pair at all (e.g. every covered name behind a CDN
 * and no inventory); every pair skipped with work for the CLI card; or every pair a CDN edge.
 * @param {object[]} pairs job pairs
 * @param {object[]} rows job rows
 * @returns {'vfy.empty.none'|'vfy.empty'|'vfy.empty.noCli'}
 */
export function emptyKey(pairs, rows) {
  if (!Array.isArray(pairs) || !pairs.length) return 'vfy.empty.none';
  return cliPlan(rows || []).rows > 0 ? 'vfy.empty' : 'vfy.empty.noCli';
}

/** The last quota reading while its window is open (ui/globalping-gate.js; kept here for the panel's callers). */
export { liveQuota };

/**
 * Whether a "quota used up" note still applies: until its reset, or an hour after it was
 * recorded when Globalping gave no reset time.
 * @param {{ resetAt?: Date|string|null, at?: number }|null} quotaOut
 * @param {number} [now]
 * @returns {boolean}
 */
export function quotaOutActive(quotaOut, now = Date.now()) {
  if (!quotaOut) return false;
  const reset = quotaOut.resetAt ? new Date(quotaOut.resetAt).getTime() : NaN;
  if (Number.isFinite(reset)) return reset > now;
  return Number.isFinite(quotaOut.at) ? quotaOut.at + 3600000 > now : true;
}

/**
 * The idle plan line: checks, servers and the cost including the probe-fault retries the
 * runner may spend (at most VERIFY_MAX_RETRIES per batch, spec §11.6).
 * @param {object[]} rows
 * @param {{ quota?: object|null }} [opts]
 * @returns {string}
 */
export function planText(rows, { quota = null } = {}) {
  const c = planCounts(rows);
  const q = liveQuota(quota);
  const limit = q && Number.isFinite(q.limit) ? q.limit : GP_LIMITS.anonymousPerHour;
  const origins = c.origins ? ` · ${t(c.originsOn ? 'vfy.planOrigins.on' : 'vfy.planOrigins.off', { count: c.origins })}` : '';
  return t('vfy.plan', {
    checks: formatNumber(c.checks), servers: formatNumber(c.servers), limit: formatNumber(limit),
    retries: formatNumber(VERIFY_MAX_RETRIES)
  }) + origins;
}

/**
 * The CLI card's command: the plan's targets and names, the new certificate and the JSON
 * report; a long name list goes to verify-names.txt (not the Behind CDN card's file), and a
 * target list still too long after that to verify-targets.txt as well.
 * @param {{ targets: string[], names: string[] }} plan lib/verify cliPlan()
 * @param {string} shell
 * @param {string[]|null} [certFiles] several certificate sets: one `--cert` per certificate
 *   (lib/certsets cliCertFiles), else new-cert.pem
 * @returns {object} lib/cmdline buildSweepCommand() result (`targetsInline: false` and
 *   `targetsFile` when the targets went to their file)
 */
export function verifyCliSweep(plan, shell, certFiles = null) {
  return buildFittedSweepCommand({
    targets: plan.targets, names: plan.names, script: CLI_SCRIPT, shell, cert: certFiles && certFiles.length ? certFiles : CLI_CERT_FILE,
    json: CLI_JSON_FILE, namesFile: CLI_NAMES_FILE, allowPorts: true
  }, CLI_TARGETS_FILE);
}

/**
 * The failure sentence of an error row; the deadline one states when the free re-fetch applies.
 * @param {object} row
 * @returns {string}
 */
export function errorText(row) {
  return t(`vfy.err.${errCode(row)}`, { minutes: formatNumber(REUSE_MINUTES) });
}

/** The Stopped note: a free re-fetch only within the reuse window. */
function stoppedText() {
  return t('vfy.stopped', { minutes: formatNumber(REUSE_MINUTES) });
}

/**
 * Headline / badge denominator: servers checked from the internet minus filtered origins and
 * origin candidates that do not host the name (lib `servers.base`).
 */
function serverBase(s) {
  if (Number.isFinite(s.base)) return Math.max(0, s.base);
  return Math.max(0, (Number(s.total) || 0) - (Number(s.filteredOrigins) || 0) - (Number(s.notHostingOrigins) || 0));
}

/**
 * Tab badge from a summarizeVerify() result: "live/total" servers (filtered origins are not
 * counted, matching the headline base); 'warn' while any server is still old, misses its
 * intermediate or exposes its origin; 'ok' when every server serves the new certificate.
 * @param {object|null} summary
 * @returns {{ value: string, variant: 'ok'|'warn'|null }|null}
 */
export function badgeFromSummary(summary) {
  if (!summary || !summary.servers) return null;
  const s = summary.servers;
  const total = serverBase(s);
  if (!total) return null;
  const live = Number(s.live) || 0;
  const warn = (Number(s.old) || 0) > 0 || (Number(s.chain) || 0) > 0 || (Number(summary.exposed) || 0) > 0;
  const ok = !warn && live === total && !(Number(s.incomplete) > 0);
  return { value: `${formatNumber(live)}/${formatNumber(total)}`, variant: warn ? 'warn' : (ok ? 'ok' : null) };
}

/**
 * Parameters of one verifyHeadline() entry: the lib's own, plus the view-built {list} of
 * vfy.head.notHere and a {count} fallback so a placeholder can never show raw.
 * @param {{ key: string, params?: object }} entry
 * @param {object} summary summarizeVerify() result
 * @param {string} list notHere list text
 * @returns {object}
 */
export function headlineParams(entry, summary, list = '') {
  const id = String(entry && entry.key || '').replace(/^vfy\.head\./, '');
  const params = { ...((entry && entry.params) || {}) };
  const s = (summary && summary.servers) || {};
  const base = serverBase(s);
  if (id === 'notHere') params.list = list;
  if (params.count === undefined) {
    const counts = {
      all: base, none: base, chain: s.chain, tlsError: s.tlsError, unreachable: s.unreachable, other: s.other,
      exposed: summary && summary.exposed, filtered: s.filteredOrigins, incomplete: s.incomplete
    };
    if (counts[id] !== undefined) params.count = Number(counts[id]) || 0;
  }
  if ((id === 'some' || id === 'partial') && params.total === undefined) params.total = base;
  if ((id === 'some' || id === 'partial') && params.live === undefined) params.live = Number(s.live) || 0;
  if (id === 'some' && params.old === undefined) params.old = Number(s.old) || 0;
  return params;
}

function errCode(row) {
  const code = row && row.error && row.error.code;
  return VERIFY_ERRORS.includes(code) ? code : 'unknown';
}

function serverLabel(row) {
  const names = [];
  if (row.server && row.server.name) names.push(row.server.name);
  for (const s of row.alsoServers || []) if (s && s.name && !names.includes(s.name)) names.push(s.name);
  return names.join(', ');
}

function probesOf(row) {
  return (row.tests || []).map((x) => x && x.probe).filter(Boolean);
}

function probeText(p) {
  return [
    p.country ? formatRegion(p.country) : null, p.city || null, p.network || null,
    p.asn ? `AS${p.asn}` : null, p.kind === 'datacenter' || p.kind === 'eyeball' ? t(`vfy.det.kind.${p.kind}`) : null
  ].filter(Boolean).join(' · ');
}

function statusText(row) {
  const spec = statusBadgeSpec(row);
  return spec ? t(spec.key) : '';
}

function warnText(w) {
  return VERIFY_WARNINGS.includes(w) ? t(`vfy.warn.${w}`) : String(w);
}

function expTitle(row) {
  const x = row.exposure;
  if (!EXPOSURES.includes(x)) return null;
  return t(`vfy.exp.${x}.title`, { name: row.name, provider: row.provider || t('common.unknown') });
}

function reasonSentence(row) {
  switch (row.state) {
    case 'skipped':
      if (!SKIP_REASONS.includes(row.skip)) return null;
      return row.skip === 'cdn-edge' ? `${t('vfy.skip.cdn-edge')}: ${t('vfy.skip.cdn-edge.title')}` : t(`vfy.skip.${row.skip}`);
    case 'not-run':
      return NOT_RUN_REASONS.includes(row.notRun) ? `${t('vfy.state.not-run')} · ${t(`vfy.notRun.${row.notRun}`)}` : t('vfy.state.not-run');
    case 'error':
      return errorText(row);
    case 'pending':
    case 'running':
      return null;
    default:
      return VERIFY_REASONS.includes(row.reason) ? t(`vfy.reason.${row.reason}`, {
        seconds: formatNumber(VERIFY_TIMEOUT_S),
        port: String(row.port ?? 443),
        alert: row.verdict && row.verdict.alert !== null && row.verdict.alert !== undefined ? String(row.verdict.alert) : '?'
      }) : null;
  }
}

function failureText(row) {
  const v = row.verdict || {};
  if (v.tlsError) return v.tlsError;
  if (v.detail) return v.detail;
  const raw = (row.tests || []).map((x) => x && x.rawOutput).find(Boolean);
  if (raw) return String(raw).split('\n')[0].slice(0, 200);
  if (row.served && row.served.error) return row.served.error;
  return row.error && row.error.message ? row.error.message : null;
}

/* ------------------------------------------------------------------------ */
/* Cells and row details                                                    */
/* ------------------------------------------------------------------------ */

function miniBadge(text, variant, icon, title, dataset) {
  const b = Badge(text, { variant, icon, title, className: 'vfy-mini' });
  Object.assign(b.dataset, dataset);
  return b;
}

function primaryBadge(row) {
  let b;
  switch (row.state) {
    case 'skipped':
      b = Badge(SKIP_REASONS.includes(row.skip) ? t(`vfy.skip.${row.skip}`) : String(row.skip || ''), {
        variant: 'private', icon: 'lock', title: row.skip === 'cdn-edge' ? t('vfy.skip.cdn-edge.title') : null
      });
      b.dataset.vfySkip = row.skip || '';
      break;
    case 'running':
      // Badge() has no spinner: a plain badge with the shared .spinner (reduced motion is handled globally).
      b = h('span', { class: 'badge badge-neutral vfy-running' },
        h('span', { class: 'spinner', attrs: { 'aria-hidden': 'true' } }), h('span', { class: 'badge-text' }, t('vfy.state.running')));
      break;
    case 'pending':
      b = Badge(t('vfy.state.pending'), { variant: 'neutral', icon: 'clock' });
      break;
    case 'not-run': {
      const reason = NOT_RUN_REASONS.includes(row.notRun) ? ` · ${t(`vfy.notRun.${row.notRun}`)}` : '';
      b = Badge(`${t('vfy.state.not-run')}${reason}`, { variant: 'neutral', icon: 'minus-circle' });
      b.dataset.vfyNotRun = row.notRun || '';
      break;
    }
    case 'error':
      b = Badge(t('vfy.state.error'), { variant: 'error', icon: 'alert', title: errorText(row) });
      b.dataset.vfyError = errCode(row);
      break;
    default: {
      const spec = statusBadgeSpec(row);
      b = spec ? Badge(t(spec.key), { variant: spec.variant, icon: spec.icon, title: reasonSentence(row) })
        : Badge(t('vfy.state.error'), { variant: 'error', icon: 'alert' });
      if (row.status) b.dataset.vfyStatus = row.status;
    }
  }
  b.dataset.vfyState = row.state || '';
  return b;
}

function resultCell(row) {
  const out = h('div', { class: 'vfy-result' }, primaryBadge(row));
  if (row.state === 'done') {
    for (const w of row.warnings || []) {
      if (STATUS_WARNING[row.status] === w) continue;
      const [variant, icon] = WARN_STYLE[w] || ['neutral', 'info'];
      out.append(miniBadge(warnText(w), variant, icon, VERIFY_WARNINGS.includes(w) ? t(`vfy.warn.${w}.title`) : null, { vfyWarn: w }));
    }
    if (row.exposure && EXPOSURES.includes(row.exposure)) {
      const [variant, icon] = EXP_STYLE[row.exposure] || ['neutral', 'info'];
      out.append(miniBadge(t(`vfy.exp.${row.exposure}`), variant, icon, expTitle(row), { vfyExp: row.exposure }));
    }
  } else if (row.stale && row.status && row.state !== 'skipped') {
    out.append(h('span', { class: 'vfy-last text-xs muted', title: t('vfy.lastTitle'), dataset: { vfyLast: row.status } },
      t('vfy.last', { status: statusText(row) })));
  }
  return out;
}

function resultSearchText(row) {
  const bits = [row.state, row.status, statusText(row), row.skip, row.notRun];
  for (const w of row.warnings || []) bits.push(w, warnText(w));
  if (row.exposure) bits.push(row.exposure);
  return bits.filter(Boolean).join(' ');
}

function ipCell(row) {
  const sub = [serverLabel(row), isOriginPair(row) ? t(`vfy.via.${row.via}`) : null, row.originStale ? t('om.stale') : null].filter(Boolean).join(' · ');
  // A check on another port (a remembered origin's) shows it: 198.51.100.30:8443.
  const where = Number.isInteger(row.port) && row.port !== VERIFY_PORT ? formatEndpoint(row.ip, row.port) ?? row.ip : row.ip;
  return h('div', { class: 'vfy-cell-2' },
    h('span', { class: 'mono vfy-ip' }, where),
    sub ? h('span', { class: 'vfy-sub' }, sub) : null);
}

/** Days-left band of the existing tables: expired / ≤ 30 days / ≤ 60 days. */
function expiryBand(days) {
  if (days === null) return null;
  if (days < 0) return 'expired';
  if (days <= 30) return 'soon';
  if (days <= 60) return 'warn';
  return null;
}

function servedCell(row) {
  const s = row.served;
  if (!s) return null;
  const primary = s.subjectCN || (s.dnsNames && s.dnsNames[0]) || '—';
  const days = s.notAfter ? daysUntil(s.notAfter) : null;
  const band = expiryBand(days);
  const exp = s.notAfter ? h('span', { class: band ? `vfy-exp-${band}` : null },
    t(days !== null && days < 0 ? 'vfy.expired' : 'vfy.expires', { date: formatDate(s.notAfter), rel: formatRelative(s.notAfter) })) : null;
  const issuer = s.issuerO || s.issuerCN || null;
  // A server serving another CA's certificate than the workspace expects is flagged in the row.
  const unexpected = issuer ? ExpectedCaBadge({ CN: s.issuerCN, O: s.issuerO }, { onlyUnexpected: true }) : null;
  return h('div', { class: ['vfy-cell-2', { 'is-stale': !!row.stale && row.state !== 'done' }] },
    h('span', { class: 'mono vfy-served-cn', title: (s.dnsNames || []).join(', ') || null }, primary),
    issuer || exp ? h('span', { class: 'vfy-sub' }, issuer, issuer && exp ? ' · ' : null, exp) : null,
    unexpected);
}

function fromCell(row) {
  const probes = probesOf(row);
  if (!probes.length) return null;
  const p = probes[0];
  const place = p.city || (p.country ? formatRegion(p.country) : '') || '—';
  return h('div', { class: 'vfy-cell-2 vfy-from', title: [p.network, p.asn ? `AS${p.asn}` : null].filter(Boolean).join(' · ') || null },
    h('span', { class: 'vfy-from-main' },
      Flag(p.country, { className: 'vfy-flag', title: p.country ? formatRegion(p.country) : null }), ' ', place,
      probes.length > 1 ? h('span', { class: 'muted' }, ` ${t('common.moreCount', { count: probes.length - 1 })}`) : null),
    p.asn ? h('span', { class: 'vfy-sub mono' }, `AS${p.asn}`) : null);
}

/**
 * Expanded row: why, what was served, from where, and the measurement.
 * @param {object} row VerifyRow
 * @returns {HTMLElement}
 */
export function verifyDetails(row) {
  const items = [];
  const reason = reasonSentence(row);
  if (reason) items.push({ key: t('vfy.det.reason'), value: reason });
  if (row.stale && row.status && row.state !== 'done') items.push({ key: t('vfy.det.last'), value: statusText(row) });
  const warns = (row.warnings || []).map((w) => h('span', null, h('strong', null, warnText(w)),
    VERIFY_WARNINGS.includes(w) ? ` — ${t(`vfy.warn.${w}.title`)}` : ''));
  if (warns.length) items.push({ key: t('vfy.det.warnings'), value: warns });
  if (row.exposure && EXPOSURES.includes(row.exposure)) {
    items.push({ key: t('vfy.det.exposure'), value: `${t(`vfy.exp.${row.exposure}`)} — ${expTitle(row)}` });
  }
  const s = row.served;
  if (s) {
    if (s.dnsNames && s.dnsNames.length) items.push({ key: t('vfy.det.names'), value: s.dnsNames.join(', '), mono: true });
    if (s.serialHex) items.push({ key: t('vfy.det.serial'), value: formatFingerprint(s.serialHex), mono: true });
    if (s.sha256) items.push({ key: t('vfy.det.sha256'), value: formatFingerprint(s.sha256), mono: true, copy: s.sha256 });
    const issuer = [s.issuerCN, s.issuerO && s.issuerO !== s.issuerCN ? `(${s.issuerO})` : null].filter(Boolean).join(' ');
    if (issuer) {
      const badge = ExpectedCaBadge({ CN: s.issuerCN, O: s.issuerO });
      items.push({ key: t('vfy.det.issuer'), value: badge ? h('span', { class: 'vfy-issuer' }, issuer, ' ', badge) : issuer });
    }
    if (s.notBefore || s.notAfter) items.push({ key: t('vfy.det.validity'), value: `${formatDate(s.notBefore)} → ${formatDate(s.notAfter)}` });
    const key = [s.keyType, s.keyBits].filter(Boolean).join(' ');
    if (key) items.push({ key: t('vfy.det.key'), value: key });
    const tls = [s.protocol, s.cipher].filter(Boolean).join(' · ');
    if (tls) items.push({ key: t('vfy.det.tls'), value: tls, mono: true });
  }
  if (row.httpStatus !== null && row.httpStatus !== undefined) items.push({ key: t('vfy.det.http'), value: String(row.httpStatus), mono: true });
  const fail = row.state === 'skipped' ? null : failureText(row);
  if (fail) items.push({ key: t('vfy.det.error'), value: fail, mono: true });
  const probes = probesOf(row).map(probeText).filter(Boolean);
  if (probes.length) items.push({ key: t('vfy.det.probe'), value: probes });
  const link = measurementUrl(row.measurementId);
  if (link) items.push({ key: t('vfy.det.measurement'), value: ExternalLink(link, row.measurementId, { className: 'mono' }) });
  if (row.checkedAt) items.push({ key: t('vfy.det.checkedAt'), value: formatDateTime(row.checkedAt, { utc: true }) });
  if (serverLabel(row)) items.push({ key: t('vfy.det.server'), value: serverLabel(row) });
  const via = t(`vfy.via.${VIA_KINDS.includes(row.via) ? row.via : 'dns'}`);
  // A remembered origin the workspace's origin map has since marked stale: why.
  items.push({ key: t('vfy.det.via'), value: row.originStale ? `${via} · ${t('om.stale')}: ${staleText({ stale: row.originStale })}` : via });
  // Several certificate sets: the set planned for the name, and the one served when another.
  if (row.setId) items.push({ key: t('vfy.det.set'), value: t('rw.set', { id: row.setId }) });
  const servedSet = row.state === 'done' && row.verdict ? row.verdict.matchedSet : null;
  if (servedSet && servedSet !== row.setId) items.push({ key: t('vfy.det.servedSet'), value: t('rw.set', { id: servedSet }) });
  return KeyValueList(items, { className: 'vfy-details' });
}

/* ------------------------------------------------------------------------ */
/* The job (owned by the scan run)                                           */
/* ------------------------------------------------------------------------ */

function emitJob(job, type, payload) {
  for (const fn of [...job.listeners]) {
    try {
      fn(type, payload);
    } catch (err) {
      // A rendering bug must not stop the checks; surface it to the shell's error handler.
      setTimeout(() => {
        throw err;
      }, 0);
    }
  }
}

function setScope(job, scope) {
  job.scope = scope === 'perIp' ? 'perIp' : 'all';
  job.rows = createVerifyRows(scopePairs(job.pairs, job.scope), { origins: job.origins });
  readOrigins(job);
}

/**
 * Mark the job's rows of remembered origins with the workspace's origin map as it is now
 * (lib/originnow.js markStaleOrigins). The map may have changed while no panel was on screen (a
 * CLI report imported in Servers › Origin map, another tab), so the job is read again whenever it
 * is picked up, exported or started.
 * @param {object} job
 * @returns {boolean} whether a row's mark changed
 */
function readOrigins(job) {
  const marks = () => job.rows.map((r) => (r.via === 'known' ? JSON.stringify(r.originStale || null) : '')).join('\n');
  const before = marks();
  markStaleOrigins(job.rows, state.workspaceData('origins'));
  return marks() !== before;
}

/**
 * The verification job of a finished scan with a certificate (created lazily, kept on the run).
 * Nothing is sent here: pairs, rows and the expected fingerprints are all local.
 * @param {object} run scan run
 * @returns {object|null}
 */
function ensureJob(run) {
  if (run.verify) {
    readOrigins(run.verify);
    return run.verify;
  }
  if (!run.result || !run.config || !run.config.cert) return null;
  // Several certificate sets (lib/certsets.js): one queue for every set; each pair carries the set
  // planned for its name, and its verdict compares with that set's certificates.
  const sets = Array.isArray(run.config.certSets) && run.config.certSets.length ? run.config.certSets : null;
  const { pairs, stats } = buildVerifyPairs(run.result, sets ? { setOf: setOfName(sets) } : {});
  const job = {
    rows: [], pairs, stats: stats || {}, scope: 'all', origins: false,
    status: 'idle', stoppedBy: null, spent: 0, runs: 0, controller: null, listeners: new Set(),
    expect: null, expectValue: null, sets, setExpect: null, setExpectValue: null, startedAt: null, finishedAt: null,
    batch: [], quotaOut: null, error: null, starting: false, launch: null, rememberTab: null,
    // The workspace the scan ran in (its origin map takes the batch's origin checks) and what that did.
    workspace: run.config.workspace || null, originNote: null
  };
  job.expect = expectationFor(sets ? sets.flatMap((s) => s.certs) : run.config.cert).then((e) => {
    job.expectValue = e;
    return e;
  });
  job.expect.catch(() => {}); // surfaced when a batch starts
  if (sets) {
    job.setExpect = setExpectations(sets).then((m) => {
      job.setExpectValue = m;
      return m;
    });
    job.setExpect.catch(() => {});
  }
  setScope(job, 'all');
  run.verify = job;
  return job;
}

/**
 * What a finished batch says (the background toast and the mounted panel's announcement).
 * @param {object} job
 * @returns {{ message: string, type: 'success'|'warn'|'info' }}
 */
function endMessage(job) {
  const s = summarizeVerify(job.rows).servers || {};
  const done = t('vfy.doneToast', { live: formatNumber(s.live || 0), total: formatNumber(serverBase(s)) });
  if (job.status === 'done') return { message: done, type: 'success' };
  if (job.status === 'cancelled') return { message: stoppedText(), type: 'info' };
  if (job.stoppedBy === 'quota' && quotaOutActive(job.quotaOut)) {
    return { message: t('vfy.quotaOut', { when: whenText(job.quotaOut.resetAt), count: job.quotaOut.count }), type: 'warn' };
  }
  if (job.error || job.stoppedBy === 'unreachable') return { message: t('vfy.unreachable'), type: 'warn' };
  return { message: done, type: 'warn' };
}

function backgroundToast(job) {
  const { message, type } = endMessage(job);
  toast(message, {
    type,
    timeout: 10000,
    action: {
      label: t('scan.showResults'),
      onClick: () => {
        if (job.rememberTab) job.rememberTab('verify');
        globalThis.location.hash = '#/scan';
      }
    }
  });
}

/**
 * Run a confirmed batch on the job (detached from any mounted panel). Only the confirmed rows
 * can be sent: a row that left the job (scope switch) or an origin row whose opt-in was
 * turned off meanwhile is dropped, and any other pending row is parked first, because the
 * runner sends every pending row it is given (critic C.3.1, spec §11.2).
 * @param {object} job
 * @param {object} client
 * @param {object[]} targets the rows the user confirmed
 * @param {{ maxProbes: number, now?: () => number }} opts
 */
function execute(job, client, targets, { maxProbes, now = undefined }) {
  const inRows = new Set(job.rows);
  const batch = targets.filter((r) => inRows.has(r) && r.state !== 'skipped' && (job.origins || !isOriginPair(r)));
  const inBatch = new Set(batch);
  for (const r of job.rows) {
    if (r.state !== 'pending' || inBatch.has(r)) continue;
    r.state = 'not-run';
    r.notRun = isOriginPair(r) && !r.verdict && !job.origins ? 'optional' : 'budget';
    r.stale = !!r.verdict;
  }
  requeueRows(batch);
  job.batch = batch;
  job.status = 'running';
  job.stoppedBy = null;
  job.error = null;
  job.quotaOut = null;
  job.controller = new AbortController();
  job.startedAt = new Date();
  job.finishedAt = null;
  job.runs += 1;
  liveJobs.add(job);
  emitJob(job, 'start');
  const { signal } = job.controller;
  (async () => {
    const expect = await job.expect;
    const bySet = job.setExpect ? await job.setExpect : null;
    // A remembered origin the map marked stale since the rows were made waits behind the others.
    readOrigins(job);
    return runVerify(runOrder(job.rows, batch), {
      client,
      expect,
      expectFor: bySet ? (row) => bySet.get(row.setId) ?? null : null,
      signal,
      maxProbes,
      now,
      onRow: (row) => emitJob(job, 'row', row),
      onQuota: (q) => {
        noteQuota(q);
        emitJob(job, 'quota', q);
      }
    });
  })().then((res) => {
    const r = res || {};
    job.spent += Number(r.spent) || 0;
    job.stoppedBy = r.stoppedBy || null;
    job.status = r.stoppedBy === 'abort' ? 'cancelled' : (r.stoppedBy ? 'stopped' : 'done');
    if (r.stoppedBy === 'quota') {
      job.quotaOut = {
        resetAt: sharedQuota() ? sharedQuota().resetAt : null,
        at: Date.now(),
        count: job.rows.filter((x) => x.state === 'not-run' && x.notRun === 'quota').length
      };
    }
  }, (err) => {
    const aborted = errorKind(err) === 'abort';
    job.status = aborted ? 'cancelled' : 'stopped';
    job.stoppedBy = aborted ? 'abort' : 'error';
    job.error = aborted ? null : err;
    for (const r of job.batch) {
      if (r.state !== 'pending' && r.state !== 'running') continue;
      if (aborted) {
        r.state = 'not-run';
        r.notRun = 'cancelled';
      } else {
        r.state = 'error';
        r.error = { code: 'unknown', message: String((err && err.message) || err) };
      }
    }
  }).finally(() => {
    job.finishedAt = new Date();
    job.controller = null;
    liveJobs.delete(job);
    recordVerifyOrigins(job);
    emitJob(job, 'end');
    if (!job.listeners.size && job.status !== 'cancelled') backgroundToast(job);
  });
}

/**
 * The batch's checks of exact origins (the origin map's own, the zone file's: never a hint's
 * candidate) with a verdict into the origin map of the workspace the scan ran in (never another
 * one switched to meanwhile); `job.originNote` says what this batch changed, or that remembering
 * is off, and is empty after a batch without such a check.
 * @param {object} job
 */
function recordVerifyOrigins(job) {
  job.originNote = null;
  const observations = verifyObservations(job.batch);
  if (!observations.length || (job.workspace && job.workspace !== state.workspace.id)) return;
  const res = recordOrigins(observations, { source: 'verify', at: job.finishedAt });
  job.originNote = { off: res.off, text: res.off ? '' : recordText(res) };
}

/**
 * The consent + cost dialog (a Modal: two paragraphs never nest inside confirmDialog's <p>).
 * An aborted launch (new scan, panel gone, "Delete all local data") closes it unanswered.
 * @returns {Promise<boolean>}
 */
async function confirmBatch({ first, checks, fit, remaining, limit, resetAt, unknown, origins, signal = null }) {
  if (signal && signal.aborted) return false;
  const partial = fit < checks;
  const when = whenText(resetAt);
  const modal = Modal({
    title: t('vfy.confirm.title'),
    size: 'md',
    className: 'vfy-confirm',
    content: h('div', { class: 'stack-sm' },
      first ? h('p', { class: 'vfy-confirm-privacy', dataset: { vfy: 'confirm-privacy' } }, t('vfy.privacy')) : null,
      origins ? h('p', { dataset: { vfy: 'confirm-origins' } }, t('vfy.origins.confirm', { count: origins })) : null,
      h('p', { class: 'vfy-confirm-cost', dataset: { vfy: 'confirm-cost', checks: String(checks), fit: String(fit) } },
        partial
          ? t('vfy.confirm.partial', { fit: formatNumber(fit), checks: formatNumber(checks), remaining: formatNumber(remaining), when })
          : t('vfy.confirm.body', { checks: formatNumber(checks), remaining: formatNumber(remaining), when, retries: formatNumber(VERIFY_MAX_RETRIES) })),
      unknown ? h('p', { class: 'muted text-sm', dataset: { vfy: 'confirm-quota-unknown' } }, t('vfy.quotaUnknown', { limit: formatNumber(limit) })) : null),
    actions: [
      { label: t('common.cancel'), value: false, variant: 'secondary' },
      { label: partial ? t('vfy.confirm.goPartial', { count: fit }) : t('vfy.confirm.go'), value: true, variant: 'primary', icon: 'globe', autofocus: true }
    ]
  });
  const onAbort = () => modal.close(null);
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
  try {
    const value = await modal.open();
    return value === true && !(signal && signal.aborted);
  } finally {
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/** Same rows, whatever the order. */
function sameRows(a, b) {
  if (a.length !== b.length) return false;
  const set = new Set(b);
  return a.every((r) => set.has(r));
}

/**
 * Free quota read, cost preview, consent dialog, then the batch. Sends nothing when the quota
 * is used up, the dialog is cancelled or the launch is aborted. The rows and the price are
 * worked out again after every wait, from the rows as they are then: a batch whose rows or
 * price changed while the dialog was open is shown again rather than run as confirmed.
 * @param {object} job
 * @param {object[]} clickTargets the rows the click was for
 * @param {object} ctx view context (getGlobalping)
 * @param {{ signal: AbortSignal, confirm: Function, now: () => number }} opts
 * @returns {Promise<boolean>} whether a batch started
 */
async function confirmAndRun(job, clickTargets, ctx, { signal, confirm, now }) {
  let client;
  try {
    client = await ctx.getGlobalping();
  } catch (err) {
    if (signal.aborted) return false;
    job.error = err;
    job.stoppedBy = 'unreachable';
    emitJob(job, 'change');
    return false;
  }
  if (signal.aborted) return false;
  let q = null;
  let unknown = false;
  try {
    q = await client.limits({ signal });
  } catch (err) {
    if (signal.aborted || errorKind(err) === 'abort') return false;
    unknown = true;
    // The client's last reading, unless its window has ended (then the hour starts over).
    q = liveQuota(client.quota);
  }
  if (signal.aborted || job.status === 'running') return false;
  noteQuota(q);
  const limit = q && Number.isFinite(q.limit) ? q.limit : GP_LIMITS.anonymousPerHour;
  const remaining = q && Number.isFinite(q.remaining) ? Math.max(0, q.remaining) : limit;
  let confirmed = null;
  for (let round = 0; round < MAX_CONFIRM_ROUNDS; round += 1) {
    const targets = targetRows(job.rows, { ran: job.runs > 0, origins: job.origins });
    if (!targets.length) return false;
    const checks = batchCost(targets, { now: now() + REUSE_MARGIN_MS });
    const fit = Math.min(checks, remaining);
    if (checks > 0 && fit === 0) {
      // Nothing fits: say when it resets and send nothing (every later click re-reads /limits for free).
      job.quotaOut = { resetAt: q ? q.resetAt : null, at: Date.now(), count: targets.length };
      job.error = null;
      if (job.stoppedBy === 'unreachable') job.stoppedBy = null;
      emitJob(job, 'change');
      return false;
    }
    const covered = !!confirmed && sameRows(targets, confirmed.targets) && checks <= confirmed.checks;
    const origins = targets.filter(isOriginPair).length;
    const ask = !covered && (!!confirmed || !hasConsent(CONSENT) || fit < checks || checks > VERIFY_SOFT_CONFIRM_PROBES
      || (origins > 0 && !originsConsented) || !sameRows(targets, clickTargets));
    if (ask) {
      const ok = await confirm({
        first: !hasConsent(CONSENT), checks, fit, remaining, limit, resetAt: q ? q.resetAt : null, unknown, origins, signal
      });
      if (!ok || signal.aborted || job.status === 'running') return false;
      confirmed = { targets, checks };
      continue;
    }
    grantConsent(CONSENT);
    // Reached only after a dialog that named the origin checks, or once one already had.
    if (origins > 0) originsConsented = true;
    // A full batch keeps room for the probe-fault retries; a partial one spends exactly what fits.
    const maxProbes = fit < checks ? fit : Math.min(remaining, checks + VERIFY_MAX_RETRIES);
    execute(job, client, targets, { maxProbes, now });
    return true;
  }
  return false;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

/**
 * The run's verification job (created on first use; null without a result or a certificate).
 * @param {object} run scan run
 * @returns {object|null}
 */
export function verifyJob(run) {
  return run ? ensureJob(run) : null;
}

/**
 * Stop the run's verification (a new scan, "Delete all local data"): a pending Start / Check
 * again (quota read or dialog) is dropped without sending anything, and rows in flight become
 * "Not checked · Stopped". Paid measurement ids are kept: "Check again" within the reuse window
 * (2 minutes, once) fetches them without a new probe; after that they are sent again.
 * @param {object|null} run
 */
export function cancelVerify(run) {
  const job = run && run.verify;
  if (!job) return;
  if (job.launch) job.launch.abort();
  if (job.controller) job.controller.abort();
}

/**
 * Start / Check again on the run's job: one free /limits read, the consent + cost dialog when
 * needed, then the batch. Re-entrancy guarded on the job; `job.starting` changes are emitted
 * ('change'), so whichever panel is mounted re-renders, even when the one clicked was disposed.
 * While it is starting, the rows cannot change ({@link setOriginOptIn}, {@link setVerifyScope}).
 * @param {object} run scan run with a verification job
 * @param {{ getGlobalping: () => Promise<object> }} ctx
 * @param {{ confirm?: (opts: object) => Promise<boolean>, now?: () => number }} [opts]
 *   `confirm` replaces the dialog (tests); `now` the clock (tests)
 * @returns {Promise<boolean>} whether a batch started
 */
export async function launchVerify(run, ctx, { confirm = confirmBatch, now = () => Date.now() } = {}) {
  const job = run && run.verify;
  if (!job || job.status === 'running' || job.starting) return false;
  const targets = targetRows(job.rows, { ran: job.runs > 0, origins: job.origins });
  if (!targets.length) return false;
  const launch = new AbortController();
  job.launch = launch;
  job.starting = true;
  launchingJobs.add(job);
  emitJob(job, 'change');
  try {
    return await confirmAndRun(job, targets, ctx, { signal: launch.signal, confirm, now });
  } catch (err) {
    if (launch.signal.aborted || errorKind(err) === 'abort') return false;
    job.error = err;
    job.stoppedBy = 'error';
    return false;
  } finally {
    if (job.launch === launch) job.launch = null;
    launchingJobs.delete(job);
    job.starting = false;
    emitJob(job, 'change');
  }
}

/**
 * The origin opt-in (critic C.3.1). Refused while a batch runs or a launch is starting: the
 * rows a confirmed batch sends must not change under it.
 * @param {object} run
 * @param {boolean} on
 * @returns {boolean} whether it changed
 */
export function setOriginOptIn(run, on) {
  const job = run && run.verify;
  if (!job || job.status === 'running' || job.starting) return false;
  job.origins = !!on;
  applyOriginOptIn(job.rows, job.origins);
  return true;
}

/**
 * Every name / one name per IP, before the first batch only; refused while a launch is starting.
 * @param {object} run
 * @param {'all'|'perIp'} scope
 * @returns {boolean} whether it changed
 */
export function setVerifyScope(run, scope) {
  const job = run && run.verify;
  if (!job || job.status === 'running' || job.starting || job.runs > 0) return false;
  setScope(job, scope);
  return true;
}

/**
 * Tab badge "live/total" servers, or null before the first batch.
 * @param {object|null} run
 * @returns {{ value: string, variant: 'ok'|'warn'|null }|null}
 */
export function verifyTabBadge(run) {
  const job = run && run.verify;
  if (!job || !job.runs) return null;
  return badgeFromSummary(summarizeVerify(job.rows));
}

/**
 * The verification block of the scan's full JSON export (null until something was checked); its
 * rows of remembered origins read the workspace's origin map as it is now (`originStale`).
 * @param {object|null} run
 * @param {string} version app version
 * @returns {object|null}
 */
export function verifyExport(run, version) {
  const job = run && run.verify;
  if (!job || !job.runs) return null;
  readOrigins(job);
  return verifyExportJson(job.rows, { expect: job.expectValue, sets: job.setExpectValue, summary: summarizeVerify(job.rows), version });
}

/**
 * The Verify tab body for a finished scan run with a certificate.
 * @param {{ run: object, ctx: import('../app.js').ViewContext, onShowTab?: (id: string) => void,
 *   onChange?: () => void, rememberTab?: (id: string) => void,
 *   cli?: { path?: string, shells?: string[], pythonFor?: Record<string, string>,
 *     getShell?: () => string, setShell?: (shell: string) => void } }} opts
 *   `cli` shares the host view's CLI path and shell choice (so the CDN and Verify cards agree);
 *   `rememberTab` lets the background toast reopen this tab; `onChange` refreshes the tab badge.
 *   After the host view changed the shared shell, `refreshShell` redraws the CLI card.
 * @returns {{ el: HTMLElement, refreshShell?: () => void, dispose(): void }}
 */
export function VerifyPanel({ run, ctx, onShowTab = null, onChange = null, rememberTab = null, cli = {} }) {
  const el = h('div', { class: 'vfy-panel', dataset: { vfy: 'panel' } });
  let job;
  try {
    job = ensureJob(run);
  } catch (err) {
    el.append(ErrorBanner(err, { title: t('vfy.failed') }));
    return { el, dispose() {} };
  }
  if (!job) {
    el.append(EmptyState({ compact: true, icon: 'minus-circle', message: t('scan.notAvailable') }));
    return { el, dispose() {} };
  }
  if (rememberTab) job.rememberTab = rememberTab;
  const cert = run.config.cert;
  // Several certificate sets: a Set column and a line on how names are compared (one set: no column).
  const showSets = !!job.sets && job.sets.length > 1;
  const subject = (run.config.domains && run.config.domains[0]) || '';
  const shells = Array.isArray(cli.shells) && cli.shells.length ? cli.shells : DEFAULT_SHELLS;
  const pythonFor = cli.pythonFor || DEFAULT_PYTHON;
  const cliPath = cli.path || DEFAULT_CLI_PATH;
  const getShell = () => {
    const sh = cli.getShell ? cli.getShell() : fallbackShell;
    return shells.includes(sh) ? sh : shells[0];
  };
  const setShell = (sh) => {
    if (cli.setShell) cli.setShell(sh);
    else fallbackShell = sh;
  };
  let disposed = false;
  const changed = () => {
    if (onChange) onChange();
  };

  /* --- static parts ------------------------------------------------------ */
  const checkable = job.pairs.some((p) => !p.skip);
  const intro = h('p', { class: 'vfy-intro' }, t('vfy.intro'),
    showSets ? h('span', { class: 'vfy-sets', dataset: { vfy: 'sets' } }, ` ${t('vfy.sets', {
      list: job.sets.map((s) => `${t('rw.set', { id: s.id })}: ${s.names[0]}${s.names.length > 1 ? ` +${s.names.length - 1}` : ''}`).join(' · ')
    })}`) : null);
  const infoHost = h('div', { class: 'vfy-info' });
  const statusHost = h('div', { class: 'vfy-status' });
  const actionsHost = h('div', { class: 'vfy-actions' });
  const quotaEl = h('p', { class: 'vfy-quota', dataset: { vfy: 'quota' }, hidden: true });
  const cliHost = h('div', { class: 'vfy-cli-host' });
  const cant = h('p', { class: 'vfy-cant', dataset: { vfy: 'cant' } }, Icon('info', { size: 14 }), h('span', null, t('vfy.cant')));

  /* --- table --------------------------------------------------------------- */
  const saveFile = (ext, text, mime) => {
    const file = downloadText(timestampedName('verify', ext, subject), text, mime);
    toast(t('vfy.exported', { file }), { type: 'success', timeout: 2500 });
  };
  const table = checkable ? DataTable({
    caption: t('vfy.caption'),
    rows: job.rows,
    rowKey: (r) => r.key,
    search: job.rows.length > 10,
    pageSize: 200,
    dense: true,
    // Rows would jump while the batch runs (updateRow re-sorts): execution order until it ends.
    sort: job.status === 'running' ? null : { key: 'result', dir: 'asc' },
    rowClass: verifyRowClass,
    details: verifyDetails,
    className: 'vfy-table',
    export: {
      filename: 'verify',
      subject,
      onExport: (format, rows) => {
        if (format === 'csv') saveFile('csv', toCsv(verifyExportRows(rows), job.sets ? [...VERIFY_CSV_COLUMNS, ...VERIFY_SET_COLUMNS] : VERIFY_CSV_COLUMNS), 'text/csv;charset=utf-8');
        else {
          const json = verifyExportJson(rows, { expect: job.expectValue, sets: job.setExpectValue, summary: summarizeVerify(rows), version: ctx.version });
          saveFile('json', `${toJson(json)}\n`, 'application/json;charset=utf-8');
        }
      }
    },
    columns: [
      {
        key: 'result', label: t('vfy.col.result'), sortable: true, sortValue: resultRank,
        searchValue: resultSearchText, render: resultCell
      },
      {
        key: 'name', label: t('vfy.col.name'), sortable: true, sortValue: (r) => hostSortKey(r.name),
        searchValue: (r) => r.name, render: (r) => h('span', { class: 'mono vfy-name' }, r.name)
      },
      showSets ? {
        key: 'set', label: t('vfy.col.set'), sortable: true, sortValue: (r) => r.setId || '',
        searchValue: (r) => (r.setId ? t('rw.set', { id: r.setId }) : ''),
        render: (r) => (r.setId ? SetBadge(r.setId, { variant: 'neutral' }) : null)
      } : null,
      {
        key: 'ip', label: t('vfy.col.ip'), sortable: true, sortValue: (r) => ipSortValue(r.ip),
        searchValue: (r) => [r.ip, serverLabel(r)].join(' '), render: ipCell
      },
      {
        key: 'served', label: t('vfy.col.served'), sortable: true,
        sortValue: (r) => (r.served && r.served.notAfter ? new Date(r.served.notAfter) : null),
        searchValue: (r) => (r.served ? [r.served.subjectCN, ...(r.served.dnsNames || []), r.served.issuerO, r.served.issuerCN].filter(Boolean).join(' ') : ''),
        render: servedCell
      },
      {
        key: 'from', label: t('vfy.col.from'), sortable: true,
        sortValue: (r) => (probesOf(r)[0] ? probesOf(r)[0].country || null : null),
        searchValue: (r) => probesOf(r).map(probeText).join(' '),
        render: fromCell
      }
    ].filter(Boolean)
  }) : null;

  /* --- rendering ------------------------------------------------------------ */
  const ran = () => job.runs > 0;
  /** Controls that change the rows are frozen while a batch runs or a launch is starting. */
  const locked = () => job.status === 'running' || job.starting;

  function planLine() {
    const c = planCounts(job.rows);
    return h('p', { class: 'vfy-plan', dataset: { vfy: 'plan', checks: String(c.checks), servers: String(c.servers) } },
      planText(job.rows, { quota: sharedQuota() }));
  }

  function notHereLine() {
    const text = notHereSentence(job.rows, job.stats);
    if (!text) return null;
    const proxied = Number(job.stats.proxiedNoOrigin) > 0 && onShowTab;
    return h('p', { class: 'vfy-nothere', dataset: { vfy: 'nothere' } },
      h('span', null, text),
      proxied ? Button({ size: 'sm', variant: 'ghost', icon: 'cloud', label: t('vfy.cdnLink'), dataset: { action: 'vfy-open-cdn' }, onClick: () => onShowTab('cdn') }) : null);
  }

  function scopeControl() {
    const count = (scope) => checkCount(scopePairs(job.pairs, scope), { origins: job.origins });
    const all = count('all');
    const perIp = count('perIp');
    if (!(perIp < all)) return null;
    const seg = SegmentedControl({
      label: t('vfy.scope.label'),
      size: 'sm',
      value: job.scope,
      options: [
        { value: 'all', label: t('vfy.scope.all', { count: all }) },
        { value: 'perIp', label: t(showSets ? 'vfy.scope.perIpSet' : 'vfy.scope.perIp', { count: perIp }) }
      ],
      onChange: (v) => {
        if (setVerifyScope(run, v) && table) table.setRows(job.rows);
        render(); // also puts the pressed state back when the switch was refused
      }
    });
    if (locked()) for (const b of seg.el.querySelectorAll('button')) b.disabled = true;
    return h('div', { class: 'vfy-scope', dataset: { vfy: 'scope' } }, h('span', { class: 'muted text-sm' }, t('vfy.scope.label')), seg.el);
  }

  function originsControl() {
    const count = planCounts(job.rows).origins;
    if (!count) return null;
    const box = checkbox({
      label: t('vfy.origins', { count }),
      hint: t('vfy.origins.hint'),
      checked: job.origins,
      disabled: locked(),
      className: 'vfy-origins',
      onChange: (on) => {
        if (!setOriginOptIn(run, on)) {
          box.input.checked = job.origins;
          return;
        }
        if (table) table.refresh();
        render();
        changed();
      }
    });
    box.el.dataset.vfy = 'origins';
    return box.el;
  }

  function renderInfo() {
    clear(infoHost);
    const idle = !ran() && job.status !== 'running';
    if (idle && checkable) infoHost.append(planLine());
    const nh = notHereLine();
    if (nh) infoHost.append(nh);
    if (idle && checkable) {
      const scope = scopeControl();
      if (scope) infoHost.append(scope);
    }
    if (checkable && job.status !== 'running') {
      const origins = originsControl();
      if (origins) infoHost.append(origins);
    }
    if (idle && checkable) {
      // A quiet line, not an alert: a privacy note is not news (Globalping probes connect to your servers).
      const privacy = PrivacyNote({ text: t('vfy.privacy'), className: 'vfy-privacy' });
      privacy.dataset.vfy = 'privacy';
      infoHost.append(privacy);
    }
    infoHost.hidden = !infoHost.firstChild;
  }

  /**
   * Status parts (quota used up, unreachable, stopped, headline) are rebuilt only when their text
   * changes: re-inserting a role=alert warning on every render (an origin toggle, a cancelled
   * dialog) would read it out again.
   */
  const statusParts = new Map();
  function renderStatus() {
    if (job.quotaOut && !quotaOutActive(job.quotaOut)) job.quotaOut = null;
    const want = [];
    if (job.quotaOut) {
      const message = t('vfy.quotaOut', { when: whenText(job.quotaOut.resetAt), count: job.quotaOut.count });
      want.push({
        id: 'quota-out', sig: message, build: () => {
          const a = Alert({ variant: 'warn', icon: 'clock', message, actions: [ExternalLink(GP_CREDITS_URL, t('vfy.credits'))] });
          a.dataset.vfy = 'quota-out';
          return a;
        }
      });
    }
    if (job.status !== 'running') {
      if (job.stoppedBy === 'unreachable' || job.stoppedBy === 'error') {
        const netRow = job.rows.find((r) => r.state === 'error' && r.error && r.error.code === 'network' && r.error.message);
        const lastErr = job.error || new TypeError(netRow ? netRow.error.message : t('vfy.err.network'));
        const title = job.stoppedBy === 'error' ? t('vfy.failed') : t('vfy.unreachable');
        want.push({
          id: 'unreachable', sig: `${title}\n${(lastErr && lastErr.message) || lastErr}`, build: () => {
            const banner = ErrorBanner(lastErr, { title, onRetry: () => launch() });
            banner.dataset.vfy = 'unreachable';
            return banner;
          }
        });
      }
      if (job.status === 'cancelled') {
        const message = stoppedText();
        want.push({
          id: 'stopped', sig: message, build: () => {
            const a = Alert({ variant: 'info', compact: true, icon: 'stop', message });
            a.dataset.vfy = 'stopped';
            return a;
          }
        });
      }
      if (ran()) {
        const summary = summarizeVerify(job.rows);
        const entries = (verifyHeadline(summary, job.stats) || []).map((entry) => {
          const id = String(entry.key || '').replace(/^vfy\.head\./, '');
          const list = id === 'notHere' ? notHereText(job.rows, job.stats, entry.parts) : '';
          return { id, variant: entry.variant || 'info', text: t(entry.key, headlineParams(entry, summary, list)) };
        });
        if (entries.length) {
          want.push({
            id: 'headline', sig: entries.map((e) => `${e.id}|${e.variant}|${e.text}`).join('\n'), build: () => {
              // No aria-live here: a finished batch is announced once (announce() on 'end').
              const head = h('div', { class: 'vfy-headline' });
              for (const e of entries) {
                const a = Alert({ variant: e.variant, compact: true, icon: HEAD_ICONS[e.id] || undefined, message: e.text });
                a.dataset.head = e.id;
                head.append(a);
              }
              return head;
            }
          });
        }
        // What the batch's origin checks did to the workspace's origin map.
        const note = job.status === 'running' ? null : job.originNote;
        if (note) {
          want.push({
            id: 'origins', sig: note.off ? 'off' : note.text, build: () => {
              const a = note.off ? OriginMapOffNote(ctx) : Alert({ variant: 'info', compact: true, icon: 'map-pin', message: note.text });
              a.dataset.vfy = 'origin-map';
              return a;
            }
          });
        }
      }
    }
    const wanted = new Map(want.map((w) => [w.id, w]));
    for (const [id, part] of [...statusParts]) {
      const w = wanted.get(id);
      if (!w || w.sig !== part.sig) {
        part.node.remove();
        statusParts.delete(id);
      }
    }
    // The ids keep a fixed order, so kept parts never move; new ones go right after their predecessor.
    let prev = null;
    for (const w of want) {
      let part = statusParts.get(w.id);
      if (!part) {
        part = { sig: w.sig, node: w.build() };
        statusParts.set(w.id, part);
        if (prev) prev.after(part.node);
        else statusHost.prepend(part.node);
      }
      prev = part.node;
    }
    statusHost.hidden = !statusHost.firstChild;
  }

  let bar = null;
  function renderProgress() {
    if (!bar) return;
    const batch = job.batch || [];
    const done = batch.filter((r) => r.state !== 'pending' && r.state !== 'running').length;
    bar.set(done, Math.max(1, batch.length));
    bar.setLabel(t('vfy.progress', { done: formatNumber(done), total: formatNumber(batch.length) }));
  }

  function renderActions() {
    clear(actionsHost);
    bar = null;
    if (!checkable) {
      actionsHost.hidden = true;
      return;
    }
    actionsHost.hidden = false;
    if (job.status === 'running') {
      bar = ProgressBar({ label: '', value: 0, max: 1, showCount: false });
      bar.el.dataset.vfy = 'progress';
      renderProgress();
      actionsHost.append(h('div', { class: 'vfy-progress' }, bar.el,
        Button({ label: t('vfy.stop'), icon: 'stop', dataset: { action: 'vfy-stop', shortcut: 'cancel' }, onClick: () => cancelVerify(run) })));
      return;
    }
    const targets = targetRows(job.rows, { ran: ran(), origins: job.origins });
    let btn = null;
    if (!ran()) {
      btn = Button({ label: t('vfy.start'), icon: 'globe', variant: 'primary', dataset: { action: 'vfy-start' }, disabled: !targets.length, onClick: () => launch() });
    } else if (targets.length) {
      btn = Button({
        label: t('vfy.recheck', { count: targets.length }), icon: 'refresh', variant: 'primary',
        dataset: { action: 'vfy-recheck', count: String(targets.length) }, onClick: () => launch()
      });
    }
    if (btn) {
      if (job.starting) setButtonBusy(btn, true);
      actionsHost.append(btn);
    }
    actionsHost.hidden = !actionsHost.firstChild;
  }

  function renderQuota() {
    const q = liveQuota(sharedQuota());
    quotaEl.hidden = !q;
    if (!q) return;
    quotaEl.dataset.remaining = String(q.remaining);
    const params = { remaining: formatNumber(q.remaining), limit: formatNumber(q.limit) };
    quotaEl.textContent = q.resetAt ? t('vfy.quota', { ...params, when: whenText(q.resetAt) }) : t('vfy.quotaFresh', params);
  }

  function renderCli() {
    clear(cliHost);
    const plan = cliPlan(job.rows);
    if (!plan || !plan.rows) return;
    const cmdHost = h('div', { class: 'stack-sm vfy-cli-cmd' });
    const renderCmd = () => {
      clear(cmdHost);
      const shell = getShell();
      const sweep = verifyCliSweep(plan, shell, job.sets ? cliCertFiles(job.sets).map((f) => f.file) : null);
      if (!sweep.command) {
        cmdHost.append(h('p', { class: 'muted text-sm', dataset: { vfy: 'cli-none' } }, t('vfy.cli.none')));
      } else {
        cmdHost.append(CodeBlock(`${pythonFor[shell] || 'python3'} ${sweep.command}`, { label: t('vfy.cli.command'), wrap: true }));
      }
      const d = sweep.dropped || {};
      const dropped = (d.targets || []).length + (d.names || []).length + (d.options || []).length;
      if (dropped) cmdHost.append(h('p', { class: 'muted text-sm', dataset: { vfy: 'cli-dropped' } }, t('vfy.cli.dropped', { count: dropped })));
      if (sweep.command && sweep.namesInline === false && sweep.namesFile) {
        const text = `${(sweep.names || []).join('\n')}\n`;
        cmdHost.append(h('div', { class: 'vfy-cli-namesfile', dataset: { file: sweep.namesFile } },
          h('p', { class: 'muted text-sm' }, t('vfy.cli.namesFile', { file: sweep.namesFile, count: formatNumber((sweep.names || []).length) })),
          Button({
            label: t('vfy.cli.namesFileDownload', { file: sweep.namesFile }), icon: 'download', size: 'sm', dataset: { action: 'vfy-names-file' },
            onClick: () => {
              const file = downloadText(sweep.namesFile, text, 'text/plain;charset=utf-8');
              toast(t('vfy.exported', { file }), { type: 'success', timeout: 2500 });
            }
          })));
      }
      if (sweep.command && sweep.targetsInline === false && sweep.targetsFile) {
        const text = `${(sweep.targets || []).join('\n')}\n`;
        cmdHost.append(h('div', { class: 'vfy-cli-namesfile', dataset: { file: sweep.targetsFile } },
          h('p', { class: 'muted text-sm' }, t('vfy.cli.targetsFile', { file: sweep.targetsFile, count: formatNumber((sweep.targets || []).length) })),
          Button({
            label: t('vfy.cli.namesFileDownload', { file: sweep.targetsFile }), icon: 'download', size: 'sm', dataset: { action: 'vfy-targets-file' },
            onClick: () => {
              const file = downloadText(sweep.targetsFile, text, 'text/plain;charset=utf-8');
              toast(t('vfy.exported', { file }), { type: 'success', timeout: 2500 });
            }
          })));
      }
    };
    const seg = SegmentedControl({
      label: t('scan.cdn.shell'),
      size: 'sm',
      value: getShell(),
      options: shells.map((sh) => ({ value: sh, label: t(`scan.cdn.shell.${sh}`), title: t(`scan.cdn.shellTitle.${sh}`) })),
      onChange: (sh) => {
        setShell(shells.includes(sh) ? sh : shells[0]);
        renderCmd();
      }
    });
    seg.el.dataset.vfy = 'shell';
    renderCmd();
    const certBtn = cert && cert.der && !job.sets ? Button({
      icon: 'download', label: t('vfy.cli.cert'), dataset: { action: 'vfy-cert' },
      onClick: () => {
        const file = downloadText(CLI_CERT_FILE, pemEncode(cert.der), 'application/x-pem-file');
        toast(t('vfy.exported', { file }), { type: 'success', timeout: 2500 });
      }
    }) : null;
    cliHost.append(Card({
      title: t('vfy.cli.title'),
      subtitle: t('vfy.cli.desc'),
      icon: 'terminal',
      className: 'vfy-cli',
      children: h('div', { class: 'stack-sm' }, seg.el, cmdHost,
        job.sets ? h('div', { class: 'vfy-actions', dataset: { vfy: 'cli-certs' } }, CertFileButtons(job.sets)) : null,
        h('div', { class: 'vfy-actions' }, certBtn,
          ButtonLink({ href: cliPath, label: t('vfy.cli.download'), icon: 'download', download: CLI_SCRIPT })))
    }));
  }

  /* --- focus ---------------------------------------------------------------- */
  // render() rebuilds the controls: the focused one is found again by its data-action /
  // data-vfy selector; a control that is gone or disabled hands focus to the panel's action button.
  const cssValue = (s) => (globalThis.CSS && typeof globalThis.CSS.escape === 'function' ? globalThis.CSS.escape(String(s)) : String(s).replace(/["\\]/g, '\\$&'));
  /** Focus to put back after a launch (the clicked button is busy or replaced meanwhile). */
  let pendingFocus = null;

  function focusKeyOf(node) {
    if (!node || node === el || !el.contains(node)) return null;
    const action = node.closest('[data-action]');
    if (action && el.contains(action)) return { node, sel: `[data-action="${cssValue(action.dataset.action)}"]` };
    const box = node.closest('[data-vfy]');
    if (box && box !== el) {
      const inner = node.tagName === 'INPUT' ? 'input' : node.dataset && node.dataset.value ? `[data-value="${cssValue(node.dataset.value)}"]` : null;
      if (inner) return { node, sel: `[data-vfy="${cssValue(box.dataset.vfy)}"] ${inner}` };
    }
    return { node, sel: null };
  }

  /** Put focus back per `key` when it fell to the page (never away from where the user or a dialog put it). */
  function restoreFocus(key) {
    const doc = globalThis.document;
    if (!key || !doc) return false;
    const active = doc.activeElement;
    if (key.node && key.node.isConnected && active === key.node) return true;
    if (active && active !== doc.body && active !== doc.documentElement) return false;
    let target = key.sel ? el.querySelector(key.sel) : null;
    if (!target || target.disabled) target = [...actionsHost.querySelectorAll('button')].find((b) => !b.disabled) || null;
    if (!target) return false;
    target.focus({ preventScroll: true });
    return doc.activeElement === target;
  }

  function render() {
    if (disposed) return;
    const doc = globalThis.document;
    const focusKey = focusKeyOf(doc && doc.activeElement);
    // Job state for tests and styling: idle | running | done | stopped | cancelled (+ starting).
    el.dataset.status = job.status;
    el.dataset.starting = job.starting ? 'true' : 'false';
    renderInfo();
    renderStatus();
    renderActions();
    renderQuota();
    renderCli();
    if (focusKey && !focusKey.node.isConnected) restoreFocus(focusKey);
    if (pendingFocus && restoreFocus(pendingFocus) && !job.starting) pendingFocus = null;
  }

  /** Start / Check again (lib-free flow in {@link launchVerify}); focus comes back to the action button. */
  async function launch() {
    if (!ctx.requireOnline()) return;
    const doc = globalThis.document;
    pendingFocus = focusKeyOf(doc && doc.activeElement);
    try {
      await launchVerify(run, ctx);
    } finally {
      if (!disposed && pendingFocus) restoreFocus(pendingFocus);
      pendingFocus = null;
    }
  }

  /* --- live updates ------------------------------------------------------------ */
  const raf = globalThis.requestAnimationFrame || ((cb) => setTimeout(cb, 16));
  let progressQueued = false;
  const progressSoon = () => {
    if (progressQueued) return;
    progressQueued = true;
    raf(() => {
      progressQueued = false;
      if (!disposed) renderProgress();
    });
  };
  const listener = (type, payload) => {
    if (disposed) return;
    switch (type) {
      case 'row':
        if (table && payload) table.updateRow(payload);
        progressSoon();
        changed();
        break;
      case 'quota':
        renderQuota();
        break;
      case 'start':
        if (table) {
          table.sortBy(null);
          table.refresh();
        }
        render();
        changed();
        break;
      case 'end':
        if (table) {
          table.refresh();
          table.sortBy('result');
        }
        render();
        changed();
        // The progress bar and its live region are gone: say how the batch ended.
        announce(endMessage(job).message);
        break;
      default: // 'change'
        if (table) table.refresh();
        render();
        changed();
    }
  };
  job.listeners.add(listener);

  // Quota times are relative ("resets in 12 minutes") and a used-up quota ends: refresh them now and then.
  const clock = setInterval(() => {
    if (disposed) return;
    if (job.quotaOut && !quotaOutActive(job.quotaOut)) render();
    else renderQuota();
  }, 30000);

  /* --- assemble ------------------------------------------------------------ */
  if (checkable) {
    el.append(intro, infoHost, statusHost, actionsHost, quotaEl, table.el, cliHost, cant);
  } else {
    el.append(EmptyState({ icon: 'globe', message: t(emptyKey(job.pairs, job.rows)) }), infoHost, cliHost, cant);
  }
  render();

  return {
    el,
    /** The shared shell (`cli.getShell`) was changed by another card: redraw the CLI card. */
    refreshShell() {
      if (!disposed) renderCli();
    },
    /**
     * The workspace's origin map changed: the rows of remembered origins say whether it now marks
     * them stale, drawn again only when a mark changed (a batch's confirmations leave the table as it is).
     */
    refreshOrigins() {
      if (!readOrigins(job) || disposed) return;
      if (table) table.refresh();
      render();
    },
    dispose() {
      disposed = true;
      clearInterval(clock);
      job.listeners.delete(listener);
      // A launch still reading the quota or showing the dialog belongs to this panel: drop it
      // (nothing sent). A batch already running keeps going on the run.
      if (job.starting && job.launch) job.launch.abort();
    }
  };
}
