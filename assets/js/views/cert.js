/**
 * views/cert.js — "Certificate": inspect a certificate file entirely in the browser.
 *
 * Shows the names (SAN list with IDN decoding and a "does it cover this host?" check),
 * validity, key, fingerprints (incl. the public-key SHA-256 for matching a private key
 * without uploading it), usages, AIA/CRL/SCT data, the chain order (with a correctly
 * ordered fullchain.pem download), a CAA check per name (lib/health.js), a Certificate
 * Transparency lookup of the serial number on crt.sh and, on a click, the DANE / TLSA check of
 * the leaf (ui/dane-panel.js over lib/dane.js: do TLSA records at its mail servers and names pin
 * another certificate?). "Find servers for this certificate" hands the certificate to the SSL
 * Targets view (state.session.pendingCert).
 *
 * "Copy summary" in the overview's actions (ui/summary-button.js, certSummaryFacts): names, validity,
 * issuer and warnings for Jira / Slack; the file is never in its link.
 *
 * The module also exports the certificate-loading helpers used by views/scan.js
 * (CertLoader, CertAlternatives, CertSummary, certWarningAlerts, …) so both views behave
 * identically. Without a file, CertAlternatives loads the public certificate of a host name
 * from Certificate Transparency (lib/ctcert.js; only the name is sent) or the bundled sample
 * (assets/data/sample-cert.pem); CertSourceNote says where such a certificate came from.
 * The loaded certificate is shared between the two views for the session through
 * `state.session.currentCert` (a {@link CertLoad}); it is never persisted or uploaded.
 *
 * Page session (lib/session.js): loading a certificate here makes its name the current target
 * ({@link certTarget}); `#/cert?host=example.com&run=0` (a host carried over from another tool)
 * fills the "No file?" field while it is empty or still holds the last lookup or the host carried
 * before, and loading still takes a click. Coming back to a certificate that was shown here when
 * the view was left says "Result from <time>"; for one from Certificate Transparency, "Run again"
 * looks its host name up again (a file or the sample has nothing to run again). "Delete all local
 * data" forgets the field, its last outcome and the CAA / CT / DANE results kept per certificate.
 */

import { h, clear, debounce, scrollBehavior } from '../ui/dom.js';
import {
  Alert, Badge, Button, ButtonLink, Card, CodeBlock, CopyButton, DataTable, Disclosure, EmptyState, ErrorBanner, ExternalLink,
  FileDrop, Icon, KeyValueList, Spinner, Tabs, TruncatedList, describeError, select, setButtonBusy, textInput, textarea, toast
} from '../ui/components.js';
import { downloadText, sanitizeFilename } from '../ui/download.js';
import {
  t, registerStrings, hasString, formatDate, formatDateTime, formatNumber, formatRegion, daysUntil
} from '../i18n.js';
import { parseCertificates, computeFingerprints, pemEncode, formatFingerprint } from '../lib/x509.js';
import {
  normalizeHostname, certCovers, baseDomainsFromNames, stripWildcard, sortHostnames
} from '../lib/domain.js';
import { findCaa, checkCaaAllows, caaIssuerInfo, caaRestrictionNotes, caaRestrictionText, HEALTH_I18N } from '../lib/health.js';
import { validateNames } from '../lib/cmdline.js';
import { lookupCtCertificate, normalizeCtHost } from '../lib/ctcert.js';
import { fetchJson, fetchText, mergeSignals, retry, errorKind } from '../lib/util.js';
// The DANE / TLSA tab (shared with SSL Targets).
import { DanePanel, cancelDane } from '../ui/dane-panel.js';
import { fillReplaces } from '../lib/session.js';
import { state as stateSingleton } from '../state.js';
import { permalinkParams } from '../lib/summary.js';
import { SummaryButton } from '../ui/summary-button.js';

/** Route id. */
export const id = 'cert';
/** i18n key of the page title. */
export const titleKey = 'nav.cert';
/** Nav/page icon. */
export const icon = 'shield';

/** File types offered by the certificate pickers (PKCS#12 / CSR / keys are detected and explained). */
export const CERT_ACCEPT = '.pem,.crt,.cer,.cert,.der,.p7b,.p7c,.pfx,.p12,.csr,.req,.txt,.key';
/** state.session key holding the {@link CertLoad} shared by the Certificate and SSL Targets views. */
export const CURRENT_CERT = 'currentCert';
/** state.session key for the one-shot hand-over to the SSL Targets view. */
export const PENDING_CERT = 'pendingCert';
/** Largest certificate file accepted (real bundles are a few KB). */
export const CERT_MAX_BYTES = 5 * 1024 * 1024;
/** Certificates expiring within this many days are highlighted. */
export const EXPIRING_DAYS = 30;
/** At most this many names are checked for CAA. */
export const CAA_MAX_NAMES = 60;

/**
 * The bundled "Try a sample" certificate (example.com / example.net, made-up CA; crafted by
 * tests/fixtures/gen_x509_fixtures.mjs). Relative to this module, so it moves with assets/ under
 * v/<commit>/ in the Pages bundle.
 */
export const SAMPLE_CERT_URL = new URL('../../data/sample-cert.pem', import.meta.url).href;

const DAY_MS = 86400000;
const CRTSH_SERIAL_URL = 'https://crt.sh/?serial=';

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

registerStrings('en', {
  'cert.dropTitle': 'Drop the certificate file here',
  'cert.dropHint': 'or click to choose · paste with Ctrl+V · PEM, CRT/CER, DER, P7B',
  'cert.pasteToggle': 'Paste the certificate as text',
  'cert.pasteLabel': 'Certificate text (PEM)',
  'cert.pastePlaceholder': '-----BEGIN CERTIFICATE-----\nMIIF…\n-----END CERTIFICATE-----',
  'cert.pasteApply': 'Read certificate',
  'cert.pasteEmpty': 'Paste a PEM block first.',
  'cert.privacy': 'The file is read locally and never uploaded. The private key is not needed — if the file contains one it is ignored and never shown.',
  'cert.loaderTitle': 'Certificate file',
  'cert.loaderSubtitle': 'The certificate your customer or CA sent — with or without the chain',
  'cert.loadAnother': 'Load another file',
  'cert.remove': 'Remove',
  'cert.removed': 'Certificate removed',
  'cert.loadedToast': '{name}: certificate loaded',
  'cert.fileInfo': '{name} · {count}',
  'cert.count': { one: '{count} certificate', other: '{count} certificates' },
  'cert.emptyTitle': 'No certificate loaded',
  'cert.emptyBody': 'Load the certificate to see its names, validity, key, chain order, CAA status and Certificate Transparency entries — and to find the servers it must be installed on.',

  'cert.alt.title': 'No file? Load the public certificate of a host name',
  'cert.alt.placeholder': 'www.example.com',
  'cert.alt.load': 'Load',
  'cert.alt.hint': 'Reads the newest valid certificate for this name from the public Certificate Transparency logs (Cert Spotter, or crt.sh when Cert Spotter cannot answer). Only the host name is sent.',
  'cert.alt.invalid': 'Enter a host name such as www.example.com (a *.example.com wildcard works too).',
  'cert.alt.searching': 'Searching the Certificate Transparency logs for {host}…',
  'cert.alt.notFound': 'No currently valid certificate for {host} is logged in Certificate Transparency. Internal names and private CAs are never logged, and a certificate issued in the last few hours may not be listed yet.',
  'cert.alt.notFoundTruncated': 'None of the certificates read for {host} is currently valid, but Cert Spotter lists more than were read, and the newest are among the unread ones: a valid certificate may still be logged.',
  'cert.alt.notFoundCrtshPartial': 'No currently valid certificate for {host} was found in the answers received, but crt.sh did not answer every search: a valid certificate may still be logged. Try again later.',
  'cert.alt.notFoundCrtshDown': 'No currently valid certificate for {host} is among those Cert Spotter listed, and crt.sh answered none of its searches: a valid certificate may still be logged. Try again later.',
  'cert.alt.revokedSkipped': { one: '{count} revoked certificate was skipped.', other: '{count} revoked certificates were skipped.' },
  'cert.alt.failed': 'Certificate Transparency could not be searched',
  'cert.alt.spotterQuota': 'Cert Spotter’s hourly limit for your IP address is used up, so crt.sh was searched instead.',
  'cert.alt.spotterAgain': 'Cert Spotter is asked again from about {time}.',
  'cert.alt.bothFailedQuota': 'Cert Spotter’s hourly limit for your IP address is used up, and crt.sh could not answer either:',
  'cert.alt.retryCrtshOnly': 'Until about {time}, “Try again” searches crt.sh only.',
  'cert.alt.spotterFailed': 'Cert Spotter could not answer, so crt.sh was searched instead.',
  'cert.alt.spotterUnreadable': 'Cert Spotter’s copy of the certificate could not be read, so crt.sh was searched instead.',
  'cert.alt.spotterPartial': 'Cert Spotter answered only in part, so crt.sh was searched too.',
  'cert.alt.manualPartial': 'crt.sh did not answer every search, so a newer certificate for this name may be missing here.',
  'cert.alt.manualTitle': 'Found on crt.sh — download it and drop the file above',
  'cert.alt.manualCert': 'Newest valid certificate for {host}: {names}, issued by {issuer}, valid until {date}.',
  'cert.alt.manualWhy': 'crt.sh does not let web pages download certificates, so save the file yourself. crt.sh lists each certificate twice — as the precertificate and as the certificate servers send — and does not say which is which: if the file you drop is marked “Precertificate”, use the other link.',
  'cert.alt.manualWhyOne': 'crt.sh does not let web pages download certificates, so save the file yourself. If the file you drop is marked “Precertificate”, the certificate servers send is not logged yet: take it from the server or the CA.',
  'cert.alt.download': 'Download #{id}',
  'cert.alt.openCrtsh': 'Open on crt.sh',
  'cert.alt.sample': 'Try a sample',
  'cert.alt.sampleHint': 'a made-up certificate for example.com and example.net',
  'cert.alt.sampleFailed': 'The sample certificate could not be loaded.',

  'cert.src.ctBadge': 'From Certificate Transparency',
  'cert.src.sampleBadge': 'Sample',
  'cert.src.ct': 'Loaded from Certificate Transparency — the server may serve a different one.',
  'cert.src.ctWhat': 'The newest valid certificate logged for {host} (issued {date}). A log shows what a CA issued, not what is installed.',
  'cert.src.ctNewerPrecert': 'A newer certificate for this name (issued {date}) is logged only as a precertificate so far.',
  'cert.src.ctPrecert': 'No final certificate of this issuance is logged yet, so the one servers send cannot be loaded from Certificate Transparency: take it from the server or the CA.',
  'cert.src.ctTruncated': 'Cert Spotter lists more certificates for this name than were read; a newer one may exist.',
  'cert.src.ctOpen': 'Open on crt.sh',
  'cert.src.verify': 'Check servers in SSL Targets',
  'cert.src.sample': 'Sample certificate for trying DomainScope: example.com and example.net, issued by a made-up “DomainScope Sample” CA. No server uses it.',

  'cert.warn.PRIVATE_KEY_PRESENT.title': 'The file also contains a private key',
  'cert.warn.PRIVATE_KEY_PRESENT.body': 'It was ignored — never displayed, stored or uploaded. Only the certificate is needed here. Keep key files private and avoid sending them by e-mail.',
  'cert.warn.PKCS12_UNSUPPORTED.title': 'PKCS#12 (.pfx / .p12) files are password-protected',
  'cert.warn.PKCS12_UNSUPPORTED.body': 'Extract the certificates with OpenSSL first, then load cert.pem:',
  'cert.warn.CSR_NOT_CERT.title': 'This is a certificate signing request (CSR), not a certificate',
  'cert.warn.CSR_NOT_CERT.body': 'A CSR is what you send to the certificate authority. Load the certificate you received back (usually .crt or .pem).',
  'cert.warn.NO_CERTIFICATE.title': 'No certificate found',
  'cert.warn.NO_CERTIFICATE.body': 'The input contains no X.509 certificate. Expected a PEM block starting with -----BEGIN CERTIFICATE-----, or a DER / P7B file.',
  'cert.warn.PARSE_ERROR.title': 'Part of the input could not be read',
  'cert.warn.PARSE_ERROR.body': 'Some data was skipped because it is damaged or in an unsupported format.',
  'cert.warn.EXPIRED.title': 'The certificate has expired',
  'cert.warn.EXPIRED.body': 'It expired on {date}. Browsers reject it — do not install it.',
  'cert.warn.NOT_YET_VALID.title': 'The certificate is not valid yet',
  'cert.warn.NOT_YET_VALID.body': 'It becomes valid on {date}. Installed earlier, it causes errors until then.',
  'cert.warn.foundOnly': 'Found instead: {what}',
  'cert.warn.noSan': 'This certificate has no DNS names in its Subject Alternative Name extension. Browsers ignore the common name ({cn}) and reject the certificate for every hostname.',
  'cert.warn.PRECERT': 'This is a precertificate: the CA logs it in Certificate Transparency before it issues the certificate. Servers send the final certificate — same names, dates and key, but another fingerprint — so load that one to check servers.',

  'cert.validity.expired': { one: 'Expired {count} day ago', other: 'Expired {count} days ago' },
  'cert.validity.expiredToday': 'Expired today',
  'cert.validity.expiresToday': 'Expires today',
  'cert.validity.daysLeft': { one: '{count} day left', other: '{count} days left' },
  'cert.validity.notYet': { one: 'Valid in {count} day', other: 'Valid in {count} days' },
  'cert.validity.range': '{from} → {to}',
  'cert.validity.lifetime': { one: '{count}-day certificate', other: '{count}-day certificate' },
  'cert.validity.elapsed': 'Elapsed validity',

  'cert.names.count': { zero: 'No DNS names', one: '{count} DNS name', other: '{count} DNS names' },
  'cert.issuedBy': 'Issued by {issuer}',
  'cert.badge.wildcard': 'Wildcard',
  'cert.badge.selfSigned': 'Self-signed',
  'cert.badge.ca': 'CA certificate',
  'cert.badge.precert': 'Precertificate',
  'cert.badge.mustStaple': 'Must-Staple',
  'cert.level.EV': 'EV · Extended Validation',
  'cert.level.OV': 'OV · Organization Validated',
  'cert.level.IV': 'IV · Individual Validated',
  'cert.level.DV': 'DV · Domain Validated',
  'cert.findTargets': 'Find servers for this certificate',
  'cert.findTargetsHint': 'Opens SSL Targets with this certificate and its domains filled in',
  'cert.details': 'Details',
  'cert.downloadPem': 'Download PEM',
  'cert.copyPem': 'Copy PEM',
  'cert.downloadChain': 'Download full chain',
  'cert.showing': 'Certificate shown',
  'cert.role.leaf': 'Server certificate',
  'cert.role.intermediate': 'Intermediate CA',
  'cert.role.root': 'Root CA',
  'cert.role.unrelated': 'Not part of this chain',
  'cert.optionLabel': '{role}: {name}',

  'cert.tab.names': 'Names',
  'cert.tab.details': 'Details',
  'cert.tab.chain': 'Chain',
  'cert.tab.caa': 'CAA',
  'cert.tab.ct': 'CT logs',
  'cert.tab.pem': 'PEM & OpenSSL',
  'cert.dane.leaf': 'The DANE check uses the leaf certificate of the file ({name}) and its chain.',

  'cert.names.domains': 'Registrable domains',
  'cert.names.domainsHint': 'Scan one of them without the certificate:',
  'cert.names.sans': 'Subject Alternative Names',
  'cert.names.col.type': 'Type',
  'cert.names.col.value': 'Value',
  'cert.names.col.unicode': 'Unicode (IDN)',
  'cert.names.col.domain': 'Registrable domain',
  'cert.san.dns': 'DNS',
  'cert.san.ip': 'IP',
  'cert.san.email': 'E-mail',
  'cert.san.uri': 'URI',
  'cert.san.other': 'Other',
  'cert.names.empty': 'No Subject Alternative Names.',
  'cert.check.label': 'Does it cover a hostname?',
  'cert.check.placeholder': 'e.g. shop.example.com.tr',
  'cert.check.covered': 'Covered by {name}',
  'cert.check.notCovered': 'Not covered — no name in the certificate matches {host}',
  'cert.check.invalid': 'Enter a valid hostname.',
  'cert.check.wildcardNote': 'A wildcard covers exactly one label: *.example.com matches www.example.com but not example.com or a.b.example.com.',

  'cert.d.subject': 'Subject',
  'cert.d.issuer': 'Issuer',
  'cert.d.validity': 'Validity',
  'cert.d.key': 'Public key & signature',
  'cert.d.usage': 'Usage',
  'cert.d.ids': 'Identifiers & fingerprints',
  'cert.d.revocation': 'Revocation & issuer links',
  'cert.d.transparency': 'Transparency & policies',
  'cert.d.extensions': 'Extensions',
  'cert.f.dn': 'Distinguished name',
  'cert.f.notBefore': 'Valid from',
  'cert.f.notAfter': 'Valid until',
  'cert.f.remaining': 'Remaining',
  'cert.f.lifetime': 'Lifetime',
  'cert.f.algorithm': 'Key algorithm',
  'cert.f.keySize': 'Key size',
  'cert.f.bits': '{bits} bits',
  'cert.f.curve': 'Curve',
  'cert.f.exponent': 'RSA exponent',
  'cert.f.sigAlg': 'Signature algorithm',
  'cert.f.weakKey': 'weak',
  'cert.f.keyUsage': 'Key usage',
  'cert.f.extKeyUsage': 'Extended key usage',
  'cert.f.basicConstraints': 'Basic constraints',
  'cert.f.caYes': 'Certificate authority',
  'cert.f.caNo': 'End entity (not a CA)',
  'cert.f.pathLen': 'path length ≤ {n}',
  'cert.f.serial': 'Serial number',
  'cert.f.version': 'Version',
  'cert.f.sha256': 'SHA-256 fingerprint',
  'cert.f.sha1': 'SHA-1 fingerprint',
  'cert.f.spki': 'Public key SHA-256',
  'cert.f.spkiHint': 'compare with your private key (see PEM & OpenSSL)',
  'cert.f.pin': 'pin-sha256',
  'cert.f.ski': 'Subject key ID',
  'cert.f.aki': 'Authority key ID',
  'cert.f.ocsp': 'OCSP responder',
  'cert.f.caIssuers': 'Issuer certificate (AIA)',
  'cert.f.crl': 'CRL distribution points',
  'cert.f.mustStaple': 'OCSP Must-Staple',
  'cert.f.scts': 'Embedded SCTs',
  'cert.f.sctNone': 'None',
  'cert.f.sctCount': { one: '{count} signed certificate timestamp', other: '{count} signed certificate timestamps' },
  'cert.f.sctItem': 'log {log} · {date}',
  'cert.f.policies': 'Certificate policies',
  'cert.f.level': 'Validation level',
  'cert.f.precert': 'Precertificate (CT poison)',
  'cert.f.critical': 'critical',
  'cert.f.computing': 'Computing…',
  'cert.f.parseErrors': 'Fields that could not be decoded',
  'cert.attr.CN': 'Common name (CN)',
  'cert.attr.O': 'Organization (O)',
  'cert.attr.OU': 'Organizational unit (OU)',
  'cert.attr.C': 'Country (C)',
  'cert.attr.ST': 'State / province (ST)',
  'cert.attr.L': 'Locality (L)',
  'cert.attr.street': 'Street',
  'cert.attr.serialNumber': 'Serial number',
  'cert.attr.emailAddress': 'E-mail',
  'cert.attr.organizationIdentifier': 'Organization identifier',
  'cert.attr.jurisdictionC': 'Jurisdiction country',
  'cert.attr.businessCategory': 'Business category',
  'cert.ku.digitalSignature': 'Digital signature',
  'cert.ku.nonRepudiation': 'Non-repudiation',
  'cert.ku.keyEncipherment': 'Key encipherment',
  'cert.ku.dataEncipherment': 'Data encipherment',
  'cert.ku.keyAgreement': 'Key agreement',
  'cert.ku.keyCertSign': 'Certificate signing',
  'cert.ku.cRLSign': 'CRL signing',
  'cert.ku.encipherOnly': 'Encipher only',
  'cert.ku.decipherOnly': 'Decipher only',
  'cert.eku.serverAuth': 'TLS server',
  'cert.eku.clientAuth': 'TLS client',
  'cert.eku.codeSigning': 'Code signing',
  'cert.eku.emailProtection': 'E-mail protection',
  'cert.eku.timeStamping': 'Time stamping',
  'cert.eku.OCSPSigning': 'OCSP signing',
  'cert.eku.noServerAuth': 'No “TLS server” usage — web servers will be rejected with this certificate.',

  'cert.chain.intro': 'Servers must send the server certificate first, then each intermediate. The root is already in the clients’ trust stores.',
  'cert.chain.ok': 'The chain is complete and in the right order.',
  'cert.chain.leafOnly': 'Only the server certificate is in the file. Servers must also send the intermediate certificate — install the full chain (fullchain.pem / CA bundle), otherwise Android, curl, Java and many API clients fail.',
  'cert.chain.ctLeafOnly': 'Certificate Transparency logs hold the server certificate only; which intermediate a server sends is not known here.',
  'cert.chain.order': 'The certificates are not in the order servers expect (server certificate first, then each issuer). “Download full chain” writes them in the right order.',
  'cert.chain.unrelated': { one: '{count} certificate in the file does not belong to this chain.', other: '{count} certificates in the file do not belong to this chain.' },
  'cert.chain.rootIncluded': 'The root certificate is included. Servers do not need to send it; it is harmless but adds bytes to every handshake.',
  'cert.chain.endsAt': 'The chain ends at {name}; clients complete it with a root from their trust store.',
  'cert.chain.expired': '{name} in the chain has expired.',
  'cert.chain.selfSigned': 'This certificate is self-signed: clients only trust it if it is installed as a trusted root.',
  'cert.chain.issuedBy': 'issued by {name}',
  'cert.chain.keyMatch': 'key ID matches',
  'cert.chain.show': 'Show',
  'cert.chain.missingIssuer': 'Issuer not in the file: {name}',
  'cert.chain.fullchainHint': 'fullchain.pem = server certificate + intermediates (without the root), in the order servers need.',

  'cert.caa.intro': 'CAA DNS records say which certificate authorities may issue certificates for a domain. If this certificate’s CA is not allowed, the next renewal will fail.',
  'cert.caa.issuerKnown': 'Issuer: {ca} — CAA identifiers {ids}',
  'cert.caa.issuerUnknown': 'The issuer ({issuer}) is not a known public CA, so CAA cannot be evaluated (private or test CA?).',
  'cert.caa.distrusted': '{ca} is distrusted by browsers (since {year}). Replace this certificate.',
  'cert.caa.run': 'Check CAA',
  'cert.caa.rerun': 'Check again',
  'cert.caa.checking': 'Looking up CAA records…',
  'cert.caa.offline': 'You are offline, so the CAA records were not checked. Use “{button}” once the connection is back.',
  'cert.caa.col.name': 'Name',
  'cert.caa.col.at': 'CAA record set',
  'cert.caa.col.records': 'Records',
  'cert.caa.col.result': 'Result',
  'cert.caa.none': 'none',
  'cert.caa.allowed': 'Allowed',
  'cert.caa.restricted': 'Allowed, with restrictions',
  'cert.caa.onlyMethods': 'only {methods}',
  'cert.caa.onlyAccount': 'only ACME account {account}',
  'cert.caa.anyMethod': 'any method',
  'cert.caa.denied': 'Blocked',
  'cert.caa.unknown': 'Unknown',
  'cert.caa.error': 'Lookup failed',
  'cert.caa.summaryOk': 'The issuer is allowed to issue for every name.',
  'cert.caa.summaryDenied': { one: 'CAA blocks this CA for {count} name — fix the CAA records before the next renewal.', other: 'CAA blocks this CA for {count} names — fix the CAA records before the next renewal.' },
  'cert.caa.summaryUnknown': 'CAA could not be evaluated for every name.',
  'cert.caa.summaryRestricted': {
    one: 'The issuer may issue for every name, but CAA restricts how for {count} name: the next renewal must meet the conditions below.',
    other: 'The issuer may issue for every name, but CAA restricts how for {count} names: the next renewal must meet the conditions below.'
  },
  'cert.caa.noNames': 'The certificate has no DNS names to check.',
  'cert.caa.truncated': 'Only the first {count} names were checked.',

  'cert.ct.intro': 'Publicly trusted certificates are recorded in Certificate Transparency logs. crt.sh is searched for this serial number.',
  'cert.ct.run': 'Search crt.sh',
  'cert.ct.rerun': 'Search again',
  'cert.ct.searching': 'Searching crt.sh… this can take up to a minute.',
  'cert.ct.offline': 'You are offline, so crt.sh was not searched. Use “{button}” once the connection is back.',
  'cert.ct.found': { one: 'Found {count} log entry for this certificate.', other: 'Found {count} log entries for this certificate (usually the precertificate and the final certificate).' },
  'cert.ct.notFound': 'Not found on crt.sh. Normal for private / internal CAs and test certificates; a brand-new public certificate can take a few hours to be indexed.',
  'cert.ct.otherIssuers': { one: '{count} entry with the same serial number from another CA was ignored.', other: '{count} entries with the same serial number from other CAs were ignored.' },
  'cert.ct.col.id': 'crt.sh ID',
  'cert.ct.col.issuer': 'Issuer',
  'cert.ct.col.from': 'Valid from',
  'cert.ct.col.to': 'Valid until',
  'cert.ct.openSerial': 'Open this serial on crt.sh',
  'cert.ct.openDomain': 'All certificates for {domain}',
  'cert.ct.manual': 'The issuer is not a known public CA, so crt.sh is not searched automatically.',
  'cert.ct.failed': 'crt.sh did not answer',

  'cert.pem.this': 'This certificate (PEM)',
  'cert.pem.fullchain': 'Full chain (PEM)',
  'cert.pem.keyMatchTitle': 'Does a private key belong to this certificate?',
  'cert.pem.keyMatchBody': 'Run this where the key is — it never has to leave the server — and compare the result with the public key SHA-256 of this certificate:',
  'cert.pem.inspectTitle': 'Inspect or check a server with OpenSSL',
  'cert.pem.spki': 'Public key SHA-256 of this certificate'
});

registerStrings('tr', {
  'cert.dropTitle': 'Sertifika dosyasını buraya bırakın',
  'cert.dropHint': 'veya seçmek için tıklayın · Ctrl+V ile yapıştırın · PEM, CRT/CER, DER, P7B',
  'cert.pasteToggle': 'Sertifikayı metin olarak yapıştır',
  'cert.pasteLabel': 'Sertifika metni (PEM)',
  'cert.pastePlaceholder': '-----BEGIN CERTIFICATE-----\nMIIF…\n-----END CERTIFICATE-----',
  'cert.pasteApply': 'Sertifikayı oku',
  'cert.pasteEmpty': 'Önce bir PEM bloğu yapıştırın.',
  'cert.privacy': 'Dosya yerel olarak okunur, hiçbir yere yüklenmez. Özel anahtar gerekmez — dosyada varsa yok sayılır ve asla gösterilmez.',
  'cert.loaderTitle': 'Sertifika dosyası',
  'cert.loaderSubtitle': 'Müşterinizin veya sertifika otoritesinin gönderdiği sertifika — zincirli ya da zincirsiz',
  'cert.loadAnother': 'Başka dosya yükle',
  'cert.remove': 'Kaldır',
  'cert.removed': 'Sertifika kaldırıldı',
  'cert.loadedToast': '{name}: sertifika yüklendi',
  'cert.fileInfo': '{name} · {count}',
  'cert.count': { one: '{count} sertifika', other: '{count} sertifika' },
  'cert.emptyTitle': 'Yüklü sertifika yok',
  'cert.emptyBody': 'Adlarını, geçerliliğini, anahtarını, zincir sırasını, CAA durumunu ve Certificate Transparency kayıtlarını görmek — ve kurulması gereken sunucuları bulmak — için sertifikayı yükleyin.',

  'cert.alt.title': 'Dosyanız yok mu? Bir host adının herkese açık sertifikasını yükleyin',
  'cert.alt.placeholder': 'www.example.com',
  'cert.alt.load': 'Yükle',
  'cert.alt.hint': 'Bu ad için geçerli en yeni sertifikayı herkese açık Certificate Transparency kayıtlarından okur (Cert Spotter; Cert Spotter yanıt veremezse crt.sh). Yalnızca host adı gönderilir.',
  'cert.alt.invalid': 'www.example.com gibi bir host adı girin (*.example.com biçiminde wildcard da olur).',
  'cert.alt.searching': '{host} için Certificate Transparency kayıtları aranıyor…',
  'cert.alt.notFound': '{host} için şu an geçerli bir sertifika Certificate Transparency kayıtlarında yok. İç ağ adları ve özel CA’lar hiç kaydedilmez; son birkaç saatte verilen bir sertifika da henüz listelenmemiş olabilir.',
  'cert.alt.notFoundTruncated': '{host} için okunan sertifikaların hiçbiri şu an geçerli değil; ancak Cert Spotter okunandan fazlasını listeliyor ve en yeniler okunmayanlar arasında: geçerli bir sertifika yine de kayıtlı olabilir.',
  'cert.alt.notFoundCrtshPartial': 'Alınan yanıtlarda {host} için şu an geçerli bir sertifika bulunamadı; ancak crt.sh her aramaya yanıt vermedi: geçerli bir sertifika yine de kayıtlı olabilir. Daha sonra tekrar deneyin.',
  'cert.alt.notFoundCrtshDown': 'Cert Spotter’ın listeledikleri arasında {host} için şu an geçerli bir sertifika yok ve crt.sh aramalarının hiçbirine yanıt vermedi: geçerli bir sertifika yine de kayıtlı olabilir. Daha sonra tekrar deneyin.',
  'cert.alt.revokedSkipped': { one: 'İptal edilmiş {count} sertifika atlandı.', other: 'İptal edilmiş {count} sertifika atlandı.' },
  'cert.alt.failed': 'Certificate Transparency aranamadı',
  'cert.alt.spotterQuota': 'IP adresinizin saatlik Cert Spotter sınırı doldu; bu yüzden crt.sh’te arandı.',
  'cert.alt.spotterAgain': 'Cert Spotter’a saat {time} civarından itibaren yeniden sorulur.',
  'cert.alt.bothFailedQuota': 'IP adresinizin saatlik Cert Spotter sınırı doldu ve crt.sh de yanıt veremedi:',
  'cert.alt.retryCrtshOnly': 'Saat {time} civarına kadar “Tekrar dene” yalnızca crt.sh’te arar.',
  'cert.alt.spotterFailed': 'Cert Spotter yanıt veremedi; bu yüzden crt.sh’te arandı.',
  'cert.alt.spotterUnreadable': 'Cert Spotter’daki sertifika kopyası okunamadı; bu yüzden crt.sh’te arandı.',
  'cert.alt.spotterPartial': 'Cert Spotter yalnızca kısmen yanıt verdi; bu yüzden crt.sh’te de arandı.',
  'cert.alt.manualPartial': 'crt.sh her aramaya yanıt vermedi; bu yüzden bu ad için daha yeni bir sertifika burada eksik olabilir.',
  'cert.alt.manualTitle': 'crt.sh’te bulundu — indirip dosyayı yukarı bırakın',
  'cert.alt.manualCert': '{host} için geçerli en yeni sertifika: {names}; veren: {issuer}; {date} tarihine kadar geçerli.',
  'cert.alt.manualWhy': 'crt.sh, web sayfalarının sertifika indirmesine izin vermez; dosyayı kendiniz kaydedin. crt.sh her sertifikayı iki kez listeler — ön sertifika olarak ve sunucuların gönderdiği sertifika olarak — ve hangisinin hangisi olduğunu söylemez: bıraktığınız dosya “Ön sertifika” olarak işaretlenirse diğer bağlantıyı kullanın.',
  'cert.alt.manualWhyOne': 'crt.sh, web sayfalarının sertifika indirmesine izin vermez; dosyayı kendiniz kaydedin. Bıraktığınız dosya “Ön sertifika” olarak işaretlenirse sunucuların gönderdiği sertifika henüz kaydedilmemiştir: onu sunucudan ya da CA’dan alın.',
  'cert.alt.download': '#{id} indir',
  'cert.alt.openCrtsh': 'crt.sh’te aç',
  'cert.alt.sample': 'Örnek deneyin',
  'cert.alt.sampleHint': 'example.com ve example.net için uydurma bir sertifika',
  'cert.alt.sampleFailed': 'Örnek sertifika yüklenemedi.',

  'cert.src.ctBadge': 'Certificate Transparency’den',
  'cert.src.sampleBadge': 'Örnek',
  'cert.src.ct': 'Certificate Transparency’den yüklendi — sunucu farklı bir sertifika sunuyor olabilir.',
  'cert.src.ctWhat': '{host} için kaydedilmiş, geçerli en yeni sertifika ({date} tarihinde verildi). Kayıt, bir CA’nın ne verdiğini gösterir; neyin kurulu olduğunu değil.',
  'cert.src.ctNewerPrecert': 'Bu ad için daha yeni bir sertifika ({date} tarihinde verildi) şimdilik yalnızca ön sertifika olarak kayıtlı.',
  'cert.src.ctPrecert': 'Bu sertifikanın son hâli henüz kaydedilmedi; bu yüzden sunucuların gönderdiği sertifika Certificate Transparency’den yüklenemez: onu sunucudan ya da CA’dan alın.',
  'cert.src.ctTruncated': 'Cert Spotter bu ad için okunandan daha fazla sertifika listeliyor; daha yeni bir tane olabilir.',
  'cert.src.ctOpen': 'crt.sh’te aç',
  'cert.src.verify': 'Sunucuları SSL Hedefleri’nde kontrol et',
  'cert.src.sample': 'DomainScope’u denemek için örnek sertifika: example.com ve example.net; uydurma “DomainScope Sample” CA’sı tarafından verildi. Hiçbir sunucu kullanmıyor.',

  'cert.warn.PRIVATE_KEY_PRESENT.title': 'Dosyada özel anahtar da var',
  'cert.warn.PRIVATE_KEY_PRESENT.body': 'Yok sayıldı — asla gösterilmedi, saklanmadı, yüklenmedi. Burada yalnızca sertifika gerekir. Anahtar dosyalarını gizli tutun, e-postayla göndermekten kaçının.',
  'cert.warn.PKCS12_UNSUPPORTED.title': 'PKCS#12 (.pfx / .p12) dosyaları parolayla korunur',
  'cert.warn.PKCS12_UNSUPPORTED.body': 'Önce sertifikaları OpenSSL ile çıkarın, ardından cert.pem dosyasını yükleyin:',
  'cert.warn.CSR_NOT_CERT.title': 'Bu bir sertifika imzalama isteği (CSR), sertifika değil',
  'cert.warn.CSR_NOT_CERT.body': 'CSR, sertifika otoritesine gönderdiğiniz dosyadır. Karşılığında aldığınız sertifikayı (genellikle .crt veya .pem) yükleyin.',
  'cert.warn.NO_CERTIFICATE.title': 'Sertifika bulunamadı',
  'cert.warn.NO_CERTIFICATE.body': 'Girdide X.509 sertifikası yok. -----BEGIN CERTIFICATE----- ile başlayan bir PEM bloğu ya da DER / P7B dosyası bekleniyordu.',
  'cert.warn.PARSE_ERROR.title': 'Girdinin bir kısmı okunamadı',
  'cert.warn.PARSE_ERROR.body': 'Bozuk veya desteklenmeyen biçimdeki bazı veriler atlandı.',
  'cert.warn.EXPIRED.title': 'Sertifikanın süresi dolmuş',
  'cert.warn.EXPIRED.body': 'Süresi {date} tarihinde doldu. Tarayıcılar reddeder — kurmayın.',
  'cert.warn.NOT_YET_VALID.title': 'Sertifika henüz geçerli değil',
  'cert.warn.NOT_YET_VALID.body': '{date} tarihinde geçerli olacak. Daha önce kurulursa o zamana kadar hata verir.',
  'cert.warn.foundOnly': 'Bunun yerine bulunan: {what}',
  'cert.warn.noSan': 'Bu sertifikanın Subject Alternative Name uzantısında DNS adı yok. Tarayıcılar ortak adı ({cn}) dikkate almaz ve sertifikayı her host adı için reddeder.',
  'cert.warn.PRECERT': 'Bu bir ön sertifika: CA, sertifikayı vermeden önce bunu Certificate Transparency’ye kaydeder. Sunucular son sertifikayı gönderir — adları, tarihleri ve anahtarı aynı, parmak izi farklı — bu yüzden sunucuları kontrol etmek için onu yükleyin.',

  'cert.validity.expired': { one: 'Süresi {count} gün önce doldu', other: 'Süresi {count} gün önce doldu' },
  'cert.validity.expiredToday': 'Süresi bugün doldu',
  'cert.validity.expiresToday': 'Bugün sona eriyor',
  'cert.validity.daysLeft': { one: '{count} gün kaldı', other: '{count} gün kaldı' },
  'cert.validity.notYet': { one: '{count} gün sonra geçerli', other: '{count} gün sonra geçerli' },
  'cert.validity.range': '{from} → {to}',
  'cert.validity.lifetime': { one: '{count} günlük sertifika', other: '{count} günlük sertifika' },
  'cert.validity.elapsed': 'Geçen geçerlilik süresi',

  'cert.names.count': { zero: 'DNS adı yok', one: '{count} DNS adı', other: '{count} DNS adı' },
  'cert.issuedBy': 'Veren: {issuer}',
  'cert.badge.wildcard': 'Wildcard',
  'cert.badge.selfSigned': 'Kendinden imzalı',
  'cert.badge.ca': 'CA sertifikası',
  'cert.badge.precert': 'Ön sertifika',
  'cert.badge.mustStaple': 'Must-Staple',
  'cert.level.EV': 'EV · Genişletilmiş doğrulama',
  'cert.level.OV': 'OV · Kurum doğrulamalı',
  'cert.level.IV': 'IV · Kişi doğrulamalı',
  'cert.level.DV': 'DV · Alan adı doğrulamalı',
  'cert.findTargets': 'Bu sertifikanın sunucularını bul',
  'cert.findTargetsHint': 'SSL Hedefleri’ni bu sertifika ve alan adlarıyla doldurulmuş olarak açar',
  'cert.details': 'Ayrıntılar',
  'cert.downloadPem': 'PEM indir',
  'cert.copyPem': 'PEM kopyala',
  'cert.downloadChain': 'Tam zinciri indir',
  'cert.showing': 'Gösterilen sertifika',
  'cert.role.leaf': 'Sunucu sertifikası',
  'cert.role.intermediate': 'Ara sertifika (CA)',
  'cert.role.root': 'Kök sertifika (CA)',
  'cert.role.unrelated': 'Bu zincire ait değil',
  'cert.optionLabel': '{role}: {name}',

  'cert.tab.names': 'Adlar',
  'cert.tab.details': 'Ayrıntılar',
  'cert.tab.chain': 'Zincir',
  'cert.tab.caa': 'CAA',
  'cert.tab.ct': 'CT kayıtları',
  'cert.tab.pem': 'PEM ve OpenSSL',
  'cert.dane.leaf': 'DANE kontrolü dosyadaki uç sertifikayı ({name}) ve zincirini kullanır.',

  'cert.names.domains': 'Kayıtlı alan adları',
  'cert.names.domainsHint': 'Birini sertifikasız tarayın:',
  'cert.names.sans': 'Subject Alternative Name (SAN) listesi',
  'cert.names.col.type': 'Tür',
  'cert.names.col.value': 'Değer',
  'cert.names.col.unicode': 'Unicode (IDN)',
  'cert.names.col.domain': 'Kayıtlı alan adı',
  'cert.san.dns': 'DNS',
  'cert.san.ip': 'IP',
  'cert.san.email': 'E-posta',
  'cert.san.uri': 'URI',
  'cert.san.other': 'Diğer',
  'cert.names.empty': 'Subject Alternative Name yok.',
  'cert.check.label': 'Bir host adını kapsıyor mu?',
  'cert.check.placeholder': 'ör. magaza.example.com.tr',
  'cert.check.covered': '{name} tarafından kapsanıyor',
  'cert.check.notCovered': 'Kapsanmıyor — sertifikadaki hiçbir ad {host} ile eşleşmiyor',
  'cert.check.invalid': 'Geçerli bir host adı girin.',
  'cert.check.wildcardNote': 'Wildcard tam olarak bir etiketi kapsar: *.example.com, www.example.com ile eşleşir ama example.com veya a.b.example.com ile eşleşmez.',

  'cert.d.subject': 'Konu (Subject)',
  'cert.d.issuer': 'Veren (Issuer)',
  'cert.d.validity': 'Geçerlilik',
  'cert.d.key': 'Açık anahtar ve imza',
  'cert.d.usage': 'Kullanım',
  'cert.d.ids': 'Tanımlayıcılar ve parmak izleri',
  'cert.d.revocation': 'İptal kontrolü ve veren bağlantıları',
  'cert.d.transparency': 'Şeffaflık ve politikalar',
  'cert.d.extensions': 'Uzantılar',
  'cert.f.dn': 'Ayırt edici ad (DN)',
  'cert.f.notBefore': 'Başlangıç',
  'cert.f.notAfter': 'Bitiş',
  'cert.f.remaining': 'Kalan',
  'cert.f.lifetime': 'Toplam süre',
  'cert.f.algorithm': 'Anahtar algoritması',
  'cert.f.keySize': 'Anahtar uzunluğu',
  'cert.f.bits': '{bits} bit',
  'cert.f.curve': 'Eğri',
  'cert.f.exponent': 'RSA üssü',
  'cert.f.sigAlg': 'İmza algoritması',
  'cert.f.weakKey': 'zayıf',
  'cert.f.keyUsage': 'Anahtar kullanımı',
  'cert.f.extKeyUsage': 'Genişletilmiş anahtar kullanımı',
  'cert.f.basicConstraints': 'Temel kısıtlamalar',
  'cert.f.caYes': 'Sertifika otoritesi',
  'cert.f.caNo': 'Uç sertifika (CA değil)',
  'cert.f.pathLen': 'yol uzunluğu ≤ {n}',
  'cert.f.serial': 'Seri numarası',
  'cert.f.version': 'Sürüm',
  'cert.f.sha256': 'SHA-256 parmak izi',
  'cert.f.sha1': 'SHA-1 parmak izi',
  'cert.f.spki': 'Açık anahtar SHA-256',
  'cert.f.spkiHint': 'özel anahtarınızla karşılaştırın (bkz. PEM ve OpenSSL)',
  'cert.f.pin': 'pin-sha256',
  'cert.f.ski': 'Konu anahtar kimliği (SKI)',
  'cert.f.aki': 'Otorite anahtar kimliği (AKI)',
  'cert.f.ocsp': 'OCSP sunucusu',
  'cert.f.caIssuers': 'Veren sertifikası (AIA)',
  'cert.f.crl': 'CRL dağıtım noktaları',
  'cert.f.mustStaple': 'OCSP Must-Staple',
  'cert.f.scts': 'Gömülü SCT’ler',
  'cert.f.sctNone': 'Yok',
  'cert.f.sctCount': { one: '{count} imzalı sertifika zaman damgası', other: '{count} imzalı sertifika zaman damgası' },
  'cert.f.sctItem': 'log {log} · {date}',
  'cert.f.policies': 'Sertifika politikaları',
  'cert.f.level': 'Doğrulama düzeyi',
  'cert.f.precert': 'Ön sertifika (CT poison)',
  'cert.f.critical': 'kritik',
  'cert.f.computing': 'Hesaplanıyor…',
  'cert.f.parseErrors': 'Çözümlenemeyen alanlar',
  'cert.attr.CN': 'Ortak ad (CN)',
  'cert.attr.O': 'Kuruluş (O)',
  'cert.attr.OU': 'Birim (OU)',
  'cert.attr.C': 'Ülke (C)',
  'cert.attr.ST': 'İl / eyalet (ST)',
  'cert.attr.L': 'Şehir (L)',
  'cert.attr.street': 'Adres',
  'cert.attr.serialNumber': 'Seri numarası',
  'cert.attr.emailAddress': 'E-posta',
  'cert.attr.organizationIdentifier': 'Kuruluş tanımlayıcısı',
  'cert.attr.jurisdictionC': 'Yetki alanı ülkesi',
  'cert.attr.businessCategory': 'İş kategorisi',
  'cert.ku.digitalSignature': 'Dijital imza',
  'cert.ku.nonRepudiation': 'İnkâr edilemezlik',
  'cert.ku.keyEncipherment': 'Anahtar şifreleme',
  'cert.ku.dataEncipherment': 'Veri şifreleme',
  'cert.ku.keyAgreement': 'Anahtar anlaşması',
  'cert.ku.keyCertSign': 'Sertifika imzalama',
  'cert.ku.cRLSign': 'CRL imzalama',
  'cert.ku.encipherOnly': 'Yalnızca şifreleme',
  'cert.ku.decipherOnly': 'Yalnızca şifre çözme',
  'cert.eku.serverAuth': 'TLS sunucusu',
  'cert.eku.clientAuth': 'TLS istemcisi',
  'cert.eku.codeSigning': 'Kod imzalama',
  'cert.eku.emailProtection': 'E-posta koruması',
  'cert.eku.timeStamping': 'Zaman damgası',
  'cert.eku.OCSPSigning': 'OCSP imzalama',
  'cert.eku.noServerAuth': '“TLS sunucusu” kullanımı yok — bu sertifikayla web sunucuları reddedilir.',

  'cert.chain.intro': 'Sunucular önce sunucu sertifikasını, ardından her ara sertifikayı göndermelidir. Kök sertifika istemcilerin güven deposunda zaten bulunur.',
  'cert.chain.ok': 'Zincir eksiksiz ve doğru sırada.',
  'cert.chain.leafOnly': 'Dosyada yalnızca sunucu sertifikası var. Sunucular ara sertifikayı da göndermelidir — tam zinciri (fullchain.pem / CA bundle) kurun; yoksa Android, curl, Java ve birçok API istemcisi hata verir.',
  'cert.chain.ctLeafOnly': 'Certificate Transparency kayıtları yalnızca sunucu sertifikasını tutar; bir sunucunun hangi ara sertifikayı gönderdiği burada bilinemez.',
  'cert.chain.order': 'Sertifikalar sunucuların beklediği sırada değil (önce sunucu sertifikası, sonra sırayla verenler). “Tam zinciri indir” doğru sırayla yazar.',
  'cert.chain.unrelated': { one: 'Dosyadaki {count} sertifika bu zincire ait değil.', other: 'Dosyadaki {count} sertifika bu zincire ait değil.' },
  'cert.chain.rootIncluded': 'Kök sertifika da dahil edilmiş. Sunucuların bunu göndermesi gerekmez; zararsızdır ama her el sıkışmaya bayt ekler.',
  'cert.chain.endsAt': 'Zincir {name} ile bitiyor; istemciler kök sertifikayı kendi güven depolarından ekler.',
  'cert.chain.expired': 'Zincirdeki {name} sertifikasının süresi dolmuş.',
  'cert.chain.selfSigned': 'Bu sertifika kendinden imzalı: istemciler ancak güvenilen kök olarak kurulursa güvenir.',
  'cert.chain.issuedBy': 'veren: {name}',
  'cert.chain.keyMatch': 'anahtar kimliği eşleşiyor',
  'cert.chain.show': 'Göster',
  'cert.chain.missingIssuer': 'Veren dosyada yok: {name}',
  'cert.chain.fullchainHint': 'fullchain.pem = sunucu sertifikası + ara sertifikalar (kök hariç), sunucuların istediği sırayla.',

  'cert.caa.intro': 'CAA DNS kayıtları bir alan adı için hangi sertifika otoritelerinin sertifika verebileceğini belirtir. Bu sertifikanın otoritesine izin yoksa bir sonraki yenileme başarısız olur.',
  'cert.caa.issuerKnown': 'Veren: {ca} — CAA tanımlayıcıları {ids}',
  'cert.caa.issuerUnknown': 'Veren ({issuer}) bilinen bir genel CA değil; bu yüzden CAA değerlendirilemiyor (özel veya test CA’sı mı?).',
  'cert.caa.distrusted': '{ca} tarayıcılar tarafından güvenilmez ilan edildi ({year} yılından beri). Bu sertifikayı değiştirin.',
  'cert.caa.run': 'CAA kontrol et',
  'cert.caa.rerun': 'Yeniden kontrol et',
  'cert.caa.checking': 'CAA kayıtları sorgulanıyor…',
  'cert.caa.offline': 'Çevrimdışısınız; bu yüzden CAA kayıtları kontrol edilmedi. Bağlantı gelince “{button}” düğmesini kullanın.',
  'cert.caa.col.name': 'Ad',
  'cert.caa.col.at': 'CAA kayıt kümesi',
  'cert.caa.col.records': 'Kayıtlar',
  'cert.caa.col.result': 'Sonuç',
  'cert.caa.none': 'yok',
  'cert.caa.allowed': 'İzinli',
  'cert.caa.restricted': 'Kısıtlamalarla izinli',
  'cert.caa.onlyMethods': 'yalnızca {methods}',
  'cert.caa.onlyAccount': 'yalnızca {account} ACME hesabı',
  'cert.caa.anyMethod': 'her yöntem',
  'cert.caa.denied': 'Engelli',
  'cert.caa.unknown': 'Bilinmiyor',
  'cert.caa.error': 'Sorgu başarısız',
  'cert.caa.summaryOk': 'Veren otoritenin her ad için sertifika vermesine izin var.',
  'cert.caa.summaryDenied': { one: 'CAA bu otoriteyi {count} ad için engelliyor — bir sonraki yenilemeden önce CAA kayıtlarını düzeltin.', other: 'CAA bu otoriteyi {count} ad için engelliyor — bir sonraki yenilemeden önce CAA kayıtlarını düzeltin.' },
  'cert.caa.summaryUnknown': 'CAA her ad için değerlendirilemedi.',
  'cert.caa.summaryRestricted': 'Veren otorite her ad için sertifika verebilir, ancak CAA {count} ad için bunun nasıl yapılacağını kısıtlıyor: bir sonraki yenileme aşağıdaki koşulları karşılamalıdır.',
  'cert.caa.noNames': 'Sertifikada kontrol edilecek DNS adı yok.',
  'cert.caa.truncated': 'Yalnızca ilk {count} ad kontrol edildi.',

  'cert.ct.intro': 'Genel olarak güvenilen sertifikalar Certificate Transparency kayıtlarına (log) yazılır. crt.sh’te bu seri numarası aranır.',
  'cert.ct.run': 'crt.sh’te ara',
  'cert.ct.rerun': 'Yeniden ara',
  'cert.ct.searching': 'crt.sh’te aranıyor… bir dakikayı bulabilir.',
  'cert.ct.offline': 'Çevrimdışısınız; bu yüzden crt.sh’te arama yapılmadı. Bağlantı gelince “{button}” düğmesini kullanın.',
  'cert.ct.found': { one: 'Bu sertifika için {count} kayıt bulundu.', other: 'Bu sertifika için {count} kayıt bulundu (genellikle ön sertifika ve asıl sertifika).' },
  'cert.ct.notFound': 'crt.sh’te bulunamadı. Özel / kurum içi CA’lar ve test sertifikaları için normaldir; yeni bir genel sertifikanın dizine eklenmesi birkaç saat sürebilir.',
  'cert.ct.otherIssuers': { one: 'Aynı seri numaralı, başka bir CA’ya ait {count} kayıt yok sayıldı.', other: 'Aynı seri numaralı, başka CA’lara ait {count} kayıt yok sayıldı.' },
  'cert.ct.col.id': 'crt.sh kimliği',
  'cert.ct.col.issuer': 'Veren',
  'cert.ct.col.from': 'Başlangıç',
  'cert.ct.col.to': 'Bitiş',
  'cert.ct.openSerial': 'Bu seri numarasını crt.sh’te aç',
  'cert.ct.openDomain': '{domain} için tüm sertifikalar',
  'cert.ct.manual': 'Veren bilinen bir genel CA olmadığından crt.sh otomatik olarak aranmıyor.',
  'cert.ct.failed': 'crt.sh yanıt vermedi',

  'cert.pem.this': 'Bu sertifika (PEM)',
  'cert.pem.fullchain': 'Tam zincir (PEM)',
  'cert.pem.keyMatchTitle': 'Bir özel anahtar bu sertifikaya mı ait?',
  'cert.pem.keyMatchBody': 'Bunu anahtarın bulunduğu yerde çalıştırın — anahtarın sunucudan çıkması gerekmez — ve sonucu bu sertifikanın açık anahtar SHA-256 değeriyle karşılaştırın:',
  'cert.pem.inspectTitle': 'OpenSSL ile incele veya bir sunucuyu kontrol et',
  'cert.pem.spki': 'Bu sertifikanın açık anahtar SHA-256 değeri'
});

// CAA verdict reasons, problems and renewal notes (health.caa.reason.* / problem.* / note.*) come with lib/health.js.
for (const lang of ['en', 'tr']) {
  registerStrings(lang, Object.fromEntries(Object.entries(HEALTH_I18N[lang])
    .filter(([k]) => /^health\.caa\.(?:reason|problem|note)\./.test(k))));
}

/* ------------------------------------------------------------------------ */
/* Pure helpers (exported for views/scan.js and the E2E checks)             */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} CertLoad
 * @property {string} name file name ('' when unknown; the host name for a CT load)
 * @property {number} size input size in bytes
 * @property {'pick'|'drop'|'paste'|'session'|'ct'|'sample'} source 'ct': read from Certificate
 *   Transparency for a host name ({@link ctCertLoad}); 'sample': the bundled sample
 * @property {Date} loadedAt
 * @property {{ certificates: object[], leaf: object|null, warnings: Array<{ code: string, detail?: string }> }} result
 *   lib/x509.parseCertificates() result
 * @property {{ host: string, provider: string, issuance: object, precertificate: boolean,
 *   newerPrecertificate: object|null, truncated: boolean }} [ct] source 'ct' only: what the lookup
 *   found (lib/ctcert.js CtLookup fields)
 */

/**
 * Parse certificate input (file bytes or pasted text) into a {@link CertLoad}.
 * Never throws (parseCertificates never throws).
 * @param {string|ArrayBuffer|Uint8Array} input
 * @param {{ name?: string, size?: number, source?: string, now?: Date|number }} [opts]
 * @returns {CertLoad}
 */
export function loadCertificateData(input, { name = '', size = null, source = 'pick', now } = {}) {
  const result = parseCertificates(input, now !== undefined ? { now } : {});
  let bytes = 0;
  if (typeof input === 'string') bytes = new TextEncoder().encode(input).length;
  else if (input && Number.isFinite(input.byteLength)) bytes = input.byteLength;
  return {
    name: String(name || ''),
    size: Number.isFinite(size) ? size : bytes,
    source,
    loadedAt: new Date(),
    result
  };
}

/**
 * The {@link CertLoad} of a lib/ctcert.js lookup that found a certificate (status 'found'):
 * source 'ct', named after the host, with the lookup's provenance in `ct`.
 * @param {import('../lib/ctcert.js').CtLookup} lookup
 * @returns {CertLoad}
 */
export function ctCertLoad(lookup) {
  const load = loadCertificateData(lookup.der, { name: lookup.host, source: 'ct' });
  load.ct = {
    host: lookup.host,
    provider: lookup.provider,
    issuance: lookup.issuance,
    precertificate: !!lookup.precertificate,
    newerPrecertificate: lookup.newerPrecertificate || null,
    truncated: !!lookup.truncated
  };
  return load;
}

/**
 * Fetch the bundled sample certificate ({@link SAMPLE_CERT_URL}) as a {@link CertLoad} with
 * source 'sample'. Rejects when the file cannot be fetched (offline, or a page left open across
 * a deploy whose v/<commit>/ is gone).
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal }} [opts]
 * @returns {Promise<CertLoad>}
 */
export async function loadSampleCert({ fetchImpl, signal } = {}) {
  const text = await fetchText(SAMPLE_CERT_URL, { fetchImpl, signal, timeoutMs: 15000, headers: { accept: 'text/plain, */*' } });
  return loadCertificateData(text, { name: 'sample-cert.pem', source: 'sample' });
}

/**
 * "O (CN)" of a DN string as crt.sh prints it ('C=US, O=Example CA, CN=R1'), else the DN.
 * @param {string} dn
 * @returns {string}
 */
export function dnDisplayName(dn) {
  const s = String(dn || '');
  const attr = (k) => {
    const m = new RegExp(`(?:^|,\\s*)${k}=("(?:[^"]|\\\\")*"|[^,]*)`).exec(s);
    return m ? m[1].replace(/^"|"$/g, '').trim() : '';
  };
  const o = attr('O');
  const cn = attr('CN');
  if (o && cn && o !== cn) return `${o} (${cn})`;
  return o || cn || s || '—';
}

/**
 * Accept the shapes other code may hand over (a CertLoad, a parseCertificates() result,
 * a bare Certificate, or `{ cert }`) and return a CertLoad (or null).
 * @param {any} value
 * @returns {CertLoad|null}
 */
export function normalizeCertLoad(value) {
  if (!value || typeof value !== 'object') return null;
  const wrap = (cert, name = '') => ({
    name: name || cert.subjectCN || '',
    size: cert.der ? cert.der.length : 0,
    source: 'session',
    loadedAt: new Date(),
    result: { certificates: [cert], leaf: cert, warnings: [] }
  });
  if (value.result && Array.isArray(value.result.certificates)) return value;
  if (Array.isArray(value.certificates)) {
    return { name: '', size: 0, source: 'session', loadedAt: new Date(), result: { leaf: value.certificates[0] || null, warnings: [], ...value } };
  }
  if (value.der && Array.isArray(value.hostnames)) return wrap(value);
  if (value.cert && value.cert.der && Array.isArray(value.cert.hostnames)) return wrap(value.cert, value.name);
  return null;
}

/**
 * The certificate shared by the Certificate and SSL Targets views in this session.
 * @param {{ getSession: (name: string) => any }} appState
 * @returns {CertLoad|null}
 */
export function getCurrentCert(appState) {
  return normalizeCertLoad(appState.getSession(CURRENT_CERT));
}

/**
 * Share (or clear with null) the current certificate for this session. Loading one also drops the
 * "No file?" block's last outcome (not found, crt.sh links): it answered a question that is settled.
 * Both views re-render that block on any change, so a host-name lookup still running in it is
 * stopped here: its requests, the busy flag and a deferred language switch end now, not when the
 * services answer.
 * @param {{ setSession: (name: string, value: any) => void }} appState
 * @param {CertLoad|null} load
 */
export function setCurrentCert(appState, load) {
  stopCtLookup();
  if (load) ctForm.last = null;
  appState.setSession(CURRENT_CERT, load || undefined);
}

/**
 * What a loaded certificate is about, as the page session's current target: the host name a
 * Certificate Transparency load was asked for, else the leaf's first DNS name (a wildcard as
 * its base name); null without a leaf or a name, and for the bundled sample (a demo: its name is
 * nothing the user worked on).
 * @param {CertLoad|null} load
 * @returns {string|null}
 */
export function certTarget(load) {
  const leaf = load && load.result ? load.result.leaf : null;
  if (!leaf || load.source === 'sample') return null;
  if (load.source === 'ct' && load.ct && load.ct.host) return stripWildcard(load.ct.host).base;
  const names = Array.isArray(leaf.hostnames) ? leaf.hostnames : [];
  return names.length ? stripWildcard(names[0]).base : null;
}

/**
 * Validity state of a certificate at `now`.
 * @param {{ notBefore: Date, notAfter: Date }} cert
 * @param {Date|number} [now=Date.now()]
 * @returns {{ state: 'notyet'|'expired'|'expiring'|'ok', days: number, elapsed: number, lifetimeDays: number }}
 *   days: whole days left (notyet: days until valid; expired: whole days since expiry);
 *   elapsed: 0…1 share of the validity period that has passed.
 */
export function validityState(cert, now = Date.now()) {
  const n = now instanceof Date ? now.getTime() : Number(now);
  const nb = cert.notBefore.getTime();
  const na = cert.notAfter.getTime();
  const lifetimeDays = Math.max(0, Math.round((na - nb) / DAY_MS));
  const span = Math.max(1, na - nb);
  const elapsed = Math.min(1, Math.max(0, (n - nb) / span));
  if (n < nb) return { state: 'notyet', days: Math.ceil((nb - n) / DAY_MS), elapsed: 0, lifetimeDays };
  if (n > na) return { state: 'expired', days: Math.floor((n - na) / DAY_MS), elapsed: 1, lifetimeDays };
  const days = daysUntil(cert.notAfter, n);
  return { state: days <= EXPIRING_DAYS ? 'expiring' : 'ok', days, elapsed, lifetimeDays };
}

/**
 * Human text for {@link validityState}.
 * @param {{ state: string, days: number }} v
 * @returns {string}
 */
export function validityText(v) {
  if (v.state === 'notyet') return t('cert.validity.notYet', { count: v.days });
  if (v.state === 'expired') return v.days === 0 ? t('cert.validity.expiredToday') : t('cert.validity.expired', { count: v.days });
  if (v.days === 0) return t('cert.validity.expiresToday');
  return t('cert.validity.daysLeft', { count: v.days });
}

/**
 * Badge variant for a validity state.
 * @param {{ state: string }} v
 * @returns {'ok'|'warn'|'error'}
 */
export function validityVariant(v) {
  if (v.state === 'expired') return 'error';
  if (v.state === 'notyet' || v.state === 'expiring') return 'warn';
  return 'ok';
}

/**
 * "12 days left" / "Expired 3 days ago" badge.
 * @param {{ notBefore: Date, notAfter: Date }} cert
 * @param {Date|number} [now]
 * @returns {HTMLSpanElement}
 */
export function ValidityBadge(cert, now = Date.now()) {
  const v = validityState(cert, now);
  const variant = validityVariant(v);
  const el = Badge(validityText(v), {
    variant,
    icon: variant === 'ok' ? 'check-circle' : variant === 'warn' ? 'clock' : 'x-circle',
    title: `${cert.notBefore.toISOString()} → ${cert.notAfter.toISOString()}`
  });
  el.dataset.validity = v.state;
  return el;
}

/**
 * Serial number as colon-separated upper-case hex pairs ('0A:1B:…').
 * @param {string} hex
 * @returns {string}
 */
export function formatSerial(hex) {
  const s = String(hex || '').toLowerCase();
  return formatFingerprint(s.length % 2 ? `0${s}` : s);
}

const PUNY = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700, bias: 72, n: 128 };

function punyAdapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / PUNY.damp) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((PUNY.base - PUNY.tMin) * PUNY.tMax) >> 1) {
    d = Math.floor(d / (PUNY.base - PUNY.tMin));
    k += PUNY.base;
  }
  return Math.floor(k + ((PUNY.base - PUNY.tMin + 1) * d) / (d + PUNY.skew));
}

function punyDigit(cp) {
  if (cp >= 0x30 && cp <= 0x39) return cp - 22; // '0'..'9' → 26..35
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;
  return PUNY.base;
}

/**
 * Decode one Punycode label body (RFC 3492, without the 'xn--' prefix).
 * @param {string} input
 * @returns {string}
 * @throws {RangeError} on invalid input
 */
export function punycodeDecode(input) {
  const out = [];
  const basicEnd = Math.max(0, input.lastIndexOf('-'));
  for (let j = 0; j < basicEnd; j += 1) {
    const cp = input.charCodeAt(j);
    if (cp >= 0x80) throw new RangeError('punycode: non-basic code point');
    out.push(cp);
  }
  let i = 0;
  let n = PUNY.n;
  let bias = PUNY.bias;
  const max = 0x7fffffff;
  for (let idx = basicEnd > 0 ? basicEnd + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = PUNY.base; ; k += PUNY.base) {
      if (idx >= input.length) throw new RangeError('punycode: truncated input');
      const digit = punyDigit(input.charCodeAt(idx));
      idx += 1;
      if (digit >= PUNY.base || digit > Math.floor((max - i) / w)) throw new RangeError('punycode: bad digit');
      i += digit * w;
      const tt = k <= bias ? PUNY.tMin : k >= bias + PUNY.tMax ? PUNY.tMax : k - bias;
      if (digit < tt) break;
      if (w > Math.floor(max / (PUNY.base - tt))) throw new RangeError('punycode: overflow');
      w *= PUNY.base - tt;
    }
    const len = out.length + 1;
    bias = punyAdapt(i - oldi, len, oldi === 0);
    if (Math.floor(i / len) > max - n) throw new RangeError('punycode: overflow');
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff) throw new RangeError('punycode: code point out of range');
    out.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...out);
}

/**
 * Display form of an IDN hostname ('xn--mnchen-3ya.example.com' → 'münchen.example.com').
 * Labels that are not valid Punycode stay as they are.
 * @param {string} host
 * @returns {string}
 */
export function hostToUnicode(host) {
  return String(host ?? '').split('.').map((label) => {
    if (!/^xn--/i.test(label)) return label;
    try {
      return punycodeDecode(label.slice(4).toLowerCase());
    } catch {
      return label;
    }
  }).join('.');
}

/** Does `issuer` look like the issuer of `cert` (DN match, key IDs when both exist)? */
function issues(issuer, cert) {
  if (!issuer || !cert || issuer === cert) return false;
  if (issuer.subjectDN !== cert.issuerDN) return false;
  if (cert.authorityKeyId && issuer.subjectKeyId) return cert.authorityKeyId === issuer.subjectKeyId;
  return true;
}

/**
 * Analyse the certificates of one file as a chain starting at `leaf`.
 * @param {object[]} certs certificates in file order
 * @param {object} [leaf=certs[0]]
 * @param {Date|number} [now]
 * @returns {{ ordered: object[], unrelated: object[], complete: boolean, inOrder: boolean,
 *   roles: Map<object, 'leaf'|'intermediate'|'root'|'unrelated'>, missingIssuer: string|null,
 *   issues: Array<{ code: 'leaf-only'|'order'|'unrelated'|'root-included'|'ends-at'|'expired'|'self-signed', cert?: object, count?: number }> }}
 */
export function analyzeChain(certs, leaf = null, now = Date.now()) {
  const list = Array.isArray(certs) ? certs.filter(Boolean) : [];
  const start = leaf && list.includes(leaf) ? leaf : list[0];
  const out = { ordered: [], unrelated: [], complete: false, inOrder: true, roles: new Map(), missingIssuer: null, issues: [] };
  if (!start) return out;
  const ordered = [start];
  let cur = start;
  while (!cur.selfSigned) {
    const next = list.find((c) => !ordered.includes(c) && issues(c, cur));
    if (!next) break;
    ordered.push(next);
    cur = next;
  }
  out.ordered = ordered;
  out.complete = !!cur.selfSigned;
  out.unrelated = list.filter((c) => !ordered.includes(c));
  out.inOrder = ordered.every((c, i) => list.indexOf(c) === i);
  if (!out.complete) out.missingIssuer = cur.issuerDN || null;
  ordered.forEach((c, i) => {
    if (i === 0) out.roles.set(c, 'leaf');
    else out.roles.set(c, c.selfSigned ? 'root' : 'intermediate');
  });
  out.unrelated.forEach((c) => out.roles.set(c, 'unrelated'));

  const endEntity = !start.isCA;
  if (start.selfSigned && endEntity) out.issues.push({ code: 'self-signed', cert: start });
  else if (ordered.length === 1 && !start.selfSigned && endEntity) out.issues.push({ code: 'leaf-only', cert: start });
  if (!out.inOrder) out.issues.push({ code: 'order' });
  if (out.unrelated.length) out.issues.push({ code: 'unrelated', count: out.unrelated.length });
  if (ordered.length > 1 && out.complete) out.issues.push({ code: 'root-included', cert: cur });
  if (ordered.length > 1 && !out.complete) out.issues.push({ code: 'ends-at', cert: cur });
  const n = now instanceof Date ? now.getTime() : Number(now);
  for (const c of ordered.slice(1)) {
    if (c.notAfter.getTime() < n) out.issues.push({ code: 'expired', cert: c });
  }
  return out;
}

/**
 * The certificates servers should send: leaf + intermediates in chain order (no root).
 * @param {{ ordered: object[] }} analysis {@link analyzeChain} result
 * @returns {object[]}
 */
export function fullchainCerts(analysis) {
  const list = analysis.ordered.filter((c, i) => i === 0 || !c.selfSigned);
  return list.length ? list : analysis.ordered.slice(0, 1);
}

/**
 * Concatenated PEM of certificates (each ends with a newline).
 * @param {object[]} certs
 * @returns {string}
 */
export function pemBundle(certs) {
  return certs.map((c) => pemEncode(c.der)).join('');
}

/**
 * Host for the copy-ready `openssl s_client` command: the first certificate name that passes
 * lib/cmdline.js's name rules unchanged (exact names first, then a `*.x` wildcard as `www.x`),
 * else `example.com`. SAN bytes are not validated by the parser, so a hostile name (`;`, `$(…)`,
 * backticks, spaces, quotes, CR/LF, a leading '-', a port or path) is skipped here — never
 * quoted into a command the user pastes into a shell.
 * @param {string[]} hostnames certificate `hostnames`
 * @returns {string}
 */
export function sClientHost(hostnames) {
  const list = Array.isArray(hostnames) ? hostnames.filter((n) => typeof n === 'string') : [];
  const ordered = [
    ...list.filter((n) => !n.startsWith('*.')),
    ...list.filter((n) => n.startsWith('*.')).map((n) => `www.${n.slice(2)}`)
  ];
  // Exact match only: normalizeHostname would quietly cut 'a.com/;id' or 'a.com:443' down to 'a.com'.
  return ordered.find((n) => validateNames([n]).valid[0] === n) || 'example.com';
}

/**
 * The `openssl s_client` line of the PEM & OpenSSL tab (POSIX shell).
 * @param {string[]} hostnames certificate `hostnames`
 * @returns {string}
 */
export function sClientCommand(hostnames) {
  const host = sClientHost(hostnames);
  return `openssl s_client -connect ${host}:443 -servername ${host} -showcerts </dev/null`;
}

/** Hex string → base64 (for the pin-sha256 value). */
function hexToBase64(hex) {
  let bin = '';
  for (let i = 0; i + 1 < hex.length; i += 2) bin += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  return btoa(bin);
}

/**
 * Keep the crt.sh `?serial=` rows that belong to `cert` (serial numbers are only unique per
 * issuer, so rows are matched on the issuer CN) and de-duplicate them by crt.sh id.
 * @param {any} json crt.sh JSON (array of rows)
 * @param {{ issuer?: object, issuerCN?: string|null }} cert
 * @returns {{ rows: Array<{ id: number|string, issuer: string, notBefore: Date|null, notAfter: Date|null }>, ignored: number }}
 */
export function crtshSerialRows(json, cert) {
  const rows = Array.isArray(json) ? json.filter((r) => r && typeof r === 'object') : [];
  const wantCn = String((cert.issuer && cert.issuer.CN) || cert.issuerCN || '').trim().toLowerCase();
  const issuerCn = (name) => {
    const m = /(?:^|,\s*)CN=([^,]+)/.exec(String(name || ''));
    return m ? m[1].trim().toLowerCase() : '';
  };
  const parseDate = (s) => {
    if (typeof s !== 'string' || !s) return null;
    const d = new Date(/Z$|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`);
    return Number.isNaN(d.getTime()) ? null : d;
  };
  const matching = wantCn ? rows.filter((r) => issuerCn(r.issuer_name) === wantCn) : rows;
  const seen = new Set();
  const out = [];
  for (const r of matching) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    out.push({ id: r.id, issuer: String(r.issuer_name || ''), notBefore: parseDate(r.not_before), notAfter: parseDate(r.not_after) });
  }
  return { rows: out, ignored: rows.length - matching.length };
}

/** Readable name for a certificate: CN, else first hostname, else the DN. */
export function certDisplayName(cert) {
  if (!cert) return '';
  return cert.subjectCN || (cert.hostnames && cert.hostnames[0]) || cert.subjectDN || '—';
}

/** Issuer display name: O (CN) when both exist. */
export function issuerDisplayName(cert) {
  const o = cert.issuer && cert.issuer.O;
  const cn = cert.issuerCN || (cert.issuer && cert.issuer.CN);
  if (o && cn && o !== cn) return `${o} (${cn})`;
  return o || cn || cert.issuerDN || '—';
}

/** An RSA key under 2048 bits, or a SHA-1 / MD5 signature (the Details tab marks both as weak). */
function isWeakCert(cert) {
  return (cert.keyAlgorithm === 'RSA' && cert.keyBits && cert.keyBits < 2048) || /sha1|md5/i.test(cert.signatureAlgorithm || '');
}

/**
 * What "Copy summary" says about a certificate (lib/summary certSummary facts): its names,
 * validity, issuer and the warnings the overview shows.
 * @param {CertLoad} load
 * @returns {object}
 */
export function certSummaryFacts(load) {
  const leaf = load.result.leaf;
  const warnings = [
    leaf.selfSigned ? 'SELF_SIGNED' : null,
    leaf.isCA ? 'CA' : null,
    !leaf.isCA && !leaf.dnsNames.length && !leaf.ipAddresses.length ? 'NO_SAN' : null,
    leaf.isPrecertificate ? 'PRECERT' : null,
    isWeakCert(leaf) ? 'WEAK' : null
  ].filter(Boolean);
  return {
    name: certDisplayName(leaf), issuer: issuerDisplayName(leaf), dnsNames: leaf.dnsNames,
    notBefore: leaf.notBefore, notAfter: leaf.notAfter, warnings, source: load.source || 'file'
  };
}

function pemFileName(cert, suffix = '') {
  const base = certDisplayName(cert).replace(/^\*\./, 'wildcard.');
  return sanitizeFilename(`${base}${suffix}.pem`, 'certificate.pem');
}

/* ------------------------------------------------------------------------ */
/* Shared UI pieces (also used by views/scan.js)                            */
/* ------------------------------------------------------------------------ */

/**
 * Certificate picker: drop zone (click / drag & drop / Ctrl+V) plus a "paste as text" box.
 * Pasted text is cleared from the box once read, so a pasted private key does not stay on screen.
 * @param {{ onLoad: (load: CertLoad) => void, compact?: boolean, title?: string, hint?: string }} opts
 * @returns {{ el: HTMLElement, drop: object, input: HTMLInputElement, paste: object }}
 */
export function CertLoader({ onLoad, compact = false, title = null, hint = null }) {
  const drop = FileDrop({
    accept: CERT_ACCEPT,
    maxBytes: CERT_MAX_BYTES,
    compact,
    icon: 'certificate',
    title: title ?? t('cert.dropTitle'),
    hint: hint ?? t('cert.dropHint'),
    className: 'cert-drop',
    onFiles: (files) => {
      const f = files[0];
      if (!f) return;
      onLoad(loadCertificateData(new Uint8Array(f.buffer), { name: f.name, size: f.size, source: f.source }));
    }
  });
  const area = textarea({
    label: t('cert.pasteLabel'),
    rows: 7,
    placeholder: t('cert.pastePlaceholder'),
    attrs: { 'data-role': 'cert-paste' }
  });
  const read = () => {
    const text = area.value.trim();
    if (!text) {
      area.setError(t('cert.pasteEmpty'));
      return;
    }
    area.setError(null);
    area.value = '';
    onLoad(loadCertificateData(text, { name: t('file.pasted'), source: 'paste' }));
  };
  // A complete PEM block is read automatically (debounced) — no extra click needed.
  const auto = debounce(() => {
    if (/-----END [A-Z0-9 #]+-----/.test(area.value)) read();
  }, 350);
  area.input.addEventListener('input', auto);
  const paste = Disclosure({
    summary: t('cert.pasteToggle'),
    className: 'cert-paste',
    children: h('div', { class: 'stack-sm' }, area.el,
      h('div', { class: 'cluster' }, Button({ label: t('cert.pasteApply'), icon: 'check', size: 'sm', onClick: read, dataset: { action: 'cert-paste-read', shortcut: 'submit' } })))
  });
  // A form of its own for the shell's Ctrl/Cmd+Enter: Read answers the paste box, never a field of the page around it.
  paste.dataset.shortcutScope = 'cert-paste';
  const el = h('div', { class: 'cert-loader stack-sm' }, drop, paste);
  return { el, drop, input: drop.input, paste: area };
}

/**
 * The host-name form's state across re-mounts (a language switch, the other view): the typed
 * text, the host name it last took from another tool (`carried`: a newer one replaces it while
 * the field still holds it, lib/session.js fillReplaces; a lookup forgets it), the last outcome
 * that is not a loaded certificate (not found, crt.sh links, error) and the AbortController of
 * the lookup in progress (stopped by {@link setCurrentCert}).
 * @type {{ text: string, carried: string|null, last: object|null, running: AbortController|null }}
 */
const ctForm = { text: '', carried: null, last: null, running: null };

/** Stop the host-name lookup in progress, if any (its block is being replaced). */
function stopCtLookup() {
  const ctl = ctForm.running;
  ctForm.running = null;
  if (ctl) ctl.abort();
}

/**
 * When a lookup's Cert Spotter request is asked again after its hourly limit (the cool-down's
 * end), or null: not rate limited, no reset time, or the time has passed.
 * @param {import('../lib/ctcert.js').CtLookup} r
 * @param {number} now
 * @returns {Date|null}
 */
function spotterResetAt(r, now) {
  const c = r && r.certspotter;
  if (!c || c.errorKind !== 'rate-limit' || !c.quota || !c.quota.resetAt) return null;
  const d = new Date(c.quota.resetAt);
  return Number.isFinite(d.getTime()) && d.getTime() > now ? d : null;
}

/**
 * Why crt.sh was asked in a lookup (null when it was not): Cert Spotter's hourly limit (with the
 * time it is asked again), a refusal or no answer, a partial list or an unreadable copy.
 * @param {import('../lib/ctcert.js').CtLookup} r
 * @param {{ now?: number }} [opts]
 * @returns {string|null}
 */
export function ctCrtshWhy(r, { now = Date.now() } = {}) {
  if (!r || !r.crtsh || !r.certspotter) return null;
  if (r.certspotter.errorKind === 'rate-limit') {
    const reset = spotterResetAt(r, now);
    return [t('cert.alt.spotterQuota'), reset ? t('cert.alt.spotterAgain', { time: formatDate(reset, { timeStyle: 'short' }) }) : null]
      .filter(Boolean).join(' ');
  }
  if (r.certspotter.state === 'partial') return t('cert.alt.spotterPartial');
  return r.certspotter.state === 'ok' ? t('cert.alt.spotterUnreadable') : t('cert.alt.spotterFailed');
}

/** The error of a failed lookup (status 'error'), shaped for describeError(). */
function ctLookupError(r) {
  return Object.assign(new Error((r && r.error) || ''), { kind: (r && r.errorKind) || 'unknown' });
}

/**
 * Did crt.sh leave searches of a lookup unanswered (some, or all of them after a partial Cert
 * Spotter list)? Then a not-found may be wrong and a crt.sh find may not be the newest.
 * @param {import('../lib/ctcert.js').CtLookup} r
 * @returns {boolean}
 */
export function ctCrtshIncomplete(r) {
  return !!(r && r.crtsh && r.crtsh.error);
}

/**
 * The text of a lookup outcome that is not a loaded certificate (status 'manual', 'not-found' or
 * 'error'), as the "No file?" block shows it. An error after Cert Spotter's hourly limit says so,
 * and until when "Try again" searches crt.sh only. A not-found says flatly that nothing is logged
 * only on a complete answer: it is hedged when Cert Spotter's list was cut at the page cap (the
 * unread issuances are the newest) and when crt.sh left some or all of its searches unanswered
 * (a wildcard certificate may sit in the one that failed); a crt.sh find is hedged the same way.
 * @param {import('../lib/ctcert.js').CtLookup} r
 * @param {{ now?: number }} [opts]
 * @returns {string}
 */
export function ctOutcomeMessage(r, { now = Date.now() } = {}) {
  const why = ctCrtshWhy(r, { now });
  const incomplete = ctCrtshIncomplete(r);
  if (r.status === 'manual' && r.crtsh && r.crtsh.entry) {
    const e = r.crtsh.entry;
    return [
      why,
      t('cert.alt.manualCert', { host: r.host, names: e.names.join(', ') || r.host, issuer: dnDisplayName(e.issuer), date: formatDate(e.notAfter) }),
      incomplete ? t('cert.alt.manualPartial') : null
    ].filter(Boolean).join(' ');
  }
  if (r.status === 'not-found') {
    let key = 'cert.alt.notFound';
    // A crt.sh error leaves a gap whatever Cert Spotter answered: with `partial` crt.sh answered
    // some of its searches, without it none (a not-found then rests on a partial Cert Spotter list).
    if (incomplete) key = r.crtsh.partial ? 'cert.alt.notFoundCrtshPartial' : 'cert.alt.notFoundCrtshDown';
    else if (r.truncated && !r.crtsh) key = 'cert.alt.notFoundTruncated';
    const lines = [why, t(key, { host: r.host })];
    if (r.skipped && r.skipped.revoked) lines.push(t('cert.alt.revokedSkipped', { count: r.skipped.revoked }));
    return lines.filter(Boolean).join(' ');
  }
  const { message } = describeError(ctLookupError(r));
  if (!(r.certspotter && r.certspotter.errorKind === 'rate-limit')) return message;
  const reset = spotterResetAt(r, now);
  return [t('cert.alt.bothFailedQuota'), message, reset ? t('cert.alt.retryCrtshOnly', { time: formatDate(reset, { timeStyle: 'short' }) }) : null]
    .filter(Boolean).join(' ');
}

/**
 * "No file?" block under a certificate picker: load the public certificate of a host name from
 * Certificate Transparency (lib/ctcert.js; only the name leaves the browser, and only on a
 * click), or the bundled sample. A certificate loaded meanwhile (the sample, a file, a hand-over)
 * stops the lookup through {@link setCurrentCert}, and a lookup whose block was replaced is never
 * loaded over the user's choice.
 * @param {{ onLoad: (load: CertLoad) => void, signal?: AbortSignal|null, onBusy?: ((busy: boolean) => void)|null,
 *   onStale?: (() => void)|null, focusTarget?: (() => HTMLElement|null)|null }} opts onBusy: the view's
 *   busy flag while a lookup runs (defers a language re-mount; the block's own live status says what
 *   runs); onStale: the sample file failed to load (ctx.checkOutdated); focusTarget: where the
 *   loaded certificate shows once `onLoad` has rendered it (its source note), for the keyboard
 *   focus that was in this block ({@link focusLoadedCert})
 * @returns {{ el: HTMLElement, input: HTMLInputElement, search: (host: string) => void }} search: look a host
 *   name up as if it were typed and Load pressed
 */
export function CertAlternatives({ onLoad, signal = null, onBusy = null, onStale = null, focusTarget = null, requireOnline = () => true }) {
  const status = h('div', { class: 'cert-alt-status', attrs: { 'aria-live': 'polite' } });
  let running = null;
  const field = textInput({
    value: ctForm.text,
    placeholder: t('cert.alt.placeholder'),
    mono: true,
    className: 'cert-alt-field',
    attrs: { 'data-role': 'ct-host', enterkeyhint: 'search' },
    onInput: (v) => {
      ctForm.text = v;
      setFieldError(null);
    },
    onEnter: () => {
      if (!running) lookup();
    }
  });
  const loadBtn = Button({
    label: t('cert.alt.load'),
    icon: 'search',
    dataset: { action: 'ct-load', shortcut: 'submit' },
    onClick: () => (running ? running.abort() : lookup())
  });
  const sampleBtn = Button({ label: t('cert.alt.sample'), icon: 'file-text', size: 'sm', variant: 'ghost', dataset: { action: 'cert-sample' }, onClick: () => sample() });
  // The hint sits under the whole row (field + Load), outside the field's own hint slot, so it is
  // tied to the input here; fieldShell rewrites aria-describedby on every setError.
  const hintId = `${field.input.id}-ct-hint`;
  const setFieldError = (msg) => {
    field.setError(msg);
    const ids = (field.input.getAttribute('aria-describedby') || '').split(' ').filter((x) => x && x !== hintId);
    field.input.setAttribute('aria-describedby', [hintId, ...ids].join(' '));
  };
  // A form of its own for the shell's shortcuts: Load answers the host name field only.
  const el = h('div', { class: 'cert-alt stack-sm', dataset: { role: 'cert-alt', shortcutScope: 'ct-lookup' } },
    h('label', { class: 'field-label', for: field.input.id }, t('cert.alt.title')),
    h('div', { class: 'cert-alt-row' }, field.el, loadBtn),
    h('p', { class: 'muted text-sm cert-alt-hint', id: hintId }, t('cert.alt.hint')),
    status,
    h('div', { class: 'cluster cert-alt-sample' }, sampleBtn, h('span', { class: 'muted text-sm' }, t('cert.alt.sampleHint'))));
  setFieldError(null);

  /** Is the keyboard focus in this block? */
  const focusInBlock = () => {
    const doc = globalThis.document;
    return !!doc && el.contains(doc.activeElement);
  };

  /**
   * Hand `load` over; the keyboard focus that is in this block (which the load replaces) follows
   * the certificate. `hadFocus`: the focus was here when the action started and has fallen to
   * <body> since (Try a sample disables its button while the file loads). Focus the user moved
   * elsewhere meanwhile stays where it is.
   */
  function loaded(load, hadFocus) {
    const doc = globalThis.document;
    const active = doc ? doc.activeElement : null;
    const lost = !active || active === doc.body || active === doc.documentElement;
    const follow = focusInBlock() || (hadFocus && lost);
    onLoad(load);
    if (follow && focusTarget && !(el.isConnected && focusInBlock())) focusLoadedCert(focusTarget());
  }

  function setRunning(host) {
    const icon = loadBtn.querySelector('.icon');
    if (icon) icon.replaceWith(Icon(host ? 'x' : 'search', { size: 16 }));
    loadBtn.querySelector('.btn-label').textContent = host ? t('common.cancel') : t('cert.alt.load');
    loadBtn.dataset.state = host ? 'running' : 'idle';
    // Esc stops a running lookup (the shell's shortcut); Enter in the field starts one.
    loadBtn.dataset.shortcut = host ? 'cancel' : 'submit';
    clear(status);
    // The spinner's label is the one announcement (status is a live region), so onBusy gets no text.
    if (host) status.append(Spinner({ label: t('cert.alt.searching', { host }), showLabel: true }));
    if (onBusy) onBusy(!!host);
  }

  async function lookup() {
    const host = normalizeCtHost(field.value);
    if (!host) {
      setFieldError(t('cert.alt.invalid'));
      field.focus();
      return;
    }
    setFieldError(null);
    if (!requireOnline()) return;
    stopCtLookup();
    const ctl = new AbortController();
    running = ctl;
    ctForm.running = ctl;
    ctForm.last = null;
    ctForm.carried = null;
    // "Try again" is cleared with the outcome: its keyboard focus moves to Load, now Cancel.
    const doc = globalThis.document;
    const fromOutcome = !!doc && status.contains(doc.activeElement);
    const hadFocus = focusInBlock();
    setRunning(host);
    if (fromOutcome) loadBtn.focus({ preventScroll: true });
    let result = null;
    try {
      result = await lookupCtCertificate(host, { signal: mergeSignals(signal, ctl.signal) });
    } catch (err) {
      if (errorKind(err) !== 'abort') result = { host, status: 'error', error: String(err && err.message ? err.message : err), errorKind: errorKind(err) };
    }
    running = null;
    if (ctForm.running === ctl) ctForm.running = null;
    if (!el.isConnected || (signal && signal.aborted)) {
      // Stopped with its block: release the busy flag, unless a newer lookup holds it.
      if (onBusy && !ctForm.running) onBusy(false);
      return;
    }
    setRunning(null);
    if (!result) return; // cancelled
    if (result.status === 'found') {
      loaded(ctCertLoad(result), hadFocus);
      return;
    }
    ctForm.last = result;
    showOutcome(result);
  }

  async function sample() {
    const hadFocus = focusInBlock();
    setButtonBusy(sampleBtn, true);
    try {
      const load = await loadSampleCert({ signal });
      if (el.isConnected) loaded(load, hadFocus);
    } catch (err) {
      if (errorKind(err) === 'abort') return;
      toast(t('cert.alt.sampleFailed'), { type: 'error' });
      if (onStale) onStale();
    } finally {
      setButtonBusy(sampleBtn, false);
    }
  }

  function retryButton() {
    return Button({ label: t('common.retry'), icon: 'refresh', size: 'sm', dataset: { action: 'ct-retry' }, onClick: () => lookup() });
  }

  function showOutcome(r) {
    clear(status);
    if (!r) return;
    let box = null;
    if (r.status === 'manual' && r.crtsh && r.crtsh.entry) {
      const e = r.crtsh.entry;
      box = Alert({
        variant: 'warn',
        compact: true,
        icon: 'download',
        title: t('cert.alt.manualTitle'),
        message: ctOutcomeMessage(r),
        // A single id: crt.sh holds one half of the pair so far, so there is no "other link".
        children: h('p', { class: 'text-sm cert-alt-why' }, t(e.downloads.length > 1 ? 'cert.alt.manualWhy' : 'cert.alt.manualWhyOne')),
        actions: [
          ...e.downloads.map((d) => ButtonLink({ href: d.url, label: t('cert.alt.download', { id: d.id }), icon: 'download', size: 'sm', external: true })),
          ExternalLink(e.pageUrl, t('cert.alt.openCrtsh'), { className: 'text-sm' })
        ]
      });
    } else if (r.status === 'not-found') {
      // A not-found that rests on unanswered crt.sh searches offers the retry its text suggests.
      box = Alert({
        variant: 'info',
        compact: true,
        icon: 'search',
        message: ctOutcomeMessage(r),
        actions: ctCrtshIncomplete(r) ? [retryButton()] : null
      });
    } else {
      // ErrorBanner's layout, with a message that also says why only crt.sh was asked; the
      // details are the failed request's own text ('HTTP 502 …', 'Failed to fetch').
      const detail = r.error || '';
      box = Alert({
        variant: 'error',
        compact: true,
        title: t('cert.alt.failed'),
        message: ctOutcomeMessage(r),
        children: detail ? h('details', { class: 'alert-details' }, h('summary', null, t('error.details')), h('code', { class: 'mono' }, detail)) : null,
        actions: [retryButton()]
      });
    }
    box.dataset.ctResult = r.status;
    status.append(box);
  }

  if (ctForm.last) showOutcome(ctForm.last);
  return {
    el,
    input: field.input,
    // Look `host` up as if it were typed and Load pressed (the Certificate view's "Run again").
    search(host) {
      if (running) return;
      field.value = host;
      ctForm.text = host;
      lookup();
    }
  };
}

/**
 * Move the keyboard focus to where a certificate loaded from the "No file?" block now shows (its
 * source note), so a keyboard user who pressed Enter or Try a sample keeps their place instead of
 * falling to <body> when the block is re-rendered. The element becomes focusable (tabindex -1).
 * @param {HTMLElement|null} target
 * @returns {boolean} focus moved
 */
export function focusLoadedCert(target) {
  if (!target || !target.isConnected || typeof target.focus !== 'function') return false;
  if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
  target.focus({ preventScroll: true });
  if (typeof target.scrollIntoView === 'function') target.scrollIntoView({ block: 'nearest', behavior: scrollBehavior() });
  return true;
}

/**
 * "From Certificate Transparency" / "Sample" badge of a {@link CertLoad}; null for a file.
 * @param {CertLoad|null} load
 * @returns {HTMLSpanElement|null}
 */
export function certSourceBadge(load) {
  if (!load) return null;
  let el = null;
  if (load.source === 'ct') el = Badge(t('cert.src.ctBadge'), { variant: 'info', icon: 'eye', title: t('cert.src.ct') });
  else if (load.source === 'sample') el = Badge(t('cert.src.sampleBadge'), { variant: 'accent', icon: 'file-text' });
  if (el) el.dataset.certSource = load.source;
  return el;
}

/**
 * Where a certificate that is not the user's file came from, as a compact callout: the CT
 * caveat ("the server may serve a different one", what was found, a newer precertificate, a
 * list read only in part) or the sample note. null for a file.
 * @param {CertLoad|null} load
 * @param {{ actions?: Array<Node|null>, extra?: string|null }} [opts] actions: e.g. a Verify link;
 *   extra: one more sentence (the SSL Targets view's)
 * @returns {HTMLElement|null}
 */
export function CertSourceNote(load, { actions = [], extra = null } = {}) {
  if (!load) return null;
  const acts = (actions || []).filter(Boolean);
  let el = null;
  if (load.source === 'sample') {
    el = Alert({ variant: 'info', compact: true, icon: 'file-text', message: [t('cert.src.sample'), extra].filter(Boolean).join(' '), actions: acts });
  } else if (load.source === 'ct' && load.ct) {
    const ct = load.ct;
    const issued = ct.issuance && ct.issuance.notBefore ? formatDate(ct.issuance.notBefore) : '—';
    const lines = [
      t('cert.src.ctWhat', { host: ct.host, date: issued }),
      ct.precertificate ? t('cert.src.ctPrecert') : null,
      ct.newerPrecertificate ? t('cert.src.ctNewerPrecert', { date: formatDate(ct.newerPrecertificate.notBefore) }) : null,
      ct.truncated ? t('cert.src.ctTruncated') : null,
      extra
    ].filter(Boolean);
    const link = ct.issuance && ct.issuance.url ? ExternalLink(ct.issuance.url, t('cert.src.ctOpen'), { className: 'text-sm' }) : null;
    el = Alert({ variant: 'info', compact: true, icon: 'eye', title: t('cert.src.ct'), message: lines.join(' '), actions: [...acts, link].filter(Boolean) });
  }
  if (el) {
    el.classList.add('cert-source-note');
    el.dataset.certSource = load.source;
  }
  return el;
}

/**
 * Alerts for parseCertificates() warnings (translated; technical details collapsed).
 * NO_CERTIFICATE is dropped when a more specific reason (PKCS#12 / CSR) explains it.
 * @param {{ warnings: Array<{ code: string, detail?: string }> }} result
 * @param {{ name?: string, compact?: boolean }} [opts]
 * @returns {HTMLElement[]}
 */
export function certWarningAlerts(result, { name = '', compact = true } = {}) {
  const warnings = (result && result.warnings) || [];
  const codes = new Set(warnings.map((w) => w.code));
  const out = [];
  const details = (list) => (list.length
    ? h('details', { class: 'alert-details' }, h('summary', null, t('error.details')),
      h('div', { class: 'stack-sm' }, list.map((d) => h('code', { class: 'mono' }, d))))
    : null);
  const seen = new Set();
  for (const w of warnings) {
    if (seen.has(w.code)) continue;
    seen.add(w.code);
    const same = warnings.filter((x) => x.code === w.code).map((x) => x.detail).filter(Boolean);
    const alert = (variant, iconName, body, children = null) => {
      const a = Alert({
        variant,
        icon: iconName,
        compact,
        title: t(`cert.warn.${w.code}.title`),
        message: body,
        children
      });
      a.dataset.warning = w.code;
      out.push(a);
    };
    switch (w.code) {
      case 'PRIVATE_KEY_PRESENT':
        alert('warn', 'key', t('cert.warn.PRIVATE_KEY_PRESENT.body'));
        break;
      case 'PKCS12_UNSUPPORTED': {
        let cmd = w.detail || 'openssl pkcs12 -in file.pfx -nokeys -out cert.pem';
        if (/^[\w.-]+\.(pfx|p12)$/i.test(name)) cmd = cmd.replace('file.pfx', name);
        alert('warn', 'lock', t('cert.warn.PKCS12_UNSUPPORTED.body'), CodeBlock(cmd, { label: 'OpenSSL' }));
        break;
      }
      case 'CSR_NOT_CERT':
        alert('info', 'file-text', t('cert.warn.CSR_NOT_CERT.body'));
        break;
      case 'NO_CERTIFICATE':
        if (codes.has('PKCS12_UNSUPPORTED') || codes.has('CSR_NOT_CERT')) break;
        alert('error', 'x-circle', t('cert.warn.NO_CERTIFICATE.body'),
          same.length ? h('div', { class: 'text-sm' }, t('cert.warn.foundOnly', { what: same.join(', ').replace(/^Found only:\s*/i, '') })) : null);
        break;
      case 'PARSE_ERROR':
        alert('warn', 'alert', t('cert.warn.PARSE_ERROR.body'), details(same));
        break;
      case 'EXPIRED':
        alert('error', 'x-circle', t('cert.warn.EXPIRED.body', { date: formatDateTime(result.leaf ? result.leaf.notAfter : w.detail) }));
        break;
      case 'NOT_YET_VALID':
        alert('warn', 'clock', t('cert.warn.NOT_YET_VALID.body', { date: formatDateTime(result.leaf ? result.leaf.notBefore : w.detail) }));
        break;
      default:
        break;
    }
  }
  const leaf = result && result.leaf;
  if (leaf && !leaf.isCA && !leaf.dnsNames.length && !leaf.ipAddresses.length) {
    const a = Alert({ variant: 'warn', compact, icon: 'alert', message: t('cert.warn.noSan', { cn: leaf.subjectCN || '—' }) });
    a.dataset.warning = 'NO_SAN';
    out.push(a);
  }
  // A precertificate (CT poison) never reaches a server: its fingerprint matches nothing served.
  if (leaf && leaf.isPrecertificate) {
    const a = Alert({ variant: 'warn', compact, icon: 'alert', message: t('cert.warn.PRECERT') });
    a.dataset.warning = 'PRECERT';
    out.push(a);
  }
  return out;
}

/**
 * Compact summary of the loaded certificate (name, issuer, validity, names).
 * @param {CertLoad} load
 * @param {{ actions?: Node|Node[], maxNames?: number }} [opts]
 * @returns {HTMLElement}
 */
export function CertSummary(load, { actions = null, maxNames = 8 } = {}) {
  const cert = load.result.leaf;
  const count = load.result.certificates.length;
  const names = cert.hostnames.length ? cert.hostnames : cert.dnsNames;
  return h('div', { class: 'cert-summary', dataset: { serial: cert.serialHex } },
    h('div', { class: 'cert-summary-head' },
      h('span', { class: 'cert-summary-icon' }, Icon('certificate', { size: 20 })),
      h('div', { class: 'cert-summary-titles' },
        h('div', { class: 'cert-summary-cn mono' }, certDisplayName(cert)),
        h('div', { class: 'cert-summary-meta' },
          h('span', null, t('cert.issuedBy', { issuer: issuerDisplayName(cert) })),
          h('span', { class: 'cert-summary-file' }, t('cert.fileInfo', { name: load.name || '—', count: t('cert.count', { count }) })))),
      actions ? h('div', { class: 'cert-summary-actions' }, actions) : null),
    h('div', { class: 'cluster cert-summary-badges' },
      certSourceBadge(load),
      ValidityBadge(cert),
      Badge(t('cert.names.count', { count: cert.dnsNames.length }), { variant: 'neutral', icon: 'globe' }),
      cert.hostnames.some((n) => n.startsWith('*.')) ? Badge(t('cert.badge.wildcard'), { variant: 'accent', icon: 'layers' }) : null,
      cert.validationLevel ? Badge(cert.validationLevel, { variant: 'info', title: t(`cert.level.${cert.validationLevel}`) }) : null,
      cert.selfSigned ? Badge(t('cert.badge.selfSigned'), { variant: 'warn', icon: 'alert' }) : null),
    names.length ? TruncatedList(names, { max: maxNames, inline: true }) : null);
}

/* ------------------------------------------------------------------------ */
/* View                                                                     */
/* ------------------------------------------------------------------------ */

/** Per-certificate async results that survive re-mounts (keyed by serial + issuer). */
const caaCache = new Map();
const ctCache = new Map();
/** DANE / TLSA job holders per leaf certificate (ui/dane-panel.js keeps its job on `holder.dane`). */
const daneHolders = new Map();
/** View state that survives navigation and language re-mounts. */
const viewState = { key: null, selected: 0, tab: 'names' };
let teardown = null;
/** The mounted view's page-session hooks ({@link result}, {@link rerun}); null while another tool is shown. */
let active = null;

/**
 * The host name a certificate from Certificate Transparency was looked up for, or null (a file,
 * the sample, a hand-over).
 * @param {CertLoad|null} load
 * @returns {string|null}
 */
function ctHostOf(load) {
  return load && load.source === 'ct' && load.ct && load.ct.host ? load.ct.host : null;
}

/** The host name of the "No file?" field's last lookup (its outcome, or the certificate it loaded), as a list. */
const lastCtLookup = (load) => {
  const host = ctForm.last ? ctForm.last.host : ctHostOf(load);
  return host ? [host] : null;
};
/** The host name the field holds, as a lookup reads it (a list of at most one). */
const ctFieldHosts = (text) => {
  const host = normalizeCtHost(text);
  return host ? [host] : [];
};

// "Delete all local data" (About, or Settings on any view) forgets the "No file?" field, its last
// outcome and what was checked per certificate (the certificate itself goes with state.session),
// stopping what runs; the shell opens the view again when it is on screen.
stateSingleton.subscribe(({ key }) => {
  if (key !== 'cleared') return;
  stopCtLookup();
  ctForm.text = '';
  ctForm.carried = null;
  ctForm.last = null;
  caaCache.clear();
  ctCache.clear();
  for (const holder of daneHolders.values()) cancelDane(holder);
  daneHolders.clear();
  Object.assign(viewState, { key: null, selected: 0, tab: 'names' });
});

/**
 * Start (or join) a cached async task. Every panel showing the running entry registers a
 * watcher, so results reach panels that were re-created while the task ran (tab switches).
 * Aborted tasks (view unmounted) are removed from the cache and re-run on the next visit.
 * @param {Map<string, object>} cache
 * @param {string} key
 * @param {() => Promise<object>} fn resolves with fields merged into the entry
 * @returns {{ status: string, watchers: Set<Function> }}
 */
function startTask(cache, key, fn) {
  const prev = cache.get(key);
  if (prev && prev.status === 'running') return prev;
  const entry = { status: 'running', watchers: new Set() };
  cache.set(key, entry);
  Promise.resolve().then(fn).then((data) => {
    Object.assign(entry, data, { status: 'done' });
  }, (err) => {
    if (errorKind(err) === 'abort') {
      if (cache.get(key) === entry) cache.delete(key);
      entry.status = 'aborted';
    } else {
      entry.status = 'error';
      entry.error = err;
    }
  }).then(() => {
    const watchers = [...entry.watchers];
    entry.watchers.clear();
    for (const w of watchers) w(entry);
  });
  return entry;
}

function certKey(cert) {
  return `${cert.serialHex}|${cert.issuerDN}`;
}

function sanTypeLabel(type) {
  return ['dns', 'ip', 'email', 'uri'].includes(type) ? t(`cert.san.${type}`) : t('cert.san.other');
}

function translatedList(values, prefix) {
  return (values || []).map((v) => (hasString(`${prefix}.${v}`) ? t(`${prefix}.${v}`) : v));
}

function linkList(urls) {
  if (!urls || !urls.length) return null;
  return h('div', { class: 'stack-sm' }, urls.map((u) => ExternalLink(u, u, { className: 'mono text-sm' })));
}

/**
 * Mount the Certificate view.
 * @param {HTMLElement} container
 * @param {import('../app.js').ViewContext} ctx
 */
export function mount(container, ctx) {
  const { state } = ctx;
  let load = getCurrentCert(state);
  // A host name carried over from another tool fills the "No file?" field while it is empty or
  // still holds the last lookup or the host carried before (never a host the user typed); an
  // outcome for another host goes.
  const carried = normalizeCtHost(ctx.params.host || '');
  if (carried && fillReplaces(ctForm.text, lastCtLookup(load), ctFieldHosts, ctForm.carried)) {
    if (ctForm.last && ctForm.last.host !== carried) ctForm.last = null;
    ctForm.text = carried;
    ctForm.carried = carried;
  }

  const loaderHost = h('div');
  // The certificate's tabs are no part of a loader's form: Ctrl/Cmd+Enter there submits nothing.
  const content = h('div', { class: 'stack cert-content', dataset: { shortcutScope: 'results' } });
  container.append(h('div', { class: 'stack cert-view' }, loaderHost, content));

  function setLoad(next, { announce = true } = {}) {
    load = next;
    setCurrentCert(state, next);
    ctx.runStarted(certTarget(next));
    // A carried-over host name (`?host=…&run=0`) has done its job once a certificate is chosen.
    if (ctx.params.host) ctx.setParams({});
    if (next && next.result.leaf) {
      const key = certKey(next.result.leaf);
      if (viewState.key !== key) {
        viewState.key = key;
        viewState.selected = Math.max(0, next.result.certificates.indexOf(next.result.leaf));
        viewState.tab = 'names';
      }
      if (announce) toast(t('cert.loadedToast', { name: next.name || certDisplayName(next.result.leaf) }), { type: 'success', timeout: 2500 });
    }
    render();
  }

  /** Hand the certificate to SSL Targets (the scan that finds its servers, then Verify). */
  function openInTargets() {
    state.setSession(PENDING_CERT, load);
    ctx.navigate('scan');
  }

  /** The "No file?" block on screen (its `search` is "Run again" for a certificate from CT). */
  let alternatives = null;

  function renderLoader() {
    clear(loaderHost);
    const loader = CertLoader({ onLoad: (l) => setLoad(l), compact: !!load });
    // '/' lands on the drop zone, which also takes a pasted certificate (Ctrl+V).
    loader.drop.el.dataset.shortcut = 'focus';
    alternatives = CertAlternatives({
      onLoad: (l) => setLoad(l),
      signal: ctx.signal,
      onBusy: ctx.setBusy,
      onStale: ctx.checkOutdated,
      requireOnline: ctx.requireOnline,
      focusTarget: () => content.querySelector('.cert-source-note') || content.querySelector('.cert-overview-cn')
    });
    if (!load) {
      loaderHost.append(Card({
        title: t('cert.loaderTitle'),
        subtitle: t('cert.loaderSubtitle'),
        icon: 'certificate',
        className: 'cert-loader-card',
        children: h('div', { class: 'stack' }, loader.el,
          h('p', { class: 'muted text-sm cert-privacy' }, Icon('lock', { size: 14 }), ' ', t('cert.privacy')),
          alternatives.el)
      }));
      return;
    }
    loaderHost.append(Disclosure({
      summary: t('cert.loadAnother'),
      className: 'cert-reload',
      children: h('div', { class: 'stack-sm' }, loader.el, h('p', { class: 'muted text-sm' }, t('cert.privacy')), alternatives.el)
    }));
  }

  // The DANE panel on screen: it listens on its holder (kept across re-mounts), so a panel that
  // is replaced (another certificate or tab render, a re-mount) must stop listening.
  let daneUi = null;
  const disposeDane = () => {
    if (daneUi) daneUi.dispose();
    daneUi = null;
  };

  function render() {
    renderLoader();
    disposeDane();
    clear(content);
    if (!load) {
      content.append(EmptyState({ icon: 'shield', title: t('cert.emptyTitle'), message: t('cert.emptyBody') }));
      return;
    }
    const { result } = load;
    content.append(...certWarningAlerts(result, { name: load.name }));
    if (!result.leaf) {
      content.append(Button({
        label: t('cert.remove'), icon: 'trash', variant: 'ghost', dataset: { action: 'cert-remove' },
        onClick: () => setLoad(null)
      }));
      return;
    }
    const analysis = analyzeChain(result.certificates, result.leaf);
    const certs = [...analysis.ordered, ...analysis.unrelated];
    if (viewState.selected >= result.certificates.length) viewState.selected = 0;
    // A CT certificate is what a CA issued, not what a server sends: point at the check that knows.
    const sourceNote = CertSourceNote(load, {
      actions: load.source === 'ct' ? [Button({
        label: t('cert.src.verify'), icon: 'check-circle', size: 'sm', dataset: { action: 'ct-verify' }, onClick: openInTargets
      })] : []
    });
    if (sourceNote) content.append(sourceNote);
    content.append(overviewCard(result.leaf, analysis));
    if (result.certificates.length > 1) {
      const sel = select({
        label: t('cert.showing'),
        className: 'cert-picker',
        value: String(viewState.selected),
        options: certs.map((c) => ({
          value: String(result.certificates.indexOf(c)),
          label: t('cert.optionLabel', { role: t(`cert.role.${analysis.roles.get(c)}`), name: certDisplayName(c) })
        })),
        onChange: (v) => {
          viewState.selected = Number(v);
          renderTabs();
        }
      });
      sel.input.dataset.role = 'cert-select';
      content.append(sel.el);
    }
    const tabsHost = h('div', { class: 'cert-tabs-host' });
    content.append(tabsHost);

    function renderTabs() {
      clear(tabsHost);
      const cert = result.certificates[viewState.selected] || result.leaf;
      const tabs = Tabs([
        { id: 'names', label: t('cert.tab.names'), icon: 'globe', badge: cert.sans.length || null, content: () => namesPanel(cert) },
        { id: 'details', label: t('cert.tab.details'), icon: 'list', content: () => detailsPanel(cert) },
        { id: 'chain', label: t('cert.tab.chain'), icon: 'git-branch', badge: result.certificates.length, content: () => chainPanel(analysis) },
        { id: 'caa', label: t('cert.tab.caa'), icon: 'shield', content: () => caaPanel(cert) },
        { id: 'dane', label: t('dane.tab'), icon: 'key', content: () => danePanel(cert) },
        { id: 'ct', label: t('cert.tab.ct'), icon: 'eye', content: () => ctPanel(cert) },
        { id: 'pem', label: t('cert.tab.pem'), icon: 'terminal', content: () => pemPanel(cert, analysis) }
      ], {
        selected: viewState.tab,
        label: t('nav.cert'),
        className: 'cert-tabs',
        onChange: (tabId) => {
          viewState.tab = tabId;
        }
      });
      tabsHost.append(tabs.el);
    }
    renderTabs();

    /** Switch the detail tabs to another certificate of the file. */
    function showCert(cert) {
      viewState.selected = result.certificates.indexOf(cert);
      viewState.tab = 'details';
      const sel = content.querySelector('[data-role="cert-select"]');
      if (sel) sel.value = String(viewState.selected);
      renderTabs();
      tabsHost.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
    }

    /* --- overview ------------------------------------------------------- */
    function overviewCard(leaf, chain) {
      const v = validityState(leaf);
      const variant = validityVariant(v);
      const fill = h('div', { class: ['cert-validity-fill', `cert-validity-${variant}`] });
      fill.style.width = `${(v.elapsed * 100).toFixed(1)}%`;
      const full = fullchainCerts(chain);
      const findBtn = Button({
        label: t('cert.findTargets'),
        icon: 'target',
        variant: 'primary',
        title: t('cert.findTargetsHint'),
        dataset: { action: 'find-targets' },
        onClick: openInTargets
      });
      const actions = h('div', { class: 'cluster cert-actions' },
        findBtn,
        Button({
          label: t('cert.downloadPem'), icon: 'download', dataset: { action: 'download-pem' },
          onClick: () => downloadText(pemFileName(leaf), pemEncode(leaf.der), 'application/x-pem-file')
        }),
        full.length > 1 ? Button({
          label: t('cert.downloadChain'), icon: 'download', dataset: { action: 'download-chain' }, title: t('cert.chain.fullchainHint'),
          onClick: () => downloadText(pemFileName(leaf, '-fullchain'), pemBundle(full), 'application/x-pem-file')
        }) : null,
        CopyButton(() => pemEncode(leaf.der), { label: t('cert.copyPem'), variant: 'ghost', size: 'md' }),
        SummaryButton({ kind: 'cert', size: 'md', facts: () => certSummaryFacts(load), url: () => ctx.shareUrl(permalinkParams('cert', ctx.params)) }),
        Button({
          label: t('cert.remove'), icon: 'trash', variant: 'ghost', dataset: { action: 'cert-remove' },
          onClick: () => {
            setLoad(null, { announce: false });
            toast(t('cert.removed'), { type: 'info', timeout: 2000 });
          }
        }));
      return h('div', { class: 'card cert-overview', dataset: { validity: v.state } },
        h('div', { class: 'cert-overview-main' },
          h('div', { class: 'cert-overview-id' },
            h('span', { class: 'cert-overview-icon' }, Icon('certificate', { size: 26 })),
            h('div', { class: 'cert-overview-titles' },
              h('h2', { class: 'cert-overview-cn mono' }, certDisplayName(leaf)),
              h('div', { class: 'cert-overview-issuer' }, t('cert.issuedBy', { issuer: issuerDisplayName(leaf) })),
              h('div', { class: 'cluster cert-overview-badges' },
                certSourceBadge(load),
                Badge(t('cert.names.count', { count: leaf.dnsNames.length }), { variant: 'neutral', icon: 'globe' }),
                leaf.hostnames.some((n) => n.startsWith('*.')) ? Badge(t('cert.badge.wildcard'), { variant: 'accent', icon: 'layers' }) : null,
                leaf.validationLevel ? Badge(t(`cert.level.${leaf.validationLevel}`), { variant: 'info', icon: 'shield' }) : null,
                leaf.selfSigned ? Badge(t('cert.badge.selfSigned'), { variant: 'warn', icon: 'alert' }) : null,
                leaf.isCA ? Badge(t('cert.badge.ca'), { variant: 'neutral', icon: 'git-branch' }) : null,
                leaf.isPrecertificate ? Badge(t('cert.badge.precert'), { variant: 'warn' }) : null,
                leaf.mustStaple ? Badge(t('cert.badge.mustStaple'), { variant: 'neutral' }) : null,
                Badge(`${leaf.keyAlgorithm}${leaf.keyBits ? ` ${leaf.keyBits}` : ''}${leaf.curve ? ` · ${leaf.curve}` : ''}`, { variant: 'neutral', icon: 'key', mono: true })))),
          h('div', { class: 'cert-validity' },
            h('div', { class: 'cert-validity-head' },
              ValidityBadge(leaf),
              h('span', { class: 'muted text-sm' }, t('cert.validity.lifetime', { count: v.lifetimeDays }))),
            h('div', {
              class: 'cert-validity-track',
              attrs: { role: 'img', 'aria-label': `${t('cert.validity.elapsed')}: ${Math.round(v.elapsed * 100)}%` }
            }, fill),
            h('div', { class: 'cert-validity-dates text-sm' },
              h('span', { title: leaf.notBefore.toISOString() }, formatDate(leaf.notBefore)),
              h('span', { title: leaf.notAfter.toISOString() }, formatDate(leaf.notAfter))))),
        h('div', { class: 'cert-overview-foot' }, actions));
    }

    /* --- names ---------------------------------------------------------- */
    function namesPanel(cert) {
      const domains = baseDomainsFromNames(cert.hostnames);
      const rows = cert.sans.map((s, i) => ({ ...s, i }));
      const hasIdn = rows.some((r) => r.type === 'dns' && /(^|\.)xn--/i.test(r.value));
      const table = DataTable({
        caption: t('cert.names.sans'),
        search: rows.length > 12,
        dense: true,
        empty: t('cert.names.empty'),
        rows,
        rowKey: (r) => `${r.type}:${r.value}:${r.i}`,
        export: { filename: 'certificate-names', subject: certDisplayName(cert) },
        columns: [
          { key: 'type', label: t('cert.names.col.type'), sortable: true, render: (r) => Badge(sanTypeLabel(r.type), { variant: r.type === 'dns' ? 'accent' : 'neutral' }), searchValue: (r) => r.type, width: '6rem' },
          {
            key: 'value',
            label: t('cert.names.col.value'),
            sortable: true,
            mono: true,
            sortValue: (r) => (r.type === 'dns' ? String(r.value).toLowerCase().split('.').reverse().join('.') : r.value),
            searchValue: (r) => r.value,
            exportValue: (r) => r.value,
            render: (r) => h('span', { class: 'cert-san' }, r.value,
              r.type === 'dns' && String(r.value).startsWith('*.') ? Badge(t('cert.badge.wildcard'), { variant: 'accent', className: 'cert-san-badge' }) : null)
          },
          hasIdn ? {
            key: 'unicode',
            label: t('cert.names.col.unicode'),
            sortable: false,
            sortValue: (r) => (r.type === 'dns' ? hostToUnicode(r.value) : ''),
            render: (r) => (r.type === 'dns' && /(^|\.)xn--/i.test(r.value) ? hostToUnicode(r.value) : null)
          } : null
        ].filter(Boolean)
      });

      const checkResult = h('div', { class: 'cert-check-result', attrs: { 'aria-live': 'polite' } });
      const check = textInput({
        label: t('cert.check.label'),
        placeholder: t('cert.check.placeholder'),
        mono: true,
        hint: t('cert.check.wildcardNote'),
        attrs: { 'data-role': 'cert-check' },
        onInput: debounce((value) => runCheck(value), 150),
        onEnter: (value) => runCheck(value)
      });
      function runCheck(value) {
        clear(checkResult);
        const raw = String(value || '').trim();
        if (!raw) {
          check.setError(null);
          return;
        }
        const host = normalizeHostname(raw);
        if (!host) {
          check.setError(t('cert.check.invalid'));
          return;
        }
        check.setError(null);
        const r = certCovers(cert.hostnames, host);
        checkResult.append(r.covered
          ? Badge(t('cert.check.covered', { name: r.by }), { variant: 'ok', icon: 'check-circle' })
          : Badge(t('cert.check.notCovered', { host }), { variant: 'error', icon: 'x-circle' }));
        checkResult.firstChild.dataset.covered = String(r.covered);
      }

      return h('div', { class: 'stack' },
        domains.length ? h('div', { class: 'cert-domains' },
          h('span', { class: 'field-label' }, t('cert.names.domains')),
          h('span', { class: 'muted text-sm' }, t('cert.names.domainsHint')),
          h('div', { class: 'cluster' }, domains.map((d) => h('a', {
            class: 'badge badge-neutral mono cert-domain-link',
            href: ctx.href('scan', { domain: d })
          }, Icon('target', { size: 12 }), h('span', { class: 'badge-text' }, d))))) : null,
        h('div', { class: 'cert-check' }, check.el, checkResult),
        table);
    }

    /* --- details -------------------------------------------------------- */
    function detailsPanel(cert) {
      const v = validityState(cert);
      const attrs = (obj) => Object.entries(obj || {}).map(([k, val]) => {
        const label = hasString(`cert.attr.${k}`) ? t(`cert.attr.${k}`) : k;
        const shown = k === 'C' || k === 'jurisdictionC' ? `${val} · ${formatRegion(val, val)}` : val;
        return { key: label, value: shown };
      });
      const sha256 = h('span', { class: 'mono', dataset: { fp: 'sha256' } }, t('cert.f.computing'));
      const sha1 = h('span', { class: 'mono', dataset: { fp: 'sha1' } }, t('cert.f.computing'));
      const spki = h('span', { class: 'mono', dataset: { fp: 'spki' } }, t('cert.f.computing'));
      const pin = h('span', { class: 'mono', dataset: { fp: 'pin' } }, t('cert.f.computing'));
      const copyOf = (el) => CopyButton(() => el.textContent, { iconOnly: true });
      computeFingerprints(cert).then((fp) => {
        sha256.textContent = formatFingerprint(fp.sha256);
        sha1.textContent = formatFingerprint(fp.sha1);
      }).catch(() => {
        sha256.textContent = '—';
        sha1.textContent = '—';
      });
      if (cert.spkiDer) {
        computeFingerprints(cert.spkiDer).then((fp) => {
          spki.textContent = fp.sha256;
          pin.textContent = hexToBase64(fp.sha256);
        }).catch(() => {
          spki.textContent = '—';
          pin.textContent = '—';
        });
      } else {
        spki.textContent = '—';
        pin.textContent = '—';
      }
      const weak = isWeakCert(cert);
      const ku = translatedList(cert.keyUsage, 'cert.ku');
      const eku = translatedList(cert.extKeyUsage, 'cert.eku');
      const noServerAuth = !cert.isCA && cert.extKeyUsage.length > 0
        && !cert.extKeyUsage.includes('serverAuth') && !cert.extKeyUsage.includes('anyExtendedKeyUsage');

      const card = (title, iconName, items) => Card({ title, icon: iconName, className: 'cert-detail-card', children: KeyValueList(items) });
      return h('div', { class: 'cert-details' },
        card(t('cert.d.subject'), 'users', [
          { key: t('cert.f.dn'), value: cert.subjectDN || '—', mono: true, copy: true },
          ...attrs(cert.subject)
        ]),
        card(t('cert.d.issuer'), 'git-branch', [
          { key: t('cert.f.dn'), value: cert.issuerDN || '—', mono: true, copy: true },
          ...attrs(cert.issuer)
        ]),
        card(t('cert.d.validity'), 'calendar', [
          [t('cert.f.notBefore'), h('span', { title: cert.notBefore.toISOString() }, formatDateTime(cert.notBefore, { utc: true }))],
          [t('cert.f.notAfter'), h('span', { title: cert.notAfter.toISOString() }, formatDateTime(cert.notAfter, { utc: true }))],
          [t('cert.f.remaining'), ValidityBadge(cert)],
          [t('cert.f.lifetime'), t('cert.validity.lifetime', { count: v.lifetimeDays })]
        ]),
        card(t('cert.d.key'), 'key', [
          [t('cert.f.algorithm'), `${cert.keyAlgorithm}${cert.keyAlgorithmName && cert.keyAlgorithmName !== cert.keyAlgorithm ? ` (${cert.keyAlgorithmName})` : ''}`],
          [t('cert.f.keySize'), cert.keyBits ? h('span', null, t('cert.f.bits', { bits: cert.keyBits }),
            weak && cert.keyBits < 2048 ? Badge(t('cert.f.weakKey'), { variant: 'error', className: 'cert-inline-badge' }) : null) : null],
          cert.curve ? [t('cert.f.curve'), cert.curve] : null,
          cert.rsaExponent ? [t('cert.f.exponent'), String(cert.rsaExponent)] : null,
          [t('cert.f.sigAlg'), h('span', { class: 'mono' }, cert.signatureAlgorithm,
            /sha1|md5/i.test(cert.signatureAlgorithm) ? Badge(t('cert.f.weakKey'), { variant: 'error', className: 'cert-inline-badge' }) : null)]
        ]),
        card(t('cert.d.usage'), 'sliders', [
          [t('cert.f.keyUsage'), ku.length ? ku.join(', ') : null],
          [t('cert.f.extKeyUsage'), eku.length ? h('div', null, eku.join(', '),
            noServerAuth ? h('div', { class: 'cert-note-warn text-sm' }, t('cert.eku.noServerAuth')) : null) : null],
          [t('cert.f.basicConstraints'), cert.isCA
            ? `${t('cert.f.caYes')}${cert.pathLen !== null ? ` · ${t('cert.f.pathLen', { n: cert.pathLen })}` : ''}`
            : t('cert.f.caNo')],
          [t('cert.f.mustStaple'), cert.mustStaple ? t('common.yes') : t('common.no')]
        ]),
        card(t('cert.d.ids'), 'hash', [
          { key: t('cert.f.serial'), value: h('span', { class: 'cert-fp' }, h('span', { class: 'mono' }, formatSerial(cert.serialHex))), copy: cert.serialHex },
          [t('cert.f.version'), `v${cert.version}`],
          { key: t('cert.f.sha256'), value: h('span', { class: 'cert-fp' }, sha256, copyOf(sha256)) },
          { key: t('cert.f.sha1'), value: h('span', { class: 'cert-fp' }, sha1, copyOf(sha1)) },
          { key: t('cert.f.spki'), hint: t('cert.f.spkiHint'), value: h('span', { class: 'cert-fp' }, spki, copyOf(spki)) },
          { key: t('cert.f.pin'), value: h('span', { class: 'cert-fp' }, pin, copyOf(pin)) },
          { key: t('cert.f.ski'), value: cert.subjectKeyId ? h('span', { class: 'cert-fp' }, h('span', { class: 'mono' }, formatFingerprint(cert.subjectKeyId))) : null },
          { key: t('cert.f.aki'), value: cert.authorityKeyId ? h('span', { class: 'cert-fp' }, h('span', { class: 'mono' }, formatFingerprint(cert.authorityKeyId))) : null }
        ]),
        card(t('cert.d.revocation'), 'link', [
          [t('cert.f.ocsp'), linkList(cert.ocspUrls)],
          [t('cert.f.caIssuers'), linkList(cert.caIssuersUrls)],
          [t('cert.f.crl'), linkList(cert.crlUrls)]
        ]),
        card(t('cert.d.transparency'), 'eye', [
          [t('cert.f.scts'), cert.sctCount === null || cert.sctCount === 0
            ? h('span', { class: 'muted' }, t('cert.f.sctNone'))
            : h('div', { class: 'stack-sm' }, h('span', null, t('cert.f.sctCount', { count: cert.sctCount })),
              TruncatedList(cert.scts.map((s) => t('cert.f.sctItem', { log: `${String(s.logId).slice(0, 12)}…`, date: formatDateTime(s.timestamp, { utc: true }) })), { max: 3, mono: false }))],
          [t('cert.f.level'), cert.validationLevel ? t(`cert.level.${cert.validationLevel}`) : null],
          [t('cert.f.policies'), cert.policies.length ? TruncatedList(cert.policies, { max: 4 }) : null],
          cert.isPrecertificate ? [t('cert.f.precert'), t('common.yes')] : null
        ]),
        card(t('cert.d.extensions'), 'layers', [
          ...cert.extensions.map((e) => ({
            key: e.name || e.oid,
            hint: e.name ? e.oid : null,
            value: h('span', { class: 'cluster' }, h('span', { class: 'mono text-sm' }, `${formatNumber(e.length)} B`),
              e.critical ? Badge(t('cert.f.critical'), { variant: 'warn' }) : null)
          })),
          cert.parseErrors && cert.parseErrors.length ? {
            key: t('cert.f.parseErrors'),
            value: h('div', { class: 'stack-sm' }, cert.parseErrors.map((pe) => h('code', { class: 'mono text-sm' }, `${pe.field}${pe.oid ? ` (${pe.oid})` : ''}: ${pe.message}`)))
          } : null
        ]));
    }

    /* --- chain ---------------------------------------------------------- */
    function chainPanel(chain) {
      const alerts = [];
      const add = (variant, message, code) => {
        const a = Alert({ variant, message, compact: true });
        a.dataset.chainIssue = code;
        alerts.push(a);
      };
      // A CT log holds the leaf alone: there is no file to blame, and the served chain is unknown
      // (still no "complete" verdict).
      const fromCt = load.source === 'ct';
      for (const is of chain.issues) {
        switch (is.code) {
          case 'self-signed': add('warn', t('cert.chain.selfSigned'), is.code); break;
          case 'leaf-only':
            if (fromCt) add('info', t('cert.chain.ctLeafOnly'), 'ct-leaf-only');
            else add('warn', t('cert.chain.leafOnly'), is.code);
            break;
          case 'order': add('warn', t('cert.chain.order'), is.code); break;
          case 'unrelated': add('warn', t('cert.chain.unrelated', { count: is.count }), is.code); break;
          case 'root-included': add('info', t('cert.chain.rootIncluded'), is.code); break;
          case 'ends-at': add('info', t('cert.chain.endsAt', { name: certDisplayName(is.cert) }), is.code); break;
          case 'expired': add('error', t('cert.chain.expired', { name: certDisplayName(is.cert) }), is.code); break;
          default: break;
        }
      }
      const serious = chain.issues.some((i) => ['self-signed', 'leaf-only', 'order', 'unrelated', 'expired'].includes(i.code));
      if (!serious) add('ok', t('cert.chain.ok'), 'ok');

      const item = (c, idx) => {
        const role = chain.roles.get(c);
        const next = idx >= 0 ? chain.ordered[idx + 1] : null;
        const keyMatch = next && c.authorityKeyId && next.subjectKeyId && c.authorityKeyId === next.subjectKeyId;
        return h('li', { class: ['cert-chain-item', `cert-chain-${role}`], dataset: { role } },
          h('div', { class: 'cert-chain-node', attrs: { 'aria-hidden': 'true' } }, Icon(role === 'leaf' ? 'certificate' : role === 'root' ? 'shield' : 'git-branch', { size: 16 })),
          h('div', { class: 'cert-chain-body card' },
            h('div', { class: 'cert-chain-head' },
              Badge(t(`cert.role.${role}`), { variant: role === 'leaf' ? 'accent' : role === 'unrelated' ? 'warn' : 'neutral' }),
              h('span', { class: 'cert-chain-cn mono' }, certDisplayName(c)),
              ValidityBadge(c),
              Button({ label: t('cert.chain.show'), size: 'sm', variant: 'ghost', icon: 'eye', onClick: () => showCert(c) })),
            h('div', { class: 'cert-chain-meta text-sm' },
              h('span', null, t('cert.chain.issuedBy', { name: issuerDisplayName(c) })),
              keyMatch ? Badge(t('cert.chain.keyMatch'), { variant: 'ok', icon: 'check' }) : null,
              h('span', { class: 'muted mono' }, `${c.keyAlgorithm}${c.keyBits ? ` ${c.keyBits}` : ''} · ${formatDate(c.notAfter)}`))));
      };
      const list = h('ol', { class: 'cert-chain' },
        chain.ordered.map((c, i) => item(c, i)),
        !chain.complete && chain.missingIssuer ? h('li', { class: 'cert-chain-item cert-chain-missing' },
          h('div', { class: 'cert-chain-node', attrs: { 'aria-hidden': 'true' } }, Icon('help', { size: 16 })),
          h('div', { class: 'cert-chain-body cert-chain-ghost' }, t('cert.chain.missingIssuer', { name: chain.missingIssuer }))) : null);
      const unrelated = chain.unrelated.length
        ? h('ol', { class: 'cert-chain cert-chain-unrelated' }, chain.unrelated.map((c) => item(c, -1))) : null;
      const full = fullchainCerts(chain);
      return h('div', { class: 'stack' },
        h('p', { class: 'muted text-sm' }, t('cert.chain.intro')),
        h('div', { class: 'stack-sm' }, alerts),
        list,
        unrelated,
        h('div', { class: 'cluster' },
          Button({
            label: t('cert.downloadChain'), icon: 'download', dataset: { action: 'download-chain-tab' },
            onClick: () => downloadText(pemFileName(full[0], '-fullchain'), pemBundle(full), 'application/x-pem-file')
          }),
          h('span', { class: 'muted text-sm' }, t('cert.chain.fullchainHint'))));
    }

    /* --- CAA ------------------------------------------------------------ */
    function caaPanel(cert) {
      const key = certKey(cert);
      const infos = caaIssuerInfo(cert.issuer && Object.keys(cert.issuer).length ? cert.issuer : cert.issuerDN);
      const body = h('div', { class: 'stack' });
      const header = h('div', { class: 'stack-sm' },
        h('p', { class: 'muted text-sm' }, t('cert.caa.intro')),
        infos.length
          ? h('div', { class: 'cluster' }, Icon('info', { size: 14 }),
            h('span', { class: 'text-sm' }, t('cert.caa.issuerKnown', { ca: infos.map((i) => i.name).join(', '), ids: infos.flatMap((i) => i.domains).join(', ') })))
          : Alert({ variant: 'info', compact: true, message: t('cert.caa.issuerUnknown', { issuer: issuerDisplayName(cert) }) }),
        ...infos.filter((i) => i.distrusted).map((i) => Alert({ variant: 'error', compact: true, message: t('cert.caa.distrusted', { ca: i.name, year: i.distrusted }) })));
      const runBtn = Button({ label: t('cert.caa.run'), icon: 'play', size: 'sm', dataset: { action: 'caa-run' }, onClick: () => run(true) });
      const panel = h('div', { class: 'stack cert-caa' }, header, h('div', { class: 'cluster' }, runBtn), body);
      const refresh = (entry) => {
        if (!panel.isConnected) return;
        // A re-mount (language switch) joined the old view's task, which its unmount then
        // cancelled: start again under this view's signal instead of leaving the panel blank.
        if (entry.status === 'aborted' && !ctx.signal.aborted) run();
        else show(entry.status === 'aborted' ? null : entry);
      };

      const names = [];
      for (const hn of cert.hostnames) {
        const { base, wildcard } = stripWildcard(hn);
        if (!base || names.some((n) => n.name === base && n.wildcard === wildcard)) continue;
        names.push({ name: base, wildcard });
      }
      const sorted = sortHostnames(names.map((n) => n.name));
      names.sort((a, b) => sorted.indexOf(a.name) - sorted.indexOf(b.name) || Number(a.wildcard) - Number(b.wildcard));

      function show(entry) {
        clear(body);
        runBtn.querySelector('.btn-label').textContent = entry && entry.status !== 'running' ? t('cert.caa.rerun') : t('cert.caa.run');
        runBtn.disabled = !!entry && entry.status === 'running';
        if (!names.length) {
          body.append(EmptyState({ compact: true, icon: 'shield', message: t('cert.caa.noNames') }));
          return;
        }
        if (!entry) return;
        if (entry.status === 'running') {
          entry.watchers.add(refresh);
          body.append(Spinner({ label: t('cert.caa.checking'), showLabel: true }));
          return;
        }
        if (entry.status === 'error') {
          body.append(ErrorBanner(entry.error, { onRetry: () => run(true) }));
          return;
        }
        const denied = entry.rows.filter((r) => r.verdict && r.verdict.allowed === false).length;
        const unknown = entry.rows.filter((r) => !r.verdict || r.verdict.allowed === null).length;
        const restricted = entry.rows.filter((r) => r.verdict && r.verdict.verdict === 'restricted').length;
        let summary;
        if (denied) summary = Alert({ variant: 'error', compact: true, message: t('cert.caa.summaryDenied', { count: denied }) });
        else if (unknown) summary = Alert({ variant: 'info', compact: true, message: t('cert.caa.summaryUnknown') });
        else if (restricted) summary = Alert({ variant: 'warn', compact: true, message: t('cert.caa.summaryRestricted', { count: restricted }) });
        else summary = Alert({ variant: 'ok', compact: true, message: t('cert.caa.summaryOk') });
        summary.dataset.caaSummary = denied ? 'denied' : unknown ? 'unknown' : restricted ? 'restricted' : 'ok';
        body.append(summary);
        if (entry.truncated) body.append(h('p', { class: 'muted text-sm' }, t('cert.caa.truncated', { count: CAA_MAX_NAMES })));
        body.append(DataTable({
          caption: t('cert.tab.caa'),
          rows: entry.rows,
          dense: true,
          rowKey: (r) => `${r.wildcard ? '*.' : ''}${r.name}`,
          export: { filename: 'caa', subject: certDisplayName(cert) },
          columns: [
            {
              key: 'name', label: t('cert.caa.col.name'), mono: true, sortable: true, className: 'cert-caa-name',
              sortValue: (r) => r.name.split('.').reverse().join('.'),
              searchValue: (r) => `${r.wildcard ? '*.' : ''}${r.name}`,
              // On a phone the name may break before a dot, and the record set column moves under it.
              render: (r) => [
                h('span', null, `${r.wildcard ? '*.' : ''}${r.name}`.split('.').flatMap((part, i) => (i ? [h('wbr'), `.${part}`] : [part]))),
                h('div', { class: 'cert-caa-at-inline' }, `${t('cert.caa.col.at')}: `, caaAt(r))
              ]
            },
            {
              key: 'at', label: t('cert.caa.col.at'), mono: true, sortable: true, className: 'cert-caa-at',
              sortValue: (r) => r.foundAt || '',
              exportValue: (r) => r.foundAt || '',
              render: caaAt
            },
            {
              // The verdict before the records it comes from: on a phone it is the column in view.
              key: 'result', label: t('cert.caa.col.result'), sortable: true, wrap: true, className: 'cert-caa-result',
              sortValue: (r) => (r.verdict ? { denied: 0, unknown: 1, restricted: 2, allowed: 3 }[r.verdict.verdict] : -1),
              exportValue: (r) => {
                if (!r.verdict) return 'error';
                const extra = [...r.verdict.restrictions.map(caaRestrictionText), ...r.verdict.unusable.map((u) => `${u.raw} (${u.problem})`)];
                return extra.length ? `${r.verdict.reason}: ${extra.join(' | ')}` : r.verdict.reason;
              },
              render: (r) => (r.verdict ? caaVerdictCell(r.verdict, r.wildcard)
                : Badge(t('cert.caa.error'), { variant: 'error', icon: 'x-circle', title: r.error || '' }))
            },
            {
              // RFC 8657 values (an accounturi) make records long: they wrap.
              key: 'records', label: t('cert.caa.col.records'), mono: true, wrap: true, className: 'cert-caa-records',
              searchValue: (r) => r.records.join(' '),
              exportValue: (r) => r.records.join(' | '),
              render: (r) => (r.records.length ? TruncatedList(r.records, { max: 4 }) : null)
            }
          ]
        }).el);
      }

      /** Where the name's CAA record set was found: its owner, "none", or the lookup error. */
      function caaAt(r) {
        return r.error ? Badge(t('cert.caa.error'), { variant: 'error', title: r.error })
          : r.foundAt || h('span', { class: 'muted' }, t('cert.caa.none'));
      }

      /**
       * The Result cell: the verdict badge and reason; for a restricted CA every allowed
       * combination (RFC 8657) and what it means for the next renewal; for a CA whose values
       * are unusable, each value and why.
       */
      function caaVerdictCell(v, wildcard) {
        const spec = {
          allowed: ['cert.caa.allowed', 'ok', 'check-circle'], restricted: ['cert.caa.restricted', 'warn', 'shield'],
          denied: ['cert.caa.denied', 'error', 'x-circle'], unknown: ['cert.caa.unknown', 'neutral', 'help']
        }[v.verdict] || ['cert.caa.unknown', 'neutral', 'help'];
        const combo = (x) => [
          Array.isArray(x.methods) ? t('cert.caa.onlyMethods', { methods: x.methods.join(', ') }) : t('cert.caa.anyMethod'),
          x.accountUri ? t('cert.caa.onlyAccount', { account: x.accountUri }) : null
        ].filter(Boolean).join(' · ');
        const notes = v.verdict === 'restricted' ? caaRestrictionNotes(v.restrictions, { wildcard }) : [];
        const restrictions = v.restrictions || [];
        const unusable = v.unusable || [];
        return h('div', { class: 'cert-caa-verdict', dataset: { caaVerdict: v.verdict } },
          Badge(t(spec[0]), { variant: spec[1], icon: spec[2] }),
          h('span', { class: 'muted text-sm' }, t(v.reasonKey)),
          restrictions.length ? h('ul', { class: 'cert-caa-list' }, restrictions.map((x) => h('li', { class: 'mono text-xs' }, combo(x)))) : null,
          notes.length ? h('ul', { class: 'cert-caa-notes' }, notes.map((n) => h('li', { class: 'text-sm', dataset: { note: n.code } }, t(n.key, n.params)))) : null,
          unusable.length ? h('ul', { class: 'cert-caa-list cert-caa-unusable' }, unusable.map((u) => h('li', null,
            h('span', { class: 'mono text-xs' }, u.raw), ' ', h('span', { class: 'text-sm' }, `— ${t(`health.caa.problem.${u.problem}`)}`)))) : null);
      }

      function run(force = false) {
        if (!names.length) {
          show(null);
          return;
        }
        const cached = caaCache.get(key);
        if (cached && (cached.status === 'running' || (!force && cached.status === 'done'))) {
          show(cached);
          return;
        }
        // Opening the tab offline sends nothing and says so here; only a click warns (a toast).
        if (!ctx.requireOnline({ quiet: !force })) {
          if (!force) {
            show(null);
            body.append(offlineNote('cert.caa.offline', 'cert.caa.run'));
          }
          return;
        }
        const issuer = cert.issuer && Object.keys(cert.issuer).length ? cert.issuer : cert.issuerDN;
        const list = names.slice(0, CAA_MAX_NAMES);
        show(startTask(caaCache, key, async () => {
          const dns = await ctx.getDns();
          const lookups = new Map();
          const lookup = (name) => {
            if (!lookups.has(name)) lookups.set(name, findCaa(name, { dns, signal: ctx.signal }));
            return lookups.get(name);
          };
          const rows = await Promise.all(list.map(async ({ name, wildcard }) => {
            try {
              const found = await lookup(name);
              if (found.error) return { name, wildcard, foundAt: null, records: [], verdict: null, error: found.error };
              return {
                name,
                wildcard,
                foundAt: found.foundAt,
                records: found.records.map((rr) => rr.text || `${rr.data.flags} ${rr.data.tag} "${rr.data.value}"`),
                verdict: checkCaaAllows(found.parsed, issuer, { wildcard }),
                error: null
              };
            } catch (err) {
              if (errorKind(err) === 'abort') throw err;
              return { name, wildcard, foundAt: null, records: [], verdict: null, error: String((err && err.message) || err) };
            }
          }));
          return { rows, truncated: names.length > CAA_MAX_NAMES };
        }));
      }

      show(caaCache.get(key) || null);
      // Automatic check: a few DoH queries, cached per certificate.
      if (!caaCache.has(key)) run();
      return panel;
    }

    /** Why a panel's automatic check did not run: the browser is offline (its button runs it later). */
    function offlineNote(key, buttonKey) {
      const note = Alert({ variant: 'info', compact: true, icon: 'cloud-off', message: t(key, { button: t(buttonKey) }) });
      note.dataset.offline = 'auto';
      return note;
    }

    /* --- DANE / TLSA (sends nothing until its button is clicked) ----------------- */
    function danePanel(shown) {
      const leaf = result.leaf;
      const key = certKey(leaf);
      if (!daneHolders.has(key)) daneHolders.set(key, {});
      disposeDane();
      const panel = DanePanel({
        certs: { leaf, chain: result.certificates },
        ctx,
        holder: daneHolders.get(key),
        subject: certDisplayName(leaf)
      });
      daneUi = panel;
      if (shown === leaf) return panel.el;
      return h('div', { class: 'stack' },
        Alert({ variant: 'info', compact: true, message: t('cert.dane.leaf', { name: certDisplayName(leaf) }) }), panel.el);
    }

    /* --- Certificate Transparency ----------------------------------------- */
    function ctPanel(cert) {
      const key = certKey(cert);
      const isPublic = caaIssuerInfo(cert.issuer && Object.keys(cert.issuer).length ? cert.issuer : cert.issuerDN).length > 0;
      const body = h('div', { class: 'stack' });
      const runBtn = Button({ label: t('cert.ct.run'), icon: 'search', size: 'sm', dataset: { action: 'ct-run' }, onClick: () => run(true) });
      const serialUrl = `${CRTSH_SERIAL_URL}${encodeURIComponent(cert.serialHex)}`;
      const domain = baseDomainsFromNames(cert.hostnames)[0];
      const panel = h('div', { class: 'stack cert-ct' },
        h('p', { class: 'muted text-sm' }, t('cert.ct.intro')),
        h('div', { class: 'cluster' }, runBtn,
          ExternalLink(serialUrl, t('cert.ct.openSerial')),
          domain ? ExternalLink(`https://crt.sh/?q=${encodeURIComponent(domain)}`, t('cert.ct.openDomain', { domain })) : null),
        body);
      const refresh = (entry) => {
        if (!panel.isConnected) return;
        if (entry.status === 'aborted' && !ctx.signal.aborted) run(); // see caaPanel
        else show(entry.status === 'aborted' ? null : entry);
      };

      function show(entry) {
        clear(body);
        runBtn.querySelector('.btn-label').textContent = entry && entry.status !== 'running' ? t('cert.ct.rerun') : t('cert.ct.run');
        runBtn.disabled = !!entry && entry.status === 'running';
        if (!entry) {
          if (!isPublic) body.append(Alert({ variant: 'info', compact: true, message: t('cert.ct.manual') }));
          return;
        }
        if (entry.status === 'running') {
          entry.watchers.add(refresh);
          body.append(Spinner({ label: t('cert.ct.searching'), showLabel: true }));
          return;
        }
        if (entry.status === 'error') {
          body.append(ErrorBanner(entry.error, { title: t('cert.ct.failed'), onRetry: () => run(true) }));
          return;
        }
        const note = entry.rows.length
          ? Alert({ variant: 'ok', compact: true, message: t('cert.ct.found', { count: entry.rows.length }) })
          : Alert({ variant: 'info', compact: true, message: t('cert.ct.notFound') });
        note.dataset.ctResult = entry.rows.length ? 'found' : 'none';
        body.append(note);
        if (entry.ignored) body.append(h('p', { class: 'muted text-sm' }, t('cert.ct.otherIssuers', { count: entry.ignored })));
        if (entry.rows.length) {
          body.append(DataTable({
            caption: t('cert.tab.ct'),
            rows: entry.rows,
            dense: true,
            rowKey: (r) => String(r.id),
            columns: [
              { key: 'id', label: t('cert.ct.col.id'), sortable: true, render: (r) => ExternalLink(`https://crt.sh/?id=${encodeURIComponent(r.id)}`, String(r.id), { className: 'mono' }) },
              { key: 'issuer', label: t('cert.ct.col.issuer'), wrap: true, sortable: true },
              { key: 'notBefore', label: t('cert.ct.col.from'), sortable: true, render: (r) => formatDateTime(r.notBefore, { utc: true }) },
              { key: 'notAfter', label: t('cert.ct.col.to'), sortable: true, render: (r) => formatDateTime(r.notAfter, { utc: true }) }
            ]
          }).el);
        }
      }

      function run(force = false) {
        const cached = ctCache.get(key);
        if (cached && (cached.status === 'running' || (!force && cached.status === 'done'))) {
          show(cached);
          return;
        }
        if (!ctx.requireOnline({ quiet: !force })) { // see caaPanel
          if (!force) {
            show(null);
            body.append(offlineNote('cert.ct.offline', 'cert.ct.run'));
          }
          return;
        }
        show(startTask(ctCache, key, async () => {
          const json = await retry(() => fetchJson(`${serialUrl}&output=json`, {
            signal: ctx.signal, timeoutMs: 60000, headers: { accept: 'application/json' }
          }), { retries: 1, baseDelayMs: 4000, maxDelayMs: 8000, signal: ctx.signal });
          return crtshSerialRows(json, cert);
        }));
      }

      show(ctCache.get(key) || null);
      // Public CAs log every certificate; private / test CAs never do — only search on demand then.
      if (isPublic && !ctCache.has(key)) run();
      return panel;
    }

    /* --- PEM & OpenSSL ---------------------------------------------------- */
    function pemPanel(cert, chain) {
      const spkiOut = h('code', { class: 'mono cert-spki-value' }, t('cert.f.computing'));
      if (cert.spkiDer) {
        computeFingerprints(cert.spkiDer).then((fp) => { spkiOut.textContent = fp.sha256; }).catch(() => { spkiOut.textContent = '—'; });
      } else {
        spkiOut.textContent = '—';
      }
      const full = fullchainCerts(chain);
      return h('div', { class: 'stack' },
        CodeBlock(pemEncode(cert.der), { label: t('cert.pem.this'), maxHeight: '320px' }),
        full.length > 1 && cert === chain.ordered[0] ? Disclosure({
          summary: t('cert.pem.fullchain'),
          children: CodeBlock(pemBundle(full), { label: 'fullchain.pem', maxHeight: '320px' })
        }) : null,
        Card({
          title: t('cert.pem.keyMatchTitle'),
          icon: 'key',
          children: h('div', { class: 'stack-sm' },
            h('p', { class: 'text-sm' }, t('cert.pem.keyMatchBody')),
            CodeBlock('openssl pkey -in private.key -pubout -outform DER | openssl dgst -sha256', { label: 'OpenSSL' }),
            h('div', { class: 'cert-spki' }, h('span', { class: 'field-label' }, t('cert.pem.spki')), spkiOut, CopyButton(() => spkiOut.textContent, { iconOnly: true })))
        }),
        Card({
          title: t('cert.pem.inspectTitle'),
          icon: 'terminal',
          children: h('div', { class: 'stack-sm' },
            CodeBlock('openssl x509 -in certificate.pem -noout -text', { label: 'x509' }),
            CodeBlock(sClientCommand(cert.hostnames), { label: 's_client', wrap: true }))
        }));
    }
  }

  render();

  // Another view (SSL Targets) may replace or clear the shared certificate.
  const off = state.subscribe(({ key, value }) => {
    if (key !== 'session' || !value || value.name !== CURRENT_CERT) return;
    const next = normalizeCertLoad(value.value);
    if (next === load) return;
    load = next;
    render();
  });
  teardown = () => {
    off();
    disposeDane();
  };
  active = {
    result() {
      if (!load || !load.result.leaf) return null;
      return { subject: certTarget(load), at: load.loadedAt, rerun: !!ctHostOf(load) };
    },
    // A certificate from Certificate Transparency: look its host name up again in the "No file?"
    // block (opened, so its progress shows); the newest certificate loads over this one. The note
    // goes only then (setLoad): a lookup that fails or finds nothing leaves the kept certificate,
    // still dated.
    rerun() {
      const host = ctHostOf(load);
      if (!host || !alternatives) return;
      const more = loaderHost.querySelector('details');
      if (more) more.open = true;
      alternatives.search(host);
    }
  };
}

/** Stop listening for session changes. */
export function unmount() {
  if (teardown) teardown();
  teardown = null;
  active = null;
}

/**
 * The loaded certificate (it stays in `state.session.currentCert`, so the shell keeps only the
 * fact, lib/session.js), or null. `rerun` only for a certificate from Certificate Transparency.
 * @returns {{ subject: string|null, at: Date, rerun: boolean }|null}
 */
export function result() {
  return active ? active.result() : null;
}

/** "Run again" of the kept-result note: look the host name of a certificate from CT up again. */
export function rerun() {
  if (active) active.rerun();
}

export default { id, titleKey, icon, mount, unmount, result, rerun };
