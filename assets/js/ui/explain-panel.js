/**
 * ui/explain-panel.js — DNS Lookup › "Explain" (ROADMAP P1.5): the records of the looked-up name
 * in plain words.
 *
 * - Loaded on the first click of the lookup summary's "Explain" button (views/lookup.js); that click
 *   is the go-ahead: it asks the shared DoH client (the lookup's resolver, or its failover chain)
 *   for what the explanations need that the lookup does not already have, and only while online.
 * - SPF (lib/spfexplain.js over lib/health.js spfLookupCount): the record, Domain Health's findings
 *   about it, the lookup meter, TXT strings that join badly, every term in the order receivers read
 *   them — what it does, the result it gives, its cost, an include's own policy one click away —,
 *   "Does an address pass?" (lib/health.js spfCheckHost: RFC 7208 check_host() with the policy
 *   expanded for that address, an optional sender and HELO for their macros) and a flatten preview.
 * - DMARC and CAA tag by tag (lib/records.js explainDmarc / explainCaa), where the record that
 *   applies was found (the organizational domain's DMARC, a parent's CAA) and what it means here.
 * - HTTPS / SVCB parameter by parameter (lib/records.js explainSvcb): protocols, port, the address
 *   hints against the real A / AAAA records, the Encrypted Client Hello configuration decoded.
 * - A section whose question got no answer says why ("n/a" wording of lib/sourcestatus.js) with a
 *   Retry that asks again without the cache; a new lookup or leaving the view stops the panel.
 * - Every value from the network (records, names, addresses) is rendered as text.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import { Alert, Badge, Button, CodeBlock, CopyButton, Disclosure, SeverityIcon, Spinner, announce, textInput } from './components.js';
import { registerStrings, formatNumber, formatDateTime } from '../i18n.js';
import { HEALTH_I18N, spfCheckHost, SPF_EVAL_RESULTS, SPF_UNKNOWN_REASONS, SPF_PERMERROR_REASONS, SPF_MACRO_NEEDS } from '../lib/health.js';
import { explainName, DMARC_MEANINGS, DMARC_ISSUES, DMARC_FO, CAA_KINDS, ECH_ERRORS, SVCB_NOTES, HINT_STATUSES } from '../lib/records.js';
import { SPF_STEP_KINDS, SPF_STEP_STATES, SPF_POLICY_STATES, SPF_FLATTEN_NOTES, SPF_UDP_SAFE_LENGTH } from '../lib/spfexplain.js';
import { normalizeIP } from '../lib/ip.js';
import { getResolver } from '../lib/resolvers.js';
import { mergeSignals } from '../lib/util.js';
import { dohStatus, sourceStatus } from '../lib/sourcestatus.js';
import { RetryButton, statusText } from './source-status.js';

registerStrings('en', HEALTH_I18N.en);
registerStrings('tr', HEALTH_I18N.tr);

registerStrings('en', {
  'xpl.title': 'Explain records',
  'xpl.intro': 'What the records of {name} say, term by term and tag by tag. SPF is followed through every include, as a receiving mail server does (RFC 7208); the questions go to the lookup’s resolver.',
  'xpl.rerun': 'Explain again',
  'xpl.running': 'Reading the records…',
  'xpl.none': 'Nothing to explain at {name}: no SPF, DMARC, CAA or HTTPS record applies to it.',
  'xpl.foot': { one: 'Asked {count} more question through {resolver}; the lookup’s own answers were reused. {time}', other: 'Asked {count} more questions through {resolver}; the lookup’s own answers were reused. {time}' },
  'xpl.footNone': 'Nothing new was asked: the lookup’s answers and the cache had everything. {time}',
  'xpl.resolverAuto': 'the lookup’s resolver chain',
  'xpl.failed': 'Could not be read: {reason}',
  'xpl.notSet': 'not set',
  'xpl.critical': 'critical',
  'xpl.dur.d': '{n} d',
  'xpl.dur.h': '{n} h',
  'xpl.dur.m': '{n} min',
  'xpl.dur.s': '{n} s',

  'xpl.res.pass': 'Pass',
  'xpl.res.fail': 'Fail',
  'xpl.res.softfail': 'Softfail',
  'xpl.res.neutral': 'Neutral',
  'xpl.res.none': 'None',
  'xpl.res.permerror': 'Permerror',
  'xpl.res.temperror': 'Temperror',
  'xpl.res.unknown': 'Cannot tell',
  'xpl.res.noMatch': 'counts as no match',
  'xpl.res.noMatchTitle': 'Inside an include only a pass counts: this result means the include does not match.',

  'xpl.spf.title': 'SPF: who may send mail as {name}',
  'xpl.spf.none': '{name} has no SPF record, so receivers cannot tell its servers from forgers (SPF result: none).',
  'xpl.spf.type99': 'The lookup also found a record of the SPF type (99): that type is obsolete and no receiver reads it (RFC 7208 §3.1). Only the TXT record counts.',
  'xpl.spf.meter': 'DNS lookups: {count} of {limit}',
  'xpl.spf.meterTitle': 'RFC 7208 §4.6.4: include, a, mx, ptr, exists and redirect each cost one lookup, through every include. Past {limit}, receivers stop with a permanent error (permerror).',
  'xpl.spf.voids': 'Lookups that find nothing: {count} of {limit}',
  'xpl.spf.size': { one: '{length} characters in {count} string', other: '{length} characters in {count} strings' },
  'xpl.spf.branches': 'Costliest: {list}',
  'xpl.spf.findings': 'Findings',
  'xpl.spf.join': 'Strings {after} and {next} join without a space, so receivers read “{joined}”. End string {after} with a space, or start string {next} with one.',
  'xpl.spf.steps': 'Term by term, in the order receivers read them',
  'xpl.spf.policyOf': 'The policy of {domain}',
  'xpl.spf.onlyPass': 'Inside an include only a pass counts: any other result here means “no match”, and the policy that included it goes on with its next term.',
  'xpl.spf.cost': { one: '{count} lookup', other: '{count} lookups' },
  'xpl.spf.costInside': { one: '{count} lookup inside', other: '{count} lookups inside' },
  'xpl.spf.ignored': 'Never read, because they come after all: {terms}',
  'xpl.spf.redirectIgnored': 'The record has an all, so receivers never reach redirect={target}.',
  'xpl.spf.implicitNeutral': 'No all and no redirect: a sender no term lists gets neutral.',
  'xpl.spf.exp': 'exp={target}: receivers may show the text published there to a sender they fail.',
  'xpl.spf.modifier': 'Unknown modifier {name}={value}: receivers ignore it.',
  'xpl.spf.cidr4': 'each widened to its /{prefix} network',
  'xpl.spf.cidr6': 'IPv6 widened to /{prefix}',
  'xpl.spf.now': 'now: {list}',
  'xpl.spf.hosts': 'mail servers: {list}',
  'xpl.spf.hostBits': '{term} has host bits set: it covers the whole {range}.',
  'xpl.spf.kind.ip4': 'Mail from {range} matches.',
  'xpl.spf.kind.ip4-range': 'Mail from {first} to {last} ({size} addresses) matches.',
  'xpl.spf.kind.ip6': 'Mail from {range} matches.',
  'xpl.spf.kind.ip6-range': 'Mail from any address in {range} matches.',
  'xpl.spf.kind.a': 'Mail from the addresses of {host} matches.',
  'xpl.spf.kind.mx': 'Mail from the mail servers (MX) of {host} matches.',
  'xpl.spf.kind.include': 'Asks the policy of {target}: a sender it passes matches here.',
  'xpl.spf.kind.redirect': 'No all here: the policy of {target} decides for every sender still left.',
  'xpl.spf.kind.exists': 'Matches when the name {target} exists (has an A record).',
  'xpl.spf.kind.ptr': 'Matches when the sender’s reverse DNS name, confirmed forward, is {target} or a name under it. Slow and deprecated (RFC 7208 §5.5).',
  'xpl.spf.kind.all': 'Every sender that gets this far matches.',
  'xpl.spf.state.void': 'Finds nothing at {target} (a void lookup: receivers allow two).',
  'xpl.spf.state.macro': 'Built from {needs}: not known until a message arrives — try the check below.',
  'xpl.spf.state.skipped': 'Not asked: this page’s query cap for one policy was reached.',
  'xpl.spf.state.dns-error': 'Got no answer here ({detail}).',
  'xpl.spf.state.no-record': '{target} publishes no SPF record: receivers stop with a permanent error (permerror).',
  'xpl.spf.state.multiple-records': '{target} publishes several SPF records: receivers stop with a permanent error (permerror).',
  'xpl.spf.state.loop': 'Leads back to a policy already on the way (a loop): permerror.',
  'xpl.spf.state.depth': 'Includes nested too deep: not followed.',
  'xpl.spf.state.too-many-mx': '{target} has more than 10 MX hosts: permerror.',
  'xpl.spf.state.ok': 'Read.',
  'xpl.spf.policy.ok': 'Read.',
  'xpl.spf.policy.no-record': '{domain} publishes no SPF record.',
  'xpl.spf.policy.multiple-records': '{domain} publishes more than one SPF record.',
  'xpl.spf.policy.dns-error': 'The SPF record of {domain} could not be read here ({detail}).',
  'xpl.spf.need.domain': 'the domain',
  'xpl.spf.need.ip': 'the sending server’s address',
  'xpl.spf.need.sender': 'the sender’s address (MAIL FROM)',
  'xpl.spf.need.helo': 'the HELO name',
  'xpl.spf.need.ptr': 'the address’s reverse name (never expanded here)',
  'xpl.spf.need.exp': 'explanation text only',

  'xpl.check.title': 'Does an address pass?',
  'xpl.check.intro': 'RFC 7208 check_host(): the policy expanded for this address — its %{i} macros asked, ptr checked — then read term by term as a receiver does.',
  'xpl.check.ip': 'Sending server’s IP address',
  'xpl.check.run': 'Check',
  'xpl.check.more': 'Sender and HELO (only for macros)',
  'xpl.check.sender': 'Sender address (MAIL FROM)',
  'xpl.check.senderHint': 'Fills in %{s}, %{l} and %{o}. Optional.',
  'xpl.check.helo': 'HELO name',
  'xpl.check.heloHint': 'Fills in %{h}. Optional.',
  'xpl.check.invalid': 'Enter an IPv4 or IPv6 address (e.g. 192.0.2.10).',
  'xpl.check.running': 'Checking {ip}…',
  'xpl.check.verdict.pass': '{ip} may send mail as {domain}: {term} in the policy of {holder} lets it.',
  'xpl.check.verdict.fail': '{ip} may not send mail as {domain}: {term} in the policy of {holder} fails it.',
  'xpl.check.verdict.softfail': '{ip} is not listed for {domain}: {term} in the policy of {holder} gives softfail (usually accepted, but marked).',
  'xpl.check.verdict.neutral': '{ip} gets neutral from {domain}: {term} in the policy of {holder} makes no statement about it.',
  'xpl.check.verdict.neutralNone': 'No term of {domain} lists {ip}, and the policy has no all: neutral.',
  'xpl.check.verdict.none': '{domain} has no SPF record: none.',
  'xpl.check.verdict.permerror': 'Receivers cannot evaluate the policy of {domain} for {ip}: a permanent error (permerror), because of {reason}.',
  'xpl.check.verdict.temperror': 'A temporary error (temperror) for {ip}.',
  'xpl.check.verdict.unknown': 'This page cannot tell for {ip}: {reason} ({term} in the policy of {holder}).',
  'xpl.check.via': 'Matched through {host} ({address}).',
  'xpl.check.path': 'Reached through: {path}',
  'xpl.check.missing': 'For a full answer, fill in {needs} under “Sender and HELO”.',
  'xpl.check.foot': 'Expanded for {ip} through {resolver} at {time}. A receiver asks its own resolver: a lookup that failed here may not fail there.',
  'xpl.check.perm.syntax': 'a syntax error in a record',
  'xpl.check.perm.multiple-records': 'more than one SPF record',
  'xpl.check.perm.no-record': 'an include or redirect to a domain without SPF',
  'xpl.check.perm.loop': 'an include loop',
  'xpl.check.perm.depth': 'includes nested too deep',
  'xpl.check.perm.too-many-mx': 'an mx term with more than 10 hosts',
  'xpl.check.perm.lookup-limit': 'more than 10 DNS lookups before the address is reached',
  'xpl.check.perm.void-limit': 'more than 2 lookups that find nothing',
  'xpl.check.unknown.macro': 'a macro needs what only a real message carries',
  'xpl.check.unknown.ptr': 'a ptr term needs the address’s reverse name',
  'xpl.check.unknown.lookup-failed': 'a lookup failed here',
  'xpl.check.unknown.skipped': 'this page’s query cap stopped a lookup',

  'xpl.flat.title': 'Flatten preview',
  'xpl.flat.intro': 'The same policy with include, a and mx replaced by the addresses they stand for today: what a flattened record would look like, for a policy over the lookup limit.',
  'xpl.flat.terms': { one: '{count} address term', other: '{count} address terms' },
  'xpl.flat.length': { one: '{count} character', other: '{count} characters' },
  'xpl.flat.strings': { one: '{count} TXT string', other: '{count} TXT strings' },
  'xpl.flat.lookups': { one: '{count} lookup left', other: '{count} lookups left' },
  'xpl.flat.tooLong': 'Longer than {max} characters: the DNS answer may not fit one UDP packet (RFC 7208 §3.4), and some receivers then fail it.',
  'xpl.flat.split': 'Over 255 characters: it must be split into {count} strings — check that your DNS host does that, at spaces.',
  'xpl.flat.refresh': 'Providers change their addresses without notice: a flattened record must be updated whenever they do, or their mail starts to fail. Keep the include for any provider you do not track.',
  'xpl.flat.note.sender': 'Kept as it is: {term} depends on the sender.',
  'xpl.flat.note.failed': 'Kept as it is: {term} could not be read here.',
  'xpl.flat.note.kept-include': 'Kept as an include: the policy behind {term} has terms that depend on the sender or could not be read.',
  'xpl.flat.note.exceptions': 'Not exact: {term} in the policy of {holder} makes an exception that a flat list of passes cannot express.',
  'xpl.flat.note.passes-all': 'Not exact: the policy of {holder} passes everyone ({term}), which ends the record.',

  'xpl.dmarc.title': 'DMARC: what receivers do with mail that fails',
  'xpl.dmarc.at': 'Published at _dmarc.{domain}.',
  'xpl.dmarc.inherited': 'No record at _dmarc.{name}: the organizational domain’s record at _dmarc.{domain} applies, with its subdomain policy (RFC 7489 §6.6.3).',
  'xpl.dmarc.none': 'No DMARC record applies to {name}: receivers do not act on SPF or DKIM failures, and nobody gets reports.',
  'xpl.dmarc.multiple': '{count} DMARC records at _dmarc.{domain}: receivers ignore DMARC until exactly one is left.',
  'xpl.dmarc.applies.none': 'Mail from {name} that fails DMARC is delivered as usual: the policy only asks for reports (monitoring).',
  'xpl.dmarc.applies.quarantine': 'Mail from {name} that fails DMARC is treated as suspicious — usually the spam folder.',
  'xpl.dmarc.applies.reject': 'Mail from {name} that fails DMARC is rejected.',
  'xpl.dmarc.pctNote': 'Only {pct}% of it; the rest gets {lower}.',
  'xpl.dmarc.testNote': 'Test mode (t=y): receivers apply {lower} instead.',
  'xpl.dmarc.external': 'another domain: {domain} must allow these reports with a TXT record at {record} (RFC 7489 §7.1)',
  'xpl.dmarc.m.v': 'This is a DMARC record (version 1).',
  'xpl.dmarc.m.p.none': 'Policy: do nothing with failing mail, only report it (monitoring).',
  'xpl.dmarc.m.p.quarantine': 'Policy: treat failing mail as suspicious — usually the spam folder.',
  'xpl.dmarc.m.p.reject': 'Policy: reject failing mail during delivery.',
  'xpl.dmarc.m.sp.none': 'Subdomains: only report failing mail.',
  'xpl.dmarc.m.sp.quarantine': 'Subdomains: treat failing mail as suspicious.',
  'xpl.dmarc.m.sp.reject': 'Subdomains: reject failing mail.',
  'xpl.dmarc.m.sp.default': 'Subdomains get the main policy ({policy}).',
  'xpl.dmarc.m.np.none': 'Subdomains that do not exist: only report failing mail.',
  'xpl.dmarc.m.np.quarantine': 'Subdomains that do not exist: treat failing mail as suspicious.',
  'xpl.dmarc.m.np.reject': 'Subdomains that do not exist: reject failing mail.',
  'xpl.dmarc.m.pct': '{pct}% of failing mail gets the policy; the other {rest}% gets {lower}.',
  'xpl.dmarc.m.pct.full': 'All failing mail gets the policy.',
  'xpl.dmarc.m.pct.default': 'All failing mail gets the policy (100%).',
  'xpl.dmarc.m.t.y': 'Test mode: receivers apply the next lower policy ({lower}).',
  'xpl.dmarc.m.t.n': 'Not in test mode.',
  'xpl.dmarc.m.rua': 'Aggregate reports (a daily summary) go to these addresses.',
  'xpl.dmarc.m.ruf': 'Failure reports (one per message) go to these addresses; few receivers still send them.',
  'xpl.dmarc.m.adkim.r': 'DKIM alignment relaxed: the signing domain may be the From domain or another name of its organizational domain.',
  'xpl.dmarc.m.adkim.s': 'DKIM alignment strict: the signing domain must be exactly the From domain.',
  'xpl.dmarc.m.adkim.default': 'DKIM alignment relaxed (the default).',
  'xpl.dmarc.m.aspf.r': 'SPF alignment relaxed: the envelope sender (MAIL FROM) domain may be the From domain or another name of its organizational domain.',
  'xpl.dmarc.m.aspf.s': 'SPF alignment strict: the envelope sender (MAIL FROM) domain must be exactly the From domain.',
  'xpl.dmarc.m.aspf.default': 'SPF alignment relaxed (the default).',
  'xpl.dmarc.m.fo': 'Failure reports are asked for when: {options}.',
  'xpl.dmarc.m.rf': 'Failure report format: {format}.',
  'xpl.dmarc.m.ri': 'Aggregate reports every {time} (most receivers send them daily anyway).',
  'xpl.dmarc.m.psd.y': 'The record of a public suffix domain (DMARCbis).',
  'xpl.dmarc.m.psd.n': 'Not a public suffix domain (DMARCbis).',
  'xpl.dmarc.m.psd.u': 'Whether this is a public suffix domain is not said (DMARCbis).',
  'xpl.dmarc.m.invalid': 'Not a valid value: receivers ignore it.',
  'xpl.dmarc.m.unknown': 'Unknown tag: receivers ignore it.',
  'xpl.dmarc.fo.0': 'SPF and DKIM both fail to align (the default)',
  'xpl.dmarc.fo.1': 'either SPF or DKIM fails to align',
  'xpl.dmarc.fo.d': 'the DKIM signature fails',
  'xpl.dmarc.fo.s': 'SPF fails',
  'xpl.dmarc.issue.missing-p': 'No p= tag: receivers ignore the record.',
  'xpl.dmarc.issue.invalid-p': '{token} is not a policy (none, quarantine or reject): receivers ignore the record.',
  'xpl.dmarc.issue.invalid-sp': '{token} is not a policy: subdomains get the main policy.',
  'xpl.dmarc.issue.invalid-np': '{token} is not a policy: subdomains that do not exist get the subdomain policy.',
  'xpl.dmarc.issue.invalid-pct': '{token} is not a percentage from 0 to 100.',
  'xpl.dmarc.issue.invalid-adkim': '{token} is not r or s.',
  'xpl.dmarc.issue.invalid-aspf': '{token} is not r or s.',
  'xpl.dmarc.issue.duplicate-tag': 'A tag appears twice ({token}): receivers use the first.',
  'xpl.dmarc.issue.unknown-tag': 'Unknown tag {token}: ignored.',
  'xpl.dmarc.issue.invalid-rua': 'Not a valid report address: {token}.',
  'xpl.dmarc.issue.invalid-ruf': 'Not a valid report address: {token}.',
  'xpl.dmarc.issue.invalid-ri': '{token} is not a number of seconds: the default (one day) is used.',
  'xpl.dmarc.issue.invalid-fo': '{token} is not a list of 0, 1, d and s: the default is used.',
  'xpl.dmarc.issue.policy-none': 'Monitoring only ({token}): failing mail is still delivered. Move to quarantine, then reject, once the reports show every real sender passes.',
  'xpl.dmarc.issue.sp-none': 'Subdomains are not protected ({token}): spoofed mail from them is delivered.',
  'xpl.dmarc.issue.pct-partial': 'The policy covers only part of the failing mail ({token}).',
  'xpl.dmarc.issue.testing': 'Test mode ({token}): receivers apply a lower policy.',
  'xpl.dmarc.issue.no-rua': 'No aggregate reports (rua): nobody sees who sends mail as this domain.',
  'xpl.dmarc.issue.multiple': 'More than one DMARC record: receivers ignore DMARC.',

  'xpl.caa.title': 'CAA: who may issue certificates for {name}',
  'xpl.caa.at': 'Published at {domain}.',
  'xpl.caa.inherited': 'No CAA at {name}: the set of {domain} applies (CAA is looked up the tree, RFC 8659 §3).',
  'xpl.caa.none': 'No CAA record at {name} or above it: any certificate authority may issue.',
  'xpl.caa.sum.issuers': 'May issue: {list}. Every other CA must refuse.',
  'xpl.caa.sum.denyAll': 'No CA may issue: no issue value authorizes anyone.',
  'xpl.caa.sum.blocked': 'No CA may issue: a critical property no CA knows blocks issuance (RFC 8659 §4.1).',
  'xpl.caa.sum.anyone': 'No issue property: any CA may issue.',
  'xpl.caa.sum.wildSame': 'Wildcard certificates: the same CAs (there is no issuewild).',
  'xpl.caa.sum.wildList': 'Wildcard certificates: only {list} (issuewild overrides issue for them).',
  'xpl.caa.sum.wildDeny': 'Wildcard certificates: no CA (issuewild authorizes nobody).',
  'xpl.caa.kind.issue': '{ca} may issue certificates.',
  'xpl.caa.kind.issuewild': '{ca} may issue wildcard certificates.',
  'xpl.caa.kind.iodef': 'A CA that refuses a request because of CAA may report it to {value}.',
  'xpl.caa.kind.issuemail': '{ca} may issue S/MIME (email) certificates (RFC 9495).',
  'xpl.caa.kind.issuevmc': '{ca} may issue Verified Mark Certificates (BIMI logos).',
  'xpl.caa.kind.contactemail': 'Contact address for domain validation: {value}.',
  'xpl.caa.kind.contactphone': 'Contact phone for domain validation: {value}.',
  'xpl.caa.kind.unknown': 'Unknown property: CAs ignore it.',
  'xpl.caa.deny': 'No CA may issue (an empty value).',
  'xpl.caa.denyWild': 'No CA may issue wildcard certificates (an empty value).',
  'xpl.caa.unknownCritical': 'Unknown and critical: every CA must refuse to issue.',
  'xpl.caa.iodefBad': 'Not a mailto: or https: address: unusable.',
  'xpl.caa.methods': 'Only with {methods} validation.',
  'xpl.caa.account': 'Only for the ACME account {account}.',
  'xpl.caa.params': 'CA-specific: {params}.',
  'xpl.caa.problem': 'Authorizes nobody: {problem}.',

  'xpl.svcb.title': '{type} record: how clients connect to {name}',
  'xpl.svcb.none': 'No {type} record: clients learn about HTTP/3 and Encrypted Client Hello only after a first connection.',
  'xpl.svcb.head': 'Priority {priority} · {mode} · {where}',
  'xpl.svcb.mode.alias': 'alias mode',
  'xpl.svcb.mode.service': 'service mode',
  'xpl.svcb.sameName': 'the same name',
  'xpl.svcb.k.alpn': 'Protocols',
  'xpl.svcb.k.port': 'Port',
  'xpl.svcb.k.ipv4hint': 'IPv4 hints',
  'xpl.svcb.k.ipv6hint': 'IPv6 hints',
  'xpl.svcb.k.ech': 'Encrypted Client Hello',
  'xpl.svcb.k.mandatory': 'Mandatory keys',
  'xpl.svcb.k.dohpath': 'DoH path',
  'xpl.svcb.k.groups': 'TLS groups',
  'xpl.svcb.k.other': 'Other parameters',
  'xpl.svcb.defaultAlpn': '+ http/1.1 (implied)',
  'xpl.svcb.hint.match': 'the same as the {type} records',
  'xpl.svcb.hint.stale': 'stale: not addresses of {target}',
  'xpl.svcb.hint.partial': 'some of the {type} records',
  'xpl.svcb.hint.unknown': 'not compared',
  'xpl.svcb.hint.no-address': '{target} has no {type} record',
  'xpl.svcb.ech.config': 'Config {id}',
  'xpl.svcb.ech.publicName': 'outer name {name}',
  'xpl.svcb.ech.key': '{bytes}-byte public key',
  'xpl.svcb.ech.maxName': 'names padded to {count} characters',
  'xpl.svcb.ech.ext': { one: '{count} extension', other: '{count} extensions' },
  'xpl.svcb.ech.mandatoryExt': 'a mandatory extension',
  'xpl.svcb.ech.skipped': 'version {version}: not one browsers use, skipped',
  'xpl.svcb.ech.unknownKem': 'KEM {id}',
  'xpl.svcb.ech.err.base64': 'not valid base64',
  'xpl.svcb.ech.err.empty': 'empty',
  'xpl.svcb.ech.err.truncated': 'cut short',
  'xpl.svcb.ech.err.length': 'its lengths do not add up',
  'xpl.svcb.note.alias': 'Alias mode: clients look up the {type} record of {target} instead.',
  'xpl.svcb.note.alias-none': 'Alias mode to “.”: the service is not available at this name.',
  'xpl.svcb.note.alias-params': 'An alias record with parameters ({keys}): clients ignore them (RFC 9460 §2.4.2).',
  'xpl.svcb.note.mixed-modes': 'The set mixes alias and service records: clients follow the alias and ignore the rest.',
  'xpl.svcb.note.other-target': 'The service runs at {target}: clients connect there.',
  'xpl.svcb.note.h3': 'HTTP/3 is offered: keep UDP port {port} open, or browsers fall back to TCP after a delay.',
  'xpl.svcb.note.no-alpn': 'No alpn: only HTTP/1.1 is implied, neither HTTP/2 nor HTTP/3.',
  'xpl.svcb.note.no-default-alpn': 'no-default-alpn: only {protocols}, not HTTP/1.1.',
  'xpl.svcb.note.no-default-alpn-alone': 'no-default-alpn without alpn: clients cannot use this record (RFC 9460 §7.1.1).',
  'xpl.svcb.note.mandatory-missing': 'mandatory names keys the record does not have ({keys}): clients must skip it.',
  'xpl.svcb.note.port': 'Port {port} instead of the default.',
  'xpl.svcb.note.ech': 'Encrypted Client Hello is on: the name a visitor asks for is hidden from the network, behind the outer name {names}.',
  'xpl.svcb.note.ech-invalid': 'The ech value cannot be read ({error}): clients ignore it.',
  'xpl.svcb.note.ech-unsupported': 'No ECH configuration of a version browsers use ({versions}).',
  'xpl.svcb.note.ech-mandatory-ext': 'A configuration has a mandatory extension: clients that do not know it skip that configuration.',
  'xpl.svcb.note.hint-stale': '{family} hints are stale: {stale} is not an address of {target} ({actual}). Clients that connect from the hints — browsers may, for HTTP/3 — reach the wrong server.',
  'xpl.svcb.note.hint-partial': '{family} hints leave out {missing}: fine, clients still use the real records.',
  'xpl.svcb.note.hint-unknown': '{family} hints not compared: the addresses of {target} could not be asked.',
  'xpl.svcb.note.hint-no-address': '{family} hints, but {target} has no {type} record.',
  'xpl.svcb.note.dohpath': 'A DNS-over-HTTPS service at {path} (RFC 9461).',
  'xpl.svcb.note.ohttp': 'Oblivious HTTP is offered (RFC 9540).'
});

registerStrings('tr', {
  'xpl.title': 'Kayıtları açıkla',
  'xpl.intro': '{name} kayıtlarının ne dediği, ifade ifade ve etiket etiket. SPF, alıcı bir e-posta sunucusunun yaptığı gibi her include içinde izlenir (RFC 7208); sorular sorgunun çözümleyicisine gider.',
  'xpl.rerun': 'Yeniden açıkla',
  'xpl.running': 'Kayıtlar okunuyor…',
  'xpl.none': '{name} için açıklanacak bir şey yok: bu ada uygulanan bir SPF, DMARC, CAA ya da HTTPS kaydı bulunmuyor.',
  'xpl.foot': { one: '{resolver} üzerinden {count} soru daha soruldu; sorgunun kendi yanıtları yeniden kullanıldı. {time}', other: '{resolver} üzerinden {count} soru daha soruldu; sorgunun kendi yanıtları yeniden kullanıldı. {time}' },
  'xpl.footNone': 'Yeni bir şey sorulmadı: sorgunun yanıtlarında ve önbellekte her şey vardı. {time}',
  'xpl.resolverAuto': 'sorgunun çözümleyici zinciri',
  'xpl.failed': 'Okunamadı: {reason}',
  'xpl.notSet': 'belirtilmemiş',
  'xpl.critical': 'kritik',
  'xpl.dur.d': '{n} gün',
  'xpl.dur.h': '{n} sa',
  'xpl.dur.m': '{n} dk',
  'xpl.dur.s': '{n} sn',

  'xpl.res.pass': 'Geçer (pass)',
  'xpl.res.fail': 'Geçmez (fail)',
  'xpl.res.softfail': 'Şüpheli (softfail)',
  'xpl.res.neutral': 'Yorumsuz (neutral)',
  'xpl.res.none': 'SPF yok (none)',
  'xpl.res.permerror': 'Kalıcı hata (permerror)',
  'xpl.res.temperror': 'Geçici hata (temperror)',
  'xpl.res.unknown': 'Belirlenemiyor',
  'xpl.res.noMatch': 'eşleşme sayılmaz',
  'xpl.res.noMatchTitle': 'Bir include içinde yalnızca pass sayılır: bu sonuç, include’un eşleşmediği anlamına gelir.',

  'xpl.spf.title': 'SPF: {name} adına kim e-posta gönderebilir',
  'xpl.spf.none': '{name} için SPF kaydı yok; alıcılar gerçek sunucularını sahtelerinden ayıramaz (SPF sonucu: none).',
  'xpl.spf.type99': 'Sorgu, SPF türünde (99) bir kayıt da buldu: bu tür artık kullanılmıyor ve hiçbir alıcı onu okumuyor (RFC 7208 §3.1). Yalnızca TXT kaydı geçerlidir.',
  'xpl.spf.meter': 'DNS sorguları: {count}/{limit}',
  'xpl.spf.meterTitle': 'RFC 7208 §4.6.4: include, a, mx, ptr, exists ve redirect her include içinde birer sorgu harcar. {limit} sorgu aşılınca alıcılar kalıcı hatayla (permerror) durur.',
  'xpl.spf.voids': 'Hiçbir şey bulamayan sorgular: {count}/{limit}',
  'xpl.spf.size': { one: '{count} parçada {length} karakter', other: '{count} parçada {length} karakter' },
  'xpl.spf.branches': 'En çok harcayanlar: {list}',
  'xpl.spf.findings': 'Bulgular',
  'xpl.spf.join': '{after}. ve {next}. parçalar arada boşluk olmadan birleşiyor; alıcılar “{joined}” okur. {after}. parçayı bir boşlukla bitirin ya da {next}. parçayı bir boşlukla başlatın.',
  'xpl.spf.steps': 'Alıcıların okuduğu sırayla, ifade ifade',
  'xpl.spf.policyOf': '{domain} politikası',
  'xpl.spf.onlyPass': 'Bir include içinde yalnızca pass sayılır: buradaki başka her sonuç “eşleşme yok” demektir ve onu çağıran politika sıradaki ifadesine geçer.',
  'xpl.spf.cost': { one: '{count} sorgu', other: '{count} sorgu' },
  'xpl.spf.costInside': { one: 'içinde {count} sorgu', other: 'içinde {count} sorgu' },
  'xpl.spf.ignored': 'all’dan sonra geldikleri için hiç okunmaz: {terms}',
  'xpl.spf.redirectIgnored': 'Kayıtta all olduğu için alıcılar redirect={target} ifadesine hiç ulaşmaz.',
  'xpl.spf.implicitNeutral': 'all ya da redirect yok: hiçbir ifadenin listelemediği gönderen neutral alır.',
  'xpl.spf.exp': 'exp={target}: alıcılar, geçemeyen bir gönderene orada yayımlanan metni gösterebilir.',
  'xpl.spf.modifier': 'Bilinmeyen değiştirici {name}={value}: alıcılar yok sayar.',
  'xpl.spf.cidr4': 'her biri /{prefix} ağına genişletilir',
  'xpl.spf.cidr6': 'IPv6 /{prefix} ağına genişletilir',
  'xpl.spf.now': 'şu an: {list}',
  'xpl.spf.hosts': 'e-posta sunucuları: {list}',
  'xpl.spf.hostBits': '{term} ifadesinde konak bitleri dolu: {range} ağının tamamını kapsar.',
  'xpl.spf.kind.ip4': '{range} adresinden gelen e-posta eşleşir.',
  'xpl.spf.kind.ip4-range': '{first} ile {last} arasından ({size} adres) gelen e-posta eşleşir.',
  'xpl.spf.kind.ip6': '{range} adresinden gelen e-posta eşleşir.',
  'xpl.spf.kind.ip6-range': '{range} ağındaki herhangi bir adresten gelen e-posta eşleşir.',
  'xpl.spf.kind.a': '{host} adının adreslerinden gelen e-posta eşleşir.',
  'xpl.spf.kind.mx': '{host} alan adının e-posta sunucularından (MX) gelen e-posta eşleşir.',
  'xpl.spf.kind.include': '{target} politikasına sorar: onun geçirdiği gönderen burada eşleşir.',
  'xpl.spf.kind.redirect': 'Burada all yok: geriye kalan her gönderen için {target} politikası karar verir.',
  'xpl.spf.kind.exists': '{target} adı varsa (A kaydı varsa) eşleşir.',
  'xpl.spf.kind.ptr': 'Gönderenin ileri yönde de doğrulanan ters DNS adı {target} ya da onun altında bir adsa eşleşir. Yavaştır ve kullanımdan kalkmıştır (RFC 7208 §5.5).',
  'xpl.spf.kind.all': 'Buraya kadar gelen her gönderen eşleşir.',
  'xpl.spf.state.void': '{target} adında hiçbir şey bulamıyor (boş sorgu: alıcılar en fazla ikisine izin verir).',
  'xpl.spf.state.macro': 'Bu ad {needs} ile kuruluyor: bir ileti gelmeden bilinemez — aşağıdaki kontrolü deneyin.',
  'xpl.spf.state.skipped': 'Sorulmadı: bu sayfanın bir politika için koyduğu sorgu sınırına ulaşıldı.',
  'xpl.spf.state.dns-error': 'Burada yanıt alınamadı ({detail}).',
  'xpl.spf.state.no-record': '{target} SPF kaydı yayımlamıyor: alıcılar kalıcı hatayla (permerror) durur.',
  'xpl.spf.state.multiple-records': '{target} birden fazla SPF kaydı yayımlıyor: alıcılar kalıcı hatayla (permerror) durur.',
  'xpl.spf.state.loop': 'Yolda zaten geçilen bir politikaya geri dönüyor (döngü): permerror.',
  'xpl.spf.state.depth': 'include’lar çok derin iç içe: izlenmedi.',
  'xpl.spf.state.too-many-mx': '{target} alan adının 10’dan fazla MX sunucusu var: permerror.',
  'xpl.spf.state.ok': 'Okundu.',
  'xpl.spf.policy.ok': 'Okundu.',
  'xpl.spf.policy.no-record': '{domain} SPF kaydı yayımlamıyor.',
  'xpl.spf.policy.multiple-records': '{domain} birden fazla SPF kaydı yayımlıyor.',
  'xpl.spf.policy.dns-error': '{domain} alan adının SPF kaydı burada okunamadı ({detail}).',
  'xpl.spf.need.domain': 'alan adı',
  'xpl.spf.need.ip': 'gönderen sunucunun adresi',
  'xpl.spf.need.sender': 'gönderenin adresi (MAIL FROM)',
  'xpl.spf.need.helo': 'HELO adı',
  'xpl.spf.need.ptr': 'adresin ters adı (burada hiç açılmaz)',
  'xpl.spf.need.exp': 'yalnızca açıklama metni',

  'xpl.check.title': 'Bir adres geçer mi?',
  'xpl.check.intro': 'RFC 7208 check_host(): politika bu adres için açılır — %{i} makroları sorulur, ptr kontrol edilir — sonra bir alıcı gibi ifade ifade okunur.',
  'xpl.check.ip': 'Gönderen sunucunun IP adresi',
  'xpl.check.run': 'Kontrol et',
  'xpl.check.more': 'Gönderen ve HELO (yalnızca makrolar için)',
  'xpl.check.sender': 'Gönderen adresi (MAIL FROM)',
  'xpl.check.senderHint': '%{s}, %{l} ve %{o} makrolarını doldurur. İsteğe bağlı.',
  'xpl.check.helo': 'HELO adı',
  'xpl.check.heloHint': '%{h} makrosunu doldurur. İsteğe bağlı.',
  'xpl.check.invalid': 'Bir IPv4 ya da IPv6 adresi girin (ör. 192.0.2.10).',
  'xpl.check.running': '{ip} kontrol ediliyor…',
  'xpl.check.verdict.pass': '{ip}, {domain} adına e-posta gönderebilir: {holder} politikasındaki {term} izin veriyor.',
  'xpl.check.verdict.fail': '{ip}, {domain} adına e-posta gönderemez: {holder} politikasındaki {term} onu reddediyor (fail).',
  'xpl.check.verdict.softfail': '{ip}, {domain} için listede yok: {holder} politikasındaki {term} softfail veriyor (genellikle kabul edilir ama işaretlenir).',
  'xpl.check.verdict.neutral': '{ip}, {domain} politikasından neutral alıyor: {holder} politikasındaki {term} onun hakkında bir şey söylemiyor.',
  'xpl.check.verdict.neutralNone': '{domain} politikasında {ip} adresini listeleyen bir ifade yok ve politikada all yok: neutral.',
  'xpl.check.verdict.none': '{domain} için SPF kaydı yok: none.',
  'xpl.check.verdict.permerror': 'Alıcılar {domain} politikasını {ip} için değerlendiremez: {reason} yüzünden kalıcı hata (permerror).',
  'xpl.check.verdict.temperror': '{ip} için geçici hata (temperror).',
  'xpl.check.verdict.unknown': 'Bu sayfa {ip} için karar veremiyor: {reason} ({holder} politikasındaki {term}).',
  'xpl.check.via': '{host} üzerinden eşleşti ({address}).',
  'xpl.check.path': 'Ulaşılan yol: {path}',
  'xpl.check.missing': 'Tam bir yanıt için “Gönderen ve HELO” altında şunları doldurun: {needs}.',
  'xpl.check.foot': '{ip} için {resolver} üzerinden {time} itibarıyla açıldı. Alıcı kendi çözümleyicisine sorar: burada başarısız olan bir sorgu orada başarısız olmayabilir.',
  'xpl.check.perm.syntax': 'bir kayıttaki sözdizimi hatası',
  'xpl.check.perm.multiple-records': 'birden fazla SPF kaydı',
  'xpl.check.perm.no-record': 'SPF kaydı olmayan bir alan adına include ya da redirect',
  'xpl.check.perm.loop': 'bir include döngüsü',
  'xpl.check.perm.depth': 'çok derin iç içe include’lar',
  'xpl.check.perm.too-many-mx': '10’dan fazla sunucusu olan bir mx ifadesi',
  'xpl.check.perm.lookup-limit': 'adrese ulaşmadan önce 10’dan fazla DNS sorgusu',
  'xpl.check.perm.void-limit': 'hiçbir şey bulamayan 2’den fazla sorgu',
  'xpl.check.unknown.macro': 'bir makro yalnızca gerçek bir iletide olan bilgiye ihtiyaç duyuyor',
  'xpl.check.unknown.ptr': 'bir ptr ifadesi adresin ters adına ihtiyaç duyuyor',
  'xpl.check.unknown.lookup-failed': 'bir sorgu burada başarısız oldu',
  'xpl.check.unknown.skipped': 'bu sayfanın sorgu sınırı bir sorguyu durdurdu',

  'xpl.flat.title': 'Düzleştirme önizlemesi',
  'xpl.flat.intro': 'Aynı politika; include, a ve mx yerine bugün karşılık geldikleri adreslerle: sorgu sınırını aşan bir politika düzleştirilseydi kayıt böyle görünürdü.',
  'xpl.flat.terms': { one: '{count} adres ifadesi', other: '{count} adres ifadesi' },
  'xpl.flat.length': { one: '{count} karakter', other: '{count} karakter' },
  'xpl.flat.strings': { one: '{count} TXT parçası', other: '{count} TXT parçası' },
  'xpl.flat.lookups': { one: '{count} sorgu kalıyor', other: '{count} sorgu kalıyor' },
  'xpl.flat.tooLong': '{max} karakterden uzun: DNS yanıtı tek bir UDP paketine sığmayabilir (RFC 7208 §3.4) ve bazı alıcılar o zaman doğrulamayı başarısız sayar.',
  'xpl.flat.split': '255 karakteri aşıyor: {count} parçaya bölünmesi gerekir — DNS sağlayıcınızın bunu boşluklardan böldüğünü kontrol edin.',
  'xpl.flat.refresh': 'Sağlayıcılar adreslerini haber vermeden değiştirir: düzleştirilmiş bir kayıt her değişiklikte güncellenmelidir, yoksa onların e-postaları SPF’ten geçemez. Takip etmediğiniz sağlayıcıların include’unu koruyun.',
  'xpl.flat.note.sender': 'Olduğu gibi bırakıldı: {term} gönderene bağlı.',
  'xpl.flat.note.failed': 'Olduğu gibi bırakıldı: {term} burada okunamadı.',
  'xpl.flat.note.kept-include': 'include olarak bırakıldı: {term} arkasındaki politikada gönderene bağlı ya da okunamayan ifadeler var.',
  'xpl.flat.note.exceptions': 'Tam karşılık değil: {holder} politikasındaki {term} bir istisna yapıyor; düz bir izin listesi bunu ifade edemez.',
  'xpl.flat.note.passes-all': 'Tam karşılık değil: {holder} politikası herkesi geçiriyor ({term}) ve bu kaydı orada bitiriyor.',

  'xpl.dmarc.title': 'DMARC: alıcılar doğrulamadan geçemeyen e-postayla ne yapar',
  'xpl.dmarc.at': '_dmarc.{domain} adında yayımlanmış.',
  'xpl.dmarc.inherited': '_dmarc.{name} adında kayıt yok: kurumsal alan adının _dmarc.{domain} adındaki kaydı, alt alan adı politikasıyla birlikte uygulanır (RFC 7489 §6.6.3).',
  'xpl.dmarc.none': '{name} için uygulanan bir DMARC kaydı yok: alıcılar SPF ya da DKIM hatalarında bir şey yapmaz ve kimse rapor almaz.',
  'xpl.dmarc.multiple': '_dmarc.{domain} adında {count} DMARC kaydı var: tek bir kayıt kalana kadar alıcılar DMARC’ı yok sayar.',
  'xpl.dmarc.applies.none': '{name} adından gelen ve DMARC’tan geçemeyen e-posta her zamanki gibi teslim edilir: politika yalnızca rapor ister (izleme).',
  'xpl.dmarc.applies.quarantine': '{name} adından gelen ve DMARC’tan geçemeyen e-posta şüpheli sayılır — genellikle spam klasörüne gider.',
  'xpl.dmarc.applies.reject': '{name} adından gelen ve DMARC’tan geçemeyen e-posta reddedilir.',
  'xpl.dmarc.pctNote': 'Bu yalnızca %{pct} için geçerli; kalanına {lower} uygulanır.',
  'xpl.dmarc.testNote': 'Test modu (t=y): alıcılar bunun yerine {lower} uygular.',
  'xpl.dmarc.external': 'başka bir alan adı: {domain}, bu raporlara {record} adındaki bir TXT kaydıyla izin vermeli (RFC 7489 §7.1)',
  'xpl.dmarc.m.v': 'Bu bir DMARC kaydı (sürüm 1).',
  'xpl.dmarc.m.p.none': 'Politika: başarısız e-postaya bir şey yapma, yalnızca raporla (izleme).',
  'xpl.dmarc.m.p.quarantine': 'Politika: başarısız e-postayı şüpheli say — genellikle spam klasörü.',
  'xpl.dmarc.m.p.reject': 'Politika: başarısız e-postayı teslim sırasında reddet.',
  'xpl.dmarc.m.sp.none': 'Alt alan adları: başarısız e-postayı yalnızca raporla.',
  'xpl.dmarc.m.sp.quarantine': 'Alt alan adları: başarısız e-postayı şüpheli say.',
  'xpl.dmarc.m.sp.reject': 'Alt alan adları: başarısız e-postayı reddet.',
  'xpl.dmarc.m.sp.default': 'Alt alan adları ana politikayı ({policy}) alır.',
  'xpl.dmarc.m.np.none': 'Var olmayan alt alan adları: başarısız e-postayı yalnızca raporla.',
  'xpl.dmarc.m.np.quarantine': 'Var olmayan alt alan adları: başarısız e-postayı şüpheli say.',
  'xpl.dmarc.m.np.reject': 'Var olmayan alt alan adları: başarısız e-postayı reddet.',
  'xpl.dmarc.m.pct': 'Politika başarısız e-postanın %{pct} kadarına uygulanır; kalan %{rest} kadarına {lower} uygulanır.',
  'xpl.dmarc.m.pct.full': 'Politika başarısız e-postanın tamamına uygulanır.',
  'xpl.dmarc.m.pct.default': 'Politika başarısız e-postanın tamamına uygulanır (%100).',
  'xpl.dmarc.m.t.y': 'Test modu: alıcılar bir alt politikayı ({lower}) uygular.',
  'xpl.dmarc.m.t.n': 'Test modunda değil.',
  'xpl.dmarc.m.rua': 'Toplu raporlar (günlük özet) bu adreslere gider.',
  'xpl.dmarc.m.ruf': 'Hata raporları (ileti başına) bu adreslere gider; bunları hâlâ gönderen alıcı azdır.',
  'xpl.dmarc.m.adkim.r': 'DKIM hizalaması gevşek: imzalayan alan adı From alan adı ya da onunla aynı kurumsal alan adındaki başka bir ad olabilir.',
  'xpl.dmarc.m.adkim.s': 'DKIM hizalaması katı: imzalayan alan adı From alan adının tam olarak aynısı olmalı.',
  'xpl.dmarc.m.adkim.default': 'DKIM hizalaması gevşek (varsayılan).',
  'xpl.dmarc.m.aspf.r': 'SPF hizalaması gevşek: zarf göndericisinin (MAIL FROM) alan adı From alan adı ya da onunla aynı kurumsal alan adındaki başka bir ad olabilir.',
  'xpl.dmarc.m.aspf.s': 'SPF hizalaması katı: zarf göndericisinin (MAIL FROM) alan adı From alan adının tam olarak aynısı olmalı.',
  'xpl.dmarc.m.aspf.default': 'SPF hizalaması gevşek (varsayılan).',
  'xpl.dmarc.m.fo': 'Hata raporu şu durumlarda istenir: {options}.',
  'xpl.dmarc.m.rf': 'Hata raporu biçimi: {format}.',
  'xpl.dmarc.m.ri': 'Toplu raporlar her {time} bir (alıcıların çoğu yine de günlük gönderir).',
  'xpl.dmarc.m.psd.y': 'Bir genel sonek (public suffix) alan adının kaydı (DMARCbis).',
  'xpl.dmarc.m.psd.n': 'Genel sonek (public suffix) alan adı değil (DMARCbis).',
  'xpl.dmarc.m.psd.u': 'Genel sonek alan adı olup olmadığı belirtilmemiş (DMARCbis).',
  'xpl.dmarc.m.invalid': 'Geçerli bir değer değil: alıcılar yok sayar.',
  'xpl.dmarc.m.unknown': 'Bilinmeyen etiket: alıcılar yok sayar.',
  'xpl.dmarc.fo.0': 'SPF ve DKIM’in ikisi de hizalanmadığında (varsayılan)',
  'xpl.dmarc.fo.1': 'SPF ya da DKIM’den biri hizalanmadığında',
  'xpl.dmarc.fo.d': 'DKIM imzası doğrulanamadığında',
  'xpl.dmarc.fo.s': 'SPF başarısız olduğunda',
  'xpl.dmarc.issue.missing-p': 'p= etiketi yok: alıcılar kaydı yok sayar.',
  'xpl.dmarc.issue.invalid-p': '{token} bir politika değil (none, quarantine ya da reject olmalı): alıcılar kaydı yok sayar.',
  'xpl.dmarc.issue.invalid-sp': '{token} bir politika değil: alt alan adları ana politikayı alır.',
  'xpl.dmarc.issue.invalid-np': '{token} bir politika değil: var olmayan alt alan adları alt alan adı politikasını alır.',
  'xpl.dmarc.issue.invalid-pct': '{token}, 0 ile 100 arasında bir yüzde değil.',
  'xpl.dmarc.issue.invalid-adkim': '{token}, r ya da s değil.',
  'xpl.dmarc.issue.invalid-aspf': '{token}, r ya da s değil.',
  'xpl.dmarc.issue.duplicate-tag': 'Bir etiket iki kez yazılmış ({token}): alıcılar ilkini kullanır.',
  'xpl.dmarc.issue.unknown-tag': 'Bilinmeyen etiket {token}: yok sayılır.',
  'xpl.dmarc.issue.invalid-rua': 'Geçerli bir rapor adresi değil: {token}.',
  'xpl.dmarc.issue.invalid-ruf': 'Geçerli bir rapor adresi değil: {token}.',
  'xpl.dmarc.issue.invalid-ri': '{token} bir saniye sayısı değil: varsayılan (bir gün) kullanılır.',
  'xpl.dmarc.issue.invalid-fo': '{token}; 0, 1, d ve s’den oluşan bir liste değil: varsayılan kullanılır.',
  'xpl.dmarc.issue.policy-none': 'Yalnızca izleme ({token}): başarısız e-posta yine teslim edilir. Raporlar tüm gerçek gönderenlerin geçtiğini gösterince önce quarantine’e, sonra reject’e geçin.',
  'xpl.dmarc.issue.sp-none': 'Alt alan adları korunmuyor ({token}): onlardan gelen sahte e-posta teslim edilir.',
  'xpl.dmarc.issue.pct-partial': 'Politika başarısız e-postanın yalnızca bir kısmını kapsıyor ({token}).',
  'xpl.dmarc.issue.testing': 'Test modu ({token}): alıcılar bir alt politikayı uygular.',
  'xpl.dmarc.issue.no-rua': 'Toplu rapor (rua) yok: bu alan adı adına kimin e-posta gönderdiğini kimse görmüyor.',
  'xpl.dmarc.issue.multiple': 'Birden fazla DMARC kaydı: alıcılar DMARC’ı yok sayar.',

  'xpl.caa.title': 'CAA: {name} için kim sertifika verebilir',
  'xpl.caa.at': '{domain} adında yayımlanmış.',
  'xpl.caa.inherited': '{name} adında CAA yok: {domain} kümesi uygulanır (CAA ağaçta yukarı doğru aranır, RFC 8659 §3).',
  'xpl.caa.none': '{name} adında ya da üstünde CAA kaydı yok: her sertifika otoritesi sertifika verebilir.',
  'xpl.caa.sum.issuers': 'Sertifika verebilir: {list}. Diğer her otorite reddetmek zorunda.',
  'xpl.caa.sum.denyAll': 'Hiçbir otorite sertifika veremez: hiçbir issue değeri kimseye izin vermiyor.',
  'xpl.caa.sum.blocked': 'Hiçbir otorite sertifika veremez: hiçbir otoritenin bilmediği kritik bir özellik bunu engelliyor (RFC 8659 §4.1).',
  'xpl.caa.sum.anyone': 'issue özelliği yok: her otorite sertifika verebilir.',
  'xpl.caa.sum.wildSame': 'Joker (wildcard) sertifikalar: aynı otoriteler (issuewild yok).',
  'xpl.caa.sum.wildList': 'Joker (wildcard) sertifikalar: yalnızca {list} (issuewild, joker sertifikalarda issue’yu geçersiz kılar).',
  'xpl.caa.sum.wildDeny': 'Joker (wildcard) sertifikalar: hiçbir otorite (issuewild kimseye izin vermiyor).',
  'xpl.caa.kind.issue': '{ca} sertifika verebilir.',
  'xpl.caa.kind.issuewild': '{ca} joker (wildcard) sertifika verebilir.',
  'xpl.caa.kind.iodef': 'CAA yüzünden bir isteği reddeden otorite bunu {value} adresine bildirebilir.',
  'xpl.caa.kind.issuemail': '{ca} S/MIME (e-posta) sertifikası verebilir (RFC 9495).',
  'xpl.caa.kind.issuevmc': '{ca} Doğrulanmış Marka Sertifikası (VMC, BIMI logoları) verebilir.',
  'xpl.caa.kind.contactemail': 'Alan adı doğrulaması için iletişim adresi: {value}.',
  'xpl.caa.kind.contactphone': 'Alan adı doğrulaması için iletişim telefonu: {value}.',
  'xpl.caa.kind.unknown': 'Bilinmeyen özellik: otoriteler yok sayar.',
  'xpl.caa.deny': 'Hiçbir otorite sertifika veremez (boş değer).',
  'xpl.caa.denyWild': 'Hiçbir otorite joker sertifika veremez (boş değer).',
  'xpl.caa.unknownCritical': 'Bilinmeyen ve kritik: her otorite sertifika vermeyi reddetmek zorunda.',
  'xpl.caa.iodefBad': 'mailto: ya da https: adresi değil: kullanılamaz.',
  'xpl.caa.methods': 'Yalnızca {methods} doğrulamasıyla.',
  'xpl.caa.account': 'Yalnızca {account} ACME hesabı için.',
  'xpl.caa.params': 'Otoriteye özgü: {params}.',
  'xpl.caa.problem': 'Kimseye izin vermiyor: {problem}.',

  'xpl.svcb.title': '{type} kaydı: istemciler {name} adına nasıl bağlanır',
  'xpl.svcb.none': '{type} kaydı yok: istemciler HTTP/3’ü ve Encrypted Client Hello’yu ancak ilk bağlantıdan sonra öğrenir.',
  'xpl.svcb.head': 'Öncelik {priority} · {mode} · {where}',
  'xpl.svcb.mode.alias': 'takma ad modu',
  'xpl.svcb.mode.service': 'hizmet modu',
  'xpl.svcb.sameName': 'aynı ad',
  'xpl.svcb.k.alpn': 'Protokoller',
  'xpl.svcb.k.port': 'Port',
  'xpl.svcb.k.ipv4hint': 'IPv4 ipuçları',
  'xpl.svcb.k.ipv6hint': 'IPv6 ipuçları',
  'xpl.svcb.k.ech': 'Encrypted Client Hello',
  'xpl.svcb.k.mandatory': 'Zorunlu anahtarlar',
  'xpl.svcb.k.dohpath': 'DoH yolu',
  'xpl.svcb.k.groups': 'TLS grupları',
  'xpl.svcb.k.other': 'Diğer parametreler',
  'xpl.svcb.defaultAlpn': '+ http/1.1 (varsayılan)',
  'xpl.svcb.hint.match': '{type} kayıtlarıyla aynı',
  'xpl.svcb.hint.stale': 'eskimiş: {target} adresleri değil',
  'xpl.svcb.hint.partial': '{type} kayıtlarının bir kısmı',
  'xpl.svcb.hint.unknown': 'karşılaştırılmadı',
  'xpl.svcb.hint.no-address': '{target} adında {type} kaydı yok',
  'xpl.svcb.ech.config': 'Yapılandırma {id}',
  'xpl.svcb.ech.publicName': 'dış ad {name}',
  'xpl.svcb.ech.key': '{bytes} baytlık genel anahtar',
  'xpl.svcb.ech.maxName': 'adlar {count} karaktere doldurulur',
  'xpl.svcb.ech.ext': { one: '{count} uzantı', other: '{count} uzantı' },
  'xpl.svcb.ech.mandatoryExt': 'zorunlu bir uzantı',
  'xpl.svcb.ech.skipped': 'sürüm {version}: tarayıcıların kullandığı bir sürüm değil, atlanır',
  'xpl.svcb.ech.unknownKem': 'KEM {id}',
  'xpl.svcb.ech.err.base64': 'geçerli base64 değil',
  'xpl.svcb.ech.err.empty': 'boş',
  'xpl.svcb.ech.err.truncated': 'yarıda kesilmiş',
  'xpl.svcb.ech.err.length': 'uzunlukları birbirini tutmuyor',
  'xpl.svcb.note.alias': 'Takma ad modu: istemciler bunun yerine {target} adının {type} kaydına bakar.',
  'xpl.svcb.note.alias-none': '“.” adına takma ad: hizmet bu adda sunulmuyor.',
  'xpl.svcb.note.alias-params': 'Parametreli bir takma ad kaydı ({keys}): istemciler parametreleri yok sayar (RFC 9460 §2.4.2).',
  'xpl.svcb.note.mixed-modes': 'Küme hem takma ad hem hizmet kayıtları içeriyor: istemciler takma adı izler, gerisini yok sayar.',
  'xpl.svcb.note.other-target': 'Hizmet {target} adında çalışıyor: istemciler oraya bağlanır.',
  'xpl.svcb.note.h3': 'HTTP/3 sunuluyor: UDP {port} portunu açık tutun, yoksa tarayıcılar bir gecikmeden sonra TCP’ye döner.',
  'xpl.svcb.note.no-alpn': 'alpn yok: yalnızca HTTP/1.1 varsayılır; HTTP/2 ya da HTTP/3 sunulmuyor.',
  'xpl.svcb.note.no-default-alpn': 'no-default-alpn: yalnızca {protocols}; HTTP/1.1 değil.',
  'xpl.svcb.note.no-default-alpn-alone': 'alpn olmadan no-default-alpn: istemciler bu kaydı kullanamaz (RFC 9460 §7.1.1).',
  'xpl.svcb.note.mandatory-missing': 'mandatory, kayıtta olmayan anahtarları sayıyor ({keys}): istemciler kaydı atlamak zorunda.',
  'xpl.svcb.note.port': 'Varsayılan yerine {port} portu.',
  'xpl.svcb.note.ech': 'Encrypted Client Hello açık: ziyaretçinin istediği ad ağdan gizlenir, dışarıda {names} adı görünür.',
  'xpl.svcb.note.ech-invalid': 'ech değeri okunamıyor ({error}): istemciler yok sayar.',
  'xpl.svcb.note.ech-unsupported': 'Tarayıcıların kullandığı sürümde bir ECH yapılandırması yok ({versions}).',
  'xpl.svcb.note.ech-mandatory-ext': 'Bir yapılandırmada zorunlu bir uzantı var: onu bilmeyen istemciler o yapılandırmayı atlar.',
  'xpl.svcb.note.hint-stale': '{family} ipuçları eskimiş: {stale}, {target} adının adresi değil ({actual}). İpuçlarından bağlanan istemciler — tarayıcılar HTTP/3 için bunu yapabilir — yanlış sunucuya gider.',
  'xpl.svcb.note.hint-partial': '{family} ipuçları {missing} adresini dışarıda bırakıyor: sorun değil, istemciler yine gerçek kayıtları kullanır.',
  'xpl.svcb.note.hint-unknown': '{family} ipuçları karşılaştırılmadı: {target} adresleri sorulamadı.',
  'xpl.svcb.note.hint-no-address': '{family} ipuçları var ama {target} adında {type} kaydı yok.',
  'xpl.svcb.note.dohpath': '{path} adresinde bir DNS-over-HTTPS hizmeti (RFC 9461).',
  'xpl.svcb.note.ohttp': 'Oblivious HTTP sunuluyor (RFC 9540).'
});

/**
 * Every key this module builds from a code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  return [
    ...SPF_EVAL_RESULTS.map((r) => `xpl.res.${r}`),
    ...SPF_STEP_KINDS.map((k) => `xpl.spf.kind.${k}`),
    ...SPF_STEP_STATES.map((s) => `xpl.spf.state.${s}`),
    ...SPF_POLICY_STATES.map((s) => `xpl.spf.policy.${s}`),
    ...[...new Set(Object.values(SPF_MACRO_NEEDS))].map((n) => `xpl.spf.need.${n}`),
    ...SPF_EVAL_RESULTS.filter((r) => r !== 'unknown').map((r) => `xpl.check.verdict.${r}`), 'xpl.check.verdict.unknown',
    ...SPF_PERMERROR_REASONS.map((r) => `xpl.check.perm.${r}`),
    ...SPF_UNKNOWN_REASONS.map((r) => `xpl.check.unknown.${r}`),
    ...SPF_FLATTEN_NOTES.map((n) => `xpl.flat.note.${n}`),
    ...DMARC_MEANINGS.map((m) => `xpl.dmarc.m.${m}`),
    ...DMARC_ISSUES.map((i) => `xpl.dmarc.issue.${i}`),
    ...DMARC_FO.map((f) => `xpl.dmarc.fo.${f}`),
    ...['none', 'quarantine', 'reject'].map((p) => `xpl.dmarc.applies.${p}`),
    ...CAA_KINDS.map((k) => `xpl.caa.kind.${k}`),
    ...['issuers', 'denyAll', 'blocked', 'anyone', 'wildSame', 'wildList', 'wildDeny'].map((s) => `xpl.caa.sum.${s}`),
    ...ECH_ERRORS.map((e) => `xpl.svcb.ech.err.${e}`),
    ...SVCB_NOTES.map((n) => `xpl.svcb.note.${n}`),
    ...HINT_STATUSES.map((s) => `xpl.svcb.hint.${s}`),
    ...['alias', 'service'].map((m) => `xpl.svcb.mode.${m}`),
    ...['alpn', 'port', 'ipv4hint', 'ipv6hint', 'ech', 'mandatory', 'dohpath', 'groups', 'other'].map((k) => `xpl.svcb.k.${k}`),
    ...['d', 'h', 'm', 's'].map((u) => `xpl.dur.${u}`)
  ];
}

const RESULT_VARIANT = Object.freeze({
  pass: 'ok', fail: 'error', softfail: 'warn', neutral: 'neutral', none: 'neutral', permerror: 'error', temperror: 'warn', unknown: 'neutral'
});
const RESULT_ICON = Object.freeze({ pass: 'check', fail: 'x-circle', softfail: 'alert', permerror: 'x-circle', temperror: 'alert', unknown: 'help' });
const SEVERITY_ORDER = Object.freeze({ error: 0, warn: 1, info: 2, ok: 3 });
const LOWER = Object.freeze({ reject: 'quarantine', quarantine: 'none', none: 'none' });

/**
 * The Explain panel of one lookup.
 * @param {{ ctx: object, name: string, types: string[], responses: Array<object|null>, resolver?: string|null }} opts
 *   `responses`: the lookup's answers, by `types` (null while one is still on its way)
 * @returns {{ el: HTMLElement, run: (opts?: { noCache?: boolean }) => Promise<void>, destroy: () => void }}
 */
export function ExplainPanel({ ctx, name, types = [], responses = [], resolver = null }) {
  const { t } = ctx;
  let controller = null;
  let checkController = null;
  let destroyed = false;
  let asked = 0;
  const runBtn = Button({ label: t('xpl.rerun'), icon: 'refresh', size: 'sm', variant: 'secondary', dataset: { action: 'explain-run' }, onClick: () => run({ noCache: true }) });
  const body = h('div', { class: 'xpl-body stack', attrs: { 'aria-live': 'polite' } });
  const el = h('section', { class: 'card xpl-panel', dataset: { name }, attrs: { 'aria-label': t('xpl.title') } },
    h('div', { class: 'xpl-head cluster' },
      h('h2', { class: 'xpl-title' }, t('xpl.title')),
      h('span', { class: 'xpl-name mono' }, name),
      h('div', { class: 'xpl-controls cluster' }, runBtn)),
    h('p', { class: 'xpl-intro muted text-sm' }, t('xpl.intro', { name })),
    body);

  const resolverLabel = () => {
    if (!resolver) return t('xpl.resolverAuto');
    const r = getResolver(resolver);
    return r ? r.name : resolver;
  };
  const stamp = (d) => formatDateTime(d, { utc: true, seconds: true });
  const duration = (sec) => {
    const n = Math.max(0, Math.floor(Number(sec) || 0));
    const parts = [];
    let rest = n;
    for (const [unit, size] of [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]]) {
      if (rest >= size) {
        const q = Math.floor(rest / size);
        parts.push(t(`xpl.dur.${unit}`, { n: formatNumber(q) }));
        rest -= q * size;
      }
      if (parts.length === 2) break;
    }
    return parts.join(' ') || t('xpl.dur.s', { n: 0 });
  };
  const known = () => {
    const map = new Map();
    types.forEach((type, i) => {
      const r = responses[i];
      if (r && r.ok && (r.rcode === 'NOERROR' || r.rcode === 'NXDOMAIN')) map.set(type, r);
    });
    return map;
  };
  /** The DoH client through the lookup's resolver, counting the questions that left the cache. */
  const dnsFor = (client, noCache) => ({
    query: async (qname, type, opts = {}) => {
      const r = await client.query(qname, type, { signal: opts.signal, resolver: resolver || undefined, noCache });
      if (r && !r.cached) asked += 1;
      return r;
    }
  });

  /* --- small builders ---------------------------------------------------------------- */

  const resultBadge = (result, extra = {}) => Badge(t(`xpl.res.${result}`), { variant: RESULT_VARIANT[result] || 'neutral', icon: RESULT_ICON[result] || null, className: 'xpl-result', ...extra });
  const section = (key, title, ...children) => h('section', { class: ['xpl-sec', `xpl-${key}`], dataset: { section: key } },
    h('h3', { class: 'xpl-sec-title' }, title), ...children);
  const recordLine = (text) => h('div', { class: 'xpl-record' }, h('code', { class: 'xpl-record-text mono' }, text), CopyButton(text, { iconOnly: true, size: 'sm' }));
  const failure = (res, error, onRetry) => {
    // No answer at all (a transport error, a rate limit), or an answer the resolver gave up on (SERVFAIL …).
    const st = res && res.ok === false ? dohStatus(res) : res && res.rcode ? sourceStatus({ source: 'doh', rcode: res.rcode }) : null;
    return Alert({
      variant: 'warn',
      compact: true,
      message: `⚠ ${st ? statusText(st) : t('xpl.failed', { reason: error || '?' })}`,
      actions: [RetryButton({ sources: ['doh'], target: name, onClick: onRetry, variant: 'secondary' })]
    });
  };
  const finding = (severity, text, detail = null, dataset = {}) => h('li', { class: ['xpl-finding', `xpl-${severity}`], dataset: { severity, ...dataset } },
    SeverityIcon(severity), h('div', { class: 'xpl-finding-text' },
      h('span', { class: detail ? 'xpl-finding-title' : null }, text),
      detail ? h('span', { class: 'xpl-finding-detail muted' }, detail) : null));
  /** Tag by tag: what is written, then what it means (two columns on a wide screen, stacked on a phone). */
  const tagList = (rows, className) => h('ul', { class: ['xpl-tags', className] }, rows.map((r) => h('li', { class: ['xpl-tag-row', r.className || null], dataset: r.dataset || {} },
    h('div', { class: 'xpl-tag-key' }, r.key),
    h('div', { class: 'xpl-tag-meaning xpl-lines' }, r.meaning))));
  const needsText = (letters) => [...new Set((letters || []).map((l) => SPF_MACRO_NEEDS[l] || 'exp'))].map((n) => t(`xpl.spf.need.${n}`)).join(', ');

  /* --- SPF ------------------------------------------------------------------------------ */

  function stepItem(step, policy) {
    const inner = policy.scope !== 'top';
    // Inside an include a fail / softfail / neutral is written as such, but for the domain checked it is no match.
    const noMatch = inner && step.result !== null && step.effective === null;
    const head = h('div', { class: 'xpl-step-head cluster' },
      h('span', { class: 'xpl-step-n', attrs: { 'aria-hidden': 'true' } }, String(step.n)),
      h('code', { class: 'xpl-term mono' }, step.term),
      step.result === null ? null : resultBadge(noMatch ? step.result : step.effective || step.result),
      noMatch ? Badge(t('xpl.res.noMatch'), { variant: 'neutral', icon: 'arrow-right', title: t('xpl.res.noMatchTitle'), className: 'xpl-no-match' }) : null,
      step.cost ? Badge(t('xpl.spf.cost', { count: step.cost }), { variant: 'neutral', mono: true, className: 'xpl-cost' }) : null);
    const p = step.params || {};
    const textParams = {
      ...p,
      size: p.size !== null && p.size !== undefined ? formatNumber(p.size) : '',
      host: p.host || name,
      target: p.target || step.target || name
    };
    const lines = [];
    if (step.kind === 'exists' && !step.target && step.missing.length) lines.push(t('xpl.spf.state.macro', { needs: needsText(step.missing) }));
    else lines.push(t(`xpl.spf.kind.${step.kind}`, textParams));
    const extra = [];
    if ((step.kind === 'a' || step.kind === 'mx') && (p.cidr4 !== null || p.cidr6 !== null)) {
      if (p.cidr4 !== null) extra.push(t('xpl.spf.cidr4', { prefix: p.cidr4 }));
      if (p.cidr6 !== null) extra.push(t('xpl.spf.cidr6', { prefix: p.cidr6 }));
    }
    if (step.addresses && step.addresses.length) extra.push(t('xpl.spf.now', { list: step.addresses.join(', ') }));
    if (step.hosts && step.hosts.length) extra.push(t('xpl.spf.hosts', { list: step.hosts.join(', ') }));
    if (p.hostBits) extra.push(t('xpl.spf.hostBits', { term: step.term, range: p.range }));
    let stateLine = null;
    if (step.state !== 'ok' && !(step.state === 'macro' && step.kind === 'exists')) {
      stateLine = h('p', { class: ['xpl-step-state', `xpl-state-${step.state}`], dataset: { state: step.state } },
        step.state === 'macro' ? t('xpl.spf.state.macro', { needs: needsText(step.missing) })
          : t(`xpl.spf.state.${step.state}`, { target: step.target || p.target || '?', detail: step.detail || '?' }));
    }
    const shown = step.result === null ? '' : noMatch ? 'no-match' : step.effective || step.result;
    const li = h('li', { class: 'xpl-step', dataset: { term: step.term, kind: step.kind, state: step.state, result: shown } },
      head,
      h('p', { class: 'xpl-step-text' }, lines.join(' ')),
      extra.length ? h('p', { class: 'xpl-step-extra muted text-sm' }, extra.join(' · ')) : null,
      stateLine);
    if (step.child) {
      li.append(Disclosure({
        summary: h('span', { class: 'xpl-child-summary' }, t('xpl.spf.policyOf', { domain: step.child.domain }),
          step.child.count ? [' ', Badge(t('xpl.spf.costInside', { count: step.child.count }), { variant: 'neutral', mono: true })] : null),
        className: 'xpl-child',
        children: policyBlock(step.child)
      }));
    }
    return li;
  }

  function policyBlock(policy) {
    const parts = [];
    if (policy.state !== 'ok') {
      parts.push(h('p', { class: 'xpl-policy-state text-sm', dataset: { state: policy.state } }, t(`xpl.spf.policy.${policy.state}`, { domain: policy.domain, detail: policy.detail || '?' })));
      return h('div', { class: 'xpl-policy stack-sm', dataset: { domain: policy.domain } }, parts);
    }
    if (policy.scope !== 'top') parts.push(recordLine(policy.record));
    if (policy.scope === 'include') parts.push(h('p', { class: 'xpl-only-pass muted text-sm' }, t('xpl.spf.onlyPass')));
    parts.push(h('ol', { class: 'xpl-steps' }, policy.steps.map((s) => stepItem(s, policy))));
    const notes = [];
    if (policy.implicitNeutral) notes.push(t('xpl.spf.implicitNeutral'));
    if (policy.ignored.length) notes.push(t('xpl.spf.ignored', { terms: policy.ignored.join(' ') }));
    if (policy.redirectIgnored) notes.push(t('xpl.spf.redirectIgnored', { target: policy.redirect }));
    if (policy.exp) notes.push(t('xpl.spf.exp', { target: policy.exp }));
    for (const [k, v] of policy.modifiers) notes.push(t('xpl.spf.modifier', { name: k, value: v }));
    if (notes.length) parts.push(h('ul', { class: 'xpl-notes muted text-sm' }, notes.map((n) => h('li', null, n))));
    return h('div', { class: 'xpl-policy stack-sm', dataset: { domain: policy.domain } }, parts);
  }

  function meterBlock(spf) {
    const m = spf.meter;
    const pct = Math.min(100, Math.round((m.count / m.limit) * 100));
    const state = m.exceeded ? 'error' : m.high ? 'warn' : 'ok';
    const bar = h('div', { class: ['xpl-meter-bar', `xpl-${state}`], attrs: { role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': String(m.limit), 'aria-valuenow': String(m.count), 'aria-label': t('xpl.spf.meter', { count: m.count, limit: m.limit }) } },
      h('span', { class: 'xpl-meter-fill' }));
    bar.firstChild.style.width = `${pct}%`;
    return h('div', { class: 'xpl-meter stack-sm', dataset: { count: String(m.count), state } },
      h('div', { class: 'xpl-meter-head cluster' },
        h('span', { class: 'xpl-meter-label', title: t('xpl.spf.meterTitle', { limit: m.limit }) }, t('xpl.spf.meter', { count: m.count, limit: m.limit })),
        h('span', { class: ['xpl-voids', 'muted', 'text-sm', { 'xpl-warn-text': m.voidExceeded }] }, t('xpl.spf.voids', { count: m.voidCount, limit: m.voidLimit })),
        h('span', { class: 'muted text-sm' }, t('xpl.spf.size', { length: formatNumber(spf.record.length), count: spf.strings.length }))),
      bar,
      m.branches.length ? h('p', { class: 'xpl-branches muted text-sm' }, t('xpl.spf.branches', { list: m.branches.slice(0, 5).map((b) => `${b.term} (${b.cost})`).join(', ') })) : null);
  }

  function checkBlock(spf) {
    const ipField = textInput({ label: t('xpl.check.ip'), placeholder: '192.0.2.10', mono: true, className: 'xpl-check-ip', attrs: { 'data-role': 'explain-ip', inputmode: 'text', enterkeyhint: 'go' }, onEnter: () => check() });
    const senderField = textInput({ label: t('xpl.check.sender'), hint: t('xpl.check.senderHint'), placeholder: `postmaster@${name}`, mono: true, optional: true, attrs: { 'data-role': 'explain-sender' }, onEnter: () => check() });
    const heloField = textInput({ label: t('xpl.check.helo'), hint: t('xpl.check.heloHint'), placeholder: `mail.${name}`, mono: true, optional: true, attrs: { 'data-role': 'explain-helo' }, onEnter: () => check() });
    const btn = Button({ label: t('xpl.check.run'), icon: 'search', size: 'sm', variant: 'primary', dataset: { action: 'explain-check' }, onClick: () => check() });
    const out = h('div', { class: 'xpl-check-out', attrs: { 'aria-live': 'polite' } });
    const more = Disclosure({ summary: t('xpl.check.more'), className: 'xpl-check-more', children: h('div', { class: 'xpl-check-extra' }, senderField.el, heloField.el) });

    async function check() {
      ipField.setError(null);
      const ip = normalizeIP(String(ipField.value || '').trim());
      if (!ip) {
        // The verdict of another address must not stay next to this one.
        if (checkController) checkController.abort();
        clear(out);
        ipField.setError(t('xpl.check.invalid'));
        ipField.focus();
        return;
      }
      if (!ctx.requireOnline()) return;
      if (checkController) checkController.abort();
      checkController = new AbortController();
      const mine = checkController;
      clear(out);
      out.append(h('div', { class: 'xpl-running cluster' }, Spinner({ size: 'sm' }), h('span', { class: 'text-sm' }, t('xpl.check.running', { ip }))));
      btn.setAttribute('aria-busy', 'true');
      try {
        const client = await ctx.getDns();
        const r = await spfCheckHost(name, ip, {
          dns: dnsFor(client, false), signal: mergeSignals(ctx.signal, mine.signal), record: spf.record,
          sender: String(senderField.value || '').trim() || null, helo: String(heloField.value || '').trim() || null
        });
        if (destroyed || checkController !== mine) return;
        clear(out);
        out.append(verdictBlock(r));
        announce(out.querySelector('.xpl-verdict-text').textContent);
      } catch (err) {
        if (err && err.name === 'AbortError') return;
        if (destroyed || checkController !== mine) return;
        clear(out);
        out.append(Alert({ variant: 'error', compact: true, message: `${t('error.title')}: ${err && err.message ? err.message : String(err)}` }));
      } finally {
        if (checkController === mine) {
          checkController = null;
          btn.removeAttribute('aria-busy');
        }
      }
    }

    return h('div', { class: 'xpl-check stack-sm' },
      h('h4', { class: 'xpl-sub' }, t('xpl.check.title')),
      h('p', { class: 'muted text-sm xpl-check-intro' }, t('xpl.check.intro')),
      h('div', { class: 'xpl-check-form' }, ipField.el, h('div', { class: 'xpl-check-btn' }, btn)),
      more,
      out);
  }

  function verdictBlock(r) {
    const v = r.verdict;
    const params = { ip: r.ip, domain: r.domain, term: v.term || '—', holder: v.holder || r.domain };
    let text;
    if (v.result === 'permerror') text = t('xpl.check.verdict.permerror', { ...params, reason: t(`xpl.check.perm.${SPF_PERMERROR_REASONS.includes(v.reason) ? v.reason : 'syntax'}`) });
    else if (v.result === 'unknown') text = t('xpl.check.verdict.unknown', { ...params, reason: t(`xpl.check.unknown.${SPF_UNKNOWN_REASONS.includes(v.reason) ? v.reason : 'lookup-failed'}`) });
    else if (v.result === 'neutral' && !v.term) text = t('xpl.check.verdict.neutralNone', params);
    else text = t(`xpl.check.verdict.${v.result}`, params);
    const lines = [h('p', { class: 'xpl-verdict-text' }, text)];
    if (v.via) lines.push(h('p', { class: 'text-sm' }, t('xpl.check.via', { host: v.via.host, address: v.via.address })));
    if (v.path && v.path.length > 1) lines.push(h('p', { class: 'text-sm muted' }, t('xpl.check.path', { path: v.path.join(' → ') })));
    const unexpanded = r.missing.filter((l) => ['s', 'l', 'h'].includes(l));
    if (v.result === 'unknown' && v.reason === 'macro' && unexpanded.length) lines.push(h('p', { class: 'text-sm' }, t('xpl.check.missing', { needs: needsText(unexpanded) })));
    lines.push(h('p', { class: 'xpl-check-foot muted text-xs' }, t('xpl.check.foot', { ip: r.ip, resolver: resolverLabel(), time: stamp(new Date()) })));
    return h('div', { class: ['xpl-verdict', `xpl-v-${v.result}`], dataset: { result: v.result, reason: v.reason || '', term: v.term || '', ip: r.ip } },
      h('div', { class: 'xpl-verdict-head cluster' }, resultBadge(v.result), h('span', { class: 'mono text-sm' }, r.ip)),
      ...lines);
  }

  function flattenBlock(spf) {
    const f = spf.flatten;
    if (!f) return null;
    const facts = [
      t('xpl.flat.terms', { count: f.addressTerms }), t('xpl.flat.length', { count: f.length }),
      t('xpl.flat.strings', { count: f.strings }), t('xpl.flat.lookups', { count: f.lookups })
    ].join(' · ');
    const notes = f.notes.map((n) => finding(n.code === 'exceptions' || n.code === 'passes-all' ? 'warn' : 'info', t(`xpl.flat.note.${n.code}`, { term: n.term, holder: n.holder }), null, { code: n.code }));
    if (!f.fits) notes.push(finding('warn', t('xpl.flat.tooLong', { max: SPF_UDP_SAFE_LENGTH }), null, { code: 'too-long' }));
    if (f.strings > 1) notes.push(finding('info', t('xpl.flat.split', { count: f.strings }), null, { code: 'split' }));
    return Disclosure({
      summary: h('span', { class: 'xpl-flat-summary' }, t('xpl.flat.title'), ' ', h('span', { class: 'muted text-sm' }, facts)),
      className: 'xpl-flat',
      children: h('div', { class: 'stack-sm' },
        h('p', { class: 'muted text-sm' }, t('xpl.flat.intro')),
        CodeBlock(f.record, { wrap: true, className: 'xpl-flat-record' }),
        notes.length ? h('ul', { class: 'xpl-findings' }, notes) : null,
        h('p', { class: 'xpl-flat-refresh text-sm' }, t('xpl.flat.refresh')))
    });
  }

  function spfBlock(spf) {
    const title = t('xpl.spf.title', { name });
    if (spf.state === 'failed') return section('spf', title, failure(spf.failure, spf.error, () => run({ noCache: true })));
    const type99 = spf.type99 ? Alert({ variant: 'info', compact: true, message: t('xpl.spf.type99') }) : null;
    if (spf.state === 'none') return section('spf', title, h('p', { class: 'xpl-state', dataset: { state: 'none' } }, t('xpl.spf.none', { name })), type99);
    if (spf.state === 'multiple') {
      return section('spf', title,
        Alert({ variant: 'error', compact: true, title: t('health.spf.multiple.title'), message: t('health.spf.multiple.detail', { count: spf.count }) }),
        h('ul', { class: 'xpl-records mono text-sm' }, spf.records.map((r) => h('li', null, r))), type99);
    }
    const findings = [...spf.checks].filter((c) => c.severity !== 'ok' || c.id.startsWith('spf.all-'))
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
      .map((c) => finding(c.severity, t(c.titleKey, c.params), t(c.detailKey, c.params), { check: c.id }));
    const joins = spf.stringIssues.map((j) => finding('error', t('xpl.spf.join', { after: j.after, next: j.after + 1, joined: j.joined }), null, { check: 'join' }));
    return section('spf', title,
      recordLine(spf.record),
      meterBlock(spf),
      findings.length || joins.length ? h('div', { class: 'stack-sm' }, h('h4', { class: 'xpl-sub' }, t('xpl.spf.findings')), h('ul', { class: 'xpl-findings' }, ...joins, ...findings)) : null,
      type99,
      h('h4', { class: 'xpl-sub' }, t('xpl.spf.steps')),
      policyBlock(spf.policy),
      checkBlock(spf),
      flattenBlock(spf));
  }

  /* --- DMARC ---------------------------------------------------------------------------- */

  function dmarcBlock(dm) {
    const title = t('xpl.dmarc.title');
    if (dm.state === 'failed') return section('dmarc', title, failure(dm.failure, dm.error, () => run({ noCache: true })));
    if (dm.state === 'none') return section('dmarc', title, h('p', { class: 'xpl-state', dataset: { state: 'none' } }, t('xpl.dmarc.none', { name: dm.domain })));
    if (dm.state === 'multiple') return section('dmarc', title, Alert({ variant: 'error', compact: true, message: t('xpl.dmarc.multiple', { count: dm.count, domain: dm.foundAt }) }));
    const x = dm.explained;
    const where = x.inherited ? t('xpl.dmarc.inherited', { name: dm.domain, domain: x.foundAt }) : t('xpl.dmarc.at', { domain: x.foundAt });
    const summary = [];
    if (x.valid && x.applies) {
      summary.push(t(`xpl.dmarc.applies.${x.applies}`, { name: dm.domain }));
      if (x.pct < 100 && x.applies !== 'none') summary.push(t('xpl.dmarc.pctNote', { pct: x.pct, lower: LOWER[x.applies] }));
      if (x.testing && x.applies !== 'none') summary.push(t('xpl.dmarc.testNote', { lower: LOWER[x.applies] }));
    }
    const rows = x.tags.map((row) => {
      const p = row.params || {};
      let meaning;
      if (row.meaning === 'fo') meaning = t('xpl.dmarc.m.fo', { options: (p.options || []).map((o) => (DMARC_FO.includes(o) ? t(`xpl.dmarc.fo.${o}`) : o)).join('; ') });
      else if (row.meaning === 'ri') meaning = t('xpl.dmarc.m.ri', { time: duration(p.seconds) });
      else meaning = t(`xpl.dmarc.m.${row.meaning}`, { ...p, pct: p.pct ?? '', rest: p.rest ?? '', lower: p.lower || 'none', policy: p.policy || '', format: p.format || '' });
      const cell = [h('div', null, meaning)];
      const reports = (row.tag === 'rua' || row.tag === 'ruf') && p.targets && p.targets.length;
      if (reports) {
        cell.push(h('ul', { class: 'xpl-reports text-sm' }, p.targets.map((r) => h('li', { dataset: { external: r.external ? '1' : '0' } },
          h('code', { class: 'mono' }, `${r.uri}${r.sizeLimit ? `!${r.sizeLimit}` : ''}`),
          r.external ? h('span', { class: 'xpl-external muted' }, ` — ${t('xpl.dmarc.external', { domain: r.domain, record: `${x.foundAt}._report._dmarc.${r.domain}` })}`) : null))));
      }
      if (row.issue && DMARC_ISSUES.includes(row.issue)) cell.push(h('div', { class: 'xpl-issue' }, SeverityIcon(row.meaning === 'unknown' ? 'warn' : 'error'), ' ', t(`xpl.dmarc.issue.${row.issue}`, { token: `${row.tag}=${row.value ?? ''}` })));
      // A report list is spelt out address by address next to its meaning; any other tag as it is written.
      const key = !row.given ? [h('code', { class: 'mono' }, row.tag), ' ', h('span', { class: 'muted text-sm' }, t('xpl.notSet'))]
        : h('code', { class: 'mono' }, reports ? row.tag : `${row.tag}=${row.value}`);
      return { className: row.given ? null : 'xpl-default', dataset: { tag: row.tag, meaning: row.meaning }, key, meaning: cell };
    });
    const issues = x.issues.filter((i) => !x.tags.some((r) => r.issue === i.code)).map((i) => finding(i.severity, t(`xpl.dmarc.issue.${i.code}`, { token: i.token }), null, { issue: i.code }));
    return section('dmarc', title,
      h('p', { class: 'xpl-where text-sm' }, where),
      recordLine(x.record),
      summary.length ? h('p', { class: ['xpl-summary', `xpl-pol-${x.applies || 'none'}`], dataset: { applies: x.applies || '' } }, summary.join(' ')) : null,
      issues.length ? h('ul', { class: 'xpl-findings' }, issues) : null,
      tagList(rows, 'xpl-dmarc-tags'));
  }

  /* --- CAA ------------------------------------------------------------------------------ */

  function caaBlock(caa) {
    const title = t('xpl.caa.title', { name });
    if (caa.state === 'failed') return section('caa', title, failure(null, caa.error, () => run({ noCache: true })));
    if (caa.state === 'none') return section('caa', title, h('p', { class: 'xpl-state', dataset: { state: 'none' } }, t('xpl.caa.none', { name })));
    const x = caa.explained;
    const names = (list) => list.map((i) => (i.ca ? `${i.ca.name} (${i.domain})` : i.domain)).join(', ');
    const summary = [];
    if (x.blocked) summary.push(t('xpl.caa.sum.blocked'));
    else if (x.anyone) summary.push(t('xpl.caa.sum.anyone'));
    else if (x.denyAll) summary.push(t('xpl.caa.sum.denyAll'));
    else if (x.issuers.length) summary.push(t('xpl.caa.sum.issuers', { list: names(x.issuers) }));
    if (!x.blocked) {
      if (x.wild === 'list') summary.push(t('xpl.caa.sum.wildList', { list: names(x.wildIssuers) }));
      else if (x.wild === 'deny') summary.push(t('xpl.caa.sum.wildDeny'));
      else if (!x.anyone) summary.push(t('xpl.caa.sum.wildSame'));
    }
    const rows = x.rows.map((r) => {
      const lines = [];
      if (r.kind === 'issue' || r.kind === 'issuewild') {
        if (r.deny) lines.push(t(r.kind === 'issue' ? 'xpl.caa.deny' : 'xpl.caa.denyWild'));
        else lines.push(t(`xpl.caa.kind.${r.kind}`, { ca: r.ca ? `${r.ca.name} (${r.issuer})` : r.issuer || '?' }));
        if (r.methods) lines.push(t('xpl.caa.methods', { methods: r.methods.join(', ') }));
        if (r.accountUri) lines.push(t('xpl.caa.account', { account: r.accountUri }));
        if (r.otherParams.length) lines.push(t('xpl.caa.params', { params: r.otherParams.map((p) => `${p.tag}=${p.value}`).join('; ') }));
      } else if (r.kind === 'iodef') lines.push(r.valid ? t('xpl.caa.kind.iodef', { value: r.value }) : t('xpl.caa.iodefBad'));
      else if (r.kind === 'unknown') lines.push(r.critical ? t('xpl.caa.unknownCritical') : t('xpl.caa.kind.unknown'));
      else lines.push(t(`xpl.caa.kind.${r.kind}`, { ca: r.value.split(';')[0].trim() || r.value, value: r.value }));
      const problem = r.problem ? h('div', { class: 'xpl-issue' }, SeverityIcon('error'), ' ', t('xpl.caa.problem', { problem: t(`health.caa.problem.${r.problem}`) })) : null;
      return {
        dataset: { tag: r.tag, kind: r.kind, usable: r.usable ? '1' : '0' },
        key: [h('code', { class: 'mono' }, `${r.flags} ${r.tag} "${r.value}"`), r.critical ? [' ', Badge(t('xpl.critical'), { variant: 'warn' })] : null],
        meaning: [...lines.map((l) => h('div', null, l)), problem]
      };
    });
    return section('caa', title,
      h('p', { class: 'xpl-where text-sm' }, x.inherited ? t('xpl.caa.inherited', { name, domain: x.foundAt }) : t('xpl.caa.at', { domain: x.foundAt || name })),
      summary.length ? h('p', { class: 'xpl-summary' }, summary.join(' ')) : null,
      tagList(rows, 'xpl-caa-tags'));
  }

  /* --- HTTPS / SVCB ------------------------------------------------------------------- */

  function echBlock(ech) {
    const list = h('ul', { class: 'xpl-ech xpl-lines' }, ech.configs.map((c) => {
      if (!c.supported) return h('li', { class: 'muted text-sm' }, t('xpl.svcb.ech.skipped', { version: c.versionHex }));
      const bits = [
        t('xpl.svcb.ech.publicName', { name: c.publicName }),
        c.kem || t('xpl.svcb.ech.unknownKem', { id: `0x${c.kemId.toString(16).padStart(4, '0')}` }),
        c.cipherSuites.map((s) => `${s.kdf || s.kdfId} + ${s.aead || s.aeadId}`).join(', '),
        t('xpl.svcb.ech.key', { bytes: c.publicKeyLength })
      ];
      if (c.maxNameLength) bits.push(t('xpl.svcb.ech.maxName', { count: c.maxNameLength }));
      if (c.extensions.length) bits.push(t('xpl.svcb.ech.ext', { count: c.extensions.length }));
      if (c.extensions.some((e) => e.mandatory)) bits.push(t('xpl.svcb.ech.mandatoryExt'));
      return h('li', { class: 'text-sm', dataset: { configId: String(c.configId) } }, h('strong', null, t('xpl.svcb.ech.config', { id: c.configId })), ` · ${c.versionHex} · `, bits.join(' · '));
    }));
    return list;
  }

  function hintCell(cmp, target, type) {
    return h('div', { class: 'xpl-lines' },
      h('span', { class: 'mono xpl-wrap' }, cmp.hints.join(', ')),
      h('span', { class: ['text-sm', `xpl-hint-${cmp.status}`], dataset: { status: cmp.status } },
        cmp.status === 'stale' ? SeverityIcon('warn') : cmp.status === 'match' ? SeverityIcon('ok') : null, ' ',
        t(`xpl.svcb.hint.${cmp.status}`, { type, target })));
  }

  function svcbBlock(sv) {
    const title = t('xpl.svcb.title', { type: sv.type, name });
    if (sv.state === 'failed') return section(`svcb`, title, failure(sv.failure, sv.error, () => run({ noCache: true })));
    if (sv.state === 'none') return section('svcb', title, h('p', { class: 'xpl-state', dataset: { state: 'none' } }, t('xpl.svcb.none', { type: sv.type })));
    const cards = sv.explained.map((r) => {
      const items = [];
      const kv = (key, value) => items.push(h('div', { class: 'xpl-kv' }, h('dt', { class: 'xpl-kv-key' }, t(`xpl.svcb.k.${key}`)), h('dd', { class: 'xpl-kv-value' }, value)));
      if (r.mode === 'service') {
        if (r.alpn.length || r.defaultAlpn) {
          kv('alpn', h('span', { class: 'cluster' }, r.alpn.map((a) => Badge(a.name ? `${a.id} · ${a.name}` : a.id, { mono: true })),
            r.defaultAlpn ? h('span', { class: 'muted text-sm' }, t('xpl.svcb.defaultAlpn')) : null));
        }
        if (r.port !== null) kv('port', h('span', { class: 'mono' }, String(r.port)));
        if (r.hints.v4) kv('ipv4hint', hintCell(r.hints.v4, r.targetName, 'A'));
        if (r.hints.v6) kv('ipv6hint', hintCell(r.hints.v6, r.targetName, 'AAAA'));
        if (r.ech) kv('ech', r.ech.ok ? echBlock(r.ech) : h('span', { class: 'xpl-issue' }, SeverityIcon('error'), ' ', t(`xpl.svcb.ech.err.${r.ech.error}`)));
        if (r.mandatory.length) kv('mandatory', h('span', { class: 'mono' }, r.mandatory.join(', ')));
        if (r.dohpath !== null) kv('dohpath', h('span', { class: 'mono xpl-wrap' }, r.dohpath));
        if (r.groups.length) kv('groups', h('span', { class: 'mono' }, r.groups.map((g) => g.name || String(g.id)).join(', ')));
        if (r.other.length) kv('other', h('span', { class: 'mono xpl-wrap' }, r.other.map((o) => `${o.key}=${o.value}`).join(' ')));
      }
      const notes = r.notes.map((n) => finding(n.severity, t(`xpl.svcb.note.${n.code}`, {
        ...n.params, type: n.code === 'hint-no-address' ? n.params.type : sv.type,
        error: n.code === 'ech-invalid' && ECH_ERRORS.includes(n.params.error) ? t(`xpl.svcb.ech.err.${n.params.error}`) : n.params.error
      }), null, { note: n.code }));
      return h('div', { class: 'xpl-svcb-rec', dataset: { priority: String(r.priority), mode: r.mode } },
        h('div', { class: 'xpl-svcb-head' }, t('xpl.svcb.head', {
          priority: r.priority, mode: t(`xpl.svcb.mode.${r.mode}`),
          where: r.target === '.' ? t('xpl.svcb.sameName') : r.targetName
        })),
        items.length ? h('dl', { class: 'xpl-kvs' }, items) : null,
        notes.length ? h('ul', { class: 'xpl-findings' }, notes) : null);
    });
    return section('svcb', title, ...cards);
  }

  /* --- run ------------------------------------------------------------------------------ */

  function render(result) {
    clear(body);
    const blocks = [];
    if (result.spf) blocks.push(spfBlock(result.spf));
    if (result.dmarc) blocks.push(dmarcBlock(result.dmarc));
    if (result.caa) blocks.push(caaBlock(result.caa));
    for (const sv of result.svcb) blocks.push(svcbBlock(sv));
    if (!blocks.length) blocks.push(h('p', { class: 'xpl-nothing muted' }, t('xpl.none', { name })));
    const time = stamp(result.at);
    body.append(...blocks,
      h('p', { class: 'xpl-foot muted text-xs' }, asked ? t('xpl.foot', { count: asked, resolver: resolverLabel(), time }) : t('xpl.footNone', { time })));
  }

  /**
   * Explain the records (the panel's own "Explain again" and Retry skip the cache).
   * @param {{ noCache?: boolean }} [opts]
   */
  async function run({ noCache = false } = {}) {
    if (destroyed) return;
    if (controller) controller.abort();
    if (checkController) checkController.abort();
    if (!ctx.requireOnline()) return;
    controller = new AbortController();
    const mine = controller;
    asked = 0;
    clear(body);
    body.append(h('div', { class: 'xpl-running cluster' }, Spinner({ size: 'sm' }), h('span', { class: 'text-sm' }, t('xpl.running'))));
    runBtn.setAttribute('aria-busy', 'true');
    el.dataset.state = 'running';
    try {
      const client = await ctx.getDns();
      const result = await explainName(name, { dns: dnsFor(client, noCache), signal: mergeSignals(ctx.signal, mine.signal), known: noCache ? new Map() : known() });
      if (destroyed || controller !== mine) return;
      render({ ...result, at: new Date() });
      el.dataset.state = 'done';
      announce(`${t('xpl.title')}: ${name}`);
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      if (destroyed || controller !== mine) return;
      clear(body);
      body.append(Alert({ variant: 'error', compact: true, message: `${t('error.title')}: ${err && err.message ? err.message : String(err)}` }));
      el.dataset.state = 'error';
    } finally {
      if (controller === mine) {
        controller = null;
        runBtn.removeAttribute('aria-busy');
      }
    }
  }

  function destroy() {
    destroyed = true;
    if (controller) controller.abort();
    if (checkController) checkController.abort();
    controller = null;
    checkController = null;
    el.remove();
  }

  return { el, run, destroy };
}
