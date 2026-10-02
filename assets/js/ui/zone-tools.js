/**
 * ui/zone-tools.js — the Zone File's Compare and Convert tabs, loaded on their first use. The
 * logic is lib/zonediff.js (the semantic diff of two zones) and lib/zoneconvert.js (BIND, Route 53,
 * octoDNS, DNSControl); this module only renders it.
 *
 * - Nothing is sent: the second zone is read in the browser like the first and kept on the
 *   holder the Zone File view owns (`C`, its module session, never a URL or storage); Forget, a
 *   workspace switch or "Delete all local data" drop it with the first. "Forget the second zone"
 *   drops only it.
 * - Exports of a comparison hide the origin addresses of proxied records (both zones') unless the
 *   user opts in, like the live check's; Copy summary names record sets by name and type, never a
 *   value, and links a bare #/zone.
 * - A converted file holds every record it can write, origin addresses included: it is the zone,
 *   in another format, downloaded on a click.
 * - Every string is rendered through h() / text nodes: record values are DNS data.
 *
 * It lives in ui/ (not views/) because every views/*.js module is a routed view.
 */

import { h, clear } from './dom.js';
import {
  Alert, Badge, Button, Card, CodeBlock, CopyButton, DataTable, Disclosure, FileDrop, Icon, SegmentedControl, SeverityIcon,
  announce, checkbox, textInput, textarea, toast
} from './components.js';
import { downloadText } from './download.js';
import { SummaryButton } from './summary-button.js';
import { permalinkParams } from './view-summaries.js';
import { t, registerStrings, formatNumber, formatBytes } from '../i18n.js';
import {
  diffZones, diffFilter, diffCsv, diffJson, diffSummaryFacts, DIFF_DEFAULTS, DIFF_OPTIONS, DIFF_STATUSES, DIFF_REASONS, DIFF_NOTES
} from '../lib/zonediff.js';
import { convertZone, CONVERT_TARGETS, TARGET_NAMES, pitfallKey, pitfallKeys, ALIAS_ZONE_PLACEHOLDER } from '../lib/zoneconvert.js';

/** Files the second zone's importer accepts (the same as the first). */
const ACCEPT = '.txt,.zone,.db,.bind,.json,.yaml,.yml,.hosts';
/** At most this many files for the second zone. */
const MAX_FILES = 20;
/** A preview shows at most this many lines; the download has them all. */
export const PREVIEW_LINES = 400;
/** At most this many names under a note before "+N more". */
const NOTE_NAMES = 6;
/** Status → badge variant (diff colours: added green, removed red). */
const STATUS_VARIANT = Object.freeze({ added: 'ok', removed: 'error', changed: 'warn', same: 'neutral', ignored: 'neutral' });
/** The chips over the table, in order (`diff`: added, removed and changed). */
const CHIPS = Object.freeze(['diff', 'added', 'removed', 'changed', 'same', 'ignored', 'all']);

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

const STRINGS = [
  ['zcmp.title', ['Compare with another zone', 'Başka bir zone ile karşılaştırın']],
  ['zcmp.lead', ['Load a second export of this zone — from another provider, or an older copy — and see what differs record set by record set: the values, the TTLs and Cloudflare’s proxy, never the text of the files.',
    'Bu zone’un ikinci bir dışa aktarımını (başka bir sağlayıcıdan ya da eski bir kopyadan) yükleyin ve farkları kayıt kümesi bazında görün: dosyaların metni değil; değerler, TTL’ler ve Cloudflare proxy’si karşılaştırılır.']],
  ['zcmp.privacy', ['The second file is read in this browser and kept only in this tab’s memory, like the first: nothing is uploaded or saved. Forget clears both.',
    'İkinci dosya da ilki gibi bu tarayıcıda okunur ve yalnızca bu sekmenin belleğinde tutulur: hiçbir şey yüklenmez ya da kaydedilmez. “Unut” ikisini de temizler.']],
  ['zcmp.drop.title', ['Drop the other zone export here, choose a file or paste it', 'Diğer zone dışa aktarımını buraya bırakın, dosya seçin ya da yapıştırın']],
  ['zcmp.drop.hint', ['Any format Zone File reads: BIND, Cloudflare API JSON, Route 53 JSON or a change batch, octoDNS YAML',
    'Zone Dosyası’nın okuduğu her biçim: BIND, Cloudflare API JSON, Route 53 JSON ya da değişiklik paketi, octoDNS YAML']],
  ['zcmp.paste.summary', ['…or paste the text', '…ya da metni yapıştırın']],
  ['zcmp.paste.label', ['The other zone’s text', 'Diğer zone’un metni']],
  ['zcmp.run', ['Compare', 'Karşılaştır']],
  ['zcmp.origin.label', ['Zone name of the other file', 'Diğer dosyanın zone adı']],
  ['zcmp.origin.placeholder', ['detected from the file', 'dosyadan algılanır']],
  ['zcmp.origin.hint', ['Detected from the file; this zone’s name when the file names none.', 'Dosyadan algılanır; dosya bir ad belirtmiyorsa bu zone’un adı kullanılır.']],
  ['zcmp.samples', ['Or compare with a sample:', 'Ya da bir örnekle karşılaştırın:']],
  ['zcmp.other', ['Compared with {origin}', '{origin} ile karşılaştırıldı']],
  ['zcmp.otherNoOrigin', ['Compared with a zone of unknown name', 'Adı bilinmeyen bir zone ile karşılaştırıldı']],
  ['zcmp.otherCounts', [{ one: '{count} record · {files}', other: '{count} records · {files}' }, '{count} kayıt · {files}']],
  ['zcmp.replace', ['Load another file', 'Başka bir dosya yükle']],
  ['zcmp.forget', ['Forget the second zone', 'İkinci zone’u unut']],
  ['zcmp.forgotten', ['Second zone forgotten', 'İkinci zone unutuldu']],
  ['zcmp.loaded', [{ one: 'Compared: {count} difference', other: 'Compared: {count} differences' }, 'Karşılaştırıldı: {count} fark']],
  ['zcmp.fatal', ['The other file could not be read', 'Diğer dosya okunamadı']],
  ['zcmp.relative', ['The zones have different names ({a} and {b}): names are compared relative to each zone, so www.{a} matches www.{b}.',
    'Zone’ların adları farklı ({a} ve {b}): adlar her zone’a göre göreli karşılaştırılır, yani www.{a} ile www.{b} eşleşir.']],
  ['zcmp.options', ['Comparison options', 'Karşılaştırma seçenekleri']],
  ['zcmp.opt.ignoreTtl', ['Ignore TTL differences', 'TTL farklarını yok say']],
  ['zcmp.opt.joinTxt', ['TXT strings split differently are the same (the strings are joined)', 'Farklı bölünmüş TXT dizileri aynı sayılır (diziler birleştirilir)']],
  ['zcmp.opt.ignoreSoa', ['Ignore the SOA serial and timers (its name server and mailbox still count)', 'SOA seri numarasını ve zamanlayıcılarını yok say (ad sunucusu ve e-posta adresi yine sayılır)']],
  ['zcmp.opt.ignoreApexNs', ['Ignore NS at the apex (two providers each name their own servers)', 'Zone kökündeki (apex) NS kayıtlarını yok say (iki sağlayıcı da kendi sunucularını yazar)']],
  ['zcmp.legend', ['This zone is the starting point: “added” is only in the other one, “removed” only in this one.',
    'Başlangıç noktası bu zone: “eklendi” yalnızca diğerinde, “kaldırıldı” yalnızca bunda olan demektir.']],
  ['zcmp.head.same', [{ one: 'No differences: the {count} record set is the same.', other: 'No differences: all {count} record sets are the same.' },
    'Fark yok: {count} kayıt kümesinin hepsi aynı.']],
  ['zcmp.head.diff', [{ one: '{count} difference: {added} added, {removed} removed, {changed} changed; {same} record sets the same.',
    other: '{count} differences: {added} added, {removed} removed, {changed} changed; {same} record sets the same.' },
  '{count} fark: {added} eklendi, {removed} kaldırıldı, {changed} değişti; {same} kayıt kümesi aynı.']],
  ['zcmp.head.ignored', [{ one: '{count} record set ignored.', other: '{count} record sets ignored.' }, '{count} kayıt kümesi yok sayıldı.']],
  ['zcmp.summaryLabel', ['Summary of the comparison', 'Karşılaştırmanın özeti']],
  ['zcmp.filter', ['Show', 'Göster']],
  ['zcmp.filter.diff', ['Differences', 'Farklar']],
  ['zcmp.filter.all', ['All', 'Tümü']],
  ['zcmp.st.added', ['Added', 'Eklendi']],
  ['zcmp.st.removed', ['Removed', 'Kaldırıldı']],
  ['zcmp.st.changed', ['Changed', 'Değişti']],
  ['zcmp.st.same', ['Same', 'Aynı']],
  ['zcmp.st.ignored', ['Ignored', 'Yok sayıldı']],
  ['zcmp.col.status', ['Status', 'Durum']],
  ['zcmp.col.name', ['Name', 'Ad']],
  ['zcmp.col.type', ['Type', 'Tür']],
  ['zcmp.col.a', ['This zone', 'Bu zone']],
  ['zcmp.col.b', ['Other zone', 'Diğer zone']],
  ['zcmp.col.note', ['Note', 'Not']],
  ['zcmp.reason.values', ['Values differ.', 'Değerler farklı.']],
  ['zcmp.reason.ttl', ['The TTL differs: {a} → {b}.', 'TTL farklı: {a} → {b}.']],
  ['zcmp.reason.proxied', ['Cloudflare’s proxy differs: {a} → {b}.', 'Cloudflare proxy’si farklı: {a} → {b}.']],
  ['zcmp.reason.routing', ['The routing policy differs.', 'Yönlendirme politikası farklı.']],
  ['zcmp.reason.soa-names', ['The SOA names another primary name server or mailbox.', 'SOA başka bir birincil ad sunucusu ya da e-posta adresi belirtiyor.']],
  ['zcmp.reason.soa-serial', ['The SOA serial differs.', 'SOA seri numarası farklı.']],
  ['zcmp.reason.soa-timers', ['The SOA timers differ.', 'SOA zamanlayıcıları farklı.']],
  ['zcmp.note.ttl-ignored', ['The TTL differs ({a} → {b}), ignored.', 'TTL farklı ({a} → {b}), yok sayıldı.']],
  ['zcmp.note.txt-split', ['The same text, split into strings differently.', 'Aynı metin, dizilere farklı bölünmüş.']],
  ['zcmp.note.soa-ignored', ['The serial, the timers or the TTL differ, ignored.', 'Seri numarası, zamanlayıcılar ya da TTL farklı, yok sayıldı.']],
  ['zcmp.note.soa-one-side', ['Only one file has an SOA record (a provider’s export leaves it out), ignored.', 'SOA kaydı yalnızca bir dosyada var (sağlayıcı dışa aktarımları onu içermez), yok sayıldı.']],
  ['zcmp.note.apex-ns', ['NS at the apex, ignored.', 'Zone kökündeki (apex) NS, yok sayıldı.']],
  ['zcmp.note.not-in-batch', ['Not in the change batch: it does not change this set, so this is no difference.', 'Değişiklik paketinde yok: paket bu kümeyi değiştirmiyor, yani bu bir fark değil.']],
  ['zcmp.note.batch-delete', ['The change batch deletes this set.', 'Değişiklik paketi bu kümeyi siliyor.']],
  ['zcmp.note.partial', ['The file without this set is incomplete: the set may be in the part that is missing.', 'Bu kümenin olmadığı dosya eksik: küme, dosyanın eksik kısmında olabilir.']],
  ['zcmp.batch.title', ['A change batch, not a zone', 'Bir zone değil, bir değişiklik paketi']],
  ['zcmp.batch', ['The other file is a Route 53 change batch, not a whole zone (created or updated: {upserts}, deleted: {deletes}). Only the record sets it changes are compared: the rest of this zone shows as ignored, “not in the change batch”, never as removed.',
    'Diğer dosya bütün bir zone değil, bir Route 53 değişiklik paketi (oluşturulan ya da güncellenen: {upserts}, silinen: {deletes}). Yalnızca değiştirdiği kayıt kümeleri karşılaştırılır: bu zone’un geri kalanı kaldırıldı olarak değil, “değişiklik paketinde yok” notuyla yok sayıldı olarak görünür.']],
  ['zcmp.batchThis', ['This zone’s file is a Route 53 change batch, not a whole zone: only the record sets it changes are compared, and the other file’s other record sets show as ignored, never as added.',
    'Bu zone’un dosyası bütün bir zone değil, bir Route 53 değişiklik paketi: yalnızca değiştirdiği kayıt kümeleri karşılaştırılır; diğer dosyanın öteki kayıt kümeleri eklendi olarak değil, yok sayıldı olarak görünür.']],
  ['zcmp.partial', ['Record sets missing from it show as removed, though they may only be in the part that is missing.', 'Onda olmayan kayıt kümeleri kaldırıldı olarak görünür; oysa yalnızca eksik kısımda olabilirler.']],
  ['zcmp.partialThis', ['This zone’s export is incomplete: record sets missing from it show as added, though they may only be in the part that is missing.',
    'Bu zone’un dışa aktarımı eksik: onda olmayan kayıt kümeleri eklendi olarak görünür; oysa yalnızca eksik kısımda olabilirler.']],
  ['zcmp.guessed', ['The other file names no zone: its name was guessed from its records. If it is wrong, type the right one under “Load another file”.',
    'Diğer dosya bir zone adı belirtmiyor: adı kayıtlarından tahmin edildi. Yanlışsa doğrusunu “Başka bir dosya yükle” altına yazın.']],
  ['zcmp.problems', [{ one: '{count} problem reading the other file', other: '{count} problems reading the other file' }, 'Diğer dosya okunurken çıkan {count} sorun']],
  ['zcmp.proxy.true', ['proxied', 'proxy’li']],
  ['zcmp.proxy.false', ['DNS only', 'yalnızca DNS']],
  ['zcmp.proxy.mixed', ['mixed', 'karışık']],
  ['zcmp.includeOrigins', ['Include origin addresses in exports', 'Dışa aktarımlara origin adreslerini ekle']],
  ['zcmp.empty', ['Nothing to show with this filter.', 'Bu filtreyle gösterilecek bir şey yok.']],

  ['zconv.title', ['Convert for another tool or provider', 'Başka bir araç ya da sağlayıcı için dönüştürün']],
  ['zconv.lead', ['The imported zone as a file for the place it moves to, built in this browser: nothing is sent. Read the notes first: they say what a format cannot hold and what changes.',
    'İçe aktarılan zone, taşınacağı yer için bu tarayıcıda bir dosyaya dönüştürülür: hiçbir şey gönderilmez. Önce notları okuyun: bir biçimin neyi tutamadığını ve neyin değiştiğini gösterirler.']],
  ['zconv.format', ['Format', 'Biçim']],
  ['zconv.t.bind', ['BIND zone file', 'BIND zone dosyası']],
  ['zconv.t.route53', ['Route 53 change batch', 'Route 53 değişiklik paketi']],
  ['zconv.t.octodns', ['octoDNS YAML', 'octoDNS YAML']],
  ['zconv.t.dnscontrol', ['DNSControl', 'DNSControl']],
  ['zconv.desc.bind', ['RFC 1035 with $ORIGIN and $TTL: for BIND, Knot, NSD, PowerDNS or a provider’s zone import.',
    '$ORIGIN ve $TTL içeren RFC 1035: BIND, Knot, NSD, PowerDNS ya da bir sağlayıcının zone içe aktarması için.']],
  ['zconv.desc.route53', ['Every record set as an UPSERT, for aws route53 change-resource-record-sets --change-batch file://… (the hosted zone keeps its own SOA and NS).',
    'Her kayıt kümesi bir UPSERT olarak; aws route53 change-resource-record-sets --change-batch file://… için (barındırılan zone kendi SOA ve NS kayıtlarını korur).']],
  ['zconv.desc.octodns', ['The zone’s YAML for octoDNS’s YamlProvider, its keys in the order octoDNS checks.',
    'octoDNS YamlProvider için zone’un YAML’ı; anahtarlar octoDNS’in denetlediği sırada.']],
  ['zconv.desc.dnscontrol', ['dnsconfig.js with D("…", REG_NONE, DnsProvider(…), …): name the provider’s entry of creds.json in it.',
    'D("…", REG_NONE, DnsProvider(…), …) içeren dnsconfig.js: içinde creds.json’daki sağlayıcı girdisinin adını belirtin.']],
  ['zconv.written', [{ one: '{count} record written', other: '{count} records written' }, '{count} kayıt yazıldı']],
  ['zconv.left', [{ one: '{count} not written as it is (see the notes)', other: '{count} not written as they are (see the notes)' }, '{count} kayıt olduğu gibi yazılmadı (notlara bakın)']],
  ['zconv.notes', ['Notes for {target}', '{target} için notlar']],
  ['zconv.noNotes', ['Nothing to watch out for: every record is written as it is.', 'Dikkat edilecek bir şey yok: her kayıt olduğu gibi yazıldı.']],
  ['zconv.countTitle', [{ one: '{count} record', other: '{count} records' }, '{count} kayıt']],
  ['zconv.download', ['Download {file}', '{file} dosyasını indir']],
  ['zconv.copy', ['Copy all', 'Tümünü kopyala']],
  ['zconv.preview', ['Preview', 'Önizleme']],
  ['zconv.previewCut', ['The preview shows the first {shown} of {total} lines; the download and Copy all have them all.',
    'Önizleme {total} satırın ilk {shown} tanesini gösteriyor; indirilen dosyada ve Tümünü kopyala’da hepsi var.']],
  ['zconv.privacy', ['The file holds every record it can write, origin addresses included: share it as you would share the zone export itself.',
    'Dosya, yazılabilen her kaydı origin adresleri dahil içerir: onu zone dışa aktarımının kendisi kadar özenle paylaşın.']],
  ['zconv.downloaded', ['{file} downloaded', '{file} indirildi']],
  ['zconv.filesLead', ['Send them to Route 53 one after another, in this order:', 'Onları Route 53’e bu sırayla, birbiri ardına gönderin:']],
  ['zconv.filesLabel', ['The change batches', 'Değişiklik paketleri']],
  ['zconv.downloadPart', ['Download', 'İndir']],
  ['zconv.copyPart', ['Copy', 'Kopyala']],
  ['zconv.copyFile', ['Copy {file}', '{file} dosyasını kopyala']],
  ['zconv.previewPart', ['The preview shows {file}, the first of {count} files.', 'Önizleme, {count} dosyanın ilki olan {file} dosyasını gösteriyor.']],
  ['zconv.previewPartCut', ['The preview shows the first {shown} of the {total} lines of {file}, the first of {count} files; its download and Copy have them all.',
    'Önizleme, {count} dosyanın ilki olan {file} dosyasının {total} satırından ilk {shown} tanesini gösteriyor; indirilen dosyada ve Kopyala’da hepsi var.']],

  ['zconv.pit.cname-apex.bind', ['CNAME at the apex: BIND cannot serve it next to the SOA and NS records, so it is commented out. Add A / AAAA records of its target instead (or ALIAS / ANAME if your name server has them).',
    'Zone kökünde (apex) CNAME: BIND onu SOA ve NS kayıtlarının yanında sunamaz, bu yüzden yorum satırına çevrildi. Yerine hedefinin A / AAAA kayıtlarını ekleyin (ad sunucunuzda varsa ALIAS / ANAME de olur).']],
  ['zconv.pit.cname-apex.route53', ['CNAME at the apex: Route 53 has none, so it is left out. A Route 53 alias can stand in only for an AWS target (CloudFront, a load balancer, S3 …) or another record of the same zone; for any other target add its A / AAAA records.',
    'Zone kökünde (apex) CNAME: Route 53’te yoktur, bu yüzden dışarıda bırakıldı. Bir Route 53 alias’ı yalnızca bir AWS hedefinin (CloudFront, yük dengeleyici, S3 …) ya da aynı zone’daki başka bir kaydın yerini tutabilir; başka bir hedef için onun A / AAAA kayıtlarını ekleyin.']],
  ['zconv.pit.cname-apex.octodns', ['CNAME at the apex: written as an ALIAS record, which octoDNS allows only at the apex. The provider must support ALIAS or CNAME flattening (Cloudflare’s, for example).',
    'Zone kökünde (apex) CNAME: octoDNS’in yalnızca zone kökünde izin verdiği bir ALIAS kaydı olarak yazıldı. Sağlayıcının ALIAS ya da CNAME düzleştirmeyi (örneğin Cloudflare’inkini) desteklemesi gerekir.']],
  ['zconv.pit.cname-apex.dnscontrol', ['CNAME at the apex: written as ALIAS("@", …). DNSControl accepts it only for providers that can flatten it (Cloudflare, for example); the others refuse it at preview.',
    'Zone kökünde (apex) CNAME: ALIAS("@", …) olarak yazıldı. DNSControl bunu yalnızca onu düzleştirebilen sağlayıcılarda (örneğin Cloudflare) kabul eder; diğerleri preview sırasında reddeder.']],
  ['zconv.pit.cname-alone', ['A CNAME that is not alone at its name (next to other records, or several CNAMEs): {target} refuses it. Keep either the CNAME or the other records (Zone File › Problems lists them).',
    'Kendi adında tek başına olmayan CNAME (başka kayıtlarla birlikte ya da birden fazla CNAME): {target} bunu reddeder. Ya CNAME’i ya da diğer kayıtları tutun (Zone Dosyası › Sorunlar bunları listeler).']],
  ['zconv.pit.r53-alias.bind', ['Route 53 alias: BIND has no equivalent, so it is commented out. Resolve the alias target and add its A / AAAA records, or keep these names at Route 53.',
    'Route 53 alias’ı: BIND’de karşılığı yok, bu yüzden yorum satırına çevrildi. Alias hedefini çözümleyip A / AAAA kayıtlarını ekleyin ya da bu adları Route 53’te tutun.']],
  ['zconv.pit.r53-alias.octodns', ['Route 53 alias: left out. octoDNS writes aliases only with the Route 53 provider’s own alias type (see octodns-route53); add them there by hand.',
    'Route 53 alias’ı: dışarıda bırakıldı. octoDNS alias’ları yalnızca Route 53 sağlayıcısının kendi alias türüyle yazar (octodns-route53’e bakın); onları orada elle ekleyin.']],
  ['zconv.pit.r53-alias.dnscontrol', ['Route 53 alias: written as R53_ALIAS(…), which works only with DNSControl’s Route 53 provider.',
    'Route 53 alias’ı: R53_ALIAS(…) olarak yazıldı; bu yalnızca DNSControl’ün Route 53 sağlayıcısıyla çalışır.']],
  ['zconv.pit.alias-zone-id', ['The source does not name the hosted zone of these alias targets: replace {placeholder} with it before you send the batch.',
    'Kaynak, bu alias hedeflerinin barındırılan zone’unu (hosted zone) belirtmiyor: paketi göndermeden önce {placeholder} yerine onu yazın.']],
  ['zconv.pit.alias-record.octodns', ['ALIAS / ANAME record at the apex: written as an ALIAS record; the octoDNS provider must support ALIAS or CNAME flattening.',
    'Zone kökünde (apex) ALIAS / ANAME kaydı: ALIAS kaydı olarak yazıldı; octoDNS sağlayıcısının ALIAS’ı ya da CNAME düzleştirmeyi desteklemesi gerekir.']],
  ['zconv.pit.alias-record.dnscontrol', ['ALIAS / ANAME records: written as ALIAS(…), which DNSControl accepts only for providers that can serve it; the others refuse it at preview.',
    'ALIAS / ANAME kayıtları: ALIAS(…) olarak yazıldı; DNSControl bunu yalnızca onu sunabilen sağlayıcılarda kabul eder, diğerleri preview sırasında reddeder.']],
  ['zconv.pit.proxied.bind', ['Cloudflare proxy: BIND serves the record’s own address, which is the origin. The flags stay as cf_tags comments.',
    'Cloudflare proxy’si: BIND kaydın kendi adresini, yani origin’i sunar. İşaretler cf_tags yorumları olarak kalır.']],
  ['zconv.pit.proxied.route53', ['Cloudflare proxy: Route 53 has none. These names would point straight at their origin servers and make their addresses public.',
    'Cloudflare proxy’si: Route 53’te yok. Bu adlar doğrudan origin sunucularına işaret eder ve adreslerini herkese açık hale getirir.']],
  ['zconv.pit.proxied.octodns', ['Cloudflare proxy: kept as octodns.cloudflare.proxied, which only the Cloudflare provider reads; any other provider serves the origin address.',
    'Cloudflare proxy’si: octodns.cloudflare.proxied olarak korundu; bunu yalnızca Cloudflare sağlayıcısı okur, diğer sağlayıcılar origin adresini sunar.']],
  ['zconv.pit.proxied.dnscontrol', ['Cloudflare proxy: kept as CF_PROXY_ON, which only the Cloudflare provider reads; any other provider serves the origin address.',
    'Cloudflare proxy’si: CF_PROXY_ON olarak korundu; bunu yalnızca Cloudflare sağlayıcısı okur, diğer sağlayıcılar origin adresini sunar.']],
  ['zconv.pit.proxied-mixed', ['Proxied and DNS-only records in one set: octoDNS has one proxy flag per set, so these DNS-only records become proxied (as Cloudflare treats the name anyway).',
    'Aynı kümede proxy’li ve yalnızca DNS kayıtlar: octoDNS’te küme başına tek bir proxy işareti var; bu yüzden bu yalnızca DNS kayıtlar proxy’li olur (Cloudflare adı zaten böyle ele alır).']],
  ['zconv.pit.cname-flatten', ['Cloudflare flattens these CNAMEs; this file serves them as plain CNAMEs, which resolvers follow themselves.',
    'Cloudflare bu CNAME’leri düzleştirir; bu dosya onları düz CNAME olarak sunar, çözümleyiciler onları kendileri izler.']],
  ['zconv.pit.txt-long.bind', ['TXT over 255 bytes: written as several quoted character-strings of at most 255 bytes in one record, as RFC 1035 requires (a longer string in the source is split); the receiver joins them.',
    '255 bayttan uzun TXT: RFC 1035’in istediği gibi tek kayıtta, her biri en fazla 255 bayt olan birden çok tırnaklı karakter dizisi olarak yazıldı (kaynaktaki daha uzun bir dizi bölündü); alıcı onları birleştirir.']],
  ['zconv.pit.txt-long.route53', ['TXT over 255 bytes: one value of several quoted strings ("…" "…"), at most 255 bytes each (a longer one in the source is split) and 4,000 characters in all.',
    '255 bayttan uzun TXT: her biri en fazla 255 bayt olan (kaynaktaki daha uzun bir dizi bölündü), toplamda en fazla 4.000 karakterlik birden çok tırnaklı diziden ("…" "…") oluşan tek değer.']],
  ['zconv.pit.txt-long.octodns', ['TXT over 255 bytes: written as one text; the octoDNS provider splits it into 255-byte strings when it sends it.',
    '255 bayttan uzun TXT: tek metin olarak yazıldı; octoDNS sağlayıcısı onu gönderirken 255 baytlık dizilere böler.']],
  ['zconv.pit.txt-long.dnscontrol', ['TXT over 255 bytes: written as one string; DNSControl splits it into 255-byte strings itself.',
    '255 bayttan uzun TXT: tek bir dizi olarak yazıldı; DNSControl onu kendisi 255 baytlık dizilere böler.']],
  ['zconv.pit.txt-split', ['TXT split into strings at other points than every 255 bytes: {target} keeps the joined text and splits it again, so the strings change (the text does not).',
    '255 baytta bir değil, başka yerlerden dizilere bölünmüş TXT: {target} birleştirilmiş metni tutar ve yeniden böler; diziler değişir (metin değişmez).']],
  ['zconv.pit.txt-bytes', ['TXT values that are not UTF-8 text (raw bytes): {target} keeps a TXT value as text, so these records are left out; add them by hand.',
    'UTF-8 metin olmayan TXT değerleri (ham baytlar): {target} bir TXT değerini metin olarak tutar, bu yüzden bu kayıtlar dışarıda bırakıldı; onları elle ekleyin.']],
  ['zconv.pit.caa-flags', ['CAA flags other than 0 or 128 ({flags}): many providers accept only these two.',
    '0 ya da 128 dışında CAA bayrakları ({flags}): birçok sağlayıcı yalnızca bu ikisini kabul eder.']],
  ['zconv.pit.caa-flags.dnscontrol', ['CAA flags other than 0 or 128 ({flags}): DNSControl writes only CAA_CRITICAL (128), so these flags are lost.',
    '0 ya da 128 dışında CAA bayrakları ({flags}): DNSControl yalnızca CAA_CRITICAL’ı (128) yazar, bu yüzden bu bayraklar kaybolur.']],
  ['zconv.pit.caa-tag', ['CAA tag {tags}: not one of issue, issuewild, iodef, issuemail, issuevmc, contactemail or contactphone; a provider may refuse it, and a CA ignores a tag it does not know.',
    'CAA etiketi {tags}: issue, issuewild, iodef, issuemail, issuevmc, contactemail ya da contactphone değil; bir sağlayıcı onu reddedebilir, bir CA da tanımadığı etiketi yok sayar.']],
  ['zconv.pit.caa-tag.dnscontrol', ['CAA tag {tags}: DNSControl accepts only issue, issuewild, iodef, issuemail, issuevmc, contactemail and contactphone, and refuses the whole file over any other; kept as a comment.',
    'CAA etiketi {tags}: DNSControl yalnızca issue, issuewild, iodef, issuemail, issuevmc, contactemail ve contactphone etiketlerini kabul eder, başka bir etiket yüzünden tüm dosyayı reddeder; yorum satırı olarak bırakıldı.']],
  ['zconv.pit.svc-key', ['HTTPS / SVCB parameters written by number ({keys}: key5 for ech, key7 for dohpath …): octoDNS has no name for them, or its check of ech fails; they mean the same.',
    'Numaralarıyla yazılan HTTPS / SVCB parametreleri ({keys}: ech için key5, dohpath için key7 …): octoDNS’te adları yok ya da ech denetimi hata veriyor; anlamları aynıdır.']],
  ['zconv.pit.txt-lenient', ['TXT text octoDNS’s check refuses (characters outside ASCII, or a \\ before a ;): written with octodns.lenient, so octoDNS loads it with a warning.',
    'octoDNS denetiminin reddettiği TXT metni (ASCII dışı karakterler ya da ; öncesinde bir \\): octodns.lenient ile yazıldı; octoDNS onu bir uyarıyla yükler.']],
  ['zconv.pit.name-lenient', ['{types} records not at a _service._proto name (such as _sip._tcp): octoDNS refuses them, so they are written with octodns.lenient; clients look them up only at such names.',
    '_service._proto biçiminde (_sip._tcp gibi) olmayan adlardaki {types} kayıtları: octoDNS onları reddeder, bu yüzden octodns.lenient ile yazıldı; istemciler onları yalnızca bu biçimdeki adlarda arar.']],
  ['zconv.pit.unsupported-type.bind', ['{types} records: provider record types a BIND server does not serve; commented out.',
    '{types} kayıtları: bir BIND sunucusunun sunmadığı, sağlayıcıya özgü kayıt türleri; yorum satırına çevrildi.']],
  ['zconv.pit.unsupported-type', ['{types} records: {target} does not support them; left out.', '{types} kayıtları: {target} bunları desteklemiyor; dışarıda bırakıldı.']],
  ['zconv.pit.by-hand', ['{types} records: {target} has them, but DomainScope cannot write them from this file; left out, add them by hand.',
    '{types} kayıtları: {target} bunları destekler, ama DomainScope onları bu dosyadan yazamıyor; dışarıda bırakıldı, elle ekleyin.']],
  ['zconv.pit.unreadable.bind', ['Records whose value could not be read (invalid, or a form DomainScope cannot decode): commented out as the file has them.',
    'Değeri okunamayan kayıtlar (geçersiz ya da DomainScope’un çözemediği bir biçim): dosyadaki halleriyle yorum satırına çevrildi.']],
  ['zconv.pit.unreadable', ['Records whose value could not be read (invalid, or a form DomainScope cannot decode): left out.',
    'Değeri okunamayan kayıtlar (geçersiz ya da DomainScope’un çözemediği bir biçim): dışarıda bırakıldı.']],
  ['zconv.pit.dnssec.bind', ['DNSSEC records copied as they are: their signatures hold only for the zone as it was. Sign the zone again on the new server.',
    'DNSSEC kayıtları olduğu gibi kopyalandı: imzaları yalnızca zone’un eski hali için geçerli. Zone’u yeni sunucuda yeniden imzalayın.']],
  ['zconv.pit.dnssec', ['DNSSEC records (DNSKEY, RRSIG, NSEC …): left out. The new provider signs the zone itself; change the DS at the registrar in the right order (Zone File › New name servers says how).',
    'DNSSEC kayıtları (DNSKEY, RRSIG, NSEC …): dışarıda bırakıldı. Yeni sağlayıcı zone’u kendisi imzalar; kayıt kuruluşundaki DS’i doğru sırayla değiştirin (Zone Dosyası › Yeni ad sunucuları nasıl yapılacağını anlatır).']],
  ['zconv.pit.routing.bind', ['Routing variants (weighted, geo, latency …): BIND serves every variant together; the policy stays only as a comment.',
    'Yönlendirme varyantları (ağırlıklı, coğrafi, gecikme …): BIND tüm varyantları birlikte sunar; politika yalnızca yorum olarak kalır.']],
  ['zconv.pit.routing.route53', ['Routing variants of a kind a change batch cannot write (octoDNS pools, geoproximity, IP-based …): merged into one plain record set.',
    'Bir değişiklik paketinin yazamadığı türde yönlendirme varyantları (octoDNS havuzları, geoproximity, IP tabanlı …): tek bir düz kayıt kümesinde birleştirildi.']],
  ['zconv.pit.routing.octodns', ['Routing variants (weighted, geo, latency …): merged into one plain record; write octoDNS dynamic records for them by hand.',
    'Yönlendirme varyantları (ağırlıklı, coğrafi, gecikme …): tek bir düz kayıtta birleştirildi; bunlar için octoDNS dynamic kayıtlarını elle yazın.']],
  ['zconv.pit.routing.dnscontrol', ['Routing variants (weighted, geo, latency …): DNSControl has no routing policies, so they are merged into one plain record set.',
    'Yönlendirme varyantları (ağırlıklı, coğrafi, gecikme …): DNSControl’de yönlendirme politikası yok, bu yüzden tek bir düz kayıt kümesinde birleştirildi.']],
  ['zconv.pit.out-of-zone.bind', ['Names outside the zone: written as absolute names, but a name server ignores them (or refuses the file).',
    'Zone dışındaki adlar: mutlak adlar olarak yazıldı, ama bir ad sunucusu onları yok sayar (ya da dosyayı reddeder).']],
  ['zconv.pit.out-of-zone', ['Names outside the zone: left out; name servers ignore them anyway.', 'Zone dışındaki adlar: dışarıda bırakıldı; ad sunucuları onları zaten yok sayar.']],
  ['zconv.pit.wildcard-inner', ['A * that is not the first label is an ordinary character, not a wildcard (RFC 4592); most providers refuse it.',
    'İlk etiket olmayan bir *, joker değil sıradan bir karakterdir (RFC 4592); çoğu sağlayıcı onu reddeder.']],
  ['zconv.pit.escaped-name', ['Names with characters that need escapes (a space, a dot or a quote inside a label …): providers and tools may refuse them.',
    'Kaçış gerektiren karakterler içeren adlar (bir etiketin içinde boşluk, nokta ya da tırnak …): sağlayıcılar ve araçlar onları reddedebilir.']],
  ['zconv.pit.repeated-domain', ['Names that repeat the zone name ({zone}.{zone} and the like, often a final dot the source left out): written with DISABLE_REPEATED_DOMAIN_CHECK, without which DNSControl refuses them. Check that they are meant.',
    'Zone adını tekrarlayan adlar ({zone}.{zone} gibi; çoğu zaman kaynakta unutulmuş bir son nokta): DNSControl bunları DISABLE_REPEATED_DOMAIN_CHECK olmadan reddeder, bu yüzden onunla yazıldı. Gerçekten böyle olmaları gerektiğini kontrol edin.']],
  ['zconv.pit.no-soa', ['The source has no SOA record (a provider’s export often leaves it out): add one before a name server loads this file.',
    'Kaynakta SOA kaydı yok (sağlayıcı dışa aktarımları onu çoğu zaman içermez): bir ad sunucusu bu dosyayı yüklemeden önce bir tane ekleyin.']],
  ['zconv.pit.soa', ['SOA: left out; the provider writes its own.', 'SOA: dışarıda bırakıldı; sağlayıcı kendi SOA kaydını yazar.']],
  ['zconv.pit.apex-ns', ['NS at the apex: left out; the new provider serves its own name servers there. Delegations below the apex are kept.',
    'Zone kökündeki (apex) NS: dışarıda bırakıldı; yeni sağlayıcı orada kendi ad sunucularını sunar. Kökün altındaki yetki devirleri korundu.']],
  ['zconv.pit.wildcard', ['Wildcards answer only names that have no records of their own, not even of another type (RFC 4592).',
    'Joker kayıtlar yalnızca kendine ait hiçbir kaydı (başka türde bile) olmayan adları yanıtlar (RFC 4592).']],
  ['zconv.pit.wildcard.route53', ['Wildcards answer only names that have no records of their own (RFC 4592). Route 53 lists the * as \\052 in its own exports.',
    'Joker kayıtlar yalnızca kendine ait kaydı olmayan adları yanıtlar (RFC 4592). Route 53 kendi dışa aktarımlarında *’ı \\052 olarak listeler.']],
  ['zconv.pit.duplicate', ['Duplicate records: written once (providers refuse the same value twice).', 'Yinelenen kayıtlar: bir kez yazıldı (sağlayıcılar aynı değeri iki kez kabul etmez).']],
  ['zconv.pit.ttl-mixed', ['Values of one record set with different TTLs: the set gets the lowest (one TTL per set, RFC 2181).',
    'Aynı kayıt kümesinde farklı TTL’li değerler: kümeye en düşüğü verildi (küme başına tek TTL, RFC 2181).']],
  ['zconv.pit.ttl-default', ['Records without a TTL in the source: written with {ttl} s.', 'Kaynakta TTL’i olmayan kayıtlar: {ttl} sn ile yazıldı.']],
  ['zconv.pit.batch-size', ['Record sets Route 53 refuses in a change batch: more than {values} values (its limit for one set), or more than {chars} characters of values (an UPSERT counts each twice; a CREATE, counted once, takes twice as many if the set is new). Make them smaller.',
    'Route 53’ün bir değişiklik paketinde reddettiği kayıt kümeleri: {values} değerden fazlası (bir kümenin sınırı) ya da değerlerde {chars} karakterden fazlası (bir UPSERT her karakteri iki kez sayar; küme yeniyse bir kez sayan CREATE iki katını alır). Onları küçültün.']],
  ['zconv.pit.batch-split', ['{records} records: more than one change batch takes, as Route 53 counts every value and every character of an UPSERT twice (at most {max} records and {maxChars} characters of values in one batch). Written as {files} change batches.',
    '{records} kayıt: bir değişiklik paketinin alabileceğinden fazla, çünkü Route 53 bir UPSERT’teki her değeri ve her karakteri iki kez sayar (bir pakette en fazla {max} kayıt ve değerlerde {maxChars} karakter). {files} değişiklik paketi olarak yazıldı.']]
];

registerStrings('en', Object.fromEntries(STRINGS.map(([k, v]) => [k, v[0]])));
registerStrings('tr', Object.fromEntries(STRINGS.map(([k, v]) => [k, v[1]])));

/**
 * Every i18n key this module builds from a library code (for tests/js/i18n-coverage.test.js).
 * @returns {string[]}
 */
export function generatedKeys() {
  const keys = [...pitfallKeys()];
  for (const s of DIFF_STATUSES) keys.push(`zcmp.st.${s}`);
  for (const r of DIFF_REASONS) keys.push(`zcmp.reason.${r}`);
  for (const n of DIFF_NOTES) keys.push(`zcmp.note.${n}`);
  for (const o of DIFF_OPTIONS) keys.push(`zcmp.opt.${o}`);
  for (const target of CONVERT_TARGETS) keys.push(`zconv.t.${target}`, `zconv.desc.${target}`);
  for (const c of CHIPS) keys.push(c === 'diff' || c === 'all' ? `zcmp.filter.${c}` : `zcmp.st.${c}`);
  for (const p of ['true', 'false', 'mixed']) keys.push(`zcmp.proxy.${p}`);
  return keys;
}

/* ------------------------------------------------------------------------ */
/* Pure helpers (unit-tested)                                               */
/* ------------------------------------------------------------------------ */

/**
 * The text of one row's note: its reasons, then its notes, worded (TTLs and proxy flags with both sides).
 * @param {object} row lib/zonediff.js DiffRow
 * @returns {string}
 */
export function rowNote(row) {
  const ttl = (s) => (s && s.ttls.length ? s.ttls.map(formatNumber).join(', ') : '—');
  const proxy = (s) => (s && s.proxied !== null ? t(`zcmp.proxy.${s.proxied}`) : '—');
  const params = { a: ttl(row.a), b: ttl(row.b) };
  const out = row.reasons.map((r) => (r === 'proxied' ? t('zcmp.reason.proxied', { a: proxy(row.a), b: proxy(row.b) }) : t(`zcmp.reason.${r}`, params)));
  out.push(...row.notes.map((n) => t(`zcmp.note.${n}`, params)));
  return out.join(' ');
}

/**
 * A pitfall's text and its params as the texts expect them (lists joined).
 * @param {{ code: string, params: object }} p lib/zoneconvert.js pitfall
 * @param {string} target
 * @returns {string}
 */
export function pitfallText(p, target) {
  const params = { ...p.params, placeholder: ALIAS_ZONE_PLACEHOLDER };
  for (const k of ['types', 'flags', 'tags', 'keys']) if (Array.isArray(params[k])) params[k] = params[k].join(', ');
  for (const k of ['records', 'max', 'maxChars', 'files', 'values', 'chars']) if (Number.isFinite(params[k])) params[k] = formatNumber(params[k]);
  return t(pitfallKey(p.code, target), params);
}

/**
 * The second zone, read: under the name typed for it; else as the file names itself; else under
 * this zone's name when the file names none (ORIGIN_REQUIRED) or only guesses one from its records
 * (low confidence) and every name in it fits under this zone's — a change batch of one record
 * names no zone after that record.
 * @param {object[]} files
 * @param {{ zone: object, typed?: string, parse: (files: object[], opts: { origin: string|null }) => object }} opts
 * @returns {object} the parsed zone
 */
export function readOther(files, { zone, typed = '', parse }) {
  const name = String(typed || '').trim() || null;
  const other = parse(files, { origin: name });
  const own = zone && zone.origin ? zone.origin : null;
  if (name || !own) return other;
  if (other.fatal) return other.fatal.code === 'ORIGIN_REQUIRED' ? parse(files, { origin: own }) : other;
  if (other.originConfidence !== 'low' || !other.records.length) return other;
  return other.records.every((r) => r.name === own || r.name.endsWith(`.${own}`)) ? parse(files, { origin: own }) : other;
}

/* ------------------------------------------------------------------------ */
/* Compare                                                                  */
/* ------------------------------------------------------------------------ */

/** Holder defaults the view's session does not set (it keeps the holder, this module its shape). */
function ensureCompare(C) {
  if (!C.options) C.options = { ...DIFF_DEFAULTS };
  if (!C.filter) C.filter = 'diff';
  return C;
}

/** At most this many of the second zone's parse problems are listed in its bar. */
const OTHER_PROBLEMS = 20;

/**
 * The Compare tab body.
 * @param {{ ctx: object, zone: object, C: object, parse: (files: object[], opts: { origin: string|null }) => object,
 *   samples: Array<{ id: string, file: string, text: string }>, formatLabel: (zone: object) => string,
 *   redact: (values: string[], include: boolean) => string[], issue: (w: object) => { text: string, where: string } }} opts
 *   `C`: the view's holder ({ files, zone, originInput, options, filter, includeOrigins, cache }); `parse`:
 *   views/zone.js parseFiles; `redact`: the origin addresses of both zones hidden unless `include`; `issue`: a parse
 *   issue worded as the Problems tab words it, and where it is
 * @returns {HTMLElement}
 */
export function CompareTab({ ctx, zone, C, parse, samples, formatLabel, redact, issue }) {
  ensureCompare(C);
  const box = h('div', { class: 'stack zcmp', dataset: { role: 'zcmp' } });

  function result() {
    if (!C.zone || C.zone.fatal) return null;
    const key = JSON.stringify(C.options);
    if (C.cache && C.cache.a === zone && C.cache.b === C.zone && C.cache.key === key) return C.cache.result;
    const res = diffZones(zone, C.zone, C.options);
    C.cache = { a: zone, b: C.zone, key, result: res };
    return res;
  }

  function load(files) {
    const list = (files || []).slice(0, MAX_FILES).map((f) => ({ name: String(f.name || ''), size: Number(f.size) || (f.text || '').length, text: String(f.text || '') }));
    if ((files || []).length > MAX_FILES) toast(t('zone.tooManyFiles', { max: MAX_FILES }), { type: 'warn' });
    if (!list.length) return;
    C.files = list;
    read({ focus: true });
  }

  /** Parse the second zone (readOther: a file that names no zone is read under this zone's name). */
  function read({ focus = false } = {}) {
    C.zone = readOther(C.files, { zone, typed: C.originInput, parse });
    C.cache = null;
    C.filter = 'diff';
    render();
    const res = result();
    if (res) announce(t('zcmp.loaded', { count: res.counts.added + res.counts.removed + res.counts.changed }));
    if (focus) {
      const head = box.querySelector('.zcmp-other-title');
      if (head) head.focus({ preventScroll: true });
    }
  }

  function forgetOther() {
    Object.assign(C, { files: null, zone: null, originInput: '', cache: null, filter: 'diff' });
    toast(t('zcmp.forgotten'), { type: 'info' });
    render();
    const drop = box.querySelector('.zcmp-drop');
    if (drop) drop.focus({ preventScroll: true });
  }

  function render() {
    const active = document.activeElement;
    const role = active && box.contains(active) ? active.dataset.role || null : null;
    clear(box);
    if (!C.zone) {
      box.append(loader({ folded: false }));
    } else {
      box.append(otherBar(), loader({ folded: true }));
      if (C.zone.fatal) box.append(fatalAlert(C.zone.fatal));
      else box.append(results());
    }
    const again = role ? box.querySelector(`[data-role="${role}"]`) : null;
    if (again) again.focus({ preventScroll: true });
  }

  /* --- the second zone's importer ------------------------------------------ */
  function loader({ folded }) {
    const drop = FileDrop({
      accept: ACCEPT,
      multiple: true,
      compact: folded,
      icon: 'upload',
      title: t('zcmp.drop.title'),
      hint: t('zcmp.drop.hint'),
      className: 'zcmp-drop',
      onFiles: (files) => load(files)
    });
    const dropEl = drop.el || drop;
    // '/' lands here while the Compare tab shows (the first importer is folded away then).
    dropEl.dataset.shortcut = 'focus';
    const pasteArea = textarea({ label: t('zcmp.paste.label'), rows: 6, attrs: { 'data-role': 'zcmp-paste' } });
    const pasteBtn = Button({
      label: t('zcmp.run'), icon: 'arrow-down', variant: 'primary', size: 'sm', dataset: { action: 'zcmp-paste-run', shortcut: 'submit' },
      onClick: () => {
        const text = pasteArea.value;
        if (text.trim()) load([{ name: t('file.pasted'), size: text.length, text }]);
      }
    });
    const paste = Disclosure({ summary: t('zcmp.paste.summary'), className: 'zcmp-paste', children: h('div', { class: 'stack-sm' }, pasteArea.el, h('div', { class: 'cluster' }, pasteBtn)) });
    const originField = textInput({
      label: t('zcmp.origin.label'),
      value: C.originInput || '',
      placeholder: t('zcmp.origin.placeholder'),
      hint: t('zcmp.origin.hint'),
      mono: true,
      className: 'zcmp-origin-field',
      attrs: { 'data-role': 'zcmp-origin' },
      onChange: (v) => {
        const next = String(v || '').trim();
        if (next === (C.originInput || '')) return;
        C.originInput = next;
        if (C.files) read();
      }
    });
    const sampleRow = h('div', { class: 'zcmp-samples cluster' },
      h('span', { class: 'muted text-sm' }, t('zcmp.samples')),
      samples.map((s) => Button({
        label: t(`zone.sample.${s.id}`), size: 'sm', variant: 'ghost', icon: 'file-text', dataset: { compareSample: s.id },
        onClick: () => load([{ name: s.file, size: s.text.length, text: s.text }])
      })));
    // A form of its own for the shell's Ctrl/Cmd+Enter: Compare answers the paste box and the zone name.
    const body = h('div', { class: 'stack-sm', dataset: { shortcutScope: 'zone-compare' } },
      h('p', { class: 'muted text-sm zcmp-privacy' }, Icon('lock', { size: 12 }), ' ', t('zcmp.privacy')),
      dropEl, originField.el, paste, folded ? null : sampleRow);
    if (folded) return Disclosure({ summary: t('zcmp.replace'), className: 'zcmp-loader zcmp-loader-folded', children: body });
    return Card({ title: t('zcmp.title'), subtitle: t('zcmp.lead'), icon: 'swap', className: 'zcmp-loader', children: body });
  }

  function otherBar() {
    const z = C.zone;
    const files = (C.files || []).map((f) => f.name).join(', ');
    const size = (C.files || []).reduce((n, f) => n + f.size, 0);
    const bar = h('div', { class: 'zcmp-other', dataset: { format: z.format || '' } },
      h('div', { class: 'zcmp-other-main' },
        h('h3', { class: 'zcmp-other-title', tabindex: -1 }, z.origin ? t('zcmp.other', { origin: z.origin }) : t('zcmp.otherNoOrigin')),
        h('div', { class: 'cluster zcmp-other-meta' },
          z.fatal ? null : Badge(formatLabel(z), { variant: 'accent', className: 'zcmp-format-badge' }),
          z.fatal ? null : h('span', { class: 'text-sm', dataset: { role: 'zcmp-other-counts' } },
            t('zcmp.otherCounts', { count: z.records.length, files: `${files} · ${formatBytes(size)}` })))),
      h('div', { class: 'cluster zcmp-other-actions' },
        Button({ label: t('zcmp.forget'), icon: 'trash', size: 'sm', variant: 'ghost', dataset: { action: 'zcmp-forget' }, onClick: forgetOther })));
    if (z.fatal) return bar;
    return h('div', { class: 'stack-sm zcmp-other-box' }, bar, ...otherNotes(z));
  }

  /** What the parser said of the second zone: a change batch, an incomplete export, a guessed name, its problems. */
  function otherNotes(z) {
    const out = [];
    if (z.origin && z.originConfidence === 'low') {
      out.push(h('p', { class: 'zone-guessed text-sm', dataset: { role: 'zcmp-guessed' } }, Icon('alert', { size: 14 }), ' ', t('zcmp.guessed')));
    }
    const isPartial = (w) => w.code === 'PARTIAL_EXPORT' || w.code === 'RECORDS_TRUNCATED';
    const partial = z.warnings.find(isPartial);
    if (partial) {
      out.push(h('div', { class: 'zcmp-partial', dataset: { role: 'zcmp-partial', code: partial.code } },
        Alert({ variant: 'error', title: t('zone.partial.title'), message: `${issue(partial).text} ${t('zcmp.partial')}` })));
    }
    if (z.changeBatch) {
      out.push(h('div', { class: 'zcmp-batch', dataset: { role: 'zcmp-batch' } },
        Alert({ variant: 'warn', title: t('zcmp.batch.title'), message: t('zcmp.batch', { upserts: formatNumber(z.changeBatch.upserts), deletes: formatNumber(z.changeBatch.deletes.length) }) })));
    }
    const problems = z.warnings.filter((w) => (w.severity === 'error' || w.severity === 'warn') && !isPartial(w));
    if (problems.length) {
      const shown = problems.slice(0, OTHER_PROBLEMS);
      out.push(Disclosure({
        summary: t('zcmp.problems', { count: problems.length }),
        className: 'zcmp-problems',
        children: h('ul', { class: 'zone-problems zcmp-problem-list' },
          shown.map((w) => {
            const { text, where } = issue(w);
            const sev = w.severity === 'warn' ? 'warn' : 'error';
            return h('li', { class: 'zone-problem', dataset: { code: w.code, severity: sev } }, SeverityIcon(sev),
              h('div', { class: 'zone-problem-body' }, h('div', { class: 'zone-problem-title' }, text), where ? h('div', { class: 'text-sm muted' }, where) : null));
          }),
          problems.length > shown.length ? h('li', { class: 'muted text-sm' }, t('common.moreCount', { count: problems.length - shown.length })) : null)
      }));
    }
    return out;
  }

  function fatalAlert(fatal) {
    return h('div', { class: 'zcmp-fatal', dataset: { code: fatal.code } },
      Alert({ variant: 'error', title: t('zcmp.fatal'), message: t(`zone.fatal.${fatal.code}`, fatal.params || {}) }));
  }

  /* --- the result ---------------------------------------------------------- */
  function results() {
    const res = result();
    const out = h('div', { class: 'stack-sm zcmp-results', dataset: { role: 'zcmp-results' } });
    const c = res.counts;
    const diffs = c.added + c.removed + c.changed;
    if (res.relative) out.append(Alert({ variant: 'info', compact: true, message: t('zcmp.relative', { a: res.a.origin, b: res.b.origin }) }));
    // This zone itself a change batch, or incomplete (its own banner says so above the tabs).
    if (res.a.changeBatch) out.append(Alert({ variant: 'warn', compact: true, message: t('zcmp.batchThis') }));
    if (res.a.partial) out.append(Alert({ variant: 'warn', compact: true, message: t('zcmp.partialThis') }));
    const head = diffs
      ? t('zcmp.head.diff', { count: diffs, added: formatNumber(c.added), removed: formatNumber(c.removed), changed: formatNumber(c.changed), same: formatNumber(c.same) })
      : t('zcmp.head.same', { count: c.same });
    const summary = SummaryButton({
      kind: 'zone',
      className: 'zcmp-summary',
      facts: () => {
        const r = result();
        return r ? { origin: zone.origin, compare: diffSummaryFacts(r, { formatA: formatLabel(zone), formatB: formatLabel(C.zone) }) } : null;
      },
      url: () => ctx.shareUrl(permalinkParams('zone', ctx.params))
    });
    // The zone's own Copy summary is on the page too: this group names the comparison.
    summary.el.setAttribute('aria-label', t('zcmp.summaryLabel'));
    out.append(h('div', { class: 'zcmp-head', dataset: { role: 'zcmp-head', differences: String(diffs) } },
      Alert({ variant: diffs ? 'warn' : 'ok', compact: true, message: c.ignored ? `${head} ${t('zcmp.head.ignored', { count: c.ignored })}` : head }),
      h('div', { class: 'zcmp-head-actions cluster' }, summary.el)));
    out.append(optionsBox());
    out.append(h('p', { class: 'muted text-sm zcmp-legend' }, t('zcmp.legend')));
    out.append(table(res));
    return out;
  }

  function optionsBox() {
    const boxes = DIFF_OPTIONS.map((name) => {
      const cb = checkbox({
        label: t(`zcmp.opt.${name}`),
        checked: !!C.options[name],
        onChange: (on) => {
          C.options = { ...C.options, [name]: !!on };
          render();
        }
      });
      cb.input.dataset.role = `zcmp-opt-${name}`;
      return cb.el;
    });
    return h('fieldset', { class: 'zcmp-options' }, h('legend', { class: 'text-sm' }, t('zcmp.options')), h('div', { class: 'zcmp-options-list' }, boxes));
  }

  function valueLines(values, mark = null) {
    return h('span', { class: 'zone-values' }, values.map((v) => h('span', { class: mark === '+' ? 'zone-diff-add' : mark === '-' ? 'zone-diff-del' : null }, mark ? `${mark === '-' ? '−' : '+'} ${v}` : v)));
  }

  /** "Other zone": its values, the ones this zone lacks marked +, the ones it dropped marked −. */
  function otherCell(r) {
    if (r.status === 'added') return valueLines(r.added, '+');
    if (!r.b) return h('span');
    if (r.status !== 'changed' || (!r.added.length && !r.removed.length)) return valueLines(r.b.values);
    const added = new Set(r.added);
    return h('span', { class: 'zone-diff' },
      r.b.values.map((v) => h('span', { class: added.has(v) ? 'zone-diff-add' : null }, added.has(v) ? `+ ${v}` : v)),
      r.removed.map((v) => h('span', { class: 'zone-diff-del' }, `− ${v}`)));
  }

  function table(res) {
    const counts = Object.fromEntries(CHIPS.map((f) => [f, res.rows.filter((r) => diffFilter(r, f)).length]));
    const dt = DataTable({
      caption: t('zone.tab.compare'),
      rowKey: (r) => r.key,
      pageSize: 200,
      search: true,
      className: 'zcmp-table',
      cellLabels: true,
      filter: (r) => diffFilter(r, C.filter),
      empty: t('zcmp.empty'),
      noMatch: t('zcmp.empty'),
      export: {
        filename: `${zone.origin || 'zone'}-compare`,
        formats: ['csv', 'json'],
        onExport: (format, rows) => {
          const opts = { redact: (values) => redact(values, C.includeOrigins) };
          const base = `${zone.origin || 'zone'}-compare`;
          if (format === 'csv') downloadText(`${base}.csv`, diffCsv(rows, opts), 'text/csv;charset=utf-8');
          else downloadText(`${base}.json`, diffJson(res, rows, opts), 'application/json;charset=utf-8');
        }
      },
      columns: [
        { key: 'status', label: t('zcmp.col.status'), sortable: true, sortValue: (r) => DIFF_STATUSES.indexOf(r.status),
          render: (r) => h('span', { dataset: { status: r.status } }, Badge(t(`zcmp.st.${r.status}`), { variant: STATUS_VARIANT[r.status] })) },
        { key: 'name', label: t('zcmp.col.name'), sortable: true, sortValue: (r) => r.rel, searchValue: (r) => `${r.rel} ${r.name}`,
          render: (r) => h('strong', { class: 'zcmp-name' }, r.rel) },
        { key: 'type', label: t('zcmp.col.type'), sortable: true, sortValue: (r) => r.type, render: (r) => Badge(r.type, { variant: 'neutral', mono: true }) },
        { key: 'a', label: t('zcmp.col.a'), mono: true, wrap: true, searchValue: (r) => (r.a ? r.a.values.join(' ') : ''),
          render: (r) => (r.a ? valueLines(r.a.values) : h('span')) },
        { key: 'b', label: t('zcmp.col.b'), mono: true, wrap: true, searchValue: (r) => (r.b ? r.b.values.join(' ') : ''), render: otherCell },
        { key: 'note', label: t('zcmp.col.note'), wrap: true, className: 'zcmp-note', render: (r) => h('span', { class: 'text-sm' }, rowNote(r)) }
      ]
    });
    dt.setRows(res.rows);
    const chips = h('div', { class: 'zone-chips cluster zcmp-chips', attrs: { role: 'group', 'aria-label': t('zcmp.filter') } });
    const chip = (value) => h('button', {
      type: 'button',
      class: 'zone-chip',
      dataset: { filter: value },
      attrs: { 'aria-pressed': String(C.filter === value) },
      on: {
        click: () => {
          C.filter = value;
          chips.querySelectorAll('.zone-chip').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.filter === value)));
          dt.setFilter((r) => diffFilter(r, C.filter));
        }
      }
    }, `${t(value === 'diff' || value === 'all' ? `zcmp.filter.${value}` : `zcmp.st.${value}`)} (${formatNumber(counts[value])})`);
    for (const f of CHIPS) if (f === 'diff' || f === 'all' || counts[f]) chips.append(chip(f));
    const inc = checkbox({ label: t('zcmp.includeOrigins'), checked: !!C.includeOrigins, onChange: (on) => { C.includeOrigins = !!on; } });
    inc.input.dataset.role = 'zcmp-include-origins';
    return h('div', { class: 'stack-sm' }, chips, inc.el, dt.el);
  }

  render();
  return box;
}

/* ------------------------------------------------------------------------ */
/* Convert                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The Convert tab body.
 * @param {{ ctx: object, zone: object, V: object }} opts `V`: the view's holder ({ target, cache })
 * @returns {HTMLElement}
 */
export function ConvertTab({ zone, V }) {
  if (!CONVERT_TARGETS.includes(V.target)) V.target = 'bind';
  const box = h('div', { class: 'stack zconv', dataset: { role: 'zconv' } });

  function output(target) {
    if (!V.cache || V.cache.zone !== zone) V.cache = { zone, out: {} };
    if (!V.cache.out[target]) V.cache.out[target] = convertZone(zone, target);
    return V.cache.out[target];
  }

  function render() {
    const active = document.activeElement;
    const keepFocus = active && box.contains(active) && active.closest('.zconv-targets') ? active.dataset.value : null;
    clear(box);
    const out = output(V.target);
    const seg = SegmentedControl({
      label: t('zconv.format'),
      size: 'sm',
      value: V.target,
      className: 'zconv-targets',
      options: CONVERT_TARGETS.map((x) => ({ value: x, label: t(`zconv.t.${x}`) })),
      onChange: (v) => {
        V.target = v;
        render();
      }
    });
    const lines = out.text.split('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    const cut = lines.length > PREVIEW_LINES;
    const preview = cut ? `${lines.slice(0, PREVIEW_LINES).join('\n')}\n…\n` : out.text;
    const card = Card({
      title: t('zconv.title'),
      subtitle: t('zconv.lead'),
      icon: 'swap',
      className: 'zconv-card',
      children: h('div', { class: 'stack-sm' },
        seg.el,
        h('p', { class: 'text-sm', dataset: { role: 'zconv-desc' } }, t(`zconv.desc.${V.target}`)),
        h('p', { class: 'text-sm zconv-counts', dataset: { role: 'zconv-counts', written: String(out.written), left: String(out.omitted.length) } },
          t('zconv.written', { count: out.written }), out.omitted.length ? ` · ${t('zconv.left', { count: out.omitted.length })}` : ''),
        notes(out),
        out.files.length > 1 ? fileList(out) : h('div', { class: 'cluster zconv-actions' },
          Button({
            label: t('zconv.download', { file: out.filename }), icon: 'download', variant: 'primary', size: 'sm', dataset: { action: 'zconv-download', target: V.target },
            onClick: () => {
              downloadText(out.filename, out.text, out.mime);
              announce(t('zconv.downloaded', { file: out.filename }));
            }
          }),
          CopyButton(() => out.text, { label: t('zconv.copy'), variant: 'secondary', size: 'sm', toastOnCopy: true, className: 'zconv-copy' })),
        h('p', { class: 'muted text-xs zconv-privacy' }, Icon('lock', { size: 12 }), ' ', t('zconv.privacy')))
    });
    box.append(card,
      h('div', { class: 'stack-sm zconv-preview' },
        h('h3', { class: 'zone-h3' }, t('zconv.preview')),
        previewNote(out, cut, lines.length),
        CodeBlock(preview, { copy: false, maxHeight: '32rem', className: 'zconv-code', label: out.filename })));
    if (keepFocus) {
      const again = box.querySelector(`.zconv-targets [data-value="${keepFocus}"]`);
      if (again) again.focus({ preventScroll: true });
    }
  }

  /** What the preview shows: the first of several files, the first lines of a long one; or nothing to say. */
  function previewNote(out, cut, total) {
    const params = { file: out.filename, count: formatNumber(out.files.length), shown: formatNumber(PREVIEW_LINES), total: formatNumber(total) };
    const key = out.files.length > 1 ? (cut ? 'zconv.previewPartCut' : 'zconv.previewPart') : cut ? 'zconv.previewCut' : null;
    return key ? h('p', { class: 'muted text-sm', dataset: { role: 'zconv-preview-note' } }, t(key, params)) : null;
  }

  /** Several change batches: each file with its records, to download or copy, in the order to send them. */
  function fileList(out) {
    return h('div', { class: 'stack-sm zconv-files', dataset: { role: 'zconv-files', count: String(out.files.length) } },
      h('p', { class: 'text-sm zconv-files-lead' }, t('zconv.filesLead')),
      h('ol', { class: 'zconv-file-list', attrs: { 'aria-label': t('zconv.filesLabel') } }, out.files.map((f, i) => h('li', { class: 'zconv-file', dataset: { part: String(i + 1) } },
        h('span', { class: 'zconv-file-name' }, h('code', null, f.filename), ' ', h('span', { class: 'muted text-sm' }, t('zconv.countTitle', { count: f.written }))),
        h('span', { class: 'cluster zconv-actions' },
          Button({
            label: t('zconv.downloadPart'), icon: 'download', variant: i === 0 ? 'primary' : 'secondary', size: 'sm',
            dataset: { action: 'zconv-download', target: V.target, part: String(i + 1) }, ariaLabel: t('zconv.download', { file: f.filename }),
            onClick: () => {
              downloadText(f.filename, f.text, out.mime);
              announce(t('zconv.downloaded', { file: f.filename }));
            }
          }),
          copyFile(f))))));
  }

  /** "Copy" of one of several files, named by its file for a screen reader. */
  function copyFile(f) {
    const btn = CopyButton(() => f.text, { label: t('zconv.copyPart'), title: t('zconv.copyFile', { file: f.filename }), variant: 'secondary', size: 'sm', toastOnCopy: true, className: 'zconv-copy' });
    btn.setAttribute('aria-label', t('zconv.copyFile', { file: f.filename }));
    return btn;
  }

  function notes(out) {
    if (!out.pitfalls.length) return h('p', { class: 'text-sm zconv-clean', dataset: { role: 'zconv-clean' } }, SeverityIcon('ok'), ' ', t('zconv.noNotes'));
    return h('div', { class: 'stack-sm' },
      h('h3', { class: 'zone-h3' }, t('zconv.notes', { target: TARGET_NAMES[V.target] })),
      h('ul', { class: 'zconv-pitfalls', dataset: { role: 'zconv-pitfalls' } }, out.pitfalls.map((p) => {
        const names = p.names.slice(0, NOTE_NAMES);
        return h('li', { class: 'zconv-pitfall', dataset: { code: p.code, severity: p.severity } },
          SeverityIcon(p.severity),
          h('div', { class: 'zconv-pitfall-body' },
            h('span', null, pitfallText(p, V.target)),
            names.length ? h('span', { class: 'zconv-names text-sm' },
              names.map((n) => h('code', { class: 'zconv-name' }, n)),
              p.names.length > NOTE_NAMES ? h('span', { class: 'muted' }, t('common.moreCount', { count: p.names.length - NOTE_NAMES })) : null) : null),
          Badge(formatNumber(p.count), { variant: 'neutral', title: t('zconv.countTitle', { count: p.count }), className: 'zconv-count' }));
      })));
  }

  render();
  return box;
}
