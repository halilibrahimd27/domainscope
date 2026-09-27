# DomainScope

**Tamamen tarayıcında çalışan, açık kaynak SSL & DNS araç kutusu.**
Bir domainin subdomainlerini keşfeder; nereye çözümlendiklerini, hangilerinin Cloudflare arkasında olduğunu ve **sertifikanın tam olarak hangi sunucularına kurulması gerektiğini** bulur.

**▶ Hemen kullan: https://halilibrahimd27.github.io/domainscope/**

[English README](README.md)

---

## Neden?

Müşteri `*.example.com` için yenilenmiş sertifikayı gönderdi, sen de yüzlerce sunucu yönetiyorsun. Bu sertifika hangi 10 sunucuya kurulacak?

- İnternetteki subdomain bulucular farklı sayılar gösteriyor (birinde 5, diğerinde 9), çünkü her biri farklı kaynaklara bakıyor.
- Cloudflare'in turuncu bulutu arkasındaki hostlar Cloudflare IP'lerine çözümleniyor, yani DNS sana gerçek (origin) sunucuyu hiç göstermiyor.
- Envanterin bir hosts dosyasında, Ansible inventory'sinde ya da Excel'de duruyor ve bunu DNS ile eşleştiren bir araç yok.

DomainScope birden fazla kaynağı birleştiriyor, her ismi çözümlüyor ve her cevabı sınıflıyor: Cloudflare, diğer CDN, SaaS platform, direkt, private, NXDOMAIN veya dangling CNAME. Ardından IP'leri **kendi envanterinle** eşleştiriyor. Bunların hepsi tarayıcında oluyor. Proxy arkasındaki hostlar için yanındaki Python CLI sunucularına SNI ile doğrudan bağlanıp hangilerinin hâlâ eski sertifikayı sunduğunu raporluyor.

## Özellikler

| Araç | Ne yapar |
|---|---|
| **Subdomain Tarama** (açılış sayfası) | Domaini yazarsın; internetin gösterebildiği tüm subdomainleri, önce DNS ile bulur. Zone'un kendi kayıtlarını (NS, MX, SPF/TXT, SRV, …) tarar, bu sitede barınan bir kelime listesi (wordlist) dener — **Kapalı**, **Küçük** (159 ad), **Akıllı** (≈ 7.000, varsayılan), **Büyük** (≈ 50.000) veya **Dev** (≈ 130.000) — ve bulunan her adın varyasyonlarını dener (`shop` → `shopapi`, `api` → `api2`, `api-dev`; varsayılan en fazla 1.500, artı bulunan üst adların altında bir tur daha). Akıllı seviyeden itibaren alan adı uzantısına göre bir **pazar kelime paketi** ekler (`.de` → Almanca, `.com.tr` → Türkçe; 12 pazar, istersen kendin seçersin); önce senin **özel kelime listeni**, ardından — açtıysan — önceki taramalarından **öğrenilen adları** dener (bkz. [Kelime listeleri](#kelime-listeleri-ve-dns-tahmininin-bulabildikleri)). Pasif kaynaklar (Certificate Transparency ve pasif DNS, aşağıda) yanında çalışır; her birinin durumu ve kota notu ayrı gösterilir. Wildcard DNS her seviyede tespit edilir, sahte eşleşmeler atılır. Cloudflare veya başka bir proxy arkasındaki hostlar için **asıl sunucu (origin) adaylarını** listeler: domainin DNS-only kayıtlarının ağları (IPv4 için /24, IPv6 için /48), diğer public resolver'ların doğrudan cevapları, geçmiş DNS kayıtları, SPF/MX adresleri ve bu ağları TLS SNI ile tarayan hazır CLI komutu (Linux/macOS ya da Windows PowerShell için). Proxy'li her hostun kendi sıralı aday listesi vardır: önce kesin adresler, sonra o hostla ilgili ağlar. Kardeş alan adlarını birlikte tararsan (`example.com example.net`), proxy'li `shop.example.com` için `shop.example.net` DNS-only bir hostsa onun adresi aday olur. Paylaşımlı bulut / hosting / CDN alanındaki ağlar işaretlenir ve komutta bütün bir /24 olarak değil, yalnızca bilinen adresleriyle taranır. Bir ağın sahibi (AS) tıkladığında sorgulanır; **Hariç tutulacak adresler** kutusu da komuta `--exclude` ekler. Kelime listesi ve varyasyon aşamaları sürerken bulunan adlar tabloya anında düşer. Listeyi kopyalayabilir veya `names.txt` indirebilirsin. |
| **Zone Dosyası** | DNS zone export'unu bırak, seç ya da yapıştır; biçimi kendisi tanır: BIND / RFC 1035 (Cloudflare export'u, cPanel, DirectAdmin, GoDaddy, cli53, `dig AXFR`), Cloudflare API JSON, Route 53 JSON, octoDNS YAML. Tüm adları tahminsiz alırsın. Cloudflare'de ayrıca **proxy'li her kaydın arkasındaki gerçek sunucuyu** dosyadan okur ve envanterinle eşleştirir. Sayfada şunlar var:<br>• kayıt tablosu;<br>• **Sorunlar** listesi (CNAME çakışmaları, boşa işaret eden hedefler, genel zone'da özel adresler, DNS-only bir kardeş / MX / SPF yüzünden açığa çıkan origin'ler, SPF / DMARC / CAA / TTL hataları …);<br>• yalnızca bu origin adreslerini ve hostlarını tarayan, asla bütün bir /24'e genişlemeyen tarama komutu;<br>• adları Subdomain Tarama'ya ya da SSL Hedefleri'ne aktaran **Bu adları tarayın**. *Kesin* modda yalnızca zone'daki adlar çözümlenir: tahmin yok, pasif kaynak yok, kota yok;<br>• dosyayı canlı DNS ile karşılaştıran, yalnızca tıkladığında çalışan **Canlı kontrol**. |
| **SSL Hedefleri** | Sertifikayı bırakırsın (PEM, DER, zincir veya P7B). Aynı keşif motorunu kullanır (Akıllı kelime listesi varsayılan olarak açık; diller, özel kelime listesi ve öğrenilen adlar Subdomain Tarama › Gelişmiş seçenekler ile ortak), hepsini DNS-over-HTTPS ile çözer, sertifikanın hangi isimleri kapsadığını kontrol eder ve sonuçları **sunucu bazında** gruplar. Sekmeler: Hostlar, Sunucular, CDN Arkası (asıl sunucu ipuçları ve iki kabuk için de hazır CLI komutuyla), **Doğrula**, Kaynaklar, CT sertifikaları. **Doğrula** (sertifika yüklüyken) her genel sunucunun her ad için gerçekte hangi sertifikayı sunduğunu [Globalping](https://globalping.io) ölçüm noktalarıyla internetten kontrol eder ve CLI'ın sonuçlarını verir (yeni sertifika, eski sertifika, bu ad burada sunulmuyor, TLS hatası, yanıt yok, port kapalı); eksik ara sertifika gibi uyarıları da gösterir. Maliyeti gösterir ve her sayfa oturumunda bir kez onay ister (50'den fazla kontrollük, kalan kotadan büyük ya da ilk kez asıl sunucu kontrolü içeren bir grupta yeniden sorar); özel adresler asla gönderilmez, onlar için hazır bir CLI komutu verir. CSV, JSON, `names.txt` ve `targets.txt` olarak export alabilirsin. |
| **Sertifika** | Sertifikanın tüm detayları: SAN'lar, geçerlilik, anahtar, parmak izleri, zincir sırası ve uyarılar. Domainin **CAA** kayıtlarının sertifikayı veren CA'ya izin verip vermediğini kontrol eder ve sertifikayı CT loglarında arar. |
| **Global DNS** | Bir ismi **12 public DoH resolver** ve EDNS Client Subnet ile **27 ülkedeki 31 konum** üzerinden sorgular. Cevapları gruplar; GeoDNS/CDN farklarını ve propagation'ı görürsün. Quad9 ve Quad9 (ECS) tarayıcılara HTTP/3 üzerinden CORS başlığı olmadan cevap verir; bu yüzden Chrome, Edge ve çoğu tarayıcıda satırlarında genellikle "Tarayıcıda okunamıyor" ve onun yerine çalıştırabileceğin bir `dig` komutu görünür. |
| **DNS Sorgulama** | Her kayıt tipi (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, HTTPS/SVCB, DS, DNSKEY, TLSA, …), istediğin resolver'dan, DNSSEC (DO/CD) seçeneğiyle. Kayıtlar ayrıştırılmış halde, ham metinle birlikte gösterilir. |
| **Toplu Çözümleme** | Yüzlerce hostname yapıştırırsın; IP, CNAME zinciri, CDN sınıfı, PTR, ASN ve envanter eşleşmesini alırsın, sonra export edersin. |
| **IP Bilgisi** | Her IP için PTR, ASN ve sahibi, prefix, ülke ve şehir, CDN/sağlayıcı, private IP işareti, envanterdeki karşılığı ve reverse IP (aynı IP'deki diğer domainler). |
| **Alan Adı Sağlığı** | NS, SOA, MX, SPF (özyinelemeli 10-lookup sayımıyla), DMARC, DKIM selector'ları, CAA, DNSSEC (imzalı mı, doğrulanıyor mu, bozuk mu), MTA-STS, TLS-RPT, BIMI, wildcard DNS ve RDAP ile domain bitiş tarihi; hepsi tek bir puanda. |
| **Sunucular** | Envanterini şu formatlardan biriyle yapıştır veya içe aktar: `isim ip` satırları, `/etc/hosts`, CSV/TSV (Excel export'u dahil), Ansible INI/YAML, JSON. Envanter **tarayıcından hiç çıkmaz**. |

Arayüz Türkçe ve İngilizce, açık/koyu tema destekli ve mobil uyumlu. Her ekranın paylaşılabilir bir linki var (örneğin `#/global?name=example.com&type=A`).

## Nasıl çalışır?

Backend yok, tamamen statik bir site. Her şey tarayıcında, açık API'lere karşı çalışıyor: crt.sh, Cert Spotter, HackerTarget, AnubisDB, AlienVault OTX, ip.thc.org (subdomain kaynakları); 12 DoH resolver; RIPEstat ve ipwho.is (IP bilgisi; RIPEstat ayrıca "Sahibini bul"a tıkladığında bir origin ağının sahibini söyler); RDAP (domain kaydı; `.de`, `.jp`, `.tr` gibi bazı ülke uzantılarında public RDAP yok); [Globalping](https://globalping.io) (jsDelivr'ın ücretsiz ölçüm ağı; yalnızca SSL Hedefleri › Doğrula'da ve yalnızca "İnternetten kontrol et"e bastığında). Bunların hepsi CORS'a izin verir; tek istisna Quad9 ve Quad9 (ECS): tarayıcılara HTTP/3 üzerinden CORS başlığı olmadan cevap verdikleri için Chrome, Edge ve çoğu tarayıcı onları genellikle okuyamaz. Global DNS bu satırları "Tarayıcıda okunamıyor" olarak bir `dig` komutuyla gösterir, keşif de Quad9'u varsayılan resolver zincirine koymaz. Terminalden ve QUIC'i engelleyen ağlarda tarayıcıdan çalışırlar.

Ücretsiz kotalar **ziyaretçi IP'si başına** işliyor, herkes aynı kotayı paylaşmıyor. Yaklaşık değerler: HackerTarget günde ~50 istek, Cert Spotter saatte ~10 tam alan adı araması (bir tarama, kapsadığı her kayıtlı alan adı için en fazla 5 kullanır; yani `example.com example.net` birlikte taranırsa 10'unun hepsi gidebilir); OTX anonim kullanımda sınırlı. Globalping hesapsız saatte 250 ölçüm verir ve bu kota IP adresinin arkasındaki herkesle ortaktır; Doğrula'daki her kontrol bir ölçüm harcar (bir ölçüm noktası hata verirse başka bir noktada yeniden denenir; parti başına en fazla 5 ek ölçüm), sekme herhangi bir hedef göndermeden önce kalan kotayı gösterir. Bir kaynak hata verirse tarama devam eder: önce-DNS keşfi (kayıt tarama, wordlist, varyasyonlar) hiçbir üçüncü taraf kotasına ihtiyaç duymaz, yalnızca public DoH resolver'ları kullanır.

**Gizlilik:** Sertifika ve sunucu envanteri yerelde işlenir, hiçbir yere yüklenmez; tek istisna **Doğrula**'da kontrol etmeyi seçtiğin genel IP / host adı çiftleridir (aşağıda). Dışarı yalnızca her sorgunun gerektirdiği veri çıkar: domain isimleri DNS resolver'lara ve pasif kaynaklara, IP'ler ise sorguladığında IP bilgi servislerine gider. Özel kelime listesi yalnızca açık sekmede (oturum deposu) durur. İçe aktardığın **zone dosyası** tarayıcından hiç çıkmaz ve hiçbir yere kaydedilmez. Yalnızca sekmenin belleğinde tutulur: sayfayı yenilemek, **Unut** ya da **Tüm yerel verileri sil** onu siler. **Canlı kontrol** yalnızca sen tıkladığında çalışır ve DoH resolver'larına yalnızca kayıt adlarını ve tiplerini gönderir; değerler ve origin adresleri gitmez. İç ağa ait görünen adlar varsayılan olarak atlanır, proxy'li kayıtların gizli hedefleri hiç sorgulanmaz. Zone adlarının kesin mod taraması da yalnızca DoH resolver'larını kullanır. **Doğrula** "İnternetten kontrol et"e basana kadar hiçbir şey göndermez. Bastığında önce ücretsiz Globalping kotan okunur (hedef içermeyen tek bir istek; sonra vazgeçsen de gider); her genel IP, host adı ve port çifti ancak onayladıktan sonra Globalping'e gider ve sonuçları ölçüm kimliğini bilen herkes yaklaşık altı ay okuyabilir. Özel adresler asla gönderilmez. İsteğe bağlı asıl sunucu kontrolü (varsayılan olarak kapalı) envanterindeki bir asıl sunucu IP'sini proxy'lenen adıyla birlikte de gönderir; böylece herkese açık ölçüm, CDN arkasında o ad için bu sunucunun yanıt verdiğini gösterir — CDN'i atlatmak isteyen birinin aradığı bilgi tam da budur. Bunu yalnızca adresi bilinse de sorun olmayan asıl sunucular için aç. Sertifika tarayıcından hiç çıkmaz; karşılaştırma yereldir. Ardından bir ölçüm noktası sunucuya tek bir HTTPS HEAD isteği gönderir (User-Agent "globalping probe"); bu yüzden yalnızca yönettiğin sunucuları kontrol et. Onay her sayfa oturumunda yeniden sorulur ve hiçbir yerde saklanmaz. Öğrenilen adlar sen açana kadar kapalıdır; `api` gibi yalın etiketlerdir, asla tam host adı ya da IP değil, ve yalnızca bu tarayıcının yerel deposunda saklanır — ama sonraki taramalar onları DNS sorgusu olarak dener (`api.<domain>`), yani resolver'lar ve o domainin ad sunucuları bu etiketleri görür. **Tüm yerel verileri sil** (Ayarlar ya da Hakkında) bunları envanter ve ayarlarla birlikte siler. Private key'e hiç ihtiyaç yok; yanlışlıkla yapıştırırsan yok sayılır ve ekranda gösterilmez.

## Kelime listeleri ve DNS tahmininin bulabildikleri

DNS'te "bütün kayıtları listele" diye bir sorgu yok; Cloudflare gibi sağlayıcılar da zone transferine izin vermiyor. Bu yüzden DomainScope listeyi dört tür kanıttan yeniden kuruyor: genel sertifikalarda ve pasif DNS'te geçen adlar, zone'un kendi kayıtlarında adı geçenler, bir kelime listesindeki kelimeler ve bulunan adların varyasyonları. Her tahmin gerçek bir DNS cevabıyla doğrulanır, wildcard benzerleri atılır.

| Seviye | Alan adı başına ad | İndirme | Alan adı başına kaba süre* |
|---|---:|---:|---:|
| Kapalı | yok (yalnızca kayıtlar + pasif kaynaklar) | — | — |
| Küçük | 159 | yerleşik | birkaç saniye |
| **Akıllı** (varsayılan) | ≈ 7.000 | 42 kB | ≈ 1 dk |
| Büyük | ≈ 50.000 | 183 kB (gzip) | ≈ 7 dk |
| Dev | ≈ 130.000 | 588 kB (gzip) | ≈ 18 dk |

\* Süreler, varsayılan Ayarlar paralelliğinde (aynı anda 24 sorgu) saniyede 120 sorgu varsayılarak hesaplanır; Ayarlar'da daha düşük bir değer taramayı orantılı olarak yavaşlatır. Tahmin bilerek temkinli tutuldu; ölçülen hızlar [docs/RESEARCH.md](docs/RESEARCH.md#measured-results-2026-09-23) içinde.

- **Tek sıralama, üç boy.** Akıllı, Büyük ve Dev, serbest lisanslı açık listelerden (SecLists, bitquark, commonspeak2, dnsgen, altdns; bkz. [Lisans](#lisans)) üretilen tek bir sıralamanın ilk ≈ 7.000, ≈ 50.000 ve ≈ 130.000 adıdır. Dosyalar bu siteden sunulur; tarama hiçbir kelime listesini üçüncü taraftan çekmez.
- **Pazar kelime paketleri** (Akıllı ve üstü): `tr, de, fr, es, pt, it, nl, pl, ru, ar, ja, zh`; her biri 83–283 genel iş ve kamu hizmeti kelimesi. **Otomatik** mod paketleri alan adı uzantısından seçer: `.com.tr` gibi ikinci seviye uzantıları da tanır, çok dilli ülkelere birden fazla paket verir (`.ch` → Almanca, Fransızca, İtalyanca). `.com` uzantısına otomatik paket verilmez; Gelişmiş seçenekler'den paketleri kendin seçebilir ya da hiçbirini seçmeyebilirsin.
- **Özel kelime listesi.** Adları yapıştır ya da bir `.txt` dosyası ekle — her satıra bir tane ya da virgül / boşlukla ayrılmış; `dev.api` bir alt seviyeyi dener. Bunlar Küçük seviyeden itibaren her seviyede ilk sırada denenir. Dosya tarayıcında okunur, liste yalnızca bu sekmede tutulur.
- **Öğrenilen adlar** (isteğe bağlı, varsayılan olarak kapalı). Açarsan her tamamlanan taramadan sonra taranan domainlerin altında çözümlenen adların en soldaki etiketleri bu tarayıcıda hatırlanır ve bir sonraki taramada özel listenin hemen ardından denenir (en sık görülen 1.000 tanesi). Böylece aynı adlandırma düzenini izleyen kardeş bir alan adı, adları hiçbir açık listede olmasa bile kapsanır. Sonraki taramalar *her* domain için bu etiketleri DNS sorgusu olarak gönderir; ilgisiz kurumları tararken anahtarı kapalı tut. **Kapalı** seviyede hiç kullanılmazlar; **Öğrenilen adları unut** ile istediğin an silebilirsin.
- **Nazik tarama.** Her tahmin, resolver havuzuna dağıtılan tek bir A sorgusudur; tarayıcın alan adının web sunucularına hiç bağlanmaz. Resolver'ın önbelleğinde olmayan adlar alan adının yetkili ad sunucularına iletilir; yani kendi ad sunucusunu işleten bir alan adı bu yoğunluğu görür. Alan adı başına en fazla 4.000 / 20.000 / 80.000 / 160.000 aday (Küçük / Akıllı / Büyük / Dev), tarama başına 200.000.
- **Yavaş kaynaklar kelime listesi taramasını bekletmez.** Wildcard kontrolü ve kelime listesi taraması, pasif kaynaklar cevap verince ya da kayıt taramasından 12 saniye sonra (hangisi önce olursa) başlar. Varyasyon ve son çözümleme aşamaları ise geç gelen adlar da dahil edilsin diye kaynakları bekler: crt.sh gibi yavaş bir kaynak hâlâ yeniden denerken (durumunda görünür) kelime listesi taraması bitmiş olsa bile sonuç tablosu boş kalabilir.

**Sınırlar, açıkça.** Yalnızca bir kurumun zone'unda bulunan, hiçbir sertifikada ya da pasif DNS'te görünmemiş bir ad (bir ürün ya da proje adı gibi) hiçbir genel kelime listesiyle bulunamaz. Onu özel kelime listene ekle, öğrenilen adlarla ilişkili bir alan adından taşınmasını sağla ya da zone export'unu **Zone Dosyası**'nda içe aktar; eksiksiz olan tek liste zone export'udur. Üst adın wildcard kaydıyla birebir aynı cevabı veren bir host wildcard'dan ayırt edilemez ve atılır. Proxy'lenen bir kaydın asıl sunucu IP'si DNS'te hiç yayınlanmaz; bu yüzden asıl sunucu paneli kesin cevap değil, CLI ile doğrulanacak adaylar verir. Kesin origin'ler yalnızca zone export'unda bulunur.

## Cloudflare arkasındaki gerçek sunucuyu bulmak: CLI

Tarayıcı rastgele IP'lere ham TLS bağlantısı açamaz, ama [`cli/ssl_origin_scan.py`](cli/ssl_origin_scan.py) açabilir. Tek dosya; Python 3.8+ yeterli, ek paket gerekmez. İç ağındaki bir makineden (örneğin jump host) çalıştırırsın. Envanterdeki her IP'ye bağlanır, her hostname'i SNI ile ister ve dönen sertifikayı yenisiyle karşılaştırır.

```bash
curl -O https://halilibrahimd27.github.io/domainscope/cli/ssl_origin_scan.py

# Hangi sunucular hâlâ eski sertifikayı sunuyor?
python3 ssl_origin_scan.py -t sunucular.txt --cert yeni-sertifika.pem

# Web uygulamasından export ettiğin names/targets ile, 443 ve 8443 portlarında
python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert yeni-sertifika.pem -p 443,8443

# Script'ler ve Excel için rapor, CI için çıkış kodu
python3 ssl_origin_scan.py -t hosts.ini --cert yeni.pem --json rapor.json --csv rapor.csv --fail-on-needs-update

# Proxy'li isimlerin origin'ini bul: Subdomain'ler sayfasının önerdiği ağı tara
python3 ssl_origin_scan.py -t 203.0.113.0/24 -n shop.example.com api.example.com

# Aynı tarama; bir mail sunucusuna ve bir /28'e hiç bağlanmadan
python3 ssl_origin_scan.py -t 203.0.113.0/24 --exclude 203.0.113.25 203.0.113.64/28 -n shop.example.com

# İçe aktarılan zone dosyasındaki kesin origin'ler (Zone Dosyası › Origin'ler ve sunucular)
python3 ssl_origin_scan.py -t zone-targets.txt -n zone-names.txt
```

| Durum | Anlamı |
|---|---|
| `UPDATED` | Sunucu yeni sertifikayı zaten sunuyor. |
| `NEEDS_UPDATE` | Sunucu bu ismi farklı (eski) bir sertifikayla sunuyor. **Yeni sertifikayı buraya kur.** |
| `NOT_HOSTED` | Bu isim bu sunucuda yok (sunucu varsayılan sertifikasını döndürüyor). |
| `TLS_ERROR` / `TIMEOUT` / `CLOSED` | Sunucuya ulaşılamadı ya da handshake başarısız oldu. |

`--exclude` IP, CIDR, aralık ya da bunları içeren bir dosya alır. Adlar çözümlendikten sonra ve hiçbir bağlantı açılmadan önce uygulanır. Hariç tutulan adresler özette, JSON'da ve CSV'de (`EXCLUDED`) listelenir. `2026092401`, `127.1` ya da `0x7f.0x1` gibi sayısal "host adları" reddedilir, çünkü sistem resolver'ı bunları IPv4 adresi olarak okur. Başında sıfır olan adresler (`010.0.0.1`) de reddedilir. `0.0.0.0/8`, multicast ve broadcast adresleri hiç taranmaz.

Subdomain Tarama'daki asıl sunucu paneli ve SSL Hedefleri'ndeki CDN Arkası sekmesi tarama komutunu senin için yazar: **Linux / macOS** (`python3 …`) ya da **Windows PowerShell** (`python …`) için. IPv4 ağları, içinde birden fazla asıl sunucu ya da envanterindeki bir sunucu varsa /24 olarak, yoksa tek tek adresler olarak eklenir. Paylaşımlı bulut / hosting / CDN alanındaki, senin sunucunu içermeyen bir /24 de yalnızca bilinen adresleriyle eklenir. IPv6 her zaman tek tek adreslerle eklenir (bir /48 taranamayacak kadar büyük). **Hariç tutulacak adresler** kutusuna yazdıkların `--exclude` olur; tamamen kapsanan bir ağ taramadan düşer. Zone Dosyası ise yalnızca dosyadaki kesin origin'leri kullanır: adresler ve host adları, asla bir /24 değil; `*.x` adları tırnaklanır. Her hedef bir IP adresi ya da ağ, her ad geçerli bir host adı olmak zorunda: geri kalan her şey — örneğin bir CT kaydından gelen kötü niyetli bir ad — komuta hiç yazılmaz, yalnızca sayısı gösterilir; kalan parçalar da seçilen kabuğa göre tırnaklanır.

## Tipik SSL rollout akışı

0. **Subdomain Tarama (isteğe bağlı):** önce her şeyi gör — tüm isimler, hangilerinin proxy'li olduğu ve kabuğuna uygun tarama komutuyla birlikte asıl sunucu ağları. Zone'u export edebiliyorsan onun yerine **Zone Dosyası**'na bırak: tüm adları ve proxy'li her kaydın kesin origin'ini görürsün; sonra **Sertifika hedeflerini bul**'a bas ya da kesin tarama komutunu kopyala.
1. **SSL Hedefleri** ekranında yeni sertifikayı bırak, domaini onayla ve taramayı başlat. Envanterin otomatik eşleşir.
2. **Sunucular** sekmesi, DNS'i sertifikanın kapsadığı bir isme işaret eden sunucuları listeler. **CDN Arkası** sekmesi proxy'li hostları, origin ipuçlarını ve CLI komutunu gösterir.
3. Sertifikayı kur, ardından **Doğrula** sekmesini açıp **İnternetten kontrol et**'e bas: her genel sunucu sunması gereken her ad için kontrol edilir, "Yeniden kontrol et" yalnızca henüz tamamlanmayanları yeniden dener. Özel adresler ve CDN arkasındaki asıl sunucular için sekmenin verdiği CLI komutunu (`--cert new-cert.pem`) çalıştır. Her sunucu `UPDATED` olana kadar tekrarla.

## Yerelde çalıştırma / kendi kopyanı yayınlama

Build adımı ve bağımlılık yok:

```bash
git clone https://github.com/halilibrahimd27/domainscope.git
cd domainscope
npm run serve            # veya: python -m http.server 8080
```

Kendi kopyanı yayınlamak için repoyu fork'la ve **Settings → Pages → Source: GitHub Actions** ayarını yap. Repodaki workflow, `main`'e yapılan her push'ta siteyi deploy eder.

## Geliştirme

Klasör yapısı ve komutlar için [README.md → Development](README.md#development). Kısaca: `npm test` (birim testleri; `node --test tests/js/` de aynı şeyi yapar), `npm run test:py` (CLI testleri), `node tests/e2e/run-all.mjs` (gerçek Chrome/Edge ile uçtan uca; verify paketi çevrimdışıdır, hiç Globalping ölçümü harcamaz). Kelime listeleri (Akıllı düz metin, Büyük ve Dev gzip) ve 12 pazar paketi `assets/data/` altında, `tools/build-wordlists.mjs` ile üretilir. Testler ve dokümanlar yalnızca örnek isimler (`example.com`, `example.net`) ve dokümantasyon IP blokları (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) kullanır; `tests/js/repo-hygiene.test.js` bunların dışındaki, bilinen public altyapıya ait olmayan her IPv4 adresinde hata verir.

## Lisans

[MIT](LICENSE). Veriler yukarıdaki servislerden gelir; her biri kendi kullanım koşullarına tabidir. Repodaki subdomain kelime listeleri serbest lisanslı listelerden üretilir (SecLists, bitquark ve dnsgen MIT; commonspeak2 ve altdns Apache-2.0). Kaynaklar, sabitlenmiş sürümler ve lisanslar [`assets/data/README.md`](assets/data/README.md) dosyasında; lisans metinlerinin tamamı [`assets/data/THIRD_PARTY_LICENSES.txt`](assets/data/THIRD_PARTY_LICENSES.txt) dosyasında (Hakkında sayfasından da bağlantılı). Pazar kelime paketleri ve yerleşik çekirdek liste DomainScope'un kendi, MIT lisanslı çalışmasıdır.
