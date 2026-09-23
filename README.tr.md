# DomainScope

**Tamamen tarayıcında çalışan, açık kaynak SSL & DNS araç kutusu.**
Bir domainin tüm subdomainlerini, nereye çözümlendiklerini, hangilerinin Cloudflare arkasında olduğunu ve **sertifikanın tam olarak hangi sunucularına kurulması gerektiğini** bulur.

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
| **SSL Hedefleri** | Sertifikayı bırakırsın (PEM, DER, zincir veya P7B). Certificate Transparency ve pasif DNS kaynaklarından subdomainleri toplar, istersen wordlist ile brute-force yapar, hepsini DNS-over-HTTPS ile çözer, sertifikanın hangi isimleri kapsadığını kontrol eder ve sonuçları **sunucu bazında** gruplar. Sekmeler: Hostlar, Sunucular, CDN Arkası (origin ipuçları ve hazır CLI komutuyla), Kaynaklar, CT sertifikaları. CSV, JSON, `names.txt` ve `targets.txt` olarak export alabilirsin. |
| **Sertifika** | Sertifikanın tüm detayları: SAN'lar, geçerlilik, anahtar, parmak izleri, zincir sırası ve uyarılar. Domainin **CAA** kayıtlarının sertifikayı veren CA'ya izin verip vermediğini kontrol eder ve sertifikayı CT loglarında arar. |
| **Global DNS** | Bir ismi **12 public DoH resolver** ve EDNS Client Subnet ile **dünyadaki 31 konum** üzerinden sorgular (Türkiye'den 4 konum: Türk Telekom, Turkcell Superonline, Vodafone). Cevapları gruplar; GeoDNS/CDN farklarını ve propagation'ı görürsün. |
| **DNS Sorgulama** | Her kayıt tipi (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, HTTPS/SVCB, DS, DNSKEY, TLSA, …), istediğin resolver'dan, DNSSEC (DO/CD) seçeneğiyle. Kayıtlar ayrıştırılmış halde, ham metinle birlikte gösterilir. |
| **Toplu Çözümleme** | Yüzlerce hostname yapıştırırsın; IP, CNAME zinciri, CDN sınıfı, PTR, ASN ve envanter eşleşmesini alırsın, sonra export edersin. |
| **IP Bilgisi** | Her IP için PTR, ASN ve sahibi, prefix, ülke ve şehir, CDN/sağlayıcı, private IP işareti, envanterdeki karşılığı ve reverse IP (aynı IP'deki diğer domainler). |
| **Domain Sağlığı** | NS, SOA, MX, SPF (özyinelemeli 10-lookup sayımıyla), DMARC, DKIM selector'ları, CAA, DNSSEC (imzalı mı, doğrulanıyor mu, bozuk mu), MTA-STS, TLS-RPT, BIMI, wildcard DNS ve RDAP ile domain bitiş tarihi; hepsi tek bir puanda. |
| **Sunucular** | Envanterini şu formatlardan biriyle yapıştır veya içe aktar: `isim ip` satırları, `/etc/hosts`, CSV/TSV (Excel export'u dahil), Ansible INI/YAML, JSON. Envanter **tarayıcından hiç çıkmaz**. |

Arayüz Türkçe ve İngilizce, açık/koyu tema destekli ve mobil uyumlu. Her ekranın paylaşılabilir bir linki var (örneğin `#/global?name=example.com&type=A`).

## Nasıl çalışır?

Backend yok, tamamen statik bir site. Her şey tarayıcında, CORS'a izin veren açık API'lere karşı çalışıyor: crt.sh, Cert Spotter, HackerTarget, AnubisDB, AlienVault OTX (subdomain kaynakları); 12 DoH resolver; RIPEstat ve ipwho.is (IP bilgisi); RDAP (domain kaydı; `.tr` için public RDAP yok).

Ücretsiz kotalar **ziyaretçi IP'si başına** işliyor, herkes aynı kotayı paylaşmıyor. Yaklaşık değerler: HackerTarget günde ~50 istek, Cert Spotter saatte ~10 istek; OTX anonim kullanımda sınırlı. Bir kaynak hata verirse tarama devam eder.

**Gizlilik:** Sertifika ve sunucu envanteri yerelde işlenir, hiçbir yere yüklenmez. Dışarı yalnızca her sorgunun gerektirdiği veri çıkar: domain isimleri DNS resolver'lara ve pasif kaynaklara, IP'ler ise sorguladığında IP bilgi servislerine gider. Private key'e hiç ihtiyaç yok; yanlışlıkla yapıştırırsan yok sayılır ve ekranda gösterilmez.

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
```

| Durum | Anlamı |
|---|---|
| `UPDATED` | Sunucu yeni sertifikayı zaten sunuyor. |
| `NEEDS_UPDATE` | Sunucu bu ismi farklı (eski) bir sertifikayla sunuyor. **Yeni sertifikayı buraya kur.** |
| `NOT_HOSTED` | Bu isim bu sunucuda yok (sunucu varsayılan sertifikasını döndürüyor). |
| `TLS_ERROR` / `TIMEOUT` / `CLOSED` | Sunucuya ulaşılamadı ya da handshake başarısız oldu. |

## Tipik SSL rollout akışı

1. **SSL Hedefleri** ekranında yeni sertifikayı bırak, domaini onayla ve taramayı başlat. Envanterin otomatik eşleşir.
2. **Sunucular** sekmesi, DNS'i sertifikanın kapsadığı bir isme işaret eden sunucuları listeler. **CDN Arkası** sekmesi proxy'li hostları, origin ipuçlarını ve CLI komutunu gösterir.
3. Sertifikayı kur, ardından CLI'ı `--cert yeni-sertifika.pem` ile çalıştır. Her sunucu `UPDATED` olana kadar tekrarla.

## Yerelde çalıştırma / kendi kopyanı yayınlama

Build adımı ve bağımlılık yok:

```bash
git clone https://github.com/halilibrahimd27/domainscope.git
cd domainscope
npm run serve            # veya: python -m http.server 8080
```

Kendi kopyanı yayınlamak için repoyu fork'la ve **Settings → Pages → Source: GitHub Actions** ayarını yap. Repodaki workflow, `main`'e yapılan her push'ta siteyi deploy eder.

## Lisans

[MIT](LICENSE). Veriler yukarıdaki servislerden gelir; her biri kendi kullanım koşullarına tabidir.
