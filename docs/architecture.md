# ScopeGuard — Mimari ve Geliştirme Yol Haritası

> Durum: Tasarım, yerel demo API, çevrimdışı girdi doğrulama, salt okunur çalıştırıcı ve JSON yanıt kontrolü aşaması.

## 1. Proje özeti

ScopeGuard, geliştiricilerin kendi API'lerinde veya açıkça yetkilendirildikleri test ortamlarında nesne ve rol bazlı erişim kontrollerini tekrarlanabilir biçimde doğrulamasına yardımcı olan, yerel öncelikli bir API güvenlik test aracıdır.

İlk sürüm, OpenAPI tanımında açıkça belirtilen uç noktaları kullanır. Birden fazla test kimliğiyle aynı kaynağa yapılan isteklerin sonuçlarını karşılaştırır ve beklenmeyen erişimleri raporlar. ScopeGuard genel amaçlı bir internet tarayıcısı ya da otomatik açık istismarı aracı değildir.

### Hedef kullanıcı

- Kendi API'sini geliştiren yazılım ekipleri
- Yetkili staging/laboratuvar ortamında API güvenlik testi yapan kişiler
- Erişim kontrolü regresyonlarını CI sürecine eklemek isteyen ekipler

### Ana problem

Bir uç noktanın giriş gerektirmesi, her kullanıcının yalnızca yetkili olduğu kayıtlara eriştiğini garanti etmez. ScopeGuard; anonim erişim, rol farkları ve kullanıcılar/tenant'lar arası kaynak erişimi için beklenen ve gerçekleşen yanıtları karşılaştırır.

## 2. MVP kapsamı

### İlk sürümde olacaklar

1. OpenAPI 3.x JSON/YAML dosyasını okuma ve temel doğrulama.
2. Kullanıcının hazırladığı YAML senaryolarında hedef kaynakları ve test kimliklerini tanımlama.
3. Yapılandırmada izin verilen tek bir `base_url` üzerinde çalışma.
4. İlk sürümde yalnızca `GET` istekleriyle salt okunur erişim kontrolleri.
5. Anonim, düşük yetkili ve başka kullanıcı/tenant kimliğiyle karşılaştırmalı istekler.
6. Beklenen HTTP durum kodları ile gerçek sonuçları karşılaştırma.
7. İsteğe bağlı JSON Pointer kontrolleriyle belirli yanıt alanlarının beklenen değere eşit/ayrı olduğunu doğrulama.
8. İnsan tarafından okunabilir terminal özeti ve makinece okunabilir JSON raporu.
9. Güvenli, sentetik ve yerelde çalışan örnek API ile uçtan uca demo.
10. Hata, kapsam dışı hedef ve eksik test verisi durumlarını açıkça raporlama.

### MVP dışında

- İnternet üzerinde hedef keşfi, port tarama veya genel web taraması
- Brute force, parola denemesi, fuzzing veya açık istismarı
- Varsayılan olarak veri değiştiren `POST`, `PUT`, `PATCH`, `DELETE` istekleri
- Üretim sistemlerinde otomatik çalışma
- OpenAPI dışında kapsamı belirsiz endpoint keşfi
- Otomatik olarak “sistem güvenlidir” sonucu verme

`POST`/`PATCH` gibi değişiklik yapabilen kontroller ancak ayrı bir tasarım ve güvenlik incelemesinden sonra; sentetik verili, açıkça etkinleştirilen bir laboratuvar modunda ele alınacaktır. Özellik düzeyinde yetki kontrolü bu sonraki aşamalardan biridir.

## 3. Gereksinimler listesi

### Ürün gereksinimleri

- Kullanıcı OpenAPI dosyasını ve test senaryolarını sağlayabilmeli.
- Her senaryo hangi kimliğin hangi kaynağa erişmeye çalıştığını ve beklenen sonucu belirtmeli.
- Rapor, başarısız testi, kullanılan kimliği, endpoint'i, beklenen ve gerçekleşen sonucu göstermeli.
- Araç test edemediği kontrolleri başarı gibi göstermemeli; `SKIPPED` veya `ERROR` olarak ayırmalı.
- Test senaryoları gerçek uygulama kullanıcı verilerini gerektirmemeli; demo sentetik verilerle çalışmalı.

### Güvenlik gereksinimleri

- İlk sürümde yalnızca konfigürasyonda açıkça belirtilen hosta istek gönderilmeli.
- Güvenli başlangıç için demo hedefi `localhost`/loopback olmalı.
- Uzak hedef kullanımı için ayrıca açık bir izin ayarı ve hedef onayı konfigürasyonda bulunmalı; kapsam dışı yönlendirmeler reddedilmeli.
- Redirect'ler varsayılan olarak izlenmemeli; izlenecekse her yönlendirme hedefi tekrar kapsam denetiminden geçmeli.
- Araç hız sınırı ve istek sayısı sınırı uygulamalı; eşzamanlılık düşük ve yapılandırılabilir olmalı.
- Kimlik bilgileri senaryo dosyasına yazılmamalı; ortam değişkeni veya işletim sistemi secret mekanizmasından alınmalı.
- Token, parola, hassas header ve yanıt gövdeleri rapora varsayılan olarak yazılmamalı.
- TLS doğrulaması varsayılan olarak açık olmalı. Doğrulamayı kapatmak ayrı, belirgin bir laboratuvar seçeneği olmalı.
- İstek/yanıt gövde boyutları sınırlanmalı; zaman aşımı uygulanmalı.
- Hata mesajları credential veya hassas yanıt içeriğini sızdırmamalı.
- Araç yalnızca kullanıcının yetkili olduğu hedeflerde kullanılmak üzere belgelenmeli.

### Operasyonel ve kalite gereksinimleri

- Aynı konfigürasyon ve demo verisiyle tekrarlanabilir sonuç vermeli.
- Rapor çıktısı deterministik ve CI için uygun olmalı.
- Bir testin sonucu en az `PASS`, `FAIL`, `SKIPPED`, `ERROR` durumlarından biri olmalı.
- Ağ hatası, kimlik doğrulama hatası ve geçersiz senaryo birbirinden ayırt edilmeli.
- İlk sürüm Python ile geliştirilecek; desteklenen Python sürümü ve bağımlılıklar kodlama başlangıcında sabitlenecek.
- Bağımlılıklar ve lisanslar GitHub'a eklenmeden önce incelenecek.

## 4. Kullanım modeli

Önerilen ilk komut akışı:

```text
scopeguard validate --spec examples/api/openapi.yaml --config examples/scopeguard.yaml
scopeguard run --spec examples/api/openapi.yaml --config examples/scopeguard.yaml --output report.json
scopeguard report report.json
```

İlk demo, repodaki örnek API'yi yerelde başlatır. README'deki komutlar dış ağa erişmeden çalıştırılabilir olmalıdır.

Örnek senaryo biçimi (taslak):

```yaml
version: 1
target:
  base_url: http://127.0.0.1:8000
  allowed_hosts:
    - 127.0.0.1
  max_requests: 30
  timeout_seconds: 5
  follow_redirects: false

identities:
  anonymous:
    auth: none
  user_a:
    bearer_token_env: SG_USER_A_TOKEN
  user_b:
    bearer_token_env: SG_USER_B_TOKEN

checks:
  - id: user-a-reads-own-record
    operation: GET /records/{record_id}
    identity: user_a
    path:
      record_id: record-a
    expected_status: [200]
  - id: user-b-cannot-read-user-a-record
    operation: GET /records/{record_id}
    identity: user_b
    path:
      record_id: record-a
    expected_status: [403, 404]
```

Bu yalnızca biçim önerisidir. Kodlamaya başlamadan önce OpenAPI operation eşlemesi, token çözümleme ve beklenen ret kodları kesinleştirilecek. Bazı API'ler yetkisiz kaynağı `404` ile gizlediği için `403` tek geçerli ret yanıtı varsayılmayacak.

## 5. Mimari

### Bileşenler

```text
CLI
 ├─ Config Loader & Validator
 ├─ OpenAPI Loader & Operation Resolver
 ├─ Scope Policy
 ├─ Scenario Planner
 ├─ HTTP Client (rate/time/body limits)
 ├─ Check Runner
 └─ Report Builder (terminal + JSON)

Local Demo API ── Seeded synthetic users, tenants, and records
```

### Sorumluluklar

- **CLI:** Komutları, dosya yollarını, çıkış kodlarını ve kullanıcıya dönük hata mesajlarını yönetir.
- **Config Loader:** YAML biçimini okur, alanları ve değer sınırlarını doğrular; gizli değerleri dosyaya gömmez.
- **OpenAPI Loader:** Belgeyi doğrular, operasyonları method/path anahtarıyla bulunabilir hale getirir.
- **Scope Policy:** Her isteğin hedef host, protokol ve izin verilen method sınırlarını denetler. İstek gönderme yetkisi burada merkezi olarak uygulanır.
- **Scenario Planner:** Senaryo girdilerini açık ve sınırlı HTTP kontrollerine dönüştürür. Otomatik keşif yapmaz.
- **HTTP Client:** Zaman aşımı, TLS, redirect, istek sayısı ve yanıt boyutu kontrollerini uygular.
- **Check Runner:** İstekleri çalıştırır, yanıt kodunu beklenen aralıklarla kıyaslar ve hassas veriyi bellekte minimum süre tutar.
- **Report Builder:** Sonuçları terminal ve JSON biçiminde üretir; credential veya tam yanıt gövdesi yazmaz.
- **Local Demo API:** İyi ve kasıtlı olarak hatalı erişim kontrolü örnekleri sunar. Yalnızca localhost'ta çalışır ve sentetik veriler kullanır.

### Veri akışı

1. CLI, spec ve konfigürasyon dosyalarını alır.
2. Dosyalar yapısal ve güvenlik sınırları açısından doğrulanır.
3. Senaryolar OpenAPI operasyonlarına eşlenir; eşleşmeyenler istek göndermeden hata verir.
4. Scope Policy her planlanan isteği gönderimden hemen önce denetler.
5. HTTP Client istekleri sınırlar dahilinde gönderir.
6. Runner yalnızca test için gereken yanıt metaverisini değerlendirir.
7. Report Builder PASS/FAIL/SKIPPED/ERROR sonuçlarını ve genel özeti üretir.

## 6. Sonuçların anlamı

- **PASS:** Yanıt, senaryodaki beklenen erişim davranışıyla uyumlu.
- **FAIL:** Yanıt, beklenen erişim politikasından farklı. Tek başına doğrulanmış zafiyet kanıtı olarak sunulmamalı; uygulama bağlamında incelenmeli.
- **SKIPPED:** Gerekli test verisi/kimlik yok veya kontrol açıkça devre dışı.
- **ERROR:** Spec, konfigürasyon, ağ veya araç hatası nedeniyle kontrol tamamlanamadı.

CI çıkış kodu: en az bir `FAIL` varsa başarısız; konfigürasyon veya çalıştırma hatası varsa ayrı hata kodu; yalnızca beklenen sonuçlar varsa başarılı. Kesin kod tablosu uygulama aşamasında sabitlenecek.

## 7. Önerilen depo yapısı

```text
scopeguard/
  README.md
  LICENSE
  pyproject.toml
  docs/
    architecture.md
    security.md
    configuration.md
  src/scopeguard/
    cli.py
    config.py
    openapi.py
    scope.py
    planner.py
    client.py
    runner.py
    report.py
  examples/
    api/
    scenarios/
  demo_api/
  tests/
    unit/
    integration/
  .github/workflows/
```

## 8. Adım adım geliştirme planı

### Aşama 0 — Tasarım ve kararlar

- [x] Projenin amacı ve ilk kullanıcı kitlesi tanımlandı.
- [x] MVP kapsamı ve kapsam dışı özellikler belirlendi.
- [x] Güvenli varsayımlar ve üst düzey mimari yazıldı.
- [ ] Konfigürasyon şeması ve sonuç/çıkış kodları kesinleştirilecek.
- [ ] Proje adı ve lisans seçimi yapılacak.

### Aşama 1 — Depo temeli (başladı)

- Python paket iskeleti ve CLI giriş noktası
- Kod biçimi/lint ve tip kontrolü tercihleri
- Lisans, `.gitignore`, `SECURITY.md`, katkı ve kullanım kuralları
- GitHub Actions ile yerel test/doğrulama akışı

### Aşama 2 — Yerel demo API (ilk iskelet hazır)

- Sentetik kullanıcı, tenant ve kayıtlar
- Güvenli sürüm ve bir kasıtlı erişim kontrolü hatası
- Yalnızca loopback'te başlatma
- Demo seed/reset komutları

### Aşama 3 — Dosya okuyucular ve doğrulama (başladı)

- OpenAPI yükleme/operation çözümleme
- YAML senaryo şeması
- Güvenli host ve method kapsamı doğrulama
- İstek göndermeden önce dry-run planı

İlk dilimde `scopeguard validate` komutu OpenAPI belgesini ve senaryo YAML'ını çevrimdışı doğrular. İstek planlama ve gönderme bu komuta dahil değildir.

### Aşama 4 — Salt okunur test çalıştırıcısı (ilk sürüm hazır)

- Kimlik başlıklarını ortam değişkenlerinden çözümleme
- GET kontrolleri, zaman aşımı ve istek sınırları
- Sonuç durumları ve hassas veri maskeleme
- JSON ve terminal raporu

İlk sürüm yalnızca açıkça tanımlanan GET kontrollerini sırayla çalıştırır. Redirect izlemez, istek hızını sınırlar, yanıt gövdesini rapora yazmaz ve hedefi loopback ile kısıtlar.

Yanıt kontrolleri JSON gövdesini bellekte ayrıştırır; rapor yalnızca JSON Pointer, karşılaştırma operatörü ve PASS/FAIL sonucunu içerir. Beklenen ve gerçek alan değerleri rapora eklenmez.

### Aşama 5 — Tekrarlanabilir örnek ve CI (ilk iş akışı hazır)

- Demo API üzerinde başarılı/başarısız senaryolar
- README quick start ve örnek rapor
- CI'da yerel demo ile uçtan uca doğrulama
- Sürüm öncesi tehdit modeli ve güvenli varsayılanların gözden geçirilmesi

İlk otomatik testler, girdi doğrulamasını ve sentetik API üzerindeki BOLA senaryosunu kapsar. GitHub Actions Python 3.11 ve 3.13 matrisinde birim/entegrasyon testlerini ve örnek yapılandırma doğrulamasını çalıştırır.

### Aşama 6 — İleri özellikler (MVP sonrasına bırakıldı)

- Kontrollü özellik düzeyi yazma testleri ve disposable fixture'lar
- Tenant/rol matrisini otomatik üretme
- Markdown/HTML raporu
- Ek kimlik sağlayıcıları ve CI entegrasyonları

## 9. MVP kabul ölçütleri

- Yerel demo, dış hedef gerektirmeden başlatılabiliyor.
- Geçerli OpenAPI ve senaryo dosyaları doğrulanıyor; bozuk dosyalar istek göndermeden reddediliyor.
- İzin verilen hedef dışına giden istekler gönderilmiyor.
- Anonim, kendi kaydına erişen kullanıcı ve başka kullanıcı kaydını deneyen kullanıcı senaryoları çalışıyor.
- Beklenmeyen 2xx erişimi başarısız kontrol olarak raporlanıyor; beklenen 403/404 reddi yapılandırılabiliyor.
- Rapor credential, token ve varsayılan olarak yanıt gövdesi içermiyor.
- JSON raporu ve anlamlı process exit code üretiliyor.
- README talimatları temiz bir ortamda takip edilebilir.

## 10. GitHub'da yayınlama hazırlığı

- Yalnızca sentetik demo verisi ve kendi yazdığımız örnekler depoya konacak.
- Staj defteri, kurum raporu, gerçek host/IP, token, kullanıcı adı veya ekran görüntüsü depoya eklenmeyecek.
- README'de izinli kullanım sınırı, demo kurulumu, kapsam dosyası örneği ve bilinen sınırlamalar açıkça yazılacak.
- Lisans, üçüncü taraf bağımlılıklar ve lisans bildirimleri kontrol edilecek.
- Güvenlik bulgusu bildirim kanalı için `SECURITY.md` eklenecek.
- İlk yayın öncesinde Git geçmişi ve örnek çıktılar gizli bilgi açısından gözden geçirilecek.

## 11. Başlangıç kararları

| Konu | İlk karar | Gerekçe |
|---|---|---|
| Dil | Python | Hızlı prototipleme ve erişilebilir katkı |
| İlk hedef | Yerel demo API | Güvenli, tekrarlanabilir GitHub demosu |
| İlk HTTP methodları | Yalnızca GET | Yan etkisiz MVP ve düşük risk |
| Test girdisi | OpenAPI + açık YAML senaryoları | Test kapsamını kullanıcı belirler |
| İlk rapor | Terminal + JSON | Kullanıcı/CI için kolay tüketim |
| Kimlik bilgileri | Ortam değişkenleri | Secret'ların repo/config'e yazılmasını önleme |
| Hedef keşfi | Yok | Her istek belgelenmiş ve kapsam denetimli olur |

## 12. Kaynak ve tasarım dayanağı

API nesne düzeyinde yetkilendirme ve özellik düzeyinde yetkilendirme, OWASP API Security Top 10'da ayrı risk alanları olarak ele alınır. ScopeGuard'ın ilk sürümü nesne erişimini salt okunur isteklerle sınar; özellik düzeyindeki yazma kontrolleri güvenli test verisi ve ayrı bir kontrollü mod gerektirdiğinden sonraki aşamaya bırakılmıştır.

- [OWASP API1:2023 — Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API3:2023 — Broken Object Property Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)
