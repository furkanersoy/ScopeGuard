# ScopeGuard

[English version](README.md) | Türkçe

**Durum: beta.** ScopeGuard, API yetkilendirme davranışlarını; kaynak kodu, yapılandırma, Dockerfile, Kubernetes ve Terraform dosyalarındaki seçili risk kalıplarını denetleyen, önce yerelde çalışan bir güvenlik aracıdır. Çevrimdışı istek planı ve kapsam matrisi, salt okunur API senaryo çalıştırıcısı, yerel kaynak ve Terraform kontrolleri, isteğe bağlı OSV bağımlılık sorgusu, gerekçeli ve süreli istisnalar, Türkçe/İngilizce bulgular ve yerel JSON, Markdown, SARIF ve HTML raporları sunar.

## Güncel özellikler

- Demo API yalnızca `127.0.0.1` adresinde dinler; API test hedefi varsayılan olarak yerel makinedir.
- Demo kayıtları ve Bearer token değerleri sentetiktir.
- `GET /records/{id}` kayıt sahipliğini denetler.
- `GET /vulnerable/records/{id}` nesne düzeyinde yetkilendirme hatasını göstermek için bilerek savunmasız bırakılmıştır.
- `scopeguard validate` OpenAPI belgesini ve YAML senaryosunu ağ erişimi olmadan doğrular.
- `scopeguard run` yalnızca senaryoda açıkça tanımlanan salt okunur `GET` isteklerini gönderir ve yerel rapor oluşturur.
- `scopeguard inspect` seçilen kaynak kodu, yapılandırma, Dockerfile, Kubernetes manifesti ve Terraform kalıplarını kod çalıştırmadan, imaj oluşturmadan ve ağa bağlanmadan tarar; bulguları JSON, Markdown, SARIF 2.1.0 ve HTML olarak kaydedebilir.
- API, yerel tarama ve bağımlılık bulguları JSON, Markdown, SARIF 2.1.0 ve tek dosyalı HTML olarak kaydedilebilir.
- Bağımlılık kontrolü yalnızca açıkça `--allow-network` verildiğinde OSV'ye bağlanır; yalnızca paket adı, ekosistem ve sabitlenmiş sürüm gönderilir.
- İstisna tanımları kural, göreli dosya yolu, gerekçe ve bitiş tarihi ister; bastırılan bulgular raporda görünür kalır.
- `scopeguard compare` kaydedilmiş JSON raporlarındaki yeni, giderilmiş ve değişmeden kalan bulguları karşılaştırır.
- İsteğe bağlı GitHub Actions iş akışı kaynağı tarar; SARIF yüklemesi yalnızca elle başlatılan çalıştırmada açılabilir.

## Hızlı başlangıç (Windows)

1. Python 3.11 veya üzerini kur ve ScopeGuard deposunu indir veya klonla.
2. `ScopeGuard.bat` dosyasına çift tıkla. İlk açılışta proje klasöründe `.venv` oluşturup ScopeGuard ve bağımlılıklarını kurar. Sonraki açılışlarda bu kurulumu tekrar kullanır.
3. Başlangıç menüsünden bir bölüm seç: `1` API Güvenliği, `2` kaynak/IaC/yapılandırma taraması, `3` sabit sır taraması, `4` gelişmiş komut konsolu, `5` isteğe bağlı bağımlılık kontrolüdür.
4. Demo API'yi başlatmak için ikinci bir PowerShell penceresi açıp depo klasöründe `& .\.venv\Scripts\python.exe -m scopeguard_demo` komutunu çalıştır. API `127.0.0.1:8000` adresinde dinler.
5. Etkileşimli konsoldan çıkmak için `exit` yaz. PowerShell'den doğrudan komut çalıştırmak için `ScopeGuard.bat` önekini kullan. Örneğin: ` .\ScopeGuard.bat validate --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml`.

Yerel kaynak kodunu doğrudan taramak için `.\ScopeGuard.bat inspect --path . --checks secrets python config docker kubernetes terraform --output inspect.json --markdown-output inspect.md --language tr` komutunu kullan. Gerçek servisleri yalnızca açıkça yetkilendirildiğin test kapsamlarında çalıştır.

### Sanal ortam oluşturmadan çalıştırma

Windows'ta depo klasöründe şu komutları çalıştırarak ScopeGuard'u kullanıcı Python kurulumuna yükleyebilirsin:

```powershell
py -3 -m pip install --user .
py -3 -m scopeguard
```

Bu yöntem proje içinde `.venv` oluşturmaz ve bağımlılıkları kullanıcı Python kurulumuna yükler. Diğer Python araçlarının bağımlılıklarıyla çakışma olasılığı nedeniyle `ScopeGuard.bat` ile otomatik kurulum önerilir.

## Kontroller ve komutlar

| Komut | Ne yapar? | Ağ kullanımı |
| --- | --- | --- |
| `init` | Anonim erişim, BOLA/IDOR, BFLA veya özel GET durum kodu kontrolleri için senaryo oluşturur. | Yok |
| `inspect` | Sabit sır, Python, yapılandırma, Dockerfile, Kubernetes ve seçili Terraform risklerini yerel dosyalarda arar. | Yok; kod çalıştırılmaz |
| `validate` | OpenAPI belgesini ve senaryo yapılandırmasını doğrular. | Yok |
| `plan` | Senaryodaki istekleri ve kimlikleri önizler. | Yok; token okunmaz |
| `coverage` | Kimlik/uç nokta kontrollerini matriste gösterir; `--strict` zorunlu kapsamı uygular. | Yok; token okunmaz |
| `run` | Tanımlı salt okunur GET kontrollerini kapsam içindeki hedefte çalıştırır ve yerel rapor yazar. | Evet, yalnızca yapılandırılmış hedefe |
| `dependencies` | Sabitlenmiş paket sürümlerini OSV ile karşılaştırır; `--allow-network` gerekir. | Evet; yalnızca paket adı, ekosistem ve sürümler |
| `compare` | İki ScopeGuard JSON raporunu karşılaştırır. | Yok |

`inspect` sezgisel statik kontroller kullanır; kapsamlı bir güvenlik tarayıcısı değildir ve çalışan web servisini test etmez. API senaryoları yalnızca açıkça tanımlanmış GET uç noktalarını ve beklenen sonuçları denetler; uç noktalara fuzzing uygulamaz ve uygulamanın yetkilendirme politikasını kendiliğinden çıkarmaz.

## Kurulum ve çalıştırma

Python 3.11 veya üzeri gerekir.

```powershell
git clone https://github.com/furkanersoy/ScopeGuard.git
cd ScopeGuard
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install .
```

Linux veya macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Linux/macOS'ta ilk kurulumdan sonra `chmod +x scopeguard.sh` komutunu bir kez çalıştırıp `./scopeguard.sh` ile başlatabilirsin. Betik ilk açılışta sanal ortamı kurar, sonraki çalıştırmalarda tekrar kullanır. Komutları doğrudan da betiğe iletebilirsin: `./scopeguard.sh inspect --path . --checks secrets python config docker kubernetes terraform`.

Geliştiriciler düzenlenebilir kurulum için `py -m pip install -e .` (Linux/macOS'ta `python -m pip install -e .`) kullanabilir.

## Başlangıç menüsünü kullanma

`scopeguard` komutunu argümansız çalıştır veya Windows'ta `ScopeGuard.bat` dosyasına çift tıklayarak iki dilli başlangıç menüsünü aç:

1. **API Güvenliği** — API alt menüsünde başlangıç senaryosu oluşturma, OpenAPI ve senaryo dosyalarını doğrulama, istek planını önizleme, kimlik/uç nokta kapsamını görüntüleme ve kontrolleri çalıştırma seçenekleri vardır. Senaryo sihirbazı GET işlemlerini, örnek yol değerlerini, kimlikleri ve beklenen kodları sorar. API çalıştırması yerel JSON, Markdown, SARIF ve HTML raporları oluşturur. Dahil edilen demo üzerinde çalıştırmak için önce başka bir terminalde demo API'yi başlat.
2. **Yerel Güvenlik Kontrollerini Seç** — virgülle ayırarak `secrets`, `python`, `config`, `docker`, `kubernetes` ve `terraform` kategorilerinden bir veya birkaçını seç. Varsayılan seçim `python,config,docker,kubernetes,terraform` olur; sır taraması ana menüde ayrıca kısayoldur. Tarama çevrimdışıdır; kod çalıştırılmaz, imaj oluşturulmaz ve Kubernetes kümesine bağlanılmaz. JSON, Markdown, SARIF ve HTML rapor yollarını ve isteğe bağlı istisna YAML dosyasını belirleyebilirsin.
3. **Gizli Bilgi Taraması** — seçilen yerel dosya veya klasörde desteklenen sabit sır kalıplarını arar ve JSON, Markdown, SARIF ve HTML raporları kaydeder. Eşleşen gizli değerleri ekrana yazdırmaz.
4. **Gelişmiş komut konsolu** — `help`, `version`, `init`, `inspect`, `dependencies`, `compare`, `validate`, `plan`, `coverage` ve `run` komutlarını kabul eder. Bölüm menüsüne dönmek için `menu`, ScopeGuard'dan çıkmak için `exit` yaz.
5. **Bağımlılık Zafiyeti Taraması** — kilit dosyası veya klasör seçer; paket adı ve sürümlerini HTTPS ile OSV'ye göndermeden önce onay ister. JSON, Markdown, SARIF ve HTML raporları yerel kaydeder.

Yerel tarama kontrolleri sezgiseldir; bulguları elle gözden geçir. Boşluk içeren yolları tırnak içine al. Komut satırında `--version` ve `--help` seçenekleri de kullanılabilir.

## Yerel kaynak kodu ve yapılandırma taraması

ScopeGuard, API denetimlerinden bağımsız olarak yerel kaynak kodu, yapılandırma, Dockerfile, Kubernetes manifestleri ve Terraform dosyalarını inceleyebilir. Desteklenen metin dosyalarını okur; kodu çalıştırmaz ve ağa bağlanmaz. Kontroller sabit atanmış olabilecek kimlik bilgilerini, `eval`/`exec`, güvensiz nesne veya YAML açma, `shell=True`, TLS doğrulamasını kapatma ve bazı güvensiz yapılandırma kalıplarını arar. Dockerfile kontrolleri son imaj aşamasında root kullanıcı kullanımını, digest ile sabitlenmemiş taban imajlarını ve kimlik bilgisine benzeyen ARG/ENV atamalarını inceler. Kubernetes kontrolleri Pod ve Workload güvenlik alanlarında ayrıcalıklı konteyner, yetki yükseltme, root kullanıcı, host namespace, hostPath ve ALL capability arar. Terraform kontrolleri seçili AWS güvenlik grubu, S3, veritabanı ve depolama ayarlarını metinsel sezgilerle tarar; HCL ifadelerini, modülleri, provider planlarını veya bulut durumunu değerlendirmez. Bulgu raporunda kaynak kod parçaları ve bulunan sır değerleri yer almaz.

Tüm kontrolleri çalıştırıp JSON, Türkçe Markdown, SARIF ve HTML raporları oluştur:

```powershell
scopeguard inspect --path . --checks secrets python config docker kubernetes terraform --output inspect.json --markdown-output inspect.md --sarif-output inspect.sarif --html-output inspect.html --language tr
```

`--checks` için `secrets`, `python`, `config`, `docker`, `kubernetes` ve `terraform` seçeneklerinden bir veya birkaçını belirt. `docker` Dockerfile dosyalarını çevrimdışı inceler; imaj oluşturmaz ve kayıt sunucularına bağlanmaz. `kubernetes` YAML manifestlerinde seçili güvenlik ayarlarını statik olarak tarar; kümeye bağlanmaz. Örneğin yalnızca Python kalıpları için `--checks python` kullan. Yaygın sanal ortam, bağımlılık ve derleme klasörleri atlanır; 1 MB üzerindeki dosyalar incelenmez. Raporlar dosya ve satır konumunu gösterir; kaynak kod parçalarını ve eşleşen sır değerlerini içermez. İsteğe bağlı SARIF 2.1.0 çıktısı önem derecelerini SARIF seviyelerine eşler; açıklama ve düzeltme önerisi ekler. Tek dosyalı HTML raporu yerel tarayıcıda açılabilir. Raporlar seçilen konumlara kaydedilir; açıkça izin verilmedikçe yüklenmez. Bulgu bulunduğunda komut `1` çıkış kodu verir. Raporu açıp her bulguyu doğrula; sezgisel kontroller yanlış pozitif üretebilir.

Altı kategoride örnek bulguları görmek için [examples/local-scan](examples/local-scan/README.md) içindeki sentetik dosyaları kullan. Bu dosyalar beklenen kural kimliklerini ve önem derecelerini açıklar; rapordaki kanıt konumu ve düzeltme önerisini gösterir. Bulgular beklendiği için örnek komut `1` çıkış kodu verir:

```powershell
scopeguard inspect --path examples/local-scan/insecure-patterns --checks secrets python config docker kubernetes terraform --output local-scan.json --markdown-output local-scan.md --sarif-output local-scan.sarif --html-output local-scan.html --language tr
```

Güvenli karşılaştırma örnekleri için aynı seçeneklerle `examples/local-scan/secure-patterns` klasörünü ve farklı rapor dosya adlarını tara. Bu taramanın sıfır bulgu üretmesi ve `0` çıkış koduyla tamamlanması beklenir.

## Gerekçeli ve süreli istisnalar

İncelenmiş bulguya geçici istisna vermek için YAML dosyası oluştur. Her kayıt kural kimliği (glob kabul edilir), göreli dosya yolu kalıbı, boş olmayan gerekçe ve ISO biçiminde bitiş tarihi gerektirir. Süresi geçmiş istisna dosyası reddedilir. Bastırılan bulgular JSON, Markdown, HTML ve SARIF raporlarında gerekçesi ve tarihiyle görünmeye devam eder.

```yaml
version: 1
suppressions:
  - rule_id: "terraform.public-ingress"
    path: "infra/network.tf"
    reason: "Onaylı geçici istisna; staging güvenlik duvarı erişimi sınırlandırıyor."
    expires: "2026-12-31"
```

Yerel veya bağımlılık taramasına `--suppressions scopeguard-ignore.yaml` ekle.

## Bağımlılık zafiyeti taraması

Bu çevrimiçi komut yalnızca `--allow-network` açıkça verildiğinde OSV'ye sorgu gönderir. Desteklenen kilit dosyaları: `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock` ve `go.sum`. Kilit dosyaları veya kaynak kod yüklenmez; OSV'ye paket ekosistemi, adı ve sürümü gider. Özel depolar için kurumunun veri paylaşım kurallarını kontrol et.

```powershell
scopeguard dependencies --path . --allow-network --output dependencies.json --markdown-output dependencies.md --sarif-output dependencies.sarif --html-output dependencies.html --language tr

### CI önem eşikleri

`inspect` ve `dependencies` komutları `--fail-on any|critical|high|medium|low|none` seçeneğini destekler. Varsayılan `any`, etkin bulgu varsa komutu mevcut davranışta olduğu gibi `1` koduyla bitirir. Bir eşik, o önem düzeyindeki veya daha yüksek önem derecesindeki etkin bulgular bulunduğunda başarısız olur; bastırılmış bulgular kapıyı başarısız kılmaz. Örneğin `scopeguard inspect --path src --checks secrets python --fail-on high` derlemeyi yüksek veya kritik kaynak kod bulgularına göre durdurur. Yalnızca yeni bulguları engellemek için önceki JSON raporunu saklayıp `scopeguard compare --previous baseline.json --current current.json` çalıştır; yeni bulgu varsa komut `1` döndürür.
```

## HTML raporları ve rapor karşılaştırma

`run`, `inspect` ve `dependencies` komutlarında `--html-output report.html` kullan. HTML tek dosyadır ve uzaktaki betik/stil yüklemez. Önceki ve güncel JSON raporlarını karşılaştır:

```powershell
scopeguard compare --previous previous.json --current current.json --output diff.json --markdown-output diff.md --html-output diff.html
```

Karşılaştırma yeni, giderilmiş ve aynı kalan bulguları listeler. Yeni etkin bulgu varsa çıkış kodu `1` olur; karşılaştırma ağ kullanmaz.

## GitHub Actions ve isteğe bağlı SARIF yükleme

`.github/workflows/scopeguard-sarif.yml` iş akışı push ve pull request sırasında tarama yapar. GitHub Code Scanning'e SARIF göndermek için Actions sekmesinde iş akışını elle başlatıp `upload_sarif` seçeneğini `true` yap. Varsayılan kapalıdır; normal CLI taraması yükleme yapmaz. Depoda Code Scanning desteğinin etkin olması gerekir.

## API senaryosu oluşturma

Bir OpenAPI belgesinden başlangıç senaryosu oluşturmak için sihirbazı çalıştır:

```powershell
scopeguard init --spec examples/api/openapi.yaml --output examples/scenarios/my-scenario.yaml
```

Sihirbaz anonim erişim, BOLA/IDOR yatay erişim, BFLA rol/yetki ve özel GET durum kodu kontrollerinden seçim yaptırır. GET işlemlerini, örnek yol değerlerini, test kimliklerini ve beklenen HTTP durum kodlarını sorar. API isteği göndermez. Oluşan senaryodaki kimlikleri ve beklenen sonuçları gözden geçir; sihirbaz uygulamanın politikasını tahmin edemez. Var olan dosya `--force` verilmediği sürece korunur.

## Demo API'yi başlatma

İkinci bir terminalde demo API'yi çalıştır:

```powershell
py -m scopeguard_demo
```

API `http://127.0.0.1:8000` adresinde açılır. Durdurmak için `Ctrl+C` kullan. Otomatik başlatıcıyla kurduysan Windows'ta `& .\.venv\Scripts\python.exe -m scopeguard_demo`, Linux/macOS'ta `./.venv/bin/python -m scopeguard_demo` komutunu çalıştır.

## Senaryoyu doğrulama ve önizleme

Örnek dosyaları çevrimdışı doğrula:

```powershell
scopeguard validate --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml
```

Senaryoda token değerleri değil ortam değişkenlerinin adları saklanır. Kimlik doğrulamalı demo kontrolleri için aynı PowerShell oturumunda sentetik tokenları ayarla:

```powershell
$env:SG_USER_A_TOKEN = 'demo-user-a'
$env:SG_USER_B_TOKEN = 'demo-user-b'
```

Çalıştırmadan önce gönderilecek istekleri gör:

```powershell
scopeguard plan --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml
```

`plan` ağ kullanmaz, token ortam değişkenlerini okumaz veya istek göndermez. Hedefi, çözümlenen yolları, kimlikleri, beklenen durum kodlarını ve JSON assertion bilgilerini gösterir. Uzak hedef için çalıştırma anında `--allow-remote` gerektiğini belirtir.

## Kapsam matrisi

Kimlik/uç nokta eşleşmelerinde hangi kontrollerin tanımlandığını görmek için:

```powershell
scopeguard coverage --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml
```

Matriste boş hücre `[not configured]` olarak görünür; bu yalnızca senaryoda kontrol tanımlı olmadığını ifade eder ve tek başına güvenlik açığı kanıtı değildir. YAML senaryosunda `coverage.required` altında zorunlu kimlik/uç nokta çiftlerini ve `coverage.required_checks` altında zorunlu kontrol kimliklerini tanımla. `scopeguard coverage --strict` eksik zorunlu kapsam veya kontrol varsa `1` ile çıkar. Komut çevrimdışıdır ve token okumaz.

## API kontrollerini çalıştırma ve raporlar

Demo API çalışırken, başka bir terminalde kontrolleri çalıştır:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json
```

Markdown özeti de kaydet:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json --markdown-output report.md
```

Bulgu açıklamalarını ve rapor dilini `--language tr` veya `--language en` ile seç (varsayılan: `en`). Rapor başlık, önem derecesi, kanıt, olası etki ve düzeltme önerisi içerir. SARIF 2.1.0 çıktısı yerel dosyaya yazılabilir:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json --sarif-output report.sarif --language tr
```

ScopeGuard raporları GitHub'a veya başka bir servise yüklemez. API raporları yanıt gövdelerini, assertion değerlerini veya token değerlerini içermez. Etkileşimli `sg>` konsolunda komutları `scopeguard` öneki olmadan gir.

Demo senaryosundaki korumalı uç nokta kontrolleri anonim erişimin reddedilmesini (`401`), iki kullanıcının kendi kayıtlarını okuyabilmesini (`200`) ve diğer kullanıcının kaydının reddedilmesini (`404`) denetler. Bilerek savunmasız olan uç nokta `200` döndürdüğü için beklenen `404` kontrolü bulgu verir. Böylece demo normalde altı başarılı kontrol ve bir beklenen başarısız kontrol raporlar; bulgu varsa `run` komutu `1` çıkış kodu verir.

JSON yanıtı assertion örneği:

```yaml
assert_json:
  - pointer: /owner
    not_equals: user-a
```

`equals`, JSON Pointer alanının bulunmasını ve eşit olmasını ister. `not_equals`, alan yanıtta yoksa da başarılı olur; korumalı uç noktanın `404` yanıtında `/owner` alanı yoktur.

## Sentetik hesaplar ve uç noktalar

User A'nın sahibi `record-a`, User B'nin sahibi `record-b` kaydıdır. Demo tokenları herkese açık test örnekleridir; başka yerde kullanma.

```powershell
Invoke-RestMethod -Headers @{ Authorization = 'Bearer demo-user-a' } -Uri 'http://127.0.0.1:8000/records/record-a'
Invoke-RestMethod -Headers @{ Authorization = 'Bearer demo-user-b' } -Uri 'http://127.0.0.1:8000/records/record-a'
Invoke-RestMethod -Headers @{ Authorization = 'Bearer demo-user-b' } -Uri 'http://127.0.0.1:8000/vulnerable/records/record-a'
```

Korumalı uç nokta kullanıcının kendi kaydı için `200`, diğer kullanıcının kaydı için `404` döndürür. Kimliksiz kayıt isteği `401` alır. Bilerek savunmasız uç noktada User B, User A'nın kaydını `200` ile okuyabilir.

## Yetkili test ortamları

Varsayılan hedef yerel makinedir. Yetkili bir staging senaryosu için tam sunucu adı ve portu izin listesine ekle, yapılandırmada opt-in değerini aç ve HTTPS sertifika doğrulamasını etkin tut:

```yaml
target:
  base_url: https://staging.example.test
  allowed_hosts:
    - staging.example.test
  allowed_ports: [443]
  allow_remote: true
  max_requests: 10
  timeout_seconds: 5
  follow_redirects: false
```

`staging.example.test` dokümantasyon için ayrılmış örnek bir addır. Yalnızca sahibi olduğun veya test etmek için açıkça izin aldığın sistemleri kullan. Uzak test için ayrıca şu komut satırı seçeneği gerekir:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/staging.yaml --output report.json --allow-remote
```

Uzak hedef HTTPS kullanmalı, tam sunucu adı ve izinli port ile eşleşmelidir. Joker karakterli sunucu adları kabul edilmez. `validate` ağ kullanmaz; `--allow-remote` olmadan `run`, istek göndermeden önce uzak hedefi reddeder.

## Güvenlik

Bu depo bilerek savunmasız bir eğitim API'si içerir. Demo API'yi yalnızca loopback üzerinde ve sentetik verilerle çalıştır. Ağa açma; gerçek kimlik bilgisi veya veri kullanma. API çalıştırıcısı sadece açıkça tanımlanmış `GET` isteklerini gönderir, yönlendirmeleri izlemez, istek sayısını ve hızını sınırlar ve yanıt gövdelerini kaydetmez. Uzak hedef yalnızca açık izin, tam sunucu/port listesi, HTTPS ve yetkili test kapsamıyla kullanılmalıdır.

## Testleri çalıştırma

Birim testleri hatalı ve kapsam dışı yapılandırmaları doğrular. Entegrasyon testleri sentetik API'yi geçici bir loopback portunda başlatıp erişim kontrolü sonuçlarını ve rapor gizliliğini denetler.

```powershell
py -m unittest discover -s tests -v
```

GitHub Actions her push ve pull request'te Python 3.11 ve 3.13 ile testleri ve örnek doğrulamasını çalıştırır.

## Proje planı

Mimari ve yol haritası için [docs/architecture.md](docs/architecture.md) dosyasına bak.

## Lisans

Henüz lisans seçilmedi. Lisans eklenene kadar bu kaynak kodu açık kaynak yeniden kullanım izni vermez.



## Hızlı tarama ve güvenli HTTP yöntemleri

`scopeguard quick-scan --path . --language tr` sır, Python, yapılandırma, Docker, Kubernetes ve Terraform için standart çevrimdışı kontrolleri çalıştırır. JSON, Markdown, SARIF ve HTML raporlarını geçerli klasöre kaydeder. İncelenmiş istisnalar için `--suppressions scopeguard-ignore.yaml`, CI önem eşiği için `--fail-on high` ekleyebilirsin.

API senaryoları yalnızca HTTP güvenli yöntemleri olan `GET`, `HEAD` ve `OPTIONS` ile yapılandırılabilir. Örneğin senaryoda `operation: "OPTIONS /records/{record_id}"` kullanıp ilgili yol parametresini tanımla. `HEAD` kontrollerinde JSON gövde doğrulaması kullanılamaz. Etkileşimli senaryo sihirbazı şimdilik GET senaryoları oluşturur. ScopeGuard POST, PUT, PATCH veya DELETE gibi yazma yöntemlerini göndermez.


## Rapor üzerinden istisna oluşturma

Yerel taramadan sonra JSON raporundaki etkin bulguları listeleyip geçici istisna oluştur:

```powershell
scopeguard ignore --report inspect.json
```

ScopeGuard etkin bulguları listeler; bulgu numarasını, gerekçeyi ve bitiş tarihini sorar. Varsayılan bitiş tarihi 90 gün sonradır. Komut `scopeguard-ignore.yaml` dosyasını oluşturur veya günceller. Dosyayı gözden geçir, ardından sonraki yerel taramada `--suppressions scopeguard-ignore.yaml` seçeneğiyle kullan. Betik kullanımında tüm değerleri komutta verebilirsin:

```powershell
scopeguard ignore --report inspect.json --finding 2 --reason "İncelendi; düzeltme planlandı" --expires 2026-12-31 --output scopeguard-ignore.yaml
```

Başlangıç menüsünde **6. Rapordan istisna oluştur** seçeneğini kullan. Bastırılan bulgular gerekçesi ve bitiş tarihiyle raporlarda görünmeye devam eder.
