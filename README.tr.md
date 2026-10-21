# ScopeGuard

[English version](README.md) | Türkçe

**Durum: beta.** ScopeGuard, API yetkilendirme davranışlarını ve yerel kaynak kodu, yapılandırma, Dockerfile ve Kubernetes manifestlerindeki seçili risk kalıplarını denetleyen, önce yerelde çalışan bir güvenlik aracıdır. Çevrimdışı istek planı ve kapsam matrisi, salt okunur API senaryo çalıştırıcısı, Türkçe/İngilizce bulgu açıklamaları ve yerel JSON, Markdown ve SARIF raporları sunar.

## Güncel özellikler

- Demo API yalnızca `127.0.0.1` adresinde dinler; API test hedefi varsayılan olarak yerel makinedir.
- Demo kayıtları ve Bearer token değerleri sentetiktir.
- `GET /records/{id}` kayıt sahipliğini denetler.
- `GET /vulnerable/records/{id}` nesne düzeyinde yetkilendirme hatasını göstermek için bilerek savunmasız bırakılmıştır.
- `scopeguard validate` OpenAPI belgesini ve YAML senaryosunu ağ erişimi olmadan doğrular.
- `scopeguard run` yalnızca senaryoda açıkça tanımlanan salt okunur `GET` isteklerini gönderir ve yerel rapor oluşturur.
- `scopeguard inspect` seçilen kaynak kodu, yapılandırma, Dockerfile ve Kubernetes manifest kalıplarını kod çalıştırmadan, imaj oluşturmadan ve ağa bağlanmadan tarar.
- Uzak hedef için yapılandırmada tam HTTPS sunucu/port izin listesi ve çalıştırırken ayrıca `--allow-remote` gerekir.

## Hızlı başlangıç (Windows)

1. Python 3.11 veya üzerini kur ve ScopeGuard deposunu indir veya klonla.
2. `ScopeGuard.bat` dosyasına çift tıkla. İlk açılışta proje klasöründe `.venv` oluşturup ScopeGuard ve bağımlılıklarını kurar. Sonraki açılışlarda bu kurulumu tekrar kullanır.
3. Başlangıç menüsünden bir bölüm seç: `1` API Güvenliği, `2` kaynak kodu/yapılandırma taraması, `3` sabit sır taraması, `4` gelişmiş komut konsoludur.
4. Demo API'yi başlatmak için ikinci bir PowerShell penceresi açıp depo klasöründe `& .\.venv\Scripts\python.exe -m scopeguard_demo` komutunu çalıştır. API `127.0.0.1:8000` adresinde dinler.
5. Etkileşimli konsoldan çıkmak için `exit` yaz. PowerShell'den doğrudan komut çalıştırmak için `ScopeGuard.bat` önekini kullan. Örneğin: ` .\ScopeGuard.bat validate --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml`.

Yerel kaynak kodunu doğrudan taramak için `.\ScopeGuard.bat inspect --path . --checks secrets python config docker kubernetes --output inspect.json --markdown-output inspect.md --language tr` komutunu kullan. Gerçek servisleri yalnızca açıkça yetkilendirildiğin test kapsamlarında çalıştır.

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
| `inspect` | Sabit sır, riskli Python kalıpları, yapılandırma, Dockerfile ve Kubernetes manifest güvenlik kontrollerini yerel dosyalarda arar. | Yok; kod çalıştırılmaz |
| `validate` | OpenAPI belgesini ve senaryo yapılandırmasını doğrular. | Yok |
| `plan` | Senaryodaki istekleri ve kimlikleri önizler. | Yok; token okunmaz |
| `coverage` | Kimlik/uç nokta kontrollerini matriste gösterir; `--strict` zorunlu kapsamı uygular. | Yok; token okunmaz |
| `run` | Tanımlı salt okunur GET kontrollerini kapsam içindeki hedefte çalıştırır ve yerel rapor yazar. | Evet, yalnızca yapılandırılmış hedefe |

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

Linux/macOS'ta ilk kurulumdan sonra `chmod +x scopeguard.sh` komutunu bir kez çalıştırıp `./scopeguard.sh` ile başlatabilirsin. Betik ilk açılışta sanal ortamı kurar, sonraki çalıştırmalarda tekrar kullanır. Komutları doğrudan da betiğe iletebilirsin: `./scopeguard.sh inspect --path . --checks secrets python config docker kubernetes`.

Geliştiriciler düzenlenebilir kurulum için `py -m pip install -e .` (Linux/macOS'ta `python -m pip install -e .`) kullanabilir.

## Başlangıç menüsünü kullanma

`scopeguard` komutunu argümansız çalıştır veya Windows'ta `ScopeGuard.bat` dosyasına çift tıklayarak iki dilli başlangıç menüsünü aç:

1. **API Güvenliği** — API alt menüsünde başlangıç senaryosu oluşturma, OpenAPI ve senaryo dosyalarını doğrulama, istek planını önizleme, kimlik/uç nokta kapsamını görüntüleme ve tanımlı kontrolleri çalıştırma seçenekleri vardır. Senaryo sihirbazı OpenAPI dosyasını, GET işlemlerini, örnek yol değerlerini, kimlikleri ve beklenen durum kodlarını sorar. Kontrolleri çalıştırırken giriş dosyaları, yerel rapor yolu ve rapor dili seçilir; JSON, Markdown ve SARIF raporları bilgisayara yazılır. Dahil edilen demo üzerinde çalıştırmak için önce ikinci bir terminalde demo API'yi başlat.
2. **Yerel Güvenlik Kontrollerini Seç** — virgülle ayırarak `secrets`, `python`, `config`, `docker` ve `kubernetes` kategorilerinden bir veya birkaçını seç. Varsayılan seçim `python,config,docker,kubernetes` olur; sır taraması ana menüde ayrıca kısayol olarak bulunur. Seçilen yerel dosya veya klasör çevrimdışı taranır; kod çalıştırılmaz, imaj oluşturulmaz ve Kubernetes kümesine bağlanılmaz.
3. **Gizli Bilgi Taraması** — seçilen yerel dosya veya klasörde desteklenen sabit kodlanmış gizli bilgi kalıplarını arar ve JSON ile Markdown raporlarını yerel olarak kaydeder. Eşleşen gizli değerleri ekrana yazdırmaz.
4. **Gelişmiş komut konsolu** — standart CLI komutlarını (`help`, `version`, `init`, `inspect`, `validate`, `plan`, `coverage` ve `run`) kabul eder. Bölüm menüsüne dönmek için `menu`, ScopeGuard'dan çıkmak için `exit` yaz. Menüde geri dönmek veya çıkmak için `0` seçeneğini kullan.

Yerel tarama kontrolleri sezgiseldir; bulguları elle gözden geçir. Boşluk içeren yolları tırnak içine al. Komut satırında `--version` ve `--help` seçenekleri de kullanılabilir.

## Yerel kaynak kodu ve yapılandırma taraması

ScopeGuard, API denetimlerinden bağımsız olarak yerel kaynak kodu, yapılandırma, Dockerfile ve Kubernetes manifestlerini inceleyebilir. Desteklenen metin dosyalarını okur; kodu çalıştırmaz ve ağa bağlanmaz. Kontroller sabit atanmış olabilecek kimlik bilgilerini, `eval`/`exec`, güvensiz nesne veya YAML açma, `shell=True`, TLS doğrulamasını kapatma ve bazı güvensiz yapılandırma kalıplarını arar. Dockerfile kontrolleri son imaj aşamasında root kullanıcı kullanımını, digest ile sabitlenmemiş taban imajlarını ve kimlik bilgisine benzeyen ARG/ENV atamalarını inceler. Kubernetes manifest kontrolleri ayrıcalıklı konteyner, yetki yükseltme, root kullanıcı, host namespace, hostPath bağlama ve ALL capability kalıplarını statik olarak arar; kümeye bağlanmaz ve Kubernetes şemasının tamamını doğrulamaz. Bulgu raporunda kaynak kod parçaları ve bulunan sır değerleri yer almaz.

Tüm kontrolleri çalıştırıp JSON ve Türkçe Markdown raporu oluştur:

```powershell
scopeguard inspect --path . --checks secrets python config docker kubernetes --output inspect.json --markdown-output inspect.md --language tr
```

`--checks` için `secrets`, `python`, `config`, `docker` ve `kubernetes` seçeneklerinden bir veya birkaçını belirt. `docker` Dockerfile dosyalarını çevrimdışı inceler; imaj oluşturmaz ve kayıt sunucularına bağlanmaz. `kubernetes` YAML manifestlerinde seçili güvenlik ayarlarını statik olarak tarar; kümeye bağlanmaz. Örneğin yalnızca Python kalıpları için `--checks python` kullan. Yaygın sanal ortam, bağımlılık ve derleme klasörleri atlanır; 1 MB üzerindeki dosyalar incelenmez. Bulgu bulunduğunda komut `1` çıkış kodu verir. Raporu açıp her bulguyu doğrula; sezgisel kontroller yanlış pozitif üretebilir.

Beş kategoride örnek bulguları görmek için [examples/local-scan](examples/local-scan/README.md) içindeki sentetik dosyaları kullan. Bu dosyalar beklenen kural kimliklerini ve önem derecelerini açıklar; rapordaki kanıt konumu ve düzeltme önerisini gösterir. Bulgular beklendiği için örnek komut `1` çıkış kodu verir:

```powershell
scopeguard inspect --path examples/local-scan/insecure-patterns --checks secrets python config docker kubernetes --output local-scan.json --markdown-output local-scan.md --language tr
```

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

