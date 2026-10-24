# ScopeGuard Sorun Giderme

## Önce kurulumu kontrol et

ScopeGuard açılıyorsa Python, PyYAML ve paketlenmiş API demo dosyalarını çevrimdışı kontrol etmek için `scopeguard doctor` (Windows kaynak deposunda `ScopeGuard.bat doctor`) çalıştır. Projeni taramaz ve ağa bağlanmaz. Komut bulunamıyorsa önce sonraki bölümü uygula.

## `scopeguard` komutu bulunamıyor

- Windows'ta indirilen depoyu kullanıyorsan, depo klasöründeki `ScopeGuard.bat` dosyasını çalıştır. Komutları dosyaya da verebilirsin; örneğin `.\ScopeGuard.bat quick-scan`.
- PyPI'dan pipx ile kurduysan kurulumdan sonra yeni bir terminal aç. Gerekirse `pipx ensurepath` çalıştırıp terminali yeniden başlat.
- Sanal ortama kurduysan `scopeguard` komutunu çalıştırmadan önce aynı ortamı etkinleştir.

## Python veya ilk açılış kurulumu başarısız

ScopeGuard Python 3.11 veya üzerini gerektirir. Windows'ta `py -3 --version`, Linux/macOS'ta `python3 --version` ile sürümü kontrol et. Depo başlatıcısı ilk çalışmada yerel bir `.venv` oluşturup bağımlılıkları kurar. Kurulum paket kaynağına erişmek zorundadır; güvenlik duvarı, proxy veya çevrimdışı bağlantı kurulumu engelleyebilir.

Kaynak depoda PowerShell'den, depo klasöründe kurulumu yeniden deneyebilirsin:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

Başlatıcılar paket metaverisi değiştiğinde kurulumu yeniler. Kurulum hâlâ başarısızsa hata çıktısının tamamını sakla ve Python 3.11+ ile pip'in kullanılabildiğini doğrula.

## Tarama 1 çıkış koduyla bitiyor

Çıkış kodu 1, ScopeGuard'ın kontrolü tamamladığı ve bir uyumsuzluk, bulgu veya eksik zorunlu kapsam bulduğu anlamına gelir. Oluşturulan raporu açıp sonuçları incele. Dahil edilen demodaki `vulnerable-route-should-deny-cross-user-read` kontrolünün başarısız olması beklenir; bu uç nokta bilerek savunmasızdır.

## Komut 2 çıkış koduyla bitiyor

Çıkış kodu 2, komutun tamamlanamadığını belirtir. Örneğin dosya geçersiz/eksik olabilir, bağımlılık bulunmayabilir, istek başarısız olabilir veya zorunlu test girdisi eksik olabilir. Çıkış kodundan hemen önce yazan hata mesajını düzeltmeden raporu yorumlama.

## Bağımlılık taraması desteklenen lockfile bulamıyor

Bağımlılık denetimi sabitlenmiş paket sürümlerini şu dosyalardan okur: `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock` veya `go.sum`. Tek başına `pyproject.toml` ya da `package.json`, gerekli kesin çözülmüş sürümleri içermez. Desteklenen bir lockfile oluşturup depoya ekle ve yeniden dene. Tarama, yalnızca ağ erişimine açıkça izin verdiğinde paket adı, ekosistem ve sürümü OSV'ye gönderir.

## API kontrolleri demo API'ye ulaşamıyor

API kontrollerinden önce demo API'yi ikinci bir terminalde başlat:

- PyPI kurulumu: `scopeguard-demo`
- Kaynak depo: `py -m scopeguard_demo`
- Windows depo başlatıcısı: `& .\.venv\Scripts\python.exe -m scopeguard_demo`

Demo `127.0.0.1:8000` adresinde dinler. Kontrol bitene kadar sunucuyu açık tut. Portu veya temel adresi değiştirdiysen senaryo dosyasını da güncelle.

## Kimlik doğrulamalı API kontrolleri atlanıyor veya başarısız oluyor

Senaryoda token değeri değil ortam değişkeni adı saklanır. ScopeGuard'ı çalıştırdığın aynı terminal oturumunda sentetik demo değerlerini ayarla:

```powershell
$env:SG_USER_A_TOKEN = 'demo-user-a'
$env:SG_USER_B_TOKEN = 'demo-user-b'
```

Gerçek sistemlerde yalnızca test etmeye yetkili olduğun ortamlara ait tokenları kullan. Token değerlerini senaryo dosyalarına, raporlara veya herkese açık sorun kayıtlarına yazma.

## Uzak API hedefi reddediliyor

Uzak hedefi çalıştırmak için HTTPS temel adresi, senaryo izin listesinde tam sunucu adı ve port, senaryoda `allow_remote: true` ve komut satırında `--allow-remote` gerekir. `validate`, `plan` ve `coverage` çevrimdışıdır, istek göndermez.

## Rapor dosya adı zaten var

Etkileşimli menü varsayılan rapor adları doluysa numaralı yeni ad seçer. Var olan bir adı kendin yazdıysan üzerine yazma sorusunu yanıtla veya farklı bir ad gir. Varsayılan rapor adları deponun `.gitignore` dosyasında yok sayılır; özel rapor adlarını kendi `.gitignore` dosyana eklemen gerekebilir.

## SARIF GitHub'a yüklenmedi

Normal yerel taramalar SARIF'i yalnızca seçtiğin dosya yoluna yazar, otomatik yüklemez. GitHub'a yükleme ayrı ve elle başlatılan bir Actions workflow seçeneğidir.

Özellikler ve kurulum için [README'ye](../README.tr.md) bak.