# ScopeGuard Sürüm Notları

## [0.2.0] - Yayımlanmadı

### Eklenenler

- İki dilli etkileşimli terminal menüsü, rehberli yerel hızlı tarama, yeniden kullanılabilir tarama profilleri ve sentetik yerel API demosu.
- OpenAPI tabanlı API yetkilendirme senaryoları: yalnızca açıkça yapılandırılmış `GET`, `HEAD` ve `OPTIONS` kontrolleri; çevrimdışı doğrulama, istek planı, kapsam ve yerel raporlama.
- Desteklenen sır kalıpları, Python, yapılandırma, Dockerfile, Kubernetes manifestleri ve seçili Terraform örüntüleri için çevrimdışı statik kontroller.
- Kullanıcı ağ erişimini açıkça etkinleştirdiğinde OSV üzerinden isteğe bağlı bağımlılık duyurusu sorgusu.
- Yerel JSON, Markdown, SARIF 2.1.0 ve tek dosyalı HTML raporları; gerekçe ve bitiş tarihi olan bulgu istisnaları; kayıtlı rapor karşılaştırması.
- Türkçe ve İngilizce bulgular, yardım, README ve raporlama seçenekleri.
- Doğrulanmış paket oluşturma ve PyPI Trusted Publishing için GitHub Release iş akışı.

### Kapsam ve sınırlamalar

- Yerel kaynak kontrolleri sezgiseldir ve insan incelemesi gerektirir; temiz sonuç projenin güvenli olduğunu kanıtlamaz.
- API kontrolleri yalnızca tanımlı güvenli HTTP yöntemlerini çalıştırır. Uç nokta keşfetmez, fuzzing yapmaz ve uygulamanın yetkilendirme politikasını çıkarmaz.
- Bağımlılık sorgusu paket adı, ekosistem ve sabitlenmiş sürümü OSV'ye gönderir; kaynak dosyalar veya kilit dosyaları yüklenmez.
- Uzak API testleri isteğe bağlıdır; HTTPS ve tam sunucu adı/port izin listesi gerektirir.
