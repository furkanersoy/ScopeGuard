# ScopeGuard'ı PyPI'da yayımlama

Depoda `.github/workflows/release.yml` yayın iş akışı bulunur. GitHub Release yayımlandığında wheel ve kaynak arşivini oluşturup doğrular, ardından Trusted Publishing ile PyPI'ya gönderir. Normal push veya pull request sırasında yayın yapmaz.

## Bir defalık kurulum

1. [pypi.org](https://pypi.org/) üzerinde hesap oluşturup e-posta adresini doğrula. Hesapta iki aşamalı doğrulamayı etkinleştir.
2. PyPI hesap ayarlarında **Publishing** sayfasını aç ve bir **pending publisher** oluştur:
   - PyPI proje adı: `scopeguard`
   - Sahip: `furkanersoy`
   - Depo: `ScopeGuard`
   - Workflow adı: `release.yml`
   - Environment adı: `pypi`
3. GitHub deposunda **Settings → Environments** bölümünden `pypi` adında bir environment oluştur. Her yüklemeden önce elle onay istersen gerekli onaylayıcıları ekle.
4. İlk sürüm `0.2.0` yayımlandı. Pending publisher artık projeye bağlandı; sonraki sürümler aynı Trusted Publishing iş akışını kullanır.

Trusted Publishing, GitHub OIDC kimliğini ve kısa ömürlü erişim belirtecini kullanır. Depoda PyPI API token'ı veya GitHub secret saklanmaz. Derleme işinin PyPI yayın izni yoktur; yalnızca ayrı yayın işi `id-token: write` izni alır.

## Sürüm yayımlama

1. `pyproject.toml` içinde yeni sürüm numarasını seç; iki changelog dosyasını ve İngilizce README'yi güncelle.
2. Gözden geçirilmiş değişiklikleri `master` dalına birleştir ve CI'ın geçtiğini doğrula.
3. Sürümle aynı etiketi kullanarak GitHub Release oluştur; örneğin `v0.2.1`. Etiket paket sürümüyle tam eşleşmezse workflow durur.
4. Release workflow'unu bekle. Derleme işi `python -m build` ve `twine check --strict` çalıştırır; yayın işi yalnızca ikisi başarılı olursa başlar.
5. PyPI sürümü işledikten sonra kullanıcılar komut satırı uygulamasını `pipx install scopeguard` ile kurabilir veya `pipx upgrade scopeguard` ile güncelleyebilir. Etkileşimli API menüsü, wheel içindeki demo OpenAPI ve senaryo dosyalarını kullanır; demo sunucusunu başka terminalde `scopeguard-demo` ile başlat.

Kaynak kod, README, bağımlılıklar ve sürüm notları gözden geçirilmeden bir sürümü yayımlama. PyPI'da aynı sürüm numarasındaki dosyalar farklı içerikle değiştirilemez.