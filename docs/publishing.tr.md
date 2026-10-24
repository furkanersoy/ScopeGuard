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
4. Pending publisher'daki proje adı, `pyproject.toml` içindeki `[project].name` ile aynı olmalı. Pending publisher ilk başarılı yayına kadar adı rezerve etmez; ilk sürümden önce adın hâlâ müsait olduğunu kontrol et.

Trusted Publishing, GitHub OIDC kimliğini ve kısa ömürlü erişim belirtecini kullanır. Depoda PyPI API token'ı veya GitHub secret saklanmaz. Derleme işinin PyPI yayın izni yoktur; yalnızca ayrı yayın işi `id-token: write` izni alır.

## Sürüm yayımlama

1. `pyproject.toml` içindeki sürümü ayarla (ilk yayın için mevcut sürüm `0.2.0`).
2. Sürüm değişikliğini `master` dalına birleştir.
3. Sürümle aynı etiketi kullanarak GitHub Release oluştur; örneğin `v0.2.0`. Etiket paket sürümüyle tam eşleşmezse workflow durur.
4. Release workflow'unu bekle. Derleme işi `python -m build` ve `twine check --strict` çalıştırır; yayın işi yalnızca ikisi başarılı olursa başlar.
5. PyPI ilk yayını işledikten sonra kullanıcılar komut satırı uygulamasını `pipx install scopeguard` veya `py -m pip install --user scopeguard` ile kurabilir.

Kaynak kod, README, bağımlılıklar ve sürüm notları gözden geçirilmeden bir sürümü yayımlama. PyPI'da aynı sürüm numarasındaki dosyalar farklı içerikle değiştirilemez.