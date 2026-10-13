# Blackwall

mitmproxy'yi motor alan, web arayüzlü bir pentest aracı. **Faz 1** kapsamı:

- mitmproxy addon'u ile **tüm HTTP(S) trafiğini yakala** ve SQLite'a kaydet
- FastAPI + basit web UI'da **History** tablosu
- Bir isteği **Repeater**'a gönder, elle düzenle, yeniden yolla

> ⚠️ Yalnızca yetkili olduğunuz hedeflerde / kendi sistemlerinizde kullanın.

HTTP/2 ve WebSocket bilerek kapsam dışıdır (sonraki faz).

---

## Kurulum

```bash
cd Blackwall
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Çalıştırma

Tek komutla proxy + web UI:

```bash
./run.sh
```

- **Proxy**: `http://127.0.0.1:8080` — tarayıcı/cihaz proxy ayarına bunu girin
- **Web UI**: `http://127.0.0.1:8000`
- **DB**: `blackwall.db` (proje kökünde)

Portları/DB'yi ortam değişkenleriyle değiştirebilirsiniz:

```bash
PROXY_PORT=9090 WEB_PORT=9000 BLACKWALL_DB=/tmp/run1.db ./run.sh
```

İki süreci elle de başlatabilirsiniz (aynı `BLACKWALL_DB` değerini verin):

```bash
export BLACKWALL_DB="$PWD/blackwall.db"
PYTHONPATH="$PWD" .venv/bin/mitmdump -s blackwall/addon.py --listen-port 8080
.venv/bin/uvicorn blackwall.web.app:app --port 8000
```

---

## mitmproxy sertifikası (HTTPS yakalama)

HTTPS trafiğini çözebilmek için mitmproxy araya kendi sertifikasını koyar. Bunu
istemcinin güvenmesi gerekir; aksi halde HTTPS siteleri sertifika hatası verir.

### 1. Sertifikayı üret

Proxy ilk kez çalıştığında CA dosyaları **`~/.mitmproxy/`** altında oluşturulur:

| Dosya | Kullanım |
|-------|----------|
| `mitmproxy-ca-cert.pem` | Linux / Firefox / cURL / Python |
| `mitmproxy-ca-cert.cer` | Windows / Android |
| `mitmproxy-ca-cert.p12` | Windows (parolasız) |

Henüz yoksa proxy'yi bir kez başlatın (`./run.sh`) ya da proxy açıkken
tarayıcıdan **http://mitm.it** adresine gidin; sayfa platformunuza uygun dosyayı
ve adımları verir.

### 2. Sertifikayı güvenilenlere ekle

**Tarayıcı proxy ayarı** (örnek, sistem geneli): HTTP ve HTTPS proxy olarak
`127.0.0.1:8080` girin.

**Firefox** (kendi sertifika deposu vardır):
Settings → Privacy & Security → Certificates → View Certificates →
Authorities → Import → `~/.mitmproxy/mitmproxy-ca-cert.pem` → "Trust this CA to
identify websites" işaretleyin.

**Linux (sistem geneli, Debian/Ubuntu):**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem \
        /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

**Linux (Arch/CachyOS):**
```bash
sudo trust anchor ~/.mitmproxy/mitmproxy-ca-cert.pem
# ya da:
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem \
        /etc/ca-certificates/trust-source/anchors/mitmproxy.pem
sudo update-ca-trust
```

**macOS:**
```bash
sudo security add-trusted-cert -d -p ssl -k /Library/Keychains/System.keychain \
     ~/.mitmproxy/mitmproxy-ca-cert.pem
```

**Windows (PowerShell, yönetici):**
```powershell
certutil -addstore root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
```

**Android:** `mitmproxy-ca-cert.cer` dosyasını cihaza aktarın →
Settings → Security → Encryption & credentials → Install a certificate →
CA certificate. (Android 7+ uygulamaları kullanıcı CA'larına varsayılan
güvenmez; test uygulamasının `network_security_config`'i ya da rootlu cihaz
gerekebilir.)

### 3. cURL / Python ile test

```bash
curl -x http://127.0.0.1:8080 \
     --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem \
     https://example.com
```

> İşiniz bitince sertifikayı güven deposundan **kaldırmayı** unutmayın; aksi
> halde proxy kapalıyken de bu CA güvenilir kalır.

---

## Web UI

- **Sol panel — History:** yakalanan tüm akışlar (en yeni üstte). Arama kutusu
  URL/host/method'a göre filtreler. "Otomatik yenile" açıkken 2 sn'de bir tazelenir.
  Repeater'dan gönderilen istekler `repeater` kaynağıyla işaretlenir.
- **Sağ panel:**
  - **İstek / Yanıt** sekmeleri: seçili akışın ham başlık ve gövdesi. İkili
    (binary) gövdeler base64 gösterilir.
  - **Repeater** sekmesi: seçili akış otomatik yüklenir. Method, URL, başlıklar
    (her satır `İsim: değer`) ve gövdeyi düzenleyip **Gönder**'e basın. Yanıt
    altta görünür ve akış geçmişe de yazılır.
    - *TLS doğrula*: kapalıyken sunucu sertifikası doğrulanmaz (geçersiz/self-signed
      hedefler için pratik). Açıkken normal doğrulama yapılır.
    - *yönlendirme izle*: 3xx yanıtlarını otomatik takip eder.

---

## Mimari

```
tarayıcı/cihaz ──▶ mitmdump (addon.py) ──▶ hedef
                        │
                        ▼
                   blackwall.db  (SQLite, WAL)
                        ▲
                        │
         FastAPI (web/app.py) ◀──▶ web UI (static/)
                        │
                        └── Repeater: httpx ile istek yollar
```

- `blackwall/db.py` — SQLite şeması ve erişim fonksiyonları. Addon ve web aynı
  dosyayı WAL modunda paylaşır.
- `blackwall/addon.py` — `response`/`error` olaylarında akışı kaydeden addon.
- `blackwall/web/app.py` — History/detay API'si ve Repeater endpoint'i.
- `blackwall/web/static/` — tek sayfalık arayüz (vanilla JS).

## Yol haritası

- **Faz 2:** HTTP/2, WebSocket, akış değiştirme (intercept), scope/filtre kuralları.
