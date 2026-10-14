# Blackwall

mitmproxy'yi motor alan, web arayüzlü bir pentest aracı. **Faz 1** kapsamı:

- mitmproxy addon'u ile **tüm HTTP(S) trafiğini yakala** ve SQLite'a kaydet
- FastAPI + basit web UI'da **History** tablosu
- Bir isteği **Repeater**'a gönder, elle düzenle, yeniden yolla

> ⚠️ Yalnızca yetkili olduğunuz hedeflerde / kendi sistemlerinizde kullanın.

HTTP/2 bilerek kapsam dışıdır (sonraki faz). WebSocket desteği eklendi (aşağıya bakın).

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
  - **Repeater** sekmesi: **sekmelidir** — birden çok isteği aynı anda açık
    tutarsınız. Her sekme kendi method/URL/başlık/gövde ve yanıtını saklar;
    üstteki çubuktan sekmeler arası geçilir, `+` ile yeni sekme açılır, `×` ile
    kapatılır, sekme adına **çift tıklayınca** yeniden adlandırılır. Method, URL,
    başlıklar (her satır `İsim: değer`) ve gövdeyi düzenleyip **Gönder**'e basın;
    yanıt o sekmede görünür ve akış geçmişe de yazılır.
    - İstek göndermek için önce **İstek** panelindeki **→ Repeater (yeni sekme)**
      ile seçili History akışını yeni bir sekmeye alın (mevcut sekmeler ezilmez).
    - *TLS doğrula*: kapalıyken sunucu sertifikası doğrulanmaz (geçersiz/self-signed
      hedefler için pratik). Açıkken normal doğrulama yapılır.
    - *yönlendirme izle*: 3xx yanıtlarını otomatik takip eder.
  - **Inspector** sekmesi *(salt-okunur)*: seçili isteğin query parametrelerini,
    cookie'lerini ve başlıklarını ayrıştırıp okunur tablolarda listeler.
  - **Intruder** sekmesi: otomatik payload saldırıları (httpx ile).
    - **Seçili isteği yükle** ile History/Repeater'daki isteği ham olarak alın
      (ya da elle yapıştırın). Payload konacak yerleri `§...§` ile işaretleyin —
      metni seçip **seçimi işaretle**'ye basmak da aynısını yapar. `http/https`
      şemasını seçin.
    - **Saldırı tipleri:**
      - *sniper* — tek liste; her konuma sırayla uygulanır (toplam = konum × liste).
      - *pitchfork* — konum başına bir liste; listeler eşli ilerler (toplam = en kısa liste).
      - *cluster bomb* — konum başına bir liste; tüm kombinasyonlar (toplam = çarpım).
    - **Payload listeleri:** her kutuya satır satır yapıştırın; ya da üreteçlerle
      ekleyin — *sayı aralığı* (başlangıç/bitiş/adım) ve *karakter seti* (her
      karakter bir payload).
    - *eşzamanlılık* ayarlanabilir (1–100, varsayılan 10). Toplam istek üst sınırı
      **10 000**'dir. **Başlat** / **İptal** ile yönetilir, ilerleme canlı görünür.
    - **Sonuç tablosu:** payload(lar), status, yanıt uzunluğu, süre (ms), hata.
      Her kolon başlığına tıklayarak sıralanır; status (ör. `200` veya `2,3`
      önekleri), min/max uzunluk ve "sadece hatalılar" ile filtrelenir. Bir satıra
      tıklayınca **gönderilen ham istek** (gerçekten gönderilen byte'lar) ve
      **tam yanıt** aşağıda görünür.
    - **grep-match:** saldırı ayarlarına satır satır arama metinleri girilir; her
      denemenin **yanıt gövdesinde** bu metinler aranır ve sonuç tablosuna her metin
      için bir **✓/✗ sütunu** eklenir. Bu sütunlara göre de sıralama ve filtreleme
      (hepsi / var / yok) yapılabilir. (Mevcut tablo/filtreler korunur.)
    - İstek gönderimi **Repeater ile birebir aynı ortak koddan** geçer
      (`blackwall/httpsend.py`): Intruder yalnızca payload'ı `§...§` konumlarına
      yerleştirir, sonra aynı fonksiyonu çağırır. Payload yerleştikten sonra
      `Content-Length` gövdenin gerçek uzunluğuna göre **yeniden hesaplanır**
      (Repeater'da da aynı), böylece iki araç aynı isteği aynı byte'larla gönderir.
    - Tamamen yerel/offline; istekler doğrudan hedefe httpx ile gider (proxy'den
      geçmez).
  - **OAST** sekmesi: out-of-band etkileşim yakalama (interactsh protokolü, saf
    Python — dış binary yok). SSRF, kör (blind) enjeksiyon, XXE gibi doğrudan
    yanıt dönmeyen zafiyetleri dışarıdan tetiklenen DNS/HTTP istekleriyle tespit
    etmek için.
    - **Sunucu** adresi değiştirilebilir (varsayılan `oast.pro`; ileride kendi
      interactsh VPS'inize yöneltebilirsiniz). Public sunucuda token boş bırakılır.
    - **Başlat**: bir RSA-2048 anahtar çifti üretir, sunucuya kaydolur ve size
      `xxxx.oast.pro` biçiminde bir subdomain verir. **Yeni subdomain üret** aynı
      kayıt altında ek subdomainler oluşturur (hepsi aynı poll'a düşer).
      Subdomain'e tıklayınca panoya kopyalanır.
    - Arka planda periyodik poll edilir; gelen etkileşimler (protokol, DNS sorgu
      tipi, kaynak IP, zaman) tabloya yazılır. Satıra tıklayınca ham istek/yanıt
      detayı görünür. **Poll'u duraklat / sürdür** ve **Durdur** (kaydı siler)
      düğmeleri vardır.
    - Protokol detayları: poll yanıtındaki AES anahtarı RSA-OAEP(SHA-256) ile,
      her etkileşim AES-256-CTR ile yerel olarak çözülür. Kayıt/poll için yalnızca
      seçilen interactsh sunucusuna bağlanılır.
  - **Decoder** sekmesi: girdiye üst üste **katmanlar** uygulayın —
    base64 (standart ve url-safe), url, HTML entity, hex, ascii (ondalık kod)
    encode/decode; ayrıca md5 / sha1 / sha256 hash. Her katmanın ara çıktısı
    sırayla görünür; sondaki sonuç kopyalanabilir. Tamamen offline (yerel hesaplama).
  - **JWT** sekmesi: token yapıştırıp **Çöz**'e basın → header/payload dolar.
    Düzenleyip **alg:none olarak üret** ya da bir secret girip **HS256 imzala**.
    Çıkan token kopyalanabilir. HMAC yerel olarak (hmac/hashlib) hesaplanır,
    dış servis kullanılmaz.
  - **WebSocket** sekmesi: proxy'den geçen WebSocket trafiği.
    - Addon, yükseltilen her bağlantıyı (`websocket_start`) ve her mesajı
      (`websocket_message`) yakalar: yön (client→server / server→client), tip
      (text/binary), zaman ve içerik `ws_flows` / `ws_messages` tablolarına yazılır.
      History'den ayrı, **bağlantıya göre gruplu** gösterilir.
    - Sol listeden bir bağlantı seçilir; sağda mesajlar kronolojik akar
      (▲ c→s sarı, ▼ s→c yeşil). Yeni mesajlar canlı eklenir.
    - **Enjeksiyon (Repeater karşılığı):** bağlantı hâlâ açıksa yön (c2s/s2c) ve
      tip seçip mesaj gönderilir — mesaj **gerçekten** canlı bağlantıya iletilir
      ve karşı tarafın yanıtı akışta görünür. Enjekte mesajlar vurgulanır ve
      "⟵ enjekte" ile işaretlenir. Bağlantı kapandıysa gönderim reddedilir.
    - *Nasıl çalışır:* web süreci enjeksiyon isteğini `ws_inject` kuyruğuna yazar;
      mitmproxy sürecindeki addon kuyruğu yoklar ve canlı akışa `inject.websocket`
      komutuyla mesajı iletir (iki süreç yalnızca SQLite paylaşır).
  - **Raw** sekmesi: ham TCP/TLS istek göndericisi (HTTP request smuggling /
    desync araştırması için). Repeater'dan ayrıdır ve ona dokunmaz.
    - **Tamamen ham soket** (stdlib `socket`/`ssl`; httpx/requests kullanmaz).
      Yazdığınız byte'lara dokunulmaz: `Content-Length` / `Transfer-Encoding`
      otomatik hesaplanmaz, header sırası korunur, chunked gövde olduğu gibi gider.
    - **host / port / TLS / SNI** seçilir. TLS'de sertifika doğrulanmaz (ALPN
      ayarlanmaz → sunucu HTTP/1.1 kullanır).
    - **Satır sonu modu:**
      - `CRLF` (varsayılan) — textarea'daki satır sonları `\r\n` yapılır.
      - `LF` — satır sonları `\n` kalır (bare-LF testleri).
      - `escape` — gerçek satır sonları yok sayılır; byte'ları `\r \n \t \0 \xHH`
        ile birebir yazarsınız (tam kontrol; null byte, bare CR vb.).
    - **İki istek** (2. opsiyonel) aynı socket'e **pipeline** olarak yazılır:
      ilk yanıt beklenmeden art arda gönderilir, sonra gelen TÜM veri okunup
      yanıtlara ayrılır (Content-Length / Transfer-Encoding: chunked / EOF'a göre).
      Böylece ilk yanıtta `Connection: close` olsa bile ikinci yanıt (ör. 404)
      yakalanır — CL.TE / TE.CL desync testleri için şarttır. İkinci istekten önce
      gecikme (ms) ayarlanabilir. Tek istek gönderiminde eski davranış korunur
      (gönder → yanıtı oku).
    - **timeout** (toplam) ve **read-idle** (yanıt bitti saymadan önce beklenen
      boşta süre) ayarlanabilir. Yanıt **ham byte** olarak (latin-1) ya da **hex
      dump** gösterilir; gönderilen ham byte'lar da (çerçevelemeyi doğrulamak için)
      açılır.
  - **Race** sekmesi: race condition saldırısı (**last-byte synchronization**,
    HTTP/1.1) veya **single-packet** (HTTP/2). Ham socket altyapısını kullanır.
    - **sync modu** seçilir:
      - **last-byte (HTTP/1.1):** ham istek **N kez ayrı bağlantılarla** gönderilir;
        her isteğin **son baytı tutulur**, tüm bağlantılar bir bariyerde buluşunca
        son baytlar aynı anda basılır → istekler ~eşzamanlı varır.
      - **single-packet (HTTP/2):** `h2` (saf Python) ile **tek TLS bağlantısı**
        (ALPN h2) açılır; N istek ayrı stream olarak hazırlanır (HEADERS + varsa
        gövde, END_STREAM yok), hepsi hazır olunca tüm stream'lerin END_STREAM
        frame'leri **TEK `write()`** ile (tek TCP paketi) gönderilir → tüm istekler
        sunucuya tek pakette, eş zamanlı varır. TLS zorunludur. PortSwigger'ın
        single-packet tekniği.
    - `N` (2–255), `prefix gecikme` (son bayttan önce sunucunun prefix'i
      tamponlaması için beklenen süre), `timeout` ve `read-idle` ayarlanabilir.
    - **Seçili isteği yükle**: History/Repeater'daki isteği alır — TÜM header'lar
      (cookie dahil) ve gövde (csrf dahil) **birebir** korunur. Hedef host/port/şema
      flow'dan çözülür (Host satırına güvenilmez; host elle doldurulmaz).
    - Gönderilen ham byte dizisi, **Repeater'ın (httpx) gönderdiğiyle birebir
      aynıdır**: payload Repeater'la aynı httpx yolundan kurulup httpx'in tel (wire)
      byte'ları olarak yazılır (Host başlığı önde, aynı başlık ekleme/sıralaması,
      `Content-Length` gerçek gövdeden). TLS'te SNI gönderilir ve ALPN `http/1.1`'dir
      (Repeater'ın TLS'iyle aynı). Son baytı ayırma (last-byte sync) korunur.
    - `N=1` tek istek gönderir. Gönderilen istek, debug için metin veya **hex dump**
      (checkbox) olarak gösterilir.
    - **Sonuç tablosu:** her bağlantının status, yanıt uzunluğu, son baytın
      gönderildiği an (`@ms`) ve yanıtın vardığı an (`@ms`). Son-bayt anlarının
      yayılımı (`sync ±…ms`) senkron kalitesini gösterir.
    - **Race kazanan** satırlar ayırt edilir: en sık görülen (status, uzunluk)
      imzası "normal" kabul edilir; ondan **farklı** dönen satırlar yeşil
      vurgulanır ve `★` ile işaretlenir. Satıra tıklayınca **gönderilen ham istek**
      (tüm bağlantılarda aynı) ve tam yanıt görünür.

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
- `blackwall/addon.py` — HTTP (`response`/`error`) ve WebSocket
  (`websocket_start`/`message`/`end`) olaylarını kaydeden addon; `ws_inject`
  kuyruğunu işleyip canlı bağlantılara mesaj enjekte eder.
- `blackwall/web/app.py` — History/Repeater/Inspector/Intruder/OAST/WebSocket API'leri.
- `blackwall/oast.py` — interactsh (OAST) istemcisi (saf Python).
- `blackwall/raw.py` — ham TCP/TLS istek göndericisi (stdlib socket/ssl); Race
  last-byte (HTTP/1.1) ve single-packet (HTTP/2, `h2`).
- `blackwall/httpsend.py` — Repeater & Intruder'ın ortak httpx gönderim yolu.
- `blackwall/tools.py` — Decoder/JWT/Intruder yardımcıları.
- `blackwall/web/static/` — tek sayfalık arayüz (vanilla JS).

## Yol haritası

- **Faz 2:** HTTP/2, akış değiştirme (intercept), scope/filtre kuralları.
