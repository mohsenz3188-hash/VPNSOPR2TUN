# VPNSOPR

**مالک پروژه: VPNSOPR** · هسته و کنترل‌پنل با Go · وب‌پنل فارسی

نسخهٔ اولیهٔ قابل ساخت برای مدیریت VPN و تونل. تونل داخلی Go و مدیریت پردازش هسته‌های خارجی دو قابلیت جدا هستند. این پروژه نسخهٔ کامل X-UI یا پیاده‌سازی مجدد تمام پروتکل‌های گیت‌هاب نیست.

## قابلیت‌های موجود

- تونل داخلی TCP با TLS 1.3، اعتبارسنجی گواهی و توکن مشترک.
- تونل داخلی دیتاگرام UDP روی TLS، با جداسازی نشست کاربران؛ UDP روی TCP است، نه QUIC.
- وب‌پنل فارسی: تعریف کاربر، UUID، انقضا، فعال/غیرفعال‌سازی، دامنه، ورودی و اوتباند سفارشی.
- ساخت لینک VLESS + WebSocket + TLS؛ مسیر هر ورودی به اوتباند انتخابی.
- اعتبارسنجی کانفیگ با باینری واقعی Xray پیش از اجرا؛ مدیریت اجرا و توقف.
- حذف کاربران منقضی/غیرفعال از کانفیگ Xray فعال حداکثر در یک دقیقه با راه‌اندازی مجدد هسته. اتصال‌های موجود هنگام این اعمال تغییر قطع می‌شوند.
- مدیریت ۲۵ درایور هستهٔ خارجی: کانفیگ اصلی، آرگومان‌ها، شروع، توقف، وضعیت و لاگ محدود.
- تست پینگ، دانلود و آپلود **مرورگر تا پنل**؛ آزمون سرعت مستقل کل اینترنت نیست.
- پشتیبان JSON و بازیابی از بخش ویرایش پیشرفته، فایل خصوصی با سطح دسترسی 0600، نوشتن اتمی.
- ورود با توکن تصادفی، نشست ۸ ساعته HttpOnly/SameSite، محدودیت تلاش ورود، جلوگیری از درخواست cross-origin و CSP.
- Go standard library؛ بدون وابستگی Go و بدون اجرای فرمان از طریق shell در پنل.

## هسته‌های قابل مدیریت

هر ردیف یک **درایور راه‌اندازی پردازش** است. باینری‌ها داخل این بسته نیستند و هیچ‌کدام صرفاً با انتخاب نام نصب نمی‌شوند. کانفیگ و نسخهٔ هسته باید با مستندات خودش مطابقت داشته باشد. ویژگی‌های جدول متعلق به پروژهٔ اصلی‌اند؛ آزمون سرتاسری همهٔ آن‌ها انجام نشده است.

| پروژه | درایورهای پنل | کاربرد / انتقال |
|---|---|---|
| [FRP](https://github.com/fatedier/frp) | `frpc`, `frps` | معکوس، TCP/UDP، QUIC، KCP، WS/WSS |
| [Rathole](https://github.com/rapiz1/rathole) | `rathole` | معکوس TCP/UDP، TLS/Noise با تنظیم مناسب |
| [GOST](https://github.com/go-gost/gost) | `gost` | زنجیره پراکسی، TCP/UDP، TLS، WS، QUIC، SSH |
| [Chisel](https://github.com/jpillora/chisel) | `chisel` | TCP/UDP روی HTTP، SSH، معکوس |
| [Hysteria 2](https://github.com/HyNetworks/hysteria) | `hysteria` | TCP/UDP روی QUIC |
| [Backhaul](https://github.com/Musixal/Backhaul) | `backhaul` | معکوس، TCP، TCPMUX، UDP، WS/WSS |
| [Realm](https://github.com/zhboner/realm) | `realm` | رله TCP/UDP و انتقال‌های وابسته به نسخه |
| [Bore](https://github.com/ekzhang/bore) | `bore` | انتشار سرویس TCP؛ رمزنگاری برنامه لازم است |
| [kcptun](https://github.com/xtaci/kcptun) | `kcptun-client`, `kcptun-server` | TCP روی KCP/UDP |
| [udp2raw](https://github.com/wangyu-/udp2raw) | `udp2raw` | UDP روی FakeTCP/UDP/ICMP؛ نیازمند raw socket |
| [Phantun](https://github.com/dndx/phantun) | `phantun-client`, `phantun-server` | UDP روی FakeTCP؛ TUN و تنظیم شبکه؛ فاقد رمزنگاری مستقل |
| [OpenSSH](https://github.com/openssh/openssh-portable) | `ssh` | TCP محلی/معکوس، SOCKS، رمزنگاری SSH |
| [sing-box](https://github.com/SagerNet/sing-box) | `sing-box` | چندپروتکلی؛ TUIC/WireGuard/TUN در نسخه و کانفیگ پشتیبانی‌شده |
| [Xray](https://github.com/XTLS/Xray-core) | `xray` | کانفیگ کامل، REALITY، VLESS، VMess، Trojan و انتقال‌های پشتیبانی‌شده |
| [V2Ray](https://github.com/v2fly/v2ray-core) | `v2ray` | هستهٔ چندپروتکلی با کانفیگ اصلی |
| [wstunnel](https://github.com/erebe/wstunnel) | `wstunnel` | TCP/UDP روی WebSocket/HTTP2 |
| [Cloudflare Tunnel](https://github.com/cloudflare/cloudflared) | `cloudflared` | انتشار سرویس؛ حساب و تنظیمات Cloudflare لازم است |
| [Brook](https://github.com/txthinking/brook) | `brook` | TCP/UDP، WS/WSS |
| [Shadowsocks Rust](https://github.com/shadowsocks/shadowsocks-rust) | `ssserver`, `sslocal` | پراکسی رمز‌شده TCP/UDP |
| [OpenVPN](https://github.com/OpenVPN/openvpn) | `openvpn` | VPN لایهٔ ۳ با PKI/TUN و تنظیم مسیر |
| [Nebula](https://github.com/slackhq/nebula) | `nebula` | VPN مش با CA، TUN و lighthouse |

WireGuard سیستم‌عامل، IPIP، GRE، SIT، VXLAN و سایر تونل‌های کرنل به مدیریت interface، route، firewall و capability نیاز دارند. این نسخه آن‌ها را خودکار نصب یا تنظیم نمی‌کند؛ کانفیگ WireGuard سازگار را می‌توان از مسیر هستهٔ خارجی پشتیبانی‌شده مدیریت کرد. TCP/UDP، انتقال، پروتکل VPN و ابزار تونل دسته‌های متفاوت‌اند؛ وجود یک نام در فهرست به معنی ساخته‌شدن همهٔ این لایه‌ها داخل Go نیست.

## نصب یکپارچهٔ پنل و هسته‌ها

راهنمای سریع در `START-HERE.txt` است. مسیر اصلی این بسته `VPNSOPR-ALL.sh` است: پنل را از باینری داخلی نصب می‌کند، سپس `install-full.sh` پیش‌نیازهای apt را نصب و `install-engines.py` هسته‌های رسمی قفل‌شده در `engines.lock.json` را دانلود، SHA256 و معماری ELF را بررسی و در پنل ثبت می‌کند. این مسیر اینترنت لازم دارد ولی Go و Release مخزن خودتان لازم ندارد. دانلودها حداکثر سه‌تایی و گزارش هر موتور جدا است. فایل `install-panel.sh` صرفاً پنل را نصب می‌کند؛ مسیرهای قدیمی زیر برای نصب پنل تنها نگه داشته شده‌اند.

فهرست بدون نصب: `python3 install-engines.py --plan`. آزمون دانلود/استخراج در پوشهٔ موقت: `python3 install-engines.py --stage /tmp/vpnsopr-check --only xray,frp`. این حالت apt، سرویس و environment سیستم را تغییر نمی‌دهد.

## نصب مستقیم بدون Release (پنل تنها)

نصب‌کنندهٔ `install-direct.sh` سورس مخزن عمومی شما را دریافت می‌کند، فایل‌های وب آپلودشده در ریشه را در پوشهٔ موقت مرتب می‌کند و برنامه را با Go می‌سازد. اگر Go مناسب نصب نباشد، نسخهٔ پایدار را از go.dev با بررسی SHA256 دریافت می‌کند. نصب واقعی به Linux با systemd، دسترسی root و دسترسی شبکه به GitHub و go.dev نیاز دارد. موتورهای VPN مثل Xray جداگانه نصب می‌شوند.

پس از استخراج این بسته، محتویات آن را در ریشهٔ مخزن جدید آپلود کنید. در دستور زیر نام حساب و مخزن خودتان را در هر دو قسمت جایگزین کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ACCOUNT/YOUR_REPO/main/install-direct.sh | sudo env VPNSOPR_REPO=YOUR_ACCOUNT/YOUR_REPO bash
```

برای صرفاً بررسی دانلود و ساخت، بدون نصب سرویس، آرگومان `--prepare-only` را به نصب‌کننده بدهید. مسیر دیگر، نصب از Release با `install.sh` است. این دو مسیر مستقل هستند.

## فایل‌های بسته

پوشهٔ `dist/` شامل آرشیو باینری Linux برای amd64، arm64 و armv7 و فایل `SHA256SUMS` است. این پوشه با `.gitignore` از commit سورس کنار گذاشته شده است. می‌توانید خروجی‌های آن را دستی به Release گیت‌هاب هم ضمیمه کنید؛ workflow همین خروجی‌ها را دوباره می‌سازد. فایل باینری unpackشدهٔ amd64 هم در `dist/vpnsopr` موجود است.

## ساخت و اجرای محلی

نیازمندی: Go 1.23 یا بالاتر. ساخت Release با Go 1.25 انجام می‌شود.

```bash
go test ./...
go vet ./...
go build -trimpath -o vpnsopr .
export VPNSOPR_ADMIN_TOKEN="$(./vpnsopr --generate-token)"
./vpnsopr --listen 127.0.0.1:8080 --data ./data
```

توکن را در محل امن ذخیره کنید؛ پنل آن را نمایش نمی‌دهد. مرورگر: `http://127.0.0.1:8080`.

برای اتصال به پنل روی VPS، از کامپیوتر خودتان:

```bash
ssh -L 8080:127.0.0.1:8080 root@SERVER_IP
```

سپس همان آدرس محلی را در مرورگر باز کنید. پنل عمومی باید HTTPS داشته باشد. می‌توان `VPNSOPR_PANEL_CERT` و `VPNSOPR_PANEL_KEY` تعیین کرد، یا از reverse proxy استفاده کرد. نمونه Caddy در `deploy/` موجود است؛ در این حالت `VPNSOPR_PUBLIC_HTTPS=1` را تنظیم و پورت داخلی را فقط در دسترس proxy نگه دارید. برنامه هدرهای Forwarded را به‌عنوان هویت کاربر یا مجوز TLS قبول نمی‌کند.

## انتشار نسخه در مخزن فعلی با مرورگر

مخزن این پروژه: https://github.com/YOUR_ACCOUNT/YOUR_REPO

بعد از ادغام اصلاح ساختار پوشه‌ها، برای انتشار نسخه بدون ترمینال:

۱. در مخزن به تب **Actions** بروید.
۲. گردش‌کار **Build, test and release** را انتخاب کنید.
۳. **Run workflow** را بزنید، شاخهٔ **main** و نسخهٔ جدید مثلا `v0.1.0` را انتخاب و اجرا کنید.
۴. تا موفقیت دو job با نام‌های `test` و `release` صبر کنید.
۵. در بخش **Releases** وجود سه فایل `vpnsopr_linux_*.tar.gz` و `SHA256SUMS` را بررسی کنید.

هر نسخه باید شمارهٔ جدید داشته باشد. گردش‌کار Release موجود یا تگ مربوط به commit دیگر را بازنویسی نمی‌کند. انتشار خودکار فقط هنگام اجرای دستی یا push تگ انجام می‌شود؛ ادغام PR به‌تنهایی Release منتشر نمی‌کند.

فقط پس از آماده‌شدن Release، دستور نصب روی VPS لینوکسی دارای systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ACCOUNT/YOUR_REPO/main/install.sh | sudo env VPNSOPR_REPO=YOUR_ACCOUNT/YOUR_REPO bash
```

## آپلود در گیت‌هاب و دریافت دستور تک‌خطی

۱. یک مخزن به نام `VPNSOPR` ایجاد کنید. فایل‌های این پوشه، از جمله `.github/workflows/release.yml`، باید در ریشهٔ مخزن باشند. فایل‌های واقعی `data/`، توکن، گواهی یا کلید خصوصی را آپلود نکنید.

۲. مخزن تازه را با فایل‌های پروژه پر کنید. اگر ترمینال Git دارید:

```bash
git init -b main
git add .
git commit -m "Initial VPNSOPR release"
git remote add origin https://github.com/YOUR_ACCOUNT/VPNSOPR.git
git push -u origin main
git tag v0.1.0
git push origin v0.1.0
```

۳. در تب Actions منتظر موفقیت workflow بمانید. Release شامل فایل‌های Linux برای amd64، arm64 و armv7 و `SHA256SUMS` ساخته می‌شود. برای branch protection و تگ انتشار، تنظیمات متناسب مخزن خودتان را اعمال کنید.

۴. پس از انتشار Release، روی سرور لینوکسی دارای systemd، نام حساب/مخزن خودتان را جایگزین کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ACCOUNT/VPNSOPR/main/install.sh | sudo env VPNSOPR_REPO=YOUR_ACCOUNT/VPNSOPR bash
```

برای نسخهٔ مشخص، آخر خط `bash -s -- v0.1.0` بنویسید. تا وقتی مخزن عمومی، فایل installer و Release موجود نباشند، این خط کار نمی‌کند. هنوز هیچ مخزنی از طرف این بسته ایجاد نشده است.

نصب‌کننده نیازمند `curl`, `tar`, `sha256sum`, `python3`, `systemctl`, `useradd`, `install` است. باینری مناسب معماری را دانلود و با checksum همان Release بررسی می‌کند؛ کاربر غیر root سرویس، تنظیمات خصوصی و systemd ایجاد می‌کند. بار اول توکن را چاپ می‌کند. ارتقا توکن/داده را حفظ می‌کند و سرویس را دوباره راه می‌اندازد؛ تونل‌ها و هسته‌ها را پس از ورود از پنل اجرا کنید.

مسیرها:

- برنامه: `/usr/local/bin/vpnsopr`
- داده: `/var/lib/vpnsopr`
- متغیرها: `/etc/vpnsopr/panel.env`
- سرویس: `vpnsopr.service`

```bash
sudo systemctl status vpnsopr
sudo journalctl -u vpnsopr -n 80 --no-pager
```

سازندهٔ VLESS با Xray نسخهٔ `26.10.29` آزموده شده است؛ نسخه‌های دیگر باید جداگانه اعتبارسنجی شوند.

Xray و سایر باینری‌ها با نصب‌کنندهٔ پنل نصب نمی‌شوند. آن‌ها را از Release رسمی خودشان تهیه کنید.

## فعال‌کردن هسته‌های خارجی

فایل `deploy/panel.env.example` را ببینید. در environment سرویس، مسیر مطلق باینری‌های مجاز را ثبت کنید:

```text
VPNSOPR_XRAY=/usr/local/bin/xray
VPNSOPR_ADAPTER_BINARIES={"frpc":"/usr/local/bin/frpc","frps":"/usr/local/bin/frps","gost":"/usr/local/bin/gost","hysteria":"/usr/local/bin/hysteria","backhaul":"/usr/local/bin/backhaul"}
```

بعد `sudo systemctl restart vpnsopr`. در پنل «هسته‌های تونل»، وضعیت نصب را ببینید. نام نمونه، درایور، آرایهٔ آرگومان و کانفیگ اصلی را وارد کنید. `{config}` به مسیر فایل خصوصی تولیدشده تبدیل می‌شود. مثلا FRP: `["-c", "{config}"]`.

توکن مدیر به محیط فرزندِ adapter منتقل نمی‌شود. هسته با همان کاربر و دسترسی پنل اجرا می‌شود. مدیر پنل باید فرد مورداعتماد اپراتور سرور باشد: کانفیگ اصلی بعضی هسته‌ها دسترسی فایل، پلاگین یا فرمان جانبی دارند و این بخش sandbox اجرای کد نامطمئن نیست. پنل دسترسی root یا capability اضافه نمی‌کند. پیش‌فرض systemd برای پردازش بدون نیاز به TUN/raw socket مناسب است؛ برای هسته‌های نیازمند TUN/raw socket، تنظیمات سرویس و شبکه باید جداگانه و آگاهانه انجام شود. همهٔ هسته‌ها باید در foreground اجرا شوند؛ حالت daemon با مدیریت پردازش این پنل سازگار نیست.

## ساخت اولین VPN

۱. دامنهٔ خودتان را به IP سرور متصل و گواهی TLS معتبر تهیه کنید. پنل فقط دامنه و مسیر فایل‌های گواهی را ذخیره می‌کند؛ DNS و ACME را مدیریت نمی‌کند.

۲. به کاربر سرویس اجازهٔ خواندن گواهی/کلید بدهید؛ فایل‌ها را داخل مسیری قرار دهید که محدودیت systemd مانع دسترسی نشود. کلید را عمومی نکنید.

۳. در «کانفیگ VPN» دامنه، کاربر و ورودی را اضافه کنید. پورت مثلا `8443` را در firewall خودتان باز کنید. اوتباند `direct` یعنی خروج از همین سرور؛ اوتباند سفارشی یعنی خروج از پروکسی موردنظر شما.

۴. «اجرای Xray» را بزنید و وضعیت را بررسی کنید. لینک تولیدی را در کلاینت سازگار وارد کنید. این لینک خودش شبکهٔ TUN روی سیستم‌عامل ایجاد نمی‌کند؛ آن بخش وظیفهٔ کلاینت است.

از کانفیگ‌های سطح پایین پیشرفته مثل REALITY، XHTTP، gRPC، VMess یا Trojan از قسمت درایور `xray` با JSON کامل استفاده کنید؛ فرم سادهٔ سازنده فقط VLESS/WS/TLS است.

## اتصال دو سرور با تونل داخلی

روی سرور خروجی، نمونهٔ `server` بسازید: `listen=0.0.0.0:7000`، مقصد `127.0.0.1:8443`، گواهی دامنهٔ تونل و توکن تصادفی حداقل ۳۲ کاراکتری.

روی سرور ورودی، نمونهٔ `client` بسازید: listener محلی یا عمومی موردنظر، `remote=tunnel.example.com:7000`، `serverName=tunnel.example.com` و همان توکن. برای CA خصوصی مسیر فایل CA را تعیین کنید. هر دو طرف را از پنل خودشان اجرا کنید. پنلِ یک سرور به سرور دوم دسترسی مدیریتی خودکار ندارد.

برای UDP، هر دو سمت `protocol=udp` باشند. listener سمت کلاینت UDP، کانال بین دو سرور TLS/TCP و مقصد سمت سرور UDP است. حداکثر دیتاگرام 65507 بایت؛ نشست‌ها ۵ دقیقه بیکاری منقضی می‌شوند. MTU عملی شبکه ممکن است پایین‌تر باشد. در شبکهٔ پرتلفات، UDP روی TCP ممکن است تأخیر ایجاد کند؛ درایور QUIC مثل Hysteria/FRP جایگزین جداگانه‌ای است.

بهینه‌سازی‌های موجود: بافر قابل استفادهٔ مجدد ۳۲ KiB برای TCP، انتقال دوطرفه، half-close، سقف ۱۲۸ اتصال/نشست در هر تونل، صف محدود UDP، timeout اتصال/بیکاری و محدودیت هم‌زمانی تست سرعت. ادعای افزایش سرعت یا بنچمارک اینترنتی ارائه نشده است.

## مرز قابلیت‌های این نسخه

سهمیهٔ حجمی و حسابداری قابل اتکا برای هر کاربر، محدودیت IP کاربر، پرداخت، چندمدیری، QR، اشتراک عمومی کاربر، مدیریت کلاستر، مدیریت خودکار DNS/ACME، تنظیم خودکار route/firewall، high availability و تمام قابلیت‌های X-UI در این نسخه پیاده نشده‌اند. «جعل IP مبدأ» وجود ندارد؛ IP خروجی با انتخاب اوتباند/سرور خروجی تغییر می‌کند.

تنظیمات و بکاپ محرمانه‌اند. تغییرات ذخیره‌شدهٔ Xray فعال طی یک دقیقه با restart اعمال می‌شوند؛ برای تونل‌های داخلی و adapterها توقف/اجرای مجدد دستی لازم است. شروع خودکار تونل‌ها بعد از reboot وجود ندارد. لاگ Xray در هر اجرا حداکثر ۱۰ MiB روی دیسک و لاگ adapter در حافظه حداکثر ۸ KiB نگهداری می‌شود و دادهٔ محرمانهٔ هسته ممکن است داخل آن باشد.

## آزمون‌ها

```bash
go test -race ./...
go vet ./...
bash -n install.sh
node --check web/app.js
# Optional: a real, locally installed Xray executable. No external target is contacted.
VPNSOPR_TEST_XRAY=/absolute/path/to/xray go test -run TestXrayVLESSRoundTrip -v
```

آزمون‌ها: TCP/UDP رمز‌شده با چند اتصال، رد توکن نادرست، فیلتر کاربران منقضی/غیرفعال، اعتبارسنجی تنظیمات، مجوز فایل، ورود/خروج، CSRF، محدودیت ورود و محدودیت نصب درایور. پوشش عملی همهٔ هسته‌های خارجی و نصب systemd روی VPS در این محیط انجام نشده است. قبل از استفادهٔ واقعی روی دو سرور تحت کنترل خودتان آزمون کنید.

## توسعهٔ درایور جدید

در `adapters.go` ردیف جدید با ID، لینک پروژه، آرگومان و توضیح نیازمندی به `catalog` اضافه کنید و مسیر باینری را به allowlist اپراتور بدهید. پنل آن را خودکار در فهرست نشان می‌دهد. درایورهای نیازمند چرخهٔ راه‌اندازی چندمرحله‌ای یا تغییر شبکه به پیاده‌سازی جدا نیاز دارند؛ افزودن نام تنها معادل پشتیبانی کامل نیست.

مجوز کد این پروژه MIT است. پروژه‌های خارجی مالک، زبان و مجوز مستقل دارند و مالکیت آن‌ها به VPNSOPR منتقل نمی‌شود.
