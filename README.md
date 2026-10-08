# Universal Iran–Kharej Tunnel

نسخه اصلاح‌شده برای کار روی بیشتر سرورها.

**پیش‌فرض پیشنهادی: FOU (GRE داخل UDP روی IPv4)** — چون GRE خام / GRE6 روی خیلی از رنج‌ها فیلتر می‌شود.

اگر کرنل FOU نداشت، از **WireGuard** استفاده کنید.

## نصب

### سرور ایران

```bash
wget -qO gre6-tunnel.sh https://cdn.jsdelivr.net/gh/alire-zw/Gre6@main/gre6-tunnel.sh && chmod +x gre6-tunnel.sh && ./gre6-tunnel.sh
```

### سرور خارج

```bash
wget -qO gre6-tunnel.sh https://raw.githubusercontent.com/alire-zw/Gre6/main/gre6-tunnel.sh && chmod +x gre6-tunnel.sh && ./gre6-tunnel.sh
```

## تنظیم

1. روی هر دو سرور اول گزینه `3` (Remove) اگر قبلاً نصب بوده
2. خارج: گزینه `2` — Transport = `5) Auto` یا `1) FOU`
3. ایران: گزینه `1` — همان Transport و همان UDP port (پیش‌فرض `5555`)
4. MTU: برای FOU معمولاً `1400`، اگر مشکل بود `1280`
5. تست: از ایران `ping 172.16.1.2`

اگر jsDelivr کش قدیمی داد:

```bash
wget -qO gre6-tunnel.sh "https://raw.githubusercontent.com/alire-zw/Gre6/main/gre6-tunnel.sh" && chmod +x gre6-tunnel.sh && ./gre6-tunnel.sh
```
