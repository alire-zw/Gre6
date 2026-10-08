# GRE6 Tunnel (fixed)

تونل GRE6 بین سرور ایران و خارج — بدون بلاک whitelist رنج‌ها، با پشتیبانی Native IPv6 و 6to4.

## نصب و اجرا

### سرور ایران

```bash
wget -qO gre6-tunnel.sh https://raw.githubusercontent.com/alire-zw/Gre6/main/gre6-tunnel.sh && chmod +x gre6-tunnel.sh && ./gre6-tunnel.sh
```

### سرور خارج

```bash
wget -qO gre6-tunnel.sh https://raw.githubusercontent.com/alire-zw/Gre6/main/gre6-tunnel.sh && chmod +x gre6-tunnel.sh && ./gre6-tunnel.sh
```

روی ایران گزینه `1`، روی خارج گزینه `2` را بزنید.

اگر IPv6 عمومی ندارید یا Native کار نکرد، هر دو طرف حالت `6to4` را انتخاب کنید.
