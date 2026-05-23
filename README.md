# heisspunk

Wi-Fi hotspot manager wrapping hostapd. Built-in DHCP and DNS — no dnsmasq dependency.

## Runtime Dependencies

`hostapd`, `iptables`, `iw`, `ip`

## Config

`~/.config/heisspunk/config.toml` — generate a documented default:

```zsh
heisspunk generate-config
```

## Usage

```zsh
heisspunk start            # start hotspot (requires root)
heisspunk stop             # kill hostapd, remove NAT rules
heisspunk status           # running / stopped
heisspunk show             # dump resolved config
heisspunk config-path      # print XDG config path
heisspunk generate-config  # write default config to XDG path
```

CLI flags mirror config fields and take precedence: `--interface`, `--ssid`, `--passphrase`, `--channel`, etc.