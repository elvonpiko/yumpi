<p align="center">
  <img src="web/favicon.svg" width="72" height="72" alt="YumPi">
</p>

<h1 align="center">YumPi</h1>

<p align="center">A Raspberry Pi gateway that puts the network on Mullvad.</p>

YumPi runs a Wi-Fi access point, hands out addresses, and sends client traffic through a Mullvad tunnel. One dashboard shows who is online and lets any single device take the direct path instead. The rest of the network stays on the tunnel.

The control plane is one Go program in a container. The Pi keeps Docker, the Mullvad daemon, and IP forwarding. The container runs hostapd, dnsmasq, and the firewall.

## Dashboard

The dashboard is on the Pi at `https://<pi>:8443`. If the tunnel drops, YumPi brings it back. Disconnect is the one choice that stays off. These pictures use example devices.

![Overview: who is online, and that a dropped tunnel comes back](docs/overview.png)

![Devices: Wi-Fi or Ethernet, and a switch for the direct path](docs/devices.png)

![Settings: the tunnel comes back unless you disconnect](docs/settings.png)

## What it does

- The installer reads the wired network already on the Pi and asks before it saves it. Wi-Fi uses a separate subnet that does not overlap that network. Wired clients that lease from the Pi use the Pi as their gateway.
- Lookups go to Mullvad DNS (`10.64.0.1`), so they follow the tunnel.
- A device set to direct keeps that choice by its MAC, and its DNS goes to `1.1.1.1`.
- If the tunnel drops, YumPi brings it back. Disconnect is the one choice that stays off. While it is down, clients use the direct path, or pause if that setting is on. A device set to direct keeps that path.
- Guest Wi-Fi can be turned on later. Guests stay on Mullvad and cannot reach the LAN or the dashboard.
- The dashboard is HTTPS only, at `https://<pi>:8443`. Trust the Pi’s certificate once. Do not forward that port from the internet. The sign-in password can be changed in Settings.

## Install

`install.sh` sets up a Raspberry Pi OS or Debian machine that already has ethernet and a working internet connection. Copy this repository onto the Pi, then:

```sh
sudo ./install.sh
```

The script installs Docker and Mullvad when they are missing, builds the image, and starts the container. It finds the wired address and gateway, suggests a Wi-Fi subnet that does not overlap them, and asks you to confirm. It also asks for a Wi-Fi name and two passwords, or generates them and prints them once. A second run keeps `/etc/yumpi/config.toml`.

After it finishes:

1. Log the host into Mullvad once: `mullvad account login`. The installer never sees the account.
2. Join the Wi-Fi it printed and confirm a client has internet.
3. Keep the wired address the installer found. If the upstream router still hands out addresses, give the Pi a fixed address on that same network and turn the router's DHCP off when the Pi should own the wired LAN. Leave the router itself on. Wired computers should reconnect so they take an address from the Pi.

These variables skip the prompts:

- `YUMPI_SSID`
- `YUMPI_WIFI_PASSPHRASE`
- `YUMPI_ADMIN_PASSWORD`
- `YUMPI_COUNTRY` (default `US`)
- `YUMPI_LAN_CIDR` and `YUMPI_UPSTREAM`
- `YUMPI_WIFI_CIDR`

## Develop

```sh
go test ./...
```

`config.example.toml` is the shape of the file the installer writes. Real copies stay on the Pi, mode `0600`.

## Remove

```sh
sudo ./install.sh --uninstall
sudo ./install.sh --uninstall --purge
```

`--purge` also deletes `/etc/yumpi`. Mullvad and Docker stay installed.

## License

MIT. The dashboard fonts are Rubik and DM Mono, both under the SIL Open Font License. Their notices are in `web/fonts/`.
