# YumPi

YumPi is a Raspberry Pi gateway. It runs a Wi-Fi access point, hands out addresses on that network and on the wired LAN, and sends client traffic through Mullvad. Any single device can be switched back to the direct path.

The control plane is one Go binary in a container. The host keeps Docker, Mullvad, and IP forwarding. The container runs hostapd, dnsmasq, and the firewall.

## Install

On a fresh Raspberry Pi OS or Debian system, with the Pi already on the wired network:

```sh
sudo ./install.sh
```

The installer asks for a Wi-Fi name and two passwords, or generates them and prints them once. A second run keeps `/etc/yumpi/config.toml`. These variables skip the prompts:

- `YUMPI_SSID`
- `YUMPI_WIFI_PASSPHRASE`
- `YUMPI_ADMIN_PASSWORD`
- `YUMPI_COUNTRY` (default `US`)

The dashboard is `http://<pi>:8080`. It is password protected and not exposed beyond the networks the Pi is on. Do not forward that port from the internet.

Mullvad has to be logged in once on the host (`mullvad account login`). The installer does not see or store the account.

## What the network does

- Wi-Fi clients use `10.23.46.1/24` by default. Wired clients that take a lease from the Pi use the Pi as their gateway.
- DNS for both is Mullvad's resolver, `10.64.0.1`, so lookups follow the tunnel.
- A device set to direct is marked out of Mullvad's routing table, including a wired client whose packets hairpin back out the LAN port. Its DNS to `10.64.0.1` is sent to `1.1.1.1` instead.
- If the tunnel is down, every client's DNS and traffic use the direct path instead of black-holing.
- The firewall table `inet yumpi` is rebuilt in one shot. DHCP accepts added to Mullvad's chain are marked `yumpi` and replaced, not appended.

## Develop

```sh
go test ./...
```

`config.example.toml` shows the file the installer writes. Real copies stay on the Pi, mode `0600`.

## Remove

```sh
sudo ./install.sh --uninstall
sudo ./install.sh --uninstall --purge
```

`--purge` also deletes `/etc/yumpi`. Mullvad and Docker stay installed.
