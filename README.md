# Cudy WR3600 (BCM6764) — Linux 6.6 + OpenWrt 24.10

Custom firmware for the **Cudy WR3600 V1.0** (Wi-Fi 7 "BE3600", Broadcom
BCM6764): vanilla **Linux 6.6.93** and an **OpenWrt 24.10.2** userspace on a
router that has no upstream OpenWrt support. Wi-Fi works through the device's
own Broadcom `wl.ko` driver (built for the vendor's 4.19 kernel) running on 6.6
behind a small open-source compatibility layer.

Русская инструкция по установке: [`docs/INSTALL.ru.md`](docs/INSTALL.ru.md).
Обсуждение и поддержка — тема на 4PDA
«[Cudy WR3600 и WR3600H – обсуждение](https://4pda.to/forum/index.php?showtopic=1103718)».

## What works

* Boot from the router's own dual-slot layout: the firmware lives in **slot 1**,
  the factory firmware stays in slot 2 for rollback; loader, U-Boot and board
  data are never written.
* **Ethernet**: SoC switch (SF2 + SystemPort), 2.5G SerDes to the external
  BCM53134 switch, all four wired ports (see limitations).
* **Wi-Fi**: both radios (2.4 GHz + 5 GHz, 2×2, 802.11ax) as access points,
  WPA2, clients get DHCP and NAT to the internet. 11be/MLO are not enabled yet.
* **LuCI**, SSH, panel LEDs, watchdog-backed `reboot`, podkop/sing-box
  preinstalled (bring your own key).
* Reproducible build: two runs of `tools/build_release.sh` produce identical
  images.

## Limitations (this release)

* The **physical WAN port does not link** (internal GPHY on SF2 port 0). All
  wired ports act as one WAN interface: plug the uplink into any **LAN** port.
  Wired LAN clients are not possible until the WAN/LAN split lands.
* LAN for clients is Wi-Fi only: `192.168.10.1/24`, SSID `CudyWR3600`,
  password `12345678`.
* Settings live in RAM (tmpfs overlay): a reboot returns the box to the
  defaults of the image. Persistent configuration is on the roadmap.
* Wi-Fi is driven by static `hostapd` configs (`/etc/hostapd-wl0.conf`,
  `-wl1.conf`), not by LuCI's wireless page.
* `root` has no password. Admin access from the wired side is limited to
  private (RFC1918) source addresses by default — see `wan_admin` in
  `/etc/config/wifi66`.

## Install

Three ways, none of them needs UART, TFTP or the bootloader — see
[`tools/install/README.md`](tools/install/README.md). The short version, from
your computer (Python 3 + OpenSSH):

```sh
python3 tools/install/cudy-install.py --router 192.168.10.1 --password 'web-ui password' \
    bootfs-release.itb rootfs-forum.sq
```

Firmware files and checksums are on the
[Releases](../../releases) page.

## Repository layout

| Path | Contents |
|---|---|
| `kernel/port/` | kernel patch, device tree, configs, FIT description |
| `kernel/initramfs-release/` | preinit (slot-aware rootfs selection, watchdog fuse) |
| `kernel/rootfs-overlay-forum/` | OpenWrt overlay: `wifi66` init, hostapd, uci configs |
| `port66/enet66`, `port66/enet66b` | Ethernet: SF2 switch, SystemPort, PMC, SerDes, BCM53134 |
| `port66/vpcie66` | virtual PCI host presenting the on-chip radios to the blob |
| `port66/leds66` | panel LED controller |
| `port66/reboot66` | watchdog-based restart (PSCI SYSTEM_RESET hangs this SoC) |
| `port66/shim66`, `bsp-6.6/compat` | `bcm_shim`: the 4.19 → 6.6 compatibility layer for `wl.ko` |
| `tools/` | release build, rootfs cleaning, module patching, `insmodf`, `ubiwrite`, installers |
| `docs/` | release notes, checklist, roadmap, hardware notes |

## Building

`docs/SOURCE_README.md` describes the inputs (vanilla 6.6.93, the vendor GPL
toolchain, an OpenWrt 24.10.2 armsr/armv7 rootfs, the blobs from your own
device) and the steps; `tools/build_release.sh` does the whole thing.

## Licensing

Everything in this repository is **GPL-2.0-only**. The Broadcom Wi-Fi driver
(`wl.ko`, `hnd.ko`, `wlshared.ko`) is proprietary: the release images contain
the copies taken from the device's own factory firmware, this repository does
not. The kernel and OpenWrt are GPL-2.0 (see their trees), podkop/sing-box and
LuCI keep their own licenses.

## Roadmap

`docs/ROADMAP.md` — including what an open-source replacement for the Wi-Fi
blob would take (the radios are a standard Broadcom AXI backplane: D11 MAC rev
139/140, PHY rev 138/136; enumeration and power-up are already open).
