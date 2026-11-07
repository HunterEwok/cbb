<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Glossary

The words the documentation, `cbb` and the apps use, in one place. Each entry links to the
page that explains it.

| Term | Meaning |
|---|---|
| **group** | The devices that share one clipboard: phones, computers, lite members, watches and TVs. A group has no central server; its members trust each other through certificates signed by the group's keys. See [how it works](../guide/how-it-works.md). |
| **member** | A device in a group. A **full member** runs the Go service (`cbb` on Linux, macOS, Windows, FreeBSD and routers); a **lite member** runs the small `cbb` in Rust; a **phone** runs the app. |
| **lite member** | `cbb` for small Linux devices and routers, without the group's keys: it joins by the phone's QR code or a computer's code, syncs, and cannot admit or remove devices. See [the lite member](../../lite/README.md). |
| **rootless** | A full member or a lite member on Linux installed without `sudo`, as its user's own service: it syncs, but every program of that user can read its keys, so it is never the root, an admin or a hub. See [installing](../guide/install.md#without-sudo-rootless). |
| **root** | The device that holds the group's root key: the phone or the computer that made the group. It makes admins and has the last word over them. |
| **admin** | A device the root has made an admin: it admits new devices, removes them, renames them and signs commands for the others. Phones, computers and watches can be admins. |
| **admin CA** | The certificate authority under the root that an admin signs with; members accept what an admin signs because the root signed its admin CA. |
| **device record** | A signed note about one device (its name, system, keys, where it keeps them) that every member keeps and passes on. A **revocation record** removes a device. |
| **freeze** | What an admin does to another admin computer that may be stolen: from then on nothing that computer signs counts, until the root decides. |
| **takeover** | How an admin becomes the root when the root is lost: `cbb takeover` on a computer, or the takeover in an admin phone's app. |
| **sync** | Whether a device's clipboard moves with the group's: on, the default, or off, the clipboard its own (`cbb sync`). |
| **secret** | A copy that a password manager marked as secret, or sent with `cbb copy -secret`: kept only in memory and gone after 60 seconds. |
| **home network** | The local networks where the group's devices find each other by mDNS, without a server. |
| **member port** | The TCP port the members talk on at home, 8764 by default. See [ports](devices.md#ports). |
| **away from home** | Sync when the devices are on different networks, through the group's WireGuard tunnel to a hub. See [away from home](../guide/away-from-home.md). |
| **hub** | The device the others reach away from home: a computer or a phone with its app open, reached from the internet directly or through a forwarder. A group may have several hubs in order. |
| **forwarder** | A server with a public address that passes the hub's tunnel traffic to clients that cannot reach the hub directly, for example behind carrier-grade NAT. It holds no keys. See [running your own servers](../admin/self-hosting.md). |
| **blind relay** | A server where the devices of a group without a hub meet away from home. It sees who is online and how much they send, never the content. |
| **server credentials** | The short credentials, made for a period, that a forwarder or a relay checks instead of the group's records, so it learns no device's name or role. |
| **invitation** | A file from `cbb invite` that lets a device away from home join through the hub's tunnel. |
| **AmneziaWG**, **VLESS with REALITY** | Two ways to hide the tunnel from networks that block VPNs. See [networks that block VPNs](../guide/blocked-networks.md). |
| **key level** | Which keys may be the root, an admin or a hub: proven hardware keys only, hardware keys (the default), or file keys too. See [keys and attestation](../guide/keys.md). |
| **attestation** | A proof from a phone's security chip or a computer's TPM that a key was made there and cannot leave it. |
| **remote paste** | An admin puts text into the focused app on another device, where that device's user turned it on (`cbb paste -on`, `cbb paste-receive`). |
| **quick action** | A preset (lock, sleep, reboot, shut down) or a program of the user's own that an admin may run on a device, where that device's user turned it on (`cbb action`). |
| **collection** | A set of devices the user arranges in an app, personal to that installation. |
| **service** | The background program of a full member (`cbb service`), started by systemd, launchd, rc.d, procd or the Windows service manager. |
| **agent** | The program in the user's desktop session that links the desktop's clipboard to the service (`cbb agent`); also called the desktop connector on Linux. |
| **paste helper** | A small program a target needs to press keys for remote paste: `uinput`, `tmux` or `console` (`cbb paste-helper`). |
| **control socket**, **admin socket** | The local sockets `cbb` and the apps talk to the service through; only an administrator of the computer may use the admin socket. |
| **release keys** | The project's keys that sign each release (`keys.json`, `release.json`, `stable.json`), checked by the installers and by updates. |
