<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Glossary

For all readers looking up the exact terms used in Connect Beyond Borders apps, command-line
tools, and documentation. Where the apps use a dedicated user-facing label, that label appears
first, with the protocol or CLI term in parentheses. Entries are in alphabetical order.

| Term | Meaning |
|---|---|
| **admin** | A device chosen by the main device to admit, remove, rename, or freeze devices and send signed commands. Phones and computers can be admins; the protocol also defines limited admin rights for a paired watch. |
| **admin key** | The signing key an admin uses to sign group records and commands, authorized by a record signed by the main device. |
| **Admin keys** (*key level*) | Group setting controlling which key storage tiers may hold main device, admin, or reading hub roles: attested hardware keys (`proven`), hardware keys (`hardware`, default), or file-backed keys (`files`). See [Keys and attestation](../guide/keys.md#the-three-levels). |
| **admin socket** | Local Unix domain socket used for administrative commands that modify the group or device privileges. Accessible only by root (or administrators on Windows). |
| **agent** | Per-session desktop process (`cbb agent`, also called the desktop connector on Linux) that links the graphical clipboard to the background service. |
| **AmneziaWG** | WireGuard-compatible obfuscation layer that randomizes packet headers and adds padding to pass networks that block standard WireGuard. See [Networks that block VPNs](../guide/blocked-networks.md). |
| **attestation** | Cryptographic proof from a phone's security chip or a computer's TPM that a key was generated in hardware and cannot be exported. See [Keys and attestation](../guide/keys.md). |
| **blind relay** (*relay*) | Public meeting-point server for groups without a hub. Devices connect through tunnels and run end-to-end mutual TLS directly between each other; the relay sees temporary pseudonyms, addresses, timing, and volume, never clipboard content. See [How it works](../guide/how-it-works.md#without-a-hub-a-blind-relay). |
| **capabilities** | Bitmask advertised by a member (`admin`, `dials`, `hub`) declaring which roles it can perform. |
| **cbb-helper** | Companion Go binary installed alongside `cbb` on computers to provide TPM and Secure Enclave keys, attestations, desktop clipboard access, Bluetooth LE keyboard, TV remotes, and `uinput` key injection. Omitted on small devices installed with `--no-helper` ([Small devices](../../member/README.md)). |
| **collection** | User-defined subset of devices organized inside an app; stored locally on that installation only. |
| **control socket** | Local Unix domain socket used by everyday CLI commands, desktop agents, and desktop apps to talk to the service. Accessible to members of the `cbb` group (`_cbb` on macOS). |
| **device record** | Signed group record describing one device (name, OS, public keys, key storage tier, role, rights, and capabilities), stored and propagated by every member. |
| **Everywhere** (*away from home*) | Syncing clipboards outside the home network through the group's encrypted WireGuard tunnel to a hub, or through a blind relay. See [Away from home](../guide/away-from-home.md). |
| **forwarder** | Public server (`cbb forward`) that relays encrypted WireGuard packets between away devices and a hub behind provider NAT. Holds no group keys and cannot read clipboard content. See [Running your own servers](../admin/self-hosting.md). |
| **freeze** | Admin action (`cbb freeze`) that halts a potentially stolen admin computer: members reject its connections and ignore anything it signs after the freeze until the main device unfreezes or removes it. See [If a device is lost](../guide/lost-device.md). |
| **group** | Set of one person's devices sharing a single clipboard, with no central server. Membership and permissions are verified locally from signed group records. See [How it works](../guide/how-it-works.md). |
| **home network** | Local network where group devices discover each other via mDNS and connect directly over mutual TLS without any server. Computers remember known home networks and stay quiet on unfamiliar networks. |
| **hub** | A computer, router, or small board at home that accepts encrypted tunnel connections from away devices, directly or through a forwarder. A phone is never a hub. A group can configure multiple hubs in priority order; a forwarding-only hub passes sealed copies without reading them. See [How it works](../guide/how-it-works.md#away-from-home-the-hub). |
| **invitation** | Single-use secret (file or QR code) created by an admin (`cbb invite` or the phone app) allowing a device away from home to join through a hub's guest tunnel. |
| **main device** (*root*) | Device holding the group's root key (the phone that created the group, or a computer running [without the app](../guide/without-app.md)). Authorizes admins, sets group rules, and has final authority over conflicts. |
| **member** | Any device admitted to a group. Computers and small devices run `cbb`; phones run their platform apps. |
| **member port** | TCP port on which computers and small devices accept home-network connections (`8764` by default). See [Ports](devices.md#ports). |
| **move the group** (*recovery*) | Replacing a lost or retired main device using the group's recovery key (from the printed recovery sheet or a YubiKey) so another member becomes the new main device (`cbb recovery`). See [If a device is lost](../guide/lost-device.md). |
| **paste helper** | Local helper (`cbb paste-helper`) delivering remote paste into non-desktop targets (`tmux`, Linux text `console`) or synthesizing keystrokes (`uinput`). |
| **quick action** | Preset command (`lock`, `sleep`, `reboot`, `shutdown`, `cancel-shutdown`, `restart`, `keyboard-layout`) or user-defined program that an admin can trigger on a computer after that computer's user explicitly enables it (`cbb action`). See [Quick actions](../guide/quick-actions.md). |
| **recovery key** | Offline two-part key generated when a group is created (shown once on the recovery sheet and optionally sealed to a YubiKey) for moving the group to a new main device if the current main device is lost. |
| **release keys** | Project signing keys pinned in `cbb`, apps, and installers to verify `keys.json`, `release.json`, and `stable.json` before installing updates. |
| **remote paste** | Admin action (`cbb paste -on`) that inserts text, images, or files into the focused app, tmux pane, or console on another device whose user turned remote paste on (`cbb paste-receive`). See [Remote paste](../guide/remote-paste.md). |
| **revocation record** | Signed group record that permanently removes a device from the group so all members refuse its connections. |
| **rootless member** (*rootless*) | Linux installation created without `sudo` (`install.sh --rootless`), running under the user's own account. Syncs clipboards like any member, but cannot act as main device, admin, or hub because any process of that user can read its key files. See [Rootless members](../guide/how-it-works.md#rootless-members). |
| **secret** | Clipboard item marked confidential by a password manager (skipped automatically) or sent deliberately as a secret (`cbb copy -secret` or app secret paste): kept in memory only, expires after the group's secret lifetime (60 s by default), and clears from clipboards on expiry. |
| **server credentials** | Short-lived, per-server cryptographic credentials rotated about once a month (and on device removal) so forwarders and blind relays never see permanent device IDs, device names, or group membership lists. |
| **service** | Background daemon (`cbb service`) on computers and small devices, managed by systemd, launchd, rc.d, procd, or Windows Service Manager. |
| **Sync** (*sync*) | Per-device switch (`cbb sync`) controlling whether that device's clipboard exchanges copies with the group. When off, the local clipboard stays private while the device remains connected. |
| **VLESS** | Transport wrapper (VLESS over XHTTP) that tunnels disguised Away traffic inside standard HTTPS requests to a forwarder's web server on networks that block UDP or VPN protocols. See [Networks that block VPNs](../guide/blocked-networks.md). |
