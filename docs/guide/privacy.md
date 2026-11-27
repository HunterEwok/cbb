<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Privacy: who sees what

For anyone who wants to know what data leaves their devices, what every server and platform can
observe, and how to limit or turn off each exposure. Connect Beyond Borders uses no accounts, no
cloud clipboard storage, and no analytics telemetry.

## What happens to your copies

Every copy—plain text, secrets, formatted text, images, and files—is encrypted end to end before
leaving the device where you copied it:

1. The copying device creates a fresh 32-byte key for that single copy and encrypts the content
   with ChaCha20-Poly1305.
2. It wraps that key individually for each reading device in your group using HPKE with **X-Wing**
   (combining X25519 and post-quantum ML-KEM-768) and signs the copy with its own member key
   (ECDSA P-256).
3. The sealed copy travels inside a mutual **TLS 1.3** connection using your group's device keys,
   and away from home inside your group's **WireGuard** tunnel as well.

No server, network, internet provider, or intermediate device without a reading key can read,
alter, or forge a copy. A removed device receives no future copies, and a newly joined device
cannot decrypt copies made before it joined.

## What the devices in between see

A copy can pass through another device in your group before reaching its destination—for example,
through your hub away from home or through another member on your home network. A device that only
passes copies on cannot open the seal, so it sees only the envelope metadata needed for delivery:

- **Sender and timestamp:** Which device copied the item and when (needed to decide which copy is
  newest).
- **Recipient list:** Which devices the copy is sealed to (already known to group members from the
  group's device records).
- **Rounded size:** Text payload size rounded to fixed steps (`1`, `4`, `16`, `64`, `256` KB,
  `1` MB, then per megabyte), and whether an image or file attachment is present with its total
  rounded to `64` KB. All files in one copy travel inside a single sealed blob, so file count is
  hidden.

Intermediate devices never see whether a copy is plain text, a secret, an image, or files; never
see the text or filenames; and never see the exact byte size.

## Opt-in exceptions

Certain features involve channels outside Connect Beyond Borders' end-to-end seal. Each requires
your explicit choice:

- **Roku TV remote (`cbb remote add -roku -consent`):** Roku's External Control Protocol uses
  unencrypted HTTP on your home network. Do not send passwords to a Roku
  ([Keyboards and TVs](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- **Hub that reads copies:** A main device or admin computer acting as a hub receives copies
  sealed to it like any other reading device. If your always-on hub keeps keys in files (such as a
  Raspberry Pi or NAS), configure it as a **hub that only passes copies on** so copies are never
  sealed to it ([Away from home](away-from-home.md)). Signed commands (such as remote paste and
  quick actions) are always sealed only to their single target device.
- **Paired watches (Apple Watch, Wear OS, HarmonyOS watch):** A watch communicates with its paired
  phone over the operating system's own encrypted phone-watch channel (WatchConnectivity, Wearable
  Data Layer, or Wear Engine) and displays device status, events, and switches rather than your
  clipboard contents.
- **Bluetooth and USB keyboards:** Text typed through a phone, Linux computer, or Arduino Nano
  ESP32 keyboard travels over Bluetooth or USB directly to the paired target device.

## Everyone outside your group

When syncing away from home is off, the background service communicates only on your home network.
When syncing away from home is on, the service communicates only with your home network and your
group's own hub, forwarder, and relay (enforced in code on every OS and by system firewall/sandbox
rules on Linux and Windows).

Neither a forwarder nor a blind relay ever sees your group's device list, device names, or
permanent device IDs. Instead, your group generates separate temporary **server credentials** for
each server and rotates them every 30 days (and on device removal), so two servers cannot link
your group's traffic together.

The table below lists every party outside your group that can observe any traffic or metadata:

| Party | What they can see | How to avoid or limit it |
|---|---|---|
| **Other devices on your home network** | mDNS broadcasts showing that devices run Connect Beyond Borders, their random device IDs, group tag, and port; which local IP addresses connect and how much data moves. Never device names or clipboard contents | Computers announce only on known home networks and stay silent on unfamiliar Wi-Fi |
| **Networks away from home** (café, hotel, mobile operator, ISP) | Encrypted WireGuard/AmneziaWG UDP packets—or with VLESS, an HTTPS connection to the forwarder's domain (visible in TLS SNI)—plus timing and traffic volume | Run a system VPN on your device to hide destinations and timing |
| **Forwarder** (the project's at `cbb.tools`, or your own) | IP addresses exchanging encrypted WireGuard packets with your hub, packet times, and packet sizes; rotating server-credential tags only, never device names, group membership, or clipboard contents | Forward UDP port 8764 directly to your hub so no forwarder is used, or [run your own forwarder](../admin/self-hosting.md#a-forwarder) |
| **Blind relay** (the project's at `cbb.tools`, or your own) | Rotating device pseudonyms online at the same time, their IP addresses, which pseudonyms talk to each other, timing, and volume (kept in memory only, never written to logs). Never clipboard contents or device names | Use a hub of your own instead of a blind relay, or [run your own relay](../admin/self-hosting.md#a-blind-relay) |
| **Hosting provider of a forwarder or relay** | IP addresses connecting to the server, connection times, and traffic volume | Use a system VPN on your devices, or self-host at a provider you choose |
| **Project push service** (`cbb.tools`) | Phone push token, rotating group face tag, sender IP address, and notification timestamp when waking a closed phone app. Each push body is sealed to the phone and padded to a fixed size, so the service cannot read it | Turn off **Notify me when the app is closed** in phone **Settings** |
| **Phone push platforms** (Apple APNs, Google FCM, or your UnifiedPush distributor such as ntfy) | That a push notification was sent to Connect Beyond Borders on your phone, and when; never the sealed contents | Turn off **Notify me when the app is closed** in phone **Settings**, or use the F-Droid Android build with your own UnifiedPush server instead of Google FCM |
| **Update servers** (GitHub Releases, `raw.githubusercontent.com`, `dl.cbb.tools`, and `cbb.tools/openwrt` for the OpenWrt feed) | Your IP address and that you checked for or downloaded a Connect Beyond Borders release; nothing about your group or copies | Turn off automatic updates (`sudo cbb update -auto off`, or in Android **Settings > About**), or point updates to your own HTTPS mirror (`sudo cbb update -mirror https://...`) |
| **Project signed lists and attestation mirror** (`cbb.tools`) | Your IP address when fetching signed server entry-point lists, or when the main device fetches the daily signed copy of Google's Android attestation revocation list (`https://cbb.tools/attest/`) | The same public files are served to everyone; mirroring avoids contacting Google directly |
| **Project bug report receiver** (`https://bug.cbb.tools/`) | Nothing in this version: the apps do not send bug reports yet, because the key that seals them is not in the build. Once it is, a report goes only after a crash **and** your **Allow** (or **Always allow**): your IP address, app version, crash fingerprint, and a report sealed to the maintainer's robot, with filtered error logs, versions, and device model, never clipboard text, files, keys, pairing codes, device names, or IP addresses | Tap **Cancel** on the crash prompt; nothing is sent without your consent |
| **App stores and package managers** (Apple App Store / TestFlight, Google Play, F-Droid, Homebrew, winget) | That you installed or updated Connect Beyond Borders, as with any app from that store | Install signed release archives or APKs directly from GitHub Releases |
| **Website analytics** (`cbb.tools`) | Page views when you browse `cbb.tools` in a web browser, counted by a self-hosted GoatCounter instance with no cookies and no third-party sharing | The apps and background service never load website pages or analytics |

Logs stay local on each device. Enabling error details (`CBB_DEBUG=1` or **Show error details** in
app settings) adds underlying error details locally and never sends them anywhere automatically.

## More detail

- What a forwarder and a blind relay store on disk:
  [Running your own servers: what the server keeps](../admin/self-hosting.md#what-the-server-keeps).
- Exact wire fields seen by servers and push services:
  [Protocol](../protocol.md), sections 13 and 14.
- Threats defended against and residual risks:
  [Threat model](../threat-model.md).
