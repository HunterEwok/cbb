<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Names, icon and official builds

Copy Beyond Borders reads your clipboard, and a clipboard sometimes holds passwords. So you
should always know whose build you install. This page says which builds are official, what
belongs to the project, and what others may do with it.

## Official builds

An official build is one of these:

- a release of this repository, from its
  [Releases page](https://github.com/HunterEwok/clipboardbridge/releases), built by the
  repository's release workflow and described by release files signed with the project's
  release keys ([docs/protocol.md, section 16](docs/protocol.md#16-signed-releases));
- an app that the maintainer publishes in an app store.

To check a download:

- The one-line installers, `get.sh` and `get.ps1`, check the archive against the signed
  release files before they install. They refuse an archive the files do not list, or files
  that a release key did not sign. This check starts once the project's root keys are
  pinned in the installers; until then they check the release's `SHA256SUMS`.
- Every release file also has a build provenance attestation that ties it to this
  repository and the build that made it. With the [GitHub CLI](https://cli.github.com/):

  ```sh
  gh attestation verify clipboardbridge-linux-amd64.tar.gz --repo HunterEwok/clipboardbridge
  ```

- The Android app in each release is signed with the project's release key
  ([docs/apps.md](docs/apps.md#releasing-the-android-app)); Android refuses to update it
  with an APK signed by any other key.

[Installing](docs/guide/install.md#checking-a-download) has the details.

## What belongs to the project

- The app icon (`apps/design/icon`, drawn by `tools/icon`).
- The domain `cbb.tools` and its servers: the relay, the forwarder and the package
  repositories.
- The release keys and the root keys that certify them.

## The name

"Copy Beyond Borders", short "CBB", is the name of this project. The borders are the ones
between your own devices, never a way around a network's blocks. The project claims no
exclusive right to "CBB", which others use too, so the full name leads wherever the project
is listed: "CBB: Copy Beyond Borders" in the App Store and Google Play, and "Copy Beyond
Borders" alone in F-Droid and Flathub.

## What you may do without asking

- Talk about the project: "works with Copy Beyond Borders", reviews, articles, videos.
- Share the official releases unchanged.
- Package it for a distribution (Debian, Arch, Homebrew and the like), with patches for
  building and packaging, as long as they do not change the protocol, the cryptography or
  the checks of keys and certificates.
- Fork the code under the [GNU AGPL](LICENSE).

## Builds with other changes

A build with other changes is not an official build. To keep it clear for users whose build
they install, such a build:

- does not use the project's icon;
- does not call itself an official build, a build of this project or its continuation, and
  does not give that impression by its name, its store listing or its website;
- has a name of its own and app identifiers of its own (the bundle ID on Apple platforms,
  the application ID on Android);
- does not use `cbb.tools` as its default address; its own servers have their own
  addresses.

It may keep the command name `cbb` and stay compatible with the protocol.

## These rules and the license

These rules do not limit your rights to the code under the GNU AGPL. They are only about
the icon, the project's servers and keys, and how a build presents itself, which section
7(e) of the license allows a licensor to keep out of its grant.

## Contact

For a [commercial license](README.md#license), open an issue with the **Commercial
license** form on [GitHub](https://github.com/HunterEwok/clipboardbridge/issues/new/choose):
say in a few words who you are and what you need, and the maintainer continues in private.
Questions about these rules go in an issue with the feature request form.
