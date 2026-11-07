<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0dae45ee8ba4 -->
# Instalación

Copy Beyond Borders se ejecuta como un pequeño servicio en segundo plano en cada ordenador. Su comando es `cbb`. Todas las formas de abajo instalan el mismo programa; elige la que prefieras.

## Linux

Cualquier Linux con systemd (x86-64, ARM64, ARMv7, ARMv6): un portátil, un sobremesa, una Raspberry Pi, un servidor, una Steam Deck.

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

Después, cierra sesión y vuelve a entrar una vez, para que tu usuario pueda usar `cbb` sin `sudo`. Una máquina sin escritorio obtiene copiar y pegar dentro de tmux con `--console` (`... | sudo sh -s -- --console`).

En un escritorio con GTK 4 y WebKitGTK 6.0 (x86-64 y ARM64) también instala la app de la bandeja, que se abre con tu sesión y está en el menú de aplicaciones. Sin ellos, indica qué paquetes añadir; después ejecútalo de nuevo para tener la app de la bandeja.

El pegado remoto en GNOME y KDE pregunta una vez, en un cuadro de diálogo en el ordenador, antes de que el primer pegado de un administrador pueda pulsar las teclas. Para saltarte el cuadro de diálogo, añade `--uinput` (`... | sudo sh -s -- --uinput`): un pequeño ayudante pulsa entonces las teclas de pegado (Mayús+Insert e Intro) por quien esté usando la pantalla, nunca en una pantalla de inicio de sesión o de bloqueo.

Los dispositivos pequeños que solo deben sincronizar, como un router o una Raspberry Pi Zero, pueden usar el [miembro ligero](../../member/README.md), más liviano: `... | sudo sh -s -- --lite`.

### Sin sudo (sin root)

En un ordenador Linux donde no puedes o no quieres usar `sudo`, instálalo para tu propio usuario, sin `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

Se ejecuta como tu propio servicio en segundo plano mientras tienes la sesión abierta y sincroniza como cualquier miembro. Úsalo solo cuando la instalación normal no sea posible: cualquier programa que ejecutes podría copiar sus claves, así que nunca puede ser la raíz del grupo, un administrador ni el hub ([cómo funciona](how-it-works.md#rootless-members)), y no tiene reglas de cortafuegos, ni TPM, ni `--console` ni `--uinput`. Para mantenerlo en marcha después de cerrar sesión, un administrador ejecuta una vez `sudo loginctl enable-linger YOUR-USER`. Para quitarlo: `sh ~/.local/share/cbb/uninstall.sh`. El miembro ligero también se instala así, con `--lite --rootless` ([miembro ligero](../../member/README.md#without-sudo-rootless)).

### SteamOS (Steam Deck)

Cambia al Modo escritorio, abre Konsole, ponle una contraseña una vez al usuario `deck` si no tiene (`passwd`) y ejecuta el mismo comando. SteamOS sustituye sus archivos de sistema con cada actualización, así que el instalador coloca Copy Beyond Borders en `/opt/cbb` en lugar de `/usr/local`, y le indica a SteamOS cuáles de sus archivos de `/etc` debe conservar (`/etc/atomic-update.conf.d/cbb.conf`). Sigue instalado y en su grupo tras las actualizaciones de SteamOS.

- `cbb` está en la ruta de un Konsole nuevo después de cerrar sesión y volver a entrar. `sudo` no busca ahí, así que los comandos que lo necesitan llevan la ruta completa: `sudo /opt/cbb/bin/cbb pair`.
- En el Modo escritorio, el portapapeles se sincroniza como en cualquier escritorio KDE Plasma.
- En el Modo juego no hay portapapeles de escritorio, así que allí no se sincroniza nada; el servicio sigue funcionando y se pone al día en el Modo escritorio.
- Para quitarlo: `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Apple silicon o Intel, macOS 14 o posterior: descargue `cbb-X.Y.Z.pkg` de la
[última versión](https://github.com/HunterEwok/cbb/releases/latest) y ábralo. Instala la app CBB en
la barra de menús y el servicio, ambos firmados por el proyecto y comprobados por Apple.

O en Terminal, sin la app, el mismo comando que en Linux:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

O con Homebrew, que también lo actualiza. Ejecuta de nuevo la segunda línea después de cada `brew upgrade`:

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
```

## Windows

Windows 10 (1809 o posterior) u 11, x86-64 o ARM64, en un PowerShell abierto con «Ejecutar como administrador»:

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

Permite que el usuario con sesión iniciada en la pantalla use `cbb` (en una terminal nueva) e inicia para él el agente del portapapeles. Los comandos que cambian el grupo se ejecutan en una terminal abierta como administrador, donde Linux y macOS usan `sudo`.

También instala la app de la bandeja, que se abre al iniciar sesión y está en el menú Inicio como CBB.

Con winget, cuando el paquete esté en el repositorio de winget:

```powershell
winget install HunterEwok.cbb
cbb install           # in the administrator terminal; again after each winget upgrade
```

## OpenWrt

Un router con OpenWrt 25.12 o posterior y espacio para un programa de 25 MB (128 MB de flash o más, o eMMC; 256 MB de RAM), como root por SSH:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

Instala `cbb` como un servicio que funciona solo en la zona `lan` y nunca responde en `wan`. Las claves están en `/etc/cbb`, que sysupgrade conserva; después de un sysupgrade atendido (ASU, owut), ejecuta de nuevo el comando. Otra zona, como una red IoT, el cortafuegos y las comprobaciones están en [routers y FreeBSD](../admin/routers.md#openwrt).

O desde nuestro repositorio de paquetes, que `apk upgrade` mantiene al día. La arquitectura del repositorio depende de la CPU del router (`grep DISTRIB_ARCH /etc/openwrt_release`): `arm64` para `aarch64_*`, `armv7` para `arm_cortex-a*` con `neon` o `vfp` en el nombre, `mipsle` para `mipsel_*`, `mips` para `mips_*`, `amd64` para `x86_64`. Pon la tuya en lugar de `arm64` en la segunda línea:

```sh
uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
apk update && apk add cbb
```

`apk del cbb` lo quita y conserva las claves en `/etc/cbb`.

## FreeBSD

FreeBSD 15, amd64 o arm64, como root (con `sudo` o `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

Instala `cbb`, un script rc.d que ejecuta el servicio mediante daemon(8), y añade la línea `cbb_enable="YES"` a rc.conf. Las claves están en `/var/db/cbb`.

En OPNsense, el mismo instalador añade además un gancho de plugin: el servicio aparece en System > Diagnostics > Services, y sus reglas de cortafuegos (en el ancla `cbb` de pf) siguen cada recarga del filtro. Desactiva el repetidor de mDNS (Services > mDNS Repeater) mientras se ejecute: ambos necesitan el puerto UDP 5353, y el servicio responde él mismo a mDNS en cada interfaz doméstica. pfSense no está soportado: el instalador también se ejecuta allí, pero imprime las reglas de cortafuegos para Firewall > Rules en lugar de añadirlas, y una actualización de pfSense puede quitar Copy Beyond Borders.

En un escritorio FreeBSD (X11, o Wayland con el protocolo data control, como en KDE, sway e Hyprland), la sesión inicia `cbb agent` desde el inicio automático de XDG y el portapapeles se une al grupo; vuelve a iniciar sesión después de la instalación. El pegado remoto escribe mediante XTEST en X11 y mediante el teclado virtual en los escritorios wlroots; GNOME no admite pegado remoto en FreeBSD, ya que sin logind nada indica si su pantalla está bloqueada.

## Docker

Para un NAS o un servidor doméstico que está siempre encendido ([README de la imagen](../../packaging/docker/README.md); publicada con cada versión desde la 0.5). Se une como un miembro normal: crea el grupo en el teléfono o en un ordenador que lleves tú.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair
```

## El cortafuegos

Copy Beyond Borders necesita un puerto TCP, el 8764, y mDNS (UDP 5353), ambos solo desde la red doméstica. El instalador localiza el cortafuegos (ufw, firewalld, nftables o iptables en Linux, pf o ipfw en FreeBSD, el cortafuegos de aplicaciones del Mac, el Firewall de Windows), enumera cada regla y pregunta `Add these rules now? [y/N]`:

- **Sí**: las añade, las mantiene al día en cada actualización y las quita cuando desinstalas. Nunca toca otras reglas.
- **No** (la opción por defecto, y la que se aplica cuando no hay terminal donde preguntar): no añade nada e imprime los comandos exactos para que los ejecutes tú.
- `--express` (`-Express` en Windows) las añade sin preguntar; `--no-firewall` responde No.

nftables e iptables reciben siempre solo los comandos, porque las reglas añadidas en tiempo de ejecución no sobreviven a un reinicio. En FreeBSD, pf recibe las reglas en un ancla propia, que pf lee mediante tres líneas marcadas que el instalador añade al final de `/etc/pf.conf` y vuelve a quitar; ipfw las recibe en el conjunto de reglas 17, añadidas de nuevo en cada arranque. Si activas un cortafuegos más tarde, ejecuta de nuevo el instalador.

**Otro puerto**, si el 8764 está ocupado: `... | sudo sh -s -- --port 9000` (en Windows, `$env:CBB_PORT = "9000"` antes del instalador). La app del teléfono conoce el puerto por el código QR.

Todas las opciones del instalador están en la [referencia de comandos](../reference/cli.md#installers).

## Actualización

Las versiones están firmadas desde la 0.6. Para pasar a la 0.6 desde una versión anterior, ejecuta de nuevo el comando de instalación; a partir de entonces lo hace `cbb update`.

`sudo cbb update` (en Windows, `cbb update` en una terminal abierta como administrador) instala la versión más reciente en un ordenador o miembro ligero instalado con `get.sh`, `get.ps1` o un archivo de versión; `cbb update -check` solo dice si hay una. Tus ajustes se conservan. Solo instala una versión firmada por el proyecto, y nunca una anterior. Si la versión nueva no arranca en un minuto, la anterior vuelve por sí sola. Cómo comprueba las firmas está en el [protocolo](../protocol.md), sección 16.

Los instaladores preguntan una vez si actualizar automáticamente (`--auto-update on|off`, o `-AutoUpdate on|off` y `$env:CBB_AUTO_UPDATE` en Windows, para responder de antemano); `sudo cbb update -auto on|off` lo cambia después. Activado, un temporizador comprueba una vez al día a una hora propia: un temporizador de systemd en Linux, una tarea de launchd en un Mac, una tarea programada como SYSTEM en Windows, cron en OpenWrt y FreeBSD. Cada comprobación descarga los mismos archivos pequeños de GitHub (o de `dl.cbb.tools` cuando GitHub no responde), así que GitHub conoce la dirección de este dispositivo y que usa Copy Beyond Borders, como con cualquier descarga; no envía nada sobre el grupo. `sudo cbb update -mirror https://...` toma las actualizaciones de otro espejo, lo que no requiere confianza, ya que las firmas se comprueban. El registro del temporizador es `update.log` en `/var/lib/cbb-update` (Linux), `/etc/cbb-update` (OpenWrt), `/var/db/cbb-update` (FreeBSD), `/Library/Application Support/cbb-update` (Mac) o `C:\Program Files\cbb-update` (Windows).

Los dispositivos de un grupo se comunican entre sí la versión firmada más reciente que alguno de ellos haya visto, así que la comprobación de un solo dispositivo basta para que `cbb status` y la app de bandeja de los demás indiquen que hay una versión más nueva («Update to X» en la app de bandeja ejecuta `cbb update` como administrador). Cada dispositivo sigue comprobando las firmas por sí mismo y descargando su propio archivo.

Ejecutar de nuevo el mismo comando de instalación también actualiza. Con Homebrew o winget, actualiza allí y ejecuta de nuevo la segunda línea; `cbb update` lo indica. Docker y el paquete de OpenWrt se actualizan con `docker compose pull` y `apk upgrade`.

## Comprobar una descarga

Los instaladores de una línea comprueban la descarga con el `SHA256SUMS` de la versión. Cada archivo de la versión lleva además una atestación de procedencia de la compilación que lo vincula a este repositorio y a la compilación que lo generó; con la [CLI de GitHub](https://cli.github.com/):

```sh
gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
```

`get.sh` la comprueba por sí mismo cuando `gh` está instalado y con sesión iniciada para root (`sudo gh auth login`); `CBB_ATTESTATION=require` se niega a instalar sin ella.

Las versiones también se firman con las claves propias del proyecto, que nunca tocan CI (las claves raíz están en llaves de hardware sin conexión, la clave de versión en el Secure Enclave del mantenedor): `keys.json` nombra las claves de versión bajo las claves raíz del proyecto, `release.json` enumera cada archivo de la versión con su hash y `stable.json` indica cuál es la versión actual. Cuando las claves raíz estén integradas en los instaladores, `get.sh` (con `openssl`) y `get.ps1` comprobarán esto antes de instalar y rechazarán una versión sin firmar; hasta entonces solo comprueban `SHA256SUMS` y la atestación. `CBB_VERIFY=skip` instala sin la comprobación.

## Desinstalación

En Linux y en un Mac:

```sh
sudo sh /usr/local/share/cbb/uninstall.sh
```

En SteamOS es `sudo sh /opt/cbb/share/uninstall.sh`. Con Homebrew, ejecuta después `brew uninstall cbb`.

En Windows: Configuración, Aplicaciones, «CBB», Desinstalar.

Esto quita el programa, el servicio, las reglas de cortafuegos que añadió el instalador y, en un Mac, la app que instaló el `.pkg`. Las claves del dispositivo se conservan, así que al instalar de nuevo vuelve a su grupo. Para borrarlas también, añade `--purge` (`-Purge` en Windows, con `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1" -Purge`) y luego quita el dispositivo del grupo desde otro (`sudo cbb remove NAME`, o en el teléfono). Para salir del grupo y conservar CBB, ejecuta en su lugar `sudo cbb leave`: borra las claves y los archivos del grupo, y el dispositivo puede volver a unirse a un grupo.
