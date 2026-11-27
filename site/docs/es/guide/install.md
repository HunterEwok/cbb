<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: d11a83f383ef -->
# Instalación

Para cualquiera que instale, actualice, verifique o desinstale Connect Beyond Borders en un ordenador, un router o un servidor doméstico. Para las apps de teléfono, tableta, reloj y televisor, consulta [Las apps](apps.md).

Connect Beyond Borders se ejecuta como un pequeño servicio en segundo plano en cada ordenador. Su herramienta de línea de comandos es `cbb`. Todos los métodos siguientes instalan el mismo servicio; elige el que corresponda a tu sistema.

## Linux

Compatible con sistemas Linux con `systemd` en x86-64, ARM64, ARMv7 y ARMv6 (portátiles, sobremesas, placas Raspberry Pi, servidores y Steam Deck).

1. Ejecuta el instalador en una terminal:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

2. Responde a las preguntas sobre las reglas de cortafuegos (cuando se detecta un cortafuegos activo) y las actualizaciones automáticas diarias.
3. Cierra sesión y vuelve a iniciarla una vez para que tu cuenta (añadida al grupo `cbb`) pueda ejecutar `cbb` sin `sudo`.

En escritorios x86-64 y ARM64 que tengan instalados GTK 4 y WebKitGTK 6.0 (`libgtk-4-1 libwebkitgtk-6.0-4` en Debian y Ubuntu; `gtk4 webkitgtk6.0` en Fedora), el instalador también instala la app de la bandeja (`cbb-desktop`), que se inicia con tu sesión de escritorio y aparece en tu menú de aplicaciones. Si faltan esas bibliotecas, el instalador indica los paquetes que debes instalar; vuelve a ejecutar el instalador después de añadirlos para instalar la app de la bandeja.

Puedes pasar opciones adicionales a `get.sh` después de `sh -s --`:

- **Consola de texto (`--console`):** Para una máquina sin escritorio, añade copiar y pegar dentro de `tmux` e instala `cbb-console.service` para el pegado remoto en la consola de texto:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --console
  ```

- **Omitir los cuadros de diálogo de pegado en el escritorio (`--uinput`):** En GNOME y KDE, el pegado remoto pregunta una vez en un cuadro de diálogo del sistema antes de pulsar teclas. Añadir `--uinput` instala `cbb-uinput.service` y carga el módulo del núcleo `uinput` para que Connect Beyond Borders pulse directamente las teclas de pegado (nunca en una pantalla de inicio de sesión o de bloqueo). Esta opción requiere `cbb-helper`.
- **Dispositivos pequeños sin el ayudante (`--no-helper`):** Deja fuera `cbb-helper` (el programa ayudante que gestiona claves en TPM, portapapeles de escritorio, inyección de teclas del pegado remoto, teclados Bluetooth y mandos de televisor) en dispositivos pequeños que solo sincronizan:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --no-helper
  ```

  Consulta [Dispositivos pequeños](../../member/README.md). Los archivos de los routers MIPS dejan fuera `cbb-helper` por defecto. Una vez instalado un dispositivo sin `cbb-helper`, las actualizaciones posteriores lo mantienen así.

También se admite Homebrew en Linux (x86-64 y ARM64):

```sh
brew install hunterewok/tap/cbb
sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"
```

Vuelve a ejecutar el segundo comando después de cada `brew upgrade`.

### Sin sudo (sin root)

En un ordenador Linux donde no tienes permisos de administrador (`sudo`), instala Connect Beyond Borders para tu propia cuenta de usuario sin `sudo`:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh -s -- --rootless
```

Esto instala `cbb` en `~/.local/bin` y lo ejecuta como un servicio de usuario de `systemd` mientras tengas la sesión abierta. No puede instalarse a la vez que una instalación para todo el sistema.

Usa una instalación sin root solo cuando no sea posible una instalación normal. Como cualquier programa que se ejecute con tu cuenta de usuario puede leer sus archivos de claves, un dispositivo sin root nunca puede ser el **dispositivo principal**, un **administrador** ni un **hub** ([miembros sin root](how-it-works.md#rootless-members)). Una instalación sin root tampoco tiene reglas de cortafuegos, compatibilidad con TPM ni los ayudantes `--console` o `--uinput`.

- **Seguir funcionando tras cerrar sesión:** Si el instalador no puede activar la persistencia automáticamente, pide a un administrador que ejecute una vez `sudo loginctl enable-linger YOUR-USER`.
- **Sin el ayudante:** Pasa `--no-helper --rootless` para omitir también `cbb-helper` (consulta [sin sudo en dispositivos pequeños](../../member/README.md#without-sudo-rootless)).
- **Desinstalar:** Ejecuta `sh ~/.local/share/cbb/uninstall.sh`.

### SteamOS (Steam Deck)

1. Cambia al **Modo escritorio** y abre **Konsole**.
2. Si no has puesto contraseña al usuario `deck`, ejecuta `passwd` para crear una.
3. Ejecuta el comando del instalador de Linux:

   ```sh
   curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
   ```

SteamOS reemplaza su sistema de archivos raíz en cada actualización del sistema operativo, así que el instalador coloca Connect Beyond Borders en `/opt/cbb` en lugar de `/usr/local` y registra sus archivos de configuración de `/etc` en `/etc/atomic-update.conf.d/cbb.conf`. Tu instalación y tu pertenencia al grupo se conservan tras las actualizaciones de SteamOS.

- Después de cerrar sesión y volver a iniciarla, `cbb` está en tu `PATH` en Konsole. Como `sudo` no busca en `/opt/cbb/bin`, los comandos que requieren `sudo` deben usar la ruta completa, como `sudo /opt/cbb/bin/cbb pair -code`.
- En el Modo escritorio, el portapapeles se sincroniza como en cualquier escritorio KDE Plasma.
- En el Modo juego no hay portapapeles de escritorio, así que allí no se sincroniza nada; el servicio sigue ejecutándose y se pone al día cuando vuelves al Modo escritorio.
- Para quitarlo, ejecuta `sudo sh /opt/cbb/share/uninstall.sh`.

## Mac

Compatible con Mac con chip de Apple o Intel con macOS 14 o posterior.

- **Paquete instalador (recomendado, incluye la app de la barra de menús):** Descarga `cbb-X.Y.Z.pkg` desde la [última versión en GitHub](https://github.com/HunterEwok/cbb/releases/latest) y ábrelo. El paquete instala la app **CBB** de la barra de menús (`/Applications/CBB.app`) y el servicio en segundo plano, ambos firmados y notarizados.
- **Terminal (solo servicio y `cbb`, sin la app de la barra de menús):**

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

- **Homebrew (solo servicio y `cbb`, sin la app de la barra de menús):**

  ```sh
  brew install hunterewok/tap/cbb
  sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"
  ```

  Vuelve a ejecutar el segundo comando después de cada `brew upgrade` para reiniciar el servicio y el agente del portapapeles en la versión actualizada.

## Windows

Compatible con Windows 10 (versión 1809 o posterior) y Windows 11, en x86-64 y ARM64.

1. Abre PowerShell con **Ejecutar como administrador**.
2. Ejecuta el instalador:

   ```powershell
   irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
   ```

3. Responde a las preguntas sobre las reglas del Firewall de Windows y las actualizaciones automáticas diarias.
4. Abre una ventana de terminal nueva para usar `cbb`.

El instalador añade al usuario con sesión iniciada al grupo `cbb`, inicia el servicio en segundo plano y el agente del portapapeles, e instala la app de la bandeja (que se inicia al abrir sesión y aparece en el menú Inicio como **CBB**). Los comandos que cambian la pertenencia al grupo o los ajustes se ejecutan en una terminal de administrador, donde Linux y macOS usan `sudo`.

Para instalar con **winget** (usando el paquete `HunterEwok.cbb`):

```powershell
winget install HunterEwok.cbb
cbb install
```

Ejecuta `cbb install` en una terminal de administrador para instalar el servicio, el agente del portapapeles, la app de la bandeja y las reglas de cortafuegos desde el paquete descomprimido, y vuelve a ejecutarlo después de cada `winget upgrade`.

## OpenWrt

Compatible con routers con OpenWrt 25.12 o posterior (con `apk`) y espacio para un programa de 25 MB (al menos 128 MB de flash o eMMC, y 256 MB de RAM).

Conéctate por SSH como `root` y ejecuta:

```sh
uclient-fetch -qO - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

El instalador configura `cbb` (sin `cbb-helper`) como un servicio `procd` que escucha solo en la zona `lan` y nunca responde en `wan`. Las claves viven en `/etc/cbb/state`, que `sysupgrade` conserva; después de un sysupgrade atendido (ASU u `owut`), vuelve a ejecutar el comando de instalación. Cuando se ejecuta en una terminal interactiva, el instalador inicia el emparejamiento de inmediato (`--no-pair` omite esto). Para zonas adicionales (como una red IoT), detalles del cortafuegos y comprobaciones, consulta [Routers y FreeBSD](../admin/routers.md#openwrt).

También puedes instalar desde el repositorio de paquetes `apk` del proyecto para que `apk upgrade` lo mantenga actualizado:

1. Comprueba la arquitectura de tu router con `grep DISTRIB_ARCH /etc/openwrt_release` y hazla corresponder con el directorio del repositorio:
   - `aarch64_*` → `arm64`
   - `arm_cortex-a*` (con `neon` o `vfp` en el nombre) → `armv7`
   - `mipsel_*` → `mipsle`
   - `mips_*` → `mips`
   - `x86_64` → `amd64`
2. Añade la clave y el repositorio (reemplaza `arm64` por tu arquitectura) e instala:

   ```sh
   uclient-fetch -qO /etc/apk/keys/cbb.pem https://cbb.tools/openwrt/cbb.pem
   echo https://cbb.tools/openwrt/arm64/packages.adb >>/etc/apk/repositories.d/customfeeds.list
   apk update && apk add cbb
   ```

`apk del cbb` quita el paquete y conserva las claves en `/etc/cbb`. Ten en cuenta que las compilaciones para routers `mips` y `mipsle` solo sincronizan en la red doméstica (sin sincronización fuera de casa).

## FreeBSD

Compatible con FreeBSD 15 (`amd64` y `arm64`). Ejecuta como `root` (con `sudo` o `doas`):

```sh
fetch -qo - https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sh
```

El instalador instala `cbb`, añade un script `rc.d` que ejecuta el servicio mediante `daemon(8)` y añade `cbb_enable="YES"` a `rc.conf`. Las claves viven en `/var/db/cbb` y los ajustes en `/usr/local/etc/cbb`.

- **OPNsense:** El mismo instalador añade un gancho de plugin para que el servicio aparezca en **System > Diagnostics > Services** y sus reglas de cortafuegos (en el ancla `cbb` de `pf`) se conserven tras recargar el filtro. Desactiva **Services > mDNS Repeater** mientras se ejecute Connect Beyond Borders, porque ambos necesitan el puerto UDP 5353 y el servicio responde él mismo a mDNS en cada interfaz doméstica.
- **pfSense (no compatible):** El instalador se ejecuta en pfSense, imprime las reglas que debes añadir a mano en **Firewall > Rules**, y puede eliminarse con una actualización del sistema de pfSense.
- **Escritorios FreeBSD:** En X11, o en compositores Wayland con el protocolo data-control (como KDE, sway e Hyprland), el inicio automático de XDG lanza `cbb agent` cuando vuelves a iniciar sesión. El pegado remoto usa XTEST en X11 y teclado virtual en escritorios wlroots; GNOME en FreeBSD no acepta pegado remoto porque el estado de la pantalla de bloqueo no está disponible sin `logind`.

## Docker

Para un NAS o un servidor doméstico siempre encendido sin escritorio (consulta el [README de la imagen de Docker](../../packaging/docker/README.md)). Un contenedor se une como un miembro normal; crea el grupo en tu teléfono o en un ordenador que lleves tú.

```sh
curl -fsSLO https://raw.githubusercontent.com/HunterEwok/cbb/main/packaging/docker/compose.home.yaml
docker compose -f compose.home.yaml up -d
docker compose -f compose.home.yaml exec cbb cbb pair -code
```

Abre primero una ventana de emparejamiento en tu teléfono o en un ordenador administrador y escribe los seis dígitos cuando `cbb pair -code` los pida.

## El cortafuegos

Connect Beyond Borders necesita tráfico entrante en el **puerto TCP 8764** (o tu puerto de miembro personalizado) y en el **puerto UDP 5353** (mDNS), solo desde tu red doméstica.

El instalador detecta tu cortafuegos (`ufw`, `firewalld`, `nftables` o `iptables` en Linux; `pf`, `ipfw` u OPNsense en FreeBSD; el cortafuegos de aplicaciones de macOS; el Firewall de Windows), enumera cada regla que necesita y pregunta `Add these rules now? [y/N]` (`Add this rule now? [y/N]` en macOS):

- **Sí:** El instalador añade las reglas, las mantiene actualizadas en las actualizaciones y las quita al desinstalar sin tocar ninguna otra regla.
- **No** (la opción por defecto, y cuando no hay una terminal interactiva conectada): El instalador no añade reglas e imprime los comandos exactos para que los ejecutes tú mismo.
- **Opciones desatendidas:**
  - En Linux, macOS y FreeBSD: pasa `--express` para añadir las reglas sin preguntar, o `--no-firewall` para rechazarlas e imprimir los comandos.
  - En Windows: establece `$env:CBB_FIREWALL = "express"` o `$env:CBB_FIREWALL = "no"` antes de ejecutar `get.ps1` (o pasa `-Express` o `-NoFirewall` a `install.ps1`).

Comportamiento según el cortafuegos:

- `nftables` e `iptables` siempre imprimen solo los comandos manuales, porque las reglas en tiempo de ejecución no sobreviven a un reinicio.
- En FreeBSD, `pf` coloca las reglas en su propia ancla `cbb`, cargada mediante tres líneas marcadas añadidas al final de `/etc/pf.conf` (se quitan al desinstalar). `ipfw` en FreeBSD las añade en el conjunto de reglas 17 y las recarga en cada arranque.
- Si activas un cortafuegos después de instalar Connect Beyond Borders, vuelve a ejecutar el instalador.

Para usar un puerto de miembro distinto cuando el TCP 8764 ya está ocupado:

- En Linux, macOS, FreeBSD y OpenWrt: pasa `--port 9000` (por ejemplo, `... | sudo sh -s -- --port 9000`).
- En Windows: establece `$env:CBB_PORT = "9000"` antes de ejecutar `get.ps1` (o pasa `-Port 9000` a `install.ps1`).

Todas las opciones del instalador se enumeran en la [referencia de comandos](../reference/cli.md#installers).

## Actualización

Mantén todos los dispositivos de un grupo en la misma versión. Consulta [Versiones y compatibilidad](../reference/compatibility.md) para los detalles de compatibilidad.

### Actualizaciones manuales

- **Instalado con `get.sh`, `get.ps1` o un archivo de versión:**
  - Comprobar si hay una versión más nueva: `cbb update -check`
  - Instalar la versión firmada más reciente: `sudo cbb update` (en Windows, ejecuta `cbb update` en una terminal de administrador; en Linux sin root, ejecuta `cbb update` sin `sudo`; en SteamOS, ejecuta `sudo /opt/cbb/bin/cbb update`).

  `cbb update` conserva tus ajustes y claves, instala solo versiones firmadas por el proyecto, rechaza versiones anteriores y restaura automáticamente la versión previa si el servicio actualizado no arranca en un minuto. Volver a ejecutar el comando original de `get.sh` o `get.ps1` también actualiza.
- **Homebrew:** Ejecuta `brew upgrade cbb` y luego vuelve a ejecutar el comando `install.sh` de la sección [Mac](#mac) o [Linux](#linux).
- **winget:** Ejecuta `winget upgrade HunterEwok.cbb` y luego ejecuta `cbb install` en una terminal de administrador.
- **Docker:** Ejecuta `docker compose -f compose.home.yaml pull` y vuelve a crear el contenedor.
- **Repositorio de paquetes de OpenWrt:** Ejecuta `apk update && apk upgrade`.

### Actualizaciones automáticas

Para las instalaciones con `get.sh` y `get.ps1`, el instalador pregunta una vez si quieres activar las actualizaciones automáticas diarias. Puedes predefinir la respuesta o cambiarla más tarde:

- **Durante la instalación:** Pasa `--auto-update on` o `--auto-update off` a `get.sh`; en Windows, establece `$env:CBB_AUTO_UPDATE = "on"` o `"off"` antes de ejecutar `get.ps1` (o pasa `-AutoUpdate on|off` a `install.ps1`).
- **Después de la instalación:** Ejecuta `sudo cbb update -auto on` o `sudo cbb update -auto off` (sin `sudo` en Linux sin root; en una terminal de administrador en Windows).

Cuando las actualizaciones automáticas están activadas, una tarea diaria busca versiones firmadas: un temporizador de `systemd` en Linux (temporizador de usuario en instalaciones sin root), una tarea de `launchd` en macOS, una tarea programada como `SYSTEM` en Windows o `cron` en OpenWrt y FreeBSD.

Cada comprobación descarga pequeños archivos de metadatos firmados desde GitHub (con respaldo en `dl.cbb.tools` si GitHub no responde). GitHub ve la dirección IP del dispositivo y que solicita metadatos de Connect Beyond Borders, pero nada sobre tu grupo. Para usar un espejo propio en su lugar, ejecuta `sudo cbb update -mirror https://...`; no hace falta confiar en el espejo porque las firmas se siguen verificando.

Los registros de actualizaciones automáticas se guardan en `update.log` en:

| Sistema | Directorio del registro de actualizaciones |
|---|---|
| Linux | `/var/lib/cbb-update` |
| Linux (sin root) | `~/.local/state/cbb-update` |
| SteamOS | `/opt/cbb-update` |
| OpenWrt | `/etc/cbb-update` |
| FreeBSD | `/var/db/cbb-update` |
| macOS | `/Library/Application Support/cbb-update` |
| Windows | `C:\Program Files\cbb-update` |

Los dispositivos de un grupo comparten avisos de la versión firmada más reciente que haya visto cualquiera de ellos, de modo que `cbb status` y las apps de escritorio te avisan cuando hay una actualización disponible. Cada dispositivo sigue verificando las firmas por sí mismo y descargando su propio archivo.

## Comprobar una descarga

Cada archivo de versión se comprueba de tres maneras:

1. **Sumas de verificación (`SHA256SUMS`):** Tanto `get.sh` como `get.ps1` verifican el archivo descargado con el archivo `SHA256SUMS` de la versión.
2. **Firmas de versión del proyecto:** Las versiones se firman con las claves raíz sin conexión y la clave de versión del proyecto (que nunca tocan CI): `keys.json` certifica las claves de versión bajo las claves raíz del proyecto, `release.json` enumera el tamaño y el hash SHA-256 de cada archivo, y `stable.json` indica la versión estable actual ([Protocolo](../protocol.md), sección 16). Tanto `get.sh` (mediante `openssl`) como `get.ps1` llevan integradas las claves raíz del proyecto y se niegan a instalar cualquier versión cuyas firmas no se verifiquen. `get.sh` comprueba tanto ES256 como SLH-DSA-SHA2-128s cuando está instalado OpenSSL 3.5 o posterior (ES256 en OpenSSL anteriores); `get.ps1` comprueba ES256. Para instalar sin comprobar las firmas del proyecto, establece `CBB_VERIFY=skip`.
3. **Atestación de procedencia de la compilación:** Cada archivo de versión tiene una atestación de procedencia de compilación de GitHub que lo vincula con el flujo de publicación de este repositorio. Con la [CLI de GitHub](https://cli.github.com/) (`gh`), puedes verificar cualquier archivo manualmente:

   ```sh
   gh attestation verify cbb-linux-amd64.tar.gz --repo HunterEwok/cbb
   ```

   Tanto `get.sh` como `get.ps1` ejecutan esta comprobación automáticamente cuando `gh` está instalado y con sesión iniciada (`gh auth login`; para `get.sh` con `sudo`, ejecuta `sudo gh auth login`). Establece `CBB_ATTESTATION=require` para rechazar la instalación sin una atestación verificada, o `CBB_ATTESTATION=skip` para omitir la comprobación de atestación.

## Desinstalación

Ejecuta el comando de desinstalación de tu sistema:

| Sistema | Comando o pasos |
|---|---|
| Linux y macOS | `sudo sh /usr/local/share/cbb/uninstall.sh` |
| Linux (sin root) | `sh ~/.local/share/cbb/uninstall.sh` |
| SteamOS | `sudo sh /opt/cbb/share/uninstall.sh` |
| FreeBSD | `sudo sh /usr/local/share/cbb/uninstall.sh` (o con `doas`) |
| OpenWrt | `sh /usr/share/cbb/uninstall.sh` (o `apk del cbb` si se instaló desde el repositorio) |
| Windows | Abre **Configuración > Aplicaciones > CBB > Desinstalar**, o ejecuta `powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\cbb\uninstall.ps1"` como administrador |

Si instalaste con Homebrew, ejecuta primero el script de desinstalación y luego ejecuta `brew uninstall cbb`.

Al desinstalar se eliminan el programa, el servicio en segundo plano, el agente del portapapeles, el temporizador de actualizaciones, las reglas de cortafuegos añadidas por el instalador y (en macOS) `/Applications/CBB.app` si se instaló desde el `.pkg`. Las claves de tu dispositivo y el estado del grupo permanecen en disco para que, al volver a instalar, el dispositivo regrese al mismo grupo.

- **Borrar también las claves y el estado del grupo:** Añade `--purge` en sistemas Unix, o ejecuta `uninstall.ps1 -Purge` en un PowerShell de administrador en Windows. Después, quita el dispositivo del grupo desde un dispositivo administrador (`sudo cbb remove NAME` o en la app del teléfono).
- **Abandonar el grupo sin desinstalar:** Ejecuta `sudo cbb leave` (sin `sudo` en Linux sin root, o `cbb leave` en una terminal de administrador en Windows). Esto borra las claves del dispositivo y los archivos del grupo mientras mantiene instalado Connect Beyond Borders para que el dispositivo pueda volver a unirse a un grupo.
