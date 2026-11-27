<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 8a4822a1fdc4 -->
# Fuera de casa

Para cualquiera que quiera que sus dispositivos sigan sincronizando fuera de su red doméstica. En esta página configuras un ordenador de casa como **hub**, activas la sincronización fuera de casa en tus demás dispositivos, configuras opcionalmente un **reenviador** o un **relé ciego** e invitas dispositivos que no están en casa.

En casa, tus dispositivos se conectan directamente en tu red local. Fuera de casa, llegan a un hub en casa mediante el túnel cifrado WireGuard propio de tu grupo. Para saber cómo funcionan los hubs, los reenviadores y los relés ciegos, consulta [Cómo funciona](how-it-works.md#away-from-home-the-hub). Para ver qué puede ver cada servidor, consulta [Privacidad: quién ve qué](privacy.md).

La sincronización fuera de casa permanece desactivada hasta que la actives en el hub y en cada dispositivo que la necesite. Configúrala **mientras todos los dispositivos están en tu red doméstica**, porque los dispositivos intercambian las claves del túnel localmente con el hub.

## 1. Elige el hub

Un **hub** es un ordenador, un router o una placa pequeña en casa (Linux, macOS, Windows, FreeBSD, OpenWrt u OPNsense). Un teléfono, un reloj o una [instalación sin root en Linux](install.md#without-sudo-rootless) nunca es un hub. Elige un dispositivo que permanezca encendido la mayor parte del tiempo, como un servidor doméstico, un NAS, un router o una Raspberry Pi. Mientras el hub está apagado, la sincronización fuera de casa se detiene, mientras que los dispositivos en casa siguen sincronizando directamente.

Elige qué tipo de hub quieres:

- **Un hub que lee las copias:** El **dispositivo principal** de tu grupo (si es un ordenador) o un ordenador **administrador**. Los dispositivos sellan las copias para él igual que para cualquier otro dispositivo lector, y el [nivel de claves](keys.md#the-three-levels) de tu grupo se aplica a sus claves.
- **Un hub que solo reenvía las copias:** Cualquier ordenador normal o placa pequeña de tu grupo. Los dispositivos sellan las copias de extremo a extremo sin incluirlo, así que no lee ninguna copia, no hace copias propias, no acepta pegados remotos ni acciones rápidas y no necesita chip de seguridad por hardware. Solo el dispositivo principal del grupo puede designar un hub que solo reenvía las copias.

Un grupo puede tener varios hubs en orden de prioridad; solo el hub en línea con mayor prioridad presta servicio cada vez. Para fijar el orden desde el dispositivo principal (o desde un ordenador administrador que pueda ser hub), ejecuta `sudo cbb global hubs NAME...`.

## 2. Actívalo en el hub

Puedes configurar el hub desde una app de escritorio, desde un teléfono administrador o desde una terminal.

### Usando la app para Mac o la app de la bandeja

1. Abre **CBB** en el ordenador que quieras usar como hub.
2. Abre la página de ese mismo ordenador y haz clic en **Convertirlo en hub**.
3. Si te lo pregunta, elige **Un hub que lee las copias** o **Un hub que solo las reenvía**, y confirma activar la sincronización fuera de casa.

**Resultado:** La app activa la sincronización fuera de casa en este ordenador y lo configura como hub mediante el reenviador del proyecto en `cbb.tools`, así que no necesitas abrir ningún puerto en tu router.

### Usando un teléfono administrador

1. En el ordenador que quieras convertir en hub, activa primero la sincronización fuera de casa (`sudo cbb global on`, o activa **En todas partes** en la app de escritorio).
2. En tu teléfono, abre **CBB** y toca el ordenador en **Inicio**.
3. Si el ordenador aún no es administrador (y quieres un hub que lea las copias), toca **Hacerlo administrador** y confirma.
4. Toca **Convertirlo en hub** y confirma con tu cara, huella, código o (en Aurora OS) tu PIN de administrador.

**Resultado:** El ordenador pasa a ser un hub a través del reenviador del proyecto en `cbb.tools`.

### Usando una terminal

En Linux, macOS o FreeBSD, ejecuta estos comandos en el ordenador hub (en Windows, omite `sudo` y usa una terminal de administrador):

1. Activa la sincronización fuera de casa:

   ```sh
   sudo cbb global on
   ```

   Si el ordenador guarda sus claves en archivos, lee el aviso y escribe `yes`.

   **Resultado:** El servicio permite conexiones salientes del túnel a los servidores de tu grupo y mantiene bloqueados todos los demás destinos de internet.

2. Convierte el ordenador en un hub. Elige una de las siguientes opciones:
   - **Conexión directa con una dirección pública doméstica** (IPv4, IPv6 o un nombre de dominio que apunte a tu casa):

     ```sh
     sudo cbb global hub 203.0.113.7:8764
     ```

   - **A través de un reenviador** (cuando tu casa no tiene dirección pública o no quieres abrir un puerto en el router):

     ```sh
     sudo cbb global hub
     ```

   **Resultado:** Si diste una dirección doméstica, `cbb global hub` enumera la regla de cortafuegos UDP que necesita y pregunta antes de añadirla. Sin direcciones, el hub se registra en el reenviador del proyecto en `cbb.tools`.

3. Si diste una dirección pública doméstica y tu hub está detrás de un router, abre los ajustes del router y redirige el **puerto UDP 8764** (o el puerto que hayas puesto con `-port`) a la dirección IP local del hub. Busca **Reenvío de puertos** (Port Forwarding) o **Servidor virtual** (Virtual Server) en los ajustes de tu router.

   En un **router OpenWrt** que actúe como hub, ejecuta los comandos anteriores como `root` sin `sudo`. No hace falta redirección de puertos salvo que el router esté detrás de otro router (doble NAT): cuando confirmas la pregunta del cortafuegos, Connect Beyond Borders añade la regla UDP de WAN a las propias reglas de cortafuegos del servicio sin editar `/etc/config/firewall`.

Para convertir otro ordenador en un hub que solo reenvía las copias desde el dispositivo principal (llamado *root* en las herramientas de línea de comandos), activa primero la sincronización fuera de casa en ese ordenador y luego ejecuta en el dispositivo principal:

```sh
sudo cbb global hub -on DEVICE -forward-only
```

## 3. Actívalo en los demás dispositivos

Mientras todos los dispositivos están en tu red doméstica y el hub está en marcha:

- **Ordenadores y dispositivos pequeños:** Ejecuta `sudo cbb global on` (en una terminal de administrador sin `sudo` en Windows), o activa **En todas partes** en la app para Mac o en la app de la bandeja. Ten en cuenta que las compilaciones para routers MIPS solo sincronizan en la red doméstica; consulta [Dispositivos, puertos y archivos](../reference/devices.md).
- **Teléfonos:** Abre **CBB** y activa **En todas partes** (el interruptor del globo) desde **Inicio**; después mantén la app abierta brevemente en casa para que intercambie las claves del túnel con el hub. Los teléfonos Android siguen sincronizando fuera de casa en segundo plano; los teléfonos iPhone, Aurora OS y HarmonyOS sincronizan mientras la app está abierta.

**Resultado:** Cada dispositivo recibe la oferta de túnel del hub e intercambia con él las claves del túnel.

## 4. Compruébalo

1. En cada ordenador, ejecuta:

   ```sh
   cbb global
   ```

   **Resultado:** La salida muestra si la sincronización fuera de casa está activada, qué dispositivo es el hub, si el túnel está conectado y cualquier error.

2. Saca un teléfono o un portátil del Wi-Fi de casa (por ejemplo, cambia un teléfono a datos móviles) y copia una línea de texto.

   **Resultado:** El texto copiado llega a tus dispositivos de casa.

Si el túnel no conecta, comprueba la redirección del puerto UDP y la dirección pública de tu router, o consulta [Solución de problemas: sincronización fuera de casa](troubleshooting.md#sync-away-from-home).

Si la dirección pública de tu casa cambia más adelante, el hub comparte la dirección nueva la próxima vez que tus dispositivos se encuentren. Cuando `cbb global` o `cbb status` informa de que la regla saliente de red del sistema va retrasada, ejecuta `sudo cbb global allow` en ese ordenador para actualizar la regla.

## 5. Cuando internet no puede llegar a tu casa: un reenviador

Muchos proveedores de internet colocan los hogares tras un NAT de operador (una dirección IP pública compartida), que bloquea las conexiones entrantes incluso con redirección de puertos. Un **reenviador** resuelve esto: tu hub abre una conexión saliente hacia el reenviador, y los dispositivos fuera de casa envían paquetes cifrados del túnel al hub a través de él. No hace falta abrir ningún puerto en el router, y el reenviador no guarda ninguna clave del grupo.

Elige una de estas dos opciones en tu hub:

- **Usar el reenviador del proyecto en `cbb.tools`:** Ejecuta `sudo cbb global hub` sin dirección, o añade `-forwarder default` junto con las direcciones públicas propias de tu hub:

  ```sh
  sudo cbb global hub -forwarder default 203.0.113.7:8764
  ```

- **Usar tu propio reenviador:** Ejecuta un reenviador en cualquier servidor con dirección pública ([Tus propios servidores](../admin/self-hosting.md#a-forwarder)) y pasa después su dirección y su clave al hub:

  ```sh
  sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
  ```

**Resultado:** Cuando un hub tiene tanto direcciones directas como un reenviador, los dispositivos fuera de casa prueban primero las direcciones directas y recurren al reenviador si las conexiones directas fallan.

## 6. Redes que bloquean las VPN

Los hoteles, las oficinas, los operadores móviles y algunos países bloquean WireGuard. Por defecto, un hub disfraza su túnel con **AmneziaWG** y (cuando usa un reenviador compatible) con **VLESS** sobre HTTPS. Para configurar o ajustar el disfraz del túnel, consulta [Redes que bloquean las VPN](blocked-networks.md).

## Un ordenador que no está en casa: una invitación

Cuando la sincronización fuera de casa ya funciona a través de un hub, puedes invitar a un ordenador o a un teléfono que no esté en tu red doméstica. Una invitación sirve una sola vez y dura 1 hora por defecto (hasta 24 horas con `-for`).

### Invitar y admitir un dispositivo

1. En el dispositivo principal o en un administrador, crea una invitación:
   - **En una terminal en un ordenador administrador:** Ejecuta `sudo cbb invite` para un ordenador (crea `cbb.cbbinvite`), o `sudo cbb invite -phone` para un teléfono (muestra un código QR). Mantén el comando en marcha hasta que el nuevo dispositivo se una.
   - **En una app de teléfono o escritorio:** Toca **+** en **Inicio** (o elige **Añadir un dispositivo > ¿El dispositivo está lejos? Envía una invitación** en una app de escritorio) y sigue las indicaciones.
2. Envía el archivo de invitación, el texto (`cbb://join#...`) o el código QR al nuevo dispositivo por un canal de confianza. Cualquiera que tenga una invitación sin usar puede pedir unirse, aunque tú sigues aprobando la admisión comprobando las huellas de clave.
3. En el nuevo dispositivo, usa la invitación:
   - **En un ordenador (terminal):** Ejecuta `sudo cbb pair -invite cbb.cbbinvite` (o `sudo cbb pair -invite -` y pega el texto `cbb://join#...` en la entrada estándar).
   - **En un ordenador (app de escritorio):** Elige **Unirse con una invitación** y pega el texto de la invitación.
   - **En un teléfono:** Abre **CBB**, toca **Unirse con una invitación** y escanea el código QR, pega el texto de la invitación o abre el archivo de invitación.

   **Resultado:** Ambos dispositivos muestran la huella de la clave del dispositivo nuevo.

4. Compara la huella de la clave que muestra el dispositivo que invita con la que muestra el nuevo dispositivo. Escribe `yes` (o toca **Admitir**) solo si coinciden exactamente.

**Resultado:** El nuevo dispositivo se une a tu grupo y empieza a sincronizar a través del hub. `cbb invite` borra el archivo temporal de invitación al terminar.

Para añadir en su lugar un ordenador desde otra red por SSH o mediante tu propia VPN, consulta [Sin la app: unirse desde otra red](without-app.md#joining-from-another-network).

## Sin ordenador para el hub

Un teléfono nunca es un hub. Si tu grupo no tiene ningún ordenador, router o placa pequeña que actúe como hub (por ejemplo, un grupo solo de teléfonos), tus dispositivos pueden encontrarse en un **relé ciego**. Ambos dispositivos deben estar en línea al mismo tiempo para intercambiar una copia.

Un relé ciego no puede leer tu portapapeles, pero ve qué seudónimos temporales de dispositivos están en línea a la vez, sus direcciones IP, los horarios y el volumen de tráfico. Solo el **dispositivo principal** del grupo activa o desactiva un relé ciego para el grupo, y solo después de que aceptes lo que ve el relé.

### Activar un relé ciego

- **En un teléfono (dispositivo principal):** Abre **Ajustes**, activa **Ajustes avanzados**, toca **Relé ciego** y elige el relé del proyecto o introduce la dirección y la clave de tu propio relé. Confirma el aviso.
- **En un ordenador (dispositivo principal):**
  - Usar el relé abierto del proyecto en `cbb.tools:8765`:

    ```sh
    sudo cbb global relay default
    ```

  - Usar tu propio relé ([Tus propios servidores](../admin/self-hosting.md#a-blind-relay)):

    ```sh
    sudo cbb global relay 198.51.100.9:8764 -key KEY
    ```

  Lee lo que puede ver el relé y escribe `yes`.

**Resultado:** Los ajustes de tu grupo nombran el relé, y los dispositivos con **En todas partes** activado se encuentran allí.

Para dejar de usar un relé ciego, ejecuta `sudo cbb global relay off` en el ordenador principal, o abre **Ajustes > Ajustes avanzados > Relé ciego** en el teléfono principal y toca **Dejar el relé**.

## Desactivarlo

### Hacer que un ordenador deje de ser un hub

Para que un ordenador deje de actuar como hub manteniendo activada en él la sincronización fuera de casa:

- **En la app para Mac o la app de la bandeja:** Abre la página del hub y haz clic en **Dejar de ser el hub**.
- **En una terminal:** Ejecuta `sudo cbb global hub off` en el hub, o `sudo cbb global hub off -on NAME` desde un ordenador administrador.

**Resultado:** Los dispositivos fuera de casa conectados cambian automáticamente al siguiente hub del grupo. Si el grupo no tiene otro hub, Connect Beyond Borders pide confirmación antes de detenerlo (pasa `-yes` en scripts para confirmar), porque los dispositivos fuera de casa dejan de sincronizar hasta que se configure otro hub.

### Desactivar la sincronización fuera de casa en un dispositivo

- **En un ordenador:** Ejecuta `sudo cbb global off` (en Windows, `cbb global off` en una terminal de administrador), o desactiva **En todas partes** en la app de escritorio.
- **En un teléfono:** Desactiva **En todas partes** en **Inicio**.

**Resultado:** El dispositivo olvida sus claves del túnel y deja de sincronizar fuera de casa. En Linux y Windows, `cbb global off` también quita los servidores del grupo de la regla de red saliente del sistema. Como las claves nuevas del túnel se intercambian con el hub en tu red doméstica, un dispositivo que desactive la sincronización fuera de casa estando fuera solo reanuda la sincronización fuera de casa cuando vuelva a conectarse en casa.
