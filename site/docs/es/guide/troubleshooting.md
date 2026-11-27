<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 50c1a7a6666c -->
# Solución de problemas

Para cualquiera cuyos dispositivos no se sincronicen, no consigan emparejarse o devuelvan errores. Cada entrada siguiente indica el **síntoma**, la **causa** y la **solución**.

## Empieza por el diagnóstico

Antes de cambiar ajustes, comprueba qué informa Connect Beyond Borders:

- **En una app de teléfono o de escritorio:** Abre **Ajustes**, activa **Ajustes avanzados** y revisa **Por qué no se sincroniza** para ver una explicación sencilla y el siguiente paso. Para ver los errores técnicos subyacentes debajo de los mensajes cortos, toca **Versión** siete veces en **Ajustes** y activa **Mostrar detalles de los errores**.
- **En una terminal:** Ejecuta `cbb status` para ver si el servicio está en marcha, el estado de tu grupo, los dispositivos conectados y el estado de la sincronización fuera de casa. Antepón `CBB_DEBUG=1` a cualquier comando (en PowerShell de Windows, ejecuta antes `$env:CBB_DEBUG = "1"`) para imprimir el error subyacente:

  ```sh
  CBB_DEBUG=1 cbb status
  ```

- **Revisar los registros del servicio:** En Linux, ejecuta `journalctl -u cbb` para el servicio y `journalctl --user` para el agente del portapapeles de escritorio. Las rutas de los registros para macOS, Windows, FreeBSD y OpenWrt están en [Dispositivos, puertos y archivos](../reference/devices.md#files-and-logs), y los interruptores de depuración de cada componente están en [Mensajes de error y detalles](../reference/errors.md).

## Comandos y servicio

### "the Connect Beyond Borders service is not running"

- **Causa:** El servicio en segundo plano está detenido o falló al iniciarse.
- **Solución:** Inicia el servicio según tu sistema operativo y revisa su registro si vuelve a cerrarse:
  - **Linux:** `sudo systemctl start cbb` (sin root: `systemctl --user start cbb`)
  - **macOS:** `sudo launchctl kickstart -k system/tools.cbb`
  - **Windows (PowerShell como administrador):** `Start-Service cbb`
  - **FreeBSD:** `sudo service cbb start`
  - **OpenWrt:** `/etc/init.d/cbb start`

### "permission denied" en el socket de control después de instalar

- **Causa:** El instalador añadió tu cuenta de usuario al grupo `cbb` (`_cbb` en macOS), y las nuevas pertenencias a grupos solo surten efecto tras tu siguiente inicio de sesión.
- **Solución:** Cierra sesión y vuelve a iniciarla (en Windows, abre una ventana de terminal nueva). Hasta que vuelvas a iniciar sesión, ejecuta los comandos con `sudo cbb ...`.

## Los dispositivos no se ven entre sí en casa

### `cbb status` avisa de que los dispositivos de casa no pueden conectarse a este ordenador

- **Causa:** El cortafuegos del ordenador bloquea el tráfico entrante en el **puerto TCP 8764** (o tu puerto de miembro personalizado) o en el **puerto UDP 5353** (mDNS).
- **Solución:** Vuelve a ejecutar el instalador y responde `y` a la pregunta del cortafuegos, o añade las reglas manualmente con los comandos de [Instalación: el cortafuegos](install.md#the-firewall).

### `cbb status` dice "Quiet on" para tu red doméstica

- **Causa:** Los ordenadores solo se anuncian y aceptan conexiones locales en redes domésticas conocidas. Si cambiaste de router o de subred, el ordenador trata la red como desconocida.
- **Solución:** Marca la red actual como red doméstica: ejecuta `sudo cbb network` en el ordenador, o haz clic en **Esta es mi red de casa** en la app para Mac o en la app de la bandeja.

### Los dispositivos están en distintas subredes o VLAN

- **Causa:** El descubrimiento de red local (mDNS) no atraviesa routers entre subredes separadas (por ejemplo, `192.168.0.x` y `192.168.20.x`).
- **Solución:** Conecta ambas redes a través de un hub ([Fuera de casa](away-from-home.md)), ejecuta `cbb` en un router conectado a ambas subredes o pasa `-peer HOST:PORT` al servicio en un dispositivo pequeño ([Dispositivos pequeños](../../member/README.md#install)).

### Los dispositivos en Wi-Fi no pueden conectarse entre sí en absoluto

- **Causa:** El router tiene activado el **Wi-Fi de invitados** o el **aislamiento de clientes / AP**, lo que impide que los dispositivos inalámbricos se comuniquen directamente.
- **Solución:** Pasa tus dispositivos a tu red Wi-Fi doméstica principal o desactiva el aislamiento de clientes en el router.

### Dos dispositivos están en línea pero nunca intercambian copias

- **Causa:** Uno de los dispositivos está en otro grupo, **Sincronizar** está desactivado o un administrador silenció el dispositivo.
- **Solución:**
  - Comprueba **Sincronizar** en ambos dispositivos (`cbb status` o **Inicio** en la app) y asegúrate de que ninguno esté silenciado.
  - Comprueba la etiqueta del grupo en `cbb status`. Si un ordenador está en el grupo equivocado, ejecuta `sudo cbb leave` en él, emparéjalo con el grupo correcto y quita su entrada antigua del grupo equivocado.

### `cbb status` o la app dice que este dispositivo se quitó del grupo

- **Causa:** Un administrador quitó este dispositivo, así que todos los demás miembros del grupo rechazan sus conexiones.
- **Solución:** Ejecuta `sudo cbb leave` en el ordenador (o toca **Abandonar el grupo** en la app del teléfono o de escritorio) y vuelve a emparejar el dispositivo como un dispositivo nuevo.

## El emparejamiento falla

### El emparejamiento informa de "wrong code" o la ventana se cierra

- **Causa:** Cada ventana de emparejamiento permanece abierta durante 5 minutos y se cierra automáticamente tras 3 intentos fallidos.
- **Solución:** Abre una ventana de emparejamiento nueva (`sudo cbb pair` en un ordenador administrador, o **+ > Añadir un dispositivo** en una app) e introduce el nuevo código de 6 dígitos o escanea el nuevo código QR.

### El teléfono no puede llegar al ordenador después de escanear el código QR

- **Causa:** El teléfono y el ordenador están en redes distintas, el cortafuegos del ordenador bloquea el puerto TCP 8764 o el acceso a la red local de iOS está denegado.
- **Solución:**
  1. Confirma que ambos dispositivos están en la misma Wi-Fi doméstica o LAN.
  2. Comprueba que el cortafuegos del ordenador permite el puerto TCP 8764 ([el cortafuegos](install.md#the-firewall)).
  3. En iPhone, activa **Ajustes > Privacidad y seguridad > Red local > CBB**.

## Sincronización fuera de casa

### Un dispositivo fuera de casa no puede conectarse al hub

- **Causa:** Uno de cuatro problemas habituales:
  - Tu router no redirige el puerto UDP 8764 al hub, el cortafuegos del hub lo descarta o la dirección pública dada a `cbb global hub` está detrás de un NAT de operador.
  - El dispositivo fuera de casa no se ha encontrado con el hub en tu red doméstica desde que se activó la sincronización fuera de casa o desde que el hub cambió sus ajustes del túnel (`-no-obfuscate`, `-no-vless`).
  - La dirección IP de tu casa cambió y la regla saliente del sistema en el ordenador solo permite todavía la dirección antigua.
  - La red que estás visitando bloquea el tráfico WireGuard o UDP.
- **Solución:**
  1. Ejecuta `cbb global` tanto en el dispositivo fuera de casa como en el hub para leer el fallo exacto.
  2. Si tu casa está tras un NAT de operador o la redirección de puertos falla, cambia el hub a un reenviador (`sudo cbb global hub` para el reenviador del proyecto; consulta [Fuera de casa](away-from-home.md#5-when-the-internet-cannot-reach-your-home-a-forwarder)).
  3. Si `cbb global` indica que la regla saliente de red del sistema va retrasada, ejecuta `sudo cbb global allow` en ese ordenador.
  4. Si el dispositivo nunca se encontró con el hub en casa tras un cambio de ajustes, conéctalo una vez a tu red doméstica (y abre brevemente la app del teléfono).
  5. Si la red que visitas filtra las VPN, verifica que AmneziaWG y VLESS estén activados en el hub ([Redes que bloquean las VPN](blocked-networks.md)). Si los puntos de entrada del reenviador del proyecto están desactualizados, importa puntos de entrada firmados nuevos con `sudo cbb global entries import STRING`.
  6. Para registrar los saludos de WireGuard en Linux, establece `CBB_DEBUG=1` en el servicio y reinícialo:

     ```sh
     sudo systemctl edit cbb
     ```

     Añade estas líneas, guarda y reinicia:

     ```ini
     [Service]
     Environment=CBB_DEBUG=1
     ```

     ```sh
     sudo systemctl restart cbb
     ```

     Después inspecciona `journalctl -u cbb`.

## Teléfonos

### Android: «Ajuste restringido» impide activar el servicio de accesibilidad

- **Causa:** Android 13 y posteriores restringen los permisos de accesibilidad a las apps instaladas desde un APK fuera de una tienda de aplicaciones.
- **Solución:** Abre **Ajustes > Aplicaciones > CBB** en Android (Información de la app), toca el menú **⋮** en la esquina superior, toca **Permitir ajustes restringidos** y luego activa **Sincronización del portapapeles** en los ajustes de Accesibilidad.

### Android: las copias de los ordenadores dejan de llegar en segundo plano

- **Causa:** La optimización de batería detuvo el servicio en primer plano que la app mantiene en segundo plano.
- **Solución:** Abre **Ajustes > Aplicaciones > CBB > Batería** en Android y ponlo en **Sin restricciones**.

### iPhone: iOS pide permiso para pegar cada vez que sincronizas

- **Causa:** iOS deja **Pegar desde otras apps** en **Preguntar** por defecto.
- **Solución:** Abre **Ajustes > Apps > CBB > Pegar desde otras apps** en el iPhone y elige **Permitir**.

### Aurora OS 5: la clave de administrador está bloqueada

- **Causa:** Siete intentos erróneos con el PIN de administrador bloquean de forma permanente la clave de administrador en el elemento seguro del teléfono. El teléfono sigue en el grupo como miembro normal.
- **Solución:** Abandona el grupo, reinstala **CBB** y vuelve a unirte como un dispositivo nuevo.

## Si sigues atascado

Abre una [incidencia en GitHub](https://github.com/HunterEwok/cbb/issues) e incluye:

- La salida de `CBB_DEBUG=1 cbb status` (y `cbb global` para problemas fuera de casa)
- Las líneas relevantes del registro del servicio o de la app
- Los sistemas operativos y las versiones de Connect Beyond Borders implicados

Elimina cualquier texto copiado, dirección personal o nombre de dispositivo que no quieras compartir. Informa de vulnerabilidades de seguridad en privado siguiendo [SECURITY.md](../../SECURITY.md).
