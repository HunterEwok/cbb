<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 9b05c71a6bfc -->
# Teclados y televisores

Para quien quiere escribir una contraseña larga, un enlace o una búsqueda en un televisor, una tableta, una consola o un ordenador que no tiene nada de Copy Beyond Borders. Un dispositivo de tu grupo escribe allí el texto como teclado o como mando a distancia del televisor, cuando tú lo pulsas o cuando un administrador envía un pegado remoto.

## Elige una forma

| Forma | Escribe en | Necesita |
|---|---|---|
| [Un teléfono Android como teclado Bluetooth](#an-android-phone-as-a-bluetooth-keyboard) | cualquier cosa que acepte un teclado Bluetooth: televisores, tabletas, teléfonos, ordenadores, la Steam Deck, la PlayStation 5 | Android 10 o posterior con el perfil de teclado Bluetooth |
| [Un ordenador Linux como teclado Bluetooth](#a-linux-computer-as-a-bluetooth-keyboard) | cualquier cosa que acepte un teclado Bluetooth LE | BlueZ 5.50 o posterior y un adaptador con Bluetooth 4.0 o posterior |
| [La Nano ESP32 como teclado USB o Bluetooth](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | por USB también una BIOS, una petición de cifrado de disco, la Xbox y la Nintendo Switch | una Arduino Nano ESP32 en tu grupo |
| [Un ordenador como mando del televisor](#a-computer-as-the-tvs-remote) | un Android TV, un Google TV o un Roku de tu red doméstica | un ordenador Linux, macOS, Windows o FreeBSD en casa |

La Xbox y la Nintendo Switch solo aceptan teclados USB, así que para ellas usa la Nano ESP32. macOS, Windows y los iPhone no dejan que ninguna app actúe como teclado Bluetooth.

## La distribución debe coincidir

Un teclado envía teclas, no caracteres: el dispositivo en el que se escribe convierte cada tecla en un carácter con su propia distribución. Por eso hay que indicar al teclado qué distribución está activa allí, inglés (EE. UU.) o ruso. Un texto con un carácter para el que esa distribución no tiene tecla no se escribe en absoluto, y se te dice cuáles son esos caracteres; no se escribe nada más en su lugar. Un salto de línea pulsa Intro y un tabulador pulsa Tab.

Escribir es lento a propósito, 20 caracteres por segundo por defecto: algunos televisores pierden teclas que llegan más rápido. Bájalo si faltan letras.

## Un teléfono Android como teclado Bluetooth

1. En la app, abre Ajustes, Teclado Bluetooth, y activa **Act as a Bluetooth keyboard**. Permite el Bluetooth («Dispositivos cercanos») si lo pide. Si la app dice que el teléfono no puede actuar como teclado, su fabricante dejó fuera el perfil (por ejemplo el Fairphone 6 y algunos teléfonos Huawei, Honor y Xiaomi antiguos); usa otra forma. Si dice que otra app puede ser el teclado del teléfono, desactiva el teclado de esa app: solo una app a la vez puede serlo.
2. Pulsa **Make this phone visible**. En dos minutos, añade el teléfono en el dispositivo, en sus propios ajustes de Bluetooth, como añadirías un teclado.
3. En **Type into**, elige el dispositivo. La app dice «Connected to …».
4. Ajusta **The device's keyboard layout** y, si hace falta, la **Speed** (10, 20 o 40 caracteres por segundo).
5. Pulsa **Type the clipboard**. El texto aparece donde el dispositivo tiene el foco, así que abre antes un campo de texto allí.

Para que los pegados remotos de un administrador se escriban allí en lugar de en el teléfono, activa el pegado remoto en la app y después **Type remote pastes there**. Un texto con un salto de línea necesita que se permita Intro en el pegado remoto.

## Un ordenador Linux como teclado Bluetooth

```sh
sudo cbb keyboard on -layout us    # registers the keyboard with BlueZ
sudo cbb keyboard pair             # discoverable for two minutes
# add "CBB <this computer's name>" on the device, in its Bluetooth settings
cbb keyboard                       # shows whether it is connected
echo 'the text' | sudo cbb keyboard type
```

`on` también admite `-rate N`, la velocidad, de 5 a 60 caracteres por segundo, y `-pastes`, que envía los pegados remotos del grupo al dispositivo en lugar de a la pantalla de este ordenador: `sudo cbb keyboard on -layout us -rate 10 -pastes`. `sudo cbb keyboard off` lo detiene. Los teclados y ratones Bluetooth del propio ordenador siguen funcionando.

## La Nano ESP32 como teclado USB o Bluetooth

La placa es un miembro ligero de tu grupo. En su consola:

- `usb keyboard` convierte su puerto USB en un teclado, con la consola como segundo puerto serie a su lado; conéctala al dispositivo. Funciona antes de que arranque ningún sistema: en una BIOS, una configuración UEFI o una petición de cifrado de disco.
- `ble on`, y después `ble pair`, la convierte en un teclado Bluetooth LE; añade «CBB Nano ESP32» en el dispositivo en dos minutos. Recuerda hasta cuatro dispositivos; `ble forget` los olvida.
- `layout ru` o `layout us` y `rate N` fijan la distribución y la velocidad.
- `type TEXT` escribe en el dispositivo Bluetooth conectado, o si no en el USB.

Los pegados remotos del grupo hacia la placa se escriben del mismo modo. La guía de la propia placa está en [esp32/](../../esp32/README.md).

## Un ordenador como mando del televisor

Un ordenador de casa puede escribir en un televisor por la red, como hace su mando. No se instala nada en el televisor, y el televisor nunca se une al grupo.

Un Android TV o un Google TV se empareja una vez:

```sh
sudo cbb remote add -name living-room-tv living-room-tv.lan   # the TV shows a six-digit code
sudo cbb remote code 123456              # within two minutes
```

Un Apple TV se empareja igual, con el PIN de cuatro cifras que muestra. Antes, en el Apple TV, pon Ajustes, AirPlay y HomeKit, Permitir acceso en "Todos en la misma red": con "Solo quienes comparten esta casa" rechaza cualquier emparejamiento.

```sh
sudo cbb remote add -appletv -name lounge 192.168.1.30   # the Apple TV shows a four-digit PIN
sudo cbb remote code 1234                # within two minutes
```

Un Roku no tiene emparejamiento ni cifrado: el texto cruza tu red doméstica como HTTP sin cifrar, así que solo se añade cuando lo dices con `-consent`. En el Roku, pon antes Ajustes, Sistema, Ajustes avanzados del sistema, Control por aplicaciones móviles en Habilitado o Permisivo.

```sh
sudo cbb remote add -roku -consent 192.168.1.40
```

Después abre un campo de búsqueda o de texto en el televisor con su propio mando, y escribe:

```sh
echo 'the film' | sudo cbb remote type
sudo cbb remote pastes living-room-tv on   # an admin's remote pastes go to that TV
```

`cbb remote` enumera los televisores, `-tv NAME` elige uno cuando hay varios, y `sudo cbb remote remove NAME` olvida uno. Un Android TV o un Apple TV que se restableció, o que olvidó este ordenador, debe volver a emparejarse.

## Seguridad

- Un teclado Bluetooth escribe donde el dispositivo tiene el foco, como si estuvieras ante su teclado. Empareja solo con los dispositivos en los que quieras escribir, y olvídalo en ambos extremos cuando dejes de usarlo.
- Con los pegados remotos enviados a un teclado o a un televisor, cualquier administrador de tu grupo puede escribir allí. Actívalo solo donde lo necesites; se desactiva con el pegado remoto.
- A un televisor solo se llega en la red doméstica: una dirección fuera de ella se rechaza, resuelva el nombre luego a lo que resuelva.
- El texto de un Roku no está cifrado en la red doméstica. No envíes contraseñas a un Roku.

## Límites

- En un televisor real solo se ha probado con un Apple TV 4K, escribiendo con `cbb remote`; lo demás se prueba contra un BlueZ, un Android TV, un Apple TV y un Roku simulados.
- Las apps de los teléfonos todavía no pueden ser el mando de un televisor; los televisores Samsung y LG vendrán después ([hoja de ruta](../roadmap.md), punto 25).
- Un teclado escribe como máximo 4096 caracteres cada vez.

Todos los parámetros están en [los comandos](../reference/cli.md); los puertos de los televisores, en [dispositivos, puertos y archivos](../reference/devices.md#ports); cómo funciona por dentro, en la [especificación de las apps](../apps.md#android-the-bluetooth-keyboard).
