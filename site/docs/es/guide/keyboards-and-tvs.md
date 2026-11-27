<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 30d3986ec6a3 -->
# Teclados y televisores

Para cualquiera que quiera escribir una contraseña larga, una URL o una búsqueda en un televisor, una tableta, una consola de juegos o un ordenador que no ejecute Connect Beyond Borders. Un dispositivo de tu grupo actúa como un teclado Bluetooth, un teclado USB o un mando a distancia de televisor por red.

Los teclados y los mandos de televisor son funciones experimentales en [El laboratorio](lab.md). Para ver el estado actual de las pruebas en hardware real, consulta [Paridad entre plataformas](../parity.md#on-real-devices).

## Elige un método

| Método | Escribe en | Requisitos |
|---|---|---|
| [Teléfono como teclado Bluetooth](#a-phone-as-a-bluetooth-keyboard) | Cualquier dispositivo que acepte un teclado Bluetooth: televisores, tabletas, teléfonos, ordenadores, Steam Deck, PlayStation 5 | Teléfono con Android 10 o posterior (con perfil HID de Bluetooth), Aurora OS o HarmonyOS |
| [Ordenador Linux como teclado Bluetooth](#a-linux-computer-as-a-bluetooth-keyboard) | Cualquier dispositivo que acepte un teclado Bluetooth LE | Linux con BlueZ 5.50 o posterior, adaptador Bluetooth 4.0+ y `cbb-helper` |
| [Arduino Nano ESP32 como teclado USB o Bluetooth](#the-nano-esp32-as-a-usb-or-bluetooth-keyboard) | Cualquier dispositivo con entrada de teclado USB o BLE, incluidos BIOS/UEFI, peticiones de cifrado de disco, Xbox y Nintendo Switch por USB | Una Arduino Nano ESP32 con el firmware de `esp32/` cargado |
| [Ordenador como mando del televisor](#a-computer-as-the-tvs-remote) | Android TV, Google TV, Apple TV o Roku en tu red doméstica | Ordenador Linux, macOS, Windows o FreeBSD en casa con `cbb-helper` |

Xbox y Nintendo Switch solo aceptan teclados USB, así que usa la Arduino Nano ESP32 para esas consolas. iPhone, macOS y Windows no permiten que las apps actúen como teclado Bluetooth.

## Haz coincidir la distribución del teclado y la velocidad

Un teclado Bluetooth o USB envía códigos de tecla físicos, no caracteres: el dispositivo de destino convierte cada código de tecla en un carácter según su distribución de teclado activa.

- **Distribución:** Configura la distribución del teclado en Connect Beyond Borders para que coincida con la distribución activa en el dispositivo de destino: **Inglés (EE. UU.)** (`us`) o **Ruso** (`ru`). Si tu texto contiene un carácter que la distribución elegida no puede escribir, Connect Beyond Borders rechaza todo el texto e indica los caracteres no compatibles en lugar de escribir caracteres incorrectos. Los saltos de línea envían Intro y los tabuladores envían Tab.
- **Velocidad:** La velocidad por defecto es de **20 caracteres por segundo**, porque algunos televisores pierden teclas que llegan más rápido. Baja la velocidad (por ejemplo, a 10 caracteres por segundo) si faltan caracteres.
- **Límite de longitud:** Un teclado Bluetooth o USB escribe como máximo **4096 caracteres** cada vez.

## Un teléfono como teclado Bluetooth

Compatible con teléfonos **Android**, **Aurora OS** y **HarmonyOS**.

1. Abre **CBB**, ve a **Ajustes**, activa **Ajustes avanzados** y abre **Laboratorio > Teclado Bluetooth**.
2. Activa **Actuar como teclado Bluetooth** y concede el permiso de Bluetooth si te lo pide.
   - En Android, si la app informa de que el teléfono no puede actuar como teclado, el fabricante del dispositivo omitió el perfil Bluetooth HID Device; usa otro método. Si otra app ocupa el perfil de teclado, desactívala allí primero porque Android solo permite una app de teclado a la vez.
3. Empareja el dispositivo de destino con tu teléfono:
   - **Android:** Toca **Hacer visible este teléfono** (visible durante 2 minutos), empareja tu teléfono en los ajustes de Bluetooth del dispositivo de destino y luego selecciona el destino en **Escribir en**.
   - **Aurora OS:** Toca **Hacer visible este teléfono** (visible durante 2 minutos) y conéctate a `CBB keyboard` desde los ajustes de Bluetooth del dispositivo de destino.
   - **HarmonyOS:** Mientras el interruptor del teclado está activado, conéctate a tu teléfono por el nombre del dispositivo desde los ajustes de Bluetooth del dispositivo de destino.

   **Resultado:** La pantalla muestra `Conectado a …` (o `Hay un dispositivo conectado.`).

4. Ajusta **Distribución del teclado del dispositivo** (`Inglés (EE. UU.)` o `Ruso`) y, si hace falta, **Velocidad** (`10`, `20` o `40` caracteres por segundo).
5. Coloca el foco en un campo de texto del dispositivo de destino y luego toca **Escribir el portapapeles** (en HarmonyOS, toca el botón **Pegar** del sistema junto a **Escribir el portapapeles**).

**Resultado:** Tu teléfono escribe el texto del portapapeles en el campo enfocado del dispositivo de destino.

## Un ordenador Linux como teclado Bluetooth

Ejecuta estos comandos en un ordenador Linux con `cbb-helper` instalado:

1. Registra el teclado Bluetooth LE con BlueZ:

   ```sh
   sudo cbb keyboard on -layout us
   ```

   Opciones adicionales: `-rate N` (de 5 a 60 caracteres por segundo; 20 por defecto) y `-pastes` (redirige los [pegados remotos](remote-paste.md) entrantes al dispositivo Bluetooth emparejado en lugar de a la pantalla de este ordenador; los saltos de línea requieren `sudo cbb paste-receive on -enter`).

2. Haz visible el ordenador durante 2 minutos:

   ```sh
   sudo cbb keyboard pair
   ```

3. En el dispositivo de destino, abre sus ajustes de Bluetooth y emparéjalo con `CBB <nombre de tu ordenador>`.
4. Comprueba la conexión y escribe texto:

   ```sh
   cbb keyboard
   echo 'the text' | sudo cbb keyboard type
   ```

**Resultado:** `cbb keyboard` confirma que hay un dispositivo conectado, y `cbb keyboard type` imprime `Typed.` tras enviar el texto. Los teclados y ratones Bluetooth propios de tu ordenador Linux siguen funcionando con normalidad.

Para desactivar el teclado Bluetooth, ejecuta `sudo cbb keyboard off`.

## La Nano ESP32 como teclado USB o Bluetooth

El [firmware para Arduino Nano ESP32](../../esp32/README.md) ejecuta un teclado USB de arranque y un teclado Bluetooth LE controlados desde su consola serie (unirse a un grupo y sincronizar el portapapeles están en la [hoja de ruta](../roadmap.md)).

1. Conéctate a la consola serie de la placa y elige un modo:
   - **Teclado USB:** Ejecuta `usb keyboard`. La placa se reinicia con su puerto USB-C actuando a la vez como teclado de arranque (que funciona en BIOS/UEFI, peticiones de cifrado de disco y consolas) y como consola serie. Conecta la placa al dispositivo de destino.
   - **Teclado Bluetooth LE:** Ejecuta `ble on`, luego `ble pair`, y empareja `CBB Nano ESP32` en los ajustes de Bluetooth del dispositivo de destino en un plazo de 2 minutos. La placa recuerda hasta 4 dispositivos emparejados (`ble forget` los borra).
2. Ajusta la distribución del destino y la velocidad de escritura:

   ```text
   layout us
   rate 20
   ```

   Usa `layout ru` para ruso.
3. En un firmware compilado con `--features console-type`, escribe texto con:

   ```text
   type hello world
   ```

**Resultado:** La placa escribe en el dispositivo Bluetooth conectado si hay uno activo, o en el teclado USB en caso contrario.

## Un ordenador como mando del televisor

Cualquier ordenador Linux, macOS, Windows o FreeBSD con `cbb-helper` en tu red doméstica puede escribir en un Android TV, Google TV, Apple TV o Roku por la red local. No se instala nada en el televisor, y el televisor nunca se une a tu grupo. Usa `sudo` en sistemas Unix (omite `sudo` en una terminal de administrador en Windows).

### 1. Emparejar o añadir el televisor

Elige los comandos correspondientes a tu televisor:

- **Android TV o Google TV:**

  ```sh
  sudo cbb remote add -name living-room-tv living-room-tv.lan
  sudo cbb remote code
  ```

  Escribe el código de 6 dígitos que muestra la pantalla del televisor en un plazo de 2 minutos.

- **Apple TV:** Primero configura **Ajustes > AirPlay y HomeKit > Permitir acceso** en el Apple TV como **Todos en la misma red** (**Solo quienes comparten esta casa** rechaza el emparejamiento). Luego ejecuta:

  ```sh
  sudo cbb remote add -appletv -name lounge 192.168.1.30
  sudo cbb remote code
  ```

  Escribe el PIN de 4 dígitos que muestra el Apple TV en un plazo de 2 minutos.

- **Roku:** El protocolo External Control Protocol de Roku usa HTTP sin cifrar y sin emparejamiento. Primero configura **Ajustes > Sistema > Ajustes avanzados del sistema > Control por aplicaciones móviles** en el Roku como **Habilitado** o **Permisivo**. Luego añádelo con `-consent`:

  ```sh
  sudo cbb remote add -roku -consent 192.168.1.40
  ```

**Resultado:** Ejecuta `cbb remote` sin argumentos para comprobar que el televisor aparece en tu lista.

### 2. Escribir en el televisor o reenviar pegados remotos

1. Abre un cuadro de búsqueda o un campo de texto en el televisor con su propio mando.
2. Escribe texto desde el ordenador:

   ```sh
   echo 'the film' | sudo cbb remote type
   ```

   Añade `-tv NAME` cuando tengas más de un televisor configurado. En Android TV y Roku, los saltos de línea pulsan Intro; en Apple TV, los saltos de línea permanecen dentro del texto.

   **Resultado:** El texto aparece en el campo de texto enfocado del televisor y `cbb remote type` imprime `Typed.`

3. Opcionalmente, redirige los [pegados remotos](remote-paste.md) entrantes de los administradores de tu grupo al televisor (un televisor a la vez; los saltos de línea requieren `sudo cbb paste-receive on -enter`):

   ```sh
   sudo cbb remote pastes living-room-tv on
   ```

Para olvidar un televisor, ejecuta `sudo cbb remote remove NAME`. Si un Android TV o Apple TV se restablece u olvida tu ordenador, vuelve a emparejarlo.

## Seguridad

- **Teclados Bluetooth:** Un teclado Bluetooth escribe donde el dispositivo emparejado tiene el foco del teclado. Empareja solo con los dispositivos que quieras controlar y olvida el emparejamiento en ambos lados cuando dejes de usarlo.
- **Pegados remotos a teclados y televisores:** Mientras el reenvío de pegados remotos está activado (`-pastes` o `cbb remote pastes TV on`), cualquier administrador de tu grupo puede escribir en ese dispositivo. Desactivar el pegado remoto también detiene el reenvío.
- **Solo en la red doméstica para televisores:** `cbb remote` solo se conecta a direcciones de tu red doméstica y rechaza cualquier dirección fuera de ella.
- **Nada de contraseñas a un Roku:** El texto enviado a un Roku cruza tu red doméstica como HTTP sin cifrar. Nunca envíes contraseñas ni otros secretos a un Roku.

Para consultar todas las opciones de la línea de comandos, consulta [Comandos](../reference/cli.md). Para los puertos de red de los televisores, consulta [Dispositivos, puertos y archivos](../reference/devices.md#ports).
