<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 92bb7661d223 -->
# Pegado remoto

Para cualquiera que quiera pegar texto, imágenes o archivos desde un teléfono o un ordenador administrador directamente en la app activa de otro ordenador —por ejemplo, una contraseña en un campo de inicio de sesión, un comando en una terminal o una captura de pantalla en un chat.

Un administrador firma la solicitud de pegado, y el ordenador de destino coloca el contenido donde está el foco del teclado pegándolo o escribiéndolo tecla a tecla. El pegado remoto está desactivado en todos los ordenadores hasta que el propio usuario de ese ordenador lo activa localmente; nadie puede activarlo a distancia. Los teléfonos envían pegados remotos a los ordenadores y no reciben pegados remotos.

## 1. Activa el pegado remoto en el ordenador de destino

Sigue la configuración del sistema operativo del ordenador de destino:

| Sistema de destino | Pasos de configuración | Dónde se pega |
|---|---|---|
| **Linux** | Ejecuta `sudo cbb paste-receive on` | La app de escritorio enfocada (X11, Wayland, GNOME, KDE), el panel activo de `tmux` y (con `-console`) la consola de texto de Linux |
| **FreeBSD** | Ejecuta `sudo cbb paste-receive on` | La app enfocada en X11 y en compositores Wayland basados en wlroots (como sway y Hyprland); GNOME en FreeBSD no es compatible porque el estado de bloqueo de pantalla no está disponible |
| **Windows** | Abre una terminal como administrador y ejecuta `cbb paste-receive on` | La ventana enfocada |
| **macOS** | Ejecuta `sudo cbb paste-receive on`, mantén abierta la app **CBB** de la barra de menús y permítela en **Ajustes del Sistema > Privacidad y seguridad > Accesibilidad** | La app enfocada |
| **Dispositivo Linux pequeño sin escritorio** | Ejecuta `sudo cbb paste-receive on` (añade `-console` para la consola de texto de Linux) | El panel activo de `tmux` o la consola de texto |

Opciones adicionales para `cbb paste-receive on`:

- `-enter`: Permite que un pegado remoto pulse Intro después del contenido. Sin `-enter`, cualquier texto que contenga un salto de línea se rechaza para que un pegado no pueda ejecutar un comando por accidente en una terminal.
- `-console`: Permite el pegado remoto en la consola de texto de Linux y en las sesiones de `tmux` de `root` (no disponible en instalaciones sin root).
- `-no-lock-check`: En Linux y FreeBSD sin `logind`, permite el pegado remoto cuando el sistema no puede informar del estado de bloqueo de sesión (un bloqueador de pantalla activo sigue bloqueando los pegados).

**Resultado:** Ejecuta `cbb paste-receive` sin argumentos para confirmar que el pegado remoto está activado y ver qué opciones están activas.

### Ayudantes adicionales en Linux

- **Cuadros de diálogo de escritorio en GNOME y KDE:** El primer pegado remoto abre el cuadro de diálogo de confirmación de control remoto de tu escritorio; permítelo una vez para que el escritorio lo recuerde. Para omitir ese cuadro de diálogo (y permitir pulsaciones de teclas en escritorios sin otra vía de entrada), vuelve a instalar con `--uinput`:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh -s -- --uinput
  ```

  Esto añade `cbb-uinput.service`, un teclado virtual que solo pulsa Mayús+Insert e Intro para el usuario con sesión iniciada.
- **`tmux` sin escritorio y consolas de texto:** Cada instalación de Linux añade el gancho de Connect Beyond Borders a `/etc/tmux.conf` para que `tmux` inicie automáticamente su ayudante de pegado. Para la consola de texto de Linux, instala con `--console` (consulta [Instalar en Linux](install.md#linux)).

## 2. Envía un pegado remoto desde un administrador

### Desde un ordenador administrador

Ejecuta `cbb paste -on DEVICE` en una terminal (`DEVICE` es el nombre del destino o su ID de dispositivo según `cbb status`):

```sh
echo 'the text' | cbb paste -on DEVICE              # paste text from standard input
cbb paste -on DEVICE                                # paste this computer's clipboard text
cbb paste -on DEVICE -type < note.txt               # type text key by key (up to 4 KiB)
cbb paste -on DEVICE -enter -secret < pass.txt      # paste as a secret and press Enter
cbb paste -on DEVICE photo.jpg notes/               # paste files into the focused app
cbb paste -on DEVICE -image screenshot.png          # paste a PNG or JPEG as an image
cbb paste -on DEVICE -copy                          # paste the group's current image or files
```

**Resultado:** El comando imprime `Pasted on DEVICE.` cuando el destino acepta y entrega el pegado, o informa del motivo exacto por el que el destino lo rechazó.

### Desde un teléfono administrador

1. Abre **CBB**, toca el ordenador de destino en **Inicio** y toca **Pegar en él…**.
2. Elige qué enviar:
   - **Texto:** Escribe el texto (o deja el campo de texto vacío para enviar el portapapeles de tu teléfono), selecciona opcionalmente escribir tecla a tecla, **Un secreto** o **Pulsar Intro después**, y toca **Pegar**.
   - **Imágenes o archivos:** Toca **Pegar una imagen o archivos…** (en el iPhone, **Pegar una imagen…** o **Pegar archivos…**) y selecciona los elementos.
3. Confirma con tu cara, huella, código o (en Aurora OS) tu PIN de administrador.

En el iPhone, configura **Ajustes > Apps > CBB > Pegar desde otras apps** en **Permitir** para que iOS no pregunte cada vez que la app lee tu portapapeles.

**Resultado:** El ordenador de destino pega o escribe el contenido en su ventana enfocada y la app muestra **Pegado.**

### Pegar frente a escribir

- **Pegar** funciona en la mayoría de las apps de escritorio y admite texto (hasta 1 MiB), imágenes y archivos.
- **Escribir** (`-type`) envía pulsaciones de teclas una a una (solo texto, hasta 4 KiB) para apps que bloquean el pegado desde el portapapeles. Escribir funciona con distintas distribuciones de teclado en X11, compositores Wayland con protocolo de teclado virtual, Windows y macOS. En GNOME y KDE a través del cuadro de diálogo de control remoto del sistema, pegar funciona mientras que escribir no está disponible.

## Cuándo rechaza un pegado el destino

Un ordenador de destino rechaza un pegado remoto cuando:

- Su pantalla está bloqueada, hay un salvapantallas activo o se muestra una pantalla de inicio de sesión.
- En Windows, la ventana enfocada se ejecuta como administrador o hay abierto un aviso de elevación a administrador.
- En macOS, un campo de contraseña o Secure Keyboard Entry tiene el foco del teclado.
- Nadie está conectado a `tmux` ni ha iniciado sesión en la consola de texto (en destinos sin escritorio).
- El texto contiene un salto de línea y `-enter` no está activado en el destino.
- Un remitente supera el límite de velocidad de **1 pegado por segundo** o **30 pegados por minuto**.

El error devuelto al remitente indica el motivo.

## Seguridad y desactivar el pegado remoto

- **Limita tus administradores:** Cualquier administrador de tu grupo puede escribir en un ordenador mientras el pegado remoto está activado. Activa el pegado remoto solo en los ordenadores donde lo necesites y mantén corta tu lista de administradores.
- **Registro de auditoría de pegados:** Cada destino registra sus últimas 100 solicitudes de pegado (remitente, marca de tiempo, longitud, método y resultado; nunca el texto pegado). Los secretos no dejan rastro en el portapapeles del destino después de pegarse.
- **Desactivar localmente:** Ejecuta `sudo cbb paste-receive off` en el ordenador de destino (desactivarlo también restablece `-enter`, `-console` y `-no-lock-check`).
- **Desactivar a distancia desde cualquier administrador:** Ejecuta `sudo cbb paste-receive off -on DEVICE` (o `-all` para desactivar el pegado remoto en todos los ordenadores del grupo). Solo el propio usuario de cada ordenador puede volver a activarlo.

Para consultar los límites exactos de tamaño y velocidad, consulta [Límites y duraciones](../reference/limits.md#remote-paste-and-quick-actions). Para saber cómo funciona el pegado remoto por dentro, consulta [Diseño: pegado remoto](../design.md#remote-paste).
