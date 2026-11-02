<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 503bd28272de -->
# Pegado remoto

Para quien quiere poner un texto en una app de otro dispositivo: una contraseña en el formulario de inicio de sesión de un televisor, un comando en la terminal de un servidor, una dirección en un ordenador al otro lado de la habitación. Un administrador del grupo envía el texto, y aterriza donde esté el foco de ese dispositivo, pegado o escrito tecla a tecla.

El pegado remoto está desactivado en cada dispositivo hasta que su propio usuario lo activa allí. Nadie puede activarlo a distancia.

## Actívalo donde debe llegar el texto

| Dispositivo | Cómo | Dónde pega |
|---|---|---|
| Linux | `sudo cbb paste-receive on` | la app con el foco del escritorio (X11, Wayland, GNOME y KDE), el panel activo de tmux; con `-console`, también la consola de texto |
| FreeBSD | `sudo cbb paste-receive on` | la app con el foco en X11 y en los escritorios wlroots (sway, Hyprland); no en GNOME, porque allí nada indica si su pantalla está bloqueada |
| Windows | `cbb paste-receive on` en una terminal abierta como administrador | la ventana que tiene el foco |
| Mac | `sudo cbb paste-receive on`, y la app del Mac abierta y permitida en Ajustes del Sistema, Privacidad y seguridad, Accesibilidad | la app que tiene el foco |
| Teléfono o televisor Android | Ajustes, «Let the group's admins paste here», y el servicio de accesibilidad de la app activado | el campo de texto que tiene el foco en otra app |
| Miembro ligero | `sudo cbb paste-receive on`; con `-console`, también la consola de texto | el panel de tmux en uso |

`-enter` (en un teléfono, «Let a paste press Enter») permite que un pegado pulse Intro después del texto. Sin él, se rechaza un texto con un salto de línea, porque un salto de línea puede ejecutar como un comando lo que va antes de él en cualquier terminal que no tome el pegado como una sola pieza.

En GNOME y KDE, el primer pegado abre el cuadro de diálogo del sistema para el control remoto de la pantalla; permítelo una vez y se recuerda. Para saltarte el cuadro de diálogo, instala el ayudante uinput: instala de nuevo con `--uinput` (`curl -fsSL https://github.com/HunterEwok/clipboardbridge/releases/latest/download/get.sh | sudo sh -s -- --uinput`), lo que añade un teclado virtual que solo pulsa Mayús+Insert e Intro para el usuario que está ante la pantalla.

Sin escritorio, tmux y la consola de texto necesitan sus ayudantes. Cada instalación añade la parte de Clipboard Bridge de `/etc/tmux.conf`, que inicia el ayudante de tmux junto con tmux; `install.sh --console` añade el servicio del ayudante de la consola.

## Pegar desde un administrador

En un ordenador administrador:

```sh
echo 'the text' | cbb paste -on DEVICE          # pastes it
cbb paste -on DEVICE                            # pastes this computer's clipboard text
cbb paste -on DEVICE -type < note.txt           # types it key by key, up to 4 KiB
cbb paste -on DEVICE -enter -secret < pass.txt  # presses Enter after it; kept as a secret
```

`DEVICE` es el nombre del dispositivo o su ID de `cbb status`. El comando dice cuándo ha llegado el texto, o por qué lo rechazó el dispositivo.

En un teléfono administrador, abre la página del dispositivo y elige «Paste on it…»: escribe el texto, o deja el campo vacío para enviar lo que hay en el portapapeles, elige pegar o escribir, y confirma con Face ID o la huella. Un iPhone pregunta cada vez si la app puede leer el portapapeles, hasta que en Ajustes, Apps, CBB, «Pegar desde otras apps» está en Permitir.

Escribir funciona con cualquier distribución de teclado en X11, en los compositores de Wayland con teclado virtual, en Windows y en el Mac. En GNOME y KDE a través del cuadro de diálogo, el pegado funciona pero escribir no, ya que las teclas seguirían la distribución del usuario.

## Cuándo se rechaza

Un dispositivo nunca pega:

- mientras su pantalla está bloqueada o hay un salvapantallas o una pantalla de inicio de sesión;
- en una ventana que se ejecuta como administrador en Windows, o bajo un aviso de administrador;
- en un Mac mientras un campo de contraseña o Secure Keyboard Entry tiene el teclado;
- cuando nadie está conectado a tmux ni ha iniciado sesión en la consola;
- más de una vez por segundo, o más de 30 veces por minuto, desde un mismo remitente.

La respuesta que recibe el remitente dice cuál fue el motivo.

## Seguridad

- Cualquier administrador de tu grupo puede escribir en tu dispositivo mientras el pegado remoto está activado, como si estuviera ante tu teclado. Actívalo solo donde lo necesites y mantén corta la lista de administradores.
- Cada dispositivo guarda un registro de sus últimos 100 pegados: quién los envió y cuándo, nunca el texto. Android además nombra al remitente en una notificación.
- Cualquier administrador puede desactivar el pegado remoto en otro dispositivo o en todos, por ejemplo cuando se pierde un teléfono: `cbb paste-receive off -on DEVICE` o `-all`. Solo el usuario del propio dispositivo vuelve a activarlo.

Los límites están en [límites y duraciones](../reference/limits.md#remote-paste-and-quick-actions); cómo funciona por dentro está en el [diseño](../design.md#remote-paste).
