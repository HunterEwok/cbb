<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 3a3178c99395 -->
# Las apps

Clipboard Bridge tiene apps para teléfonos, relojes y escritorios. Las apps de teléfono llevan el grupo; las de escritorio son una ventana al servicio que ya se ejecuta en el ordenador.

| App | Dónde conseguirla | Estado |
|---|---|---|
| Android | `clipboardbridge-X.Y.Z.apk` en cada [versión](https://github.com/HunterEwok/clipboardbridge/releases) | compilada y probada en CI, aún no en un teléfono real |
| Android sin Google | `clipboardbridge-fdroid-X.Y.Z.apk`, y F-Droid cuando la acepten: la misma app sin el reloj Wear OS | compilada y probada en CI |
| iPhone y iPad | TestFlight, cuando se abra | compilada y probada en CI, aún no en un teléfono real |
| Wear OS | `clipboardbridge-wear-X.Y.Z.apk`, que se instala en el reloj desde un ordenador con `adb install` por la depuración inalámbrica del reloj, hasta que la app esté en Google Play | compilada |
| Apple Watch | con la app del iPhone | compilada |
| App para Mac | aún no es una descarga: por ahora se compila desde `apps/macos` | compilada |
| App de bandeja para Linux y Windows | aún no es una descarga: por ahora se compila desde `apps/desktop` | compilada |

## Teléfonos

### Crear un grupo

1. [Instala](install.md) Clipboard Bridge en un ordenador y ejecuta allí `sudo cbb pair`. Muestra un código QR.
2. Abre la app, pulsa **Connect a new device** y escanea el código. La app crea la clave del grupo en el chip de seguridad del teléfono (el Secure Enclave en un iPhone, el Keystore en Android), añade el ordenador y abre Inicio.
3. Añade cada ordenador adicional con **+** en Inicio. Un miembro ligero se une de la misma manera (`sudo -u clipboardbridge cbb pair` en él muestra su código).

Cuando no se puede usar la cámara: en un iPhone, escribe los seis dígitos que muestra el ordenador; en Android, pega el texto del código QR, que `cbb pair` también imprime.

### Cada día

- **Inicio** muestra todos los dispositivos del grupo, como iconos o como lista, con un punto que indica si está en línea. El botón grande envía lo que tiene el teléfono, o trae la última copia de los ordenadores si se hizo hace un momento.
- **iPhone**: iOS solo deja a una app usar el portapapeles mientras está en primer plano, así que el iPhone sincroniza con un solo gesto: la acción «Sync clipboard» en Tocar atrás o en el botón de Acción, el control del Centro de control o el widget de la pantalla de inicio. Compartir, Clipboard Bridge envía de inmediato un texto o un enlace.
- **Android**: las copias de los ordenadores llegan solas. Para que también se envíen solas las copias del teléfono, activa **Send my copies by themselves** (un servicio de accesibilidad; la app explica qué lee). Sin él, basta una pulsación: el icono **Send clipboard** de Ajustes rápidos, Send en la notificación, el widget de la pantalla de inicio, o Compartir y la selección de texto, Clipboard Bridge.
- **Las notificaciones** avisan cuando un dispositivo se une o se elimina, se convierte en administrador, o el hub no responde fuera de casa. Cada tipo tiene su propio interruptor en Ajustes.

### Dispositivos

Pulsa un dispositivo para ver su tipo, sistema, versión y rol. En un teléfono administrador también puedes:

- **Renombrarlo** o **eliminarlo**; eliminar pide confirmación una vez y después tu cara, tu huella o tu código.
- **Make it an admin**, en el caso de un ordenador: entonces puede añadir y quitar dispositivos con `sudo cbb pair` y `sudo cbb remove`. Su clave es un archivo del ordenador, salvo que sea un ordenador Linux con TPM, y la app te avisa primero; así que elige un ordenador de confianza, a ser posible uno que esté siempre encendido y que además sea el [hub](away-from-home.md).

### Un segundo teléfono y un teléfono perdido

- **Un segundo teléfono**: en él, pulsa **I already use Clipboard Bridge on another phone**; muestra un código QR que el primer teléfono escanea con **+**. El primer teléfono, la raíz, lo convierte en administrador, para que perder un teléfono no suponga perder nada.
- **Un teléfono perdido**: en tu otro teléfono, elimínalo de la lista de dispositivos. Los ordenadores siguen en el grupo; si el teléfono perdido era la raíz, el otro teléfono asume el grupo en el mismo paso. Más en [si se pierde o roban un dispositivo](lost-device.md).

### Ajustes

- **Sync away from home**: consulta [Fuera de casa](away-from-home.md#3-turn-it-on-on-the-other-devices).
- **Tema**: diez colores, cada uno oscuro y claro, o el del sistema; en Android también los colores del fondo de pantalla.
- **Idioma**: el del sistema, inglés o ruso.
- **Notificaciones**, un interruptor para cada tipo.
- **Show error details**: pulsa siete veces la versión para mostrar este interruptor. Activado, un error muestra su causa bajo el mensaje breve, lo que ayuda cuando informas de un problema.

## Relojes

Las apps de Apple Watch y Wear OS muestran los dispositivos del grupo y si están en línea, los últimos eventos y el interruptor de la sincronización fuera de casa. Funcionan a través del teléfono emparejado.

## Apps de escritorio

La app para Mac y la app de bandeja para Linux y Windows muestran lo mismo que el teléfono: los dispositivos como iconos, lista u órbitas, los detalles de un dispositivo, **Send the clipboard** y **Fetch**, y el interruptor de la sincronización fuera de casa. Los cambios en el grupo (renombrar, eliminar, hacer administrador) piden la contraseña del administrador. Añadir un dispositivo sigue haciéndose en la terminal (`sudo cbb pair`). El servicio sigue sincronizando tanto si la app está abierta como si no.

Cuando algo no funciona, consulta [Solución de problemas](troubleshooting.md).
