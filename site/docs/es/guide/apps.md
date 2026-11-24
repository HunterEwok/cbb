<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 36f5c3ab297b -->
# Las apps

Connect Beyond Borders tiene apps para teléfonos, relojes y escritorios. Las apps de teléfono llevan el grupo; las de escritorio son una ventana al servicio que ya se ejecuta en el ordenador.

| App | Dónde conseguirla | Estado |
|---|---|---|
| Android | `cbb-X.Y.Z.apk` en cada [versión](https://github.com/HunterEwok/cbb/releases) | compilada y probada en CI, aún no en un teléfono real |
| Android sin Google | `cbb-fdroid-X.Y.Z.apk`, y F-Droid cuando la acepten: la misma app sin el reloj Wear OS | compilada y probada en CI |
| iPhone y iPad | TestFlight, cuando se abra | compilada y probada en CI; funciona en un iPhone compilada con el equipo propio de un desarrollador |
| Wear OS | `cbb-wear-X.Y.Z.apk`, que se instala en el reloj desde un ordenador con `adb install` por la depuración inalámbrica del reloj, hasta que la app esté en Google Play | compilada |
| Apple Watch | con la app del iPhone | compilada; funciona en un Apple Watch con la app del iPhone |
| App para Mac | aún no es una descarga: por ahora se compila desde `apps/macos` | compilada |
| App de bandeja para Linux y Windows | en los archivos de Windows y Linux de cada versión, instalada con el servicio | compilada; probada en una máquina virtual con Windows 11 |

## Teléfonos

### Crear un grupo

1. Abre la app y pulsa **Crear un grupo**. La app crea la clave del grupo en el chip de seguridad del teléfono (el Secure Enclave en un iPhone, el Keystore en Android), pregunta cómo guardar la clave de recuperación (**Escribir en una hoja** o **Escribir en la YubiKey**) y abre Inicio.
2. Pulsa **+** en Inicio (Añadir un dispositivo). Muestra un código QR y seis dígitos, y espera unos minutos con la pantalla abierta.
3. En un ordenador, [instala](install.md) Connect Beyond Borders y ejecuta `sudo cbb pair -code`, o haz clic en **Unirse a un grupo** en su app de la bandeja o de la barra de menús, y escribe los seis dígitos. Un dispositivo pequeño se une de la misma manera (`sudo -u cbb cbb pair -code` en él). Un teléfono nuevo pulsa **Unirse a un grupo** y escanea el código, o escribe los dígitos.

### Cada día

- **Inicio** muestra todos los dispositivos del grupo, como iconos o como lista, con un punto que indica si está en línea. El botón grande toma una copia de otro dispositivo que aún esté vigente (un minuto por defecto; un administrador lo cambia en Ajustes) y, si no, envía lo que tiene el teléfono.
- **iPhone**: iOS solo deja a una app usar el portapapeles mientras está en primer plano, así que el iPhone sincroniza con un solo gesto: la acción «Sync clipboard» en Tocar atrás o en el botón de Acción, el control del Centro de control o el widget de la pantalla de inicio. Compartir, Connect Beyond Borders envía de inmediato un texto o un enlace.
- **Android**: las copias de los ordenadores llegan solas. Para que también se envíen solas las copias del teléfono, activa **Clipboard sync** (un servicio de accesibilidad; la app explica qué lee). Sin él, basta una pulsación: el icono **Send clipboard** de Ajustes rápidos, Send en la notificación, el widget de la pantalla de inicio, o Compartir y la selección de texto, Connect Beyond Borders.
- **Las notificaciones** avisan cuando un dispositivo se une o se elimina, se convierte en administrador, o el hub no responde fuera de casa. Cada tipo tiene su propio interruptor en Ajustes.

### Dispositivos

Pulsa un dispositivo para ver su tipo, sistema, versión y rol. En un teléfono administrador también puedes:

- **Renombrarlo** o **eliminarlo**; eliminar pide confirmación una vez y después tu cara, tu huella o tu código. En Android cada firma lo pide: añadir el primer ordenador lo pide cinco veces (los certificados propios del grupo y luego los del ordenador), cada uno más dos veces y cualquier otra acción una vez; cada solicitud dice cuál es («Signature 2 of 5»). Cuando hay que renovar el certificado de un ordenador, o las claves del grupo para sincronizar fuera de casa, la app lo pide al abrirla.
- **Make it an admin**, en el caso de un ordenador: entonces puede añadir y quitar dispositivos con `sudo cbb pair` y `sudo cbb remove`. Su clave es un archivo del ordenador, salvo que sea un ordenador Linux con TPM, y la app te avisa primero; así que elige un ordenador de confianza, a ser posible uno que esté siempre encendido y que además sea el [hub](away-from-home.md).

### Un segundo teléfono y un teléfono perdido

- **Un segundo teléfono**: pulsa **+** en el primer teléfono; en el segundo, pulsa **Unirse a un grupo** y escanea el código. El primer teléfono, la raíz, lo convierte en administrador, para que perder un teléfono no suponga perder nada.
- **Un teléfono perdido**: en tu otro teléfono, elimínalo de la lista de dispositivos. Los ordenadores siguen en el grupo; si el teléfono perdido era la raíz, abre en su lugar la recuperación en el otro teléfono y dale la clave de recuperación, que deja fuera el teléfono perdido. Más en [si se pierde o roban un dispositivo](lost-device.md).

### Ajustes

- **Sync away from home**: consulta [Fuera de casa](away-from-home.md#3-turn-it-on-on-the-other-devices).
- **Tema**: diez colores, cada uno oscuro y claro, o el del sistema; en Android también los colores del fondo de pantalla.
- **Idioma**: el del sistema, inglés o ruso.
- **Notificaciones**, un interruptor para cada tipo.
- **Show error details**: pulsa siete veces la versión para mostrar este interruptor. Activado, un error muestra su causa bajo el mensaje breve, lo que ayuda cuando informas de un problema.

## Relojes

Las apps de Apple Watch y Wear OS muestran los dispositivos del grupo y si están en línea, los últimos eventos y el interruptor de la sincronización fuera de casa. Funcionan a través del teléfono emparejado.

## Apps de escritorio

La app para Mac y la app de bandeja para Linux y Windows muestran lo mismo que el teléfono: los dispositivos como iconos, lista u órbitas, los detalles de un dispositivo, **Send the clipboard** y **Fetch**, y el interruptor de la sincronización fuera de casa. Los cambios en el grupo (renombrar, eliminar, hacer administrador) piden la contraseña del administrador. **+** abre una ventana de emparejamiento con un código QR y seis dígitos para un dispositivo nuevo, y fuera de un grupo **Unirse a un grupo** se une a una ventana por sus seis dígitos. El servicio sigue sincronizando tanto si la app está abierta como si no.

Cuando algo no funciona, consulta [Solución de problemas](troubleshooting.md).
