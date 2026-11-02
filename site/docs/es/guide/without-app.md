<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 7358caef15ed -->
# Sin la app

Un grupo no necesita la app del teléfono. Un ordenador puede sostener el grupo, y un iPhone sin la app se une con un atajo. Este es también el camino mientras la app del iPhone espera a TestFlight.

![Un ordenador Linux sostiene el grupo y añade el Mac y Windows con un código de seis dígitos, y el iPhone con un perfil y el atajo](../images/without-app.svg)

## 1. Crea el grupo en un ordenador

[Instala](install.md) Clipboard Bridge en un ordenador que esté encendido a menudo: Linux, Windows, un Mac o FreeBSD. Sostiene el grupo y sirve el atajo del iPhone. Después:

```sh
sudo cbb new
```

Este ordenador es ahora la **raíz** del grupo: guarda la clave del grupo y añade y quita dispositivos. Su clave es un archivo del ordenador, protegido por el sistema; la app del teléfono guarda la misma clave en el chip de seguridad del teléfono.

## 2. Añade ordenadores

En la raíz:

```sh
sudo cbb pair
```

Muestra un código de seis dígitos y espera. En el ordenador nuevo, ejecuta también `sudo cbb pair`: primero muestra un código QR para la app del teléfono, que puedes ignorar, y pide el código; escribe allí los seis dígitos. El ordenador nuevo se une en unos segundos.

Después activa el uso compartido en cada ordenador, como en el [inicio rápido](quickstart.md#4-share-the-computers-clipboard): `sudo cbb mode shared`.

## 3. Añade un iPhone con el atajo

En la raíz, o en un ordenador administrador que responda por `clipboardbridge.local` (`cbb status` dice si lo hace):

```sh
sudo cbb pair -phone
```

Imprime un código QR, el comienzo de una huella digital y un código de seis dígitos.

1. Escanea el código QR con la cámara del iPhone y sigue la página: instala el perfil.
2. Comprueba que la huella digital del perfil empieza por la impresa (Ajustes, General, VPN y gestión de dispositivos, «Clipboard Bridge», Más detalles), y luego activa la confianza total para él (Ajustes, General, Información, Ajustes de confianza de certificados).
3. Añade el atajo «clipboardbridge» desde la misma página y ejecútalo una vez; te pide el código de seis dígitos.
4. Pon el atajo en el botón de acción, o en Tocar atrás (Ajustes, Accesibilidad, Tocar, Tocar atrás, Doble toque).

Una sola pulsación elige entonces la dirección por sí misma: lo que se copió en un ordenador hace un momento llega al iPhone; si no, una copia nueva en el iPhone va a los ordenadores.

## 4. No dependas de un solo ordenador

Haz administrador a un segundo ordenador, para que también pueda añadir y quitar dispositivos:

```sh
sudo cbb admin NAME                   # on the root; NAME as cbb status shows it, and it must be on
sudo cbb admin -allow-file-key NAME   # for a Mac, or a Windows PC or Linux computer without a TPM
```

Un ordenador Linux o un PC con Windows con TPM guarda allí su clave de administrador. Un Mac, o un PC con Windows u ordenador Linux sin TPM, la guarda en un archivo, así que `cbb admin` pide antes `-allow-file-key`: quien copie ese archivo actúa como administrador hasta que otro administrador quite el ordenador, así que haz administrador solo a un ordenador que guardes con seguridad.

Si la raíz se pierde o se estropea, el administrador toma el control del grupo, y todos los demás dispositivos se quedan:

```sh
sudo cbb takeover NAME       # on the admin; NAME is the lost root
```

Los iPhone con el atajo se vuelven a emparejar tras una toma de control. Más en [si un dispositivo se pierde o te lo roban](lost-device.md).

## Unirse desde otra red

Un ordenador que no está en casa se une con una invitación del hub ([Fuera de casa](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)), o a través de una conexión que ya controlas:

- **SSH** a la raíz o a un administrador: en el ordenador nuevo ejecuta `ssh -N -L 18764:localhost:8764 user@that-machine`, luego `sudo cbb pair` allí (en otra sesión SSH) y `sudo cbb pair -code 127.0.0.1:18764` aquí.
- **Tu propia VPN** que dé direcciones privadas a ambas máquinas: `sudo cbb pair` en la raíz o en un administrador, y luego `sudo cbb pair -code ITS-VPN-ADDRESS:8764` aquí. En Linux, ejecuta el instalador de nuevo tras configurar la VPN, para que sus reglas de cortafuegos permitan la red de la VPN.

El código nunca viaja en claro: el emparejamiento se hace dentro de SSH o de tu VPN, y dentro de TLS. El ordenador nuevo se sincroniza por ese camino hasta que su servicio se reinicia; para seguir sincronizando después, activa la [sincronización fuera de casa](away-from-home.md) en ambos antes de cerrar la conexión.

## Un grupo anterior a la 0.6

La 0.6 solo lee registros de grupo de la versión 2 y no ofrece vuelta atrás a grupos antiguos. Un ordenador actualizado desde una versión anterior deja su grupo antiguo al arrancar por primera vez: mueve los archivos del grupo a `before-0.6` en su directorio de estado, conserva sus ajustes y `cbb status` lo indica. Vuelve a crear el grupo: `cbb new` en un ordenador y luego `cbb pair` en los demás.
