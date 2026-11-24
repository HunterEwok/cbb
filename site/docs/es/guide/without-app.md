<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 5013aca345ad -->
# Sin la app

Un grupo de ordenadores no necesita la app del teléfono: un ordenador puede sostener el grupo.

![Un ordenador Linux sostiene el grupo y añade el Mac y Windows con un código de seis dígitos](../images/without-app.svg)

## 1. Crea el grupo en un ordenador

[Instala](install.md) Connect Beyond Borders en un ordenador que esté encendido a menudo: Linux, Windows, un Mac o FreeBSD. Sostiene el grupo. Después:

```sh
sudo cbb new
```

Este ordenador es ahora la **raíz** del grupo: guarda la clave del grupo y añade y quita dispositivos. Su clave está en el TPM o el Secure Enclave del ordenador si tiene uno; si no, en un archivo protegido por el sistema.

`cbb new` también muestra una vez la **hoja de recuperación** del grupo: cuatro líneas de letras y dígitos y un código QR. Anótala o imprime la pantalla, y guárdala lejos de tus dispositivos. Con ella recuperas el grupo si pierdes este ordenador (`cbb recovery`); nadie guarda una copia.

## 2. Añade ordenadores

En la raíz:

```sh
sudo cbb pair
```

Abre una ventana de emparejamiento, muestra un código de seis dígitos y espera. En el ordenador nuevo ejecuta `sudo cbb pair -code` y escribe ese código: encuentra la ventana en la red de casa y se une en segundos. Un código erróneo gasta uno de tres intentos; la ventana se cierra tras el tercero, o cuando un ordenador se ha unido.

Después cada ordenador se sincroniza, como en el [inicio rápido](quickstart.md#4-copy-on-one-paste-on-another).

## 3. No dependas de un solo ordenador

Haz administrador a un segundo ordenador, para que también pueda añadir y quitar dispositivos:

```sh
sudo cbb admin NAME                   # on the root; NAME as cbb status shows it, and it must be on
sudo cbb admin -allow-file-key NAME   # for a computer without a TPM or a Secure Enclave
```

Un ordenador Linux o un PC con Windows con TPM guarda allí su clave de administrador, y un Mac en su Secure Enclave. Un ordenador sin ninguno de los dos la guarda en un archivo, así que `cbb admin` pide antes `-allow-file-key`: quien copie ese archivo actúa como administrador hasta que otro administrador quite el ordenador, así que haz administrador solo a un ordenador que guardes con seguridad.

Si la raíz se pierde o se rompe, otro ordenador pasa a ser la raíz con la hoja de recuperación del grupo, y todos los demás dispositivos se quedan:

```sh
sudo cbb recovery            # then type the recovery key from the sheet
```

Más en [si un dispositivo se pierde o te lo roban](lost-device.md).

## Unirse desde otra red

Un ordenador que no está en casa se une con una invitación del hub ([Fuera de casa](away-from-home.md#a-computer-that-is-not-at-home-an-invitation)), o a través de una conexión que ya controlas:

- **SSH** a la raíz o a un administrador: en el ordenador nuevo ejecuta `ssh -N -L 18764:localhost:8764 user@that-machine`, luego `sudo cbb pair` allí (en otra sesión SSH) y `sudo cbb pair -code 127.0.0.1:18764` aquí.
- **Tu propia VPN** que dé direcciones privadas a ambas máquinas: `sudo cbb pair` en la raíz o en un administrador, y luego `sudo cbb pair -code ITS-VPN-ADDRESS:8764` aquí. En Linux, ejecuta el instalador de nuevo tras configurar la VPN, para que sus reglas de cortafuegos permitan la red de la VPN.

En los dos casos, escribe la línea que `cbb pair` imprime bajo el código (`cbb://pair?...`) en lugar de los seis dígitos: los dígitos solos no nombran ninguna ventana donde mDNS no llega, y la línea la nombra, con el mismo código dentro.

Los códigos nunca viajan: cada ordenador calcula el suyo a partir del emparejamiento, que va dentro de SSH o de tu VPN, y dentro de TLS. El ordenador nuevo se sincroniza por ese camino hasta que su servicio se reinicia; para seguir sincronizando después, activa la [sincronización fuera de casa](away-from-home.md) en ambos antes de cerrar la conexión.

## Un grupo anterior a la 0.6

La 0.6 solo lee registros de grupo de la versión 2 y no ofrece vuelta atrás a grupos antiguos. Un ordenador actualizado desde una versión anterior deja su grupo antiguo al arrancar por primera vez: mueve los archivos del grupo a `before-0.6` en su directorio de estado, conserva sus ajustes y `cbb status` lo indica. Vuelve a crear el grupo: `cbb new` en un ordenador y luego `cbb pair -code` en los demás.
