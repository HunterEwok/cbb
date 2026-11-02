<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 7ef91335d714 -->
# Fuera de casa

En casa, tus dispositivos se sincronizan solos. Para seguir sincronizando cuando un portátil o un teléfono está en otro sitio, un ordenador de casa se convierte en el **hub** del grupo, y los dispositivos que viajan llegan a él por el túnel cifrado del propio grupo. Las imágenes de cada caso están en [Cómo funciona](how-it-works.md#away-from-home-the-hub).

La sincronización fuera de casa está desactivada hasta que la actives, en el hub y en cada dispositivo que deba usarla. Configúrala **mientras todos los dispositivos están en casa**: es entonces cuando se entregan unos a otros las claves del túnel.

## 1. Elige el hub

El hub es un ordenador que es administrador del grupo: Linux, Windows, un Mac, FreeBSD o un router con OpenWrt u OPNsense. Lo mejor es uno que esté siempre encendido: un servidor doméstico, un NAS, una Raspberry Pi. Un NAS con Docker solo puede ser el hub si sus claves están en un archivo, cosa que rechaza a menos que lo permitas ([README de la imagen](../../packaging/docker/README.md#keys)). Un ordenador que enciendes solo cuando lo necesitas también sirve; mientras el hub está apagado, nada se sincroniza fuera de casa, y todo lo que está en casa sigue sincronizando.

En un grupo creado en un teléfono, convierte primero ese ordenador en administrador: en el teléfono, pulsa el ordenador y **Make it an admin**.

## 2. Actívalo en el hub

En Linux, en una terminal del hub (en Windows, sin `sudo`, en una terminal de administrador):

```sh
sudo cbb global on                        # read what it says about the keys, type yes
sudo cbb global hub 203.0.113.7:8764      # the address the internet reaches your home at
```

- **La dirección** es la dirección IP pública de tu casa (IPv4 o IPv6), o un nombre que apunte a ella. La página de estado del router la muestra, o un sitio como `ifconfig.me`.
- **El router** debe redirigir el puerto UDP 8764 al hub. Busca «reenvío de puertos» o «servidor virtual» en sus ajustes.
- **El cortafuegos del hub**: `cbb global hub` enumera la regla que necesita y pregunta antes de añadirla.

**Un router OpenWrt como hub** no necesita redirección de puertos: ejecuta los mismos comandos en el router, como root y sin `sudo`. Con Yes, la regla para el puerto UDP del hub desde `wan` pasa a formar parte de las reglas de cortafuegos del propio servicio, que van y vienen con el servicio; `/etc/config/firewall` queda como estaba. Un router tras otro router (doble NAT) sigue necesitando la redirección en el router de delante, o un reenviador.

¿No tienes dirección pública porque tu proveedor te pone tras un NAT de operador? Entonces el router no puede ayudar; usa en su lugar un reenviador (paso 5).

## 3. Actívalo en los demás dispositivos

En casa, con el hub encendido:

- **Ordenadores**: `sudo cbb global on` (en Windows, en una terminal de administrador).
- **Teléfonos**: en la app, Ajustes, **Sync away from home**. Después deja la app abierta un momento en casa, para que se encuentre con el hub. Un iPhone sincroniza fuera de casa mientras la app está abierta; Android también en segundo plano. En un grupo creado en un teléfono, ese teléfono empieza siendo el hub, y el interruptor aparece cuando deja de serlo: en **Move the hub to a computer** haz hub al ordenador (guardando antes el reenviador en el teléfono), o apaga **This phone as the hub**.
- **Miembro ligero**: `sudo cbb global on` en el dispositivo ([miembro ligero](../../lite/README.md#sync-away-from-home)).

## 4. Compruébalo

```sh
cbb global
```

En cada ordenador muestra si la sincronización fuera de casa está activada, qué dispositivo es el hub, si el túnel está levantado y qué falló si no lo está. Después saca un portátil o un teléfono del Wi-Fi de casa (basta con los datos móviles del teléfono) y copia algo.

Cuando no conecta, los motivos habituales son que el router no redirige el puerto o que la dirección no es la que ve internet. [Solución de problemas](troubleshooting.md#sync-away-from-home) tiene más.

Cuando cambia la dirección de tu casa, el hub se lo dice a los dispositivos la próxima vez que se encuentren; en un ordenador, `cbb global` indica entonces que ejecutes `sudo cbb global allow`.

## 5. Cuando internet no puede llegar a tu casa: un reenviador

Tras un NAT de operador, el hub se registra en cambio en un **reenviador** de internet, mediante una conexión saliente, así que no hace falta abrir nada en casa. El reenviador solo pasa paquetes cifrados y no guarda claves.

```sh
sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

La dirección y la clave las da el reenviador. Puedes [ejecutar el tuyo](../admin/self-hosting.md#a-forwarder) en cualquier servidor pequeño. El reenviador del proyecto en `cbb.tools` aún no está abierto a todos; su dirección y su clave estarán aquí cuando lo esté.

El hub puede tener a la vez su propia dirección y un reenviador: los dispositivos prueban primero el hub y el reenviador en último lugar.

## 6. Redes que bloquean las VPN

Los hoteles, las oficinas y algunos países bloquean WireGuard. El hub puede disfrazar el túnel con AmneziaWG o esconderlo dentro de VLESS: consulta [Redes que bloquean las VPN](blocked-networks.md).

## Un ordenador que no está en casa: una invitación

Un ordenador lejano puede unirse al grupo con una invitación del hub, una vez que la sincronización fuera de casa funciona:

```sh
sudo cbb invite        # on the hub: writes clipboardbridge.cbbinvite, valid for an hour
```

Envía el archivo al nuevo ordenador por un canal de confianza, como una aplicación de mensajería que uses contigo mismo; es un secreto hasta que se usa. Allí, ejecuta `sudo cbb pair -invite clipboardbridge.cbbinvite`. Ambos ordenadores muestran la huella de la clave del nuevo; en el hub, escribe `yes` solo si coinciden. Los teléfonos todavía no pueden unirse por invitación: añádelos en casa.

Otras formas de unirse desde lejos, por SSH o con tu propia VPN, están en [Sin la app](without-app.md#joining-from-another-network).

## Sin ordenador para el hub

Un teléfono puede ser el hub mientras su app está abierta (Ajustes, **This phone as the hub**). O los dispositivos se encuentran en un **relé ciego** de tu propio servidor en lugar de un hub: los ordenadores con `cbb global relay`, los teléfonos en **Blind relay** de Ajustes. El relé no puede leer el portapapeles, pero ve qué dispositivos se comunican, cuándo y cuánto. Consulta [cómo ejecutar tus propios servidores](../admin/self-hosting.md#a-blind-relay).

Más adelante: un relé ciego en `cbb.tools` que cualquier grupo podrá usar.

## Desactivarlo

```sh
sudo cbb global off
```

Olvida las claves del túnel en ese dispositivo. Las claves nuevas de un `cbb global on` posterior solo llegan al hub en la red doméstica, así que un dispositivo que esté fuera ahora volverá a sincronizar solo cuando llegue a casa. En un teléfono, desactiva el interruptor en Ajustes.
