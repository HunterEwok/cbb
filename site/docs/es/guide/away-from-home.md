<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 0ee54fa655f3 -->
# Fuera de casa

En casa, tus dispositivos se sincronizan solos. Para seguir sincronizando cuando un portátil o un teléfono está en otro sitio, un ordenador de casa se convierte en el **hub** del grupo, y los dispositivos que viajan llegan a él por el túnel cifrado del propio grupo. Las imágenes de cada caso están en [Cómo funciona](how-it-works.md#away-from-home-the-hub).

> Entre ordenadores está hecho y probado en CI, todavía no en dispositivos reales; el iPhone se ha sincronizado con datos móviles a través de un hub en un Mac y el reenviador del proyecto. La [tabla de estado](../../README.md#status) del README dice qué se ha probado y dónde.

La sincronización fuera de casa está desactivada hasta que la actives, en el hub y en cada dispositivo que deba usarla. Configúrala **mientras todos los dispositivos están en casa**: es entonces cuando se entregan unos a otros las claves del túnel.

## 1. Elige el hub

El hub es un ordenador: Linux, Windows, un Mac, FreeBSD o un router con OpenWrt u OPNsense. El
mejor está siempre encendido: un servidor doméstico, un NAS, una Raspberry Pi. Un ordenador que
enciendes solo cuando lo necesitas también sirve; mientras el hub está apagado, nada se
sincroniza fuera de casa, y en casa todo sigue sincronizándose.

Un hub es de uno de dos tipos, y eliges cuál al nombrarlo:

- **Un hub que lee las copias** es un administrador del grupo, así que las copias se sellan para
  él como para tus otros dispositivos, y el [nivel de claves](keys.md#the-three-levels) del
  grupo se aplica a sus claves. En un grupo creado en un teléfono, el teléfono hace primero
  administrador al ordenador.
- **Un hub que solo pasa las copias** es cualquier otro ordenador del grupo. Las copias se sellan
  de extremo a extremo para tus otros dispositivos y nunca para él, así que no lee ninguna, y sus
  claves no necesitan un chip de seguridad: una Raspberry Pi o un NAS en Docker con sus claves en
  un archivo es una buena opción. No hace, lee ni pega copias propias.

En el teléfono, toca el ordenador, luego **Make it a hub** y el tipo; la app del Mac y la app
de la bandeja preguntan lo mismo. Desde un ordenador administrador,
`sudo cbb global hub -on DEVICE -forward-only` convierte otro ordenador en un hub que solo pasa
las copias. Antes debe estar activada allí la sincronización fuera de casa (paso 2 más abajo,
con `sudo cbb global on`).

## 2. Actívalo en el hub

En Linux, en una terminal del hub (en Windows, sin `sudo`, en una terminal de administrador):

```sh
sudo cbb global on                        # read what it says about the keys, type yes
sudo cbb global hub 203.0.113.7:8764      # the address the internet reaches your home at
```

En la app de Mac o en la app de la bandeja, abre la página del propio ordenador y elige **Make it a hub**: pregunta una vez y activa con él la sincronización fuera de casa, a través del reenviador del proyecto.

- **La dirección** es la dirección IP pública de tu casa (IPv4 o IPv6), o un nombre que apunte a ella. La página de estado del router la muestra, o un sitio como `ifconfig.me`.
- **El router** debe redirigir el puerto UDP 8764 al hub. Busca «reenvío de puertos» o «servidor virtual» en sus ajustes.
- **El cortafuegos del hub**: `cbb global hub` enumera la regla que necesita y pregunta antes de añadirla.

**Un router OpenWrt como hub** no necesita redirección de puertos: ejecuta los mismos comandos en el router, como root y sin `sudo`. Con Yes, la regla para el puerto UDP del hub desde `wan` pasa a formar parte de las reglas de cortafuegos del propio servicio, que van y vienen con el servicio; `/etc/config/firewall` queda como estaba. Un router tras otro router (doble NAT) sigue necesitando la redirección en el router de delante, o un reenviador.

¿No tienes dirección pública porque tu proveedor te pone tras un NAT de operador? Entonces el router no puede ayudar; usa en su lugar un reenviador (paso 5).

## 3. Actívalo en los demás dispositivos

En casa, con el hub encendido:

- **Ordenadores**: `sudo cbb global on` (en Windows, en una terminal de administrador).
- **Teléfonos**: en la app, Ajustes, **Sync away from home**. Después deja la app abierta un momento en casa, para que se encuentre con el hub. Un iPhone sincroniza fuera de casa mientras la app está abierta; Android también en segundo plano. En un grupo creado en un teléfono, ese teléfono empieza siendo el hub, y el interruptor aparece cuando deja de serlo: en **Move the hub to a computer** haz hub al ordenador (guardando antes el reenviador en el teléfono), o apaga **This phone as the hub**.
- **Miembro ligero**: `sudo cbb global on` en el dispositivo ([miembro ligero](../../member/README.md#sync-away-from-home)).

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
sudo cbb global hub
```

Sin direcciones propias, el hub pasa por el reenviador del proyecto en `cbb.tools`: cbb conoce su dirección y su clave, y un teléfono que hace de hub también lo usa. `-forwarder default` lo añade a un hub que además tiene sus propias direcciones. Para [tu propio reenviador](../admin/self-hosting.md#a-forwarder), en cualquier servidor pequeño, da en su lugar su dirección y su clave: `sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key>`; en un teléfono, en **This phone as the hub**.

El hub puede tener a la vez su propia dirección y un reenviador: los dispositivos prueban primero el hub y el reenviador en último lugar.

## 6. Redes que bloquean las VPN

Los hoteles, las oficinas y algunos países bloquean WireGuard. El hub puede disfrazar el túnel con AmneziaWG o esconderlo dentro de VLESS: consulta [Redes que bloquean las VPN](blocked-networks.md).

## Un ordenador que no está en casa: una invitación

Un ordenador lejano puede unirse al grupo con una invitación del hub, una vez que la sincronización fuera de casa funciona:

```sh
sudo cbb invite        # on the hub: writes cbb.cbbinvite, valid for an hour
```

Envía el archivo al nuevo ordenador por un canal de confianza, como una aplicación de mensajería que uses contigo mismo; es un secreto hasta que se usa. Allí, ejecuta `sudo cbb pair -invite cbb.cbbinvite`. Ambos ordenadores muestran la huella de la clave del nuevo; en el hub, escribe `yes` solo si coinciden. Los teléfonos todavía no pueden unirse por invitación: añádelos en casa.

Otras formas de unirse desde lejos, por SSH o con tu propia VPN, están en [Sin la app](without-app.md#joining-from-another-network).

## Sin ordenador para el hub

Un teléfono puede ser el hub mientras su app está abierta (Ajustes, **This phone as the hub**). O los dispositivos se encuentran en un **relé ciego** de tu propio servidor en lugar de un hub: los ordenadores con `cbb global relay`, los teléfonos en **Blind relay** de Ajustes. El relé no puede leer el portapapeles, pero ve qué dispositivos se comunican, cuándo y cuánto. Consulta [cómo ejecutar tus propios servidores](../admin/self-hosting.md#a-blind-relay).

El interruptor **This phone as the hub** está solo en Ajustes, no en la página del teléfono en la lista de dispositivos como en un ordenador: un teléfono hace de hub solo mientras su app está abierta (un Android también en segundo plano, a costa de la batería), así que un ordenador siempre encendido es mejor hub.

Más adelante: un relé ciego en `cbb.tools` que cualquier grupo podrá usar.

## Desactivarlo

Para que un ordenador deje de ser el hub pero siga sincronizando fuera de casa, ejecuta allí `sudo cbb global hub off`, o elige **Stop being the hub** en su página de la app de Mac o de la app de la bandeja; un administrador también puede hacerlo para otro ordenador (`sudo cbb global hub off -on NOMBRE`). Los dispositivos conectados a él pasan al siguiente hub del grupo. Si no hay otro hub, pregunta antes, porque los dispositivos fuera de casa dejan de sincronizar hasta que un dispositivo vuelva a ser hub.

```sh
sudo cbb global off
```

Olvida las claves del túnel en ese dispositivo. Las claves nuevas de un `cbb global on` posterior solo llegan al hub en la red doméstica, así que un dispositivo que esté fuera ahora volverá a sincronizar solo cuando llegue a casa. En un teléfono, desactiva el interruptor en Ajustes.
