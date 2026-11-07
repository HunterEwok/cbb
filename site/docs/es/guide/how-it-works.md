<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 1e2dc830708b -->
# Cómo funciona

Esta página explica Copy Beyond Borders con imágenes: quién forma parte de un grupo, cómo se encuentran los dispositivos en casa y todas las formas en que pueden seguir en contacto cuando están fuera. Las reglas exactas están en el [diseño](../design.md); no las necesitas para usarlo.

## El grupo

Tus dispositivos forman un **grupo**. Solo pertenecen a él los dispositivos que dejas entrar, y
hablan solo entre sí, siempre cifrados (TLS). Además, cada copia va cifrada de extremo a extremo:
el dispositivo que copia la sella para los dispositivos del grupo que leen copias y la firma, así
que un dispositivo que solo la pasa no puede leerla, cambiarla ni falsificarla. Cada dispositivo
tiene un rol:

| Rol | Quién | Qué hace |
|---|---|---|
| **Raíz** | el teléfono que creó el grupo (o el ordenador, [sin la app](without-app.md)) | guarda la clave del grupo, añade y quita dispositivos, nombra administradores |
| **Administrador** | un segundo teléfono, o un ordenador que elige la raíz | añade y quita dispositivos, como la raíz |
| **Miembro** | cada ordenador y cada teléfono | sincroniza el portapapeles |
| **Miembro ligero** | un dispositivo Linux pequeño: un router, una Raspberry Pi Zero | sincroniza, nunca añade a nadie ([miembro ligero](../../member/README.md)) |
| **Miembro sin root** | un ordenador Linux instalado sin `sudo` | sincroniza como un miembro, pero nunca es la raíz, un administrador ni un hub ([más abajo](#rootless-members)) |
| **Hub** | un ordenador en casa, o un teléfono mientras su app está abierta, si quieres uno | permite que tus dispositivos sincronicen cuando están fuera de casa; uno que solo pasa las copias no lee ninguna |

Las claves del teléfono se crean en su chip de seguridad (el Secure Enclave, el Keystore de Android) y nunca salen de él; cada firma con la clave raíz del grupo o con una clave de administrador pide tu cara, tu huella o tu código, mientras que la clave con la que sincroniza funciona sin preguntar. Un ordenador guarda sus claves en archivos que solo lee Copy Beyond Borders.

### Miembros sin root

Normalmente el instalador necesita `sudo` una vez, para que Copy Beyond Borders se ejecute bajo una cuenta propia: tu navegador, tus juegos y cualquier otro programa que ejecutes no pueden leer sus claves, y el sistema mantiene el servicio en un entorno aislado muy estricto. Una instalación sin root se salta eso, para un ordenador donde no tienes `sudo`, en el trabajo por ejemplo. Sincroniza como cualquier miembro, pero cualquiera de tus programas podría copiar su clave y hacerse pasar por él, así que nunca puede ser la raíz, un administrador ni el hub, aunque lo pidas. La lista de dispositivos lo marca como «rootless». Una Steam Deck no lo necesita: usa la instalación normal ([instalación](install.md#steamos-steam-deck)).

## Dos tipos de grupo

Un grupo puede tener un ordenador en su centro o estar formado solo por teléfonos. Ambos están totalmente soportados y puedes pasar de uno a otro en cualquier momento. Recomendamos un ordenador que esté encendido a menudo, por la razón que figura debajo de la tabla.

| | Con un ordenador | Solo teléfonos |
|---|---|---|
| Quién guarda la clave del grupo | el teléfono (en su chip de seguridad), o el ordenador [sin la app](without-app.md) | el teléfono, en su chip de seguridad |
| Sincronización en casa | cada dispositivo directamente | cada dispositivo directamente |
| Sincronización fuera de casa | a través del ordenador como hub, en cualquier momento | a través del teléfono como hub mientras su app está abierta (en Android también en segundo plano), o un relé ciego |
| Qué necesitas | un ordenador que esté encendido a menudo | nada más |

Por qué recomendamos un ordenador: está encendido mucho más a menudo de lo que una app está abierta en un teléfono, y el iPhone da muy poco tiempo a una app en segundo plano, así que la sincronización fuera de casa simplemente funciona. Cuando un ordenador siempre encendido se une a un grupo de teléfonos, la app del teléfono ofrece convertirlo en el hub.

## En casa: no hace falta hub

En una misma red doméstica, los dispositivos se encuentran solos (mDNS) y se conectan directamente. Nada sale de tu red y no hay ningún servidor en medio: cualquier dispositivo puede estar apagado y los demás siguen sincronizando.

![En casa, cada dispositivo habla directamente con todos los demás, sin servidor](../images/at-home.svg)

**Dos redes en casa**, por ejemplo una red aparte para dispositivos inteligentes: mDNS no cruza el router, así que los dispositivos de redes distintas no se encuentran solos. Las apps de teléfono recuerdan las direcciones de cada ordenador a partir de su código QR y aun así llegan a él; a un miembro ligero se le puede indicar la dirección de un ordenador ([`-peer`](../../member/README.md#install)); y para todo lo demás, un hub (más abajo) une ambos lados.

## Fuera de casa: el hub

Cuando un portátil o un teléfono sale de casa, necesita un camino de vuelta. Un ordenador en casa se convierte en el **hub** del grupo: los dispositivos que están fuera se conectan a él a través del túnel cifrado del propio grupo (WireGuard), y él transmite el portapapeles a todos los que están en casa.

![Fuera de casa, el portátil y el teléfono llegan al hub de casa por el túnel WireGuard del grupo](../images/hub.svg)

- El hub es tu propio ordenador: Linux, Windows, un Mac, FreeBSD o un router. Es de uno de dos
  tipos. **Un hub que lee las copias** es un administrador, así que las copias se sellan para él
  como para tus otros dispositivos. **Un hub que solo pasa las copias** puede ser cualquier
  ordenador del grupo, por ejemplo una Raspberry Pi con sus claves en un archivo: las copias se
  sellan de extremo a extremo sin incluirlo, así que no lee ninguna, y sus claves no necesitan un
  chip de seguridad.
- Tu router redirige un puerto UDP (8764) al hub, para que internet pueda llegar a él.
- El hub no tiene por qué estar siempre encendido. Mientras está apagado, nada se sincroniza fuera de casa, y los dispositivos que están en casa siguen sincronizando sin él.
- Los dispositivos obtienen los datos del hub mientras están en casa, así que activa la sincronización fuera de casa antes de salir.

La configuración está en [Fuera de casa](away-from-home.md).

## Cuando internet no puede llegar a tu hub: un reenviador

Muchos proveedores de internet ponen los hogares tras una dirección compartida (CGNAT), y entonces ninguna redirección de puertos sirve. En su lugar, el hub puede registrarse en un **reenviador**, un servidor de internet que pasa los paquetes cifrados del túnel entre tus dispositivos y tu hub. El hub llama hacia fuera al reenviador, así que no hace falta abrir nada en casa.

![El hub, tras el NAT del proveedor, llama a un reenviador, que pasa el túnel de los dispositivos que están fuera](../images/forwarder.svg)

El reenviador no guarda claves y no puede leer nada: solo ve paquetes cifrados que van a tu hub, de dónde vienen, cuándo y de qué tamaño. Hay dos tipos:

- **El tuyo**: `cbb forward` en cualquier servidor con dirección pública, por ejemplo un servidor virtual barato ([cómo ejecutar tus propios servidores](../admin/self-hosting.md)).
- **El reenviador de Copy Beyond Borders** en `cbb.tools`, mantenido por el proyecto para todo el mundo. Está en pruebas y aún no está abierto a todos; su dirección y su clave aparecerán en esta página cuando se abra.

Los dispositivos prueban primero la dirección propia del hub y el reenviador en último lugar.

## Cuando la red bloquea WireGuard

Algunas redes (hoteles, oficinas, algunos países) bloquean el tráfico de VPN. El hub puede disfrazar el túnel del grupo:

- **Ofuscación** (`-obfuscate`): el túnel habla AmneziaWG, que en la red no se parece a WireGuard. Los ordenadores y las dos apps de teléfono lo admiten.
- **VLESS con REALITY** (`-vless`, a través de un reenviador): los dispositivos llegan al reenviador dentro de lo que parece una conexión HTTPS corriente a un sitio web conocido. Para redes que bloquean las dos opciones anteriores. Los ordenadores y las dos apps de teléfono lo admiten.

El miembro ligero solo habla WireGuard normal, así que con cualquiera de estas dos opciones solo sincroniza en casa.

## Solo teléfonos: el teléfono como hub

Un grupo de solo teléfonos, o de teléfonos y un Mac, no tiene un ordenador que haga de hub. Hay dos maneras de mantenerlo sincronizando fuera de casa:

- **El teléfono como hub**, mientras su app está abierta (Ajustes, **This phone as the hub**; activado desde el principio en un grupo creado en un teléfono). Los demás teléfonos, televisores y miembros ligeros se conectan a él en casa y, con un reenviador, también llegan a él desde lejos. En Android puede seguir funcionando en segundo plano; un iPhone solo atiende mientras la app está abierta.
- **Un relé ciego propio** (`cbb relay` en tu servidor). Hace de punto de encuentro en lugar del hub, pero no es un miembro: el cifrado de los dispositivos va de extremo a extremo a través de él, así que no puede leer el portapapeles. Sí ve cuáles de tus dispositivos se comunican y cuándo. Los ordenadores y las dos apps de teléfono pueden usarlo.

![Un relé ciego une el portátil que está fuera y el Mac que está en casa; el cifrado va de extremo a extremo a través de él](../images/relay.svg)

Un grupo puede tener varios hubs: la raíz, cada administrador con un hub configurado y los hubs
que solo pasan las copias. Los dispositivos fuera de casa usan el primero que responde, primero
los teléfonos, así que un grupo de teléfonos y un ordenador sigue funcionando mientras la app del
teléfono está cerrada.

**Previsto:** un relé ciego en `cbb.tools` para quien no quiera ejecutar un hub ni un relé. Verá qué dispositivos se comunican y cuándo, nunca lo que copian, y lo activas tú mismo.

## Qué puede ver cada servidor

| Servidor | Lee el portapapeles | Sabe qué dispositivos tuyos se comunican, y cuándo | De quién es |
|---|---|---|---|
| Hub que lee las copias | sí, es tu dispositivo y un administrador | sí | tuyo |
| Hub que solo pasa las copias | no: las copias se sellan sin incluirlo | sí | tuyo |
| Reenviador | no | no: ve las direcciones de las que vienen los paquetes cifrados y que van a tu hub, cuándo y sus tamaños | tuyo, o del proyecto en `cbb.tools` |
| Relé ciego | no | sí | tuyo (está previsto uno en `cbb.tools`) |

No interviene nada más: ni cuentas, ni nube, ni telemetría. Todos los demás que pueden ver algo, desde tu Wi-Fi hasta la comprobación de actualizaciones, están en [privacidad](privacy.md). Con la sincronización fuera de casa activada, el servicio de Copy Beyond Borders de un ordenador solo puede llegar a la red doméstica y al hub, el reenviador y el relé del propio grupo.
