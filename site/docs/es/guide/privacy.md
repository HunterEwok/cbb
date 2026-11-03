<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 753c15aad88e -->
# Privacidad: quién ve qué

Para quien quiere saber qué sale de sus dispositivos. Copy Beyond Borders no tiene cuentas, ni nube, ni telemetría: lo que copias va solo a los dispositivos de tu grupo, cifrado de extremo a extremo. Esta página enumera todo lo demás que alguien ajeno al grupo puede ver, y cómo desactivarlo.

## Lo que copias

Los textos, las imágenes y los archivos pasan solo entre los dispositivos de tu grupo, dentro de TLS 1.3 con los certificados propios del grupo. Fuera de casa pasan además dentro de WireGuard, a través de tu hub, y quizá a través de un reenviador o un relé. Ningún servidor, red o proveedor puede leerlos, incluidos los servidores del proyecto. Un dispositivo que se quita del grupo no recibe nada más.

Hay dos excepciones, y ambas son decisión tuya:

- Un **Roku** añadido con `cbb remote add -roku -consent` recibe su texto como HTTP sin cifrar en tu red doméstica ([teclados y televisores](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- Un **hub** es uno de tus propios dispositivos, así que lee las copias como cualquier otro miembro.

## Todos los demás

| Quién | Qué puede ver | Cómo evitarlo |
|---|---|---|
| Otros en tu red doméstica | que hay dispositivos que ejecutan Copy Beyond Borders, sus ID de dispositivo aleatorios y la etiqueta de tu grupo en mDNS, y cuáles se comunican y cuánto; nunca los nombres de los dispositivos ni los contenidos | nada que hacer; un ordenador publica solo en las redes domésticas que conoce (un miembro ligero, en todas las redes) |
| Otros en una red fuera de casa (una cafetería, un hotel) | que el dispositivo habla WireGuard, o que con VLESS abre una conexión TLS a tu hub o reenviador, cuándo y cuánto | una VPN del sistema oculta incluso eso |
| El reenviador (el tuyo, o el del proyecto en `cbb.tools`) | las direcciones de las que vienen los paquetes cifrados y que van a tu hub; no a qué grupo o dispositivo pertenecen | ejecutar el tuyo, o redirigir un puerto a tu hub y no usar ninguno |
| Un relé ciego | cuáles de los dispositivos de un grupo están en línea ahora y se comunican entre sí, cuándo y cuánto; no guarda nada de ello | ejecutar el tuyo, o usar un hub |
| La empresa que aloja un reenviador o un relé | las direcciones que se comunican con él, cuándo y cuánto | una VPN del sistema en el dispositivo |
| GitHub, o `dl.cbb.tools` cuando GitHub no responde | tu dirección y que usas Copy Beyond Borders, en cada comprobación de actualizaciones y descarga; nada sobre el grupo | `sudo cbb update -auto off`, o un espejo propio (`-mirror`) |
| `cbb.tools` | la dirección de la raíz, una vez al día, cuando obtiene la copia firmada de la lista de claves de Android revocadas de Google (cuando esa copia empiece, con las claves de firma del proyecto) | no hace falta nada: es el mismo archivo para todos |
| Apple, Intel o AMD | que un dispositivo de ese tipo les pidió respaldar su clave, desde tu dirección | solo en el nivel de claves **estricto**; el nivel por defecto no pregunta a nadie ([claves](keys.md#the-three-levels)) |
| La App Store, Google Play, F-Droid, Homebrew, winget | que instalaste la app, como con cualquier app | instala en su lugar el archivo firmado de la versión |

Nada informa de fallos ni de uso. Los registros se quedan en cada dispositivo; con los detalles de error activados (`CBB_DEBUG=1`), contienen más información de la causa, también solo en ese dispositivo.

## El sitio web

`cbb.tools` cuenta las visitas con su propio GoatCounter, sin cookies y sin enviar nada a otra empresa. Las apps y el servicio nunca cargan nada de él aparte de los archivos mencionados arriba.

## Más detalle

- Qué guardan un reenviador y un relé, y qué ve su proveedor de alojamiento: [cómo ejecutar tus propios servidores](../admin/self-hosting.md#what-the-server-keeps).
- Qué aprende cada servidor, campo por campo: el [protocolo](../protocol.md), secciones 13 y 14.
- Los ataques frente a los que se defiende Copy Beyond Borders, y aquellos frente a los que no: el [modelo de amenazas](../threat-model.md).
